"""Render structured rules into nft lines, and build chains.

A rule is a mapping of match keys + an ``action`` (or a ``raw:`` passthrough).
Address matching is family-aware: a rule with address matches renders once per
IP family common to all of them. A named group referenced in a rule becomes
``@name`` when it's a declared set, otherwise it's inlined as an anonymous set.
Literals are only accepted where they're unambiguous (an IP/CIDR address, a
numeric port/range); interface and service names must be defined groups so a
typo fails the build instead of silently never matching.
"""

from __future__ import annotations

import ipaddress
import itertools

from nftgen.definitions import Definitions
from nftgen.ir import (
    _PORT_LITERAL,
    BODY_INDENT,
    SERVICE_PAIR_TYPE,
    BuildError,
    Chain,
    Flowtable,
    NamedSet,
    check_comment,
    check_nft_name,
    render_literal,
)
from nftgen.schema import check_rule

PRIORITIES = {
    "raw": -300,
    "mangle": -150,
    "dstnat": -100,
    "filter": 0,
    "security": 50,
    "srcnat": 100,
}


def resolve_priority(value) -> int:
    if isinstance(value, str) and value in PRIORITIES:
        return PRIORITIES[value]
    try:
        return int(value)
    except (TypeError, ValueError):
        raise BuildError(
            f"priority {value!r} is not a number or one of {sorted(PRIORITIES)}"
        ) from None


def _anon(items: list[str]) -> str:
    return items[0] if len(items) == 1 else "{ " + ", ".join(items) + " }"


def _nat_family(target) -> str:
    """Infer the nft family qualifier ('ip'/'ip6') from a dnat/snat target.

    inet tables can't infer it, so `dnat to <addr>` is rejected there; the
    target address itself disambiguates. Handles `host`, `host:port`,
    `[v6]:port`, and ranges (`a-b`).
    """
    host = str(target)
    if host.startswith("["):  # [2001:db8::1]:443
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:  # 10.0.0.1:443 (single colon => host:port)
        host = host.split(":", 1)[0]
    host = host.split("-", 1)[0]  # range a-b => first endpoint
    try:
        version = ipaddress.ip_address(host).version
    except ValueError as e:
        raise BuildError(
            f"dnat/snat target {target!r} must contain an IP so its family "
            f"(ip/ip6) can be set for an inet table ({e})"
        ) from e
    return "ip6" if version == 6 else "ip"


def _has_port(addr: str) -> bool:
    """True if a target carries a port (host:port / [v6]:port), vs a bare address."""
    if addr.startswith("["):
        return "]:" in addr
    return addr.count(":") == 1  # bare IPv6 has >1 colon; one colon == host:port


# protocols that exist in one IP family only
_PROTO_FAMILY = {"icmp": "ip", "icmpv6": "ip6", "ipv6-icmp": "ip6"}

_TCP_FLAGS = ("fin", "syn", "rst", "psh", "ack", "urg", "ecn", "cwr")
_TCP_ALL = (
    "fin",
    "syn",
    "rst",
    "psh",
    "ack",
    "urg",
)  # the 'all' keyword (excludes ecn/cwr)


def _expand_flags(value) -> list[str]:
    """Expand a flags value (list / 'all' / 'none' / None) to canonical flag names."""
    if value in (None, "none", []):
        return []
    items = [value] if isinstance(value, str) else list(value)
    out: list[str] = []
    for item in items:
        f = str(item).lower()
        if f == "all":
            out.extend(_TCP_ALL)
        elif f == "none":
            continue
        elif f in _TCP_FLAGS:
            out.append(f)
        else:
            raise BuildError(f"unknown tcp flag {item!r}")
    return [f for f in _TCP_FLAGS if f in out]  # canonical order, deduped


def _fmt_flags(flags: list[str]) -> str:
    if not flags:
        return "0x0"
    return flags[0] if len(flags) == 1 else "(" + "|".join(flags) + ")"


def _flag_clause(check: dict) -> str:
    """Render one {match, mask} flag check to 'tcp flags & <mask> == <comp>'."""
    match = _expand_flags(check.get("match", []))
    mask = (
        _expand_flags(check["mask"]) if check.get("mask") is not None else list(match)
    )
    if not mask:
        raise BuildError(f"flags check needs a mask (examined flags): {check!r}")
    if not set(match) <= set(mask):
        raise BuildError(f"flags check match is not a subset of mask: {check!r}")
    return f"tcp flags & {_fmt_flags(mask)} == {_fmt_flags(match)}"


_KNOWN_RULE_KEYS = frozenset(
    {
        "iifname",
        "oifname",
        "saddr",
        "daddr",
        "ct",
        "mark",
        "proto",
        "sport",
        "dport",
        "iif",
        "oif",
        "flags",
        "icmp-type",
        "meter",
        "limit",
        "quota",
        "log",
        "set-mark",
        "set-mss",
        "flow-offload",
        "counter",
        "action",
        "raw",
        "vmap",
        "set",
    }
)

# a concat (`set:`) rule may only carry these alongside the set reference
_CONCAT_RULE_KEYS = frozenset(
    {
        "set",
        "action",
        "counter",
        "meter",
        "limit",
        "quota",
        "log",
        "set-mark",
        "set-mss",
        "flow-offload",
    }
)


def _reject_offload_with_verdict(rule: dict) -> None:
    """`flow add` breaks the rule when the flow can't be offloaded yet.

    The kernel's flow-offload expression yields NFT_BREAK whenever it declines
    to offload (TCP still handshaking, fin/rst, no conntrack entry). NFT_BREAK
    aborts the *rest of the current rule*, so a verdict written after
    `flow-offload:` is silently skipped and the packet falls through — in a
    `policy: drop` chain the return path dies and the connection never
    establishes. `nft -c` accepts it happily; only traffic reveals it.
    Author it as two rules: offload in one, verdict in the next.
    """
    if "flow-offload" not in rule:
        return
    verdict = "action" in rule
    if verdict:
        raise BuildError(
            f"`flow-offload:` must not share a rule with `action:` — when the "
            f"flow can't be offloaded yet (e.g. mid-handshake) the kernel "
            f"aborts the rule and the verdict never runs. Split into two "
            f"rules: one with `flow-offload:`, the next with the same matches "
            f"and `action:`. Rule: {rule!r}"
        )


class RuleRenderer:
    def __init__(
        self,
        defs: Definitions,
        named: dict[str, NamedSet],
        counters=frozenset(),
        flowtables=None,
    ):
        self.defs = defs
        self.named = named
        self.counters = frozenset(counters)
        # None = not known (a renderer used on its own): no flowtable check
        self.flowtables = None if flowtables is None else frozenset(flowtables)

    # -- public ------------------------------------------------------------- #
    def render(self, rule: dict) -> list[str]:
        """Render one rule to nft line(s). A `comment:` is appended to every
        line the rule expands to (v4 + v6, one per flags clause) — nft wants
        it last on the rule."""
        if not isinstance(rule, dict) or "comment" not in rule:
            return self._render(rule)
        if "raw" in rule:
            raise BuildError(
                f'`raw:` can\'t take `comment:` — write `comment "…"` inside the '
                f"raw string: {rule!r}"
            )
        text = check_comment(rule["comment"], "rule")
        body = {k: v for k, v in rule.items() if k != "comment"}
        return [f'{line} comment "{text}"' for line in self._render(body)]

    def _render(self, rule: dict) -> list[str]:  # noqa: PLR0912, PLR0915 - dispatches per rule key
        if not isinstance(rule, dict):
            check_rule(rule)  # raises: a rule must be a mapping
        # Reject typos/unknown keys loudly: an unread key silently weakens a rule
        # (e.g. `dprot:` for `dport:`) and nft -c can't catch it (still valid nft).
        unknown = set(rule) - _KNOWN_RULE_KEYS
        if unknown:
            raise BuildError(f"unknown rule key(s) {sorted(unknown)}: {rule!r}")
        # then every value's shape, before anything reads it (nftgen/schema.py)
        rule = check_rule(rule)
        if "raw" in rule:
            if len(rule) != 1:
                raise BuildError(f"`raw:` must be a rule's only key: {rule!r}")
            return [rule["raw"]]
        if "vmap" in rule:
            if len(rule) != 1:
                raise BuildError(f"`vmap:` must be a rule's only key: {rule!r}")
            return [self._vmap(rule["vmap"])]
        if "set" in rule:
            return [self._concat_match(rule)]
        _reject_offload_with_verdict(rule)
        statements = self._statements(rule)
        flag_clauses = self._flag_clauses(rule)
        if "action" not in rule and not statements and not rule.get("counter"):
            raise BuildError(f"rule has neither an action nor a statement: {rule!r}")

        addr = {k: self._addr(rule[k]) for k in ("saddr", "daddr") if k in rule}
        if addr:
            families = sorted(set.intersection(*[set(a) for a in addr.values()]))
            if not families:
                raise BuildError(f"rule mixes incompatible address families: {rule!r}")
            # icmp exists only in IPv4 and icmpv6 only in IPv6: the other
            # family's line could never match, so it isn't rendered
            only = _PROTO_FAMILY.get(str(rule.get("proto")))
            if only is not None:
                if only not in families:
                    raise BuildError(
                        f"`proto: {rule['proto']}` is {'IPv4' if only == 'ip' else 'IPv6'}"
                        f"-only, but the rule's addresses are "
                        f"{'IPv6' if only == 'ip' else 'IPv4'}: {rule!r}"
                    )
                families = [only]
        else:
            families = [None]

        lines = []
        for fam in families:
            for flag_clause in flag_clauses:
                parts: list[str] = []
                if "iifname" in rule:
                    parts.append(f"iifname {self._iface(rule['iifname'])}")
                if "oifname" in rule:
                    parts.append(f"oifname {self._iface(rule['oifname'])}")
                # iif/oif match the interface *index* (resolved from the name at
                # load): faster, but the ruleset fails to load if the interface
                # is absent, and a recreated interface needs a reload. Prefer
                # for static-named interfaces; see docs/best-practices.md §8a.
                if "iif" in rule:
                    parts.append(f"iif {self._iface(rule['iif'], index=True)}")
                if "oif" in rule:
                    parts.append(f"oif {self._iface(rule['oif'], index=True)}")
                if "saddr" in rule:
                    parts.append(f"{fam} saddr {addr['saddr'][fam]}")
                if "daddr" in rule:
                    parts.append(f"{fam} daddr {addr['daddr'][fam]}")
                if rule.get("ct"):
                    parts.append("ct state " + ",".join(rule["ct"]))
                if "mark" in rule:
                    parts.append(f"meta mark {rule['mark']}")
                if "icmp-type" in rule:
                    proto = rule.get("proto")
                    if proto not in ("icmp", "icmpv6"):
                        raise BuildError(
                            f"icmp-type needs `proto: icmp` or `proto: icmpv6`, got {proto!r}: {rule!r}"
                        )
                    types = rule["icmp-type"]
                    types = types if isinstance(types, list) else [types]
                    parts.append(f"{proto} type {_anon([str(t) for t in types])}")
                else:
                    parts.extend(self._proto_ports(rule))
                if flag_clause:
                    parts.append(flag_clause)
                parts.extend(statements)
                if rule.get("counter"):
                    parts.append(self._counter(rule["counter"]))
                if "action" in rule:
                    parts.append(self._verdict(rule["action"]))
                lines.append(" ".join(p for p in parts if p))
        return lines

    # -- tcp flags ---------------------------------------------------------- #
    def _flag_clauses(self, rule: dict) -> list:
        flags = rule.get("flags")
        if flags is None:
            return [None]
        checks = flags if isinstance(flags, list) else [flags]
        return [_flag_clause(c) for c in checks]

    # -- statements (non-terminal: rate/quota/log/mangle) ------------------- #
    def _statements(self, rule: dict) -> list[str]:
        out = []
        # meter first: a per-key rate gate (`update @set { <key> limit rate }`)
        # — it gates whatever follows (typically a log), so it renders ahead.
        if "meter" in rule:
            out.append(self._meter(rule["meter"]))
        if "limit" in rule:
            out.append(f"limit rate {rule['limit']}")
        if "quota" in rule:
            out.append(f"quota {rule['quota']}")
        # only `log: false` means no log; `log: {}` is a plain log (an empty
        # mapping is falsy, so test for False, not for truthiness)
        if "log" in rule and rule["log"] is not False:
            out.append(self._log(rule["log"]))
        if "set-mark" in rule:
            out.append(f"meta mark set {rule['set-mark']}")
        if "set-mss" in rule:
            mss = rule["set-mss"]
            target = "rt mtu" if str(mss) in ("pmtu", "rt-mtu", "rt_mtu") else str(mss)
            out.append(f"tcp flags syn tcp option maxseg size set {target}")
        if "flow-offload" in rule:
            name = rule["flow-offload"]
            if self.flowtables is not None and name not in self.flowtables:
                # nft would say only "Could not process rule: No such file or
                # directory", pointing at the generated file
                declared = ", ".join(sorted(self.flowtables)) or "none"
                raise BuildError(
                    f"flowtable {name!r} is not declared in the table's "
                    f"`flowtables:` (declared: {declared})"
                )
            out.append(f"flow add @{name}")
        return out

    _METER_KEYS = frozenset({"saddr", "daddr", "iifname", "oifname"})
    _METER_SPEC_KEYS = frozenset({"set", "key", "rate", "timeout"})

    def _meter(self, spec) -> str:
        """`update @set { <key> [timeout T] limit rate R }` — per-key rate
        limiting on a dynamic set. The typical use is per-source drop-log
        sampling; the author declares the dynamic set (`flags: [dynamic,
        timeout]`)."""
        if not isinstance(spec, dict):
            raise BuildError(f"`meter:` must be a mapping: {spec!r}")
        unknown = set(spec) - self._METER_SPEC_KEYS
        if unknown:
            raise BuildError(f"unknown meter key(s) {sorted(unknown)}: {spec!r}")
        name = spec.get("set")
        if name not in self.named:
            raise BuildError(f"meter set @{name} is not a declared set: {spec!r}")
        s = self.named[name]
        if "dynamic" not in s.flags:
            raise BuildError(
                f"meter set @{name} must be declared `flags: [dynamic]`: {spec!r}"
            )
        key = spec.get("key")
        if key not in self._METER_KEYS:
            raise BuildError(
                f"meter key {key!r} not supported (use {sorted(self._METER_KEYS)})"
            )
        rate = spec.get("rate")
        if not rate:
            raise BuildError(f"`meter:` needs a `rate:`: {spec!r}")
        if key in ("saddr", "daddr"):
            if s.type not in ("ipv4_addr", "ipv6_addr"):
                raise BuildError(
                    f"meter key {key!r} needs an address set, got {s.type}: {spec!r}"
                )
            keyexpr = f"{'ip' if s.type == 'ipv4_addr' else 'ip6'} {key}"
        else:  # iifname / oifname
            if s.type != "ifname":
                raise BuildError(
                    f"meter key {key!r} needs an ifname set, got {s.type}: {spec!r}"
                )
            keyexpr = key
        timeout = f"timeout {spec['timeout']} " if spec.get("timeout") else ""
        return f"update @{name} {{ {keyexpr} {timeout}limit rate {rate} }}"

    def _counter(self, value) -> str:
        if value is True:
            return "counter"
        name = str(value)
        if name not in self.counters:
            raise BuildError(
                f"counter {name!r} is not declared in the table's `counters:` list"
            )
        return f"counter name {name}"

    @staticmethod
    def _log(value) -> str:
        if value is True:
            return "log"
        parts = ["log"]
        if value.get("prefix"):
            parts.append(f'prefix "{value["prefix"]}"')
        if value.get("level"):
            parts.append(f"level {value['level']}")
        if value.get("group") is not None:
            parts.append(f"group {value['group']}")
        return " ".join(parts)

    # -- match helpers ------------------------------------------------------ #
    def _addr(self, value) -> dict[str, str]:
        """Return {family('ip'|'ip6'): nft token} for an address match.

        A list is an inline set of its elements, each resolved as a single
        value would be (group or literal), split per family; a named set
        can't sit inside a list (nft has no set-in-anonymous-set)."""
        if isinstance(value, list):
            buckets: dict[str, list[str]] = {}
            for item in value:
                self._no_set_in_list(item)
                for fam, items in self._addr_items(item).items():
                    buckets.setdefault(fam, []).extend(items)
            return {
                fam: _anon(list(dict.fromkeys(items)))
                for fam, items in sorted(buckets.items())
            }
        name = value[1:] if isinstance(value, str) and value.startswith("@") else value
        if name in self.named:
            s = self.named[name]
            if s.type not in ("ipv4_addr", "ipv6_addr"):
                raise BuildError(f"set @{name} is {s.type}, not an address set")
            return {("ip" if s.type == "ipv4_addr" else "ip6"): f"@{name}"}
        if isinstance(value, str) and value.startswith("@"):
            raise BuildError(f"unknown set reference {value!r}")
        return {fam: _anon(items) for fam, items in self._addr_items(value).items()}

    def _no_set_in_list(self, item) -> None:
        if isinstance(item, str) and (item.startswith("@") or item in self.named):
            raise BuildError(
                f"set {item!r} can't go inside a list — nft has no set inside an "
                f"inline set; use it on its own"
            )

    def _addr_items(self, value) -> dict[str, list[str]]:
        """A network group or an IP/CIDR literal -> {family: [addresses]}."""
        if value in self.defs.networks:
            addrs = self.defs.network(value)
            if not addrs:
                raise BuildError(f"network group {value!r} resolves to no addresses")
            buckets: dict[str, list[str]] = {}
            for a in addrs:
                fam = (
                    "ip"
                    if ipaddress.ip_network(a, strict=False).version == 4
                    else "ip6"
                )
                buckets.setdefault(fam, []).append(a)
            return buckets
        try:
            fam = (
                "ip"
                if ipaddress.ip_network(str(value), strict=False).version == 4
                else "ip6"
            )
        except ValueError:
            raise BuildError(
                f"address {value!r} is not a known network group, set, or IP/CIDR"
            ) from None
        return {fam: [str(value)]}

    def _iface(self, value, index: bool = False) -> str:
        # Strict: an unknown name would otherwise render as a literal device and
        # silently never match — a typo'd group must fail the build instead. A
        # genuine one-off device gets a one-device group under `interfaces:`.
        if isinstance(value, list):  # an inline set of the groups' devices
            devices: list[str] = []
            for item in value:
                self._no_set_in_list(item)
                devices.extend(self._iface_devices(item))
            return _anon([f'"{d}"' for d in dict.fromkeys(devices)])
        if value in self.named:
            s = self.named[value]
            if s.type != "ifname":
                raise BuildError(f"set @{value} is {s.type}, not an interface set")
            if index:
                # an `ifname` set holds names; iif/oif compare interface
                # indexes — nft rejects the pair as a datatype mismatch
                raise BuildError(
                    f"`iif`/`oif` match interface indexes, but set @{value} holds "
                    f"names — use `iifname`/`oifname` with the set, or "
                    f"`iif`/`oif` with the group inline (not under `sets:`)"
                )
            return f"@{value}"
        return _anon([f'"{d}"' for d in self._iface_devices(value)])

    def _iface_devices(self, value) -> list[str]:
        if value in self.defs.interfaces:
            devices = self.defs.interface(value)
            if not devices:
                raise BuildError(f"interface group {value!r} resolves to no devices")
            return devices
        raise BuildError(
            f"unknown interface group {value!r} (define it under `interfaces:`)"
        )

    def _proto_ports(self, rule: dict) -> list[str]:
        proto = rule.get("proto")
        if "sport" in rule or "dport" in rule:
            if not proto:
                raise BuildError(f"port match needs a proto: {rule!r}")
            out, pairs = [], []
            for key in ("sport", "dport"):
                if key not in rule:
                    continue
                value = rule[key]
                if self._is_pair_set(value):
                    self._check_pair_proto(value, proto)
                    pairs.append(f"meta l4proto . th {key} @{value}")
                else:
                    out.append(f"{proto} {key} {self._port(value, proto)}")
            # a pair lookup carries no proto of its own: the rule's `proto:`
            # needs its own match unless a `<proto> sport/dport` already pins it
            if pairs and not out:
                out.append(f"meta l4proto {proto}")
            return out + pairs
        if proto:
            return [f"meta l4proto {proto}"]
        return []

    def _is_pair_set(self, value) -> bool:
        s = self.named.get(value) if isinstance(value, str) else None
        return s is not None and s.type == SERVICE_PAIR_TYPE

    def _check_pair_proto(self, name: str, proto: str) -> None:
        """A service pair set used with `proto:` must hold ports for it —
        the same "no <proto> ports" error the inline form gives."""
        service = self.named[name].service
        if service is not None and not self.defs.service_ports(service, proto):
            raise BuildError(f"service {service!r} has no {proto} ports")

    def _port(self, value, proto: str) -> str:
        if isinstance(value, list):  # an inline set of each element's ports
            ports: list[str] = []
            for item in value:
                self._no_set_in_list(item)
                ports.extend(self._port_items(item, proto))
            return _anon(list(dict.fromkeys(ports)))
        if isinstance(value, str) and value in self.named:
            s = self.named[value]
            if s.type != "inet_service":
                raise BuildError(f"set @{value} is {s.type}, not a port set")
            return f"@{value}"
        return _anon(self._port_items(value, proto))

    def _port_items(self, value, proto: str) -> list[str]:
        """A service (its ports for `proto`) or a port/range literal."""
        if isinstance(value, str) and value in self.defs.services:
            ports = self.defs.service_ports(value, proto)
            if not ports:
                raise BuildError(f"service {value!r} has no {proto} ports")
            return ports
        if isinstance(value, int) or (
            isinstance(value, str) and _PORT_LITERAL.match(value)
        ):
            return [str(value)]
        raise BuildError(
            f"port {value!r} is not a known service group or a port/range "
            f"(define it under `services:`)"
        )

    _VMAP_KEYS = {
        "iifname": "iifname",
        "oifname": "oifname",
        "iif": "iif",  # interface index (see iif/oif note in render)
        "oif": "oif",
        "proto": "meta l4proto",
        # ports never render alone (th = any protocol): a dport/sport vmap is a
        # `meta l4proto . th dport` pair lookup, or a concat whose own `proto`
        # column pins the protocol per row (_vmap_port_pairs)
        "dport": "th dport",
        "sport": "th sport",
        "mark": "meta mark",
        "state": "ct state",
    }
    _VMAP_ADDR = {"saddr", "daddr"}  # family-aware (single-key only)
    _VMAP_HELP = "iifname/oifname/proto/dport/sport/mark/state/saddr/daddr"

    def _vmap(self, spec: dict) -> str:
        if not isinstance(spec, dict):
            raise BuildError(
                f"`vmap:` needs a mapping with `key:` and `map:`, got {spec!r}"
            )
        unknown = set(spec) - {"key", "map"}
        if unknown:
            raise BuildError(f"unknown vmap key(s) {sorted(unknown)}: {spec!r}")
        key = spec.get("key")
        if isinstance(key, list):  # concatenated key
            return self._concat_vmap(spec, key)
        if key in self._VMAP_ADDR:  # family-aware address vmap
            return self._addr_vmap(spec, key)
        keyexpr = self._VMAP_KEYS.get(key)
        if keyexpr is None:
            raise BuildError(f"vmap key {key!r} not supported (use {self._VMAP_HELP})")
        mapping = spec.get("map")
        if not isinstance(mapping, dict) or not mapping:
            raise BuildError(
                f"a {key} vmap needs a non-empty `map:` of value -> verdict: {spec!r}"
            )
        ports = key in ("dport", "sport")
        if ports:  # a service is proto + port: keep both in the lookup
            keyexpr = f"meta l4proto . {keyexpr}"
        entries = []
        for k, verdict in mapping.items():
            v = self._vmap_verdict(verdict)
            toks = (
                [f"{p} . {port}" for p, port in self._vmap_port_pairs(key, k)]
                if ports
                else self._vmap_lit_tokens(key, k)
            )
            entries.extend(f"{tok} : {v}" for tok in toks)
        return f"{keyexpr} vmap {render_literal(entries, BODY_INDENT)}"

    def _addr_vmap(self, spec: dict, key: str) -> str:
        """Address vmap (`saddr`/`daddr`) -> `ip saddr vmap` / `ip6 saddr vmap`.

        Network groups resolve to their members; a vmap is single-family, so all
        keys must share one family (mixing v4/v6 is an error — split per family).
        """
        mapping = spec.get("map")
        if not isinstance(mapping, dict):
            raise BuildError(
                f"a {key} vmap needs a `map:` of address -> verdict: {spec!r}"
            )
        fam, entries = None, []
        for k, verdict in mapping.items():
            kfam, cidrs = self._vmap_addr_tokens(key, k)
            fam = self._one_family(key, fam, kfam)
            v = self._vmap_verdict(verdict)
            entries.extend(f"{c} : {v}" for c in cidrs)
        return f"{fam} {key} vmap {render_literal(entries, BODY_INDENT)}"

    def _vmap_addr_tokens(self, key: str, value) -> tuple:
        """One address vmap key -> (family, [cidrs]); a network group expands."""
        cidrs = (
            self.defs.network(value) if value in self.defs.networks else [str(value)]
        )
        if not cidrs:
            raise BuildError(f"vmap {key} group {value!r} resolves to no addresses")
        fams = set()
        for a in cidrs:
            try:
                ver = ipaddress.ip_network(a, strict=False).version
            except ValueError as e:
                raise BuildError(
                    f"vmap {key} key {a!r} is not an address/CIDR or known network ({e})"
                ) from e
            fams.add("ip" if ver == 4 else "ip6")
        if len(fams) > 1:
            raise BuildError(f"vmap {key} value {value!r} mixes IP families")
        return fams.pop(), cidrs

    def _concat_vmap(self, spec: dict, keys: list) -> str:
        """Concatenated vmap, e.g. ``key: [iifname, oifname]`` -> ``iifname . oifname vmap``.

        ``map`` is a list of ``{match: [v0, v1, …], <verdict>}`` entries; each
        match value resolves like a normal iifname/oifname (an interface group expands to
        its devices, cartesian-producting into elements), proto stays literal.
        """
        for k in keys:
            if k not in self._VMAP_KEYS and k not in self._VMAP_ADDR:
                raise BuildError(
                    f"vmap key {k!r} not supported (use {self._VMAP_HELP})"
                )
        mapping = spec.get("map")
        if not isinstance(mapping, list):
            raise BuildError(
                f"a concat vmap (`key: {keys}`) needs a list `map:` of "
                f"`{{match: [...], <verdict>}}` entries: {spec!r}"
            )
        # a `proto` column pins each row's protocol, so a port column takes that
        # proto's ports; without one, a port column is a proto . port pair
        proto_col = keys.index("proto") if "proto" in keys else None
        fam, entries = None, []
        for entry in mapping:
            if not isinstance(entry, dict) or "match" not in entry:
                raise BuildError(f"concat vmap entry needs `match: [...]`: {entry!r}")
            match = entry["match"]
            if not isinstance(match, list) or len(match) != len(keys):
                raise BuildError(
                    f"concat vmap `match` must list {len(keys)} value(s), "
                    f"one per key {keys}: {entry!r}"
                )
            rest = {k: v for k, v in entry.items() if k != "match"}
            if len(rest) != 1:
                raise BuildError(
                    f"concat vmap entry needs exactly one verdict (`action:`, "
                    f"`jump:` or `goto:`): {entry!r}"
                )
            # `action: <verdict>` like a rule's, or the `jump:`/`goto:` shorthand
            v = self._vmap_verdict(rest.get("action", rest))
            row_proto = str(match[proto_col]) if proto_col is not None else None
            cols = []
            for kt, value in zip(keys, match, strict=True):
                if kt in self._VMAP_ADDR:  # family-aware position
                    kfam, toks = self._vmap_addr_tokens(kt, value)
                    fam = self._one_family(kt, fam, kfam)
                    cols.append(toks)
                else:
                    cols.append(self._concat_col_tokens(kt, value, row_proto))
            for combo in itertools.product(*cols):
                entries.append(f"{' . '.join(combo)} : {v}")
        if any(k in self._VMAP_ADDR for k in keys) and fam is None:
            raise BuildError(
                f"concat vmap with an address key needs at least one entry: {spec!r}"
            )
        keyexprs = [
            f"{fam} {k}"
            if k in self._VMAP_ADDR
            else self._concat_col_expr(k, proto_col)
            for k in keys
        ]
        return f"{' . '.join(keyexprs)} vmap {render_literal(entries, BODY_INDENT)}"

    def _concat_col_tokens(self, keytype: str, value, row_proto) -> list:
        """Element tokens for one non-address concat column. A port column
        takes the row's proto's ports, or is a proto . port pair without one."""
        if keytype not in ("dport", "sport"):
            return self._vmap_lit_tokens(keytype, value)
        pairs = self._vmap_port_pairs(keytype, value, row_proto)
        if row_proto:
            return [port for _p, port in pairs]
        return [f"{p} . {port}" for p, port in pairs]

    def _concat_col_expr(self, keytype: str, proto_col) -> str:
        if keytype in ("dport", "sport") and proto_col is None:
            return f"meta l4proto . {self._VMAP_KEYS[keytype]}"
        return self._VMAP_KEYS[keytype]

    def _vmap_lit_tokens(self, keytype: str, value) -> list:
        """Non-address vmap element tokens for one key — groups and services expand."""
        if keytype in ("iifname", "oifname", "iif", "oif"):
            if value in self.defs.interfaces:
                devices = self.defs.interface(value)
                if not devices:
                    raise BuildError(
                        f"vmap {keytype} group {value!r} resolves to no devices"
                    )
                return [f'"{d}"' for d in devices]
            raise BuildError(
                f"vmap {keytype} value {value!r} is not a known interface group "
                f"(define it under `interfaces:`)"
            )
        return [str(value)]  # proto / mark / state literal

    def _vmap_port_pairs(self, keytype: str, value, proto: str | None = None):
        """A dport/sport vmap value -> [(proto, port)]. A service keeps each
        port's own proto; ``N/proto`` is a literal pair; a bare number has no
        proto, so it is only accepted when the row pins one (``proto``)."""
        if isinstance(value, str) and value in self.defs.services:
            pairs = self.defs.service(value)
            if proto is not None:
                pairs = [(p, port) for p, port in pairs if p == proto]
                if not pairs:
                    raise BuildError(f"service {value!r} has no {proto} ports")
            if not pairs:
                raise BuildError(
                    f"vmap {keytype} service {value!r} resolves to no ports"
                )
            return pairs
        text = str(value)
        port, sep, lproto = text.rpartition("/")
        if sep and _PORT_LITERAL.match(port) and lproto:
            if proto is not None and lproto != proto:
                raise BuildError(
                    f"vmap {keytype} value {text!r} is {lproto}, but the row's "
                    f"proto is {proto}"
                )
            return [(lproto, port)]
        if _PORT_LITERAL.match(text):
            if proto is not None:
                return [(proto, text)]
            raise BuildError(
                f"vmap {keytype} value {text!r} has no protocol — a port vmap "
                f"matches proto . port; write {text}/tcp (or /udp) or use a service"
            )
        raise BuildError(
            f"vmap {keytype} value {value!r} is not a known service, "
            f"`port/proto`, or a port/range"
        )

    def _one_family(self, key: str, fam, kfam: str) -> str:
        if fam is None:
            return kfam
        if fam != kfam:
            raise BuildError(
                f"vmap {key} mixes IP families ({fam} and {kfam}); a vmap is "
                f"single-family — split into per-family vmaps"
            )
        return fam

    def _concat_match(self, rule: dict) -> str:
        name = rule["set"]
        s = self.named.get(name)
        if s is None or not s.concat_fields:
            raise BuildError(f"`set: {name}` is not a declared concat set")
        extra = set(rule) - _CONCAT_RULE_KEYS
        if extra:
            raise BuildError(
                f"a concat rule (`set: {name}`) can't carry match keys {sorted(extra)}: {rule!r}"
            )
        _reject_offload_with_verdict(rule)
        if (
            "action" not in rule
            and not self._statements(rule)
            and not rule.get("counter")
        ):
            raise BuildError(
                f"concat rule has neither an action nor a statement: {rule!r}"
            )

        exprs = []
        for f in s.concat_fields:
            if f in ("saddr", "daddr"):
                exprs.append(f"{s.concat_family} {f}")
            elif f in ("sport", "dport"):
                exprs.append(f"{s.concat_proto} {f}")
            elif f == "mark":
                exprs.append("meta mark")
            else:  # iifname / oifname: field name is the nft expression
                exprs.append(f)
        parts = [" . ".join(exprs) + f" @{name}"]
        parts.extend(self._statements(rule))
        if rule.get("counter"):
            parts.append(self._counter(rule["counter"]))
        if "action" in rule:
            parts.append(self._verdict(rule["action"]))
        return " ".join(p for p in parts if p)

    _VMAP_VERDICTS = ("accept", "drop", "return", "continue")

    def _vmap_verdict(self, value) -> str:
        """A vmap value: only real verdicts. `reject`, `masquerade` and NAT are
        statements, not verdicts — nft refuses them in a vmap (syntax error)."""
        if isinstance(value, str):
            if value in self._VMAP_VERDICTS:
                return value
            raise BuildError(
                f"{value!r} can't go in a vmap — a vmap can only route "
                f"({', '.join(self._VMAP_VERDICTS)}, jump, goto); use `jump:` to "
                f"a chain that does it"
            )
        if isinstance(value, dict) and len(value) == 1:
            ((kind, target),) = value.items()
            if kind in ("jump", "goto") and isinstance(target, str) and target:
                return f"{kind} {target}"
        raise BuildError(
            f"vmap verdict must be one of {', '.join(self._VMAP_VERDICTS)}, or "
            f"`jump:`/`goto:` a chain, got {value!r}"
        )

    def _verdict(self, action) -> str:
        if isinstance(action, dict):
            ((kind, target),) = action.items()
            if kind in ("jump", "goto"):
                return f"{kind} {target}"
            if kind in ("dnat", "snat"):
                if isinstance(target, dict):  # map form: dnat to <proto> dport map {…}
                    return self._nat_map(kind, target)
                target = self._nat_target(kind, target)
                # inet tables require a family qualifier (`dnat ip to`); infer it
                # from the target address. Required in inet, accepted in ip/ip6.
                return f"{kind} {_nat_family(target)} to {target}"
            raise BuildError(f"unknown action: {action!r}")
        return str(action)

    def _nat_target(self, kind: str, target) -> str:
        """A bare dnat/snat target: a network group resolves to its one address
        (site overlays put the per-site NAT address behind a shared name)."""
        t = str(target)
        if t in self.defs.networks:
            addrs = self.defs.network(t)
            if len(addrs) != 1:
                raise BuildError(
                    f"{kind} target {t!r} resolves to {len(addrs)} addresses; "
                    f"a nat target takes one"
                )
            return addrs[0]
        return t

    def _nat_map(self, kind: str, spec: dict) -> str:
        """`dnat/snat: {proto, map, key?}` -> `dnat ip to tcp dport map { k : v, … }`."""
        key = spec.get("key", "dport")
        if key not in ("dport", "sport"):
            raise BuildError(f"{kind} map key must be dport/sport, got {key!r}")
        proto = spec.get("proto")
        if not proto:
            raise BuildError(f"{kind} map needs `proto:` for the {key} key")
        mapping = spec.get("map")
        if not mapping:
            raise BuildError(f"{kind} map needs `map:` entries: {spec!r}")
        entries, families = [], set()
        for k, v in mapping.items():
            keytok = self._map_port_key(kind, k, proto)
            valtok = str(v)
            if valtok in self.defs.networks:
                addrs = self.defs.network(valtok)
                if len(addrs) != 1:
                    raise BuildError(
                        f"{kind} map target {valtok!r} resolves to {len(addrs)} "
                        f"addresses; a map target takes one"
                    )
                valtok = addrs[0]
            if _has_port(valtok):
                raise BuildError(
                    f"{kind} map target {valtok!r} has a port; map targets are "
                    f"address-only for now (port translation in a map is unsupported)"
                )
            families.add(_nat_family(valtok))
            entries.append(f"{keytok} : {valtok}")
        if len(families) > 1:
            raise BuildError(f"{kind} map mixes v4 and v6 targets: {sorted(families)}")
        fam = families.pop()
        return (
            f"{kind} {fam} to {proto} {key} map {render_literal(entries, BODY_INDENT)}"
        )

    def _map_port_key(self, kind: str, val, proto: str) -> str:
        val = str(val)
        if val in self.defs.services:
            ports = self.defs.service_ports(val, proto)
            if len(ports) != 1:
                raise BuildError(
                    f"{kind} map key service {val!r} has {len(ports)} {proto} port(s); need one"
                )
            return ports[0]
        return val


_FLOWTABLE_KEYS = frozenset({"name", "hook", "priority", "devices"})
_CHAIN_KEYS = frozenset(
    {"name", "hook", "type", "priority", "policy", "rules", "comment"}
)


def build_flowtables(specs: list, defs: Definitions) -> list[Flowtable]:
    out = []
    for spec in specs or []:
        unknown = set(spec) - _FLOWTABLE_KEYS
        if unknown:
            raise BuildError(f"unknown flowtable key(s) {sorted(unknown)}: {spec!r}")
        if "name" not in spec:
            raise BuildError(f"flowtable needs a `name:`: {spec!r}")
        check_nft_name(spec["name"], "flowtable")
        devices: list[str] = []
        for dev in spec.get("devices", []):
            if dev not in defs.interfaces:
                raise BuildError(
                    f"flowtable {spec['name']!r}: device {dev!r} is not a known "
                    f"interface group (define it under `interfaces:`)"
                )
            devices.extend(f'"{d}"' for d in defs.interface(dev))
        if not devices:
            raise BuildError(f"flowtable {spec['name']!r} resolves to no devices")
        out.append(
            Flowtable(
                name=spec["name"],
                hook=spec.get("hook", "ingress"),
                priority=resolve_priority(spec.get("priority", 0)),
                devices=devices,
            )
        )
    return out


def build_chain(spec: dict, renderer: RuleRenderer) -> Chain:
    unknown = set(spec) - _CHAIN_KEYS
    if unknown:
        raise BuildError(f"unknown chain key(s) {sorted(unknown)}: {spec!r}")
    if "name" not in spec:
        raise BuildError(f"chain needs a `name:`: {spec!r}")
    check_nft_name(spec["name"], "chain")
    base_only = sorted(set(spec) & {"type", "priority", "policy"})
    if base_only and "hook" not in spec:
        # without a hook it's a regular chain (reached only by jump/goto), which
        # has no type/priority/policy — dropping them silently would leave an
        # intended `policy: drop` filter attached to nothing.
        raise BuildError(
            f"chain {spec['name']!r} has {base_only} but no `hook:` — add a "
            f"hook for a base chain, or remove them for a regular chain"
        )
    rule_lines: list[str] = []
    for r in spec.get("rules", []):
        if isinstance(r, dict) and "include" in r:
            # render_tables expands includes before this runs; one left here
            # means a caller skipped that step — fail, don't drop it.
            raise BuildError(
                f"unresolved include {r['include']!r} — includes are expanded "
                f"by render_tables"
            )
        rule_lines.extend(renderer.render(r))
    chain = Chain(name=spec["name"], rules=rule_lines)
    if "comment" in spec:
        chain.comment = check_comment(spec["comment"], f"chain {spec['name']!r}")
    if "hook" in spec:
        chain.hook = spec["hook"]
        chain.type = spec.get("type", "filter")
        chain.priority = resolve_priority(spec.get("priority", 0))
        # drop is only a sane default for filter chains: on a nat/route chain it
        # would drop every flow the chain's rules don't match.
        chain.policy = spec.get(
            "policy", "drop" if chain.type == "filter" else "accept"
        )
    return chain

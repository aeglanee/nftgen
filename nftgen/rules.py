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
    BuildError,
    Chain,
    Flowtable,
    NamedSet,
    render_literal,
)

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
        self, defs: Definitions, named: dict[str, NamedSet], counters=frozenset()
    ):
        self.defs = defs
        self.named = named
        self.counters = frozenset(counters)

    # -- public ------------------------------------------------------------- #
    def render(self, rule: dict) -> list[str]:  # noqa: PLR0912, PLR0915 - dispatches per rule key
        # Reject typos/unknown keys loudly: an unread key silently weakens a rule
        # (e.g. `dprot:` for `dport:`) and nft -c can't catch it (still valid nft).
        unknown = set(rule) - _KNOWN_RULE_KEYS
        if unknown:
            hint = (
                " (renamed in v0.4.0: iif->iifname, oif->oifname)"
                if unknown & {"iif", "oif"}
                else ""
            )
            raise BuildError(f"unknown rule key(s) {sorted(unknown)}{hint}: {rule!r}")
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
        if "log" in rule:
            out.append(self._log(rule["log"]))
        if "set-mark" in rule:
            out.append(f"meta mark set {rule['set-mark']}")
        if "set-mss" in rule:
            mss = rule["set-mss"]
            target = "rt mtu" if str(mss) in ("pmtu", "rt-mtu", "rt_mtu") else str(mss)
            out.append(f"tcp flags syn tcp option maxseg size set {target}")
        if "flow-offload" in rule:
            out.append(f"flow add @{rule['flow-offload']}")
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
    def _addr(self, value: str) -> dict[str, str]:
        """Return {family('ip'|'ip6'): nft token} for an address match."""
        name = value[1:] if isinstance(value, str) and value.startswith("@") else value
        if name in self.named:
            s = self.named[name]
            if s.type not in ("ipv4_addr", "ipv6_addr"):
                raise BuildError(f"set @{name} is {s.type}, not an address set")
            return {("ip" if s.type == "ipv4_addr" else "ip6"): f"@{name}"}
        if isinstance(value, str) and value.startswith("@"):
            raise BuildError(f"unknown set reference {value!r}")
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
            return {fam: _anon(addrs) for fam, addrs in buckets.items()}
        try:
            fam = (
                "ip"
                if ipaddress.ip_network(value, strict=False).version == 4
                else "ip6"
            )
        except ValueError:
            raise BuildError(
                f"address {value!r} is not a known network group, set, or IP/CIDR"
            ) from None
        return {fam: value}

    def _iface(self, value: str) -> str:
        # Strict: an unknown name would otherwise render as a literal device and
        # silently never match — a typo'd group must fail the build instead. A
        # genuine one-off device gets a one-device group under `interfaces:`.
        if value in self.named:
            s = self.named[value]
            if s.type != "ifname":
                raise BuildError(f"set @{value} is {s.type}, not an interface set")
            return f"@{value}"
        if value in self.defs.interfaces:
            devices = self.defs.interface(value)
            if not devices:
                raise BuildError(f"interface group {value!r} resolves to no devices")
            return _anon([f'"{d}"' for d in devices])
        raise BuildError(
            f"unknown interface group {value!r} (define it under `interfaces:`)"
        )

    def _proto_ports(self, rule: dict) -> list[str]:
        proto = rule.get("proto")
        if "sport" in rule or "dport" in rule:
            if not proto:
                raise BuildError(f"port match needs a proto: {rule!r}")
            out = []
            if "sport" in rule:
                out.append(f"{proto} sport {self._port(rule['sport'], proto)}")
            if "dport" in rule:
                out.append(f"{proto} dport {self._port(rule['dport'], proto)}")
            return out
        if proto:
            return [f"meta l4proto {proto}"]
        return []

    def _port(self, value, proto: str) -> str:
        if value in self.named:
            s = self.named[value]
            if s.type != "inet_service":
                raise BuildError(f"set @{value} is {s.type}, not a port set")
            return f"@{value}"
        if isinstance(value, str) and value in self.defs.services:
            ports = self.defs.service_ports(value, proto)
            if not ports:
                raise BuildError(f"service {value!r} has no {proto} ports")
            return _anon(ports)
        if isinstance(value, int) or (
            isinstance(value, str) and _PORT_LITERAL.match(value)
        ):
            return str(value)
        raise BuildError(
            f"port {value!r} is not a known service group or a port/range "
            f"(define it under `services:`)"
        )

    _VMAP_KEYS = {
        "iifname": "iifname",
        "oifname": "oifname",
        "proto": "meta l4proto",
        "dport": "th dport",
        "sport": "th sport",  # transport-agnostic ports
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
            hint = (
                " (renamed in v0.4.0: iif->iifname, oif->oifname)"
                if unknown & {"iif", "oif"}
                else ""
            )
            raise BuildError(f"unknown vmap key(s) {sorted(unknown)}{hint}: {spec!r}")
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
        entries = []
        for k, verdict in mapping.items():
            v = self._verdict(verdict)
            entries.extend(f"{tok} : {v}" for tok in self._vmap_lit_tokens(key, k))
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
            v = self._verdict(verdict)
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
            verdict = {k: v for k, v in entry.items() if k != "match"}
            if len(verdict) != 1:
                raise BuildError(
                    f"concat vmap entry needs exactly one verdict: {entry!r}"
                )
            v = self._verdict(verdict)
            cols = []
            for i, kt in enumerate(keys):
                if kt in self._VMAP_ADDR:  # family-aware position
                    kfam, toks = self._vmap_addr_tokens(kt, match[i])
                    fam = self._one_family(kt, fam, kfam)
                    cols.append(toks)
                else:
                    cols.append(self._vmap_lit_tokens(kt, match[i]))
            for combo in itertools.product(*cols):
                entries.append(f"{' . '.join(combo)} : {v}")
        if any(k in self._VMAP_ADDR for k in keys) and fam is None:
            raise BuildError(
                f"concat vmap with an address key needs at least one entry: {spec!r}"
            )
        keyexprs = [
            f"{fam} {k}" if k in self._VMAP_ADDR else self._VMAP_KEYS[k] for k in keys
        ]
        return f"{' . '.join(keyexprs)} vmap {render_literal(entries, BODY_INDENT)}"

    def _vmap_lit_tokens(self, keytype: str, value) -> list:
        """Non-address vmap element tokens for one key — groups and services expand."""
        if keytype in ("iifname", "oifname"):
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
        if keytype in ("dport", "sport"):
            if isinstance(value, str) and value in self.defs.services:
                ports = list(
                    dict.fromkeys(port for _proto, port in self.defs.service(value))
                )
                if not ports:
                    raise BuildError(
                        f"vmap {keytype} service {value!r} resolves to no ports"
                    )
                return ports
            if isinstance(value, int) or (
                isinstance(value, str) and _PORT_LITERAL.match(value)
            ):
                return [str(value)]
            raise BuildError(
                f"vmap {keytype} value {value!r} is not a known service group or a port/range"
            )
        return [str(value)]  # proto / mark / state literal

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
_CHAIN_KEYS = frozenset({"name", "hook", "type", "priority", "policy", "rules"})


def build_flowtables(specs: list, defs: Definitions) -> list[Flowtable]:
    out = []
    for spec in specs or []:
        unknown = set(spec) - _FLOWTABLE_KEYS
        if unknown:
            raise BuildError(f"unknown flowtable key(s) {sorted(unknown)}: {spec!r}")
        if "name" not in spec:
            raise BuildError(f"flowtable needs a `name:`: {spec!r}")
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
    rule_lines: list[str] = []
    for r in spec.get("rules", []):
        if isinstance(r, dict) and "include" in r:
            continue  # includes resolved in a later phase
        rule_lines.extend(renderer.render(r))
    chain = Chain(name=spec["name"], rules=rule_lines)
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

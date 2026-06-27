"""Render structured rules into nft lines, and build chains.

A rule is a mapping of match keys + an ``action`` (or a ``raw:`` passthrough).
Address matching is family-aware: a rule with address matches renders once per
IP family common to all of them. A named group referenced in a rule becomes
``@name`` when it's a declared set, otherwise it's inlined as an anonymous set;
a literal stays literal.
"""
from __future__ import annotations

import ipaddress

from nftgen.definitions import Definitions
from nftgen.ir import BuildError, Chain, Flowtable, NamedSet

PRIORITIES = {"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0, "security": 50, "srcnat": 100}


def resolve_priority(value) -> int:
    if isinstance(value, str) and value in PRIORITIES:
        return PRIORITIES[value]
    return int(value)


def _anon(items: list[str]) -> str:
    return items[0] if len(items) == 1 else "{ " + ", ".join(items) + " }"


def _nat_family(target) -> str:
    """Infer the nft family qualifier ('ip'/'ip6') from a dnat/snat target.

    inet tables can't infer it, so `dnat to <addr>` is rejected there; the
    target address itself disambiguates. Handles `host`, `host:port`,
    `[v6]:port`, and ranges (`a-b`).
    """
    host = str(target)
    if host.startswith("["):            # [2001:db8::1]:443
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:          # 10.0.0.1:443 (single colon => host:port)
        host = host.split(":", 1)[0]
    host = host.split("-", 1)[0]        # range a-b => first endpoint
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
_TCP_ALL = ("fin", "syn", "rst", "psh", "ack", "urg")  # the 'all' keyword (excludes ecn/cwr)


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
    mask = _expand_flags(check["mask"]) if check.get("mask") is not None else list(match)
    if not mask:
        raise BuildError(f"flags check needs a mask (examined flags): {check!r}")
    if not set(match) <= set(mask):
        raise BuildError(f"flags check match is not a subset of mask: {check!r}")
    return f"tcp flags & {_fmt_flags(mask)} == {_fmt_flags(match)}"


_KNOWN_RULE_KEYS = frozenset({
    "iif", "oif", "saddr", "daddr", "ct", "mark", "proto", "sport", "dport", "flags",
    "limit", "quota", "log", "set-mark", "set-mss", "flow-offload",
    "counter", "action", "raw", "vmap", "set",
})

# a concat (`set:`) rule may only carry these alongside the set reference
_CONCAT_RULE_KEYS = frozenset({
    "set", "action", "counter", "limit", "quota", "log",
    "set-mark", "set-mss", "flow-offload",
})


class RuleRenderer:
    def __init__(self, defs: Definitions, named: dict[str, NamedSet], counters=frozenset()):
        self.defs = defs
        self.named = named
        self.counters = frozenset(counters)

    # -- public ------------------------------------------------------------- #
    def render(self, rule: dict) -> list[str]:
        # Reject typos/unknown keys loudly: an unread key silently weakens a rule
        # (e.g. `dprot:` for `dport:`) and nft -c can't catch it (still valid nft).
        unknown = set(rule) - _KNOWN_RULE_KEYS
        if unknown:
            raise BuildError(f"unknown rule key(s) {sorted(unknown)}: {rule!r}")
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
                if "iif" in rule:
                    parts.append(f"iifname {self._iface(rule['iif'])}")
                if "oif" in rule:
                    parts.append(f"oifname {self._iface(rule['oif'])}")
                if "saddr" in rule:
                    parts.append(f"{fam} saddr {addr['saddr'][fam]}")
                if "daddr" in rule:
                    parts.append(f"{fam} daddr {addr['daddr'][fam]}")
                if rule.get("ct"):
                    parts.append("ct state " + ",".join(rule["ct"]))
                if "mark" in rule:
                    parts.append(f"meta mark {rule['mark']}")
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
            buckets: dict[str, list[str]] = {}
            for a in self.defs.network(value):
                fam = "ip" if ipaddress.ip_network(a, strict=False).version == 4 else "ip6"
                buckets.setdefault(fam, []).append(a)
            return {fam: _anon(addrs) for fam, addrs in buckets.items()}
        fam = "ip" if ipaddress.ip_network(value, strict=False).version == 4 else "ip6"
        return {fam: value}

    def _iface(self, value: str) -> str:
        if value in self.named:
            return f"@{value}"
        if value in self.defs.interfaces:
            return _anon([f'"{d}"' for d in self.defs.interface(value)])
        return f'"{value}"'

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
            return f"@{value}"
        if isinstance(value, str) and value in self.defs.services:
            ports = self.defs.service_ports(value, proto)
            if not ports:
                raise BuildError(f"service {value!r} has no {proto} ports")
            return _anon(ports)
        return str(value)

    _VMAP_KEYS = {"iif": "iifname", "oif": "oifname", "proto": "meta l4proto"}

    def _vmap(self, spec: dict) -> str:
        key = spec.get("key")
        keyexpr = self._VMAP_KEYS.get(key)
        if keyexpr is None:
            raise BuildError(f"vmap key {key!r} not supported (use iif/oif/proto)")
        quote = key in ("iif", "oif")
        entries = []
        for k, verdict in spec["map"].items():
            token = f'"{k}"' if quote else str(k)
            entries.append(f"{token} : {self._verdict(verdict)}")
        return f"{keyexpr} vmap {{ {', '.join(entries)} }}"

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
        if "action" not in rule and not self._statements(rule) and not rule.get("counter"):
            raise BuildError(f"concat rule has neither an action nor a statement: {rule!r}")

        exprs = []
        for f in s.concat_fields:
            if f in ("saddr", "daddr"):
                exprs.append(f"{s.concat_family} {f}")
            elif f in ("sport", "dport"):
                exprs.append(f"{s.concat_proto} {f}")
            elif f == "mark":
                exprs.append("meta mark")
            else:  # iif / oif
                exprs.append("iifname" if f == "iif" else "oifname")
        parts = [" . ".join(exprs) + f" @{name}"]
        parts.extend(self._statements(rule))
        if rule.get("counter"):
            parts.append(self._counter(rule["counter"]))
        if "action" in rule:
            parts.append(self._verdict(rule["action"]))
        return " ".join(p for p in parts if p)

    def _verdict(self, action) -> str:
        if isinstance(action, dict):
            (kind, target), = action.items()
            if kind in ("jump", "goto"):
                return f"{kind} {target}"
            if kind in ("dnat", "snat"):
                if isinstance(target, dict):  # map form: dnat to <proto> dport map {…}
                    return self._nat_map(kind, target)
                # inet tables require a family qualifier (`dnat ip to`); infer it
                # from the target address. Required in inet, accepted in ip/ip6.
                return f"{kind} {_nat_family(target)} to {target}"
            raise BuildError(f"unknown action: {action!r}")
        return str(action)

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
        return f"{kind} {fam} to {proto} {key} map {{ {', '.join(entries)} }}"

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


def build_flowtables(specs: list, defs: Definitions) -> list[Flowtable]:
    out = []
    for spec in specs or []:
        devices: list[str] = []
        for dev in spec.get("devices", []):
            if dev in defs.interfaces:
                devices.extend(f'"{d}"' for d in defs.interface(dev))
            else:
                devices.append(f'"{dev}"')
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
        chain.policy = spec.get("policy", "drop")
    return chain

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


class RuleRenderer:
    def __init__(self, defs: Definitions, named: dict[str, NamedSet], counters=frozenset()):
        self.defs = defs
        self.named = named
        self.counters = frozenset(counters)

    # -- public ------------------------------------------------------------- #
    def render(self, rule: dict) -> list[str]:
        if "raw" in rule:
            return [rule["raw"]]
        statements = self._statements(rule)
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
            parts.extend(self._proto_ports(rule))
            parts.extend(statements)
            if rule.get("counter"):
                parts.append(self._counter(rule["counter"]))
            if "action" in rule:
                parts.append(self._verdict(rule["action"]))
            lines.append(" ".join(p for p in parts if p))
        return lines

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

    def _verdict(self, action) -> str:
        if isinstance(action, dict):
            (kind, target), = action.items()
            if kind in ("jump", "goto"):
                return f"{kind} {target}"
            if kind in ("dnat", "snat"):
                return f"{kind} to {target}"
            raise BuildError(f"unknown action: {action!r}")
        return str(action)


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

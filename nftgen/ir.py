"""Intermediate representation: typed nftables objects that render themselves.

YAML -> IR (Table / NamedSet / Chain) -> text. Keeping the model in the middle
(rather than building strings ad hoc) is what makes the output robust and lets a
JSON emitter drop in later from the same objects.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from nftgen.definitions import Definitions

_PORT_LITERAL = re.compile(r"^\d+(-\d+)?$")  # port or port-range

SET_INDENT = "    "
BODY_INDENT = "        "

# nftables scanner keywords that break when used as an object identifier
# (set / map / chain / counter / flowtable name) — nft emits a cryptic parse
# error pointing at the *generated* file, so catch it here against the YAML.
# Empirically confirmed against `nft -c`; not exhaustive — `nft -c`/`--check`
# stays the complete backstop for anything version-specific this misses.
# (Contextual words like input/forward/nat/last/state are valid names and are
# deliberately absent.)
_NFT_KEYWORDS = frozenset(
    {
        "ip",
        "ip6",
        "inet",
        "arp",
        "tcp",
        "udp",
        "sctp",
        "dccp",
        "ah",
        "esp",
        "comp",
        "icmp",
        "icmpv6",
        "igmp",
        "th",
        "meta",
        "ct",
        "rt",
        "fib",
        "fwd",
        "dup",
        "numgen",
        "jhash",
        "symhash",
        "osf",
        "socket",
        "exthdr",
        "frag",
        "vlan",
        "ether",
        "map",
        "vmap",
        "set",
        "element",
        "flow",
        "flowtable",
        "counter",
        "quota",
        "limit",
        "log",
        "reject",
        "snat",
        "dnat",
        "masquerade",
        "redirect",
        "tproxy",
        "accept",
        "drop",
        "queue",
        "continue",
        "return",
        "jump",
        "goto",
        "chain",
        "table",
        "rule",
        "mark",
        "ecn",
        "secmark",
        "notrack",
        "synproxy",
        "typeof",
        "size",
        "timeout",
        "flags",
        "type",
        "hook",
        "device",
        "priority",
        "policy",
        "comment",
    }
)


def check_nft_name(name, kind: str) -> None:
    """Reject a reserved nftables keyword used as an object name (§strict
    authoring surface: fail early with a clear message instead of leaking a
    cryptic nft parse error at deploy time)."""
    if name in _NFT_KEYWORDS:
        raise BuildError(
            f"{kind} name {name!r} is a reserved nftables keyword — rename it "
            f"(it would render to a ruleset nft can't parse)"
        )


_WRAP_AT = 4  # a { … } literal with this many entries renders one per line


def render_literal(entries: list[str], base_indent: str) -> str:
    """Render a ``{ … }`` literal — single-line while small, one entry per
    line from ``_WRAP_AT`` entries up. Large dispatch tables and element lists
    stay readable, and a membership change is a one-line git diff in the
    committed artifact instead of an opaque long-line change."""
    if len(entries) < _WRAP_AT:
        return "{ " + ", ".join(entries) + " }"
    body = ",\n".join(f"{base_indent}    {e}" for e in entries)
    return "{\n" + body + "\n" + base_indent + "}"


class BuildError(Exception):
    """A policy/definition combination cannot be turned into valid IR."""


# --------------------------------------------------------------------------- #
# IR objects
# --------------------------------------------------------------------------- #
@dataclass
class NamedSet:
    name: str
    type: str  # ipv4_addr | ipv6_addr | inet_service | ifname | concat (a . b) | …
    elements: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    # concatenation metadata (None for a plain set) — lets the renderer build the
    # `field . field @set` match from the same field list that built the type.
    concat_fields: list[str] | None = None
    concat_proto: str | None = None
    concat_family: str | None = None  # 'ip' | 'ip6' | None (no address field)

    def render(self) -> list[str]:
        lines = [f"{SET_INDENT}set {self.name} {{", f"{BODY_INDENT}type {self.type}"]
        if self.flags:
            lines.append(f"{BODY_INDENT}flags {', '.join(self.flags)}")
        if self.elements:
            lines.append(
                f"{BODY_INDENT}elements = {render_literal(self.elements, BODY_INDENT)}"
            )
        lines.append(f"{SET_INDENT}}}")
        return lines


@dataclass
class Chain:
    name: str
    rules: list[str] = field(default_factory=list)  # rendered rule lines (Phase 3)
    # base-chain attributes (all None => a regular chain)
    hook: str | None = None
    type: str | None = None
    priority: int | str | None = None
    policy: str | None = None

    def render(self) -> list[str]:
        lines = [f"{SET_INDENT}chain {self.name} {{"]
        if self.hook is not None:
            lines.append(
                f"{BODY_INDENT}type {self.type} hook {self.hook} "
                f"priority {self.priority}; policy {self.policy};"
            )
        for rule in self.rules:
            lines.append(f"{BODY_INDENT}{rule}")
        lines.append(f"{SET_INDENT}}}")
        return lines


@dataclass
class Flowtable:
    name: str
    hook: str
    priority: int | str
    devices: list[str]  # already-resolved device tokens (quoted)

    def render(self) -> list[str]:
        return [
            f"{SET_INDENT}flowtable {self.name} {{",
            f"{BODY_INDENT}hook {self.hook} priority {self.priority}",
            f"{BODY_INDENT}devices = {{ {', '.join(self.devices)} }}",
            f"{SET_INDENT}}}",
        ]


@dataclass
class Table:
    family: str
    name: str
    sets: list[NamedSet] = field(default_factory=list)
    chains: list[Chain] = field(default_factory=list)
    raw: list[str] = field(default_factory=list)  # table-level raw object declarations
    counters: list[str] = field(default_factory=list)  # named counter objects
    flowtables: list[Flowtable] = field(default_factory=list)

    def render(self) -> str:
        out = [f"table {self.family} {self.name} {{"]
        blocks: list[list[str]] = []
        blocks += [[f"{SET_INDENT}{r}"] for r in self.raw]
        blocks += [ft.render() for ft in self.flowtables]
        blocks += [
            [f"{SET_INDENT}counter {c} {{", f"{SET_INDENT}}}"] for c in self.counters
        ]
        blocks += [s.render() for s in self.sets]
        blocks += [c.render() for c in self.chains]
        for i, block in enumerate(blocks):
            out.extend(block)
            if i != len(blocks) - 1:
                out.append("")
        out.append("}")
        return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# Named-set construction from a table's `sets:` list
# --------------------------------------------------------------------------- #
def build_sets(sets_spec: list, defs: Definitions) -> list[NamedSet]:
    out: list[NamedSet] = []
    for entry in sets_spec or []:
        if isinstance(entry, str):
            out.append(_set_from_definition(entry, defs))
        elif isinstance(entry, dict):
            if "include" in entry:
                continue  # includes are resolved in a later phase
            if "concat" in entry:
                out.append(_concat_set(entry, defs))
            else:
                out.append(_bare_set(entry))
        else:
            raise BuildError(f"set entry must be a name or a mapping, got {entry!r}")
        check_nft_name(out[-1].name, "set")
    return out


def _set_from_definition(name: str, defs: Definitions) -> NamedSet:
    matches = [
        c for c in ("networks", "services", "interfaces") if name in getattr(defs, c)
    ]
    if not matches:
        raise BuildError(f"set {name!r}: not a defined network, service, or interface")
    if len(matches) > 1:
        raise BuildError(
            f"set {name!r}: ambiguous — defined in {matches}; names must be unique"
        )

    category = matches[0]
    if category == "networks":
        elements = defs.network(name)
        if not elements:
            raise BuildError(f"set {name!r}: network group resolves to no elements")
        family = _classify_family(elements, name)
        return NamedSet(name, f"{family}_addr", elements, flags=["interval"])
    if category == "services":
        ports = _unique_ports(defs.service(name))
        if not ports:
            raise BuildError(f"set {name!r}: service group resolves to no ports")
        flags = ["interval"] if any("-" in p for p in ports) else []
        return NamedSet(name, "inet_service", ports, flags)
    devices = [f'"{d}"' for d in defs.interface(name)]
    if not devices:
        raise BuildError(f"set {name!r}: interface group resolves to no devices")
    return NamedSet(name, "ifname", devices)


_BARE_SET_KEYS = frozenset({"name", "type", "elements", "flags"})
_CONCAT_SET_KEYS = frozenset({"name", "concat", "proto", "tuples"})


def _bare_set(entry: dict) -> NamedSet:
    if "name" not in entry or "type" not in entry:
        raise BuildError(f"bare set must have 'name' and 'type': {entry!r}")
    unknown = set(entry) - _BARE_SET_KEYS
    if unknown:
        raise BuildError(f"unknown set key(s) {sorted(unknown)}: {entry!r}")
    return NamedSet(
        name=entry["name"],
        type=entry["type"],
        elements=[str(e) for e in entry.get("elements", [])],
        flags=list(entry.get("flags", [])),
    )


# concat field -> nft set-type component ("addr" resolves to ipv4_addr/ipv6_addr)
_CONCAT_FIELD_TYPE = {
    "saddr": "addr",
    "daddr": "addr",
    "sport": "inet_service",
    "dport": "inet_service",
    "iifname": "ifname",
    "oifname": "ifname",
    "mark": "mark",
}


def _concat_set(entry: dict, defs: Definitions) -> NamedSet:  # noqa: PLR0912 - one branch per field kind
    """Build a concatenated (tuple) set from `concat:` fields + `tuples:` rows."""
    name = entry.get("name")
    fields = entry.get("concat")
    if not name or not fields:
        raise BuildError(f"concat set needs 'name' and 'concat': {entry!r}")
    unknown = set(entry) - _CONCAT_SET_KEYS
    if unknown:
        raise BuildError(f"unknown concat set key(s) {sorted(unknown)}: {entry!r}")
    for f in fields:
        if f not in _CONCAT_FIELD_TYPE:
            # iif/oif (index) aren't concat fields — a concat set over
            # interfaces uses iifname/oifname (ifname type).
            hint = (
                " (concat sets use iifname/oifname, not the index form)"
                if f in ("iif", "oif")
                else ""
            )
            raise BuildError(
                f"concat set {name!r}: unknown field {f!r}{hint} "
                f"(use {sorted(_CONCAT_FIELD_TYPE)})"
            )
    proto = entry.get("proto")
    if any(f in ("sport", "dport") for f in fields) and not proto:
        raise BuildError(f"concat set {name!r}: a port field needs `proto:`")

    rows: list[str] = []
    interval = False
    families: set[str] = set()
    for tup in entry.get("tuples", []):
        if not isinstance(tup, list) or len(tup) != len(fields):
            raise BuildError(
                f"concat set {name!r}: tuple {tup!r} must have {len(fields)} values "
                f"(one per field {fields})"
            )
        parts = []
        for f, val in zip(fields, tup, strict=True):
            token, fam, is_iv = _resolve_concat_value(name, f, val, proto, defs)
            parts.append(token)
            if fam:
                families.add(fam)
            interval = interval or is_iv
        rows.append(" . ".join(parts))

    if families == {"ip"}:
        family = "ip"
    elif families == {"ip6"}:
        family = "ip6"
    elif not families:
        family = None
    else:
        raise BuildError(
            f"concat set {name!r} mixes IPv4 and IPv6; single-family only — "
            f"split into {name}_v4 / {name}_v6"
        )

    addr_type = "ipv4_addr" if family == "ip" else "ipv6_addr"
    type_str = " . ".join(
        addr_type if _CONCAT_FIELD_TYPE[f] == "addr" else _CONCAT_FIELD_TYPE[f]
        for f in fields
    )
    s = NamedSet(name, type_str, rows, ["interval"] if interval else [])
    s.concat_fields = list(fields)
    s.concat_proto = proto
    s.concat_family = family
    return s


def _resolve_concat_value(setname, field, val, proto, defs):
    """Resolve one tuple value -> (nft token, family|None, needs_interval)."""
    kind = _CONCAT_FIELD_TYPE[field]
    val = str(val)
    if kind == "addr":
        if val in defs.networks:
            vals = defs.network(val)
            if len(vals) != 1:
                raise BuildError(
                    f"concat set {setname!r}: field {field}={val!r} resolves to "
                    f"{len(vals)} values; a tuple field takes one. Use a regular "
                    f"rule with sets for group-to-group, or list separate tuples."
                )
            val = vals[0]
        try:
            fam = (
                "ip" if ipaddress.ip_network(val, strict=False).version == 4 else "ip6"
            )
        except ValueError:
            raise BuildError(
                f"concat set {setname!r}: field {field}={val!r} is not a known "
                f"network group or an IP/CIDR"
            ) from None
        return val, fam, "/" in val  # prefix notation (incl. /32) needs interval
    if kind == "inet_service":
        if val in defs.services:
            ports = defs.service_ports(val, proto)
            if len(ports) != 1:
                raise BuildError(
                    f"concat set {setname!r}: service {val!r} has {len(ports)} "
                    f"{proto} port(s); a tuple field takes one"
                )
            val = ports[0]
        elif not _PORT_LITERAL.match(val):
            raise BuildError(
                f"concat set {setname!r}: field {field}={val!r} is not a known "
                f"service group or a port/range"
            )
        return val, None, "-" in val  # a port range needs interval
    if kind == "mark":
        return val, None, "-" in val  # bare fwmark number; no name resolution
    # ifname — strict: a typo'd group would silently become a literal device
    if val not in defs.interfaces:
        raise BuildError(
            f"concat set {setname!r}: field {field}={val!r} is not a known "
            f"interface group (define it under `interfaces:`)"
        )
    devs = defs.interface(val)
    if len(devs) != 1:
        raise BuildError(
            f"concat set {setname!r}: interface {val!r} resolves to {len(devs)} "
            f"devices; a tuple field takes one"
        )
    return f'"{devs[0]}"', None, False


def _classify_family(elements: list[str], name: str) -> str:
    versions = {ipaddress.ip_network(e, strict=False).version for e in elements}
    if versions == {4}:
        return "ipv4"
    if versions == {6}:
        return "ipv6"
    if not versions:
        raise BuildError(f"set {name!r} has no elements to derive a family from")
    raise BuildError(
        f"set {name!r} mixes IPv4 and IPv6; a named set is single-family — "
        f"split into e.g. {name}_v4 / {name}_v6"
    )


def _unique_ports(pairs: list[tuple[str, str]]) -> list[str]:
    return list(dict.fromkeys(port for _proto, port in pairs))

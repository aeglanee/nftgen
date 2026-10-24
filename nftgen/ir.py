"""Intermediate representation: typed nftables objects that render themselves.

YAML -> IR (Table / NamedSet / Chain) -> text. Keeping the model in the middle
(rather than building strings ad hoc) keeps parsing, checking and output apart.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from nftgen.definitions import Definitions
from nftgen.protocols import (  # noqa: F401 - re-exported
    PORT_PROTOS,
    PROTO_NUMBERS,
    proto_name,
)

_PORT_LITERAL = re.compile(r"^\d+(-\d+)?$")  # port or port-range
_MARK_NUMBER = r"(?:0x[0-9a-fA-F]+|\d+)"
MARK_VALUE = re.compile(
    rf"^{_MARK_NUMBER}(?:-{_MARK_NUMBER})?$"
)  # match: may be a range
MARK_SET_VALUE = re.compile(rf"^{_MARK_NUMBER}$")  # set: one value

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
    if not isinstance(name, str) or not name:
        # a list or mapping here crashed the keyword lookup (unhashable)
        raise BuildError(f"{kind} name must be text, got {name!r}")
    if name in _NFT_KEYWORDS:
        raise BuildError(
            f"{kind} name {name!r} is a reserved nftables keyword — rename it "
            f"(it would render to a ruleset nft can't parse)"
        )


_COMMENT_MAX_BYTES = 128  # nft rejects longer: "128 characters maximum allowed"


def check_comment(value, where: str) -> str:
    """A `comment:` value, rendered as nft's native `comment "…"` (kept in the
    kernel, shown by `nft list ruleset`). nft can't escape a `"` and caps the
    length in bytes, so both fail here against the YAML, not at load."""
    if not isinstance(value, str) or not value:
        raise BuildError(
            f"{where}: `comment:` must be a non-empty string, got {value!r}"
        )
    if '"' in value or "\n" in value or "\r" in value:
        raise BuildError(
            f"{where}: `comment:` can't contain a double quote or a line break: {value!r}"
        )
    size = len(value.encode())
    if size > _COMMENT_MAX_BYTES:
        raise BuildError(
            f"{where}: `comment:` is {size} bytes; nft allows at most "
            f"{_COMMENT_MAX_BYTES}: {value!r}"
        )
    return value


_WRAP_AT = 4  # a { … } literal with this many entries renders one per line

# A named service set: (l4 protocol, port) pairs, matched with
# `meta l4proto . th dport @set`.
SERVICE_PAIR_TYPE = "inet_proto . inet_service"


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
    comment: str | None = None
    # the service definition a (proto . port) pair set was built from (None
    # otherwise) — lets a rule check its proto against the definition.
    service: str | None = None

    def render(self) -> list[str]:
        lines = [f"{SET_INDENT}set {self.name} {{", f"{BODY_INDENT}type {self.type}"]
        if self.flags:
            lines.append(f"{BODY_INDENT}flags {', '.join(self.flags)}")
        if self.comment:
            lines.append(f'{BODY_INDENT}comment "{self.comment}"')
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
    comment: str | None = None

    def render(self) -> list[str]:
        lines = [f"{SET_INDENT}chain {self.name} {{"]
        if self.hook is not None:
            lines.append(
                f"{BODY_INDENT}type {self.type} hook {self.hook} "
                f"priority {self.priority}; policy {self.policy};"
            )
        if self.comment:
            lines.append(f'{BODY_INDENT}comment "{self.comment}"')
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
    comment: str | None = None

    def render(self) -> str:
        out = [f"table {self.family} {self.name} {{"]
        if self.comment:
            out.append(f'{SET_INDENT}comment "{self.comment}"')
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


RESET_MODES = ("flush", "own-tables")


@dataclass
class Reset:
    """What a deploy file clears before loading its tables: the whole ruleset
    (`flush`) or only the tables it renders (`own-tables`, one `destroy table`
    per distinct family + name, first-seen order — so foreign tables survive)."""

    mode: str
    tables: list[Table] = field(default_factory=list)

    def render(self) -> str:
        if self.mode == "flush":
            return "flush ruleset\n"
        names = dict.fromkeys((t.family, t.name) for t in self.tables)
        return "".join(f"destroy table {family} {name}\n" for family, name in names)


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
                # render_tables expands includes before this runs; one left
                # here means a caller skipped that step — fail, don't drop it.
                raise BuildError(
                    f"unresolved include {entry['include']!r} — includes are "
                    f"expanded by render_tables"
                )
            if "concat" in entry:
                out.append(_concat_set(entry, defs))
            else:
                out.append(_bare_set(entry))
        else:
            raise BuildError(f"set entry must be a name or a mapping, got {entry!r}")
        check_nft_name(out[-1].name, "set")
        if isinstance(entry, dict) and "comment" in entry:
            out[-1].comment = check_comment(entry["comment"], f"set {out[-1].name!r}")
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
        # A service is proto + port, so its set keeps both: a port-only set
        # would let `proto: udp` match a port the service only has on tcp.
        pairs = defs.service(name)
        if not pairs:
            raise BuildError(f"set {name!r}: service group resolves to no ports")
        elements = [f"{proto} . {port}" for proto, port in pairs]
        flags = ["interval"] if any("-" in port for _proto, port in pairs) else []
        return NamedSet(name, SERVICE_PAIR_TYPE, elements, flags, service=name)
    devices = [f'"{d}"' for d in defs.interface(name)]
    if not devices:
        raise BuildError(f"set {name!r}: interface group resolves to no devices")
    return NamedSet(name, "ifname", devices)


_BARE_SET_KEYS = frozenset({"name", "type", "elements", "flags", "comment"})
_CONCAT_SET_KEYS = frozenset({"name", "concat", "proto", "tuples", "family", "comment"})


# nft's set flags; `auto-merge` is a statement of its own, not a flag
SET_FLAGS = ("constant", "interval", "dynamic", "timeout")


def _set_values(entry: dict, key: str) -> list:
    """A bare set's `elements:`/`flags:` — one value or a list. A bare string
    must not be read letter by letter."""
    value = entry.get(key, [])
    if not isinstance(value, list):
        value = [value]
    for v in value:
        if isinstance(v, bool) or not isinstance(v, (str, int)):
            raise BuildError(
                f"set {entry['name']!r}: `{key}:` takes a value or a list of "
                f"values, got {entry[key]!r}"
            )
    return value


def _bare_set(entry: dict) -> NamedSet:
    if "name" not in entry or "type" not in entry:
        raise BuildError(f"bare set must have 'name' and 'type': {entry!r}")
    unknown = set(entry) - _BARE_SET_KEYS
    if unknown:
        raise BuildError(f"unknown set key(s) {sorted(unknown)}: {entry!r}")
    flags = _set_values(entry, "flags")
    for f in flags:
        if f not in SET_FLAGS:
            hint = (
                " (`auto-merge` is a line of its own in nft, not a flag — use "
                "table-level `raw:`)"
                if f == "auto-merge"
                else ""
            )
            raise BuildError(
                f"set {entry['name']!r}: unknown flag {f!r} "
                f"(nft set flags: {', '.join(SET_FLAGS)}){hint}"
            )
    return NamedSet(
        name=entry["name"],
        type=entry["type"],
        elements=[str(e) for e in _set_values(entry, "elements")],
        flags=list(dict.fromkeys(flags)),
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
    if not isinstance(fields, list):
        # a bare string was read letter by letter ("unknown field 's'")
        raise BuildError(
            f"concat set {name!r}: `concat:` takes a list of fields, "
            f"e.g. [saddr, daddr, dport], got {fields!r}"
        )
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
    written = entry.get("proto")
    proto = proto_name(written)  # `proto: 17` → udp, as in rules and vmaps
    if any(f in ("sport", "dport") for f in fields):
        if not proto:
            raise BuildError(f"concat set {name!r}: a port field needs `proto:`")
        if proto not in PORT_PROTOS:
            raise BuildError(
                f"concat set {name!r}: `proto: {written}` has no ports — a port "
                f"field needs one of {', '.join(PORT_PROTOS)}"
            )

    rows: list[str] = []
    interval = False
    families: set[str] = set()
    if not isinstance(entry.get("tuples", []), list):
        raise BuildError(
            f"concat set {name!r}: `tuples:` takes a list of rows, "
            f"got {entry['tuples']!r}"
        )
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

    if len(families) > 1:
        raise BuildError(
            f"concat set {name!r} mixes IPv4 and IPv6; single-family only — "
            f"split into {name}_v4 / {name}_v6"
        )
    family = _concat_family(name, fields, entry.get("family"), families)

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


def _concat_family(name, fields, explicit, derived: set) -> str | None:
    """The address family of a concat set: from its tuples, or the authored
    `family:` — required when an address field has no tuples to derive it
    from (a set filled at runtime), since both the set type and the rule's
    `ip`/`ip6 saddr` must be spelled out at load time."""
    has_addr = any(_CONCAT_FIELD_TYPE[f] == "addr" for f in fields)
    if explicit is not None:
        if explicit not in ("ip", "ip6"):
            raise BuildError(
                f"concat set {name!r}: `family:` must be ip or ip6, got {explicit!r}"
            )
        if not has_addr:
            raise BuildError(
                f"concat set {name!r}: `family:` only applies to a set with a "
                f"saddr/daddr field"
            )
        if derived and derived != {explicit}:
            raise BuildError(
                f"concat set {name!r}: `family: {explicit}` contradicts its "
                f"tuples ({derived.pop()})"
            )
        return explicit
    if derived:
        return derived.pop()
    if has_addr:
        raise BuildError(
            f"concat set {name!r} has an address field but no tuples to tell "
            f"IPv4 from IPv6 — add `family: ip` or `family: ip6`"
        )
    return None


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
        if not MARK_VALUE.match(val):
            raise BuildError(
                f"concat set {setname!r}: field mark={val!r} is not a mark "
                f"(a number or 0x…, or a range a-b)"
            )
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

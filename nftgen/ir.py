"""Intermediate representation: typed nftables objects that render themselves.

YAML -> IR (Table / NamedSet / Chain) -> text. Keeping the model in the middle
(rather than building strings ad hoc) is what makes the output robust and lets a
JSON emitter drop in later from the same objects.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from nftgen.definitions import Definitions

SET_INDENT = "    "
BODY_INDENT = "        "


class BuildError(Exception):
    """A policy/definition combination cannot be turned into valid IR."""


# --------------------------------------------------------------------------- #
# IR objects
# --------------------------------------------------------------------------- #
@dataclass
class NamedSet:
    name: str
    type: str  # ipv4_addr | ipv6_addr | inet_service | ifname | …
    elements: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    def render(self) -> list[str]:
        lines = [f"{SET_INDENT}set {self.name} {{", f"{BODY_INDENT}type {self.type}"]
        if self.flags:
            lines.append(f"{BODY_INDENT}flags {', '.join(self.flags)}")
        if self.elements:
            lines.append(f"{BODY_INDENT}elements = {{ {', '.join(self.elements)} }}")
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
class Table:
    family: str
    name: str
    sets: list[NamedSet] = field(default_factory=list)
    chains: list[Chain] = field(default_factory=list)
    raw: list[str] = field(default_factory=list)  # table-level raw object declarations
    counters: list[str] = field(default_factory=list)  # named counter objects

    def render(self) -> str:
        out = [f"table {self.family} {self.name} {{"]
        blocks: list[list[str]] = []
        blocks += [[f"{SET_INDENT}{r}"] for r in self.raw]
        blocks += [[f"{SET_INDENT}counter {c} {{", f"{SET_INDENT}}}"] for c in self.counters]
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
            out.append(_bare_set(entry))
        else:
            raise BuildError(f"set entry must be a name or a mapping, got {entry!r}")
    return out


def _set_from_definition(name: str, defs: Definitions) -> NamedSet:
    matches = [c for c in ("networks", "services", "interfaces") if name in getattr(defs, c)]
    if not matches:
        raise BuildError(f"set {name!r}: not a defined network, service, or interface")
    if len(matches) > 1:
        raise BuildError(f"set {name!r}: ambiguous — defined in {matches}; names must be unique")

    category = matches[0]
    if category == "networks":
        elements = defs.network(name)
        family = _classify_family(elements, name)
        return NamedSet(name, f"{family}_addr", elements, flags=["interval"])
    if category == "services":
        ports = _unique_ports(defs.service(name))
        flags = ["interval"] if any("-" in p for p in ports) else []
        return NamedSet(name, "inet_service", ports, flags)
    devices = [f'"{d}"' for d in defs.interface(name)]
    return NamedSet(name, "ifname", devices)


def _bare_set(entry: dict) -> NamedSet:
    if "name" not in entry or "type" not in entry:
        raise BuildError(f"bare set must have 'name' and 'type': {entry!r}")
    return NamedSet(
        name=entry["name"],
        type=entry["type"],
        elements=[str(e) for e in entry.get("elements", [])],
        flags=list(entry.get("flags", [])),
    )


def _classify_family(elements: list[str], name: str) -> str:
    versions = {ipaddress.ip_network(e, strict=False).version for e in elements}
    if versions == {4}:
        return "ipv4"
    if versions == {6}:
        return "ipv6"
    raise BuildError(
        f"set {name!r} mixes IPv4 and IPv6; a named set is single-family — "
        f"split into e.g. {name}_v4 / {name}_v6"
    )


def _unique_ports(pairs: list[tuple[str, str]]) -> list[str]:
    return list(dict.fromkeys(port for _proto, port in pairs))

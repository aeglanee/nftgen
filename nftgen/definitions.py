"""Definitions: networks / services / interfaces, with composition.

A definition value is a list whose items are either a literal (an IP/CIDR, a
``port/proto``, or an interface device name) or the name of another group in the
same category (composition, resolved recursively). Groups merge across files;
a host may overlay one or more per-site definition files. Names are unique
within a category — a duplicate (including a site overlay redefining a common
name) is an error.
"""
from __future__ import annotations

import ipaddress
import pathlib
from typing import Any, Iterable, Mapping

import yaml

CATEGORIES = ("networks", "services", "interfaces")


class DefinitionError(Exception):
    """A definition is malformed, duplicated, or references something undefined."""


class Definitions:
    def __init__(self) -> None:
        self.networks: dict[str, list] = {}
        self.services: dict[str, list] = {}
        self.interfaces: dict[str, list] = {}

    # -- construction -------------------------------------------------------- #
    @classmethod
    def load(cls, def_dir: str | pathlib.Path, site_files: Iterable[str | pathlib.Path] = ()) -> "Definitions":
        """Merge every ``*.yaml`` under ``def_dir`` recursively (common), then site overlays."""
        defs = cls()
        for path in sorted(pathlib.Path(def_dir).rglob("*.y*ml")):
            defs._merge(yaml.safe_load(path.read_text()) or {}, str(path))
        for sf in site_files:
            defs._merge(yaml.safe_load(pathlib.Path(sf).read_text()) or {}, str(sf))
        return defs

    @classmethod
    def from_mappings(cls, *mappings: Mapping[str, Any]) -> "Definitions":
        """Build directly from in-memory mappings (tests / programmatic use)."""
        defs = cls()
        for i, mapping in enumerate(mappings):
            defs._merge(mapping or {}, f"<mapping {i}>")
        return defs

    def _merge(self, data: Mapping[str, Any], source: str) -> None:
        for category in CATEGORIES:
            target = getattr(self, category)
            for name, value in (data.get(category) or {}).items():
                if name in target:
                    raise DefinitionError(
                        f"duplicate {category} definition {name!r} (in {source})"
                    )
                if not isinstance(value, list):
                    raise DefinitionError(
                        f"{category} {name!r} must be a list (in {source})"
                    )
                target[name] = value

    # -- resolution ---------------------------------------------------------- #
    def network(self, name: str) -> list[str]:
        """Resolve a network group to an ordered, deduped list of IP/CIDR strings."""
        return self._expand("networks", self.networks, name, _net_leaf, frozenset())

    def service(self, name: str) -> list[tuple[str, str]]:
        """Resolve a service group to ordered, deduped (proto, port) pairs."""
        return self._expand("services", self.services, name, _svc_leaf, frozenset())

    def interface(self, name: str) -> list[str]:
        """Resolve an interface group to an ordered, deduped list of device names."""
        return self._expand("interfaces", self.interfaces, name, _iface_leaf, frozenset())

    def service_ports(self, name: str, proto: str) -> list[str]:
        """Just the ports of a service for one protocol (e.g. tcp)."""
        return [port for p, port in self.service(name) if p == proto]

    def _expand(self, category, table, name, leaf, seen) -> list:
        if name not in table:
            raise DefinitionError(f"undefined {category[:-1]}: {name!r}")
        if name in seen:
            return []  # cycle guard
        seen = seen | {name}
        out: list = []
        for item in table[name]:
            key = str(item)
            if key in table:
                out.extend(self._expand(category, table, key, leaf, seen))
            else:
                out.extend(leaf(key, name))
        return list(dict.fromkeys(out))  # dedupe, preserve order


# -- leaf parsers ------------------------------------------------------------ #
def _net_leaf(item: str, group: str) -> list[str]:
    try:
        ipaddress.ip_network(item, strict=False)
    except ValueError as e:
        raise DefinitionError(
            f"network {group!r}: {item!r} is not a known group or an IP/CIDR ({e})"
        ) from e
    return [item]  # preserve the author's form


def _svc_leaf(item: str, group: str) -> list[tuple[str, str]]:
    if "/" not in item:
        raise DefinitionError(
            f"service {group!r}: {item!r} must be 'port/proto' or a known service"
        )
    port, proto = item.rsplit("/", 1)
    if not port or not proto:
        raise DefinitionError(f"service {group!r}: malformed entry {item!r}")
    return [(proto, port)]


def _iface_leaf(item: str, group: str) -> list[str]:
    return [item]  # any non-group string is a literal device name

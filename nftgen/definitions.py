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
from collections.abc import Iterable, Mapping
from typing import Any

import yaml

CATEGORIES = ("networks", "services", "interfaces")


class DefinitionError(Exception):
    """A definition is malformed, duplicated, or references something undefined."""


class Definitions:
    def __init__(self) -> None:
        self.networks: dict[str, list] = {}
        self.services: dict[str, list] = {}
        self.interfaces: dict[str, list] = {}
        # (category, name) -> the source that first defined it, for dual-origin
        # provenance in duplicate errors.
        self._origin: dict[tuple[str, str], str] = {}

    # -- construction -------------------------------------------------------- #
    @classmethod
    def load(
        cls, def_dir: str | pathlib.Path, site_files: Iterable[str | pathlib.Path] = ()
    ) -> Definitions:
        """Merge every ``*.yaml`` under ``def_dir`` recursively (common), then site overlays."""
        def_dir = pathlib.Path(def_dir)
        if not def_dir.is_dir():
            # A missing dir would silently yield empty definitions, degrading
            # every group reference downstream — fail here instead.
            raise DefinitionError(f"definitions directory not found: {def_dir}")
        defs = cls()
        for path in sorted(def_dir.rglob("*.y*ml")):
            defs._merge(yaml.safe_load(path.read_text()) or {}, str(path))
        for sf in map(pathlib.Path, site_files):
            if not sf.is_file():
                raise DefinitionError(f"site definitions file not found: {sf}")
            defs._merge(yaml.safe_load(sf.read_text()) or {}, str(sf))
        return defs

    @classmethod
    def from_mappings(cls, *mappings: Mapping[str, Any]) -> Definitions:
        """Build directly from in-memory mappings (tests / programmatic use)."""
        defs = cls()
        for i, mapping in enumerate(mappings):
            defs._merge(mapping or {}, f"<mapping {i}>")
        return defs

    @classmethod
    def from_named_mappings(
        cls, mappings: Mapping[str, Mapping[str, Any]]
    ) -> Definitions:
        """Build from named layers ``{layer_name: mapping}``.

        The layer name is the provenance reported in duplicate errors (both the
        first-seen and the duplicating layer). Layers merge in sorted-name order
        — determinism, not precedence: names are unique, so order never changes
        the result, only which duplicate is reported first. This is the surface
        the Ansible vars front-end feeds (layer name == the chunk var name).
        """
        defs = cls()
        for name in sorted(mappings):
            defs._merge(mappings[name] or {}, name)
        return defs

    def _merge(self, data: Mapping[str, Any], source: str) -> None:
        for category in CATEGORIES:
            target = getattr(self, category)
            for name, value in (data.get(category) or {}).items():
                if name in target:
                    first = self._origin.get((category, name), "?")
                    raise DefinitionError(
                        f"duplicate {category} definition {name!r} ({first}, {source})"
                    )
                if not isinstance(value, list):
                    raise DefinitionError(
                        f"{category} {name!r} must be a list (in {source})"
                    )
                target[name] = value
                self._origin[(category, name)] = source

    # -- resolution ---------------------------------------------------------- #
    def network(self, name: str) -> list[str]:
        """Resolve a network group to an ordered, deduped list of IP/CIDR strings."""
        return self._expand("networks", self.networks, name, _net_leaf, ())

    def service(self, name: str) -> list[tuple[str, str]]:
        """Resolve a service group to ordered, deduped (proto, port) pairs."""
        return self._expand("services", self.services, name, _svc_leaf, ())

    def interface(self, name: str) -> list[str]:
        """Resolve an interface group to an ordered, deduped list of device names."""
        return self._expand("interfaces", self.interfaces, name, _iface_leaf, ())

    def service_ports(self, name: str, proto: str) -> list[str]:
        """Just the ports of a service for one protocol (e.g. tcp)."""
        return [port for p, port in self.service(name) if p == proto]

    def _expand(self, category, table, name, leaf, stack: tuple) -> list:
        if name not in table:
            raise DefinitionError(f"undefined {category[:-1]}: {name!r}")
        if name in stack:
            raise DefinitionError(
                f"{category} definition cycle: {' -> '.join((*stack, name))}"
            )
        stack = (*stack, name)
        out: list = []
        for item in table[name]:
            key = str(item)
            # A group referencing itself is meaningless as composition; read it
            # as a literal so `eth0: [eth0]` names a one-device group.
            if key in table and key != name:
                out.extend(self._expand(category, table, key, leaf, stack))
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

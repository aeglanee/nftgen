"""Top level: a host policy file -> a complete nftables ruleset string.

Resolves `- include:` in both `sets:` and `rules:` lists, applies the host's
per-site definition overlay (`site:`), builds each table's named-set registry,
and renders tables -> sets -> chains.
"""

from __future__ import annotations

import pathlib
from collections.abc import Mapping

import yaml

from nftgen.definitions import Definitions
from nftgen.ir import BuildError, Table, build_sets, check_nft_name
from nftgen.rules import RuleRenderer, build_chain, build_flowtables

# Strict authoring surface: an unknown key is a typo, and a typo'd `tables:` or
# `chains:` would otherwise generate a valid-but-empty ruleset that nft -c
# passes — with `flush ruleset` that artifact wipes the firewall on deploy.
_POLICY_KEYS = frozenset({"site", "tables"})
_TABLE_KEYS = frozenset(
    {"family", "name", "sets", "chains", "counters", "raw", "flowtables"}
)


class PathResolver:
    """`include:` -> a YAML file under base_dir, section `key` (CLI / file mode)."""

    def __init__(self, base_dir: str | pathlib.Path) -> None:
        self.base_dir = pathlib.Path(base_dir)

    def cycle_id(self, ref: str) -> pathlib.Path:
        return (self.base_dir / ref).resolve()

    def fetch(self, ref: str, key: str) -> list:
        path = self.cycle_id(ref)
        if not path.is_file():
            raise BuildError(f"include file not found: {self.base_dir / ref}")
        return (yaml.safe_load(path.read_text()) or {}).get(key, [])


class DictResolver:
    """`include:` -> a fragment name in a shared dict (Ansible vars mode).

    A fragment is one list, shared across `sets:`/`rules:` contexts, so `key` is
    unused. Unknown names error listing the known fragments.
    """

    def __init__(self, fragments: Mapping[str, list]) -> None:
        self.fragments = fragments

    def cycle_id(self, ref: str) -> str:
        return ref

    def fetch(self, ref: str, key: str) -> list:
        if ref not in self.fragments:
            raise BuildError(
                f"unknown fragment {ref!r} (known: {sorted(self.fragments)})"
            )
        return self.fragments[ref]


def _resolve_list(items: list, key: str, resolver, stack: tuple = ()) -> list:
    """Flatten a list, expanding `{include: <ref>}` entries recursively.

    `key` is the section a file include pulls ('sets' or 'rules'); the resolver
    maps a ref to its list and to a cycle id (a path or a name). `include:` must
    be the entry's only key.
    """
    out: list = []
    for item in items or []:
        if isinstance(item, dict) and "include" in item:
            if len(item) != 1:
                raise BuildError(f"`include:` must be the entry's only key: {item!r}")
            ref = item["include"]
            cid = resolver.cycle_id(ref)
            if cid in stack:
                chain = " -> ".join(str(p) for p in (*stack, cid))
                raise BuildError(f"include cycle: {chain}")
            out.extend(
                _resolve_list(resolver.fetch(ref, key), key, resolver, (*stack, cid))
            )
        else:
            out.append(item)
    return out


def render_tables(
    tables: list,
    defs: Definitions,
    resolver,
    *,
    source: str | None = None,
    flush: bool = False,
) -> str:
    """Render a policy `tables:` list to a complete nftables ruleset string.

    The pure core shared by both front-ends: given already-merged ``defs`` and an
    include ``resolver`` (``PathResolver`` for the file-tree CLI, ``DictResolver``
    for the Ansible vars mode), render tables -> sets -> chains. ``source`` labels
    the header and error messages (a policy file name or an inventory hostname);
    ``flush`` prepends ``flush ruleset`` for the deploy artifact.
    """
    where = f"{source}: " if source else ""
    if not tables:
        raise BuildError(f"{where}no `tables:` — refusing to render an empty ruleset")
    out_tables = []
    for tspec in tables:
        unknown = set(tspec) - _TABLE_KEYS
        if unknown:
            raise BuildError(
                f"{where}unknown table key(s) {sorted(unknown)}: "
                f"{tspec.get('name', tspec)!r}"
            )
        if "family" not in tspec or "name" not in tspec:
            raise BuildError(f"{where}a table needs `family:` and `name:`: {tspec!r}")
        sets = build_sets(_resolve_list(tspec.get("sets", []), "sets", resolver), defs)
        counters = list(tspec.get("counters", []))
        for c in counters:
            check_nft_name(c, "counter")
        renderer = RuleRenderer(defs, {s.name: s for s in sets}, counters=set(counters))
        chains = []
        for spec in tspec.get("chains", []):
            cspec = dict(spec)
            cspec["rules"] = _resolve_list(cspec.get("rules", []), "rules", resolver)
            chains.append(build_chain(cspec, renderer))
        out_tables.append(
            Table(
                family=tspec["family"],
                name=tspec["name"],
                sets=sets,
                chains=chains,
                raw=list(tspec.get("raw", [])),
                counters=counters,
                flowtables=build_flowtables(tspec.get("flowtables", []), defs),
            )
        )

    label = f" from {source}" if source else ""
    header = f"#!/usr/sbin/nft -f\n# generated by nftgen{label} — do not edit\n"
    # `flush ruleset` makes the file a complete, atomic, reapply-safe deploy
    # artifact (the build() output that ships verbatim as /etc/nftables.conf).
    # generate()/render_tables stay flush-free by default for composition.
    flush_prefix = "flush ruleset\n\n" if flush else ""
    return header + "\n" + flush_prefix + "\n".join(t.render() for t in out_tables)


def generate(
    policy_path: str | pathlib.Path,
    defs_dir: str | pathlib.Path,
    include_base: str | pathlib.Path,
    sites_dir: str | pathlib.Path | None = None,
    flush: bool = False,
) -> str:
    policy_path = pathlib.Path(policy_path)
    include_base = pathlib.Path(include_base)
    policy = yaml.safe_load(policy_path.read_text()) or {}

    if not isinstance(policy, dict):
        raise BuildError(
            f"{policy_path}: policy must be a mapping, got {type(policy).__name__}"
        )
    unknown = set(policy) - _POLICY_KEYS
    if unknown:
        raise BuildError(f"{policy_path}: unknown policy key(s) {sorted(unknown)}")
    if not policy.get("tables"):
        raise BuildError(
            f"{policy_path}: policy defines no `tables:` — refusing to generate "
            f"an empty ruleset"
        )

    site_files: list[pathlib.Path] = []
    if policy.get("site") and sites_dir:
        site_files = [pathlib.Path(sites_dir) / f"{policy['site']}.yaml"]
    defs = Definitions.load(defs_dir, site_files=site_files)

    return render_tables(
        policy["tables"],
        defs,
        PathResolver(include_base),
        source=policy_path.name,
        flush=flush,
    )


def build(root: str | pathlib.Path, host: str | None = None) -> dict[str, str]:
    """Generate the deploy `.nft` for every host under ``<root>`` (or just ``host``).

    Convention layout: ``<root>/{def, sites, policies/includes, policies/hosts}``.
    Returns ``{host_name: text}`` where each text is a complete, applyable ruleset
    (with ``flush ruleset``). The host name is the policy filename stem — the
    ``inventory_hostname == policies/hosts/<name>.yaml == generated/<name>.nft``
    contract (DEPLOYMENT §10.2).
    """
    root = pathlib.Path(root)
    defs_dir = root / "definitions"
    include_base = root / "policies"
    sites_dir = root / "sites"
    hosts_dir = root / "policies" / "hosts"

    if host is not None:
        host_files = sorted(hosts_dir.glob(f"{host}.y*ml"))
        if not host_files:
            raise FileNotFoundError(f"no host policy {host!r} under {hosts_dir}")
    else:
        host_files = sorted(hosts_dir.glob("*.y*ml"))

    return {
        hf.stem: generate(hf, defs_dir, include_base, sites_dir, flush=True)
        for hf in host_files
    }

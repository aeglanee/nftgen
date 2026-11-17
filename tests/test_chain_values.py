"""A table's `family:` and a base chain's `hook:`, `type:` and `policy:` render
as bare nft tokens, so each must be a value nft takes there."""

import re

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError

DEFS = Definitions.from_mappings({"interfaces": {"lo_if": ["lo"]}})

requires_nft = pytest.mark.skipif(
    not validate.can_check(), reason="nft -c not usable in this environment"
)

# every base chain nft takes: (family, type, hook)
VALID = [
    *[
        (family, "filter", hook)
        for family in ("ip", "ip6", "inet", "bridge")
        for hook in ("prerouting", "input", "forward", "output", "postrouting")
    ],
    ("inet", "filter", "ingress"),
    ("arp", "filter", "input"),
    ("arp", "filter", "output"),
    ("netdev", "filter", "ingress"),
    ("netdev", "filter", "egress"),
    *[
        (family, "nat", hook)
        for family in ("ip", "ip6", "inet")
        for hook in ("prerouting", "input", "output", "postrouting")
    ],
    *[(family, "route", "output") for family in ("ip", "ip6", "inet")],
]


def _render(chain: dict, family: str = "inet") -> str:
    tables = [{"family": family, "name": "t", "chains": [chain]}]
    return render_tables(tables, DEFS, DictResolver({}))


def _chain(family: str, type_: str, hook: str) -> dict:
    chain = {"name": "c", "hook": hook, "type": type_, "policy": "accept"}
    if hook in ("ingress", "egress"):
        chain["devices"] = "lo_if"
    return chain


@pytest.mark.parametrize(("family", "type_", "hook"), VALID)
def test_every_base_chain_nft_takes_renders(family, type_, hook):
    assert f"type {type_} hook {hook}" in _render(_chain(family, type_, hook), family)


@requires_nft
@pytest.mark.parametrize(("family", "type_", "hook"), VALID)
def test_every_base_chain_nft_takes_passes_nft_check(family, type_, hook):
    result = validate.check(_render(_chain(family, type_, hook), family))
    assert result.ok, result.stderr


def _fails(match: str, chain: dict, family: str = "inet") -> None:
    with pytest.raises(BuildError, match=re.escape(match)):
        _render(chain, family)


@pytest.mark.parametrize(
    "policy",
    ["drop;\n        accept", "drop # x", "reject", "ACCEPT", "", True, None, ["drop"]],
)
def test_policy_must_be_accept_or_drop(policy):
    # `drop;\n accept` rendered `policy drop;` and a second line `accept;`
    _fails(
        "`policy:` must be one of accept, drop",
        {"name": "c", "hook": "input", "policy": policy},
    )


@pytest.mark.parametrize(
    "hook",
    [
        "input priority 0; policy accept; }\n    chain x {\n        type filter hook input",
        "input\n",
        "Input",
        "local_in",
        5,
    ],
)
def test_hook_must_be_a_hook(hook):
    # the first rendered a second base chain `x` with the default policy drop
    _fails("`hook:` must be one of", {"name": "c", "hook": hook})


@pytest.mark.parametrize(
    ("family", "hook"),
    [
        ("inet", "egress"),
        ("ip", "ingress"),
        ("bridge", "ingress"),
        ("arp", "forward"),
        ("netdev", "input"),
    ],
)
def test_hook_must_be_one_of_its_familys(family, hook):
    chain = {"name": "c", "hook": hook, "devices": "lo_if", "policy": "accept"}
    _fails(f"chain 'c' (table family {family}): `hook:`", chain, family)


@pytest.mark.parametrize(
    ("family", "type_", "hook"),
    [
        (
            "inet",
            "filter hook output priority 0; policy accept; }\nchain y { type filter",
            "input",
        ),
        ("inet", "Filter", "input"),
        ("inet", "mangle", "input"),
        ("bridge", "nat", "prerouting"),
        ("arp", "route", "output"),
        ("netdev", "nat", "ingress"),
    ],
)
def test_type_must_be_one_of_its_familys(family, type_, hook):
    chain = {"name": "c", "hook": hook, "type": type_, "devices": "lo_if"}
    _fails(f"chain 'c' (table family {family}): `type:`", chain, family)


@pytest.mark.parametrize(
    ("type_", "hook"),
    [("nat", "forward"), ("route", "input"), ("route", "postrouting")],
)
def test_nat_and_route_take_their_hooks_only(type_, hook):
    _fails(f"a {type_} chain's `hook:`", {"name": "c", "hook": hook, "type": type_})


@pytest.mark.parametrize("family", ["inet\n", "inet6", "INET", "ipv4", 4, ["inet"]])
def test_family_must_be_an_nft_family(family):
    _fails(
        "table 't': `family:` must be one of ip, ip6, inet, arp, bridge, netdev",
        {"name": "c"},
        family,
    )


@pytest.mark.parametrize("hook", ["egress", "ingress priority 0\n    }\n    chain x {"])
def test_flowtable_hook_must_be_ingress(hook):
    tables = [
        {
            "family": "inet",
            "name": "t",
            "flowtables": [{"name": "ft", "hook": hook, "devices": "lo_if"}],
        }
    ]
    with pytest.raises(
        BuildError, match=re.escape("flowtable 'ft': `hook:` must be one of ingress")
    ):
        render_tables(tables, DEFS, DictResolver({}))


def test_defaults_render():
    assert "type filter hook input priority 0; policy drop;" in _render(
        {"name": "c", "hook": "input"}
    )
    assert "type nat hook postrouting priority 100; policy accept;" in _render(
        {"name": "c", "hook": "postrouting", "type": "nat", "priority": "srcnat"}
    )

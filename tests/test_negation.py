"""Negated matches: `{not: …}` on an address or interface key renders `!=`."""

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError, build_sets
from nftgen.rules import RuleRenderer

DEFS = Definitions.from_mappings(
    {
        "networks": {
            "allowed": ["192.0.2.10", "192.0.2.11"],
            "mgmt": ["192.168.9.0/24", "fd00:9::/64"],
            "v6only": ["2001:db8::/48"],
        },
        "interfaces": {
            "lan": ["lan0", "lan1"],
            "wan": ["wan0", "wwan0"],
            "loopback": ["lo"],
        },
    }
)
NAMED = {s.name: s for s in build_sets(["allowed", "lan"], DEFS)}
R = RuleRenderer(DEFS, NAMED)

TABLES = [
    {
        "family": "inet",
        "name": "filter",
        "sets": ["allowed", "lan"],
        "chains": [
            {
                "name": "input",
                "hook": "input",
                "rules": [
                    {
                        "iifname": {"not": "lan"},
                        "saddr": {"not": "allowed"},
                        "action": "drop",
                    },
                    {
                        "iif": {"not": "loopback"},
                        "daddr": {"not": "mgmt"},
                        "action": "drop",
                    },
                    {"oifname": {"not": ["wan", "loopback"]}, "action": "accept"},
                ],
            }
        ],
    }
]

RULES = [
    "iifname != @lan ip saddr != @allowed drop",
    'iif != "lo" ip daddr != 192.168.9.0/24 drop',
    'iif != "lo" ip6 daddr != fd00:9::/64 drop',
    'oifname != { "wan0", "wwan0", "lo" } accept',
]


def test_a_named_set_lookup_is_negated():
    assert R.render({"saddr": {"not": "allowed"}, "action": "drop"}) == [
        "ip saddr != @allowed drop"
    ]


def test_an_at_reference_works_too():
    assert R.render({"saddr": {"not": "@allowed"}, "action": "drop"}) == [
        "ip saddr != @allowed drop"
    ]


def test_an_inline_group_is_negated_per_family():
    assert R.render({"daddr": {"not": "mgmt"}, "action": "drop"}) == [
        "ip daddr != 192.168.9.0/24 drop",
        "ip6 daddr != fd00:9::/64 drop",
    ]


def test_a_literal_and_a_list():
    assert R.render({"saddr": {"not": "10.0.0.1"}, "action": "drop"}) == [
        "ip saddr != 10.0.0.1 drop"
    ]
    assert R.render({"saddr": {"not": ["10.0.0.1", "v6only"]}, "action": "drop"}) == [
        "ip saddr != 10.0.0.1 drop",
        "ip6 saddr != 2001:db8::/48 drop",
    ]


def test_interface_name_matches():
    assert R.render({"iifname": {"not": "lan"}, "action": "drop"}) == [
        "iifname != @lan drop"
    ]
    assert R.render({"oifname": {"not": "wan"}, "action": "drop"}) == [
        'oifname != { "wan0", "wwan0" } drop'
    ]
    assert R.render({"iifname": {"not": "loopback"}, "action": "drop"}) == [
        'iifname != "lo" drop'
    ]


def test_interface_index_matches():
    assert R.render({"iif": {"not": "loopback"}, "action": "drop"}) == [
        'iif != "lo" drop'
    ]
    assert R.render({"oif": {"not": "wan"}, "action": "drop"}) == [
        'oif != { "wan0", "wwan0" } drop'
    ]


def test_negated_and_plain_matches_mix_in_nft_order():
    assert R.render(
        {
            "iifname": "wan",
            "saddr": {"not": "allowed"},
            "proto": "tcp",
            "dport": 22,
            "comment": "ssh from elsewhere",
            "action": "drop",
        }
    ) == [
        'iifname { "wan0", "wwan0" } ip saddr != @allowed tcp dport 22 drop '
        'comment "ssh from elsewhere"'
    ]


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"nott": "allowed"},
        {"not": "allowed", "match": "mgmt"},
        {"not": {"not": "allowed"}},
        {"not": []},
        {"not": None},
    ],
)
def test_the_mapping_takes_exactly_not(value):
    with pytest.raises(BuildError, match="rule key 'saddr'"):
        R.render({"saddr": value, "action": "drop"})


def test_the_inner_value_is_checked_like_the_plain_one():
    with pytest.raises(BuildError, match="unknown set reference"):
        R.render({"saddr": {"not": "@nope"}, "action": "drop"})
    with pytest.raises(BuildError, match="unknown interface group"):
        R.render({"iifname": {"not": "eth0"}, "action": "drop"})
    with pytest.raises(BuildError, match="can't go inside a list"):
        R.render({"saddr": {"not": ["allowed", "mgmt"]}, "action": "drop"})


def test_ports_take_no_negation():
    with pytest.raises(BuildError, match="rule key 'dport'"):
        R.render({"proto": "tcp", "dport": {"not": 22}, "action": "drop"})


def test_tables_render():
    text = render_tables(TABLES, DEFS, DictResolver({}))
    for rule in RULES:
        assert f"        {rule}\n" in text


@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_passes_nft_check():
    result = validate.check(render_tables(TABLES, DEFS, DictResolver({})))
    assert result.ok, result.stderr


def test_the_pair_link_recipe_of_best_practices_8e():
    # the two lines behavioral test B32 loads as its loose-on-peer variant
    defs = Definitions.from_mappings({"interfaces": {"peer": ["peer0"]}})
    r = RuleRenderer(defs, {})
    loose = {"key": ["saddr", "mark"], "result": "oif", "match": "missing"}
    strict = {"key": ["saddr", "mark", "iif"], "result": "oif", "match": "missing"}
    assert r.render({"iifname": "peer", "fib": loose, "action": "drop"}) == [
        'iifname "peer0" fib saddr . mark oif missing drop'
    ]
    assert r.render({"iifname": {"not": "peer"}, "fib": strict, "action": "drop"}) == [
        'iifname != "peer0" fib saddr . mark . iif oif missing drop'
    ]

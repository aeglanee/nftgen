"""Interface groups in concat set rows: a group expands the row to every device."""

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError, build_sets
from nftgen.rules import RuleRenderer

DEFS = Definitions.from_mappings(
    {
        "networks": {"db": ["192.0.2.20"]},
        "services": {"postgres": ["5432/tcp"]},
        "interfaces": {
            "lan": ["lan0", "lan1"],
            "lan0_only": ["lan0"],
            "wan": ["wan", "wwan0"],
        },
    }
)


def _set(concat, tuples, proto=None):
    spec = {"name": "f", "concat": concat, "tuples": tuples}
    if proto:
        spec["proto"] = proto
    return build_sets([spec], DEFS)[0]


def test_a_group_expands_the_row_to_every_device():
    s = _set(["iifname", "daddr", "dport"], [["lan", "db", "postgres"]], "tcp")
    assert s.elements == [
        '"lan0" . 192.0.2.20 . 5432',
        '"lan1" . 192.0.2.20 . 5432',
    ]
    assert s.type == "ifname . ipv4_addr . inet_service"


def test_two_groups_in_a_row_cross():
    s = _set(["iifname", "oifname"], [["lan", "wan"]])
    assert s.elements == [
        '"lan0" . "wan"',
        '"lan0" . "wwan0"',
        '"lan1" . "wan"',
        '"lan1" . "wwan0"',
    ]


def test_a_bare_name_is_the_group_even_when_a_device_shares_it():
    s = _set(["iifname", "dport"], [["wan", 22]], "tcp")
    assert s.elements == ['"wan" . 22', '"wwan0" . 22']


def test_one_device_alone_is_its_own_one_device_group():
    defs = Definitions.from_mappings(
        {"interfaces": {"wan": ["wan"], "uplinks": ["wan", "wwan0"]}}
    )
    spec = {
        "name": "f",
        "concat": ["iifname", "oifname"],
        "tuples": [["wan", "uplinks"]],
    }
    assert build_sets([spec], defs)[0].elements == ['"wan" . "wan"', '"wan" . "wwan0"']


def test_a_group_named_after_its_device_is_the_group_inside_another_too():
    defs = Definitions.from_mappings(
        {"interfaces": {"wan": ["wan", "wwan0"], "wan_wired": ["wan"]}}
    )
    assert defs.interface("wan_wired") == ["wan", "wwan0"]


def test_rows_sharing_an_element_list_it_once():
    s = _set(["iifname", "dport"], [["lan", 22], ["lan0_only", 22]], "tcp")
    assert s.elements == ['"lan0" . 22', '"lan1" . 22']


def test_identical_rows_are_one_element():
    s = _set(["saddr", "dport"], [["db", 22], ["db", 22]], "tcp")
    assert s.elements == ["192.0.2.20 . 22"]


def test_an_unknown_group_errors():
    with pytest.raises(BuildError, match="not a known interface group"):
        _set(["iifname", "dport"], [["eth0", 22]], "tcp")


def test_an_empty_group_errors():
    defs = Definitions.from_mappings({"interfaces": {"none": []}})
    with pytest.raises(BuildError, match="resolves to no devices"):
        build_sets(
            [
                {
                    "name": "f",
                    "concat": ["iifname", "oifname"],
                    "tuples": [["none", "none"]],
                }
            ],
            defs,
        )


@pytest.mark.parametrize("value", [["lan", "wan"], {"lan": None}])
def test_a_field_takes_one_value(value):
    with pytest.raises(BuildError, match="takes one value"):
        _set(["iifname", "dport"], [[value, 22]], "tcp")


def test_addresses_and_ports_still_take_one_value():
    defs = Definitions.from_mappings(
        {
            "networks": {"two": ["192.0.2.1", "192.0.2.2"]},
            "interfaces": {"lan": ["lan0"]},
        }
    )
    with pytest.raises(BuildError, match="2 values"):
        build_sets(
            [{"name": "f", "concat": ["iifname", "saddr"], "tuples": [["lan", "two"]]}],
            defs,
        )


def test_rule_renders_the_lookup_as_before():
    s = _set(["iifname", "daddr", "dport"], [["lan", "db", "postgres"]], "tcp")
    r = RuleRenderer(DEFS, {"f": s})
    assert r.render({"set": "f", "action": "accept"}) == [
        "iifname . ip daddr . tcp dport @f accept"
    ]


TABLES = [
    {
        "family": "inet",
        "name": "filter",
        "sets": [
            {
                "name": "to_db",
                "concat": ["iifname", "daddr", "dport"],
                "proto": "tcp",
                "tuples": [["lan", "db", "postgres"], ["lan0_only", "db", 5433]],
            }
        ],
        "chains": [
            {
                "name": "forward",
                "hook": "forward",
                "rules": [{"set": "to_db", "action": "accept"}],
            }
        ],
    }
]


def test_tables_render():
    text = render_tables(TABLES, DEFS, DictResolver({}))
    assert (
        "        type ifname . ipv4_addr . inet_service\n"
        '        elements = { "lan0" . 192.0.2.20 . 5432, "lan1" . 192.0.2.20 . 5432, '
        '"lan0" . 192.0.2.20 . 5433 }\n'
    ) in text


@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_passes_nft_check():
    result = validate.check(render_tables(TABLES, DEFS, DictResolver({})))
    assert result.ok, result.stderr

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError
from nftgen.rules import RuleRenderer

DEFS = Definitions.from_mappings(
    {
        "interfaces": {
            "lan": ["lan0", "lan1"],
            "mgmt": ["mgmt0"],
            "dmz": ["dmz0"],
            "wan": ["wan0"],
        },
        "networks": {
            "admins": ["192.0.2.10"],
            "ops": ["192.0.2.20", "192.0.2.21"],
            "admins_v6": ["2001:db8::10"],
        },
        "services": {"ssh": ["22/tcp"], "dns": ["53/tcp", "53/udp"]},
    }
)
R = RuleRenderer(DEFS, {})


def _vmap(keys, *entries):
    return R.render({"vmap": {"key": keys, "map": list(entries)}})


def test_an_interface_list_is_one_row_per_group():
    assert _vmap(
        ["iifname", "oifname"],
        {"match": [["lan", "mgmt"], "wan"], "jump": "to_wan"},
    ) == _vmap(
        ["iifname", "oifname"],
        {"match": ["lan", "wan"], "jump": "to_wan"},
        {"match": ["mgmt", "wan"], "jump": "to_wan"},
    )


def test_lists_in_two_columns_cross():
    assert _vmap(
        ["iifname", "oifname"],
        {"match": [["mgmt", "dmz"], ["wan", "lan"]], "action": "accept"},
    ) == _vmap(
        ["iifname", "oifname"],
        {"match": ["mgmt", "wan"], "action": "accept"},
        {"match": ["mgmt", "lan"], "action": "accept"},
        {"match": ["dmz", "wan"], "action": "accept"},
        {"match": ["dmz", "lan"], "action": "accept"},
    )


def test_an_address_list_is_one_row_per_value():
    assert _vmap(
        ["saddr", "oifname"],
        {"match": [["admins", "ops", "192.0.2.30"], "mgmt"], "action": "accept"},
    ) == _vmap(
        ["saddr", "oifname"],
        {"match": ["admins", "mgmt"], "action": "accept"},
        {"match": ["ops", "mgmt"], "action": "accept"},
        {"match": ["192.0.2.30", "mgmt"], "action": "accept"},
    )


def test_an_address_list_stays_single_family():
    with pytest.raises(BuildError, match="mixes IP families"):
        _vmap(
            ["saddr", "oifname"],
            {"match": [["admins", "admins_v6"], "mgmt"], "action": "accept"},
        )


def test_a_port_list_takes_the_row_proto():
    assert _vmap(
        ["proto", "dport"],
        {"match": ["tcp", ["ssh", 8080]], "jump": "svc"},
    ) == ["meta l4proto . th dport vmap { tcp . 22 : jump svc, tcp . 8080 : jump svc }"]


def test_a_proto_list_pins_each_row():
    assert _vmap(
        ["proto", "dport"],
        {"match": [["tcp", "udp"], "dns"], "jump": "dns_in"},
    ) == [
        "meta l4proto . th dport vmap { tcp . 53 : jump dns_in, udp . 53 : jump dns_in }"
    ]


def test_a_mark_list():
    assert _vmap(
        ["mark", "oifname"],
        {"match": [["0x1", "0x2"], "wan"], "action": "accept"},
    ) == ['meta mark . oifname vmap { 0x1 . "wan0" : accept, 0x2 . "wan0" : accept }']


def test_a_value_two_rows_share_is_folded():
    assert _vmap(
        ["iifname", "oifname"],
        {"match": [["lan", "lan"], "wan"], "action": "drop"},
    ) == ['iifname . oifname vmap { "lan0" . "wan0" : drop, "lan1" . "wan0" : drop }']


def test_a_list_that_repeats_a_key_with_another_verdict_fails():
    with pytest.raises(BuildError, match="comes from both"):
        _vmap(
            ["iifname", "oifname"],
            {"match": [["lan", "mgmt"], "wan"], "action": "accept"},
            {"match": ["mgmt", "wan"], "action": "drop"},
        )


@pytest.mark.parametrize(
    "column",
    [[], [["lan"]], [{"not": "lan"}], {"not": "lan"}, {"lan": "wan"}],
)
def test_a_column_takes_one_value_or_a_flat_list(column):
    with pytest.raises(BuildError, match="takes one value or a non-empty list"):
        _vmap(["iifname", "oifname"], {"match": [column, "wan"], "action": "accept"})


def test_an_unknown_group_in_a_list_fails():
    with pytest.raises(BuildError, match="'nope' is not a known interface group"):
        _vmap(["iifname", "oifname"], {"match": [["lan", "nope"], "wan"], "jump": "x"})


TABLES = [
    {
        "family": "inet",
        "name": "filter",
        "chains": [
            {"name": "to_wan", "rules": [{"action": "accept"}]},
            {"name": "svc", "rules": [{"action": "accept"}]},
            {
                "name": "forward",
                "hook": "forward",
                "rules": [
                    {
                        "vmap": {
                            "key": ["iifname", "oifname"],
                            "map": [
                                {
                                    "match": [["lan", "mgmt", "dmz"], "wan"],
                                    "jump": "to_wan",
                                },
                                {"match": ["wan", ["lan", "dmz"]], "action": "drop"},
                            ],
                        }
                    },
                    {
                        "vmap": {
                            "key": ["saddr", "proto", "dport"],
                            "map": [
                                {
                                    "match": [["admins", "ops"], ["tcp", "udp"], "dns"],
                                    "jump": "svc",
                                }
                            ],
                        }
                    },
                ],
            },
        ],
    }
]


@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_passes_nft_check():
    result = validate.check(render_tables(TABLES, DEFS, DictResolver({})))
    assert result.ok, result.stderr

"""Phase 6D — verdict maps (vmap rule type)."""
import pytest

from nftgen.definitions import Definitions
from nftgen.ir import BuildError
from nftgen.rules import RuleRenderer

R = RuleRenderer(Definitions.from_mappings({}), {})


def test_iif_vmap():
    rule = {"vmap": {"key": "iif", "map": {"wan0": {"jump": "wan_input"}, "lan0": {"jump": "lan_input"}}}}
    assert R.render(rule) == [
        'iifname vmap { "wan0" : jump wan_input, "lan0" : jump lan_input }'
    ]


def test_proto_vmap_unquoted_keys_and_verdicts():
    rule = {"vmap": {"key": "proto", "map": {"tcp": {"goto": "tcp_chain"}, "udp": "drop"}}}
    assert R.render(rule) == ["meta l4proto vmap { tcp : goto tcp_chain, udp : drop }"]


def test_unsupported_vmap_key_errors():
    with pytest.raises(BuildError):
        R.render({"vmap": {"key": "dport", "map": {"80": "accept"}}})


# -- concatenated (iif . oif) vmap ------------------------------------------ #
RI = RuleRenderer(
    Definitions.from_mappings(
        {"interfaces": {"users": ["lan0"], "uplinks": ["wan0", "wwan0"], "servers": ["svc0"]}}
    ),
    {},
)


def test_concat_vmap_iif_oif_expands_groups():
    rule = {
        "vmap": {
            "key": ["iif", "oif"],
            "map": [
                {"match": ["users", "uplinks"], "jump": "fwd_users_inet"},
                {"match": ["users", "servers"], "jump": "fwd_users_servers"},
            ],
        }
    }
    assert RI.render(rule) == [
        "iifname . oifname vmap { "
        '"lan0" . "wan0" : jump fwd_users_inet, '
        '"lan0" . "wwan0" : jump fwd_users_inet, '
        '"lan0" . "svc0" : jump fwd_users_servers }'
    ]


def test_concat_vmap_literal_devices():
    rule = {"vmap": {"key": ["iif", "oif"], "map": [{"match": ["eth0", "eth1"], "goto": "x"}]}}
    assert R.render(rule) == ['iifname . oifname vmap { "eth0" . "eth1" : goto x }']


def test_concat_vmap_match_arity_error():
    with pytest.raises(BuildError):
        RI.render({"vmap": {"key": ["iif", "oif"], "map": [{"match": ["users"], "jump": "x"}]}})

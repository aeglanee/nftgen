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
        R.render({"vmap": {"key": "dscp", "map": {"0x1": "accept"}}})


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


# -- more single-key vmaps: ports / mark / state / addresses ----------------- #
RN = RuleRenderer(
    Definitions.from_mappings(
        {"networks": {"admins": ["192.168.10.8/29"], "trusted6": ["2001:db8::/48"]}}
    ),
    {},
)


def test_dport_vmap_transport_agnostic():
    rule = {"vmap": {"key": "dport", "map": {22: {"jump": "ssh_in"}, 80: {"jump": "web_in"}}}}
    assert R.render(rule) == ["th dport vmap { 22 : jump ssh_in, 80 : jump web_in }"]


def test_mark_and_state_vmaps():
    assert R.render({"vmap": {"key": "mark", "map": {"0x1": {"jump": "a"}}}}) == [
        "meta mark vmap { 0x1 : jump a }"
    ]
    assert R.render(
        {"vmap": {"key": "state", "map": {"established": "accept", "new": {"jump": "n"}}}}
    ) == ["ct state vmap { established : accept, new : jump n }"]


def test_saddr_vmap_resolves_group_keeps_family():
    rule = {"vmap": {"key": "saddr", "map": {"admins": {"jump": "admin_in"}, "10.0.0.0/8": "drop"}}}
    assert RN.render(rule) == [
        "ip saddr vmap { 192.168.10.8/29 : jump admin_in, 10.0.0.0/8 : drop }"
    ]


def test_daddr_vmap_v6():
    assert RN.render({"vmap": {"key": "daddr", "map": {"trusted6": {"jump": "x"}}}}) == [
        "ip6 daddr vmap { 2001:db8::/48 : jump x }"
    ]


def test_saddr_vmap_mixed_family_errors():
    with pytest.raises(BuildError):
        RN.render({"vmap": {"key": "saddr", "map": {"10.0.0.0/8": "accept", "2001:db8::/48": "drop"}}})


def test_address_key_rejected_in_concat():
    with pytest.raises(BuildError):
        RN.render(
            {"vmap": {"key": ["saddr", "dport"], "map": [{"match": ["admins", 22], "jump": "x"}]}}
        )

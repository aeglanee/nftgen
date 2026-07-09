"""Phase 6D — verdict maps (vmap rule type)."""

import pytest

from nftgen.definitions import Definitions
from nftgen.ir import BuildError
from nftgen.rules import RuleRenderer

R = RuleRenderer(Definitions.from_mappings({}), {})
# per-device dispatch happens through one-device groups (strict: no literals)
RD = RuleRenderer(
    Definitions.from_mappings({"interfaces": {"wan0": ["wan0"], "lan0": ["lan0"]}}), {}
)


def test_iif_vmap():
    rule = {
        "vmap": {
            "key": "iif",
            "map": {"wan0": {"jump": "wan_input"}, "lan0": {"jump": "lan_input"}},
        }
    }
    assert RD.render(rule) == [
        'iifname vmap { "wan0" : jump wan_input, "lan0" : jump lan_input }'
    ]


def test_iif_vmap_unknown_group_errors():
    with pytest.raises(BuildError, match="not a known interface group"):
        R.render({"vmap": {"key": "iif", "map": {"wan0": {"jump": "wan_input"}}}})


def test_vmap_needs_map():
    with pytest.raises(BuildError, match="needs a non-empty `map:`"):
        R.render({"vmap": {"key": "iif"}})


def test_vmap_unknown_spec_key_errors():
    with pytest.raises(BuildError, match="unknown vmap key"):
        R.render({"vmap": {"key": "proto", "maps": {"tcp": "accept"}}})  # typo'd `map:`


def test_proto_vmap_unquoted_keys_and_verdicts():
    rule = {
        "vmap": {"key": "proto", "map": {"tcp": {"goto": "tcp_chain"}, "udp": "drop"}}
    }
    assert R.render(rule) == ["meta l4proto vmap { tcp : goto tcp_chain, udp : drop }"]


def test_unsupported_vmap_key_errors():
    with pytest.raises(BuildError):
        R.render({"vmap": {"key": "dscp", "map": {"0x1": "accept"}}})


# -- concatenated (iif . oif) vmap ------------------------------------------ #
RI = RuleRenderer(
    Definitions.from_mappings(
        {
            "interfaces": {
                "users": ["lan0"],
                "uplinks": ["wan0", "wwan0"],
                "servers": ["svc0"],
            }
        }
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


def test_concat_vmap_unknown_device_errors():
    rule = {
        "vmap": {
            "key": ["iif", "oif"],
            "map": [{"match": ["eth0", "eth1"], "goto": "x"}],
        }
    }
    with pytest.raises(BuildError, match="not a known interface group"):
        R.render(rule)


def test_concat_vmap_match_arity_error():
    with pytest.raises(BuildError):
        RI.render(
            {
                "vmap": {
                    "key": ["iif", "oif"],
                    "map": [{"match": ["users"], "jump": "x"}],
                }
            }
        )


# -- more single-key vmaps: ports / mark / state / addresses ----------------- #
RN = RuleRenderer(
    Definitions.from_mappings(
        {
            "networks": {"admins": ["192.168.10.8/29"], "trusted6": ["2001:db8::/48"]},
            "services": {"ssh": ["22/tcp"], "web": ["80/tcp", "443/tcp"]},
            "interfaces": {"users": ["lan0"], "uplinks": ["wan0", "wwan0"]},
        }
    ),
    {},
)


def test_dport_vmap_transport_agnostic():
    rule = {
        "vmap": {
            "key": "dport",
            "map": {22: {"jump": "ssh_in"}, 80: {"jump": "web_in"}},
        }
    }
    assert R.render(rule) == ["th dport vmap { 22 : jump ssh_in, 80 : jump web_in }"]


def test_mark_and_state_vmaps():
    assert R.render({"vmap": {"key": "mark", "map": {"0x1": {"jump": "a"}}}}) == [
        "meta mark vmap { 0x1 : jump a }"
    ]
    assert R.render(
        {
            "vmap": {
                "key": "state",
                "map": {"established": "accept", "new": {"jump": "n"}},
            }
        }
    ) == ["ct state vmap { established : accept, new : jump n }"]


def test_saddr_vmap_resolves_group_keeps_family():
    rule = {
        "vmap": {
            "key": "saddr",
            "map": {"admins": {"jump": "admin_in"}, "10.0.0.0/8": "drop"},
        }
    }
    assert RN.render(rule) == [
        "ip saddr vmap { 192.168.10.8/29 : jump admin_in, 10.0.0.0/8 : drop }"
    ]


def test_daddr_vmap_v6():
    assert RN.render(
        {"vmap": {"key": "daddr", "map": {"trusted6": {"jump": "x"}}}}
    ) == ["ip6 daddr vmap { 2001:db8::/48 : jump x }"]


def test_saddr_vmap_mixed_family_errors():
    with pytest.raises(BuildError):
        RN.render(
            {
                "vmap": {
                    "key": "saddr",
                    "map": {"10.0.0.0/8": "accept", "2001:db8::/48": "drop"},
                }
            }
        )


def test_dport_vmap_resolves_service_bundle():
    # web -> 80,443 (two elements, same verdict); a number stays literal
    rule = {"vmap": {"key": "dport", "map": {"web": {"jump": "w"}, 53: {"jump": "d"}}}}
    assert RN.render(rule) == [
        "th dport vmap { 80 : jump w, 443 : jump w, 53 : jump d }"
    ]


def test_dport_vmap_unknown_name_errors():
    with pytest.raises(BuildError, match="not a known service group"):
        RN.render({"vmap": {"key": "dport", "map": {"weird": "drop"}}})


def test_iif_vmap_expands_group_single_key():
    rule = {"vmap": {"key": "iif", "map": {"uplinks": {"jump": "wan_in"}}}}
    assert RN.render(rule) == [
        'iifname vmap { "wan0" : jump wan_in, "wwan0" : jump wan_in }'
    ]


def test_concat_saddr_dport_family_aware():
    rule = {
        "vmap": {
            "key": ["saddr", "dport"],
            "map": [{"match": ["admins", "ssh"], "jump": "admin_ssh"}],
        }
    }
    assert RN.render(rule) == [
        "ip saddr . th dport vmap { 192.168.10.8/29 . 22 : jump admin_ssh }"
    ]


def test_large_vmap_wraps_one_entry_per_line():
    rule = {
        "vmap": {
            "key": "proto",
            "map": {
                "tcp": {"jump": "t"},
                "udp": {"jump": "u"},
                "icmp": {"jump": "i"},
                "sctp": {"jump": "s"},
            },
        }
    }
    assert R.render(rule) == [
        "meta l4proto vmap {\n"
        "            tcp : jump t,\n"
        "            udp : jump u,\n"
        "            icmp : jump i,\n"
        "            sctp : jump s\n"
        "        }"
    ]

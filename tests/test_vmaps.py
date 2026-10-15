"""Phase 6D — verdict maps (vmap rule type)."""

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.ir import BuildError, Table
from nftgen.rules import RuleRenderer, build_chain

R = RuleRenderer(Definitions.from_mappings({}), {})
# per-device dispatch happens through one-device groups (strict: no literals)
RD = RuleRenderer(
    Definitions.from_mappings({"interfaces": {"wan0": ["wan0"], "lan0": ["lan0"]}}), {}
)


def test_iif_vmap():
    rule = {
        "vmap": {
            "key": "iifname",
            "map": {"wan0": {"jump": "wan_input"}, "lan0": {"jump": "lan_input"}},
        }
    }
    assert RD.render(rule) == [
        'iifname vmap { "wan0" : jump wan_input, "lan0" : jump lan_input }'
    ]


def test_iif_index_vmap():
    # the index form dispatches too — same names (nft resolves at load), keyword iif
    rule = {
        "vmap": {
            "key": "iif",
            "map": {"wan0": {"jump": "wan_input"}, "lan0": {"jump": "lan_input"}},
        }
    }
    assert RD.render(rule) == [
        'iif vmap { "wan0" : jump wan_input, "lan0" : jump lan_input }'
    ]


def test_concat_iif_oif_index_vmap():
    rd = RuleRenderer(
        Definitions.from_mappings({"interfaces": {"wan0": ["wan0"], "lan0": ["lan0"]}}),
        {},
    )
    rule = {
        "vmap": {
            "key": ["iif", "oif"],
            "map": [{"match": ["lan0", "wan0"], "jump": "fwd"}],
        }
    }
    assert rd.render(rule) == ['iif . oif vmap { "lan0" . "wan0" : jump fwd }']


def test_iif_vmap_unknown_group_errors():
    with pytest.raises(BuildError, match="not a known interface group"):
        R.render({"vmap": {"key": "iifname", "map": {"wan0": {"jump": "wan_input"}}}})


def test_vmap_needs_map():
    with pytest.raises(BuildError, match="needs a non-empty `map:`"):
        R.render({"vmap": {"key": "iifname"}})


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
            "key": ["iifname", "oifname"],
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
            "key": ["iifname", "oifname"],
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
                    "key": ["iifname", "oifname"],
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


def test_dport_vmap_literal_port_proto_pairs():
    rule = {
        "vmap": {
            "key": "dport",
            "map": {"22/tcp": {"jump": "ssh_in"}, "53/udp": {"jump": "dns_in"}},
        }
    }
    assert R.render(rule) == [
        "meta l4proto . th dport vmap { tcp . 22 : jump ssh_in, udp . 53 : jump dns_in }"
    ]


def test_dport_vmap_bare_number_needs_proto():
    # C3: `th dport vmap { 22 : … }` matched any protocol (udp/22 too)
    with pytest.raises(BuildError, match="'22' has no protocol .* write 22/tcp"):
        R.render({"vmap": {"key": "dport", "map": {22: {"jump": "ssh_in"}}}})


def test_dport_vmap_port_range_pair():
    rule = {"vmap": {"key": "sport", "map": {"8000-8100/tcp": "drop"}}}
    assert R.render(rule) == ["meta l4proto . th sport vmap { tcp . 8000-8100 : drop }"]


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
    # web -> tcp . 80, tcp . 443 (two elements, same verdict)
    rule = {
        "vmap": {"key": "dport", "map": {"web": {"jump": "w"}, "53/udp": {"jump": "d"}}}
    }
    assert RN.render(rule) == [
        "meta l4proto . th dport vmap { tcp . 80 : jump w, tcp . 443 : jump w, udp . 53 : jump d }"
    ]


_MIXED = Definitions.from_mappings(
    {
        "services": {"web": ["80/tcp", "443/tcp", "443/udp"], "ssh": ["22/tcp"]},
        "interfaces": {"lan": ["lan0"]},
    }
)
_MR = RuleRenderer(_MIXED, {})


def test_dport_vmap_service_keeps_each_proto():
    # C3: a service's ports used to merge into `th dport` (any protocol)
    rule = {"vmap": {"key": "dport", "map": {"web": "accept"}}}
    assert _MR.render(rule) == [
        "meta l4proto . th dport vmap { tcp . 80 : accept, tcp . 443 : accept, udp . 443 : accept }"
    ]


def test_concat_proto_dport_filters_service_by_row_proto():
    # C3: `match: [udp, web]` used to yield udp . 80 too
    rule = {
        "vmap": {
            "key": ["proto", "dport"],
            "map": [{"match": ["udp", "web"], "jump": "q"}],
        }
    }
    assert _MR.render(rule) == ["meta l4proto . th dport vmap { udp . 443 : jump q }"]


def test_concat_proto_dport_row_proto_without_ports_errors():
    rule = {
        "vmap": {
            "key": ["proto", "dport"],
            "map": [{"match": ["udp", "ssh"], "jump": "q"}],
        }
    }
    with pytest.raises(BuildError, match="service 'ssh' has no udp ports"):
        _MR.render(rule)


def test_concat_proto_column_allows_bare_number():
    # the row's proto column pins the protocol, so a bare port is unambiguous
    rule = {
        "vmap": {
            "key": ["proto", "dport"],
            "map": [{"match": ["tcp", 8080], "jump": "q"}],
        }
    }
    assert _MR.render(rule) == ["meta l4proto . th dport vmap { tcp . 8080 : jump q }"]


def test_concat_literal_pair_must_agree_with_row_proto():
    rule = {
        "vmap": {
            "key": ["proto", "dport"],
            "map": [{"match": ["udp", "8080/tcp"], "jump": "q"}],
        }
    }
    with pytest.raises(BuildError, match="is tcp, but the row's proto is udp"):
        _MR.render(rule)


def test_concat_dport_without_proto_column_becomes_pair():
    rule = {
        "vmap": {
            "key": ["iifname", "dport"],
            "map": [{"match": ["lan", "web"], "jump": "q"}],
        }
    }
    assert _MR.render(rule) == [
        'iifname . meta l4proto . th dport vmap { "lan0" . tcp . 80 : jump q, '
        '"lan0" . tcp . 443 : jump q, "lan0" . udp . 443 : jump q }'
    ]


def test_dport_vmap_unknown_name_errors():
    with pytest.raises(BuildError, match="not a known service"):
        RN.render({"vmap": {"key": "dport", "map": {"weird": "drop"}}})


def test_iif_vmap_expands_group_single_key():
    rule = {"vmap": {"key": "iifname", "map": {"uplinks": {"jump": "wan_in"}}}}
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
        "ip saddr . meta l4proto . th dport vmap { 192.168.10.8/29 . tcp . 22 : jump admin_ssh }"
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


# -- C16: verdicts in vmaps ------------------------------------------------------ #
_IF = Definitions.from_mappings(
    {"interfaces": {"lan": ["lan0"], "wan": ["wan0"], "mgmt": ["mgmt0"]}}
)
_IR = RuleRenderer(_IF, {})


def test_concat_vmap_rows_take_action():
    # C16: rows could only jump/goto; `accept`/`drop` needed a one-rule chain
    rule = {
        "vmap": {
            "key": ["iifname", "oifname"],
            "map": [
                {"match": ["lan", "wan"], "jump": "lan_to_wan"},
                {"match": ["lan", "mgmt"], "action": "accept"},
                {"match": ["wan", "lan"], "action": "drop"},
                {"match": ["mgmt", "lan"], "action": {"goto": "mgmt_in"}},
            ],
        }
    }
    assert _IR.render(rule) == [
        "iifname . oifname vmap {\n"
        '            "lan0" . "wan0" : jump lan_to_wan,\n'
        '            "lan0" . "mgmt0" : accept,\n'
        '            "wan0" . "lan0" : drop,\n'
        '            "mgmt0" . "lan0" : goto mgmt_in\n'
        "        }"
    ]


@pytest.mark.parametrize(
    "bad_verdict", ["reject", "reject with tcp reset", "masquerade"]
)
def test_non_verdicts_cannot_go_in_a_vmap(bad_verdict):
    # nft refuses these in a vmap with a syntax error — single-key vmaps used
    # to pass any word straight through
    with pytest.raises(BuildError, match="can't go in a vmap"):
        _IR.render({"vmap": {"key": "iifname", "map": {"lan": bad_verdict}}})
    with pytest.raises(BuildError, match="can't go in a vmap"):
        _IR.render(
            {
                "vmap": {
                    "key": ["iifname", "oifname"],
                    "map": [{"match": ["lan", "wan"], "action": bad_verdict}],
                }
            }
        )


def test_concat_vmap_row_needs_exactly_one_verdict():
    rule = {
        "vmap": {
            "key": ["iifname", "oifname"],
            "map": [{"match": ["lan", "wan"], "action": "accept", "jump": "x"}],
        }
    }
    with pytest.raises(BuildError, match="exactly one verdict"):
        _IR.render(rule)


@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_vmap_verdicts_pass_nft_check():
    chain = build_chain(
        {
            "name": "forward",
            "hook": "forward",
            "rules": [
                {
                    "vmap": {
                        "key": ["iifname", "oifname"],
                        "map": [
                            {"match": ["lan", "mgmt"], "action": "accept"},
                            {"match": ["wan", "lan"], "action": "drop"},
                            {"match": ["lan", "wan"], "action": "return"},
                        ],
                    }
                }
            ],
        },
        _IR,
    )
    result = validate.check(
        Table(family="inet", name="filter", chains=[chain]).render()
    )
    assert result.ok, result.stderr


# -- review N3: duplicate keys --------------------------------------------------- #
_DUP = Definitions.from_mappings(
    {
        "services": {
            "dns": ["53/tcp", "53/udp"],
            "web": ["80/tcp"],
            "http": ["80/tcp"],
        },
        "interfaces": {"lan": ["lan0"], "all": ["lan0", "wan0"]},
        "networks": {"a": ["10.0.0.0/8"], "b": ["10.0.0.0/8", "192.168.0.0/16"]},
    }
)
_DR = RuleRenderer(_DUP, {})


def test_vmap_same_key_different_verdict_errors():
    # nft refused this at load ("element exists") on the generated file
    with pytest.raises(BuildError, match=r"vmap key 'udp . 53' comes from both 'dns'"):
        _DR.render(
            {"vmap": {"key": "dport", "map": {"dns": "accept", "53/udp": "drop"}}}
        )
    with pytest.raises(BuildError, match="comes from both 'lan'"):
        _DR.render(
            {"vmap": {"key": "iifname", "map": {"lan": "accept", "all": "drop"}}}
        )
    with pytest.raises(BuildError, match="comes from both 'a'"):
        _DR.render({"vmap": {"key": "saddr", "map": {"a": "accept", "b": "drop"}}})
    with pytest.raises(BuildError, match="comes from both"):
        _DR.render(
            {
                "vmap": {
                    "key": ["iifname", "dport"],
                    "map": [
                        {"match": ["lan", "web"], "action": "accept"},
                        {"match": ["all", "http"], "action": "drop"},
                    ],
                }
            }
        )


def test_vmap_same_key_same_verdict_is_folded():
    assert _DR.render(
        {"vmap": {"key": "iifname", "map": {"lan": "accept", "all": "accept"}}}
    ) == ['iifname vmap { "lan0" : accept, "wan0" : accept }']


def test_dnat_map_duplicate_port_errors():
    rule = {
        "proto": "tcp",
        "action": {
            "dnat": {"proto": "tcp", "map": {"web": "10.0.0.5", 80: "10.0.0.6"}}
        },
    }
    with pytest.raises(BuildError, match=r"dnat map key '80' comes from both 'web'"):
        _DR.render(rule)

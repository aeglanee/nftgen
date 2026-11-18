import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError, build_sets
from nftgen.rules import RuleRenderer

DEFS = Definitions.from_mappings(
    {
        "interfaces": {"wan": ["wan0"]},
        "networks": {
            "lan_v4": ["192.0.2.0/24"],
            "lan_v6": ["2001:db8::/64"],
            "both": ["192.0.2.0/24", "2001:db8::/64"],
        },
    }
)
R = RuleRenderer(DEFS, {})
ND = ["nd-neighbor-solicit", "nd-neighbor-advert", "nd-router-advert"]


@pytest.mark.parametrize(
    ("rule", "line"),
    [
        ({"pkttype": "host"}, "meta pkttype host"),
        (
            {"pkttype": ["broadcast", "multicast"]},
            "meta pkttype { broadcast, multicast }",
        ),
        ({"pkttype": {"not": "host"}}, "meta pkttype != host"),
        ({"ttl": 255}, "ip ttl 255"),
        ({"ttl": "1-5"}, "ip ttl 1-5"),
        ({"ttl": {"not": [1, "250-255"]}}, "ip ttl != { 1, 250-255 }"),
        ({"hoplimit": 255}, "ip6 hoplimit 255"),
        ({"hoplimit": {"not": 255}}, "ip6 hoplimit != 255"),
        ({"ct-status": "dnat"}, "ct status dnat"),
        ({"ct-status": ["dnat", "snat"]}, "ct status dnat,snat"),
        (
            {"proto": "icmp", "icmp-code": ["port-unreachable", "frag-needed"]},
            "icmp code { port-unreachable, frag-needed }",
        ),
        (
            {"proto": "icmpv6", "icmp-type": "destination-unreachable", "icmp-code": 4},
            "icmpv6 type destination-unreachable icmpv6 code 4",
        ),
    ],
)
def test_renders(rule, line):
    assert R.render({**rule, "action": "accept"}) == [f"{line} accept"]


def test_ttl_and_hoplimit_pick_their_family_from_the_addresses():
    assert R.render({"saddr": "both", "ttl": 1, "action": "drop"}) == [
        "ip saddr 192.0.2.0/24 ip ttl 1 drop"
    ]
    assert R.render({"saddr": "both", "hoplimit": 1, "action": "drop"}) == [
        "ip6 saddr 2001:db8::/64 ip6 hoplimit 1 drop"
    ]


def test_the_neighbour_discovery_hop_limit_rule():
    rule = {
        "iifname": "wan",
        "proto": "icmpv6",
        "icmp-type": ND,
        "hoplimit": {"not": 255},
        "action": "drop",
    }
    assert R.render(rule) == [
        'iifname "wan0" ip6 hoplimit != 255 icmpv6 type { nd-neighbor-solicit, '
        "nd-neighbor-advert, nd-router-advert } drop"
    ]


@pytest.mark.parametrize(
    ("rule", "message"),
    [
        ({"saddr": "lan_v6", "ttl": 64}, "`ttl` is IPv4-only"),
        ({"saddr": "lan_v4", "hoplimit": 64}, "`hoplimit` is IPv6-only"),
        ({"ttl": 64, "hoplimit": 64}, "different IP families"),
        ({"proto": "icmpv6", "ttl": 64}, "different IP families"),
        ({"proto": "icmp", "hoplimit": 64}, "different IP families"),
        ({"icmp-code": 4}, "icmp-code needs `proto: icmp`"),
        ({"proto": "udp", "icmp-code": 4}, "icmp-code needs `proto: icmp`"),
        ({"proto": "icmp", "icmp-code": 4, "dport": 22}, "icmp has no ports"),
        ({"ttl": 256}, "a number 0-255"),
        ({"ttl": "5-1"}, "a number 0-255"),
        ({"ttl": "64-"}, "a number 0-255"),
        ({"ttl": True}, "a number 0-255"),
        ({"ttl": "\u0666\u0664"}, "a number 0-255"),
        ({"hoplimit": "\uff16\uff14"}, "a number 0-255"),
        ({"hoplimit": []}, "non-empty list"),
        ({"pkttype": "bcast"}, "a packet type"),
        ({"ct-status": "new"}, "a ct status"),
        ({"ct-status": {"not": "dnat"}}, "a ct status"),
    ],
)
def test_bad_values_fail(rule, message):
    with pytest.raises(BuildError, match=message):
        R.render({**rule, "action": "accept"})


SETS = build_sets(
    [
        {"name": "m4", "type": "ipv4_addr", "flags": ["dynamic", "timeout"]},
        {"name": "m6", "type": "ipv6_addr", "flags": ["dynamic", "timeout"]},
        {
            "name": "v6_in",
            "concat": ["saddr", "iifname"],
            "tuples": [["lan_v6", "wan"]],
        },
    ],
    DEFS,
)
RS = RuleRenderer(DEFS, {s.name: s for s in SETS})
M4 = {"set": "m4", "key": "saddr", "rate": "1/second"}
M6 = {"set": "m6", "key": "saddr", "rate": "1/second"}


@pytest.mark.parametrize(
    "rule",
    [
        {"hoplimit": 64, "action": {"snat": "192.0.2.1"}},
        {"ttl": 64, "action": {"dnat": "2001:db8::1"}},
        {"ttl": 64, "action": {"dnat": {"proto": "tcp", "map": {80: "2001:db8::5"}}}},
        {"proto": "icmpv6", "action": {"snat": "192.0.2.1"}},
        {"ttl": 64, "meter": M6, "action": "drop"},
        {"hoplimit": 64, "meter": M4, "action": "drop"},
        {"saddr": "lan_v6", "meter": M4, "action": "drop"},
        {"saddr": "both", "meter": M4, "action": "drop"},
        {"meter": M6, "action": {"snat": "192.0.2.1"}},
        {"set": "v6_in", "meter": M4, "action": "drop"},
    ],
    ids=[
        "hoplimit snat ip",
        "ttl dnat ip6",
        "ttl dnat ip6 map",
        "icmpv6 snat ip",
        "ttl ip6 meter",
        "hoplimit ip meter",
        "v6 address ip meter",
        "both families ip meter",
        "ip6 meter snat ip",
        "v6 concat ip meter",
    ],
)
def test_a_family_bound_meets_what_the_rule_does(rule):
    with pytest.raises(BuildError, match="are one family"):
        RS.render(rule)


def test_a_concat_rule_checks_its_meter_before_its_family():
    meter = {"set": "nope", "key": "saddr", "rate": "1/second"}
    with pytest.raises(BuildError, match="not a declared set"):
        RS.render({"set": "v6_in", "meter": meter, "action": "drop"})


def test_a_family_bound_keeps_what_shares_its_family():
    assert RS.render({"hoplimit": 64, "action": {"snat": "2001:db8::1"}}) == [
        "ip6 hoplimit 64 snat ip6 to 2001:db8::1"
    ]
    assert RS.render({"ttl": 1, "meter": M4, "action": "drop"}) == [
        "ip ttl 1 update @m4 { ip saddr limit rate 1/second } drop"
    ]


TABLES = [
    {
        "family": "inet",
        "name": "filter",
        "chains": [
            {
                "name": "input",
                "hook": "input",
                "rules": [
                    {"pkttype": ["broadcast", "multicast"], "action": "drop"},
                    {
                        "pkttype": {"not": ["host", "unicast", "other"]},
                        "action": "drop",
                    },
                    {"ttl": {"not": [1, "250-255"]}, "action": "accept"},
                    {"saddr": "both", "ttl": 1, "action": "drop"},
                    {
                        "iifname": "wan",
                        "proto": "icmpv6",
                        "icmp-type": ND,
                        "hoplimit": {"not": 255},
                        "action": "drop",
                    },
                    {"ct-status": ["dnat", "snat"], "action": "accept"},
                    {
                        "ct-status": [
                            "expected",
                            "seen-reply",
                            "assured",
                            "confirmed",
                            "dying",
                        ],
                        "action": "accept",
                    },
                    {
                        "proto": "icmp",
                        "icmp-code": [
                            "net-unreachable",
                            "host-unreachable",
                            "prot-unreachable",
                            "port-unreachable",
                            "frag-needed",
                            "net-prohibited",
                            "host-prohibited",
                            "admin-prohibited",
                        ],
                        "action": "accept",
                    },
                    {
                        "proto": "icmpv6",
                        "icmp-type": "destination-unreachable",
                        "icmp-code": [
                            "no-route",
                            "admin-prohibited",
                            "addr-unreachable",
                            "port-unreachable",
                            "policy-fail",
                            "reject-route",
                        ],
                        "action": "accept",
                    },
                ],
            }
        ],
    }
]


@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_passes_nft_check():
    result = validate.check(render_tables(TABLES, DEFS, DictResolver({})))
    assert result.ok, result.stderr

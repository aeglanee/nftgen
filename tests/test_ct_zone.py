import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError, build_sets
from nftgen.rules import RuleRenderer

DEFS = Definitions.from_mappings(
    {
        "interfaces": {"wan": ["wan0"], "uplinks": ["wan0", "wan1"], "lo": ["lo"]},
        "networks": {"peer": ["192.0.2.2/32", "2001:db8::2/128"]},
        "services": {"ssh": ["22/tcp"]},
    }
)
R = RuleRenderer(DEFS, {s.name: s for s in build_sets(["ssh"], DEFS)})


@pytest.mark.parametrize(
    ("zone", "line"),
    [
        (1, "ct zone set 1"),
        (0, "ct zone set 0"),
        (65535, "ct zone set 65535"),
        ("2", "ct zone set 2"),
        ("0x10", "ct zone set 0x10"),
        ("0xffff", "ct zone set 0xffff"),
    ],
)
def test_renders(zone, line):
    assert R.render({"set-ct-zone": zone}) == [line]


def test_follows_the_matches_and_precedes_the_verdict():
    assert R.render({"iifname": "wan", "set-ct-zone": 1, "action": "accept"}) == [
        'iifname "wan0" ct zone set 1 accept'
    ]


def test_after_a_fib_prediction():
    rule = {
        "iifname": {"not": ["uplinks", "lo"]},
        "fib": {"key": ["daddr", "mark"], "result": "oifname", "match": "wan"},
        "set-ct-zone": 2,
    }
    assert R.render(rule) == [
        'iifname != { "wan0", "wan1", "lo" } fib daddr . mark oifname "wan0" '
        "ct zone set 2"
    ]


def test_after_the_mark_statements():
    assert R.render({"set-mark": "0x1", "set-ct-mark": "0x2", "set-ct-zone": 3}) == [
        "meta mark set 0x1 ct mark set 0x2 ct zone set 3"
    ]


def test_in_a_concat_rule():
    renderer = RuleRenderer(
        DEFS,
        {
            s.name: s
            for s in build_sets(
                [
                    {
                        "name": "flows",
                        "concat": ["daddr", "dport"],
                        "proto": "tcp",
                        "tuples": [["192.0.2.2", "ssh"]],
                    }
                ],
                DEFS,
            )
        },
    )
    assert renderer.render({"set": "flows", "set-ct-zone": 1}) == [
        "ip daddr . tcp dport @flows ct zone set 1"
    ]


@pytest.mark.parametrize(
    "zone",
    [
        65536,
        "65536",
        "0x10000",
        -1,
        "1-2",
        "mark",
        "ct-mark",
        "zone1",
        "",
        "٣",
        "007",
        True,
        1.5,
        [1],
        {"key": "iifname", "map": "zones"},
    ],
)
def test_rejects_what_nft_does_not_take(zone):
    with pytest.raises(BuildError, match="rule key 'set-ct-zone'"):
        R.render({"set-ct-zone": zone})


TABLES = [
    {
        "family": "inet",
        "name": "raw",
        "chains": [
            {
                "name": "raw_prerouting",
                "hook": "prerouting",
                "priority": "raw",
                "policy": "accept",
                "rules": [
                    {
                        "iifname": {"not": ["uplinks", "lo"]},
                        "saddr": {"not": "peer"},
                        "set-mark": "0x1",
                    },
                    {"iifname": "wan", "action": {"jump": "wan_zone"}},
                    {
                        "iifname": {"not": ["uplinks", "lo"]},
                        "fib": {
                            "key": ["daddr", "mark"],
                            "result": "oifname",
                            "match": "wan",
                        },
                        "action": {"jump": "wan_zone"},
                    },
                ],
            },
            {
                "name": "raw_output",
                "hook": "output",
                "priority": "raw",
                "policy": "accept",
                "rules": [{"oifname": "wan", "action": {"jump": "wan_zone"}}],
            },
            {"name": "wan_zone", "rules": [{"set-ct-zone": 1}]},
        ],
    }
]


GOLDEN = """\
table inet raw {
    chain raw_prerouting {
        type filter hook prerouting priority -300; policy accept;
        iifname != { "wan0", "wan1", "lo" } ip saddr != 192.0.2.2/32 meta mark set 0x1
        iifname != { "wan0", "wan1", "lo" } ip6 saddr != 2001:db8::2/128 meta mark set 0x1
        iifname "wan0" jump wan_zone
        iifname != { "wan0", "wan1", "lo" } fib daddr . mark oifname "wan0" jump wan_zone
    }

    chain raw_output {
        type filter hook output priority -300; policy accept;
        oifname "wan0" jump wan_zone
    }

    chain wan_zone {
        ct zone set 1
    }
}
"""


def test_golden_zone_for_one_uplink():
    assert render_tables(TABLES, DEFS, DictResolver({})).endswith(GOLDEN)


@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_passes_nft_check():
    result = validate.check(render_tables(TABLES, DEFS, DictResolver({})))
    assert result.ok, result.stderr

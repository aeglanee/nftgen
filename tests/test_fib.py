"""Routing lookups (`fib:`) and the `notrack` statement."""

import shutil
import subprocess

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError
from nftgen.rules import RuleRenderer

DEFS = Definitions.from_mappings(
    {"interfaces": {"lan": ["lan0", "lan1"], "loopback": ["lo"]}}
)
R = RuleRenderer(DEFS, {})

TABLES = [
    {
        "family": "inet",
        "name": "raw",
        "chains": [
            {
                "name": "pre",
                "hook": "prerouting",
                "priority": "raw",
                "policy": "accept",
                "rules": [
                    {
                        "iifname": "lan",
                        "fib": {
                            "key": "daddr",
                            "result": "oifname",
                            "match": "loopback",
                        },
                        "notrack": True,
                        "comment": "to the router itself",
                    },
                    {
                        "fib": {
                            "key": ["saddr", "mark", "iif"],
                            "result": "oif",
                            "match": "missing",
                        },
                        "action": "drop",
                    },
                    {
                        "fib": {
                            "key": "daddr",
                            "result": "type",
                            "match": ["local", "broadcast"],
                        },
                        "action": "accept",
                    },
                ],
            }
        ],
    }
]

RULES = [
    'iifname { "lan0", "lan1" } fib daddr oifname "lo" notrack comment "to the router itself"',
    "fib saddr . mark . iif oif missing drop",
    "fib daddr type { local, broadcast } accept",
]


def test_rules_render():
    text = render_tables(TABLES, DEFS, DictResolver({}))
    for rule in RULES:
        assert f"        {rule}\n" in text


def test_key_renders_in_nft_order():
    assert R.render(
        {
            "fib": {
                "key": ["iif", "mark", "saddr"],
                "result": "oif",
                "match": "missing",
            },
            "action": "drop",
        }
    ) == ["fib saddr . mark . iif oif missing drop"]


def test_oif_result_matches_an_interface_index():
    assert R.render(
        {
            "fib": {"key": "daddr", "result": "oif", "match": "loopback"},
            "action": "accept",
        }
    ) == ['fib daddr oif "lo" accept']


def test_notrack_alone_is_a_rule():
    assert R.render({"iifname": "lan", "notrack": True}) == [
        'iifname { "lan0", "lan1" } notrack'
    ]


def test_notrack_false_is_nothing():
    with pytest.raises(BuildError, match="neither an action nor a statement"):
        R.render({"iifname": "lan", "notrack": False})


@pytest.mark.parametrize(
    ("fib", "message"),
    [
        ("daddr", "mapping"),
        ({"key": "daddr", "result": "oifname"}, "takes `key:`"),
        ({"key": "daddr", "result": "oifname", "match": "lo", "x": 1}, "takes `key:`"),
        ({"key": "iif", "result": "oif", "match": "missing"}, "one of saddr, daddr"),
        (
            {"key": ["saddr", "daddr"], "result": "oif", "match": "missing"},
            "one of saddr, daddr",
        ),
        (
            {"key": ["saddr", "iif", "oif"], "result": "oif", "match": "missing"},
            "at most one of iif, oif",
        ),
        (
            {"key": ["saddr", "saddr"], "result": "oif", "match": "missing"},
            "each field once",
        ),
        ({"key": "daddr", "result": "oifnam", "match": "lo"}, "oif, oifname, type"),
        ({"key": "daddr", "result": "type", "match": "locl"}, "address type"),
        ({"key": "daddr", "result": "oifname", "match": "missing"}, "oif with"),
        (
            {"key": "daddr", "result": "oif", "match": ["missing", "loopback"]},
            "alone, not in a list",
        ),
        ({"key": "daddr", "result": "oifname", "match": "nope"}, "unknown interface"),
    ],
)
def test_bad_fib_fails(fib, message):
    with pytest.raises(BuildError, match=message):
        R.render({"fib": fib, "action": "accept"})


def test_notrack_takes_a_boolean():
    with pytest.raises(BuildError, match="true or false"):
        R.render({"notrack": "yes"})


@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_passes_nft_check():
    result = validate.check(render_tables(TABLES, DEFS, DictResolver({})))
    assert result.ok, result.stderr


@pytest.mark.skipif(
    not (validate.can_check() and shutil.which("unshare")),
    reason="needs nft + unshare to load a ruleset",
)
def test_kernel_loads_the_rules(tmp_path):
    path = tmp_path / "r.nft"
    path.write_text(render_tables(TABLES, DEFS, DictResolver({})))
    proc = subprocess.run(
        ["unshare", "-rn", "sh", "-c", f"nft -f {path} && nft list ruleset"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert RULES[0] in proc.stdout
    assert RULES[2] in proc.stdout

"""Ethernet address matches: ether-saddr / ether-daddr, plain or masked."""

import shutil
import subprocess

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError
from nftgen.rules import RuleRenderer

DEFS = Definitions.from_mappings({"interfaces": {"vports": ["veth*"]}})
R = RuleRenderer(DEFS, {})

TABLES = [
    {
        "family": "bridge",
        "name": "l2",
        "chains": [
            {
                "name": "l2_forward",
                "hook": "forward",
                "priority": "filter",
                "policy": "accept",
                "rules": [
                    {
                        "ether-saddr": {
                            "match": "02:42:ac:11:00:00",
                            "mask": "ff:ff:ff:ff:00:00",
                        },
                        "counter": True,
                        "action": "drop",
                    },
                    {
                        "iifname": "vports",
                        "ether-daddr": {
                            "match": "01:00:00:00:00:00",
                            "mask": "01:00:00:00:00:00",
                        },
                        "action": "drop",
                    },
                    {
                        "ether-saddr": ["02:00:00:00:00:01", "02:00:00:00:00:02"],
                        "action": "accept",
                    },
                ],
            }
        ],
    }
]

RULES = [
    "ether saddr & ff:ff:ff:ff:00:00 == 02:42:ac:11:00:00 counter drop",
    'iifname "veth*" ether daddr & 01:00:00:00:00:00 == 01:00:00:00:00:00 drop',
    "ether saddr { 02:00:00:00:00:01, 02:00:00:00:00:02 } accept",
]


def test_plain_mac():
    assert R.render({"ether-saddr": "02:00:00:00:00:01", "action": "drop"}) == [
        "ether saddr 02:00:00:00:00:01 drop"
    ]


def test_mac_is_lowercased_and_deduped():
    assert R.render(
        {"ether-daddr": ["02:AA:00:00:00:01", "02:aa:00:00:00:01"], "action": "drop"}
    ) == ["ether daddr 02:aa:00:00:00:01 drop"]


def test_masked_match():
    assert R.render(
        {
            "ether-saddr": {"match": "02:42:AC:11:00:00", "mask": "FF:FF:FF:FF:00:00"},
            "action": "drop",
        }
    ) == ["ether saddr & ff:ff:ff:ff:00:00 == 02:42:ac:11:00:00 drop"]


def test_ether_renders_after_interfaces_and_before_addresses():
    defs = Definitions.from_mappings(
        {"interfaces": {"lan": ["lan0"]}, "networks": {"net": ["10.0.0.0/8"]}}
    )
    assert RuleRenderer(defs, {}).render(
        {
            "saddr": "net",
            "ether-saddr": "02:00:00:00:00:01",
            "iifname": "lan",
            "action": "accept",
        }
    ) == ['iifname "lan0" ether saddr 02:00:00:00:00:01 ip saddr 10.0.0.0/8 accept']


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("02:00:00:00:00", "MAC address"),
        ("02-00-00-00-00-01", "MAC address"),
        ([], "MAC address"),
        (41135085296, "quote the address"),
        ({"match": "01:00:00:00:00:00"}, "exactly `match:` and `mask:`"),
        (
            {"match": "01:00:00:00:00:00", "mask": "01:00:00:00:00:00", "op": "!="},
            "exactly `match:` and `mask:`",
        ),
        ({"match": "01:00:00:00:00:00", "mask": "00:00:00:00:00:00"}, "all-zero"),
        ({"match": "03:00:00:00:00:00", "mask": "01:00:00:00:00:00"}, "outside mask"),
    ],
)
def test_bad_values_fail(value, message):
    with pytest.raises(BuildError, match=message):
        R.render({"ether-daddr": value, "action": "drop"})


def test_not_allowed_on_a_concat_rule():
    with pytest.raises(BuildError):
        R.render({"set": "pairs", "ether-saddr": "02:00:00:00:00:01", "action": "drop"})


def test_bridge_table_golden():
    text = render_tables(TABLES, DEFS, DictResolver({}))
    for rule in RULES:
        assert f"        {rule}\n" in text


@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_passes_nft_check():
    result = validate.check(render_tables(TABLES, DEFS, DictResolver({})))
    assert result.ok, result.stderr


@pytest.mark.skipif(
    not (validate.can_check() and shutil.which("unshare")),
    reason="needs nft + unshare to load a ruleset",
)
def test_kernel_lists_the_rules_as_rendered(tmp_path):
    path = tmp_path / "r.nft"
    path.write_text(render_tables(TABLES, DEFS, DictResolver({})))
    proc = subprocess.run(
        ["unshare", "-rn", "sh", "-c", f"nft -f {path} && nft list ruleset"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    listed = [line.strip() for line in proc.stdout.splitlines()]
    assert [
        r.replace("counter drop", "counter packets 0 bytes 0 drop") for r in RULES
    ] == [line for line in listed if line.startswith(("ether", "iifname"))]

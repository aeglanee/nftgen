import shutil
import subprocess

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError

DEFS = Definitions.from_mappings(
    {
        "interfaces": {"lan": ["lan0", "lan1"], "dmz": ["dmz0"], "wan": ["wan0"]},
        "networks": {"admins": ["192.0.2.10"]},
    }
)
MAPS = [
    {
        "name": "zone_marks",
        "type": "ifname : mark",
        "elements": {"lan": "0x1", "dmz": "0x2", "wan": "0x3"},
    },
    {"name": "admin_marks", "type": "ipv4_addr : mark"},
    {"name": "port_marks", "type": "inet_service : mark"},
    {"name": "mark_marks", "type": "mark : mark"},
    {"name": "lease_snat", "type": "ifname : ipv4_addr"},
]
SETS = [
    {
        "name": "zone_pairs",
        "concat": ["mark", "oifname"],
        "tuples": [["0x1", "wan"], ["0x2", "wan"]],
    }
]


def _tables(prerouting, forward):
    return [
        {
            "family": "inet",
            "name": "filter",
            "maps": MAPS,
            "sets": SETS,
            "chains": [
                {
                    "name": "prerouting",
                    "hook": "prerouting",
                    "priority": "mangle",
                    "policy": "accept",
                    "rules": prerouting,
                },
                {"name": "lan_wan", "rules": [{"action": "accept"}]},
                {"name": "forward", "hook": "forward", "rules": forward},
            ],
        }
    ]


def _render(prerouting=(), forward=()):
    return render_tables(
        _tables(list(prerouting), list(forward)), DEFS, DictResolver({})
    )


MARK_ZONE = {"set-mark": {"key": "iifname", "map": "zone_marks"}}
FORWARD = [
    {"ct": ["established", "related"], "action": "accept"},
    {
        "vmap": {
            "key": ["mark", "oifname"],
            "map": [
                {"match": ["0x1", "wan"], "jump": "lan_wan"},
                {"match": ["0x2", "lan"], "action": "drop"},
            ],
        }
    },
    {"set": "zone_pairs", "action": "accept"},
    {"mark": "0x3", "oifname": "dmz", "action": "accept"},
]


def test_set_mark_from_an_interface_map():
    text = _render([MARK_ZONE], FORWARD)
    assert "        meta mark set iifname map @zone_marks\n" in text
    assert (
        '            "lan0" : 0x1,\n'
        '            "lan1" : 0x1,\n'
        '            "dmz0" : 0x2,\n'
        '            "wan0" : 0x3\n'
    ) in text


def test_the_mark_is_matched_later():
    text = _render([MARK_ZONE], FORWARD)
    assert (
        '        meta mark . oifname vmap { 0x1 . "wan0" : jump lan_wan, '
        '0x2 . "lan0" : drop, 0x2 . "lan1" : drop }\n'
    ) in text
    assert "        meta mark . oifname @zone_pairs accept\n" in text
    assert '        oifname "dmz0" meta mark 0x3 accept\n' in text


def test_set_ct_mark_from_a_map():
    text = _render([{"set-ct-mark": {"key": "iifname", "map": "zone_marks"}}])
    assert "        ct mark set iifname map @zone_marks\n" in text


@pytest.mark.parametrize(
    ("spec", "line"),
    [
        (
            {"key": "saddr", "map": "admin_marks"},
            "meta mark set ip saddr map @admin_marks",
        ),
        (
            {"key": "dport", "proto": "tcp", "map": "port_marks"},
            "meta mark set tcp dport map @port_marks",
        ),
        (
            {"key": "mark", "map": "mark_marks"},
            "meta mark set meta mark map @mark_marks",
        ),
    ],
)
def test_other_keys(spec, line):
    assert f"        {line}\n" in _render([{"set-mark": spec}])


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ({"key": "iifname", "map": "nope"}, "not declared"),
        ({"key": "iifname", "map": "lease_snat"}, "holds ipv4_addr"),
        ({"key": "saddr", "map": "zone_marks"}, "keyed by ifname"),
        ({"key": "iif", "map": "zone_marks"}, "key must be one of"),
        ({"map": "zone_marks"}, "key must be one of"),
        ({"key": "dport", "map": "port_marks"}, "needs `proto:`"),
        ({"key": "iifname", "proto": "tcp", "map": "zone_marks"}, "takes no"),
        ({"key": "iifname", "map": "zone_marks", "x": 1}, "unknown set-mark map"),
        ({"key": "iifname"}, "a {key, map} mapping"),
        ({"key": "iifname", "map": ["zone_marks"]}, "a {key, map} mapping"),
    ],
)
def test_bad_mark_maps_fail(spec, message):
    with pytest.raises(BuildError, match=message):
        _render([{"set-mark": spec}])


@pytest.mark.parametrize("bad", ["lan", "0x1-", True, "1.5"])
def test_a_vmap_mark_column_takes_marks(bad):
    rule = {
        "vmap": {
            "key": ["mark", "oifname"],
            "map": [{"match": [bad, "wan"], "action": "accept"}],
        }
    }
    with pytest.raises(BuildError, match="is not a mark"):
        _render(forward=[rule])


@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_passes_nft_check():
    prerouting = [
        MARK_ZONE,
        {"set-ct-mark": {"key": "iifname", "map": "zone_marks"}},
        {"set-mark": {"key": "saddr", "map": "admin_marks"}},
        {"set-mark": {"key": "dport", "proto": "tcp", "map": "port_marks"}},
        {"set-mark": {"key": "mark", "map": "mark_marks"}},
    ]
    result = validate.check(_render(prerouting, FORWARD))
    assert result.ok, result.stderr


@pytest.mark.skipif(
    not (validate.can_check() and shutil.which("unshare")),
    reason="needs nft + unshare to load a ruleset",
)
def test_kernel_loads_the_mark_map(tmp_path):
    path = tmp_path / "r.nft"
    path.write_text(_render([MARK_ZONE], FORWARD))
    proc = subprocess.run(
        ["unshare", "-rn", "sh", "-c", f"nft -f {path} && nft list ruleset"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "meta mark set iifname map @zone_marks" in proc.stdout

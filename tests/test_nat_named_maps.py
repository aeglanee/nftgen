"""NAT through a named map: `snat: {key: oifname, map: <name>}`."""

import shutil
import subprocess

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError

DEFS = Definitions.from_mappings(
    {
        "interfaces": {"uplink": ["wan0"]},
        "networks": {"internal_v4": ["10.0.0.0/8"], "internal_v6": ["fd00::/8"]},
    }
)
MAPS = [
    {
        "name": "lease_snat",
        "type": "ifname : ipv4_addr",
        "include": "/nonexistent/leases/*.nft",
    },
    {"name": "port_dnat", "type": "inet_service : ipv4_addr"},
    {"name": "src_snat", "type": "ipv6_addr : ipv6_addr"},
    {"name": "mark_snat", "type": "mark : ipv4_addr"},
    {"name": "verdicts", "type": "ifname : verdict"},
]


def _render(rules, maps=MAPS):
    tables = [
        {
            "family": "inet",
            "name": "nat",
            "maps": maps,
            "chains": [
                {
                    "name": "postrouting",
                    "hook": "postrouting",
                    "type": "nat",
                    "priority": "srcnat",
                    "rules": rules,
                }
            ],
        }
    ]
    return render_tables(tables, DEFS, DictResolver({}))


SNAT_RULES = [
    {
        "oifname": "uplink",
        "saddr": "internal_v4",
        "action": {"snat": {"key": "oifname", "map": "lease_snat"}},
    },
    {"oifname": "uplink", "action": "masquerade"},
]


def test_snat_through_an_interface_map():
    text = _render(SNAT_RULES)
    assert (
        '        oifname "wan0" ip saddr 10.0.0.0/8 snat ip to oifname map @lease_snat\n'
        '        oifname "wan0" masquerade\n'
    ) in text


@pytest.mark.parametrize(
    ("target", "line"),
    [
        (
            {"dnat": {"key": "dport", "proto": "tcp", "map": "port_dnat"}},
            "dnat ip to tcp dport map @port_dnat",
        ),
        (
            {"snat": {"key": "saddr", "map": "src_snat"}},
            "snat ip6 to ip6 saddr map @src_snat",
        ),
        (
            {"snat": {"key": "mark", "map": "mark_snat"}},
            "snat ip to meta mark map @mark_snat",
        ),
    ],
)
def test_other_keys(target, line):
    assert f"        {line}\n" in _render([{"action": target}])


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ({"snat": {"key": "oifname", "map": "nope"}}, "not declared"),
        ({"snat": {"key": "oifname", "map": "verdicts"}}, "holds verdict"),
        ({"snat": {"key": "iif", "map": "lease_snat"}}, "key must be one of"),
        ({"snat": {"map": "lease_snat"}}, "key must be one of"),
        ({"snat": {"key": "dport", "map": "lease_snat"}}, "needs `proto:`"),
        ({"snat": {"key": "oifname", "proto": "tcp", "map": "lease_snat"}}, "takes no"),
        ({"snat": {"key": "saddr", "map": "lease_snat"}}, "keyed by ifname"),
        ({"dnat": {"key": "dport", "proto": "tcp", "map": "src_snat"}}, "keyed by"),
        ({"snat": {"key": "oifname", "map": "lease_snat", "x": 1}}, "unknown snat map"),
    ],
)
def test_bad_named_nat_maps_fail(target, message):
    with pytest.raises(BuildError, match=message):
        _render([{"action": target}])


@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_passes_nft_check():
    rules = [
        *SNAT_RULES,
        {"action": {"snat": {"key": "mark", "map": "mark_snat"}}},
        {"action": {"snat": {"key": "saddr", "map": "src_snat"}}},
    ]
    result = validate.check(_render(rules))
    assert result.ok, result.stderr


@pytest.mark.skipif(
    not (validate.can_check() and shutil.which("unshare")),
    reason="needs nft + unshare to load a ruleset",
)
def test_kernel_loads_the_snat_map(tmp_path):
    path = tmp_path / "r.nft"
    path.write_text(_render(SNAT_RULES, maps=MAPS[:1]))
    proc = subprocess.run(
        ["unshare", "-rn", "sh", "-c", f"nft -f {path} && nft list ruleset"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "snat ip to oifname map @lease_snat" in proc.stdout

"""Named maps: a table's `maps:` (type, elements or an include)."""

import shutil
import subprocess

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError

DEFS = Definitions.from_mappings(
    {
        "interfaces": {"uplinks": ["wan0", "wan1"], "lan": ["lan0"], "unplugged": []},
        "networks": {"wan_ip": ["192.0.2.1"], "pool": ["192.0.2.0/24"]},
    }
)


def _table(maps, sets=None):
    table = {"family": "ip", "name": "nat", "maps": maps, "chains": []}
    if sets is not None:
        table["sets"] = sets
    return [table]


def _render(maps, sets=None):
    return render_tables(_table(maps, sets), DEFS, DictResolver({}))


def test_include_map():
    text = _render(
        [
            {
                "name": "lease_snat",
                "type": "ifname : ipv4_addr",
                "include": "/var/lib/leases/*.nft",
            }
        ]
    )
    assert (
        "    map lease_snat {\n"
        "        type ifname : ipv4_addr\n"
        '        include "/var/lib/leases/*.nft"\n'
        "    }\n"
    ) in text


def test_elements_resolve_groups():
    text = _render(
        [
            {
                "name": "static_snat",
                "type": "ifname : ipv4_addr",
                "flags": "interval",
                "comment": "fixed addresses",
                "elements": {"uplinks": "wan_ip"},
            }
        ]
    )
    assert (
        "    map static_snat {\n"
        "        type ifname : ipv4_addr\n"
        "        flags interval\n"
        '        comment "fixed addresses"\n'
        '        elements = { "wan0" : 192.0.2.1, "wan1" : 192.0.2.1 }\n'
        "    }\n"
    ) in text


def test_type_spacing_is_normalized():
    text = _render([{"name": "m", "type": "  inet_service :  ipv4_addr "}])
    assert "        type inet_service : ipv4_addr\n" in text


def test_literal_keys_and_values():
    text = _render(
        [
            {
                "name": "ports",
                "type": "inet_service : ipv4_addr",
                "elements": {80: "192.0.2.10", 443: "192.0.2.20"},
            }
        ]
    )
    assert "elements = { 80 : 192.0.2.10, 443 : 192.0.2.20 }" in text


def test_mark_keys():
    text = _render(
        [
            {
                "name": "by_mark",
                "type": "mark : ipv4_addr",
                "elements": {"0x1": "192.0.2.10", 2: "192.0.2.20"},
            }
        ]
    )
    assert "elements = { 0x1 : 192.0.2.10, 2 : 192.0.2.20 }" in text


@pytest.mark.parametrize(
    ("typ", "elements", "message"),
    [
        ("inet_service : ipv4_addr", {"80, 81": "192.0.2.1"}, "is not a port"),
        ("inet_service : ipv4_addr", {"http": "192.0.2.1"}, "is not a port"),
        ("inet_service : ipv4_addr", {70000: "192.0.2.1"}, "is not a port"),
        ("inet_service : ipv4_addr", {"80\n": "192.0.2.1"}, "is not a port"),
        ("mark : ipv4_addr", {"gold": "192.0.2.1"}, "is not a mark"),
        ("mark : ipv4_addr", {"0x1-0x2": "192.0.2.1"}, "is not a mark"),
        (
            "ether_addr : ipv4_addr",
            {"02:00:00:00:00:01": "192.0.2.1"},
            "not ether_addr",
        ),
        ("ifname : verdict", {"lan": "accept"}, "not verdict"),
        (
            "ipv4_addr . inet_service : ipv4_addr",
            {"10.0.0.1 . 80": "192.0.2.1"},
            "not ipv4_addr . inet_service",
        ),
    ],
)
def test_elements_are_checked_or_refused(typ, elements, message):
    with pytest.raises(BuildError, match=message):
        _render([{"name": "m", "type": typ, "elements": elements}])


def test_a_map_of_another_type_is_declared_without_elements():
    text = _render(
        [
            {
                "name": "by_mac",
                "type": "ether_addr : ipv4_addr",
                "include": "/var/lib/macs/*.nft",
            }
        ]
    )
    assert "type ether_addr : ipv4_addr\n" in text


def test_maps_render_after_sets():
    text = _render(
        [{"name": "m", "type": "ifname : ipv4_addr"}],
        sets=[{"name": "s", "type": "ipv4_addr"}],
    )
    assert text.index("set s {") < text.index("map m {")


@pytest.mark.parametrize(
    ("maps", "message"),
    [
        ([{"type": "ifname : ipv4_addr"}], "needs `name:` and `type:`"),
        ([{"name": "m"}], "needs `name:` and `type:`"),
        ([{"name": "m", "type": "ifname : ipv4_addr", "typo": 1}], "unknown map key"),
        ([{"name": "m", "type": "ifname"}], "<key type> : <value type>"),
        ([{"name": "m", "type": "ifname:ipv4_addr"}], "<key type> : <value type>"),
        ([{"name": "m", "type": "a : b : c"}], "<key type> : <value type>"),
        ([{"name": "map", "type": "ifname : ipv4_addr"}], "reserved"),
        (
            [
                {"name": "m", "type": "ifname : ipv4_addr"},
                {"name": "m", "type": "ifname : ipv4_addr"},
            ],
            "already has a set or map",
        ),
        (
            [
                {
                    "name": "m",
                    "type": "ifname : ipv4_addr",
                    "include": "/x/*.nft",
                    "elements": {"lan": "192.0.2.1"},
                }
            ],
            "not both",
        ),
        ([{"name": "m", "type": "ifname : ipv4_addr", "include": 'a"b'}], "glob"),
        ([{"name": "m", "type": "ifname : ipv4_addr", "elements": {}}], "non-empty"),
        (
            [
                {
                    "name": "m",
                    "type": "ifname : ipv4_addr",
                    "elements": {"eth9": "192.0.2.1"},
                }
            ],
            "unknown interface group",
        ),
        (
            [
                {
                    "name": "m",
                    "type": "ifname : ipv4_addr",
                    "elements": {"unplugged": "192.0.2.1"},
                }
            ],
            "resolves to no devices",
        ),
        (
            [{"name": "m", "type": "ifname : ipv4_addr", "elements": {"lan": "pool"}}],
            "is not an address",
        ),
        (
            [
                {
                    "name": "m",
                    "type": "ifname : ipv6_addr",
                    "elements": {"lan": "wan_ip"},
                }
            ],
            "not an ipv6_addr",
        ),
        (
            [{"name": "m", "type": "ifname : ipv4_addr", "flags": "bogus"}],
            "unknown flag",
        ),
        ("m", "must be a list"),
        (["m"], "must be a mapping"),
    ],
)
def test_bad_maps_fail(maps, message):
    with pytest.raises(BuildError, match=message):
        _render(maps)


def test_a_set_and_a_map_cannot_share_a_name():
    with pytest.raises(BuildError, match="already has a set or map"):
        _render(
            [{"name": "s", "type": "ifname : ipv4_addr"}],
            sets=[{"name": "s", "type": "ipv4_addr"}],
        )


def test_conflicting_elements_fail():
    defs = Definitions.from_mappings({"interfaces": {"a": ["wan0"], "b": ["wan0"]}})
    with pytest.raises(BuildError, match="maps to"):
        render_tables(
            _table(
                [
                    {
                        "name": "m",
                        "type": "ifname : ipv4_addr",
                        "elements": {"a": "192.0.2.1", "b": "192.0.2.2"},
                    }
                ]
            ),
            defs,
            DictResolver({}),
        )


@pytest.mark.skipif(not validate.can_check(), reason="nft -c not usable here")
def test_passes_nft_check_without_include_files(tmp_path):
    text = _render(
        [
            {
                "name": "lease_snat",
                "type": "ifname : ipv4_addr",
                "include": f"{tmp_path}/none/*.nft",
            },
            {
                "name": "static_snat",
                "type": "ifname : ipv4_addr",
                "comment": "fixed",
                "elements": {"uplinks": "wan_ip"},
            },
        ]
    )
    result = validate.check(text)
    assert result.ok, result.stderr


@pytest.mark.skipif(
    not (validate.can_check() and shutil.which("unshare")),
    reason="needs nft + unshare to load a ruleset",
)
def test_include_fills_the_map(tmp_path):
    (tmp_path / "inc").mkdir()
    (tmp_path / "inc" / "lease.nft").write_text('elements = { "wan0" : 192.0.2.7 }\n')
    path = tmp_path / "r.nft"
    path.write_text(
        _render(
            [
                {
                    "name": "lease_snat",
                    "type": "ifname : ipv4_addr",
                    "include": f"{tmp_path}/inc/*.nft",
                }
            ]
        )
    )
    proc = subprocess.run(
        [
            "unshare",
            "-rn",
            "sh",
            "-c",
            f"nft -f {path} && nft list map ip nat lease_snat",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert '"wan0" : 192.0.2.7' in proc.stdout

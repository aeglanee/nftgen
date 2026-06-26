"""Phase 4 — full host -> .nft, includes, and the per-site overlay (golden)."""
import pathlib

import pytest

from nftgen.generate import generate

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "example"
GOLDEN = pathlib.Path(__file__).resolve().parent / "golden"


def _gen(host: str) -> str:
    return generate(
        EXAMPLE / "policies" / "hosts" / host,
        defs_dir=EXAMPLE / "def",
        include_base=EXAMPLE / "policies",
        sites_dir=EXAMPLE / "sites",
    )


@pytest.mark.parametrize("host", ["router1.yaml", "router2.yaml", "gateway.yaml"])
def test_matches_golden(host):
    expected = (GOLDEN / host.replace(".yaml", ".nft")).read_text()
    assert _gen(host) == expected


def test_gateway_showcases_all_capabilities():
    out = _gen("gateway.yaml")
    assert "flowtable ft {" in out                                  # 6C
    assert "flow add @ft" in out
    assert "counter bad_tcp {" in out                               # 6B
    assert "iifname vmap {" in out                                  # 6D
    assert "tcp flags & (fin|syn) == (fin|syn) counter name bad_tcp drop" in out  # 6E + named counter
    assert "limit rate 4/minute" in out                             # 6A limit
    assert 'log prefix "ssh-excess "' in out                        # 6A log
    assert "maxseg size set rt mtu" in out                          # 6A mss
    assert "meta mark set 0x1" in out                               # 6A mark
    assert "quota over 10240 mbytes" in out                         # 6A quota
    assert "ip saddr 192.168.10.0/24" in out                        # per-site overlay
    assert "ip dscp set ef" in out                                  # raw hatch
    assert "dnat ip to 192.168.10.50:443" in out                    # dnat, family-qualified for inet


def test_site_overlay_differs_per_host():
    assert "192.168.10.0/24" in _gen("router1.yaml")  # site1
    assert "192.168.20.0/24" in _gen("router2.yaml")  # site2


def test_per_table_set_named_vs_inline():
    out = _gen("router1.yaml")
    # `wan` is a named set in the filter table...
    assert "set wan {" in out
    assert "oifname @wan" in out
    # ...but the nat table doesn't declare it, so it inlines there
    assert 'oifname { "wan0", "wwan0" }' in out


def test_includes_and_raw_present():
    out = _gen("router1.yaml")
    assert "ct state established,related accept" in out          # common-input baseline
    assert "tcp flags & (fin|syn) == (fin|syn) counter drop" in out  # scrub raw
    assert "maxseg size set rt mtu" in out                       # common-forward raw

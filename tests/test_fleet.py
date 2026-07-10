"""example-fleet — the realistic 3-site reference builds, validates, never drifts.

The three site routers share one identical policy; only the `site:` overlay
differs. These tests pin that: the artifacts regenerate byte-identically, pass
`nft -c`, and the overlay resolves each site's own subnets from the same YAML.
"""

import pathlib

import pytest

from nftgen import validate
from nftgen.generate import build

ROOT = pathlib.Path(__file__).resolve().parent.parent
FLEET = ROOT / "example-fleet"
HOSTS = ["hq-r", "br1-r", "br2-r"]

requires_nft = pytest.mark.skipif(
    not validate.can_check(), reason="nft -c not usable in this environment"
)


def test_fleet_builds_every_site():
    assert set(build(FLEET)) == set(HOSTS)


@pytest.mark.parametrize("host", HOSTS)
def test_fleet_committed_artifact_is_current(host):
    # the committed render is the golden — YAML edits must regenerate it
    committed = (FLEET / "generated" / f"{host}.nft").read_text()
    assert build(FLEET, host=host)[host] == committed


@requires_nft
@pytest.mark.parametrize("host", HOSTS)
def test_fleet_is_valid_nft(host):
    result = validate.check(build(FLEET, host=host)[host])
    assert result.ok, result.stderr


def test_fleet_shares_one_policy_specialised_by_overlay():
    arts = build(FLEET)
    # identical structure: same chains everywhere (the vmap dispatch spine)
    for host in HOSTS:
        assert "iifname . oifname vmap {" in arts[host]
        assert "ip6 hoplimit 255 accept" in arts[host]  # RFC 4890 NDP
        assert "flow add @ft" in arts[host]  # fast path
    # but the site overlay resolves each site's own subnets from the same YAML
    assert "192.168.1.0/24" in arts["hq-r"]  # users_hq
    assert "192.168.2.0/24" in arts["br1-r"]  # users_br1
    assert "192.168.3.0/24" in arts["br2-r"]  # users_br2
    # the fleet-wide central service resolves the same fixed host everywhere
    for host in HOSTS:
        assert "10.0.1.10" in arts[host]  # hq_central, reachable fleet-wide


def test_fleet_hygiene_and_dispatch_surface():
    hq = build(FLEET, host="hq-r")["hq-r"]
    # dual-stack scrub even though real traffic is v4
    assert "ip saddr @bogons_v4" in hq
    assert "ip6 saddr @bogons_v6" in hq
    # invalid-tcp-flag scrub on the uplink
    assert "tcp flags & (fin|syn) == (fin|syn)" in hq
    # wan group expands in the pair vmap
    assert '"lan_users" . "wan0" : jump fwd_users_inet' in hq
    assert '"lan_users" . "wan1" : jump fwd_users_inet' in hq
    # attributed, metered drop logging
    assert 'log prefix "fwd-users-services-drop "' in hq
    assert "update @log_meter { ip saddr timeout 1m limit rate 4/minute }" in hq
    # multi-WAN egress + published web dnat
    assert 'oifname { "wan0", "wan1" } masquerade' in hq
    assert "dnat ip to 10.0.11.10" in hq

"""example-poc — the best-practice showcase pair builds, validates, and never drifts."""
import pathlib

import pytest

from nftgen import validate
from nftgen.generate import build

ROOT = pathlib.Path(__file__).resolve().parent.parent
POC = ROOT / "example-poc"

requires_nft = pytest.mark.skipif(
    not validate.can_check(), reason="nft -c not usable in this environment"
)


def test_poc_builds_both_hosts():
    assert set(build(POC)) == {"poc-gw1", "poc-gw2"}


@pytest.mark.parametrize("host", ["poc-gw1", "poc-gw2"])
def test_poc_committed_artifact_is_current(host):
    # the committed render is the golden — YAML edits must regenerate it
    committed = (POC / "generated" / f"{host}.nft").read_text()
    assert build(POC, host=host)[host] == committed


@requires_nft
@pytest.mark.parametrize("host", ["poc-gw1", "poc-gw2"])
def test_poc_is_valid_nft(host):
    result = validate.check(build(POC, host=host)[host])
    assert result.ok, result.stderr


def test_poc_showcases_the_surface():
    gw1 = build(POC, host="poc-gw1")["poc-gw1"]
    assert "iifname vmap {" in gw1                          # input zone dispatch
    assert "iifname . oifname vmap {" in gw1                # forward pair dispatch
    assert '"lan0" . "lte0" : jump fwd_users_inet' in gw1   # group row expanded
    assert "th dport vmap { 22 : jump svc_ssh" in gw1       # service dispatch
    assert "ip saddr . ip daddr . tcp dport @mon_flows" in gw1  # paired flows
    assert "dnat ip to tcp dport map { 80 : 10.10.40.10" in gw1  # data map
    assert "snat ip to 203.0.113.10" in gw1                 # site-resolved target
    gw2 = build(POC, host="poc-gw2")["poc-gw2"]
    assert "masquerade" in gw2                              # dynamic-uplink contrast
    assert "10.20.20.0/24" in gw2                           # site2 overlay values
    assert "dmz" not in gw2                                 # site2 composes no DMZ

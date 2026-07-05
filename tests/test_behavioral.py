"""Layer 4 — behavioral: packets obey the generated ruleset (testing-plan §1).

B01–B03 on the `basic` fixture, applied as the real deploy artifact (build()
output, flush form) inside a router namespace. Every negative assertion has a
positive control in the same topology, so a harness failure can't masquerade
as a firewall drop.
"""
import pathlib

import pytest

from nftgen.generate import build
from tests.behavioral.netns import Harness, can_netns

FIXTURES = pathlib.Path(__file__).resolve().parent / "behavioral" / "fixtures"

requires_netns = pytest.mark.skipif(
    not can_netns(), reason="netns harness not usable here (unshare/veth/nft/ct)"
)

ROUTER_LAN = "10.77.1.1"
CLIENT = "10.77.1.2"
ROUTER_WAN = "10.77.2.1"
SERVER = "10.77.2.2"


@pytest.fixture(scope="module")
def fw():
    harness = Harness()
    try:
        harness.topology([
            {"name": "lan", "router_if": "r-lan", "router_addr": f"{ROUTER_LAN}/24",
             "ns_addr": f"{CLIENT}/24", "gw": ROUTER_LAN},
            {"name": "wan", "router_if": "r-wan", "router_addr": f"{ROUTER_WAN}/24",
             "ns_addr": f"{SERVER}/24", "gw": ROUTER_WAN},
        ])
        harness.nft_apply(build(FIXTURES / "basic")["router"])
        harness.listen(None, 22)      # router "ssh"
        harness.listen("wan", 9000)   # the internet-side service
        harness.listen("lan", 9000)   # target for the unsolicited-inbound probe
        yield harness
    finally:
        harness.close()


@requires_netns
def test_harness_distinguishes_the_three_outcomes(fw):
    # accepted + listener = connected; accepted + closed port = refused;
    # dropped by policy = timeout. If these ever collapse, nothing else here
    # can be trusted.
    assert fw.probe_tcp("lan", ROUTER_LAN, 22) == "connected"
    assert fw.probe_tcp("lan", ROUTER_LAN, 2323) == "refused"
    assert fw.probe_tcp("lan", ROUTER_LAN, 4444) == "timeout"


@requires_netns
def test_b01_unsolicited_input_dropped(fw):
    # same router port, two zones: lan is allowlisted, wan falls to policy drop
    assert fw.probe_tcp("wan", ROUTER_WAN, 22) == "timeout"
    assert fw.probe_tcp("lan", ROUTER_LAN, 22) == "connected"  # positive control


@requires_netns
def test_b02_forward_and_established_return_path(fw):
    # lan->wan:9000 is the only allowed forward; a completed handshake proves
    # the SYN passed the allowlist *and* the SYN-ACK came back via ct
    # established/related — both directions, one probe.
    assert fw.probe_tcp("lan", SERVER, 9000) == "connected"


@requires_netns
def test_b03_unsolicited_inbound_forward_dropped(fw):
    # the same service port the other way, with a live listener waiting:
    # no ct entry, no wan->lan rule -> policy drop.
    assert fw.probe_tcp("wan", CLIENT, 9000) == "timeout"

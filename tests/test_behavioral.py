"""Layer 4 — behavioral: packets obey the generated ruleset (testing-plan §1).

B01–B03 on the `basic` fixture, applied as the real deploy artifact (build()
output, flush form) inside a router namespace. Every negative assertion has a
positive control in the same topology, so a harness failure can't masquerade
as a firewall drop.
"""

import pathlib
import re
import sys
import time

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
        harness.topology(
            [
                {
                    "name": "lan",
                    "router_if": "r-lan",
                    "router_addr": f"{ROUTER_LAN}/24",
                    "ns_addr": f"{CLIENT}/24",
                    "gw": ROUTER_LAN,
                },
                {
                    "name": "wan",
                    "router_if": "r-wan",
                    "router_addr": f"{ROUTER_WAN}/24",
                    "ns_addr": f"{SERVER}/24",
                    "gw": ROUTER_WAN,
                },
            ]
        )
        harness.nft_apply(build(FIXTURES / "basic")["router"])
        harness.listen(None, 22)  # router "ssh"
        harness.listen("wan", 9000)  # the internet-side service
        harness.listen("lan", 9000)  # target for the unsolicited-inbound probe
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


# --------------------------------------------------------------------------- #
# B05/B06 — input vmap dispatch (fixture: vmap-input)
# --------------------------------------------------------------------------- #

ZA_ROUTER, ZB_ROUTER, ZC_ROUTER = "10.78.1.1", "10.78.2.1", "10.78.3.1"


@pytest.fixture(scope="module")
def fw_vmap_input():
    harness = Harness()
    try:
        harness.topology(
            [
                {
                    "name": z,
                    "router_if": f"r-{z}",
                    "router_addr": f"{addr}/24",
                    "ns_addr": f"{addr[:-1]}2/24",
                    "gw": addr,
                }
                for z, addr in (
                    ("za", ZA_ROUTER),
                    ("zb", ZB_ROUTER),
                    ("zc", ZC_ROUTER),
                )
            ]
        )
        harness.nft_apply(build(FIXTURES / "vmap-input")["router"])
        harness.listen(None, 7000)
        harness.listen(None, 7001)
        yield harness
    finally:
        harness.close()


@requires_netns
def test_b05_input_vmap_dispatches_per_zone(fw_vmap_input):
    # same router, same listeners — the only difference is the inbound zone,
    # so a verdict flip proves the vmap dispatched to different chains.
    assert fw_vmap_input.probe_tcp("za", ZA_ROUTER, 7000) == "connected"
    assert fw_vmap_input.probe_tcp("za", ZA_ROUTER, 7001) == "timeout"
    assert fw_vmap_input.probe_tcp("zb", ZB_ROUTER, 7001) == "connected"
    assert fw_vmap_input.probe_tcp("zb", ZB_ROUTER, 7000) == "timeout"


@requires_netns
def test_b06_zone_absent_from_vmap_falls_to_policy(fw_vmap_input):
    # zc is wired up but has no vmap entry: the lookup is a no-match and the
    # packet falls through to the base chain's policy drop.
    assert fw_vmap_input.probe_tcp("zc", ZC_ROUTER, 7000) == "timeout"
    assert fw_vmap_input.probe_tcp("zc", ZC_ROUTER, 7001) == "timeout"


# --------------------------------------------------------------------------- #
# B07 — concat vmap pair dispatch (fixture: vmap-pairs)
# --------------------------------------------------------------------------- #

PAIR_A_CLIENT, PAIR_B_CLIENT = "10.79.1.2", "10.79.2.2"


@pytest.fixture(scope="module")
def fw_vmap_pairs():
    harness = Harness()
    try:
        harness.topology(
            [
                {
                    "name": "za",
                    "router_if": "r-za",
                    "router_addr": "10.79.1.1/24",
                    "ns_addr": f"{PAIR_A_CLIENT}/24",
                    "gw": "10.79.1.1",
                },
                {
                    "name": "zb",
                    "router_if": "r-zb",
                    "router_addr": "10.79.2.1/24",
                    "ns_addr": f"{PAIR_B_CLIENT}/24",
                    "gw": "10.79.2.1",
                },
            ]
        )
        harness.nft_apply(build(FIXTURES / "vmap-pairs")["router"])
        harness.listen("za", 9000)  # target for the reversed-pair probe
        harness.listen("zb", 9000)
        yield harness
    finally:
        harness.close()


@requires_netns
def test_b07_pair_dispatch_is_directional(fw_vmap_pairs):
    # identical service, identical topology — only the (in, out) interface
    # pair differs. Mapped pair passes; the reversed pair is a vmap no-match.
    assert fw_vmap_pairs.probe_tcp("za", PAIR_B_CLIENT, 9000) == "connected"
    assert fw_vmap_pairs.probe_tcp("zb", PAIR_A_CLIENT, 9000) == "timeout"


# --------------------------------------------------------------------------- #
# B08 — interface-group expansion in a vmap (fixture: vmap-group)
# --------------------------------------------------------------------------- #

GRP_ZA_ROUTER, GRP_ZB_ROUTER, GRP_ZC_ROUTER = "10.81.1.1", "10.81.2.1", "10.81.3.1"


@pytest.fixture(scope="module")
def fw_vmap_group():
    harness = Harness()
    try:
        harness.topology(
            [
                {
                    "name": z,
                    "router_if": f"r-{z}",
                    "router_addr": f"{addr}/24",
                    "ns_addr": f"{addr[:-1]}2/24",
                    "gw": addr,
                }
                for z, addr in (
                    ("za", GRP_ZA_ROUTER),
                    ("zb", GRP_ZB_ROUTER),
                    ("zc", GRP_ZC_ROUTER),
                )
            ]
        )
        harness.nft_apply(build(FIXTURES / "vmap-group")["router"])
        harness.listen(None, 7000)
        yield harness
    finally:
        harness.close()


@requires_netns
def test_b08_group_expands_to_both_member_devices(fw_vmap_group):
    # one map entry (the group name), two member devices: both zones must hit
    # the same verdict chain; the non-member zone proves the expansion didn't
    # widen into a wildcard.
    assert fw_vmap_group.probe_tcp("za", GRP_ZA_ROUTER, 7000) == "connected"
    assert fw_vmap_group.probe_tcp("zb", GRP_ZB_ROUTER, 7000) == "connected"
    assert fw_vmap_group.probe_tcp("zc", GRP_ZC_ROUTER, 7000) == "timeout"


# --------------------------------------------------------------------------- #
# B09 — named-set membership (fixture: set-member)
# --------------------------------------------------------------------------- #

MEMBER_ROUTER, NONMEMBER_ROUTER = "10.80.1.1", "10.80.2.1"


@pytest.fixture(scope="module")
def fw_set_member():
    harness = Harness()
    try:
        harness.topology(
            [
                {
                    "name": "za",
                    "router_if": "r-za",
                    "router_addr": f"{MEMBER_ROUTER}/24",
                    "ns_addr": "10.80.1.2/24",
                    "gw": MEMBER_ROUTER,
                },
                {
                    "name": "zb",
                    "router_if": "r-zb",
                    "router_addr": f"{NONMEMBER_ROUTER}/24",
                    "ns_addr": "10.80.2.2/24",
                    "gw": NONMEMBER_ROUTER,
                },
            ]
        )
        artifact = build(FIXTURES / "set-member")["router"]
        assert "@members" in artifact  # it must be a set lookup, not an inline
        harness.nft_apply(artifact)
        harness.listen(None, 7000)
        yield harness
    finally:
        harness.close()


@requires_netns
def test_b09_named_set_membership(fw_set_member):
    # identical rule path for both zones (any_zone matches both devices) —
    # only @members membership differs between the two source addresses.
    assert fw_set_member.probe_tcp("za", MEMBER_ROUTER, 7000) == "connected"
    assert fw_set_member.probe_tcp("zb", NONMEMBER_ROUTER, 7000) == "timeout"


# --------------------------------------------------------------------------- #
# B04 — ct invalid: out-of-state ACK is dropped and counted (fixture: basic)
# --------------------------------------------------------------------------- #

# Build one bare TCP ACK (no conntrack entry) and send it raw. Runs as root
# inside the wan zone namespace, where CAP_NET_RAW is held over the netns.
_ACK_SCRIPT = r"""
import socket, struct, random

SRC, DST, SPORT, DPORT = "10.77.2.2", "10.77.2.1", 45555, 22

def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF

seq, ack = random.randint(0, 2**32 - 1), random.randint(0, 2**32 - 1)
hdr = struct.pack("!HHIIBBHHH", SPORT, DPORT, seq, ack, 5 << 4, 0x10, 8192, 0, 0)
pseudo = socket.inet_aton(SRC) + socket.inet_aton(DST) + struct.pack("!BBH", 0, 6, len(hdr))
hdr = struct.pack(
    "!HHIIBBHHH", SPORT, DPORT, seq, ack, 5 << 4, 0x10, 8192, csum(pseudo + hdr), 0
)
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.sendto(hdr, (DST, 0))
print("sent")
"""


def _invalid_hits(fw) -> int:
    r = fw.run(None, ["nft", "list", "counter", "inet", "filter", "invalid_hits"])
    assert r.returncode == 0, r.stderr
    m = re.search(r"packets (\d+)", r.stdout)
    assert m, r.stdout
    return int(m.group(1))


@requires_netns
def test_b04_out_of_state_ack_is_invalid_dropped_and_counted(fw):
    # Default nf_conntrack_tcp_loose=1 classifies a bare ACK as NEW (pickup);
    # disable it so window tracking marks the ACK INVALID, as on a real router.
    r = fw.run(
        None,
        ["sh", "-c", "echo 0 > /proc/sys/net/netfilter/nf_conntrack_tcp_loose"],
    )
    if r.returncode != 0:
        pytest.skip("nf_conntrack_tcp_loose not writable in this userns")

    before = _invalid_hits(fw)
    r = fw.run("wan", [sys.executable, "-c", _ACK_SCRIPT])
    assert r.returncode == 0, r.stderr

    deadline = time.time() + 3
    hits = _invalid_hits(fw)
    while hits <= before and time.time() < deadline:
        time.sleep(0.1)
        hits = _invalid_hits(fw)
    assert hits > before

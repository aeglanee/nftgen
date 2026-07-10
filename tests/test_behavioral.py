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


# --------------------------------------------------------------------------- #
# B10 — bogon scrub + named counter (fixture: bogon-counter)
# --------------------------------------------------------------------------- #

BOGON_LEGIT_ROUTER, BOGON_SPOOF_ROUTER = "10.82.1.1", "192.168.99.1"


def _counter_packets(fw, name: str) -> int:
    r = fw.run(None, ["nft", "list", "counter", "inet", "filter", name])
    assert r.returncode == 0, r.stderr
    m = re.search(r"packets (\d+)", r.stdout)
    assert m, r.stdout
    return int(m.group(1))


@pytest.fixture(scope="module")
def fw_bogon():
    harness = Harness()
    try:
        harness.topology(
            [
                {
                    "name": "wan",
                    "router_if": "r-wan",
                    "router_addr": f"{BOGON_LEGIT_ROUTER}/24",
                    "ns_addr": "10.82.1.2/24",
                    "gw": BOGON_LEGIT_ROUTER,
                },
            ]
        )
        # second (bogon) subnet on the same link: source selection makes the
        # probe to 192.168.99.1 leave with the rfc1918 saddr — the spoof.
        for ns, dev, addr in (
            (None, "r-wan", f"{BOGON_SPOOF_ROUTER}/24"),
            ("wan", "eth0", "192.168.99.2/24"),
        ):
            r = harness.run(ns, ["ip", "addr", "add", addr, "dev", dev])
            assert r.returncode == 0, r.stderr
        harness.nft_apply(build(FIXTURES / "bogon-counter")["router"])
        harness.listen(None, 7000)
        yield harness
    finally:
        harness.close()


@requires_netns
def test_b10_bogon_saddr_dropped_and_counted(fw_bogon):
    before = _counter_packets(fw_bogon, "bogon_drops")
    # legit subnet reaches the service — the accept rule works…
    assert fw_bogon.probe_tcp("wan", BOGON_LEGIT_ROUTER, 7000) == "connected"
    # …so the rfc1918-sourced probe dying proves the scrub rule, counted.
    assert fw_bogon.probe_tcp("wan", BOGON_SPOOF_ROUTER, 7000) == "timeout"
    assert _counter_packets(fw_bogon, "bogon_drops") > before


# --------------------------------------------------------------------------- #
# B11 — concat set paired flows, no cartesian bleed (fixture: concat-flows)
# --------------------------------------------------------------------------- #

FLOWS_SERVER = "10.84.3.2"


@pytest.fixture(scope="module")
def fw_concat_flows():
    harness = Harness()
    try:
        harness.topology(
            [
                {
                    "name": "za",
                    "router_if": "r-za",
                    "router_addr": "10.84.1.1/24",
                    "ns_addr": "10.84.1.2/24",
                    "gw": "10.84.1.1",
                },
                {
                    "name": "zb",
                    "router_if": "r-zb",
                    "router_addr": "10.84.2.1/24",
                    "ns_addr": "10.84.2.2/24",
                    "gw": "10.84.2.1",
                },
                {
                    "name": "zs",
                    "router_if": "r-zs",
                    "router_addr": "10.84.3.1/24",
                    "ns_addr": f"{FLOWS_SERVER}/24",
                    "gw": "10.84.3.1",
                },
            ]
        )
        harness.nft_apply(build(FIXTURES / "concat-flows")["router"])
        harness.listen("zs", 9000)
        harness.listen("zs", 9001)
        yield harness
    finally:
        harness.close()


@requires_netns
def test_b11_concat_tuples_exact_no_cartesian_bleed(fw_concat_flows):
    # exact tuples pass…
    assert fw_concat_flows.probe_tcp("za", FLOWS_SERVER, 9000) == "connected"
    assert fw_concat_flows.probe_tcp("zb", FLOWS_SERVER, 9001) == "connected"
    # …the crossed combinations — live listeners waiting — must not:
    # independent matches would have allowed both of these.
    assert fw_concat_flows.probe_tcp("za", FLOWS_SERVER, 9001) == "timeout"
    assert fw_concat_flows.probe_tcp("zb", FLOWS_SERVER, 9000) == "timeout"


# --------------------------------------------------------------------------- #
# B12 — live blocklist: runtime add, block, expire (fixture: live-blocklist)
# --------------------------------------------------------------------------- #

BL_ROUTER, BL_CLIENT = "10.83.1.1", "10.83.1.2"


@pytest.fixture(scope="module")
def fw_blocklist():
    harness = Harness()
    try:
        harness.topology(
            [
                {
                    "name": "za",
                    "router_if": "r-za",
                    "router_addr": f"{BL_ROUTER}/24",
                    "ns_addr": f"{BL_CLIENT}/24",
                    "gw": BL_ROUTER,
                },
            ]
        )
        harness.nft_apply(build(FIXTURES / "live-blocklist")["router"])
        harness.listen(None, 7000)
        yield harness
    finally:
        harness.close()


@requires_netns
def test_b12_live_blocklist_blocks_then_expires(fw_blocklist):
    # phase 1: set ships empty — traffic flows
    assert fw_blocklist.probe_tcp("za", BL_ROUTER, 7000) == "connected"

    # phase 2: the runtime workflow the artifact promises — block the client
    r = fw_blocklist.run(
        None,
        [
            "nft",
            "add",
            "element",
            "inet",
            "filter",
            "blocklist",
            f"{{ {BL_CLIENT} timeout 2s }}",
        ],
    )
    assert r.returncode == 0, r.stderr
    assert fw_blocklist.probe_tcp("za", BL_ROUTER, 7000) == "timeout"

    # phase 3: entry expiry is kernel-GC-scheduled, so poll with a deadline
    # rather than sleep-and-assert — timing-sensitive otherwise.
    deadline = time.time() + 15
    outcome = "timeout"
    while time.time() < deadline:
        outcome = fw_blocklist.probe_tcp("za", BL_ROUTER, 7000)
        if outcome == "connected":
            break
        time.sleep(0.5)
    assert outcome == "connected"


# --------------------------------------------------------------------------- #
# B13-B17 — NAT: dnat single/map/fall-through, forward leg, snat (fixture: nat)
# --------------------------------------------------------------------------- #

NAT_ROUTER_WAN = "10.85.1.1"  # == snat_ip in the fixture
NAT_WAN_CLIENT = "10.85.1.2"
NAT_LAN_CLIENT = "10.85.0.2"


@pytest.fixture(scope="module")
def fw_nat():
    harness = Harness()
    try:
        harness.topology(
            [
                {
                    "name": z,
                    "router_if": f"r-{z}",
                    "router_addr": f"{router}/24",
                    "ns_addr": f"{ns}/24",
                    "gw": router,
                }
                for z, router, ns in (
                    ("lan", "10.85.0.1", NAT_LAN_CLIENT),
                    ("wan", NAT_ROUTER_WAN, NAT_WAN_CLIENT),
                    ("web", "10.85.2.1", "10.85.2.2"),
                    ("jump", "10.85.3.1", "10.85.3.2"),
                )
            ]
        )
        harness.nft_apply(build(FIXTURES / "nat")["router"])
        harness.listen("web", 7000, echo_peer=True)  # B13 target (port rewritten)
        harness.listen("web", 80)  # B14 map target
        harness.listen("jump", 2222)  # B14 map target
        harness.listen("jump", 9022)  # B16: dnat'd but not forward-allowed
        harness.listen("wan", 9000, echo_peer=True)  # B17: outside server
        yield harness
    finally:
        harness.close()


@requires_netns
def test_b13_dnat_single_target_rewrites_and_preserves_saddr(fw_nat):
    # wan client hits the router's public :8080; dnat sends it to web:7000.
    # The echoed peer proves the server saw the *original* client address.
    outcome, seen = fw_nat.probe_tcp_reply("wan", NAT_ROUTER_WAN, 8080)
    assert outcome == "connected"
    assert seen == NAT_WAN_CLIENT


@requires_netns
def test_b14_dnat_map_dispatches_per_port(fw_nat):
    # one map rule, two targets; ports preserved (map values are address-only)
    assert fw_nat.probe_tcp("wan", NAT_ROUTER_WAN, 80) == "connected"
    assert fw_nat.probe_tcp("wan", NAT_ROUTER_WAN, 2222) == "connected"


@requires_netns
def test_b15_dnat_map_fall_through_dies_at_filter(fw_nat):
    # unmapped port: prerouting (policy accept) leaves it un-rewritten, so it
    # targets the router itself and dies against input's policy drop.
    assert fw_nat.probe_tcp("wan", NAT_ROUTER_WAN, 9999) == "timeout"


@requires_netns
def test_b16_forward_leg_filters_post_rewrite(fw_nat):
    # :9022 IS dnat'd (to jump, listener live) — but forward has no rule for
    # it, so the rewritten packet must die crossing the forward hook.
    assert fw_nat.probe_tcp("wan", NAT_ROUTER_WAN, 9022) == "timeout"


@requires_netns
def test_b17_snat_rewrites_source_to_fixed_ip(fw_nat):
    # lan client reaches the outside server; the server must see the router's
    # snat_ip, not the lan client's address.
    outcome, seen = fw_nat.probe_tcp_reply("lan", NAT_WAN_CLIENT, 9000)
    assert outcome == "connected"
    assert seen == NAT_ROUTER_WAN
    assert seen != NAT_LAN_CLIENT

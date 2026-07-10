"""§2 reachability truth table — the composed example-fleet policy behaves.

Stands up **hq-r** in the netns harness with one veth per zone (users /
services / dmz / nwm / transit / wan), applies the real generated `.nft`, and
walks P01–P22. Where B01–B26 proved primitives in isolation, this proves the
whole composed policy: skeleton + includes + site overlay + fleet sets + the
vmap dispatch + NAT, end to end. Cross-site *arrival* is exercised by sourcing
from the transit veth with a branch address (true two-router end-to-end is the
staged multi-router harness).
"""

import pathlib
import re

import pytest

from nftgen.generate import build
from tests.behavioral.netns import Harness, can_netns

FLEET = pathlib.Path(__file__).resolve().parent.parent / "example-fleet"

requires_netns = pytest.mark.skipif(
    not can_netns(), reason="netns harness not usable here (unshare/veth/nft/ct)"
)

# hq-r addressing (matches the hq site overlay: users 192.168.1/24, services
# 10.0.1/24, dmz 10.0.11/24, nwm 10.90.1/24, transit 172.16.0/24). Interface
# device names match the fleet's interfaces.yaml so `iifname` matches.
ZONES = [
    ("users", "lan_users", "192.168.1.1", "192.168.1.2"),
    ("services", "lan_svc", "10.0.1.1", "10.0.1.10"),  # 10.0.1.10 = hq_central
    ("dmz", "lan_dmz", "10.0.11.1", "10.0.11.10"),  # = local_dmz_web
    ("nwm", "lan_nwm", "10.90.1.1", "10.90.1.10"),  # = hq_monitor
    ("transit", "transit0", "172.16.0.252", "172.16.0.2"),
    ("wan", "wan0", "8.8.8.1", "8.8.8.2"),
]
HQ_DB = "10.0.1.20"  # second host on the services vlan


@pytest.fixture(scope="module")
def fw():
    h = Harness()
    try:
        h.topology(
            [
                {
                    "name": name,
                    "router_if": dev,
                    "router_addr": f"{r}/24",
                    "ns_addr": f"{n}/24",
                    "gw": r,
                }
                for name, dev, r, n in ZONES
            ]
        )
        # hq_db is a second address on the services vlan
        assert (
            h.run(
                "services", ["ip", "addr", "add", f"{HQ_DB}/24", "dev", "eth0"]
            ).returncode
            == 0
        )
        h.artifact = build(FLEET)["hq-r"]
        h.nft_apply(h.artifact)

        # listeners — a live target on every probed port so a drop reads as
        # timeout (not refused) and an allow reads as connected.
        for port in (80, 22, 5432, 9100, 636):
            h.listen("services", port)
        h.listen("dmz", 80)
        h.listen("dmz", 22)
        h.listen("users", 80)  # target for the reverse-pair (dmz->users) probe
        h.listen("wan", 80, echo_peer=True)  # egress target + snat peer proof
        h.listen("wan", 25)  # egress drop control
        h.listen(None, 22)  # the router itself (mgmt ssh) — input-chain tests

        # a bogon (rfc1918) source on the wan side, routed so a probe to the
        # services vlan leaves with saddr 10.0.0.5 (P13 spoofed-source scrub)
        assert (
            h.run(None, ["ip", "addr", "add", "10.0.0.1/24", "dev", "wan0"]).returncode
            == 0
        )
        assert (
            h.run("wan", ["ip", "addr", "add", "10.0.0.5/24", "dev", "eth0"]).returncode
            == 0
        )
        assert (
            h.run(
                "wan",
                [
                    "ip",
                    "route",
                    "add",
                    "10.0.1.0/24",
                    "via",
                    "10.0.0.1",
                    "src",
                    "10.0.0.5",
                ],
            ).returncode
            == 0
        )

        # cross-site arrivals: branch source hosts live on the transit ns (it
        # stands in for the far-side router), and the router routes replies to
        # the branch subnets back over transit — so a source-bound probe can
        # complete a round trip (P17/P18).
        for addr in ("192.168.2.5", "10.0.2.30"):  # a br1 user, and br1_app
            assert (
                h.run(
                    "transit", ["ip", "addr", "add", f"{addr}/32", "dev", "eth0"]
                ).returncode
                == 0
            )
        for subnet in ("192.168.2.0/24", "10.0.2.0/24"):
            assert (
                h.run(
                    None, ["ip", "route", "add", subnet, "via", "172.16.0.2"]
                ).returncode
                == 0
            )
        yield h
    finally:
        h.close()


def _counter(fw, name: str) -> int:
    r = fw.run(None, ["nft", "list", "counter", "inet", "filter", name])
    assert r.returncode == 0, r.stderr
    m = re.search(r"packets (\d+)", r.stdout)
    assert m, r.stdout
    return int(m.group(1))


# --------------------------------------------------------------------------- #
# Intra-site allow / deny (P01–P11)
# --------------------------------------------------------------------------- #


@requires_netns
def test_p01_users_to_services_web(fw):
    assert fw.probe_tcp("users", "10.0.1.10", 80) == "connected"


@requires_netns
def test_p02_users_to_services_ssh_denied(fw):
    # only nwm manages services; users have no ssh to the services vlan
    assert fw.probe_tcp("users", "10.0.1.10", 22) == "timeout"


@requires_netns
def test_p03_users_to_services_postgres_local_app(fw):
    assert fw.probe_tcp("users", "10.0.1.10", 5432) == "connected"


@requires_netns
def test_p04_users_to_dmz_web(fw):
    assert fw.probe_tcp("users", "10.0.11.10", 80) == "connected"


@requires_netns
def test_p05_users_to_dmz_ssh_denied(fw):
    # the dmz exposes only web to the user vlan
    assert fw.probe_tcp("users", "10.0.11.10", 22) == "timeout"


@requires_netns
def test_p06_users_egress_web(fw):
    assert fw.probe_tcp("users", "8.8.8.2", 80) == "connected"


@requires_netns
def test_p07_users_egress_smtp_denied(fw):
    # egress is web/dns/ntp only; smtp falls to the metered drop-log
    assert fw.probe_tcp("users", "8.8.8.2", 25) == "timeout"


@requires_netns
def test_p08_dmz_to_users_reverse_pair_denied(fw):
    # dmz->users is not a vmap pair; only ct-established return traffic flows
    assert fw.probe_tcp("dmz", "192.168.1.2", 80) == "timeout"


@requires_netns
def test_p09_nwm_to_services_ssh(fw):
    assert fw.probe_tcp("nwm", "10.0.1.10", 22) == "connected"


@requires_netns
def test_p10_monitor_scrapes_services_metrics(fw):
    # hq_monitor (in nwm at hq) -> local services :9100
    assert fw.probe_tcp("nwm", "10.0.1.10", 9100) == "connected"


@requires_netns
def test_p11_nwm_to_services_web_denied(fw):
    # nwm reaches services on mgmt/metrics ports only, not web
    assert fw.probe_tcp("nwm", "10.0.1.10", 80) == "timeout"


# --------------------------------------------------------------------------- #
# WAN edge (P12–P16)
# --------------------------------------------------------------------------- #


@requires_netns
def test_p12_wan_to_router_input_denied(fw):
    # nwm may ssh the router (positive control); wan may not reach input at all
    assert fw.probe_tcp("nwm", "10.90.1.1", 22) == "connected"
    assert fw.probe_tcp("wan", "8.8.8.1", 22) == "timeout"


@requires_netns
def test_p13_wan_bogon_source_scrubbed(fw):
    before = _counter(fw, "bogon_drops")
    # a forwarded packet arriving on wan with an rfc1918 source dies in wan_scrub
    assert fw.probe_tcp("wan", "10.0.1.10", 80) == "timeout"
    assert _counter(fw, "bogon_drops") > before


@requires_netns
def test_p14_wan_malformed_flags_dropped(fw):
    # A crafted syn+fin is dropped silently. Note: conntrack marks illegal flag
    # combos INVALID, so `ct invalid` (which precedes the wan_scrub jump) catches
    # them first — the bad_tcp scrub is defense-in-depth for the notrack case.
    before_inv = _counter(fw, "ct_invalid")
    before_bad = _counter(fw, "bad_tcp")
    assert fw.send_tcp("wan", "8.8.8.2", "10.0.1.10", 80, ["fin", "syn"]) == "silent"
    assert (
        _counter(fw, "ct_invalid") > before_inv or _counter(fw, "bad_tcp") > before_bad
    )


@requires_netns
def test_p15_wan_dnat_published_web_served(fw):
    # inbound :80 -> prerouting dnat to the dmz web host -> forward-allowed -> served
    assert fw.probe_tcp("wan", "8.8.8.1", 80) == "connected"


@requires_netns
def test_p16_wan_unmapped_port_drops(fw):
    # :23 isn't dnat'd; the packet stays destined for the router and input drops it
    assert fw.probe_tcp("wan", "8.8.8.1", 23) == "timeout"


# --------------------------------------------------------------------------- #
# Cross-site arrival, snat, blocklist, icmp (P17–P21)
# --------------------------------------------------------------------------- #


@requires_netns
def test_p17_all_users_reach_hq_central_over_transit(fw):
    # a branch user (192.168.2.5, in all_users) arriving over transit reaches
    # the HQ directory; a source not in all_users would not.
    assert fw.probe_tcp("transit", "10.0.1.10", 636, src="192.168.2.5") == "connected"


@requires_netns
def test_p18_specific_cross_site_app_flow(fw):
    # br1_app -> hq_db:5432 is the one allowed cross-site app flow…
    assert fw.probe_tcp("transit", "10.0.1.20", 5432, src="10.0.2.30") == "connected"
    # …the same port from any other transit source is not.
    assert fw.probe_tcp("transit", "10.0.1.20", 5432, src="192.168.2.5") == "timeout"


@requires_netns
def test_p19_egress_source_is_masqueraded(fw):
    # the wan peer sees the router's wan address, not the lan client
    outcome, seen = fw.probe_tcp_reply("users", "8.8.8.2", 80)
    assert outcome == "connected"
    assert seen == "8.8.8.1"  # the router's wan addr
    assert seen != "192.168.1.2"


@requires_netns
def test_p20_runtime_blocklist_kills_reachability(fw):
    # the users client reaches services (P01)…
    assert fw.probe_tcp("users", "10.0.1.10", 80) == "connected"
    # …until its address is added to the live blocklist.
    r = fw.run(
        None,
        ["nft", "add", "element", "inet", "filter", "blocklist", "{ 192.168.1.2 }"],
    )
    assert r.returncode == 0, r.stderr
    try:
        assert fw.probe_tcp("users", "10.0.1.10", 80) == "timeout"
    finally:
        fw.run(
            None,
            [
                "nft",
                "delete",
                "element",
                "inet",
                "filter",
                "blocklist",
                "{ 192.168.1.2 }",
            ],
        )


@requires_netns
def test_p21_icmp_echo_to_router(fw):
    # the icmp include accepts (rate-limited) echo-request on input
    assert fw.ping("users", "192.168.1.1") == "replied"


# --------------------------------------------------------------------------- #
# P22 — a dropped flow emits its attributed log (NFLOG capture)
# --------------------------------------------------------------------------- #

FIXTURES = pathlib.Path(__file__).resolve().parent / "behavioral" / "fixtures"


@requires_netns
def test_p22_dropped_flow_emits_attributed_log():
    # A dedicated fixture whose drop-log ships to NFLOG group 2 (what a real
    # deployment points a log collector at). Bind the group, send a flow to an
    # un-allowed port, and confirm the metered drop-log actually emitted with
    # its prefix — the troubleshoot story proven end to end.
    h = Harness()
    try:
        h.topology(
            [
                {
                    "name": "za",
                    "router_if": "r-za",
                    "router_addr": "10.50.0.1/24",
                    "ns_addr": "10.50.0.2/24",
                    "gw": "10.50.0.1",
                }
            ]
        )
        h.nft_apply(build(FIXTURES / "nflog")["router"])
        h.listen(None, 7000)  # the allowed port — positive control
        assert h.probe_tcp("za", "10.50.0.1", 7000) == "connected"
        # a probe to an un-allowed port is dropped and logged to NFLOG group 2
        prefix = h.nflog_capture(2, "za", "10.50.0.1", 9999)
        assert prefix == "input-drop ", f"captured {prefix!r}"
    finally:
        h.close()

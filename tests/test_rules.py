"""Phase 3 — structured rule rendering + chain building."""
import pytest

from nftgen.definitions import Definitions
from nftgen.ir import BuildError, build_sets
from nftgen.rules import RuleRenderer, build_chain, resolve_priority

DEFS = Definitions.from_mappings(
    {
        "networks": {
            "webhosts": ["192.0.2.10", "192.0.2.11"],
            "mgmt": ["192.168.9.0/24"],
            "dual": ["192.0.2.10", "2001:db8::10"],
            "v6only": ["2001:db8::/48"],
        },
        "services": {"http": ["80/tcp"], "https": ["443/tcp"], "web": ["http", "https"], "dns": ["53/tcp", "53/udp"]},
        "interfaces": {"wan": ["wan0", "wwan0"], "lan_if": ["lan0"]},
    }
)
# webhosts/web/wan/lan_if declared as NAMED sets; mgmt/dual/v6only inline.
NAMED = {s.name: s for s in build_sets(["webhosts", "web", "wan", "lan_if"], DEFS)}
R = RuleRenderer(DEFS, NAMED)


def one(rule):
    out = R.render(rule)
    assert len(out) == 1
    return out[0]


def test_named_sets_referenced_by_at():
    line = one({"saddr": "webhosts", "proto": "tcp", "dport": "web", "counter": True, "action": "accept"})
    assert line == "ip saddr @webhosts tcp dport @web counter accept"


def test_inline_group_not_declared():
    line = one({"saddr": "mgmt", "proto": "tcp", "dport": "ssh".replace("ssh", "22"), "action": "accept"})
    assert line == "ip saddr 192.168.9.0/24 tcp dport 22 accept"


def test_interface_named_and_literal():
    assert one({"iif": "lan_if", "oif": "wan", "action": "accept"}) == \
        'iifname @lan_if oifname @wan accept'
    assert one({"iif": "eth9", "action": "drop"}) == 'iifname "eth9" drop'


def test_ct_state():
    assert one({"ct": ["established", "related"], "action": "accept"}) == \
        "ct state established,related accept"


def test_mark_match():
    assert one({"mark": "0x1", "action": "accept"}) == "meta mark 0x1 accept"
    assert one({"saddr": "mgmt", "mark": "0x1", "action": "drop"}) == \
        "ip saddr 192.168.9.0/24 meta mark 0x1 drop"


def test_service_inline_is_proto_correct():
    # dns is tcp+udp 53; inline for udp must only give the udp port
    line = one({"saddr": "mgmt", "proto": "udp", "dport": "dns", "action": "accept"})
    assert line == "ip saddr 192.168.9.0/24 udp dport 53 accept"


def test_standalone_proto():
    assert one({"proto": "icmp", "action": "accept"}) == "meta l4proto icmp accept"


def test_icmp_type():
    # single type, and the meta l4proto is suppressed (icmp type implies the proto)
    assert one({"proto": "icmp", "icmp-type": "echo-request", "limit": "5/second", "action": "accept"}) == \
        "icmp type echo-request limit rate 5/second accept"
    # v6 + a list of types -> anon set
    assert one({"proto": "icmpv6",
                "icmp-type": ["nd-neighbor-solicit", "nd-neighbor-advert", "nd-router-advert"],
                "action": "accept"}) == \
        "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept"


def test_icmp_type_needs_icmp_proto():
    with pytest.raises(BuildError):
        R.render({"proto": "tcp", "icmp-type": "echo-request", "action": "accept"})


def test_actions_jump_dnat():
    # inet tables need a family qualifier; it's inferred from the target address
    assert one({"proto": "tcp", "dport": "8443", "action": {"dnat": "192.168.1.50:443"}}) == \
        "tcp dport 8443 dnat ip to 192.168.1.50:443"
    assert one({"action": {"dnat": "[2001:db8::5]:443"}}) == "dnat ip6 to [2001:db8::5]:443"
    assert one({"oif": "wan", "action": {"snat": "203.0.113.7"}}) == "oifname @wan snat ip to 203.0.113.7"
    assert one({"action": {"jump": "common_input"}}) == "jump common_input"


def test_dnat_target_without_ip_errors():
    with pytest.raises(BuildError):
        R.render({"proto": "tcp", "dport": "8443", "action": {"dnat": "not-an-ip"}})


def test_dnat_map():
    d = Definitions.from_mappings(
        {"networks": {"web": ["10.0.0.10"], "db": ["10.0.0.20"]}, "services": {"https": ["443/tcp"]}}
    )
    r = RuleRenderer(d, {})
    assert r.render({"iif": "eth0", "action": {"dnat": {"proto": "tcp", "map": {80: "web", "https": "db"}}}}) == \
        ['iifname "eth0" dnat ip to tcp dport map { 80 : 10.0.0.10, 443 : 10.0.0.20 }']


def test_dnat_map_errors():
    d = Definitions.from_mappings({"networks": {"web": ["10.0.0.10"], "grp": ["10.0.0.1", "10.0.0.2"]}})
    r = RuleRenderer(d, {})
    with pytest.raises(BuildError):  # target carries a port (address-only)
        r.render({"action": {"dnat": {"proto": "tcp", "map": {80: "10.0.0.10:8080"}}}})
    with pytest.raises(BuildError):  # port key needs a proto
        r.render({"action": {"dnat": {"map": {80: "web"}}}})
    with pytest.raises(BuildError):  # target resolves to >1 address
        r.render({"action": {"dnat": {"proto": "tcp", "map": {80: "grp"}}}})


def test_masquerade():
    assert one({"oif": "wan", "saddr": "mgmt", "action": "masquerade"}) == \
        "oifname @wan ip saddr 192.168.9.0/24 masquerade"


def test_raw_passthrough():
    assert R.render({"raw": "tcp flags & (fin|syn) == (fin|syn) counter drop"}) == \
        ["tcp flags & (fin|syn) == (fin|syn) counter drop"]


# -- strict key validation (typos must fail loudly, not silently weaken) ----- #
def test_unknown_key_errors():
    # `dprot` is a typo for `dport`; without the guard this would render a rule
    # with no port match (silently broader) and nft -c would not catch it.
    with pytest.raises(BuildError):
        R.render({"saddr": "mgmt", "proto": "tcp", "dprot": "22", "action": "accept"})


def test_raw_must_be_alone():
    with pytest.raises(BuildError):
        R.render({"raw": "ip saddr 10.0.0.1 accept", "action": "drop"})


def test_vmap_must_be_alone():
    with pytest.raises(BuildError):
        R.render({"vmap": {"key": "iif", "map": {"wan0": "drop"}}, "action": "accept"})


def test_explicit_at_reference():
    assert one({"saddr": "@webhosts", "action": "drop"}) == "ip saddr @webhosts drop"


# -- family handling -------------------------------------------------------- #
def test_mixed_inline_group_expands_to_two_lines():
    out = R.render({"saddr": "dual", "action": "accept"})
    assert out == ["ip saddr 192.0.2.10 accept", "ip6 saddr 2001:db8::10 accept"]


def test_incompatible_families_error():
    # v6-only source with a v4 literal dest can never render
    with pytest.raises(BuildError):
        R.render({"saddr": "v6only", "daddr": "192.0.2.0/24", "action": "accept"})


def test_port_without_proto_errors():
    with pytest.raises(BuildError):
        R.render({"dport": "web", "action": "accept"})


# -- chains ----------------------------------------------------------------- #
def test_resolve_priority():
    assert resolve_priority("filter") == 0
    assert resolve_priority("srcnat") == 100
    assert resolve_priority(-150) == -150


def test_build_base_chain():
    spec = {
        "name": "input",
        "hook": "input",
        "priority": "filter",
        "policy": "drop",
        "rules": [
            {"ct": ["established", "related"], "action": "accept"},
            {"include": "x.yaml"},  # skipped for now
            {"saddr": "webhosts", "proto": "tcp", "dport": "web", "action": "accept"},
        ],
    }
    chain = build_chain(spec, R)
    assert chain.render() == [
        "    chain input {",
        "        type filter hook input priority 0; policy drop;",
        "        ct state established,related accept",
        "        ip saddr @webhosts tcp dport @web accept",
        "    }",
    ]


def test_build_regular_chain_has_no_header():
    chain = build_chain({"name": "common", "rules": [{"proto": "icmp", "action": "accept"}]}, R)
    assert chain.hook is None
    assert chain.render() == [
        "    chain common {",
        "        meta l4proto icmp accept",
        "    }",
    ]

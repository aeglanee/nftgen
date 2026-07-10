"""Phase 6A — statement rule keys: limit / quota / log / set-mark / set-mss."""

import pytest

from nftgen.definitions import Definitions
from nftgen.ir import BuildError, build_sets
from nftgen.rules import RuleRenderer

DEFS = Definitions.from_mappings(
    {"networks": {"bad": ["192.0.2.50/32"]}, "services": {"ssh": ["22/tcp"]}}
)
R = RuleRenderer(DEFS, {s.name: s for s in build_sets(["ssh"], DEFS)})


def one(rule):
    out = R.render(rule)
    assert len(out) == 1
    return out[0]


def test_limit():
    assert (
        one(
            {
                "proto": "tcp",
                "dport": "ssh",
                "ct": ["new"],
                "limit": "10/minute",
                "action": "accept",
            }
        )
        == "ct state new tcp dport @ssh limit rate 10/minute accept"
    )


def test_quota():
    assert (
        one({"saddr": "bad", "quota": "over 1024 mbytes", "action": "drop"})
        == "ip saddr 192.0.2.50/32 quota over 1024 mbytes drop"
    )


def test_log_bool_and_opts():
    assert (
        one({"proto": "tcp", "dport": "ssh", "log": True, "action": "accept"})
        == "tcp dport @ssh log accept"
    )
    assert (
        one(
            {
                "proto": "tcp",
                "dport": "ssh",
                "log": {"prefix": "ssh ", "level": "info"},
                "action": "accept",
            }
        )
        == 'tcp dport @ssh log prefix "ssh " level info accept'
    )


def test_set_mark_statement_only():
    # mangle, no terminal action: the packet continues
    assert (
        one({"daddr": "10.0.0.0/8", "set-mark": "0x1"})
        == "ip daddr 10.0.0.0/8 meta mark set 0x1"
    )


def test_set_mss_pmtu_and_fixed():
    assert (
        one({"proto": "tcp", "set-mss": "pmtu"})
        == "meta l4proto tcp tcp flags syn tcp option maxseg size set rt mtu"
    )
    assert (
        one({"proto": "tcp", "set-mss": 1460})
        == "meta l4proto tcp tcp flags syn tcp option maxseg size set 1460"
    )


def test_statement_with_counter_and_no_action():
    assert (
        one({"daddr": "10.0.0.0/8", "set-mark": "0x1", "counter": True})
        == "ip daddr 10.0.0.0/8 meta mark set 0x1 counter"
    )


def test_empty_rule_errors():
    with pytest.raises(BuildError):
        R.render({"proto": "tcp"})  # no action, no statement, no counter


def test_statement_order_before_verdict():
    line = one(
        {
            "proto": "tcp",
            "dport": "ssh",
            "limit": "5/second",
            "log": True,
            "counter": True,
            "action": "accept",
        }
    )
    assert line == "tcp dport @ssh limit rate 5/second log counter accept"


def test_flow_offload_must_not_carry_a_verdict():
    """`flow add` yields NFT_BREAK when it declines to offload (mid-handshake,
    fin/rst, unconfirmed ct), which aborts the rest of the rule — a verdict
    after it is silently skipped and the packet falls through to the chain
    policy. nft -c accepts the combined form; only traffic reveals it."""
    r = RuleRenderer(Definitions.from_mappings({}), {})
    with pytest.raises(BuildError, match="must not share a rule with `action:`"):
        r.render({"ct": ["established"], "flow-offload": "ft", "action": "accept"})
    # offload alone is fine (it is a statement, so the rule needs no verdict)
    assert r.render({"ct": ["established"], "flow-offload": "ft"}) == [
        "ct state established flow add @ft"
    ]


# --- meter: per-key rate limiting on a dynamic set ------------------------- #

_METER_DEFS = Definitions.from_mappings({"networks": {"any": ["0.0.0.0/0"]}})
_METER_SETS = build_sets(
    [
        {"name": "m4", "type": "ipv4_addr", "flags": ["dynamic", "timeout"]},
        {"name": "m6", "type": "ipv6_addr", "flags": ["dynamic", "timeout"]},
        {"name": "mif", "type": "ifname", "flags": ["dynamic"]},
        {"name": "static4", "type": "ipv4_addr", "flags": ["interval"]},
    ],
    _METER_DEFS,
)
RM = RuleRenderer(_METER_DEFS, {s.name: s for s in _METER_SETS})


def test_meter_saddr_with_log():
    assert RM.render(
        {
            "meter": {"set": "m4", "key": "saddr", "rate": "4/minute", "timeout": "1m"},
            "log": {"prefix": "drop "},
        }
    ) == ['update @m4 { ip saddr timeout 1m limit rate 4/minute } log prefix "drop "']


def test_meter_v6_and_ifname_keys():
    assert RM.render(
        {"meter": {"set": "m6", "key": "daddr", "rate": "10/second"}, "action": "drop"}
    ) == ["update @m6 { ip6 daddr limit rate 10/second } drop"]
    assert RM.render(
        {
            "meter": {"set": "mif", "key": "iifname", "rate": "3/minute"},
            "action": "drop",
        }
    ) == ["update @mif { iifname limit rate 3/minute } drop"]


def test_meter_validation_errors():
    with pytest.raises(BuildError, match="not a declared set"):
        RM.render({"meter": {"set": "nope", "key": "saddr", "rate": "1/s"}})
    with pytest.raises(BuildError, match="must be declared `flags: \\[dynamic\\]`"):
        RM.render({"meter": {"set": "static4", "key": "saddr", "rate": "1/s"}})
    with pytest.raises(BuildError, match="key 'oifname' needs an ifname set"):
        RM.render({"meter": {"set": "m4", "key": "oifname", "rate": "1/s"}})
    with pytest.raises(BuildError, match="needs a `rate:`"):
        RM.render({"meter": {"set": "m4", "key": "saddr"}})
    with pytest.raises(BuildError, match="unknown meter key"):
        RM.render({"meter": {"set": "m4", "key": "saddr", "rate": "1/s", "x": 1}})

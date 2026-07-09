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

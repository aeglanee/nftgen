"""Phase 6E — structured tcp flags (flags: match/mask, single or a list)."""
import pytest

from nftgen.definitions import Definitions
from nftgen.ir import BuildError
from nftgen.rules import RuleRenderer

R = RuleRenderer(Definitions.from_mappings({}), {})


def test_single_check_default_mask():
    # mask defaults to match
    assert R.render({"flags": {"match": ["syn"]}, "action": "accept"}) == \
        ["tcp flags & syn == syn accept"]


def test_single_check_explicit_mask():
    assert R.render({"flags": {"match": ["syn"], "mask": ["syn", "ack"]}, "action": "accept"}) == \
        ["tcp flags & (syn|ack) == syn accept"]


def test_null_scan_all_none():
    assert R.render({"flags": {"match": "none", "mask": "all"}, "action": "drop"}) == \
        ["tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop"]


def test_list_of_checks_multiplies_lines():
    rule = {
        "flags": [
            {"match": "none", "mask": "all"},
            {"match": ["fin", "syn"], "mask": ["fin", "syn"]},
            {"match": ["fin"], "mask": ["fin", "ack"]},
        ],
        "counter": True,
        "action": "drop",
    }
    assert R.render(rule) == [
        "tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 counter drop",
        "tcp flags & (fin|syn) == (fin|syn) counter drop",
        "tcp flags & (fin|ack) == fin counter drop",
    ]


def test_subset_violation_errors():
    with pytest.raises(BuildError):
        R.render({"flags": {"match": ["syn", "fin"], "mask": ["syn"]}, "action": "drop"})


def test_unknown_flag_errors():
    with pytest.raises(BuildError):
        R.render({"flags": {"match": ["syn", "bogus"], "mask": "all"}, "action": "drop"})


def test_no_mask_for_empty_match_errors():
    with pytest.raises(BuildError):
        R.render({"flags": {"match": "none"}, "action": "drop"})


def test_flags_combine_with_other_matches():
    assert R.render({"proto": "tcp", "flags": {"match": ["syn"], "mask": ["syn", "ack"]}, "action": "accept"}) == \
        ["meta l4proto tcp tcp flags & (syn|ack) == syn accept"]

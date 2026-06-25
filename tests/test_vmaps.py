"""Phase 6D — verdict maps (vmap rule type)."""
import pytest

from nftgen.definitions import Definitions
from nftgen.ir import BuildError
from nftgen.rules import RuleRenderer

R = RuleRenderer(Definitions.from_mappings({}), {})


def test_iif_vmap():
    rule = {"vmap": {"key": "iif", "map": {"wan0": {"jump": "wan_input"}, "lan0": {"jump": "lan_input"}}}}
    assert R.render(rule) == [
        'iifname vmap { "wan0" : jump wan_input, "lan0" : jump lan_input }'
    ]


def test_proto_vmap_unquoted_keys_and_verdicts():
    rule = {"vmap": {"key": "proto", "map": {"tcp": {"goto": "tcp_chain"}, "udp": "drop"}}}
    assert R.render(rule) == ["meta l4proto vmap { tcp : goto tcp_chain, udp : drop }"]


def test_unsupported_vmap_key_errors():
    with pytest.raises(BuildError):
        R.render({"vmap": {"key": "dport", "map": {"80": "accept"}}})

"""Phase 5 — `nft -c -f` validation of generated output.

The nft checks skip automatically when `nft -c` isn't usable here (no binary, or
unprivileged sandbox). Run them on a box with nftables to actually validate.
"""

import pathlib

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, generate, render_tables

EXAMPLE = pathlib.Path(__file__).resolve().parent.parent / "example"

requires_nft = pytest.mark.skipif(
    not validate.can_check(), reason="nft -c not usable in this environment"
)


def _gen(host: str) -> str:
    return generate(
        EXAMPLE / "policies" / "hosts" / host,
        defs_dir=EXAMPLE / "definitions",
        include_base=EXAMPLE / "policies",
        sites_dir=EXAMPLE / "sites",
    )


def test_validate_module_is_graceful_without_nft():
    # never raises, regardless of whether nft is installed
    assert isinstance(validate.nft_available(), bool)
    assert isinstance(validate.can_check(), bool)


@requires_nft
@pytest.mark.parametrize("host", ["router1.yaml", "router2.yaml", "gateway.yaml"])
def test_generated_passes_nft_check(host):
    result = validate.check(_gen(host))
    assert result.ok, result.stderr


@requires_nft
def test_invalid_ruleset_is_rejected():
    # a sanity check that our checker actually catches bad nft
    assert not validate.check("table inet t { chain c { nonsense-token } }").ok


@requires_nft
def test_ct_mark_save_restore_passes_nft_check():
    # symmetric return: connections that arrive over the pair link are marked,
    # and their locally generated replies get the mark back for an `ip rule`
    tables = [
        {
            "family": "inet",
            "name": "pairmark",
            "chains": [
                {
                    "name": "prerouting",
                    "hook": "prerouting",
                    "type": "filter",
                    "priority": "mangle",
                    "policy": "accept",
                    "rules": [
                        {"iifname": "peer", "ct": ["new"], "set-ct-mark": "0x1"},
                    ],
                },
                {
                    "name": "output",
                    "hook": "output",
                    "type": "route",
                    "priority": "mangle",
                    "policy": "accept",
                    "rules": [
                        {"ct-mark": "0x1", "set-mark": "ct-mark"},
                        {"set-ct-mark": "mark"},
                    ],
                },
            ],
        }
    ]
    text = render_tables(
        tables,
        Definitions.from_mappings({"interfaces": {"peer": ["peer0"]}}),
        DictResolver({}),
    )
    assert "ct mark set 0x1" in text
    assert "ct mark 0x1 meta mark set ct mark" in text
    res = validate.check(text)
    assert res.ok, res.stderr

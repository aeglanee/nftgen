"""Phase 5 — `nft -c -f` validation of generated output.

The nft checks skip automatically when `nft -c` isn't usable here (no binary, or
unprivileged sandbox). Run them on a box with nftables to actually validate.
"""
import pathlib

import pytest

from nftgen import validate
from nftgen.generate import generate

EXAMPLE = pathlib.Path(__file__).resolve().parent.parent / "example"

requires_nft = pytest.mark.skipif(
    not validate.can_check(), reason="nft -c not usable in this environment"
)


def _gen(host: str) -> str:
    return generate(
        EXAMPLE / "policies" / "hosts" / host,
        defs_dir=EXAMPLE / "def",
        include_base=EXAMPLE / "policies",
        sites_dir=EXAMPLE / "sites",
    )


def test_validate_module_is_graceful_without_nft():
    # never raises, regardless of whether nft is installed
    assert isinstance(validate.nft_available(), bool)
    assert isinstance(validate.can_check(), bool)


@requires_nft
@pytest.mark.parametrize("host", ["router1.yaml", "router2.yaml"])
def test_generated_passes_nft_check(host):
    result = validate.check(_gen(host))
    assert result.ok, result.stderr


@requires_nft
def test_invalid_ruleset_is_rejected():
    # a sanity check that our checker actually catches bad nft
    assert not validate.check("table inet t { chain c { nonsense-token } }").ok

"""Step 2 — build(<root>): fleet generation + flush-ruleset deploy artifact."""
import pathlib

import pytest

from nftgen import validate
from nftgen.cli import main
from nftgen.generate import build

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "example"

requires_nft = pytest.mark.skipif(
    not validate.can_check(), reason="nft -c not usable in this environment"
)


def test_build_all_hosts():
    out = build(EXAMPLE)
    assert set(out) == {"gateway", "router1", "router2"}
    for name, text in out.items():
        assert text.startswith("#!/usr/sbin/nft -f")
        assert "flush ruleset" in text          # deploy artifact (Shape A)


def test_build_single_host():
    out = build(EXAMPLE, host="router1")
    assert set(out) == {"router1"}


def test_build_missing_host_errors():
    with pytest.raises(FileNotFoundError):
        build(EXAMPLE, host="does-not-exist")


def test_flush_precedes_tables():
    text = build(EXAMPLE, host="router1")["router1"]
    assert text.index("flush ruleset") < text.index("table inet")


def test_build_body_matches_generate_golden():
    # build() == the committed (flush-free) golden, plus the flush line — i.e.
    # build is generate() + the deploy header, nothing else changes.
    text = build(EXAMPLE, host="router1")["router1"]
    golden = (ROOT / "tests" / "golden" / "router1.nft").read_text()
    assert text == golden.replace("\n\ntable inet raw", "\n\nflush ruleset\n\ntable inet raw", 1)


def test_cli_build_writes_files(tmp_path):
    assert main(["build", str(EXAMPLE), "--out-dir", str(tmp_path)]) == 0
    for host in ("gateway", "router1", "router2"):
        assert (tmp_path / f"{host}.nft").exists()


@requires_nft
@pytest.mark.parametrize("host", ["gateway", "router1", "router2"])
def test_build_output_is_valid_nft(host):
    result = validate.check(build(EXAMPLE, host=host)[host])
    assert result.ok, result.stderr

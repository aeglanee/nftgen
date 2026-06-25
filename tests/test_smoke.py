"""Phase 0 smoke tests — the package imports and the CLI runs."""
import nftgen
from nftgen.cli import build_parser, main


def test_has_version():
    assert nftgen.__version__


def test_cli_no_args_prints_help_and_exits_zero():
    assert main([]) == 0


def test_parser_accepts_policy_and_flags():
    args = build_parser().parse_args(["host.yaml", "--defs", "def", "--out", "x.nft"])
    assert args.policy == "host.yaml"
    assert args.defs == "def"
    assert args.out == "x.nft"

"""Command-line entry point for nftgen.

Phase 0 skeleton: argument parsing only. Generation lands in later phases
(defs loader -> named sets -> chains/rules -> includes -> output).
"""
from __future__ import annotations

import argparse
import sys

from nftgen import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nftgen",
        description="nftables-only firewall generator (YAML -> .nft)",
    )
    parser.add_argument("--version", action="version", version=f"nftgen {__version__}")
    parser.add_argument("policy", nargs="?", help="host policy YAML file")
    parser.add_argument("--defs", help="definitions directory (default: ./def)")
    parser.add_argument("--out", help="output .nft file (default: stdout)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.policy:
        build_parser().print_help()
        return 0
    print("nftgen: generation not implemented yet (Phase 0 skeleton)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

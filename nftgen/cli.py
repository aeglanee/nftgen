"""Command-line entry point for nftgen."""
from __future__ import annotations

import argparse
import pathlib
import sys

from nftgen import __version__
from nftgen.generate import generate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nftgen",
        description="nftables-only firewall generator (YAML -> .nft)",
    )
    parser.add_argument("--version", action="version", version=f"nftgen {__version__}")
    parser.add_argument("policy", nargs="?", help="host policy YAML file")
    parser.add_argument("--defs", help="definitions dir (default: <root>/def)")
    parser.add_argument("--base", help="include base dir (default: the policies dir)")
    parser.add_argument("--sites", help="sites dir (default: <root>/sites)")
    parser.add_argument("--out", help="output .nft file (default: stdout)")
    return parser


def _defaults(policy: pathlib.Path):
    """For a <root>/policies/hosts/<host>.yaml layout, infer defs/base/sites."""
    include_base = policy.parent.parent          # .../policies
    root = policy.parents[2] if len(policy.parents) >= 3 else policy.parent
    return root / "def", include_base, root / "sites"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.policy:
        build_parser().print_help()
        return 0

    policy = pathlib.Path(args.policy)
    def_default, base_default, sites_default = _defaults(policy)
    text = generate(
        policy,
        defs_dir=args.defs or def_default,
        include_base=args.base or base_default,
        sites_dir=args.sites or sites_default,
    )

    if args.out:
        out = pathlib.Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text)
        print(f"wrote {out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

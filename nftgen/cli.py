"""Command-line entry point for nftgen."""

from __future__ import annotations

import argparse
import functools
import pathlib
import sys

import yaml

from nftgen import __version__, validate
from nftgen.definitions import DefinitionError
from nftgen.generate import build, generate
from nftgen.ir import BuildError


def _clean_errors(fn):
    """Authoring mistakes get a one-line `nftgen: error:` instead of a traceback."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (BuildError, DefinitionError, FileNotFoundError, yaml.YAMLError) as e:
            print(f"nftgen: error: {e}", file=sys.stderr)
            return 1

    return wrapper


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nftgen",
        description="nftables-only firewall generator (YAML -> .nft)",
    )
    parser.add_argument("--version", action="version", version=f"nftgen {__version__}")
    parser.add_argument("policy", nargs="?", help="host policy YAML file")
    parser.add_argument("--defs", help="definitions dir (default: <root>/definitions)")
    parser.add_argument("--base", help="include base dir (default: the policies dir)")
    parser.add_argument("--sites", help="sites dir (default: <root>/sites)")
    parser.add_argument("--out", help="output .nft file (default: stdout)")
    parser.add_argument(
        "--check", action="store_true", help="validate the output with `nft -c -f`"
    )
    return parser


def _defaults(policy: pathlib.Path):
    """For a <root>/policies/hosts/<host>.yaml layout, infer defs/base/sites."""
    include_base = policy.parent.parent  # .../policies
    root = policy.parents[2] if len(policy.parents) >= 3 else policy.parent
    return root / "definitions", include_base, root / "sites"


@_clean_errors
def _build_cmd(argv: list[str]) -> int:
    """`nftgen build <root>` — regenerate generated/<host>.nft for every host."""
    parser = argparse.ArgumentParser(
        prog="nftgen build",
        description="generate generated/<host>.nft for every host under <root>",
    )
    parser.add_argument("root", help="project root (definitions/, sites/, policies/)")
    parser.add_argument("--host", help="build only this host (default: all)")
    parser.add_argument("--out-dir", help="output dir (default: <root>/generated)")
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="print the ruleset to stdout, write nothing (requires --host)",
    )
    parser.add_argument(
        "--check", action="store_true", help="validate each output with `nft -c -f`"
    )
    args = parser.parse_args(argv)

    # stdout is a single stream, so it maps to exactly one host.
    if args.stdout and not args.host:
        print(
            "nftgen: error: --stdout requires --host (stdout is a single stream "
            "— one host)",
            file=sys.stderr,
        )
        return 2

    # Probe before generating: a --check that can't run must fail loudly, not
    # silently skip validation the caller (CI, the Ansible play) asked for.
    if args.check and not validate.can_check():
        print(
            "nftgen: error: --check requested but `nft -c` is not usable here "
            "(nft missing, or no netlink and no unshare fallback)",
            file=sys.stderr,
        )
        return 2

    results = build(args.root, host=args.host)

    # --stdout: emit the one host's ruleset and write nothing (previews, pipes,
    # a deployer rendering on the fly without touching the committed tree).
    if args.stdout:
        text = next(iter(results.values()))
        rc = 0
        if args.check:
            result = validate.check(text)
            if not result.ok:
                print(
                    f"nftgen: {args.host}: nft -c FAILED:\n{result.stderr}",
                    file=sys.stderr,
                )
                rc = 1
        sys.stdout.write(text)
        return rc

    out_dir = (
        pathlib.Path(args.out_dir)
        if args.out_dir
        else pathlib.Path(args.root) / "generated"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    rc = 0
    for name, text in sorted(results.items()):
        path = out_dir / f"{name}.nft"
        path.write_text(text)
        print(f"wrote {path}", file=sys.stderr)
        if args.check:
            result = validate.check(text)
            if not result.ok:
                print(
                    f"nftgen: {name}: nft -c FAILED:\n{result.stderr}", file=sys.stderr
                )
                rc = 1
    return rc


@_clean_errors
def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "build":
        return _build_cmd(argv[1:])

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

    if args.check:
        if not validate.nft_available():
            print("nftgen: --check requested but `nft` was not found", file=sys.stderr)
            return 2
        result = validate.check(text)
        if result.ok:
            print("nftgen: nft -c passed", file=sys.stderr)
        else:
            print(f"nftgen: nft -c FAILED:\n{result.stderr}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

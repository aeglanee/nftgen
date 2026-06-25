"""Validate a generated ruleset with ``nft -c -f`` (check only — never applies).

`nft -c` parses and semantically checks a ruleset without committing it. It does
need to talk to netlink, so it requires a usable (often privileged) `nft`;
``can_check()`` probes for that so callers/tests can skip cleanly when it isn't
available (e.g. unprivileged CI, or a box without nftables).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass


@dataclass
class CheckResult:
    ok: bool
    returncode: int
    stderr: str


def nft_available() -> bool:
    """Is an `nft` binary on PATH?"""
    return shutil.which("nft") is not None


def check(text: str) -> CheckResult:
    """Run ``nft -c -f`` on the ruleset text. Raises OSError if nft is missing."""
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as fh:
        fh.write(text)
        path = fh.name
    try:
        proc = subprocess.run(
            ["nft", "-c", "-f", path], capture_output=True, text=True
        )
        return CheckResult(proc.returncode == 0, proc.returncode, proc.stderr.strip())
    finally:
        os.unlink(path)


_PROBE = "table inet nftgen_probe {\n\tchain c {\n\t}\n}\n"


def can_check() -> bool:
    """True only if `nft` is present AND ``nft -c`` actually works here.

    (`nft -c` needs netlink access, so it can be present but unusable in an
    unprivileged sandbox.) Never raises.
    """
    if not nft_available():
        return False
    try:
        return check(_PROBE).ok
    except OSError:
        return False

"""Validate a generated ruleset with ``nft -c -f`` (check only — never applies).

`nft -c` parses and semantically checks a ruleset without committing it. It does
need to talk to netlink, so it requires a usable `nft`. On a privileged box / CI
that's a plain ``nft -c``; in a restricted shell (no_new_privs, no host netlink)
we fall back to running the check inside a throwaway user+net namespace
(``unshare -rn``), which hands ``nft`` a private netlink to initialise against.
The check still only *validates* — nothing is ever applied, in any namespace.

``can_check()`` probes which mode works (if any) so callers/tests skip cleanly
when nft can't run here at all (e.g. no binary, or namespaces disabled too).
"""
from __future__ import annotations

import functools
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


_PROBE = "table inet nftgen_probe {\n\tchain c {\n\t}\n}\n"


def _run(prefix: list[str], text: str) -> CheckResult:
    """Run ``[*prefix] nft -c -f <file>`` on the ruleset. OSError if nft/prefix missing."""
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as fh:
        fh.write(text)
        path = fh.name
    try:
        proc = subprocess.run(
            [*prefix, "nft", "-c", "-f", path], capture_output=True, text=True
        )
        return CheckResult(proc.returncode == 0, proc.returncode, proc.stderr.strip())
    finally:
        os.unlink(path)


@functools.lru_cache(maxsize=1)
def _runner() -> tuple[str, ...] | None:
    """The argv prefix that makes ``nft -c`` work here (``()`` = direct), or None.

    Prefer a direct ``nft`` (works as root / in CI, and doesn't depend on
    unprivileged user namespaces). Fall back to ``unshare -rn`` for restricted
    shells. If neither validates a known-good probe, checking isn't possible.
    """
    if not nft_available():
        return None
    candidates: list[tuple[str, ...]] = [()]
    if shutil.which("unshare"):
        candidates.append(("unshare", "-rn"))
    for prefix in candidates:
        try:
            if _run(list(prefix), _PROBE).ok:
                return prefix
        except OSError:
            continue
    return None


def check(text: str) -> CheckResult:
    """Run ``nft -c -f`` on the ruleset text (direct, else under ``unshare -rn``).

    Raises OSError only if no `nft` binary exists at all.
    """
    prefix = _runner()
    return _run(list(prefix) if prefix is not None else [], text)


def can_check() -> bool:
    """True iff ``nft -c`` can actually validate here (direct or via unshare). Never raises."""
    return _runner() is not None

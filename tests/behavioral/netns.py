"""Client for the netns behavioral harness (docs/testing-plan.md).

``Harness`` launches tests/behavioral/agent.py under ``unshare -r -n`` (root
in a user namespace that owns a fresh net namespace — the router) and drives
it over JSON lines. ``can_netns()`` probes whether that whole stack works
here (unshare + veth creation + an nft ct rule actually applying), so tests
skip cleanly on boxes without user namespaces, iproute2, nft, or conntrack.
"""

from __future__ import annotations

import functools
import json
import pathlib
import shutil
import subprocess
import sys

AGENT = pathlib.Path(__file__).with_name("agent.py")

_PROBE_RULESET = (
    "table inet nftgen_probe {\n"
    "  chain c {\n"
    "    type filter hook input priority 0; policy accept;\n"
    "    ct state established accept\n"
    "  }\n"
    "}\n"
)


@functools.lru_cache(maxsize=1)
def can_netns() -> bool:
    """True iff the full harness stack works: userns, veth, nft apply with ct."""
    if not all(shutil.which(b) for b in ("unshare", "ip", "nft")):
        return False
    try:
        proc = subprocess.run(
            [
                "unshare",
                "-r",
                "-n",
                "sh",
                "-c",
                "ip link add name a type veth peer name b && nft -f -",
            ],
            input=_PROBE_RULESET,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


class HarnessError(RuntimeError):
    pass


class Harness:
    """One supervisor process = one router namespace + its zone namespaces."""

    def __init__(self) -> None:
        self._proc = subprocess.Popen(
            ["unshare", "-r", "-n", sys.executable, "-u", str(AGENT)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _rpc(self, **req) -> dict:
        assert self._proc.stdin and self._proc.stdout
        self._proc.stdin.write(json.dumps(req) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            err = self._proc.stderr.read() if self._proc.stderr else ""
            raise HarnessError(f"agent died: {err.strip()}")
        resp = json.loads(line)
        if not resp.get("ok"):
            raise HarnessError(resp.get("err", "unknown agent error"))
        return resp

    # -- operations ---------------------------------------------------------- #
    def topology(self, zones: list[dict]) -> None:
        """zones: [{name, router_if, router_addr(cidr), ns_addr(cidr), gw}, …]"""
        self._rpc(op="topology", zones=zones)

    def nft_apply(self, text: str) -> None:
        self._rpc(op="nft", text=text)

    def listen(self, ns: str | None, port: int) -> None:
        """TCP accept-loop in a zone ns (or the router when ns is None)."""
        self._rpc(op="listen", ns=ns, port=port)

    def probe_tcp(
        self, ns: str | None, dst: str, port: int, timeout: float = 1.5
    ) -> str:
        """-> 'connected' | 'refused' | 'timeout' (drop shows as timeout)."""
        return self._rpc(op="probe", ns=ns, dst=dst, port=port, timeout=timeout)[
            "result"
        ]

    def run(self, ns: str | None, argv: list[str]) -> subprocess.CompletedProcess:
        resp = self._rpc(op="run", ns=ns, argv=argv)
        return subprocess.CompletedProcess(argv, resp["rc"], resp["out"], resp["err"])

    def close(self) -> None:
        if self._proc.poll() is None:
            try:
                self._proc.stdin.write('{"op": "quit"}\n')  # type: ignore[union-attr]
                self._proc.stdin.flush()  # type: ignore[union-attr]
                self._proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                self._proc.kill()

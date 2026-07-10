#!/usr/bin/env python3
"""Behavioral-harness agent. Runs as root inside ``unshare -r -n``.

The parent (tests/behavioral/netns.py) launches this file under a user+net
namespace and drives it with one JSON object per line on stdin; every request
gets one JSON line back on stdout. The agent's own namespace is the *router*;
each zone is an anonymous net namespace kept alive by a paused holder child
and entered via ``setns(/proc/<pid>/ns/net)`` — no /run/netns, no mount ns.

Stdlib only; must be runnable as a bare file (it is exec'd by path).

Ops:
  {"op": "topology", "zones": [{"name", "router_if", "router_addr",
      "ns_addr", "gw"}, …]}            veths, addrs, routes, ip_forward=1
  {"op": "nft", "text": "…"}           apply a ruleset in the router ns
  {"op": "listen", "ns": name|null, "port": N,
      "echo_peer": bool}               TCP accept-loop; echo_peer writes the
                                       accepted peer address back on the conn
  {"op": "probe", "ns": name|null, "dst": "a.b.c.d", "port": N,
      "timeout": secs, "read": bool}   -> connected | refused | timeout
                                       (read: also return the server's reply)
  {"op": "run", "ns": name|null, "argv": […]}       escape hatch / debugging
  {"op": "quit"}
"""

import contextlib
import ctypes
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile

libc = ctypes.CDLL(None, use_errno=True)
CLONE_NEWNET = 0x40000000

NAMESPACES: dict[str, int] = {}  # zone name -> holder pid
CHILDREN: list[int] = []  # holders + listeners, killed on quit


def _unshare_newnet() -> None:
    if libc.unshare(CLONE_NEWNET) != 0:
        raise OSError(ctypes.get_errno(), "unshare(CLONE_NEWNET) failed")


def _setns_net(pid: int) -> None:
    fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    try:
        if libc.setns(fd, CLONE_NEWNET) != 0:
            raise OSError(ctypes.get_errno(), f"setns into pid {pid} failed")
    finally:
        os.close(fd)


def _spawn_holder() -> int:
    """A child that owns a fresh net namespace and just sleeps."""
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_r)
        _unshare_newnet()
        os.write(ready_w, b"1")
        os.close(ready_w)
        while True:
            signal.pause()
    os.close(ready_w)
    os.read(ready_r, 1)
    os.close(ready_r)
    CHILDREN.append(pid)
    return pid


def _run(
    ns: str | None, argv: list[str], input_text: str | None = None
) -> subprocess.CompletedProcess:
    """Run argv in the router ns (ns=None) or a zone ns (via setns pre-exec)."""
    pre = None
    if ns is not None:
        pid = NAMESPACES[ns]
        pre = lambda: _setns_net(pid)  # noqa: E731 - runs in the forked child
    return subprocess.run(
        argv,
        check=False,
        preexec_fn=pre,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _sh(ns: str | None, *argv: str) -> None:
    proc = _run(ns, list(argv))
    if proc.returncode != 0:
        raise RuntimeError(f"{' '.join(argv)!r} in ns={ns}: {proc.stderr.strip()}")


def op_topology(req: dict) -> dict:
    _sh(None, "ip", "link", "set", "lo", "up")
    with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
        fh.write("1")
    for zone in req["zones"]:
        name = zone["name"]
        pid = _spawn_holder()
        NAMESPACES[name] = pid
        rif = zone["router_if"]
        # iproute2 7.x needs the explicit `name` keyword for veth pairs
        _sh(
            None,
            "ip",
            "link",
            "add",
            "name",
            rif,
            "type",
            "veth",
            "peer",
            "name",
            "eth0",
            "netns",
            str(pid),
        )
        _sh(None, "ip", "addr", "add", zone["router_addr"], "dev", rif)
        _sh(None, "ip", "link", "set", rif, "up")
        _sh(name, "ip", "link", "set", "lo", "up")
        _sh(name, "ip", "addr", "add", zone["ns_addr"], "dev", "eth0")
        _sh(name, "ip", "link", "set", "eth0", "up")
        _sh(name, "ip", "route", "add", "default", "via", zone["gw"])
    return {"ok": True}


def op_nft(req: dict) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as fh:
        fh.write(req["text"])
        path = fh.name
    try:
        proc = _run(None, ["nft", "-f", path])
    finally:
        os.unlink(path)
    if proc.returncode != 0:
        return {"ok": False, "err": proc.stderr.strip()}
    return {"ok": True}


def op_listen(req: dict) -> dict:
    ns = req.get("ns")
    ns_pid = NAMESPACES[ns] if ns is not None else None
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_r)
        try:
            if ns_pid is not None:
                _setns_net(ns_pid)
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((req.get("addr", "0.0.0.0"), req["port"]))
            srv.listen(8)
        except Exception:
            os._exit(1)
        os.write(ready_w, b"1")
        os.close(ready_w)
        echo_peer = bool(req.get("echo_peer"))
        while True:
            conn, peer = srv.accept()
            if echo_peer:
                with contextlib.suppress(OSError):
                    conn.sendall(peer[0].encode())
            conn.close()
    os.close(ready_w)
    ready = os.read(ready_r, 1)
    os.close(ready_r)
    if not ready:
        os.waitpid(pid, 0)
        return {
            "ok": False,
            "err": f"listener failed to bind :{req['port']} in ns={ns}",
        }
    CHILDREN.append(pid)
    return {"ok": True, "pid": pid}


def op_probe(req: dict) -> dict:
    ns = req.get("ns")
    ns_pid = NAMESPACES[ns] if ns is not None else None
    timeout = float(req.get("timeout", 1.5))
    reply_r, reply_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(reply_r)
        os.dup2(reply_w, 1)
        try:
            if ns_pid is not None:
                _setns_net(ns_pid)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((req["dst"], req["port"]))
            if req.get("read"):
                data = sock.recv(64)
                os.write(1, data)  # parent reads the reply from a pipe
            os._exit(0)
        except ConnectionRefusedError:
            os._exit(2)
        except TimeoutError:
            os._exit(3)
        except Exception:
            os._exit(4)
    os.close(reply_w)
    _, status = os.waitpid(pid, 0)
    reply = b""
    while True:
        chunk = os.read(reply_r, 64)
        if not chunk:
            break
        reply += chunk
    os.close(reply_r)
    code = os.waitstatus_to_exitcode(status)
    outcome = {0: "connected", 2: "refused", 3: "timeout"}.get(code, f"error({code})")
    return {"ok": True, "result": outcome, "reply": reply.decode() or None}


def op_run(req: dict) -> dict:
    proc = _run(req.get("ns"), req["argv"])
    return {"ok": True, "rc": proc.returncode, "out": proc.stdout, "err": proc.stderr}


def main() -> int:
    handlers = {
        "topology": op_topology,
        "nft": op_nft,
        "listen": op_listen,
        "probe": op_probe,
        "run": op_run,
    }
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        req = json.loads(line)
        if req["op"] == "quit":
            break
        try:
            resp = handlers[req["op"]](req)
        except Exception as exc:  # report, never die mid-session
            resp = {"ok": False, "err": f"{type(exc).__name__}: {exc}"}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
    for pid in CHILDREN:
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

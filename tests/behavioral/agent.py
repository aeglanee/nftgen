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
      "ns_addr", "gw", "router_addr6"?, "ns_addr6"?, "gw6"?}, …]}
                                       veths, addrs, routes, ip_forward=1
                                       (v6 keys optional; forwarding too)
  {"op": "nft", "text": "…"}           apply a ruleset in the router ns
  {"op": "listen", "ns": name|null, "port": N,
      "echo_peer": bool}               TCP accept-loop; echo_peer writes the
                                       accepted peer address back on the conn
  {"op": "probe", "ns": name|null, "dst": "a.b.c.d", "port": N,
      "timeout": secs, "read": bool}   -> connected | refused | timeout
                                       (read: also return the server's reply)
  {"op": "ping", "ns": name|null, "dst": addr, "timeout": secs}
                                       raw-socket ICMP/ICMPv6 echo (the ping
                                       binary needs /etc/protocols; raw
                                       sockets work as userns root)
                                       -> replied | timeout
  {"op": "send_tcp", "ns": name|null, "src", "dst", "dport",
      "flags": [...], "sport"?, "timeout"?}
                                       raw crafted TCP segment (arbitrary
                                       flags) -> replied | silent
  {"op": "nflog_capture", "group": N, "ns": name|null, "dst", "port",
      "timeout"?}                      bind NFLOG group N, trigger a probe to
                                       dst:port (expected to be dropped+logged),
                                       -> the captured log prefix (or null)
  {"op": "run", "ns": name|null, "argv": […]}       escape hatch / debugging
  {"op": "quit"}
"""

import contextlib
import ctypes
import json
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

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
    with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as fh:
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
        if zone.get("router_addr6"):
            _sh(None, "ip", "-6", "addr", "add", zone["router_addr6"], "dev", rif)
            _sh(name, "ip", "-6", "addr", "add", zone["ns_addr6"], "dev", "eth0")
            # DAD would leave the addresses tentative for a moment; wait it out
            _sh(name, "ip", "-6", "route", "add", "default", "via", zone["gw6"])
    if any(z.get("router_addr6") for z in req["zones"]):
        _wait_dad_settled(req["zones"])
    return {"ok": True}


def _wait_dad_settled(zones: list[dict], timeout: float = 5.0) -> None:
    """Block until no v6 address is still `tentative` (DAD in progress)."""
    deadline = time.time() + timeout
    targets = [(None, "r-" + z["name"]) for z in zones if z.get("router_addr6")]
    targets += [(z["name"], "eth0") for z in zones if z.get("ns_addr6")]
    while time.time() < deadline:
        if all(
            "tentative" not in _run(ns, ["ip", "-6", "addr", "show", "dev", dev]).stdout
            for ns, dev in targets
        ):
            return
        time.sleep(0.05)


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
            if req.get("src"):  # bind a specific source (must exist on an iface)
                sock.bind((req["src"], 0))
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


def _icmp_csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def op_ping(req: dict) -> dict:
    """Raw-socket echo request; the kernel checksums ICMPv6 for us."""
    ns = req.get("ns")
    ns_pid = NAMESPACES[ns] if ns is not None else None
    dst = req["dst"]
    timeout = float(req.get("timeout", 2.0))
    v6 = ":" in dst
    reply_r, reply_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(reply_r)
        os.dup2(reply_w, 1)  # fd 1 is the JSON protocol channel; never write to it
        try:
            if ns_pid is not None:
                _setns_net(ns_pid)
            ident = os.getpid() & 0xFFFF
            if v6:
                sock = socket.socket(
                    socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6
                )
                pkt = struct.pack("!BBHHH", 128, 0, 0, ident, 1)  # echo-request
            else:
                sock = socket.socket(
                    socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
                )
                hdr = struct.pack("!BBHHH", 8, 0, 0, ident, 1)
                pkt = struct.pack("!BBHHH", 8, 0, _icmp_csum(hdr), ident, 1)
            sock.settimeout(timeout)
            sock.sendto(pkt, (dst, 0))
            deadline = time.time() + timeout
            while time.time() < deadline:
                sock.settimeout(max(deadline - time.time(), 0.01))
                data, _ = sock.recvfrom(1024)
                # v4 replies carry the IP header; v6 sockets hand us ICMPv6
                icmp = data if v6 else data[(data[0] & 0x0F) * 4 :]
                echo_reply = 129 if v6 else 0
                if icmp[0] == echo_reply and struct.unpack("!H", icmp[4:6])[0] == ident:
                    os.write(1, b"replied")
                    os._exit(0)
            os._exit(3)
        except (TimeoutError, OSError):
            os._exit(3)
    os.close(reply_w)
    _, status = os.waitpid(pid, 0)
    got = os.read(reply_r, 16)
    os.close(reply_r)
    code = os.waitstatus_to_exitcode(status)
    if code == 0 and got == b"replied":
        return {"ok": True, "result": "replied"}
    return {"ok": True, "result": "timeout"}


_TCP_FLAG_BITS = {
    "fin": 0x01,
    "syn": 0x02,
    "rst": 0x04,
    "psh": 0x08,
    "ack": 0x10,
    "urg": 0x20,
}


def op_send_tcp(req: dict) -> dict:
    """Send one crafted TCP segment (arbitrary flags) and report whether the
    target replied. Used for tcp-flags scrub tests: a legit SYN draws a
    SYN-ACK or RST (a reply); a scrubbed segment draws silence.
    -> replied | silent
    """
    ns = req.get("ns")
    ns_pid = NAMESPACES[ns] if ns is not None else None
    src, dst = req["src"], req["dst"]
    dport = int(req["dport"])
    sport = int(req.get("sport", 54321))
    flags = 0
    for f in req.get("flags", ["syn"]):
        flags |= _TCP_FLAG_BITS[f]
    timeout = float(req.get("timeout", 1.5))
    reply_r, reply_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(reply_r)
        os.dup2(reply_w, 1)
        try:
            if ns_pid is not None:
                _setns_net(ns_pid)
            seq = 1000
            hdr = struct.pack(
                "!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 8192, 0, 0
            )
            pseudo = (
                socket.inet_aton(src)
                + socket.inet_aton(dst)
                + struct.pack("!BBH", 0, 6, len(hdr))
            )
            hdr = struct.pack(
                "!HHIIBBHHH",
                sport,
                dport,
                seq,
                0,
                5 << 4,
                flags,
                8192,
                _icmp_csum(pseudo + hdr),
                0,
            )
            send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            recv.settimeout(timeout)
            send.sendto(hdr, (dst, 0))
            deadline = time.time() + timeout
            while time.time() < deadline:
                recv.settimeout(max(deadline - time.time(), 0.01))
                data, addr = recv.recvfrom(2048)
                ihl = (data[0] & 0x0F) * 4
                tcp = data[ihl:]
                # a reply from dst:dport back to our sport
                if (
                    addr[0] == dst
                    and struct.unpack("!H", tcp[0:2])[0] == dport
                    and struct.unpack("!H", tcp[2:4])[0] == sport
                ):
                    os.write(1, b"replied")
                    os._exit(0)
            os._exit(3)
        except (TimeoutError, OSError):
            os._exit(3)
    os.close(reply_w)
    _, status = os.waitpid(pid, 0)
    got = os.read(reply_r, 16)
    os.close(reply_r)
    return {"ok": True, "result": "replied" if got == b"replied" else "silent"}


# NFLOG (nfnetlink_log) — subsystem 4, used by `log group N`.
_NFNL_SUBSYS_ULOG = 4
_NFULNL_MSG_PACKET = 0
_NFULNL_MSG_CONFIG = 1
_NFULA_PREFIX = 10  # the `log prefix` string attribute


def _nflog_bind(group: int):
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)  # NETLINK_NETFILTER
    s.bind((0, 0))
    nfgen = struct.pack(">BBH", socket.AF_INET, 0, group)  # family, version, res_id
    attr = struct.pack("HHB", 5, 1, 1) + b"\x00" * 3  # NFULA_CFG_CMD -> CMD_BIND
    payload = nfgen + attr
    mtype = (_NFNL_SUBSYS_ULOG << 8) | _NFULNL_MSG_CONFIG
    s.send(struct.pack("IHHII", 16 + len(payload), mtype, 1, 0, 0) + payload)
    return s


def _nflog_prefix(data: bytes) -> str | None:
    off = 20  # nlmsghdr(16) + nfgenmsg(4)
    while off + 4 <= len(data):
        alen, atype = struct.unpack("HH", data[off : off + 4])
        if alen < 4:
            break
        if (atype & 0x3FFF) == _NFULA_PREFIX:
            return data[off + 4 : off + alen].rstrip(b"\x00").decode(errors="replace")
        off += (alen + 3) & ~3
    return None


def op_nflog_capture(req: dict) -> dict:
    """Prove a dropped flow emits its log: bind the NFLOG group, trigger a
    probe that should be dropped+logged, return the captured log prefix."""
    group = int(req["group"])
    ns = req.get("ns")
    ns_pid = NAMESPACES[ns] if ns is not None else None
    timeout = float(req.get("timeout", 3.0))
    r, w = os.pipe()
    lpid = os.fork()
    if lpid == 0:  # listener: capture the first packet's prefix
        os.close(r)
        try:
            sk = _nflog_bind(group)
            sk.settimeout(timeout)
            while True:
                data = sk.recv(16384)
                mtype = struct.unpack("H", data[4:6])[0]
                if (mtype >> 8) == _NFNL_SUBSYS_ULOG and (
                    mtype & 0xFF
                ) == _NFULNL_MSG_PACKET:
                    os.write(w, (_nflog_prefix(data) or "").encode())
                    os._exit(0)
        except (TimeoutError, OSError):
            os._exit(0)
    os.close(w)
    time.sleep(0.3)  # let the listener bind before we trigger
    tpid = os.fork()
    if tpid == 0:  # trigger: a probe that gets dropped+logged
        try:
            if ns_pid is not None:
                _setns_net(ns_pid)
            sk = socket.socket()
            sk.settimeout(1.0)
            with contextlib.suppress(OSError):
                sk.connect((req["dst"], int(req["port"])))
        finally:
            os._exit(0)
    os.waitpid(tpid, 0)
    rlist, _, _ = select.select([r], [], [], timeout)
    prefix = (os.read(r, 256).decode() or None) if rlist else None
    os.close(r)
    with contextlib.suppress(OSError):
        os.kill(lpid, signal.SIGKILL)
        os.waitpid(lpid, 0)
    return {"ok": True, "prefix": prefix}


def op_run(req: dict) -> dict:
    proc = _run(req.get("ns"), req["argv"])
    return {"ok": True, "rc": proc.returncode, "out": proc.stdout, "err": proc.stderr}


def main() -> int:
    handlers = {
        "topology": op_topology,
        "nft": op_nft,
        "listen": op_listen,
        "probe": op_probe,
        "ping": op_ping,
        "send_tcp": op_send_tcp,
        "nflog_capture": op_nflog_capture,
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

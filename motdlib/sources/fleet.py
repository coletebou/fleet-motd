"""Hub ⇄ peer exchange over the existing SSH aliases (no new service or port).

One connection per peer per cycle: the hub writes its bundle (global source
records + the fleet table) to the peer's ~/.cache/motd/v2/hub/bundle.json on
stdin, and the same command prints the peer's own snapshot.json back. Peers
therefore render SaaS/AI panels and the fleet table without holding a single
API call of their own; if the hub goes quiet they fall back after a while
(see registry.Source.fallback).
"""
from __future__ import annotations

import json

from .. import core
from ..registry import SOURCES, source, src_path

REMOTE = ("umask 077; d=$HOME/.cache/motd/v2; mkdir -p \"$d/hub\" && "
          "cat > \"$d/hub/.bundle.tmp\" && mv -f \"$d/hub/.bundle.tmp\" \"$d/hub/bundle.json\"; "
          "cat \"$d/snapshot.json\" 2>/dev/null || true")


def build_bundle(host, peers_prev: dict) -> dict:
    srcs = {}
    for name, s in SOURCES.items():
        if s.scope == "global":
            rec = core.read_json(src_path(name))
            if rec:
                srcs[name] = rec
    hosts = dict(peers_prev)
    own = core.read_json(core.SNAPSHOT_PATH)
    if own:
        hosts[host.name] = {"ok": True, "seen": own.get("ts", core.now()), "snap": own}
    return {"v": 2, "from": host.name, "ts": core.now(), "sources": srcs, "fleet": {"hosts": hosts}}


def _exchange(peer: str, payload: bytes) -> dict:
    ssh = core.which("ssh") or "/usr/bin/ssh"
    argv = [ssh, "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2", "-o", "LogLevel=ERROR", "--", peer, REMOTE]
    import subprocess
    import time
    t0 = time.monotonic()
    try:
        p = subprocess.run(argv, input=payload, capture_output=True, timeout=25)
        ms = int((time.monotonic() - t0) * 1000)
    except subprocess.TimeoutExpired:
        return {"ok": False, "unreachable": True, "error": "ssh timeout", "ms": 25000}
    if p.returncode != 0:  # 255 = ssh itself failed; anything else = the remote shell did
        err = p.stderr.decode("utf-8", "replace").strip().splitlines()
        return {"ok": False, "unreachable": p.returncode == 255, "ms": ms,
                "error": (err[-1] if err else "ssh rc %d" % p.returncode)[:160]}
    try:
        snap = json.loads(p.stdout.decode("utf-8", "replace") or "null")
    except ValueError:
        snap = None
    return {"ok": True, "pushed": True, "snap": snap, "ms": ms,
            "error": None if snap else "peer has no snapshot yet"}


@source("fleet", ttl=240, timeout=30, hosts=("#hub",))
def fleet(ctx):
    """Exchange bundle/snapshot with every peer (hub only)."""
    prev_hosts = (ctx.prev or {}).get("hosts") or {}
    carry = {k: v for k, v in prev_hosts.items() if k != ctx.host.name}
    payload = json.dumps(build_bundle(ctx.host, carry), separators=(",", ":")).encode()
    from concurrent.futures import ThreadPoolExecutor
    peers = ctx.host.peers
    with ThreadPoolExecutor(max_workers=max(1, len(peers))) as ex:
        results = dict(zip(peers, ex.map(lambda p: _exchange(p, payload), peers)))
    out, alerts = {}, []
    for peer, res in results.items():
        old = prev_hosts.get(peer) or {}
        if res.get("snap") and res["snap"].get("host") not in (None, peer):
            alerts.append({"sev": "warn", "msg": "peer %s reports itself as %s: name it %s in peers, or set MOTD_MACHINE=%s there" % (
                peer, res["snap"].get("host"), res["snap"].get("host"), peer)})
        if res.get("snap"):
            out[peer] = {"ok": True, "seen": core.now(), "snap": res["snap"], "ms": res["ms"], "fails": 0}
        else:
            fails = (int(old.get("fails", 0)) + 1) if res.get("unreachable") else 0
            out[peer] = {"ok": bool(res.get("ok")), "seen": old.get("seen", 0), "snap": old.get("snap"),
                         "error": res.get("error"), "ms": res.get("ms"), "fails": fails}
            if fails >= 3:
                alerts.append({"sev": "warn", "msg": "%s unreachable over ssh ×%d (%s)" % (peer, fails, res.get("error"))})
    data = {"hosts": out, "bytes": len(payload)}
    if alerts:
        data["alerts"] = alerts
    return data

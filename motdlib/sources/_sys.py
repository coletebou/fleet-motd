"""Shared helpers for host-ops sources: loopback endpoint checks, systemd runs."""
from __future__ import annotations

import json

from .. import core, live


def check_endpoints(items, timeout: float = 3.0) -> list:
    """items: [(label, url, extract(body)->str | None)] probed in parallel."""
    if not items:
        return []
    from concurrent.futures import ThreadPoolExecutor

    def one(it):
        label, url, extract = it
        try:
            r = core.http(url, timeout=timeout, headers={"Accept": "application/json, */*"})
            info = ""
            if extract and r.ok and isinstance(r.body, dict):
                try:
                    info = extract(r.body) or ""
                except Exception:  # noqa: BLE001
                    info = ""
            return {"label": label, "status": r.status, "ms": r.ms, "ok": 200 <= r.status < 300, "info": info}
        except Exception as e:  # noqa: BLE001
            return {"label": label, "status": 0, "ms": 0, "ok": False, "info": type(e).__name__}
    with ThreadPoolExecutor(max_workers=len(items)) as ex:
        return list(ex.map(one, items))


def flap_guard(rows, prev_rows) -> list:
    """Rows that failed this run AND the previous one. A deploy restarts a service
    briefly; one refused connection is not an outage."""
    was_down = {r["label"] for r in prev_rows or [] if not r.get("ok")}
    return [r for r in rows if not r["ok"] and r["label"] in was_down]


def endpoint_alerts(rows, host_label: str) -> list:
    return [{"sev": "crit", "msg": "%s health %s on %s" % (r["label"], r["status"] or r["info"], host_label)}
            for r in rows if not r["ok"]]


def unit_runs(units) -> dict:
    """{unit: {result, exit, ended, active, last, next}}; times are epoch secs."""
    names = [u if "." in u else u + ".service" for u in units]
    rc, out, _ = core.run(["systemctl", "show", "--timestamp=unix", "--no-pager", "-p",
                           "Id,Result,ExecMainStatus,ExecMainExitTimestamp,ActiveState"] + names, 4)
    res = {}
    for cur in live.parse_show(out):
        if not cur.get("Id"):
            continue
        ts = cur.get("ExecMainExitTimestamp", "").lstrip("@")
        res[cur["Id"].rsplit(".", 1)[0]] = {
            "result": cur.get("Result"), "exit": cur.get("ExecMainStatus"),
            "ended": int(ts) if ts.isdigit() else 0, "active": cur.get("ActiveState")}
    rc, out, _ = core.run(["systemctl", "list-timers", "--all", "--output=json", "--no-pager"], 4)
    try:
        timers = json.loads(out) if rc == 0 else []
    except ValueError:
        timers = []
    for t in timers:
        u = (t.get("activates") or t.get("unit", "")).rsplit(".", 1)[0]
        if u in res:
            res[u]["last"] = int((t.get("last") or 0) / 1e6)
            res[u]["next"] = int((t.get("next") or 0) / 1e6)
    return res


def tail(path: str, nbytes: int = 65536) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - nbytes))
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def dotenv(path: str) -> dict:
    """KEY=VALUE lines of a service env file, read in memory (values never logged)."""
    out = {}
    for line in core.read_text(path, 65536).splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            out[(k[7:] if k.startswith("export ") else k).strip()] = v.strip().strip("'\"")
    return out

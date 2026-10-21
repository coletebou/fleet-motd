"""This host's compact status, written after every collector run.

The hub pulls it from each peer (sources/fleet.py) to build the fleet table, so
keep it small: vitals, agent counts, and top alerts.
"""
from __future__ import annotations

import os

from . import alerts, core, live, registry


def build(host, cache=None) -> dict:
    cache = cache or registry.Cache()
    lv = alerts.probe_all(host)
    v = lv["vitals"]
    pr = cache.data("procs") or {}
    found = alerts.gather(host, cache, lv)
    found = alerts.own(found)
    snap = {
        "v": 2, "host": host.name, "label": host.label, "ts": core.now(), "os": v.get("os"),
        "uptime": v.get("uptime"), "load": round(v["load"][0], 2), "cores": v["cores"],
        "mem": round(core.pct(v["mem"]["used"], v["mem"]["total"])),
        "swap": round(core.pct(v["swap"]["used"], v["swap"]["total"])) if v["swap"]["total"] else 0,
        "disks": [{"m": d["mount"], "p": round(d["pct"])} for d in v["disks"]],
        "agents": {"claude": pr.get("claude", 0), "codex": (pr.get("codex") or {}).get("total", 0)},
        "tmux": lv.get("tmux") or live.tmux(),
        "alerts": [{"sev": a["sev"], "msg": a["msg"]} for a in found[:8]],
        "counts": {"crit": sum(1 for a in found if a["sev"] == "crit"),
                   "warn": sum(1 for a in found if a["sev"] == "warn")},
    }
    return snap


HISTORY_LEN = 48          # at the 5-minute timer: the last four hours
HISTORY_MIN_GAP = 120     # a burst of manual collects must not flood the ring


def history_path() -> str:
    return os.path.join(core.STATE_DIR, "history.json")


def record_history(snap, path=None) -> dict:
    """Append this run's cpu (load % of cores), mem and fullest-disk % to a small ring."""
    path = path or history_path()
    h = core.read_json(path) or {}
    ts = h.get("ts") or []
    if ts and snap["ts"] - ts[-1] < HISTORY_MIN_GAP:
        return h
    disk = max((d.get("p", 0) for d in snap.get("disks") or []), default=0)
    sample = {"ts": snap["ts"], "cpu": round(100.0 * snap["load"] / max(1, snap["cores"])), "mem": snap["mem"], "disk": disk}
    for k, v in sample.items():
        h[k] = ((h.get(k) or []) + [v])[-HISTORY_LEN:]
    core.write_json_atomic(path, h)
    return h


def write(host) -> dict:
    snap = build(host)
    core.write_json_atomic(core.SNAPSHOT_PATH, snap)
    try:
        record_history(snap)
    except (OSError, KeyError, TypeError, ValueError):
        pass
    return snap

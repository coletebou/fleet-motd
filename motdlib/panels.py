"""Panel builders. Each takes the render context and returns a Panel or None.

Builders read caches through ctx.cache, never the network. A builder whose
data is missing returns a short "waiting for data" line rather than nothing,
so a fresh box shows what will appear once the collector has run.
"""
from __future__ import annotations

import os

from . import core, hosts, theme as T
from .render import Panel

BUILDERS = {}
SEP = T.dim(" · ")


def builder(key):
    def deco(fn):
        BUILDERS[key] = fn
        return fn
    return deco


def resolve(key):
    """A builder by panel key; `checks:<group>` builds the checks panel for that group."""
    if key in BUILDERS:
        return BUILDERS[key]
    if key.startswith("checks:") and len(key) > 7:
        from .panels_checks import group_builder
        return group_builder(key[7:])
    return None


def kv(label: str, value: str, w: int = 9) -> str:
    return T.dim(label.ljust(w)) + value


def fnum(x: float) -> str:
    if x < 10:
        return "%.2f" % x
    if x < 100:
        return "%.1f" % x
    return "%.0f" % x


def _alert_key(msg: str) -> str:
    from .alerts import key
    return key(msg)


def visit(host, login: bool, alerts=()):
    """Previous login time; tags alerts that appeared since then as new.
    Only a login shell moves the bookmark; `motd` by hand just reads it."""
    path = os.path.join(core.STATE_DIR, "last_visit.json")
    prev = core.read_json(path) or {}
    seen = set(prev.get("alerts") or [])
    if prev.get("ts"):
        for a in alerts:
            a["new"] = _alert_key(a["msg"]) not in seen
    if login:
        try:
            core.ensure_dirs()
            core.write_json_atomic(path, {"ts": core.now(), "alerts": sorted({_alert_key(a["msg"]) for a in alerts})})
        except OSError:
            pass
    return prev.get("ts")


DISK_LABEL = {"/": "disk", "C:": "C:"}


def _failed_units(x) -> list:
    return [u for u in x.lv.get("failed") or [] if not u.endswith("motd-news.service")]


@builder("system")
def p_system(x):
    v, cw = x.v, x.cw
    bw = max(8, min(28, cw - 1 - 6 - 24))
    rows = []

    def meter(label, p, bar, value, warn=85, crit=92):
        rows.append(T.dim(label.ljust(6)) + bar + "  " + T.sev("%3d%%" % round(p), T.level_for(p, warn, crit))
                    + "  " + value)
    load, cores = v["load"][0], v["cores"]
    lp = 100.0 * load / cores
    rows.append(T.dim("cpu".ljust(6)) + T.bar(lp, bw, 70, 100) + "  " +
                T.sev(fnum(load), T.level_for(lp, 70, 100)) + T.dim(" load · %d cores" % cores))
    m = v["mem"]
    mp = core.pct(m["used"], m["total"])
    meter("mem", mp, T.bar(mp, bw, 80, 92), T.dim("%s/%s" % (core.human_bytes(m["used"]), core.human_bytes(m["total"]))))
    s = v["swap"]
    if s["total"]:
        sp = core.pct(s["used"], s["total"])
        meter("swap", sp, T.bar(sp, bw, 60, 85), T.dim("%s/%s" % (core.human_bytes(s["used"]), core.human_bytes(s["total"]))), 80, 95)
    for d in v["disks"]:
        meter(DISK_LABEL.get(d["mount"], os.path.basename(d["mount"])[:5]), d["pct"], T.bar(d["pct"], bw, 85, 92),
              T.dim("%s/%s" % (core.human_bytes(d["used"]), core.human_bytes(d["total"]))))
    for m in v.get("stalled") or []:
        rows.append(T.dim("disk".ljust(6)) + T.c("✖ %s not responding" % m, "amber"))
    procs = v.get("procs") or (x.cache.data("procs") or {}).get("total")
    tail = []
    if procs:
        tail.append("%s procs" % procs)
    tail.append("up " + core.human_age(v.get("uptime", 0)))
    if not core.IS_MAC:
        failed = _failed_units(x)
        tail.append(T.c("%d failed units" % len(failed), "red") if failed else T.c("0 failed units", "green"))
    rows.append(SEP.join(tail))
    hist = core.read_json(os.path.join(core.STATE_DIR, "history.json")) or {}
    if len(hist.get("ts") or []) >= 3:
        sw = max(4, min(24, (cw - 1 - 31) // 3))  # 31 = labels, spaces and the span
        span = core.human_age(core.now() - hist["ts"][-min(sw, len(hist["ts"]))])
        rows.append(T.dim("trend ") + T.dim("cpu ") + T.spark(hist.get("cpu") or [], 70, 100, sw) + " " +
                    T.dim("mem ") + T.spark(hist.get("mem") or [], 80, 92, sw) + " " +
                    T.dim("disk ") + T.spark(hist.get("disk") or [], 85, 92, sw) + T.dim(" " + span))
    lvl = T.worst(*[T.level_for(d["pct"], 85, 92) for d in v["disks"]])
    return Panel("system", "SYSTEM", rows, lvl)


def cells(items, cw, minw=14) -> list:
    """Lay (text) cells out in as many columns as fit."""
    if not items:
        return []
    w = min(cw, max(minw, max(T.width(i) for i in items) + 2))
    per = max(1, cw // w)
    return ["".join(T.pad(i, w) for i in items[r:r + per]).rstrip() for r in range(0, len(items), per)]


@builder("services")
def p_services(x):
    items, lvl = [], "ok"
    for label, l, detail in (x.lv.get("units") or []) + (x.lv.get("launchd") or []):
        items.append(T.dot(l) + " " + (T.c(label, "fg") if l == "ok" else T.sev(label, l)) +
                     ((" " + T.dim(detail)) if detail else ""))
        lvl = T.worst(lvl, l)
    for port, label, is_open in x.lv.get("ports") or []:
        items.append(T.dot("ok" if is_open else "crit" if x.host.server else "unknown") + " " +
                     (label if is_open else T.dim(label)) + T.dim(" :%d" % port))
        if x.host.server and not is_open:
            lvl = T.worst(lvl, "crit")
    if core.IS_MAC:
        ts = x.cache.data("tailscale") or {}
        if ts.get("installed"):
            ok = ts.get("state") == "Running"
            down = "crit"
            items.append(T.dot("ok" if ok else down) + " tailscale" + ("" if ok else T.dim(" " + str(ts.get("state")))))
    rows = cells(items, x.cw - 1, 15)
    failed = _failed_units(x)
    for u in failed[:4]:
        rows.append(T.c("✖ ", "red") + T.c(u, "red") + T.dim(" failed"))
        lvl = "crit"
    if len(failed) > 4:
        rows.append(T.dim("… %d more failed units" % (len(failed) - 4)))
    if not rows:
        return None
    return Panel("services", "SERVICES", rows, lvl)


@builder("agents")
def p_agents(x):
    pr = x.cache.data("procs") or {}
    rows = []
    if pr:
        cx = pr.get("codex") or {}
        parts = ["%d claude" % pr.get("claude", 0)]
        if cx.get("total"):
            sub = ", ".join("%d %s" % (n, k) for k, n in sorted(cx.items()) if k != "total")
            parts.append("%d codex" % cx["total"] + T.dim(" (%s)" % sub))
        rows.append(kv("procs", SEP.join(parts)))
    tm = x.lv.get("tmux") or {"sessions": 0, "windows": 0, "attached": 0}
    rows.append(kv("tmux", "%d sessions" % tm["sessions"] + SEP + "%d windows" % tm["windows"] +
                   (T.dim(" (%d attached)" % tm["attached"]) if tm["attached"] else "")))
    if pr:
        pw = pr.get("playwright") or {}
        bits = ["%d playwright-mcp" % pw.get("total", 0)]
        if pw.get("orphans"):
            bits.append(T.c("%d orphaned" % pw["orphans"], "amber"))
        bits.append(("%d zombies" % pr.get("zombies", 0)) if pr.get("zombies") else T.dim("0 zombies"))
        rows.append(kv("hygiene", SEP.join(bits)))
        top = pr.get("top") or []
        if top:
            rows.append(kv("top mem", SEP.join("%s %s" % (t["name"], T.dim(core.human_bytes(t["rss"]))) for t in top[:3])))
    return Panel("agents", "AGENTS", rows, "ok", x.stale_note("procs", 6, 900))



def fleet_table(x) -> dict:
    """{host: {"snap", "seen", "ok"}} incl. this host from live probes."""
    from .alerts import own as own_alerts
    mine = own_alerts(x.alerts)  # count like the peers' snapshots do: this host's alerts only
    table = dict(x.cache.fleet_hosts(x.host.hub))
    own = dict(core.read_json(core.SNAPSHOT_PATH) or {})
    own.update({"host": x.host.name, "label": x.host.label, "ts": core.now(),
                "load": round(x.v["load"][0], 2), "cores": x.v["cores"],
                "mem": round(core.pct(x.v["mem"]["used"], x.v["mem"]["total"])),
                "disks": [{"m": d["mount"], "p": round(d["pct"])} for d in x.v["disks"]],
                "counts": {"crit": sum(1 for a in mine if a["sev"] == "crit"),
                            "warn": sum(1 for a in mine if a["sev"] == "warn")}})
    table[x.host.name] = {"ok": True, "seen": core.now(), "snap": own}
    return table


@builder("fleet")
def p_fleet(x):
    table = fleet_table(x)
    ts_rows = {r["name"]: r for r in (x.cache.data("tailscale") or {}).get("rows") or []}
    order = hosts.fleet_order()
    names = [n for n in order if n in table] + sorted(n for n in table if n not in order)
    if len(names) <= 1 and not x.host.hub:
        names += [n for n in order if n not in names and n in ts_rows]
    hdr = T.dim("%-11s %5s %4s %4s  %-9s %-8s %s" % ("host", "load", "mem", "disk", "agents", "alerts", "seen"))
    rows, lvl = [" " + hdr], "ok"
    for n in names:
        rec = table.get(n) or {}
        snap = rec.get("snap") or {}
        age = core.now() - (snap.get("ts") or rec.get("seen") or 0)
        tsr = ts_rows.get(n) or {}
        online = None  # None: tailscale has no row for this host
        if tsr:
            # Tailscale's Online bit flaps during control reconnects; trust "offline" only
            # when the node has also not been seen for 10 minutes.
            online = tsr.get("online") or core.now() - (tsr.get("seen") or 0) < 600
        label = hosts.short(n)[:11]
        if not snap or age > 1800:
            state = "crit" if online is False else "unknown"
            err = rec.get("error") or ""
            if online is False:
                why = "offline"
            elif not online:
                why = "no data"
            elif not snap and rec.get("ok"):
                why = "online · motd not installed yet"
            else:
                why = "online · " + (err[:40] or "no snapshot")
            rows.append(T.dot(state) + " " + T.pad(label, 10) + " " + T.dim(why + ((" · " + core.human_age(age) + " ago") if snap else "")))
            lvl = T.worst(lvl, "warn" if state == "crit" else "ok")
            continue
        cnt = snap.get("counts") or {}
        nc, nw = cnt.get("crit", 0), cnt.get("warn", 0)
        if nc:
            state = "crit"
        elif nw:
            state = "warn"
        else:
            state = "ok"
        lvl = T.worst(lvl, state)
        load, cores = snap.get("load", 0), snap.get("cores") or 1
        disk = max((d.get("p", 0) for d in snap.get("disks") or []), default=0)
        ag = snap.get("agents") or {}
        agents = "%dcc %dcx" % (ag.get("claude", 0), ag.get("codex", 0))
        badges = []
        if nc:
            badges.append(T.c("%d✖" % nc, "red"))
        if nw:
            badges.append(T.c("%d▲" % nw, "amber"))
        rows.append(T.dot(state) + " " + T.pad(T.c(label, "fg"), 10) + " " +
                    T.pad(T.sev(fnum(load), T.level_for(100 * load / cores, 70, 100)), 5, ">") + " " +
                    T.pad(T.sev("%d%%" % snap.get("mem", 0), T.level_for(snap.get("mem", 0), 85, 95)), 4, ">") + " " +
                    T.pad(T.sev("%d%%" % disk, T.level_for(disk, 85, 92)), 4, ">") + "  " +
                    T.pad(agents, 9) + " " + T.pad(" ".join(badges) or T.c("ok", "green"), 8) + " " +
                    T.dim("now" if age < 90 else core.human_age(age)))
    if len(rows) == 1:
        return None
    if x.host.hub:
        note = x.stale_note("fleet", 4, 900)
    elif x.cache.bundle:
        note = core.human_age(core.now() - (x.cache.bundle.get("ts") or 0))
    else:
        note = "no hub bundle"
    return Panel("fleet", "FLEET", rows, lvl, note)


def repo_rows(r, label: str, untracked: int = 0) -> list:
    bits = [(T.c("%d modified" % r["dirty"], "amber") if r["dirty"] else T.c("clean", "green"))]
    if untracked:
        bits.append(T.c("%d untracked" % untracked, "slate"))
    if r["ahead"]:
        bits.append(T.c("↑%d" % r["ahead"], "sky"))
    if r["behind"]:
        bits.append(T.c("↓%d" % r["behind"], "rose"))
    if r.get("last"):
        bits.append(T.dim("last commit %s" % core.human_age(core.now() - r["last"], " ago")))
    return [T.c(label, "fg") + T.dim(" @ ") + T.c(r["branch"], "violet") + "  " + SEP.join(bits)]


@builder("repo")
def p_repo(x):
    rows = []
    untracked = (x.cache.data("repos") or {}).get("repos") or {}
    for r in x.lv.get("repos") or []:
        rows += repo_rows(r, r["path"].replace(core.HOME, "~", 1), (untracked.get(r["path"]) or {}).get("untracked", 0))
    return Panel("repo", "REPOS", rows) if rows else None

from . import panels_checks, panels_devops, panels_more  # noqa: E402,F401 — registers the remaining builders

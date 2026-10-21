"""One ranked alert list from live probes, source records, and fleet peers."""
from __future__ import annotations

import re

from . import core, live, registry

# Units that fail by design or are pure noise on these boxes.
IGNORE_FAILED = {"motd-news.service"}
SEV_RANK = {"crit": 0, "warn": 1, "info": 2}
# (glyph, color) per severity: the login attention strip and `motd alerts`.
GLYPH = {"crit": ("✖", "red"), "warn": ("▲", "amber"), "info": ("·", "sky")}


def probe_all(host, vitals=None, repos=()) -> dict:
    """Every live probe the renderer and snapshot share, run once, in parallel."""
    jobs = {"units": lambda: live.units(host), "failed": live.failed_units,
            "launchd": lambda: live.launchd(host), "tmux": live.tmux}
    if host.ports:
        jobs["ports"] = lambda: live.ports(host.ports)
    if not vitals:
        jobs["vitals"] = lambda: live.vitals(host)
    for p in repos:
        jobs["repo:" + p] = (lambda p=p: live.repo(p))
    lv = core.parallel(jobs)
    lv["vitals"] = vitals or lv.get("vitals") or live.vitals(host, disks=False)
    found = [lv.pop("repo:" + p, None) for p in repos]
    lv["repos"] = [r for r in found if r]
    return lv


_MEASURE = re.compile(r"(?<![A-Za-z0-9_\-./:@#!])\d+(\.\d+)?")


def key(msg: str) -> str:
    """An alert's identity across runs: measurements folded ('disk / 91%' and '92%' are one
    alert) while numbers inside names stay (web-01 and web-02, api1, #10 are different)."""
    return _MEASURE.sub("#", msg.replace(" (stale)", ""))


def own(found) -> list:
    """This host's own alerts: live probes plus host-local sources. Excludes peer
    alerts imported from the fleet table and fleet-wide (global-source) alerts."""
    return [a for a in found if a.get("src") == "live" or
            (a.get("src") in registry.SOURCES and registry.SOURCES[a["src"]].scope == "local")]


def gather(host, cache, lv) -> list:
    if not isinstance(lv, dict) or "vitals" not in lv:
        lv = probe_all(host, lv)
    v = lv["vitals"]
    out = []

    def add(sev, msg, src="live"):
        out.append({"sev": sev, "msg": msg, "src": src})

    for d in v.get("disks", []):
        p = d["pct"]
        if p >= 92:
            add("crit", "disk %s %d%% full on %s" % (d["mount"], p, host.label))
        elif p >= 85:
            add("warn", "disk %s %d%% on %s" % (d["mount"], p, host.label))
    for m in v.get("stalled") or []:
        add("warn", "mount %s not responding on %s" % (m, host.label))
    memp = core.pct(v["mem"]["used"], v["mem"]["total"])
    if memp >= 92:
        add("warn", "memory %d%% on %s" % (memp, host.label))
    if v["swap"]["total"]:
        sw = core.pct(v["swap"]["used"], v["swap"]["total"])
        if sw >= 95:
            add("crit", "swap %d%% on %s" % (sw, host.label))
        elif sw >= 80:
            add("warn", "swap %d%% on %s" % (sw, host.label))
    load, cores = v["load"][0], v["cores"]
    if load >= 2 * cores:
        add("crit", "load %.1f on %d cores (%s)" % (load, cores, host.label))
    elif load >= cores:
        add("warn", "load %.1f on %d cores (%s)" % (load, cores, host.label))
    for u in lv.get("failed") or []:
        if u.split(":", 1)[-1] not in IGNORE_FAILED:
            add("crit", "%s failed on %s" % (u, host.label))
    if host.server:  # a configured listener that stopped listening; on a dev box a closed port is a choice
        for port, label, is_open in lv.get("ports") or []:
            if not is_open:
                add("crit", "%s not listening on :%d on %s" % (label, port, host.label))
    failed_set = {u.split(":", 1)[-1].rsplit(".", 1)[0] for u in lv.get("failed") or []}
    # Profile labels are short ("web" for myapp-web): match the cell's units, not its label.
    label_units = {}
    for unit, label, _scope in host.units:
        label_units.setdefault(label, set()).add(unit)
    for label, lvl, detail in lv.get("units") or []:
        if lvl != "ok" and not (label_units.get(label, {label}) & failed_set):
            add(lvl, "%s %s on %s" % (label, detail or "down", host.label))
    for label, lvl, detail in lv.get("launchd") or []:
        if lvl != "ok":
            add("warn", "launchd %s %s" % (label, detail))

    from . import sources  # noqa: F401 — registers sources so applicability is known
    for name, src in registry.SOURCES.items():
        if not registry.serves(src, host) or (src.scope != "global" and not registry.applies(src, host)):
            continue
        d = cache.data(name)
        if isinstance(d, dict):
            stale = cache.age(name) > max(6 * src.ttl, 3600)
            for a in d.get("alerts") or []:
                msg = a.get("msg", "")
                add(a.get("sev", "warn"), msg + (" (stale)" if stale else ""), name)

    # Peers' critical alerts on whichever host has the fleet table.
    for peer, rec in cache.fleet_hosts(host.hub).items():
        snap = (rec or {}).get("snap") or {}
        if peer == host.name or core.now() - snap.get("ts", 0) > 1800:
            continue
        label = snap.get("label", peer)
        for a in snap.get("alerts") or []:
            if a.get("sev") != "crit":
                continue
            # Name the peer unless its alert text already does ("disk / 93% on server").
            msg = a["msg"] if label in a.get("msg", "") else "%s: %s" % (label, a["msg"])
            add("crit", msg, "peer")  # not "fleet": that is the hub source's own name

    seen, uniq = set(), []
    for a in sorted(out, key=lambda a: SEV_RANK.get(a["sev"], 3)):
        key = a["msg"].replace(" (stale)", "")
        if key not in seen:
            seen.add(key)
            uniq.append(a)
    return uniq

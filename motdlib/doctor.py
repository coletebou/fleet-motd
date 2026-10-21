"""`motd doctor`: is every source fresh, and if not, why."""
from __future__ import annotations

import os

from . import core, registry, theme as T
from .collect import is_due


def _timer_state() -> str:
    if core.IS_MAC:
        rc, out, _ = core.run(["/bin/launchctl", "list", "com.motd-collect"], 2)
        if rc != 0:
            return T.c("launchd agent com.motd-collect not loaded (see deploy/)", "amber")
        m = [l for l in out.splitlines() if "LastExitStatus" in l]
        return T.c("launchd com.motd-collect loaded", "green") + (T.dim(" · " + m[0].strip().rstrip(";")) if m else "")
    rc, out, _ = core.run(["systemctl", "--user", "show", "motd-collect.timer", "-p", "ActiveState,NextElapseUSecRealtime,LastTriggerUSec"], 3)
    props = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    if props.get("ActiveState") != "active":
        return T.c("systemd motd-collect.timer %s (see deploy/)" % (props.get("ActiveState") or "missing"), "amber")
    return T.c("systemd motd-collect.timer active", "green") + T.dim(" · last %s" % props.get("LastTriggerUSec", "?"))


def run(host, cache) -> int:
    now = core.now()
    print(T.c("motd doctor", "gold", bold=True) + T.dim("  ·  %s%s" % (host.name, " · hub" if host.hub else "")))
    print(T.dim("cache ") + core.CACHE_DIR + T.dim("  ·  color ") + T.MODE)
    print(_timer_state())
    if not host.hub:
        b = cache.bundle
        print((T.dim("hub bundle from %s, %s old" % (b.get("from"), core.human_age(now - b.get("ts", 0)))))
              if b else T.c("no hub bundle yet (global panels need the hub or local fallback)", "amber"))
    print()
    print(T.dim("%-14s %-6s %6s %8s  %-5s %7s  %s" % ("source", "scope", "ttl", "age", "state", "ms", "note")))
    env = None
    for name in sorted(registry.SOURCES):
        s = registry.SOURCES[name]
        if not registry.applies(s, host):
            continue
        local = core.read_json(registry.src_path(name))
        rec = cache.rec(name)
        origin = "hub" if rec is not None and rec != local else "local"
        age = now - rec.get("ts", 0) if rec else None
        if rec is None:
            state, color = "none", "dim"
        elif rec.get("ok"):
            state, color = "ok", "green"
        elif rec.get("skip"):
            state, color = "skip", "slate"
        else:
            state, color = "FAIL", "red"
        note = (rec or {}).get("error") or ""
        ms = (rec or {}).get("ms") or 0
        if not note and origin == "local" and ms > s.timeout * 1000:
            note = "slow: %.1fs > %ss budget" % (ms / 1000.0, s.timeout)
        elif not note:
            note = s.desc
        if (s.needs or s.needs_any) and state != "ok":
            env = env or core.secrets()
            miss = registry.missing_env(s, env)
            if miss:
                note = "missing " + ", ".join(miss)
        due = is_due(s, host, now, cache)
        print("%-14s %-6s %6s %8s  %s %7s  %s" % (
            name, s.scope if origin == "local" else "hub", core.human_age(s.ttl),
            core.human_age(age) if age is not None else "—", T.pad(T.c(state, color), 5),
            (rec or {}).get("ms", "") if origin == "local" else "", T.dim(note[:90]) + (T.c(" due", "sky") if due else "")))
    targets = (core.config().get("notify") or {}).get("targets") or []
    if targets:
        st = core.read_json(os.path.join(core.STATE_DIR, "notify.json")) or {}
        print()
        line = "notify: %d target(s) · %d alert(s) tracked" % (len(targets), len(st.get("alerts") or {}))
        if st.get("ts"):
            line += " · last send %s ago" % core.human_age(now - st["ts"])
        print(T.dim(line) + ((" " + T.c("errors: " + "; ".join(st["errors"]), "amber")) if st.get("errors") else ""))
    if os.path.exists(core.LOG_PATH):
        print()
        print(T.dim("last collector runs:"))
        for line in core.read_text(core.LOG_PATH).splitlines()[-4:]:
            print("  " + T.dim(line[:200]))
    return 0

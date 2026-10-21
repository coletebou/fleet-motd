"""Push new alerts to ntfy, Slack, Discord or any webhook, from the collector.

    "notify": {"targets": [{"type": "ntfy", "url": "https://ntfy.sh/${NTFY_TOPIC}"},
                           {"type": "slack", "url": "${SLACK_WEBHOOK_URL}"}],
               "min_sev": "crit", "repeat_after": 21600, "resolved": true}

After each collector run the host compares its current alerts with what it last
sent (state/notify.json): new ones go out in one batched message per target,
an alert still firing after `repeat_after` seconds goes out again, and one that
cleared sends a "resolved" line when `resolved` is on. The hub sends everything
it sees (its own, fleet-wide and peers' critical alerts) and a peer stays quiet
while its hub is alive, speaking for itself when the hub goes quiet; "sender":
"each" makes every host send its own instead. One machine owns each alert. ${VAR} in a url expands from the collector env,
so webhook secrets stay in ~/.config/motd/env.
"""
from __future__ import annotations

import os
import re

from . import core

SEV_RANK = {"info": 0, "warn": 1, "crit": 2}
TYPES = ("ntfy", "slack", "discord", "webhook")
STATE = "notify.json"


def key(msg: str) -> str:
    from .alerts import key as alert_key
    return alert_key(msg)


def _expand(text, env) -> str:
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", lambda m: env.get(m.group(1), ""), str(text or ""))


def plan(current, state, now, min_sev="crit", repeat_after=21600, resolved=True):
    """(events, new_state). events are dicts {kind: new|repeat|resolved, sev, msg}."""
    floor = SEV_RANK.get(min_sev, 2)
    cur = {}
    for a in current:
        if SEV_RANK.get(a.get("sev"), 0) >= floor:
            cur.setdefault(key(a["msg"]), a)
    events, out = [], {}
    for k, a in cur.items():
        old = state.get(k)
        if old is None:
            events.append({"kind": "new", "sev": a["sev"], "msg": a["msg"]})
            out[k] = {"first": now, "sent": now, "sev": a["sev"], "msg": a["msg"]}
        elif repeat_after and now - old.get("sent", 0) >= repeat_after:
            events.append({"kind": "repeat", "sev": a["sev"], "msg": a["msg"], "since": old.get("first", now)})
            out[k] = dict(old, sent=now, sev=a["sev"], msg=a["msg"])
        else:
            out[k] = dict(old, sev=a["sev"], msg=a["msg"])
    if resolved:
        for k, old in state.items():
            if k not in cur:
                events.append({"kind": "resolved", "sev": old.get("sev", "warn"), "msg": old.get("msg", k),
                               "since": old.get("first", now)})
    return events, out


def render_text(host_label: str, events) -> tuple:
    """(title, body) for one batched message."""
    order = {"new": 0, "repeat": 1, "resolved": 2}
    events = sorted(events, key=lambda e: (order[e["kind"]], -SEV_RANK.get(e["sev"], 0)))
    n_new = sum(1 for e in events if e["kind"] != "resolved")
    title = "%s: %s" % (host_label, ("%d alert%s" % (n_new, "" if n_new == 1 else "s")) if n_new else "resolved")
    lines = []
    for e in events:
        glyph = "✅" if e["kind"] == "resolved" else ("🔴" if e["sev"] == "crit" else "🟠")
        tail = ""
        if e["kind"] == "repeat":
            tail = " (still, since %s)" % core.human_age(core.now() - e.get("since", core.now()), " ago")
        elif e["kind"] == "resolved":
            tail = " (resolved)"
        lines.append("%s %s%s" % (glyph, e["msg"], tail))
    return title, "\n".join(lines)


def send(target: dict, env: dict, host_label: str, events) -> str:
    """Deliver one batch to one target; '' on success, else a short error (never raises)."""
    kind = target.get("type")
    url = _expand(target.get("url"), env)
    if kind not in TYPES:
        return "unknown target type %r" % kind
    if not url.startswith(("https://", "http://")):
        return "%s: url is not http(s) (unset ${VAR}?)" % kind
    title, body = render_text(host_label, events)
    worst = max((SEV_RANK.get(e["sev"], 0) for e in events if e["kind"] != "resolved"), default=0)
    try:
        if kind == "ntfy":
            hdrs = {"Title": title.encode("utf-8").decode("latin-1", "replace"), "Priority": "5" if worst >= 2 else "3",
                    "Tags": "rotating_light" if worst >= 2 else "warning" if worst else "white_check_mark"}
            tok = _expand(target.get("token"), env)
            if tok:
                hdrs["Authorization"] = "Bearer " + tok
            r = core.http(url, method="POST", data=body.encode("utf-8"), headers=hdrs, timeout=8)
        elif kind == "slack":
            r = core.http(url, method="POST", json_body={"text": "*%s*\n%s" % (title, body)}, timeout=8)
        elif kind == "discord":
            r = core.http(url, method="POST", json_body={"content": ("**%s**\n%s" % (title, body))[:1990]}, timeout=8)
        else:
            r = core.http(url, method="POST", timeout=8, json_body={
                "host": host_label, "title": title, "text": body, "events": events, "ts": int(core.now())})
    except Exception as e:  # noqa: BLE001 — a dead webhook must not break the collector
        return "%s: %s" % (kind, type(e).__name__)
    return "" if 200 <= r.status < 300 else "%s: HTTP %s" % (kind, r.status)


HUB_FRESH_S = 1800  # a peer whose hub bundle is older than this speaks for itself


def current_alerts(host, cache) -> list:
    """What this host is responsible for sending. With "sender": "hub" (the default) the
    hub sends everything it sees (its own, fleet-wide, and its peers' critical alerts),
    and a peer stays quiet while its hub bundle is fresh, speaking for itself only when the
    hub has gone quiet. With "sender": "each" every host sends its own alerts and the hub
    adds only the fleet-wide ones. Either way one machine owns each alert."""
    from . import alerts
    found = alerts.gather(host, cache, alerts.probe_all(host))
    mode = (core.config().get("notify") or {}).get("sender", "hub")
    if host.hub:
        return found if mode == "hub" else [a for a in found if a.get("src") != "peer"]
    if mode == "hub" and cache.bundle and core.now() - (cache.bundle.get("ts") or 0) < HUB_FRESH_S:
        return []
    return alerts.own(found)


def run(host, cache, env, test=False) -> dict:
    """Called by the collector after each run. Returns {sent, errors} for logging."""
    cfg = core.config().get("notify") or {}
    targets = [t for t in cfg.get("targets") or [] if isinstance(t, dict)]
    if not targets:
        return {"sent": 0, "errors": []}
    path = os.path.join(core.STATE_DIR, STATE)
    state = core.read_json(path) or {}
    now = core.now()
    if test:
        events, new_state = [{"kind": "new", "sev": "warn", "msg": "test notification from fleet-motd"}], state
    else:
        events, new_state = plan(current_alerts(host, cache), state.get("alerts") or {}, now,
                                 cfg.get("min_sev", "crit"), float(cfg.get("repeat_after", 21600)),
                                 bool(cfg.get("resolved", True)))
    if not events:
        if not test and new_state != (state.get("alerts") or {}):  # e.g. a clear with "resolved": false
            core.ensure_dirs()
            core.write_json_atomic(path, dict(state, alerts=new_state, ts=now))
        return {"sent": 0, "errors": []}
    res = core.parallel({str(i): (lambda t=t: send(t, env, host.label, events)) for i, t in enumerate(targets)}, timeout=12)
    errors = [res.get(str(i)) if str(i) in res else "%s: timeout" % t.get("type") for i, t in enumerate(targets)]
    errors = [e for e in errors if e]
    if not test and len(errors) < len(targets):  # someone heard it; otherwise retry next run
        core.ensure_dirs()
        core.write_json_atomic(path, {"alerts": new_state, "ts": now, "errors": errors})
    elif not test:
        core.ensure_dirs()
        core.write_json_atomic(path, dict(state, errors=errors, ts=now))
    return {"sent": len(events), "errors": errors}

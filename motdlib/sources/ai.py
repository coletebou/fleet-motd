"""AI subscription limits (Claude, Codex/ChatGPT, Cursor, Grok) as sources.

Opt-in: each reads the local CLI login (Claude Code's credentials file or macOS
Keychain item, Codex's auth.json, ...) and asks the vendor's own usage endpoint,
so list the ones you want in config.json "enable" (see README). Global: the hub
holds the logins and peers render the hub's copy. If the hub's Claude token is
not readable (Keychain locked, ssh session), it tries peers whose file token is
live (usage_probe.first_success)."""
from __future__ import annotations

import time

from ..registry import source


def _up():
    """Imported on first use (sqlite3, subprocess, ...) so the login render stays lean."""
    from . import usage_probe
    return usage_probe


def _when(t) -> str:
    return time.strftime("%a %H:%M", time.localtime(t)) if t else "?"


def _limit_alerts(name: str, res: dict, warn=75.0, crit=90.0) -> list:
    out = []
    for w in res.get("windows") or []:
        p = w.get("used_pct")
        if p is None:
            continue
        if p >= crit:
            sev = "crit"
        elif p >= warn:
            sev = "warn"
        else:
            continue
        out.append({"sev": sev, "msg": "%s %s at %d%% (resets %s)" % (name, w["label"], p, _when(w.get("resets_at")))})
    return out


def _wrap(res: dict, alerts: list) -> dict:
    res.pop("host", None)
    if alerts:
        res["alerts"] = alerts
    return res


@source("claude_usage", ttl=600, timeout=40, scope="global", optin=True)
def claude_usage(ctx):
    """Claude Max 5h / 7d / per-model weekly windows."""
    res = _up()._safe("claude")
    if res.get("error") and ctx.host.hub:
        res = _up().first_success("claude", list(ctx.host.peers))
    return _wrap(res, _limit_alerts("Claude", res))


@source("codex_usage", ttl=600, timeout=20, scope="global", optin=True)
def codex_usage(ctx):
    """Codex (ChatGPT plan) windows + credit balance; rollout snapshot fallback."""
    res = _up()._safe("codex")
    al = _limit_alerts("Codex", res)
    if (res.get("detail") or {}).get("limit_reached"):
        al.insert(0, {"sev": "crit", "msg": "Codex rate limit reached"})
    return _wrap(res, al)


@source("cursor_usage", ttl=1800, timeout=20, scope="global", optin=True)
def cursor_usage(ctx):
    """Cursor plan usage (desktop app token)."""
    res = _up()._safe("cursor")
    al = [a for a in _limit_alerts("Cursor", res, 85, 98) if " api " not in a["msg"]]
    msg = (res.get("detail") or {}).get("message")
    if msg:
        cr = res.get("credits") or {}
        al.append({"sev": "warn", "msg": "Cursor: %s (on-demand $%.0f)" % (msg.rstrip("."), cr.get("on_demand_used_usd") or 0)})
    return _wrap(res, al)


@source("grok_usage", ttl=3600, timeout=20, scope="global", retry=6 * 3600, optin=True)
def grok_usage(ctx):
    """Grok Build CLI plan credits (needs a live `grok login`)."""
    res = _up()._safe("grok")
    return _wrap(res, _limit_alerts("Grok", res))

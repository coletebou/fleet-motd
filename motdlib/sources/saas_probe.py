#!/usr/bin/env python3
"""saas_probe: read-only SaaS / infra status probes for fleet-motd.

Tests: tests/motd-saas.test.py.
motdlib/sources/cloud.py wraps each fetch_* as a hub-collected source; Tailscale
lives in sources/local.py (local CLI), so the probe's API variant was dropped.

Python 3.9+, stdlib only. Debug: `set -a; . ~/.config/motd/env; set +a; python3 saas_probe.py --lines [--only a,b]`.
Every fetch_<service>(env) returns {"status": ok|warn|crit|unknown, "summary": "<= 60 chars",
"details": {small, JSON-safe, no secrets or PII}, "error": None | "short reason"}.

Rules this module keeps (preserve them when editing):
  * Read-only. GET everywhere, plus exactly three read-only POST queries:
    Cloudflare GraphQL, GitHub GraphQL and the UptimeRobot v2 getMonitors
    fallback. Nothing creates, updates or deletes remote state (a test audits
    the source for this).
  * Credentials go only into request headers/bodies. They are never put in
    URLs, exceptions, summaries or details, and main() scrubs every sensitive
    env value from the final output as a second line of defense.
  * Every HTTP request and subprocess has a hard timeout (REQ_TIMEOUT).
  * Redirects are never followed, so credentials cannot be forwarded off-host.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import html
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

REQ_TIMEOUT = 6.0  # seconds per HTTP request / subprocess
USER_AGENT = "saas-probe/1.0"
SUMMARY_MAX = 60


# --------------------------------------------------------------------------
# transport
# --------------------------------------------------------------------------
class ProbeError(Exception):
    """Transport-level failure or unusable response. The message is secret-free."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None  # surface the 3xx as an HTTPError instead of forwarding credentials


_OPENER = urllib.request.build_opener(_NoRedirect)


class Resp(object):
    """Minimal response: status, headers (lower-cased keys), raw body, elapsed ms."""

    def __init__(self, status: int, headers: Dict[str, str], body: bytes, ms: int) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.ms = ms

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None


def _net_err(exc: BaseException) -> str:
    reason = getattr(exc, "reason", exc)
    text = str(reason).lower()
    if isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in text:
        return "timeout"
    if isinstance(reason, socket.gaierror):
        return "dns lookup failed"
    if isinstance(reason, ssl.SSLError):
        return "tls error"
    if isinstance(reason, ConnectionRefusedError):
        return "connection refused"
    if isinstance(reason, (ConnectionResetError, http.client.RemoteDisconnected)):
        return "connection reset"
    return "network error (%s)" % type(reason).__name__


def _http(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Any = None,
    form: Optional[Dict[str, Any]] = None,
    basic: Optional[Tuple[str, str]] = None,
    timeout: Optional[float] = None,
) -> Resp:
    """One HTTP request. Non-2xx statuses are returned, not raised; transport failures raise ProbeError."""
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ProbeError("unsupported URL scheme")  # urllib would also open file:// and ftp://
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})
    body = None
    if form is not None:
        body = urllib.parse.urlencode(form).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif data is not None:
        body = json.dumps(data).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    if basic is not None:
        hdrs["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % basic).encode("utf-8")).decode("ascii")
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    t0 = time.monotonic()
    try:
        with _OPENER.open(req, timeout=timeout or REQ_TIMEOUT) as r:
            raw, status, rh = r.read(), r.status, r.headers
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
        except (OSError, http.client.HTTPException):
            raw = b""
        finally:
            e.close()  # release the socket; the status and headers stay readable
        status, rh = e.code, e.headers
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        raise ProbeError(_net_err(e)) from None
    lowered = {k.lower(): v for k, v in (rh.items() if rh else [])}
    return Resp(status, lowered, raw, int((time.monotonic() - t0) * 1000))


def _run(cmd: List[str], timeout: Optional[float] = None, env: Optional[Dict[str, str]] = None):
    """subprocess.run wrapper; raises ProbeError on timeout / missing binary."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout or REQ_TIMEOUT, env=env, stdin=subprocess.DEVNULL
        )
    except subprocess.TimeoutExpired:
        raise ProbeError("timeout") from None
    except OSError:
        raise ProbeError("cannot run %s" % os.path.basename(cmd[0])) from None


def _first_existing(cands: Tuple[Optional[str], ...]) -> Optional[str]:
    return next((c for c in cands if c and os.path.exists(c)), None)


# --------------------------------------------------------------------------
# scrubbing / redaction
# --------------------------------------------------------------------------
_TOKENISH = re.compile(r"[A-Za-z0-9_\-.]{24,}")
_MASKED_KEY = re.compile(r"\b[A-Za-z]{2,6}-\.\.\.[A-Za-z0-9]{2,8}\b")
_SENSITIVE_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASS|PWD|AUTH|CREDENTIAL|EMAIL|SID|PRIVATE)", re.I)


def _scrub(s: Any, n: int = 90) -> str:
    """Collapse whitespace, mask key-like runs, cap length. For remote error text only."""
    text = " ".join(str(s).split())
    text = _MASKED_KEY.sub("<key>", text)
    text = _TOKENISH.sub("<redacted>", text)
    return text if len(text) <= n else text[: n - 3] + "..."


def _secret_values(env: Dict[str, str]) -> List[str]:
    """Values of sensitive-looking env vars. Plain short words ('subscription', 'default') are skipped:
    redacting them would corrupt legitimate output, and real secrets contain digits/symbols or are long."""
    vals = {v for k, v in env.items()
            if isinstance(v, str) and len(v) >= 8 and _SENSITIVE_NAME.search(k)
            and (len(v) >= 20 or re.search(r"[^A-Za-z]", v))}
    return sorted(vals, key=len, reverse=True)


def _redact_text(text: str, env: Dict[str, str]) -> str:
    for v in _secret_values(env):
        text = text.replace(v, "<redacted>")
    return text


def _api_err(resp: Resp, label: str = "") -> str:
    """'HTTP 401: message' from a failed response, with the message scrubbed."""
    j = resp.json()
    msg = ""
    if isinstance(j, dict):
        for k in ("message", "error", "detail", "msg", "name"):
            v = j.get(k)
            if isinstance(v, str) and v:
                msg = v
                break
            if isinstance(v, dict) and isinstance(v.get("message"), str):
                msg = v["message"]
                break
        if not msg and isinstance(j.get("errors"), list) and j["errors"]:
            e0 = j["errors"][0]
            msg = e0.get("message", "") if isinstance(e0, dict) else str(e0)
    return "%sHTTP %d" % (label, resp.status) + (": " + _scrub(msg) if msg else "")


def _get_json(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    label: str = "",
    basic: Optional[Tuple[str, str]] = None,
    expect: type = dict,
) -> Any:
    """GET + parse JSON. A non-2xx, non-JSON or wrong-shaped (not `expect`) answer raises ProbeError."""
    r = _http("GET", url, headers=headers, params=params, basic=basic)
    j = r.json()
    if not r.ok:
        raise ProbeError(_api_err(r, label))
    if j is None:
        raise ProbeError("%snon-JSON response" % label)
    if not isinstance(j, expect):
        raise ProbeError("%sunexpected response shape" % label)
    return j


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}(?::?\d{2})?)?$"
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ts(s: Any) -> Optional[datetime]:
    """RFC3339-ish -> aware UTC datetime. Python 3.9 safe (no fromisoformat); zero time -> None."""
    if not isinstance(s, str):
        return None
    m = _TS_RE.match(s.strip())
    if not m:
        return None
    y, mo, d, h, mi, se, frac, tz = m.groups()
    if int(y) <= 1:
        return None  # Go zero time, e.g. 0001-01-01T00:00:00Z
    us = int((frac or "0")[:6].ljust(6, "0"))
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(se), us, tzinfo=timezone.utc)
        if tz and tz != "Z":
            digits = tz[1:].replace(":", "")
            off = timedelta(hours=int(digits[:2]), minutes=int(digits[2:] or 0))
            dt = dt - off if tz[0] == "+" else dt + off
    except (ValueError, OverflowError):  # well-formed but impossible: month 13, 25:61, year 9999 + offset...
        return None
    return dt


def _clip(s: Any, n: int = SUMMARY_MAX) -> str:
    text = " ".join(str(s).split())
    return text if len(text) <= n else text[: n - 3] + "..."


def _res(status: str, summary: str, details: Optional[dict] = None, error: Optional[str] = None) -> dict:
    return {"status": status, "summary": _clip(summary), "details": details or {}, "error": error}


def _fail(err: str, summary: Optional[str] = None) -> dict:
    return _res("unknown", summary or err, {}, _scrub(err, 200))


def _missing(names: List[str]) -> dict:
    return _res("unknown", "missing env: " + ", ".join(names), {}, "missing env: " + ",".join(names))


def _need(env: Dict[str, str], *names: str) -> List[str]:
    return [n for n in names if not env.get(n)]


def _worst(statuses: List[str]) -> str:
    """crit > warn > ok; 'unknown' only when nothing else is known."""
    rank = {"ok": 0, "warn": 1, "crit": 2}
    known = [s for s in statuses if s in rank]
    return max(known, key=lambda s: rank[s]) if known else "unknown"


def _pmap(calls: Dict[str, Callable[[], Any]], workers: int = 8) -> Dict[str, Tuple[Any, Optional[str]]]:
    """Run callables concurrently -> {key: (value, error_string)}. Exceptions never escape."""
    out: Dict[str, Tuple[Any, Optional[str]]] = {}
    if not calls:
        return out
    with cf.ThreadPoolExecutor(max_workers=min(workers, len(calls))) as ex:
        futs = {ex.submit(fn): key for key, fn in calls.items()}
        for f in cf.as_completed(futs):
            key = futs[f]
            try:
                out[key] = (f.result(), None)
            except ProbeError as e:
                out[key] = (None, str(e))
            except Exception as e:  # defensive: a parser bug must not take down the dashboard
                out[key] = (None, "%s: %s" % (type(e).__name__, _scrub(e)))
    return out


def _k(n: float) -> str:
    n = float(n)
    if abs(n) >= 1e6:
        return "%.1fM" % (n / 1e6)
    if abs(n) >= 1e3:
        return "%.1fk" % (n / 1e3)
    return "%d" % n


def _dicts(v: Any) -> List[dict]:
    """Only the dict elements of a list-valued API field; None, wrong types and junk elements are dropped."""
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def _d(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _f(x: Any) -> Optional[float]:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _days(td: timedelta) -> int:
    return int(td.total_seconds() // 86400)


# --------------------------------------------------------------------------
# 1. Cloudflare  (tunnels, zones, 24h traffic via GraphQL, email routing)
# --------------------------------------------------------------------------
CF_BASE = "https://api.cloudflare.com/client/v4"
_CF_TRAFFIC_Q = (
    "query($z:String!,$s:Time!,$u:Time!){viewer{zones(filter:{zoneTag:$z}){"
    "httpRequests1hGroups(limit:1,filter:{datetime_geq:$s,datetime_lt:$u}){"
    "sum{requests cachedRequests threats bytes responseStatusMap{edgeResponseStatus requests}}"
    "uniq{uniques}}}}}"
)
_CF_EMAIL_Q = (
    "query($z:String!,$s:Time!,$u:Time!){viewer{zones(filter:{zoneTag:$z}){"
    "emailRoutingAdaptiveGroups(limit:20,filter:{datetime_geq:$s,datetime_lt:$u}){count dimensions{status}}}}}"
)


def _cf_rest(h: Dict[str, str], path: str, params: Optional[dict] = None) -> Any:
    r = _http("GET", CF_BASE + path, headers=h, params=params)
    j = r.json()
    if not r.ok or not isinstance(j, dict) or j.get("success") is False:
        raise ProbeError(_api_err(r, "cf "))
    return j.get("result")


def _cf_gql(h: Dict[str, str], query: str, variables: dict) -> dict:
    """Read-only GraphQL query (POST is the only verb the endpoint takes). Returns the first zone node."""
    r = _http("POST", CF_BASE + "/graphql", headers=h, data={"query": query, "variables": variables})
    j = r.json()
    if not r.ok or not isinstance(j, dict) or j.get("errors"):
        errs = j.get("errors") if isinstance(j, dict) else None
        e0 = errs[0] if errs and isinstance(errs[0], dict) else {}
        raise ProbeError("cf graphql HTTP %d%s" % (r.status, ": " + _scrub(e0.get("message", "")) if e0 else ""))
    zones = _dicts(_d(_d(j.get("data")).get("viewer")).get("zones")) or [{}]
    return zones[0]


def fetch_cloudflare(env: Dict[str, str]) -> dict:
    miss = _need(env, "CF_EMAIL", "CF_GLOBAL_API_KEY")
    if miss:
        return _missing(miss)
    h = {"X-Auth-Email": env["CF_EMAIL"], "X-Auth-Key": env["CF_GLOBAL_API_KEY"]}
    acct = env.get("CLOUDFLARE_ACCOUNT_ID")
    zone = env.get("CF_ZONE_ID")
    now = _now()
    var = {"z": zone, "s": _iso(now - timedelta(hours=24)), "u": _iso(now)}
    calls: Dict[str, Callable[[], Any]] = {"zones": lambda: _cf_rest(h, "/zones", {"per_page": 50})}
    if acct:
        calls["tunnels"] = lambda: _cf_rest(
            h, "/accounts/%s/cfd_tunnel" % acct, {"is_deleted": "false", "per_page": 50}
        )
    if zone:
        calls["traffic"] = lambda: _cf_gql(h, _CF_TRAFFIC_Q, var)
        calls["email"] = lambda: _cf_rest(h, "/zones/%s/email/routing" % zone)
        calls["email_stats"] = lambda: _cf_gql(h, _CF_EMAIL_Q, var)
    res = _pmap(calls)
    errors = {k: e for k, (v, e) in res.items() if e}
    if len(errors) == len(calls):
        return _fail("; ".join("%s: %s" % kv for kv in sorted(errors.items())), "all Cloudflare calls failed")

    def val(key: str) -> Any:
        return res.get(key, (None, None))[0]

    crit: List[str] = []
    warn: List[str] = []
    d: Dict[str, Any] = {}
    n_active = healthy = 0
    tun = _dicts(val("tunnels")) if val("tunnels") is not None else None
    if tun is not None:
        degraded, down_recent, stale = 0, [], 0
        by_status: Dict[str, List[str]] = {}
        for t in tun:
            st, name = t.get("status"), t.get("name", "?")
            by_status.setdefault(str(st), []).append(str(name))
            if st == "healthy":
                healthy += 1
            elif st == "degraded":
                degraded += 1
                warn.append("tunnel %s degraded" % name)
            else:  # down / inactive: only a *recent* drop is an incident; months-old ones are retired tunnels
                ts = _parse_ts(t.get("conns_inactive_at"))
                if ts and now - ts < timedelta(days=14):
                    down_recent.append(name)
                    crit.append("tunnel %s down" % name)
                else:
                    stale += 1
        n_active = healthy + degraded + len(down_recent)
        d["tunnels"] = {"total": len(tun), "healthy": healthy, "degraded": degraded,
                        "down_recent": down_recent, "stale_down": stale, "by_status": by_status}
    zones = _dicts(val("zones")) if val("zones") is not None else None
    if zones is not None:
        bad = [z.get("name", "?") for z in zones if z.get("status") != "active"]
        d["zones"] = {"total": len(zones), "not_active": bad}
        if bad:
            warn.append("zone not active: " + ",".join(bad))
    req = e5 = 0
    traffic = val("traffic")
    if traffic is not None:
        g = (_dicts(traffic.get("httpRequests1hGroups")) or [{}])[0]
        s = _d(g.get("sum"))
        req = int(s.get("requests") or 0)
        cached = int(s.get("cachedRequests") or 0)
        e5 = sum(int(x.get("requests") or 0) for x in _dicts(s.get("responseStatusMap"))
                 if 500 <= int(x.get("edgeResponseStatus") or 0) < 600)
        rate = (e5 / req) if req else 0.0
        d["traffic_24h"] = {"requests": req, "cached_pct": round(100.0 * cached / req, 2) if req else 0.0,
                            "threats": int(s.get("threats") or 0), "http_5xx": e5,
                            "pct_5xx": round(100.0 * rate, 2), "uniques": int(_d(g.get("uniq")).get("uniques") or 0)}
        if req >= 50 and rate >= 0.05:
            crit.append("5xx rate %.1f%%" % (100 * rate))
        elif req >= 20 and rate >= 0.01:
            warn.append("5xx rate %.1f%%" % (100 * rate))
    em = _d(val("email")) if val("email") is not None else None
    if em is not None:
        d["email_routing"] = {"enabled": bool(em.get("enabled")), "status": em.get("status"), "synced": em.get("synced")}
        if not (em.get("enabled") and em.get("status") == "ready"):
            warn.append("email routing not ready")
    es = val("email_stats")
    if es is not None:
        d.setdefault("email_routing", {})["last_24h"] = {
            _d(x.get("dimensions")).get("status", "?"): x.get("count") for x in _dicts(es.get("emailRoutingAdaptiveGroups"))
        }
    if errors:
        d["partial_errors"] = errors
        if any(k in errors for k in ("tunnels", "zones", "traffic")):
            warn.append("partial data")
    status = "crit" if crit else "warn" if warn else "ok"
    parts = []
    if tun is not None:
        parts.append("%d/%d tunnels up" % (healthy, n_active))
    if traffic is not None:
        parts.append("%s req/24h" % _k(req))
        parts.append("%d 5xx (%.1f%%)" % (e5, 100.0 * e5 / req if req else 0.0))
    issue = (crit + warn)
    summary = ", ".join(parts) if parts else "no data"
    if issue and status != "ok" and tun is None:
        summary = issue[0]
    return _res(status, summary, d, None)


# --------------------------------------------------------------------------
# 2. Vercel  (one call: /v9/projects carries targets.production = latest prod deploy)
# --------------------------------------------------------------------------
def fetch_vercel(env: Dict[str, str]) -> dict:
    tok = env.get("VERCEL_TOKEN")
    if not tok:
        return _missing(["VERCEL_TOKEN"])
    h = {"Authorization": "Bearer " + tok}
    params: Dict[str, Any] = {"limit": 100}
    if env.get("VERCEL_TEAM_ID"):  # the token's default scope is already the team, so this is optional
        params["teamId"] = env["VERCEL_TEAM_ID"]
    projects: List[dict] = []
    try:
        for _ in range(5):
            j = _get_json("https://api.vercel.com/v9/projects", h, params, "vercel ")
            projects += _dicts(j.get("projects"))
            nxt = _d(j.get("pagination")).get("next")
            if not nxt:
                break
            params["until"] = nxt
    except ProbeError as e:
        return _fail(str(e))
    now_ms = _now().timestamp() * 1000.0
    states: Dict[str, int] = {}
    by_project: Dict[str, str] = {}
    err_24h: List[str] = []
    err_7d: List[str] = []
    stale_err: List[str] = []
    building: List[str] = []
    for p in projects:
        prod = _d(_d(p.get("targets")).get("production"))
        st = prod.get("readyState") or "NONE"
        states[st] = states.get(st, 0) + 1
        name = p.get("name", "?")
        by_project[str(name)] = st
        age_h = (now_ms - float(prod["createdAt"])) / 3.6e6 if prod.get("createdAt") else None
        if st == "ERROR":
            if age_h is not None and age_h < 24:
                err_24h.append(name)
            elif age_h is not None and age_h < 168:
                err_7d.append(name)
            else:
                stale_err.append(name)
        elif st in ("BUILDING", "QUEUED", "INITIALIZING"):
            building.append(name)
    # CANCELED is routine here (ignored-build-step / superseded builds), so it is counted, never alarmed on.
    d = {"projects": len(projects), "prod_states": states, "failing_24h": err_24h, "failing_7d": err_7d,
         "stale_errors": stale_err, "building": building, "prod_by_project": by_project}
    if err_24h:
        return _res("crit", "prod deploy ERROR: " + ", ".join(err_24h), d)
    if err_7d:
        return _res("warn", "prod deploy ERROR (<7d): " + ", ".join(err_7d), d)
    ready = states.get("READY", 0)
    return _res("ok", "%d projects, prod ok (%d READY, %d building)" % (len(projects), ready, len(building)), d)


# --------------------------------------------------------------------------
# 3. UptimeRobot  (v3 REST preferred; v2 POST getMonitors as fallback)
# --------------------------------------------------------------------------
def _ur_v3(key: str) -> List[dict]:
    mons: List[dict] = []
    url, params = "https://api.uptimerobot.com/v3/monitors", {"limit": 200}  # type: Tuple[str, Optional[dict]]
    h = {"Authorization": "Bearer " + key}
    for _ in range(5):
        r = _http("GET", url, headers=h, params=params)
        j = r.json()
        if not r.ok or not isinstance(j, dict):
            raise ProbeError(_api_err(r, "v3 "))
        for m in _dicts(j.get("data")):
            st = str(m.get("status", "")).upper()
            state = "up" if st == "UP" else "down" if st in ("DOWN", "SEEMS_DOWN") else "paused" if st == "PAUSED" else "other"
            dur = m.get("currentStateDuration")
            mons.append({"name": html.unescape(str(m.get("friendlyName", "?"))), "state": state,
                         "down_s": int(dur) if state == "down" and isinstance(dur, (int, float)) else None})
        nxt = j.get("nextLink")
        if not nxt:
            break
        if isinstance(nxt, str) and nxt.startswith("https://") and urllib.parse.urlsplit(nxt).hostname == "api.uptimerobot.com":
            url, params = nxt, None
        else:
            params = {"limit": 200, "cursor": nxt}
    return mons


def _ur_v2(key: str) -> List[dict]:
    mons: List[dict] = []
    offset = 0
    for _ in range(5):
        r = _http("POST", "https://api.uptimerobot.com/v2/getMonitors",
                  form={"api_key": key, "format": "json", "limit": 50, "offset": offset})
        j = r.json()
        if not r.ok or not isinstance(j, dict) or j.get("stat") != "ok":
            raise ProbeError(_api_err(r, "v2 ") if not r.ok else "v2 unexpected response (stat=%s)" % _scrub(j.get("stat") if isinstance(j, dict) else None))
        batch = _dicts(j.get("monitors"))
        for m in batch:
            code = m.get("status")
            state = "up" if code == 2 else "down" if code in (8, 9) else "paused" if code == 0 else "other"
            mons.append({"name": str(m.get("friendly_name", "?")), "state": state, "down_s": None})
        offset += len(batch)
        if not batch or offset >= int(_d(j.get("pagination")).get("total") or 0):
            break
    return mons


def fetch_uptimerobot(env: Dict[str, str]) -> dict:
    key = env.get("UPTIMEROBOT_API_KEY")
    if not key:
        return _missing(["UPTIMEROBOT_API_KEY"])
    mons: Optional[List[dict]] = None
    api, err3 = "v3", None
    try:
        mons = _ur_v3(key)
    except ProbeError as e:
        err3 = str(e)
    if mons is None:
        api = "v2"
        try:
            mons = _ur_v2(key)
        except ProbeError as e:
            return _fail("v3: %s; v2: %s" % (err3, e))
    ignore = [s.strip().lower() for s in (env.get("PROBE_UPTIMEROBOT_IGNORE") or "").split(",") if s.strip()]
    kept = [m for m in mons if not any(s in m["name"].lower() for s in ignore)]
    up = [m for m in kept if m["state"] == "up"]
    paused = [m for m in kept if m["state"] == "paused"]
    down = [m for m in kept if m["state"] == "down"]
    week = 7 * 86400
    recent = [m for m in down if m["down_s"] is None or m["down_s"] < week]  # unknown duration counts as recent
    d = {"api": api, "total": len(kept), "up": len(up), "paused": len(paused), "ignored": len(mons) - len(kept),
         "other": len(kept) - len(up) - len(paused) - len(down),
         "states": {m["name"]: m["state"] for m in kept},
         "down": [{"name": m["name"], "down_days": None if m["down_s"] is None else round(m["down_s"] / 86400.0, 1)} for m in down]}
    if err3:
        d["v3_error"] = err3
    if not down:
        return _res("ok", "%d/%d monitors up%s" % (len(up), len(kept), ", %d paused" % len(paused) if paused else ""), d)
    first = down[0]
    tail = "" if first["down_s"] is None else " %dd" % (first["down_s"] // 86400)
    summary = "%d/%d up; down: %s%s" % (len(up), len(kept), first["name"], tail)
    return _res("crit" if recent else "warn", summary, d)


# --------------------------------------------------------------------------
# 4. Hetzner  (Cloud servers + Storage Box via the new api.hetzner.com; no billing API exists)
# --------------------------------------------------------------------------
HCLOUD = "https://api.hetzner.cloud/v1"
HETZNER = "https://api.hetzner.com/v1"


def fetch_hetzner(env: Dict[str, str]) -> dict:
    tok = env.get("HCLOUD_TOKEN")
    if not tok:
        return _missing(["HCLOUD_TOKEN"])
    h = {"Authorization": "Bearer " + tok}
    res = _pmap({
        "servers": lambda: _get_json(HCLOUD + "/servers", h, {"per_page": 50}, "hcloud "),
        "volumes": lambda: _get_json(HCLOUD + "/volumes", h, {"per_page": 50}, "hcloud "),
        "pricing": lambda: _get_json(HCLOUD + "/pricing", h, None, "hcloud "),
        "boxes": lambda: _get_json(HETZNER + "/storage_boxes", h, {"per_page": 50}, "hetzner "),
    })
    errors = {k: e for k, (v, e) in res.items() if e}
    if len(errors) == len(res):
        return _fail("; ".join("%s: %s" % kv for kv in sorted(errors.items())), "all Hetzner calls failed")
    crit: List[str] = []
    warn: List[str] = []
    d: Dict[str, Any] = {"cost_mtd": "not exposed by any Hetzner API; est_monthly_usd is a price-list run-rate"}
    est = 0.0
    est_ok = True
    servers = _dicts(_d(res["servers"][0]).get("servers")) if res["servers"][0] is not None else None
    running = 0
    if servers is not None:
        rows = []
        for s in servers:
            st = s.get("status")
            loc = _d(s.get("location")).get("name") or _d(_d(s.get("datacenter")).get("location")).get("name")
            if st == "running":
                running += 1
            elif st in ("off", "deleting", "unknown"):
                crit.append("server %s %s" % (s.get("name"), st))
            else:
                warn.append("server %s %s" % (s.get("name"), st))
            inc = _f(s.get("included_traffic")) or 0.0
            out = _f(s.get("outgoing_traffic")) or 0.0
            pct = round(100.0 * out / inc, 1) if inc else None
            if pct is not None and pct >= 90:
                warn.append("server %s traffic %.0f%%" % (s.get("name"), pct))
            price = None
            for p in _dicts(_d(s.get("server_type")).get("prices")):
                if p.get("location") == loc:
                    price = _f(_d(p.get("price_monthly")).get("gross"))
            if price is None:
                est_ok = False
            else:
                est += price * (1.2 if s.get("backup_window") else 1.0)
            rows.append({"name": s.get("name"), "status": st, "type": _d(s.get("server_type")).get("name"),
                         "location": loc, "traffic_out_pct": pct})
        d["servers"] = rows
    vols = res["volumes"][0]
    pricing = res["pricing"][0]
    if vols is not None and pricing is not None:
        per_gb = _f(_d(_d(_d(_d(pricing).get("pricing")).get("volume")).get("price_per_gb_month")).get("gross"))
        if per_gb is not None:
            est += sum(int(v.get("size") or 0) for v in _dicts(_d(vols).get("volumes"))) * per_gb
        else:
            est_ok = False
    else:
        est_ok = False
    box_pct = None
    boxes = _dicts(_d(res["boxes"][0]).get("storage_boxes")) if res["boxes"][0] is not None else None
    if boxes:
        b = boxes[0]
        quota = _f(_d(b.get("storage_box_type")).get("size")) or 0.0
        used = _f(_d(b.get("stats")).get("size")) or 0.0
        box_pct = round(100.0 * used / quota, 1) if quota else None
        d["storage_box"] = {"name": b.get("name"), "status": b.get("status"), "location": _d(b.get("location")).get("name"),
                            "used_pct": box_pct, "used_tib": round(used / 2.0 ** 40, 2), "quota_tib": round(quota / 2.0 ** 40, 2)}
        if b.get("status") != "active":
            warn.append("storage box %s" % b.get("status"))
        if box_pct is not None and box_pct >= 90:
            crit.append("storage box %.0f%% full" % box_pct)
        elif box_pct is not None and box_pct >= 80:
            warn.append("storage box %.0f%% full" % box_pct)
        for p in _dicts(_d(b.get("storage_box_type")).get("prices")):
            if p.get("location") == _d(b.get("location")).get("name"):
                price = _f(_d(p.get("price_monthly")).get("gross"))
                est = est + price if price is not None else est
    if est_ok and servers is not None:
        cur = str(_d(_d(pricing).get("pricing")).get("currency") or "USD").upper()
        if cur == "USD":
            d["est_monthly_usd"] = round(est, 2)
        else:
            d["est_monthly"], d["currency"] = round(est, 2), cur
    if errors:
        d["partial_errors"] = errors
        if "servers" in errors or "boxes" in errors:
            warn.append("partial data")
    parts = []
    if servers is not None:
        parts.append("%d/%d servers up" % (running, len(servers)))
    if box_pct is not None:
        parts.append("box %.0f%%" % box_pct)
    if "est_monthly_usd" in d:
        parts.append("~$%.0f/mo" % d["est_monthly_usd"])
    elif "est_monthly" in d:
        parts.append("~%.0f %s/mo" % (d["est_monthly"], d["currency"]))
    status = "crit" if crit else "warn" if warn else "ok"
    summary = ", ".join(parts) if parts else "no data"
    if status != "ok" and (crit + warn):
        summary = ((crit + warn)[0] + "; " + summary)
    return _res(status, summary, d)


# --------------------------------------------------------------------------
# 6. GitHub  (token from env, else `gh auth token`; push-event CI + PR counts)
# --------------------------------------------------------------------------
GH = "https://api.github.com"
_REPO_RE = re.compile(r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$")


def _gh_headers(tok: str) -> Dict[str, str]:
    return {"Authorization": "Bearer " + tok, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


def _gh_cli_token() -> Optional[str]:
    b = _first_existing((shutil.which("gh"), "/opt/homebrew/bin/gh", "/usr/local/bin/gh"))
    if not b:
        return None
    try:
        p = _run([b, "auth", "token"], timeout=5)
    except ProbeError:
        return None
    out = p.stdout.strip()
    return out if p.returncode == 0 and out else None


def _gh_pick_token(env: Dict[str, str]) -> Tuple[Optional[str], str]:
    """First candidate that /rate_limit (free, not counted) accepts. Env PATs go stale; gh's OAuth token is the fallback."""
    cands = [("env", env.get("GH_TOKEN")), ("env", env.get("GITHUB_TOKEN")), ("gh", None),
             ("env", env.get("GITHUB_PERSONAL_ACCESS_TOKEN"))]
    seen = set()
    for src, tok in cands:
        if src == "gh":
            tok = _gh_cli_token()
        if not tok or tok in seen:
            continue
        seen.add(tok)
        if _http("GET", GH + "/rate_limit", headers=_gh_headers(tok)).ok:
            return tok, src
    return None, ""


def _ci_state(runs: List[dict], max_age_days: int = 14) -> Tuple[List[str], List[str], int, Optional[dict]]:
    """(failing, stale-failing workflow names, in-progress count, newest conclusive run) from newest-first push runs.
    cancelled/skipped/neutral runs are superseded or inert, so they never decide the verdict; a workflow whose
    latest conclusive run failed more than max_age_days ago is stale, not a live incident."""
    seen: Dict[str, Tuple[str, Optional[datetime]]] = {}
    pending = 0
    newest = None
    now = _now()
    for r in runs:
        c = r.get("conclusion")
        if c is None:
            pending += 1 if r.get("status") in ("queued", "in_progress", "waiting", "pending", "requested") else 0
            continue
        if c in ("cancelled", "skipped", "neutral", "stale"):
            continue
        seen.setdefault(r.get("name") or "?", (c, _parse_ts(r.get("updated_at"))))
        newest = newest or {"workflow": r.get("name"), "conclusion": c, "at": r.get("updated_at")}
    failed = [(n, ts) for n, (c, ts) in seen.items() if c in ("failure", "timed_out", "startup_failure", "action_required")]
    bad = [n for n, ts in failed if ts is None or now - ts <= timedelta(days=max_age_days)]
    stale = [n for n, ts in failed if n not in bad]
    return bad, stale, pending, newest


def fetch_github(env: Dict[str, str]) -> dict:
    repos = [r.strip() for r in (env.get("PROBE_GH_REPOS") or "").split(",") if r.strip()]
    repos = [r for r in repos if _REPO_RE.match(r)]
    user = env.get("PROBE_GH_USER") or ""
    branch = env.get("PROBE_GH_BRANCH") or "master"
    if not repos or not _REPO_RE.match("x/" + user) or not re.match(r"^[A-Za-z0-9_./\-]+$", branch):
        return _fail("bad PROBE_GH_* settings")
    try:
        tok, src = _gh_pick_token(env)
    except ProbeError as e:
        return _fail(str(e))
    if not tok:
        return _fail("no valid GitHub token (env PAT rejected, gh not logged in)", "no valid GitHub token")
    h = _gh_headers(tok)
    q: List[str] = []
    for i, repo in enumerate(repos):
        o, n = repo.split("/", 1)
        base = "repo:%s is:pr is:open author:%s" % (repo, user)
        q.append('o%d: search(query:"%s", type:ISSUE, first:1){issueCount} ' % (i, base))
        q.append('c%d: search(query:"%s review:changes_requested", type:ISSUE, first:1){issueCount} ' % (i, base))
        q.append('h%d: repository(owner:"%s", name:"%s"){ref(qualifiedName:"refs/heads/%s"){target{... on Commit{statusCheckRollup{state}}}}} '
                 % (i, o, n, branch))
    query = "query{" + "".join(q) + "}"

    def graphql() -> dict:
        r = _http("POST", GH + "/graphql", headers=h, data={"query": query})  # read-only query
        j = r.json()
        if not r.ok or not isinstance(j, dict) or j.get("errors") or not j.get("data"):
            errs = j.get("errors") if isinstance(j, dict) else None
            raise ProbeError("github graphql HTTP %d%s" % (r.status, ": " + _scrub(errs[0].get("message", "")) if errs and isinstance(errs[0], dict) else ""))
        return j["data"]

    calls: Dict[str, Callable[[], Any]] = {"gql": graphql}
    for i, repo in enumerate(repos):
        calls["runs%d" % i] = (lambda repo=repo: _get_json(
            GH + "/repos/%s/actions/runs" % repo, h, {"branch": branch, "event": "push", "per_page": 30}, "github "))
    res = _pmap(calls)
    errors = {k: e for k, (v, e) in res.items() if e}
    if len(errors) == len(calls):
        return _fail("; ".join("%s: %s" % kv for kv in sorted(errors.items())), "all GitHub calls failed")
    gql = _d(res["gql"][0])
    crit: List[str] = []
    warn: List[str] = []
    rows = []
    for i, repo in enumerate(repos):
        runs = _dicts(_d(res["runs%d" % i][0]).get("workflow_runs"))
        bad, stale, pending, newest = _ci_state(runs)
        roll = _d(_d(_d(_d(gql.get("h%d" % i)).get("ref")).get("target")).get("statusCheckRollup")).get("state")
        row = {"repo": repo, "open_prs": _d(gql.get("o%d" % i)).get("issueCount"),
               "changes_requested": _d(gql.get("c%d" % i)).get("issueCount"),
               "head_rollup": roll, "ci_failing": bad, "ci_stale_failing": stale, "ci_pending": pending,
               "last_push_run": newest}
        rows.append(row)
        short = repo.split("/")[1]
        if bad:
            crit.append("%s CI failing: %s" % (short, ",".join(bad)))
        elif roll in ("FAILURE", "ERROR"):
            crit.append("%s HEAD checks %s" % (short, roll))
        if row["changes_requested"]:
            warn.append("%s: %d PR(s) need changes" % (short, row["changes_requested"]))
    d: Dict[str, Any] = {"token_source": src, "branch": branch, "repos": rows}
    if errors:
        d["partial_errors"] = errors
        warn.append("partial data (%s)" % ",".join(sorted(errors)))
    status = "crit" if crit else "warn" if warn else "ok"
    total_open = sum(int(r["open_prs"] or 0) for r in rows)
    if crit:
        summary = crit[0]
    elif warn:
        summary = warn[0]
    else:
        summary = "CI green x%d; %d open PRs, 0 need changes" % (len(rows), total_open)
    return _res(status, summary, d)


# --------------------------------------------------------------------------
# 7. Sentry  (Discover: unique unresolved issues with events in the last 24h, per project, one call)
# --------------------------------------------------------------------------
def fetch_sentry(env: Dict[str, str]) -> dict:
    tok = env.get("SENTRY_AUTH_TOKEN")
    if not tok:
        return _missing(["SENTRY_AUTH_TOKEN"])
    h = {"Authorization": "Bearer " + tok}
    try:
        orgs = _get_json("https://sentry.io/api/0/organizations/", h, None, "sentry ", expect=list)
    except ProbeError as e:
        return _fail(str(e))
    if not orgs:
        return _fail("no Sentry organizations visible to this token")
    calls: Dict[str, Callable[[], Any]] = {}
    slugs: List[str] = []
    for o in _dicts(orgs)[:5]:
        slug = str(o.get("slug") or "")
        region = str(_d(o.get("links")).get("regionUrl") or "https://sentry.io").rstrip("/")
        host = urllib.parse.urlsplit(region).hostname or ""
        if not re.match(r"^[a-z0-9\-]+$", slug) or not (host == "sentry.io" or host.endswith(".sentry.io")) or not region.startswith("https://"):
            continue  # never send the token to a host the API merely told us about, unless it is Sentry's own
        base = "%s/api/0/organizations/%s" % (region, slug)
        slugs.append(slug)
        calls[slug + ":events"] = (lambda base=base: _get_json(base + "/events/", h, {
            "field": ["project", "count_unique(issue)", "count()"], "query": "is:unresolved", "statsPeriod": "24h",
            "dataset": "errors", "project": "-1", "per_page": 50, "sort": "-count_unique(issue)"}, "sentry "))
        calls[slug + ":projects"] = (lambda base=base: _get_json(base + "/projects/", h, {"per_page": 100}, "sentry ", expect=list))
    res = _pmap(calls)
    issues = events = projects = 0
    per_project: Dict[str, int] = {}
    errors = {k: e for k, (v, e) in res.items() if e}
    ev_ok = False
    for slug in slugs:
        ev, pr = res[slug + ":events"][0], res[slug + ":projects"][0]
        if isinstance(ev, dict) and isinstance(ev.get("data"), list):
            ev_ok = True
            for row in _dicts(ev["data"]):
                n = int(row.get("count_unique(issue)") or 0)
                issues += n
                events += int(row.get("count()") or 0)
                per_project[str(row.get("project"))] = n
        if isinstance(pr, list):
            projects += len(pr)
    if not ev_ok:
        return _fail("; ".join("%s: %s" % kv for kv in sorted(errors.items())) or "no Sentry data", "Sentry query failed")
    d = {"orgs": slugs, "projects": projects, "unresolved_issues_24h": issues, "events_24h": events,
         "by_project": dict(sorted(per_project.items(), key=lambda kv: -kv[1])[:6])}
    if errors:
        d["partial_errors"] = errors
    status = "ok" if issues == 0 else "crit" if (issues >= 10 or events >= 200) else "warn"
    if issues == 0:
        summary = "0 unresolved issues in 24h (%d projects)" % projects
    else:
        top = max(per_project.items(), key=lambda kv: kv[1])[0]
        summary = "%d unresolved issues, %d events/24h (%s)" % (issues, events, top)
    return _res(status, summary, d)


# --------------------------------------------------------------------------
# 8. Stripe  (GET only; mode comes from the key prefix, never the key itself)
# --------------------------------------------------------------------------
STRIPE = "https://api.stripe.com/v1"
_MONTHLY = {"day": 30.0, "week": 52.0 / 12.0, "month": 1.0, "year": 1.0 / 12.0}


def _money(minor: float, cur: str) -> str:
    cur = (cur or "").lower()
    return "$%.2f" % (minor / 100.0) if cur == "usd" else "%.2f %s" % (minor / 100.0, cur.upper())


def fetch_stripe(env: Dict[str, str]) -> dict:
    key = env.get("STRIPE_SECRET_KEY")
    if not key:
        return _missing(["STRIPE_SECRET_KEY"])
    m = re.match(r"^(sk|rk)_(live|test)_", key)
    mode = "%s_%s" % (m.group(1), m.group(2)) if m else "unknown"
    h = {"Authorization": "Bearer " + key}
    res = _pmap({
        "balance": lambda: _get_json(STRIPE + "/balance", h, None, "stripe "),
        "subs": lambda: _get_json(STRIPE + "/subscriptions", h, {"status": "all", "limit": 100}, "stripe "),
    })
    errors = {k: e for k, (v, e) in res.items() if e}
    if len(errors) == len(res):
        return _fail("; ".join("%s: %s" % kv for kv in sorted(errors.items())), "Stripe calls failed (%s)" % mode)
    d: Dict[str, Any] = {"key_mode": mode}
    warn: List[str] = []
    parts: List[str] = [mode.split("_")[-1]]
    bal = res["balance"][0]
    if bal:
        avail = {str(x.get("currency")): int(x.get("amount") or 0) for x in _dicts(bal.get("available"))}
        pend = {str(x.get("currency")): int(x.get("amount") or 0) for x in _dicts(bal.get("pending"))}
        d["available"] = {c: round(v / 100.0, 2) for c, v in avail.items()}
        d["pending"] = {c: round(v / 100.0, 2) for c, v in pend.items()}
        cur = "usd" if "usd" in avail else (next(iter(avail)) if avail else "usd")
        parts.append("%s avail" % _money(avail.get(cur, 0), cur))
    subs = res["subs"][0]
    if subs:
        by: Dict[str, int] = {}
        mrr: Dict[str, float] = {}
        for s in _dicts(subs.get("data")):
            by[str(s.get("status"))] = by.get(str(s.get("status")), 0) + 1
            if s.get("status") != "active":
                continue
            for it in _dicts(_d(s.get("items")).get("data")):
                pr = _d(it.get("price"))
                rec = _d(pr.get("recurring"))
                per = _MONTHLY.get(rec.get("interval"))
                if pr.get("unit_amount") is None or per is None:
                    continue  # metered / tiered prices have no flat monthly figure
                cnt = max(int(rec.get("interval_count") or 1), 1)
                c = str(pr.get("currency"))
                mrr[c] = mrr.get(c, 0.0) + pr["unit_amount"] * int(it.get("quantity") or 1) * per / cnt / 100.0
        bad = by.get("past_due", 0) + by.get("unpaid", 0)
        d["subscriptions"] = {"by_status": by, "list_truncated": bool(subs.get("has_more")),
                              "mrr_est": {c: round(v, 2) for c, v in mrr.items()}}
        parts.append("%d active%s" % (by.get("active", 0), "+" if subs.get("has_more") else ""))
        parts.append("%d past due" % bad)
        if bad:
            warn.append("%d past-due/unpaid subscription(s)" % bad)
    if errors:
        d["partial_errors"] = errors
        warn.append("partial data")
    return _res("warn" if warn else "ok", ", ".join(parts), d)


# --------------------------------------------------------------------------
# 9. Resend  (a send-only key cannot read anything; that is detected, not guessed)
# --------------------------------------------------------------------------
RESEND = "https://api.resend.com"


def fetch_resend(env: Dict[str, str]) -> dict:
    key = env.get("RESEND_API_KEY")
    if not key:
        return _missing(["RESEND_API_KEY"])
    h = {"Authorization": "Bearer " + key}
    try:
        r = _http("GET", RESEND + "/domains", headers=h)
    except ProbeError as e:
        return _fail(str(e))
    j = r.json()
    j = j if isinstance(j, dict) else {}
    if r.status in (401, 403) and j.get("name") == "restricted_api_key":
        # proven valid (an invalid key answers 400 validation_error) but send-only: no read endpoint is allowed
        return _res("unknown", "send-only key: cannot read domains/emails",
                    {"key_valid": True, "can_read": False,
                     "fix": "a full-access key is needed to read status (Resend has no read-only scope)"},
                    "restricted_api_key")
    if not r.ok:
        err = _api_err(r, "resend ")
        return _res("crit" if r.status in (400, 401, 403) else "unknown", "Resend key rejected" if r.status in (400, 401, 403) else err, {}, err)
    domains = [{"name": x.get("name"), "status": x.get("status")} for x in _dicts(j.get("data"))]
    d: Dict[str, Any] = {"key_valid": True, "can_read": True, "domains": domains}
    crit: List[str] = []
    warn: List[str] = []
    for dom in domains:
        if dom["status"] == "failed":
            crit.append("domain %s failed" % dom["name"])
        elif dom["status"] != "verified":
            warn.append("domain %s %s" % (dom["name"], dom["status"]))
    n24 = bad = 0
    try:
        em = _get_json(RESEND + "/emails", h, {"limit": 100}, "resend ")
        cutoff = _now() - timedelta(hours=24)
        events: Dict[str, int] = {}
        for m in _dicts(em.get("data")):
            ts = _parse_ts(m.get("created_at"))
            if ts is None or ts < cutoff:
                continue
            n24 += 1
            ev = str(m.get("last_event"))
            events[ev] = events.get(ev, 0) + 1
        bad = sum(events.get(k, 0) for k in ("bounced", "complained", "failed"))
        d["emails_24h"] = {"count": n24, "truncated": bool(em.get("has_more")), "by_last_event": events}
        if n24 >= 20 and bad / float(n24) >= 0.05:
            crit.append("%d/%d emails bounced/failed" % (bad, n24))
        elif bad:
            warn.append("%d bounced/failed in 24h" % bad)
    except ProbeError as e:
        d["emails_error"] = str(e)
    status = "crit" if crit else "warn" if warn else "ok"
    ok_domains = sum(1 for x in domains if x["status"] == "verified")
    summary = (crit + warn)[0] if (crit or warn) else "%d/%d domains verified, %d emails/24h" % (ok_domains, len(domains), n24)
    return _res(status, summary, d)


# --------------------------------------------------------------------------
# 10. Langfuse  (health + per-project 24h traces/cost; each key pair is its own project)
# --------------------------------------------------------------------------
LF_PAIRS = (("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY"), ("LANGFUSE_PUBLIC_KEY_2", "LANGFUSE_SECRET_KEY_2"))


def _lf_project(base: str, pk: str, sk: str, since: str, until: str) -> dict:
    auth = (pk, sk)
    query = json.dumps({"view": "traces", "dimensions": [],
                        "metrics": [{"measure": "count", "aggregation": "count"}, {"measure": "totalCost", "aggregation": "sum"}],
                        "filters": [], "fromTimestamp": since, "toTimestamp": until})
    res = _pmap({
        "project": lambda: _get_json(base + "/api/public/projects", None, None, "langfuse ", basic=auth),
        "metrics": lambda: _get_json(base + "/api/public/metrics", None, {"query": query}, "langfuse ", basic=auth),
    })
    proj, perr = res["project"]
    mx, merr = res["metrics"]
    out: Dict[str, Any] = {"project": (_dicts(_d(proj).get("data")) or [{}])[0].get("name")}
    if mx is not None:
        row = (_dicts(mx.get("data")) or [{}])[0]
        out["traces_24h"] = int(row.get("count_count") or 0)
        out["cost_24h_usd"] = round(float(row.get("sum_totalCost") or 0.0), 4)
    else:  # older servers lack the metrics query API: fall back to the traces list total
        try:
            t = _get_json(base + "/api/public/traces", None, {"limit": 1, "fromTimestamp": since}, "langfuse ", basic=auth)
            out["traces_24h"] = int(_d(t.get("meta")).get("totalItems") or 0)
        except ProbeError as e:
            out["error"] = str(e)
    if perr and "error" not in out:
        out["error"] = perr
    return out


def fetch_langfuse(env: Dict[str, str]) -> dict:
    urls = [u.rstrip("/") for u in (env.get("LANGFUSE_HOST"), env.get("LANGFUSE_BASE_URL")) if u]
    if not urls:
        return _missing(["LANGFUSE_HOST"])
    health = _pmap({str(i): (lambda u=u: _http("GET", u + "/api/public/health", timeout=min(4.0, REQ_TIMEOUT))) for i, u in enumerate(urls)})
    base, version, errs = None, None, []
    for i, u in enumerate(urls):
        r, e = health[str(i)]
        if r is not None and r.ok and isinstance(r.json(), dict) and r.json().get("status") == "OK":
            base, version = u, r.json().get("version")
            break
        errs.append("url%d: %s" % (i + 1, e or "HTTP %d" % r.status))
    if base is None:
        return _res("crit", "Langfuse unreachable", {"health_errors": errs}, "; ".join(errs))
    now = _now()
    since, until = _iso(now - timedelta(hours=24)), _iso(now)
    pairs = [(env[a], env[b]) for a, b in LF_PAIRS if env.get(a) and env.get(b)]
    res = _pmap({str(i): (lambda p=p: _lf_project(base, p[0], p[1], since, until)) for i, p in enumerate(pairs)})
    projects: List[dict] = []
    warn: List[str] = []
    for i in range(len(pairs)):
        v, e = res[str(i)]
        v = v if v is not None else {"error": e}
        projects.append(v)
        if v.get("error"):
            warn.append("key pair %d: %s" % (i + 1, v["error"]))
    d = {"version": version, "used_fallback_url": base != urls[0], "projects": projects}
    parts = ["v%s ok" % version]
    for v in projects:
        if "traces_24h" in v:
            parts.append("%s %dtr/$%.2f" % (v.get("project") or "?", v["traces_24h"], v.get("cost_24h_usd") or 0.0))
    if not pairs:
        warn.append("no LANGFUSE_* key pairs in env")
    return _res("warn" if warn else "ok", "; ".join(parts) if not warn else warn[0], d)


# --------------------------------------------------------------------------
# 11. AI spend  (OpenRouter credits, Anthropic + OpenAI admin cost reports, xAI management)
# --------------------------------------------------------------------------
def _month_start(now: datetime) -> datetime:
    return datetime(now.year, now.month, 1, tzinfo=timezone.utc)


def fetch_openrouter(env: Dict[str, str]) -> dict:
    key = env.get("OPENROUTER_MGMT_KEY") or env.get("OPENROUTER_API_KEY")
    if not key:
        return _missing(["OPENROUTER_MGMT_KEY"])
    h = {"Authorization": "Bearer " + key}
    res = _pmap({
        "credits": lambda: _get_json("https://openrouter.ai/api/v1/credits", h, None, "openrouter "),
        "key": lambda: _get_json("https://openrouter.ai/api/v1/key", h, None, "openrouter "),
    })
    credits, err = res["credits"]
    if credits is None:
        return _fail(err or "no credits data")
    data = _d(credits.get("data"))
    total, used = _f(data.get("total_credits")), _f(data.get("total_usage"))
    if total is None or used is None:
        return _fail("unexpected OpenRouter credits payload")
    left = total - used
    k = _d(_d(res["key"][0]).get("data"))  # NB: k["label"] can embed a masked key, so it is never read
    d = {"credits_total_usd": round(total, 2), "credits_used_usd": round(used, 2), "remaining_usd": round(left, 2),
         "remaining_pct": round(100.0 * left / total, 1) if total else None, "key_limit_usd": k.get("limit"),
         "key_limit_remaining_usd": k.get("limit_remaining"), "key_usage_monthly_usd": k.get("usage_monthly"),
         "mgmt_key": bool(k.get("is_management_key"))}
    crit_at = _f(env.get("PROBE_OPENROUTER_CRIT_USD")) or 10.0
    warn_at = _f(env.get("PROBE_OPENROUTER_WARN_USD")) or 50.0
    status = "crit" if left < crit_at else "warn" if left < warn_at else "ok"
    return _res(status, "$%.2f left of $%.0f credits" % (left, total), d)


def fetch_anthropic(env: Dict[str, str]) -> dict:
    key = env.get("ANTHROPIC_ADMIN_KEY")
    if not key:
        return _missing(["ANTHROPIC_ADMIN_KEY"])
    h = {"x-api-key": key, "anthropic-version": "2023-06-01"}
    params: Dict[str, Any] = {"starting_at": _iso(_month_start(_now())), "bucket_width": "1d", "limit": 31}
    cents, last_day = 0.0, None
    try:
        for _ in range(5):
            j = _get_json("https://api.anthropic.com/v1/organizations/cost_report", h, params, "anthropic ")
            for b in _dicts(j.get("data")):
                last_day = str(b.get("starting_at") or "")[:10] or last_day
                for r in _dicts(b.get("results")):
                    if str(r.get("currency", "USD")).upper() == "USD":
                        cents += _f(r.get("amount")) or 0.0
            if not (j.get("has_more") and j.get("next_page")):
                break
            params["page"] = j["next_page"]
    except ProbeError as e:
        return _fail(str(e))
    # amounts are USD *cents* as decimal strings (checked: 41,603 Opus input tokens at $5/MTok = $0.208 = "20.8015")
    usd = cents / 100.0
    return _res("ok", "MTD $%.2f (through %s)" % (usd, last_day or "n/a"), {"mtd_usd": round(usd, 2), "last_bucket": last_day})


def fetch_openai(env: Dict[str, str]) -> dict:
    key = env.get("OPENAI_ADMIN_KEY")
    if not key:
        return _missing(["OPENAI_ADMIN_KEY"])
    h = {"Authorization": "Bearer " + key}
    params: Dict[str, Any] = {"start_time": int(_month_start(_now()).timestamp()), "bucket_width": "1d", "limit": 31}
    total, last_day = 0.0, None
    try:
        for _ in range(5):
            j = _get_json("https://api.openai.com/v1/organization/costs", h, params, "openai ")
            for b in _dicts(j.get("data")):
                if isinstance(b.get("start_time"), (int, float)):
                    last_day = datetime.fromtimestamp(b["start_time"], timezone.utc).strftime("%Y-%m-%d")
                for r in _dicts(b.get("results")):
                    amt = _d(r.get("amount"))
                    if str(amt.get("currency", "usd")).lower() == "usd":
                        total += _f(amt.get("value")) or 0.0
            if not (j.get("has_more") and j.get("next_page")):
                break
            params["page"] = j["next_page"]
    except ProbeError as e:
        return _fail(str(e))
    return _res("ok", "MTD $%.2f (through %s)" % (total, last_day or "n/a"), {"mtd_usd": round(total, 2), "last_bucket": last_day})


def fetch_xai(env: Dict[str, str]) -> dict:
    key = env.get("XAI_MGMT_KEY")
    if not key:
        return _missing(["XAI_MGMT_KEY"])
    base, h = "https://management-api.x.ai", {"Authorization": "Bearer " + key}
    try:
        v = _get_json(base + "/auth/management-keys/validation", h, None, "xai ")
    except ProbeError as e:
        return _fail(str(e))
    team = str(v.get("teamId") or "")
    if not re.match(r"^[0-9a-fA-F\-]{36}$", team):
        return _res("unknown", "xAI key valid but no team id", {"key_valid": True}, "no teamId")
    try:
        r = _http("GET", "%s/v1/billing/teams/%s/prepaid/balance" % (base, team), headers=h)
    except ProbeError as e:
        return _fail(str(e))
    if r.status == 403:  # the key validates but carries no BillingRead ACL
        return _res("unknown", "xAI mgmt key lacks BillingRead permission",
                    {"key_valid": True, "billing_read": False, "fix": "grant BillingRead to the management key at console.x.ai"},
                    "HTTP 403 BillingRead")
    if not r.ok:
        return _fail(_api_err(r, "xai "))
    body = r.json()
    total = (((body if isinstance(body, dict) else {}).get("total")) or {}).get("val")  # schema unverified (no BillingRead yet)
    return _res("ok", "xAI prepaid total (raw units): %s" % total, {"billing_read": True, "prepaid_total_raw": total})


def fetch_ai_spend(env: Dict[str, str]) -> dict:
    subs = (("openrouter", fetch_openrouter), ("anthropic", fetch_anthropic), ("openai", fetch_openai), ("xai", fetch_xai))
    res = _pmap({n: (lambda f=f: f(env)) for n, f in subs}, workers=4)
    parts = {n: (res[n][0] if res[n][0] is not None else _res("unknown", "internal error", {}, res[n][1])) for n, _ in subs}
    d = {n: {"status": p["status"], "summary": p["summary"], "error": p["error"], "details": p["details"]} for n, p in parts.items()}
    status = _worst([p["status"] for p in parts.values()])
    bits = []
    for label, n, field in (("A", "anthropic", "mtd_usd"), ("O", "openai", "mtd_usd")):
        v = parts[n]["details"].get(field)
        bits.append("%s$%.2f" % (label, v) if v is not None else "%s n/a" % label)
    left = parts["openrouter"]["details"].get("remaining_usd")
    summary = "MTD %s | OR %s | xAI %s" % (
        " ".join(bits), "$%.0f left" % left if left is not None else "n/a", "ok" if parts["xai"]["status"] == "ok" else "n/a")
    ok_n = sum(1 for p in parts.values() if p["status"] != "unknown")
    error = None if ok_n else "; ".join("%s: %s" % (n, p["error"]) for n, p in parts.items() if p["error"])
    return _res(status, summary, d, error)


# --------------------------------------------------------------------------
# 12. AWS  (CLI-based so there is no SDK dependency; Cost Explorer is opt-in because it bills $0.01/call)
# --------------------------------------------------------------------------
def _aws_bin() -> Optional[str]:
    return _first_existing((shutil.which("aws"), os.path.expanduser("~/.local/bin/aws"), "/opt/homebrew/bin/aws",
                            "/usr/local/bin/aws"))


def _aws_profiles(env: Dict[str, str]) -> List[str]:
    names: List[str] = [env["AWS_PROFILE"]] if env.get("AWS_PROFILE") else []
    try:
        with open(os.path.expanduser(env.get("AWS_CONFIG_FILE") or "~/.aws/config")) as fh:
            txt = fh.read()
    except OSError:
        txt = ""
    for m in re.finditer(r"^\[(default|profile\s+([^\]\s]+))\]\s*$", txt, re.M):
        n = m.group(2) or "default"
        if n not in names:
            names.append(n)
    return names


def _aws_err(stderr: str) -> str:
    lines = (stderr or "").strip().splitlines()
    low = (lines[-1] if lines else "").lower()
    if "token has expired" in low or ("sso" in low and "expired" in low):
        return "sso-expired"
    if "unable to locate credentials" in low:
        return "no-credentials"
    if "expiredtoken" in low or ("security token" in low and "expired" in low):
        return "credentials-expired"
    if "accessdenied" in low or "unauthorizedoperation" in low:
        return "access-denied"
    return _scrub(lines[-1] if lines else "aws failed", 80)


def _aws_cli(args: List[str], profile: str, region: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> Any:
    b = _aws_bin()
    if not b:
        raise ProbeError("aws CLI not found")
    cmd = [b] + args + ["--profile", profile, "--output", "json", "--cli-connect-timeout", "4", "--cli-read-timeout", "5"]
    if region:
        cmd += ["--region", region]
    cenv = dict(env if env is not None else os.environ)  # the merged collector env (motd env file included)
    cenv.update({"AWS_EC2_METADATA_DISABLED": "true", "AWS_PAGER": ""})  # no 2s IMDS probe when creds are absent
    for k in ("AWS_REGION", "AWS_DEFAULT_REGION"):  # set-but-empty breaks endpoint resolution ("sts..amazonaws.com")
        if not cenv.get(k):
            cenv.pop(k, None)
    p = _run(cmd, env=cenv)
    if p.returncode != 0:
        raise ProbeError(_aws_err(p.stderr))
    try:
        return json.loads(p.stdout or "null")
    except ValueError:
        raise ProbeError("aws: bad JSON") from None


def fetch_aws(env: Dict[str, str]) -> dict:
    if not _aws_bin():
        return _fail("aws CLI not found", "aws CLI not installed")
    profiles = _aws_profiles(env) or ["default"]
    res = _pmap({p: (lambda p=p: _aws_cli(["sts", "get-caller-identity"], p, "us-east-1", env)) for p in profiles})
    errs = {p: res[p][1] for p in profiles if res[p][1]}
    prof = next((p for p in profiles if res[p][0]), None)
    if prof is None:
        expired = [p for p, e in errs.items() if e == "sso-expired"]
        if expired:
            return _res("warn", "SSO token expired: aws sso login --profile %s" % expired[0], {"profile_errors": errs}, "sso-expired")
        return _res("unknown", "no usable AWS credentials", {"profile_errors": errs}, "; ".join(sorted(set(errs.values()))))
    ident = _d(res[prof][0])
    arn = str(ident.get("Arn", ""))
    d: Dict[str, Any] = {"profile": prof, "account_last4": str(ident.get("Account", ""))[-4:],
                         "principal_type": arn.split(":")[5].split("/")[0] if arn.count(":") >= 5 else "?"}
    query = "Reservations[].Instances[].{n:Tags[?Key=='Name']|[0].Value,t:InstanceType}"
    regions = ("us-east-1", "us-west-2")
    ec2 = _pmap({r: (lambda r=r: _aws_cli(["ec2", "describe-instances", "--filters", "Name=instance-state-name,Values=running",
                                           "--query", query], prof, r, env)) for r in regions})
    running: Dict[str, Any] = {}
    for r in regions:
        v, e = ec2[r]
        running[r] = {"error": e} if e else {"count": len(_dicts(v)), "names": [str(i.get("n")) for i in _dicts(v)][:8]}
    d["ec2_running"] = running
    if env.get("PROBE_AWS_CE") == "1":  # opt-in: Cost Explorer charges $0.01 per request
        now = _now()
        try:
            ce = _aws_cli(["ce", "get-cost-and-usage", "--time-period", "Start=%s,End=%s" % (
                _month_start(now).strftime("%Y-%m-%d"), (now + timedelta(days=1)).strftime("%Y-%m-%d")),
                "--granularity", "MONTHLY", "--metrics", "UnblendedCost"], prof, "us-east-1", env)
            d["mtd_unblended_usd"] = round(float(ce["ResultsByTime"][0]["Total"]["UnblendedCost"]["Amount"]), 2)
        except (ProbeError, KeyError, IndexError, ValueError, TypeError) as e:
            d["ce_error"] = str(e)
    n = sum(v.get("count", 0) for v in running.values())
    parts = ["acct ...%s" % d["account_last4"], "%d EC2 running" % n]
    if any("error" in v for v in running.values()):
        parts.append("(partial)")
    return _res("warn" if any("error" in v for v in running.values()) else "ok", ", ".join(parts), d)


# --------------------------------------------------------------------------
# 13. Twilio  (the live path is covered by mocked-HTTP tests, never run against Twilio)
# --------------------------------------------------------------------------
def fetch_twilio(env: Dict[str, str]) -> dict:
    sid, tok = env.get("TWILIO_ACCOUNT_SID"), env.get("TWILIO_AUTH_TOKEN")
    if not sid or not tok:
        return _res("unknown", "no TWILIO_* creds in env",
                    {},
                    "missing env: TWILIO_ACCOUNT_SID,TWILIO_AUTH_TOKEN")
    if not re.match(r"^AC[0-9a-fA-F]{32}$", sid):
        return _fail("TWILIO_ACCOUNT_SID is not an AC... SID", "bad TWILIO_ACCOUNT_SID")
    base = (env.get("TWILIO_API_BASE") or "https://api.twilio.com").rstrip("/") + "/2010-04-01/Accounts/" + sid
    auth = (sid, tok)
    res = _pmap({
        "balance": lambda: _get_json(base + "/Balance.json", None, None, "twilio ", basic=auth),
        "today": lambda: _get_json(base + "/Usage/Records/Today.json", None, {"Category": "sms"}, "twilio ", basic=auth),
    })
    errors = {k: e for k, (v, e) in res.items() if e}
    if len(errors) == len(res):
        return _fail("; ".join("%s: %s" % kv for kv in sorted(errors.items())), "Twilio calls failed")
    d: Dict[str, Any] = {}
    bal = res["balance"][0]
    left = _f(_d(bal).get("balance"))
    if left is not None:
        d["balance"] = {"amount": round(left, 2), "currency": _d(bal).get("currency")}
    today = res["today"][0]
    count = None
    if today is not None:
        count = sum(int(_f(r.get("count")) or 0) for r in _dicts(today.get("usage_records")))
        d["sms_today"] = count
    if errors:
        d["partial_errors"] = errors
    status = "ok" if left is None else "crit" if left < 5 else "warn" if left < 20 else "ok"
    if errors and status == "ok":
        status = "warn"
    bits = ["$%.2f balance" % left] if left is not None else []
    if count is not None:
        bits.append("%d SMS today" % count)
    return _res(status, ", ".join(bits) or "no data", d)


# --------------------------------------------------------------------------
# registry + runner
# --------------------------------------------------------------------------
FETCHERS: Tuple[Tuple[str, Callable[[Dict[str, str]], dict]], ...] = (
    ("cloudflare", fetch_cloudflare),
    ("vercel", fetch_vercel),
    ("uptimerobot", fetch_uptimerobot),
    ("hetzner", fetch_hetzner),
    ("github", fetch_github),
    ("sentry", fetch_sentry),
    ("stripe", fetch_stripe),
    ("resend", fetch_resend),
    ("langfuse", fetch_langfuse),
    ("ai_spend", fetch_ai_spend),
    ("aws", fetch_aws),
    ("twilio", fetch_twilio),
)
_VALID = ("ok", "warn", "crit", "unknown")


def _normalize(r: Any) -> dict:
    """Force the documented shape, whatever a fetcher returned."""
    r = r if isinstance(r, dict) else {}
    err = r.get("error")
    return {
        "status": r.get("status") if r.get("status") in _VALID else "unknown",
        "summary": _clip(r.get("summary", "")),
        "details": r.get("details") if isinstance(r.get("details"), dict) else {},
        "error": None if err is None else str(err),
    }


def _timed(fn: Callable[[Dict[str, str]], dict], env: Dict[str, str]) -> Tuple[dict, int]:
    t0 = time.monotonic()
    try:
        out = fn(env)
    except Exception as e:  # a fetcher bug must never blank the whole dashboard
        out = _res("unknown", "internal error", {}, "%s: %s" % (type(e).__name__, _scrub(e)))
    return _normalize(out), int((time.monotonic() - t0) * 1000)


DEADLINE = 20.0  # seconds: hard cap on the whole run, so a hung API can never stall a login shell


def run_all(env: Dict[str, str], only: Optional[List[str]] = None, deadline: Optional[float] = None) -> dict:
    """Run the selected fetchers in parallel. Returns results plus per-service and total wall time.
    Fetchers still running at the deadline are reported as unknown and listed under 'deadline_hit'."""
    table = dict(FETCHERS)
    names = [n for n, _ in FETCHERS if not only or n in only]
    t0 = time.monotonic()
    results: Dict[str, dict] = {}
    timing: Dict[str, int] = {}
    ex = cf.ThreadPoolExecutor(max_workers=max(len(names), 1))
    futs = {ex.submit(_timed, table[n], env): n for n in names}
    done, pending = cf.wait(list(futs), timeout=DEADLINE if deadline is None else deadline)
    for f in done:
        n = futs[f]
        results[n], timing[n] = f.result()
    hung = [futs[f] for f in pending]
    for n in hung:
        results[n] = _normalize(_res("unknown", "timed out waiting for the API", {}, "deadline exceeded"))
        timing[n] = int((time.monotonic() - t0) * 1000)
    ex.shutdown(wait=False, cancel_futures=True)
    out = {
        "generated_at": _iso(_now()),
        "wall_time_s": round(time.monotonic() - t0, 2),
        "timing_ms": {n: timing[n] for n in names},
        "results": {n: results[n] for n in names},
    }
    if hung:
        out["deadline_hit"] = hung
    return out


def set_timeout(seconds: float) -> None:
    global REQ_TIMEOUT
    REQ_TIMEOUT = float(seconds)


def format_lines(out: dict) -> str:
    rows = ["%-12s %-7s %-60s %5dms" % (n, r["status"].upper(), r["summary"], out["timing_ms"][n]) for n, r in out["results"].items()]
    rows.append("wall time %.2fs, %d services" % (out["wall_time_s"], len(out["results"])))
    return "\n".join(rows)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Read-only SaaS/infra status probes (env from the process environment).")
    ap.add_argument("--only", help="comma-separated service names: " + ",".join(n for n, _ in FETCHERS))
    ap.add_argument("--lines", action="store_true", help="one human-readable line per service instead of JSON")
    ap.add_argument("--compact", action="store_true", help="single-line JSON")
    ap.add_argument("--timeout", type=float, default=REQ_TIMEOUT, help="per-request timeout in seconds (default %(default)s)")
    ap.add_argument("--deadline", type=float, default=DEADLINE, help="hard cap on the whole run in seconds (default %(default)s)")
    a = ap.parse_args(argv)
    set_timeout(a.timeout)
    only = [s.strip() for s in a.only.split(",") if s.strip()] if a.only else None
    unknown = [s for s in (only or []) if s not in dict(FETCHERS)]
    if unknown:
        ap.error("unknown service(s): " + ", ".join(unknown))
    env = dict(os.environ)
    out = run_all(env, only, a.deadline)
    text = format_lines(out) if a.lines else json.dumps(out, indent=None if a.compact else 2, default=str, sort_keys=False)
    sys.stdout.write(_redact_text(text, env) + "\n")  # last line of defense: no env secret value can reach stdout
    if out.get("deadline_hit"):  # a worker is stuck in a socket call: do not let interpreter shutdown wait for it
        sys.stdout.flush()
        os._exit(0)
    return 0


if __name__ == "__main__":
    sys.exit(main())

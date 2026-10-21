#!/usr/bin/env python3
"""Subscription usage probe for the MOTD: Claude, Codex, Cursor, Grok, xAI API.

Vendored from the 2026-10-16 research probe; motdlib/sources/ai.py wraps each
fetch_* as a hub-collected source. Self-contained on purpose: run_remote()
pipes this file to `ssh HOST python3 -` so a token never leaves its host.

Python 3.9+, stdlib only. Strictly read-only: it never refreshes, rotates or writes a
credential, and it never prints or returns a token. Every fetch_* returns a dict:

  {"provider": "claude", "host": "my-mac", "plan": "max (default_claude_max_20x)",
   "windows": [{"label": "5h", "used_pct": 17.0, "resets_at": 1792151999}, ...],
   "credits": {...} or None, "source": "api" | "rollout" | None,
   "as_of": <epoch of the data>, "latency_ms": 444, "error": None or "why", "detail": {...}}

CLI:  usage_probe.py [--json] [--host SSH_ALIAS] [claude codex cursor grok xai_api]
      With --host the module pipes itself to `ssh HOST python3 -`, so tokens never leave
      the host that owns them.
"""
import base64
import datetime
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HOST = socket.gethostname().split(".")[0]
HOME = os.path.expanduser("~")

CLAUDE_USAGE_URL = "https://api.anthropic.com/api/oauth/usage"
CODEX_WHAM_URL = "https://chatgpt.com/backend-api/wham/usage"
CURSOR_USAGE_URL = "https://api2.cursor.sh/aiserver.v1.DashboardService/GetCurrentPeriodUsage"
CURSOR_PROFILE_URL = "https://api2.cursor.sh/auth/full_stripe_profile"
CURSOR_SUMMARY_URL = "https://cursor.com/api/usage-summary"
GROK_BILLING_URL = "https://cli-chat-proxy.grok.com/v1/billing?format=credits"
XAI_MGMT_URL = "https://management-api.x.ai"


# ---------------------------------------------------------------- helpers

def _ms(t0):
    return int((time.time() - t0) * 1000)


def _http(url, headers=None, method="GET", body=None, timeout=10.0):
    """Return (status, payload, ms). status is None on a network error.

    payload is parsed JSON when possible, else up to 300 chars of text."""
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except Exception as e:  # URLError, socket.timeout, ssl errors
        return None, "%s: %s" % (type(e).__name__, e), _ms(t0)
    text = raw.decode("utf-8", "replace")
    try:
        return status, (json.loads(text) if text.strip() else {}), _ms(t0)
    except ValueError:
        return status, text[:300], _ms(t0)


def _scrub(text):
    """Belt and braces: mask anything key- or token-shaped before it reaches an error string."""
    text = re.sub(r"(xai-|sk-ant-|sk-|eyJ)[A-Za-z0-9._\-]{4,}", r"\1...", str(text))
    return re.sub(r"[A-Za-z0-9_\-]{40,}", "...", text)


def _err(status, payload):
    """One-line, secret-free error for a failed HTTP call."""
    msg = payload
    if isinstance(payload, dict):
        e = payload.get("error")
        if isinstance(e, dict):
            msg = e.get("message") or e.get("type") or e
        else:
            msg = e or payload.get("detail") or payload.get("message") or payload
    if status is None:
        return "network: %s" % _scrub(msg)[:160]
    return "HTTP %s: %s" % (status, _scrub(json.dumps(msg) if isinstance(msg, (dict, list)) else msg)[:200])


def _epoch(v):
    """ISO-8601 text or epoch seconds/milliseconds (number or digit string) -> int epoch seconds."""
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit()):
        f = float(v)
        return int(f / 1000) if f > 1e11 else int(f)
    s = str(v).strip().replace("Z", "+00:00")
    m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(.*)$", s)
    if m:  # Python 3.9 fromisoformat accepts exactly 3 or 6 fractional digits
        s = m.group(1) + "." + (m.group(2) or "")[:6].ljust(6, "0") + m.group(3)
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return int(dt.timestamp())


def _fmt(epoch):
    return time.strftime("%Y-%m-%d %H:%M %Z", time.localtime(epoch)) if epoch else "?"


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _jwt_claims(token):
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part.encode()))
    except Exception:
        return {}


def _read_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _keychain(service, account=None, timeout=5):
    """macOS Keychain generic password -> (value, error). Never blocks on a GUI prompt."""
    if sys.platform != "darwin" or not shutil.which("security"):
        return None, "no keychain"
    cmd = ["security", "find-generic-password", "-s", service] + (["-a", account] if account else []) + ["-w"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "keychain timed out (locked or prompting)"
    if p.returncode == 36:  # errSecInteractionNotAllowed: ssh/cron sessions cannot see the GUI keychain
        return None, "keychain unavailable in this session (rc 36); run from the GUI login (LaunchAgent or GUI-rooted tmux)"
    if p.returncode != 0 or not p.stdout.strip():
        return None, (p.stderr.strip().splitlines() or ["not found (rc %d)" % p.returncode])[-1][:120]
    return p.stdout.strip(), None


def _secret(name):
    """Env var, else a plain `NAME=value` line in the motd env file (no shell expansion)."""
    if os.environ.get(name):
        return os.environ[name]
    try:
        with open(os.environ.get("MOTD_ENV_FILE") or os.path.join(
                os.environ.get("MOTD_CONFIG_DIR") or os.path.join(HOME, ".config", "motd"), "env")) as fh:
            for line in fh:
                m = re.match(r"\s*(?:export\s+)?%s=(.*)$" % re.escape(name), line.rstrip("\n"))
                if m:
                    v = m.group(1).strip()
                    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                        v = v[1:-1]
                    if v and "$" not in v:
                        return v
    except OSError:
        pass
    return None


def _login_name():
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return None


def _result(provider, **kw):
    r = {"provider": provider, "host": HOST, "plan": None, "windows": [], "credits": None,
         "source": None, "as_of": int(time.time()), "latency_ms": None, "error": None, "detail": {}}
    r.update(kw)
    return r


def _win(label, used_pct, resets_at, **extra):
    w = {"label": label, "used_pct": None if _num(used_pct) is None else round(_num(used_pct), 1),
         "resets_at": _epoch(resets_at)}
    w.update({k: v for k, v in extra.items() if v is not None})
    return w


def _dur(seconds):
    s = int(_num(seconds) or 0)
    if s <= 0:
        return "?"
    if s % 86400 == 0:
        return "%dd" % (s // 86400)
    if s % 3600 == 0:
        return "%dh" % (s // 3600)
    return "%dm" % (s // 60)


# ---------------------------------------------------------------- Claude (Max/Pro OAuth)

def _claude_credentials():
    """Every readable claudeAiOauth blob, freshest first.

    Linux: ~/.claude/.credentials.json. macOS: Keychain service "Claude Code-credentials".
    The Mac can hold several items under that service (seen: account "unknown", stale since
    Oct 8, next to account "$USER", live), and `security -w` without -a returns whichever
    it finds first, so every candidate account is read and the latest expiresAt wins."""
    found, errors = [], set()
    cfg = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(HOME, ".claude")
    c = ((_read_json(os.path.join(cfg, ".credentials.json")) or {}).get("claudeAiOauth") or {})
    if c.get("accessToken"):
        found.append((c, "file"))
    if sys.platform == "darwin":
        accounts = []
        for a in (os.environ.get("USER"), _login_name(), "unknown", None):
            if a not in accounts:
                accounts.append(a)
        for a in accounts:
            raw, err = _keychain("Claude Code-credentials", a)
            if err and ("rc 36" in err or "timed out" in err):
                errors.add(err)
                break  # same answer for every account; do not repeat the wait
            try:
                c = (json.loads(raw).get("claudeAiOauth") or {}) if raw else {}
            except ValueError:
                c = {}
            if c.get("accessToken"):
                found.append((c, "keychain:%s" % (a or "any")))
    found.sort(key=lambda x: x[0].get("expiresAt") or 0, reverse=True)
    return found, sorted(errors)


def fetch_claude():
    creds, kc_errors = _claude_credentials()
    if not creds:
        return _result("claude", error="no subscription login found (no claudeAiOauth in ~/.claude/.credentials.json"
                                       " or Keychain)%s" % ("; " + "; ".join(kc_errors) if kc_errors else ""))
    c, store = creds[0]
    plan = c.get("subscriptionType")
    if plan and c.get("rateLimitTier"):
        plan = "%s (%s)" % (plan, c["rateLimitTier"])
    exp = int((c.get("expiresAt") or 0) / 1000)
    detail = {"token_store": store, "token_expires_at": exp}
    if exp < time.time() + 30:
        return _result("claude", plan=plan, detail=detail, error=(
            "OAuth access token expired %s; the claude CLI refreshes it (8h tokens) on its next "
            "API call. Not refreshing here: rotation would log the CLI out." % _fmt(exp)))
    status, d, ms = _http(CLAUDE_USAGE_URL, {"Authorization": "Bearer " + c["accessToken"],
                                             "anthropic-beta": "oauth-2025-04-20", "Accept": "application/json"})
    if status != 200 or not isinstance(d, dict):
        return _result("claude", plan=plan, latency_ms=ms, detail=detail, error=_err(status, d))
    windows = []
    for lim in d.get("limits") or []:  # the normalized list `/usage` renders
        kind = lim.get("kind")
        model = ((lim.get("scope") or {}).get("model") or {}).get("display_name")
        label = {"session": "5h", "weekly_all": "7d"}.get(kind) or (
            "7d " + model if kind == "weekly_scoped" and model else str(kind))
        windows.append(_win(label, lim.get("percent"), lim.get("resets_at"), severity=lim.get("severity")))
    if not windows:  # older response shape
        for key, label in (("five_hour", "5h"), ("seven_day", "7d"), ("seven_day_opus", "7d opus"),
                           ("seven_day_sonnet", "7d sonnet")):
            b = d.get(key)
            if isinstance(b, dict) and b.get("utilization") is not None:
                windows.append(_win(label, b["utilization"], b.get("resets_at")))
    credits = None
    ex = d.get("extra_usage")
    if isinstance(ex, dict):
        scale = 10 ** int(ex.get("decimal_places") or 2)
        used, limit = _num(ex.get("used_credits")), _num(ex.get("monthly_limit"))
        credits = {"extra_usage_enabled": bool(ex.get("is_enabled")), "currency": ex.get("currency"),
                   "used": None if used is None else used / scale,
                   "monthly_limit": None if limit is None else limit / scale}
    buckets = {k: {"used_usd": v.get("used_dollars"), "limit_usd": v.get("limit_dollars"),
                   "resets_at": _epoch(v.get("resets_at"))}
               for k, v in d.items() if isinstance(v, dict) and v.get("limit_dollars") is not None}
    if buckets:  # codenamed dollar budgets (e.g. a $250 monthly bucket); meaning not documented
        detail["dollar_buckets"] = buckets
    return _result("claude", plan=plan, windows=windows, credits=credits, source="api",
                   latency_ms=ms, detail=detail)


# ---------------------------------------------------------------- Codex (ChatGPT plan)

def _wham_windows(rl, prefix=""):
    out, now = [], time.time()
    for key in ("primary_window", "secondary_window"):
        w = (rl or {}).get(key)
        if isinstance(w, dict):
            reset = w.get("reset_at")
            if reset is None and w.get("reset_after_seconds") is not None:
                reset = now + float(w["reset_after_seconds"])
            out.append(_win(prefix + _dur(w.get("limit_window_seconds")), w.get("used_percent"), reset))
    return out


def _codex_credits(cr):
    if not isinstance(cr, dict):
        return None
    return {"has_credits": cr.get("has_credits"), "unlimited": cr.get("unlimited"), "balance": _num(cr.get("balance"))}


def _codex_from_wham(d, ms, detail):
    rl = d.get("rate_limit") or {}
    windows = _wham_windows(rl)  # label comes from the window length, not its slot
    if isinstance(d.get("code_review_rate_limit"), dict):
        windows += _wham_windows(d["code_review_rate_limit"], "review ")
    extra = d.get("additional_rate_limits")
    for item in (extra if isinstance(extra, list) else []):
        if isinstance(item, dict):
            name = item.get("limit_name") or item.get("metered_feature") or "extra"
            windows += _wham_windows(item.get("rate_limit") or item, "%s " % name)
    detail.update({"limit_reached": rl.get("limit_reached"), "allowed": rl.get("allowed"),
                   "rate_limit_reached_type": d.get("rate_limit_reached_type"),
                   "spend_control_reached": (d.get("spend_control") or {}).get("reached")})
    return _result("codex", plan=d.get("plan_type"), windows=windows, credits=_codex_credits(d.get("credits")),
                   source="api", latency_ms=ms, detail=detail)


def _newest_rollouts(root, limit=6):
    """Newest rollout files without a full recursive walk (sessions/YYYY/MM/DD/rollout-*)."""
    def subdirs(path):
        return sorted((p for p in os.listdir(path) if p.isdigit()), reverse=True)

    files, days = [], 0
    if os.path.isdir(root):
        for y in subdirs(root):
            for m in subdirs(os.path.join(root, y)):
                for dd in subdirs(os.path.join(root, y, m)):
                    day = os.path.join(root, y, m, dd)
                    got = [os.path.join(day, f) for f in os.listdir(day)
                           if f.startswith("rollout-") and f.endswith((".jsonl", ".jsonl.zst"))]
                    if got:  # scan 3 days: a long session started earlier may hold the newest write
                        files += got
                        days += 1
                    if days >= 3:
                        return sorted(files, key=os.path.getmtime, reverse=True)[:limit]
    return sorted(files, key=os.path.getmtime, reverse=True)[:limit]


def _rollout_lines_reversed(path, max_bytes=8 << 20):
    if path.endswith(".zst"):  # Linux Codex compresses finished rollouts; stdlib cannot read zstd
        if not shutil.which("zstd"):
            return
        try:
            out = subprocess.run(["zstd", "-dcq", path], capture_output=True, timeout=15).stdout
        except Exception:
            return
        for line in reversed(out.split(b"\n")):
            yield line
        return
    with open(path, "rb") as fh:  # plain .jsonl: read 64 KB blocks from the end
        fh.seek(0, 2)
        pos, buf, read = fh.tell(), b"", 0
        while pos > 0 and read < max_bytes:
            n = min(65536, pos)
            pos -= n
            fh.seek(pos)
            buf = fh.read(n) + buf
            read += n
            lines = buf.split(b"\n")
            buf = lines[0]
            for line in reversed(lines[1:]):
                yield line
        if buf:
            yield buf


def _codex_rollout_snapshot(home):
    """Zero-network fallback: the last token_count event's rate_limits in the newest rollout."""
    for path in _newest_rollouts(os.path.join(home, "sessions")):
        for line in _rollout_lines_reversed(path):
            if b'"rate_limits"' not in line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            p = ev.get("payload") or {}
            rl = p.get("rate_limits") or (p.get("info") or {}).get("rate_limits")
            if not rl:
                continue
            ts, now, windows = _epoch(ev.get("timestamp")), time.time(), []
            for key in ("primary", "secondary"):
                w = rl.get(key)
                if not isinstance(w, dict):
                    continue
                reset = w.get("resets_at")
                if reset is None and w.get("resets_in_seconds") is not None and ts:
                    reset = ts + float(w["resets_in_seconds"])
                win = _win(_dur((_num(w.get("window_minutes")) or 0) * 60), w.get("used_percent"), reset)
                if win["resets_at"] and win["resets_at"] < now:  # window rolled over since the snapshot
                    win.update(used_pct=None, note="reset since snapshot")
                windows.append(win)
            return _result("codex", plan=rl.get("plan_type"), windows=windows,
                           credits=_codex_credits(rl.get("credits")), source="rollout", as_of=ts,
                           detail={"snapshot_age_s": int(now - ts) if ts else None,
                                   "rate_limit_reached_type": rl.get("rate_limit_reached_type")})
    return None


def fetch_codex():
    home = os.environ.get("CODEX_HOME") or os.path.join(HOME, ".codex")
    auth = _read_json(os.path.join(home, "auth.json")) or {}
    tok = auth.get("tokens") or {}
    at, plan, detail = tok.get("access_token"), None, {}
    if at:
        claims = _jwt_claims(at)
        plan = (claims.get("https://api.openai.com/auth") or {}).get("chatgpt_plan_type")
        exp = int(claims.get("exp") or 0)
        detail["token_expires_at"] = exp
        if exp and exp < time.time() + 30:
            err = "ChatGPT access token expired %s (codex refreshes it on next use; not refreshing here)" % _fmt(exp)
        else:
            hdrs = {"Authorization": "Bearer " + at, "Accept": "application/json"}
            if tok.get("account_id"):
                hdrs["ChatGPT-Account-Id"] = tok["account_id"]
            status, d, ms = _http(CODEX_WHAM_URL, hdrs)
            if status == 200 and isinstance(d, dict):
                return _codex_from_wham(d, ms, detail)
            err = _err(status, d)
    elif auth.get("OPENAI_API_KEY"):
        err = "codex is on an API key (no ChatGPT plan limits)"
    else:
        err = "codex not logged in with ChatGPT"
    snap = _codex_rollout_snapshot(home)
    if snap:
        snap["detail"]["api_error"] = err
        return snap
    return _result("codex", plan=plan, error=err, detail=detail)


# ---------------------------------------------------------------- Cursor

def _cursor_tokens():
    """(access_token, source, plan) candidates: cursor-agent CLI first, then the desktop app."""
    out = []
    if sys.platform == "darwin":  # cursor-agent keychain store: account "cursor-user"
        raw, _ = _keychain("cursor-access-token", "cursor-user")
        if raw:
            out.append((raw, "cursor-agent keychain", None))
        auth_file = os.path.join(HOME, ".cursor", "auth.json")
        db = os.path.join(HOME, "Library/Application Support/Cursor/User/globalStorage/state.vscdb")
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(HOME, ".config")
        auth_file = os.path.join(xdg, "cursor", "auth.json")
        db = os.path.join(xdg, "Cursor/User/globalStorage/state.vscdb")
    tok = (_read_json(auth_file) or {}).get("accessToken")
    if tok:
        out.append((tok, "cursor-agent auth.json", None))
    if os.path.exists(db):
        try:
            con = sqlite3.connect("file:%s?mode=ro" % urllib.parse.quote(db), uri=True, timeout=3)
            try:
                kv = dict(con.execute("SELECT key, value FROM ItemTable WHERE key IN "
                                      "('cursorAuth/accessToken', 'cursorAuth/stripeMembershipType')"))
            finally:
                con.close()
            if kv.get("cursorAuth/accessToken"):
                out.append((kv["cursorAuth/accessToken"], "desktop state.vscdb",
                            kv.get("cursorAuth/stripeMembershipType")))
        except sqlite3.Error:
            pass
    return out


def _cents(v):
    v = _num(v)
    return None if v is None else round(v / 100.0, 2)


def _cursor_summary(token):
    """Fallback: the web dashboard endpoint (session cookie built from the same JWT)."""
    uid = str(_jwt_claims(token).get("sub", "")).split("|")[-1]
    cookie = "WorkosCursorSessionToken=" + urllib.parse.quote(uid + "::" + token, safe="")
    status, d, ms = _http(CURSOR_SUMMARY_URL, {"Cookie": cookie, "Accept": "application/json"})
    if status != 200 or not isinstance(d, dict):
        return None, _err(status, d), ms
    plan_u = (d.get("individualUsage") or {}).get("plan") or {}
    od = (d.get("individualUsage") or {}).get("onDemand") or {}
    end = d.get("billingCycleEnd")
    windows = [_win("total", plan_u.get("totalPercentUsed"), end), _win("auto", plan_u.get("autoPercentUsed"), end),
               _win("api", plan_u.get("apiPercentUsed"), end)]
    credits = {"included_used_usd": _cents(plan_u.get("used")), "included_limit_usd": _cents(plan_u.get("limit")),
               "bonus_usd": _cents((plan_u.get("breakdown") or {}).get("bonus")),
               "on_demand_used_usd": _cents(od.get("used")), "on_demand_enabled": od.get("enabled")}
    return _result("cursor", plan=d.get("membershipType"), windows=windows, credits=credits, source="api",
                   latency_ms=ms, detail={"cycle_start": _epoch(d.get("billingCycleStart")),
                                          "message": d.get("autoModelSelectedDisplayMessage")}), None, ms


def fetch_cursor():
    cands = _cursor_tokens()
    if not cands:
        return _result("cursor", error="no Cursor login (cursor-agent not logged in, no desktop app token)")
    live = [c for c in cands if (_jwt_claims(c[0]).get("exp") or 0) > time.time() + 30]
    if not live:
        exp = max(_jwt_claims(c[0]).get("exp") or 0 for c in cands)
        return _result("cursor", error="Cursor token expired %s; open Cursor or run `cursor-agent login`" % _fmt(exp))
    token, src, plan = live[0]
    detail = {"token_source": src, "token_expires_at": _jwt_claims(token).get("exp")}
    status, d, ms = _http(CURSOR_USAGE_URL, {"Authorization": "Bearer " + token, "Content-Type": "application/json",
                                             "Connect-Protocol-Version": "1"}, "POST", b"{}")
    if status != 200 or not isinstance(d, dict):
        res, err2, ms2 = _cursor_summary(token)
        if res:
            res["detail"].update(detail, api2_error=_err(status, d))
            return res
        return _result("cursor", plan=plan, latency_ms=ms + ms2, detail=detail,
                       error="%s; fallback %s" % (_err(status, d), err2))
    if not plan:  # cursor-agent tokens carry no cached plan; ask Stripe profile (whitelisted fields only)
        st, prof, ms2 = _http(CURSOR_PROFILE_URL, {"Authorization": "Bearer " + token})
        ms += ms2
        if st == 200 and isinstance(prof, dict):
            plan = prof.get("individualMembershipType") or prof.get("membershipType")
    pu, end = d.get("planUsage") or {}, d.get("billingCycleEnd")
    windows = [_win("total", pu.get("totalPercentUsed"), end), _win("auto", pu.get("autoPercentUsed"), end),
               _win("api", pu.get("apiPercentUsed"), end)]
    credits = {"included_used_usd": _cents(pu.get("includedSpend")), "included_limit_usd": _cents(pu.get("limit")),
               "bonus_usd": _cents(pu.get("bonusSpend")), "total_spend_usd": _cents(pu.get("totalSpend")),
               "on_demand_used_usd": _cents((d.get("spendLimitUsage") or {}).get("individualUsed"))}
    detail.update({"cycle_start": _epoch(d.get("billingCycleStart")), "message": d.get("displayMessage"),
                   "auto_message": d.get("autoModelSelectedDisplayMessage")})
    return _result("cursor", plan=plan, windows=windows, credits=credits, source="api", latency_ms=ms, detail=detail)


# ---------------------------------------------------------------- Grok Build CLI (grok.com plan)

def fetch_grok():
    """xAI "Grok Build" CLI (`grok`, x.ai/cli). Its /usage view calls GET <proxy>/v1/billing?format=credits.

    Path, headers and field names come from the grok 0.2.101 binary; the path is confirmed live
    (JSON 401 from the auth layer vs nginx 404 for neighbours) but no live session existed to
    confirm the 200 body, so parsing is defensive."""
    auth = _read_json(os.path.join(HOME, ".grok", "auth.json"))
    entries = [v for v in (auth or {}).values() if isinstance(v, dict) and v.get("key")]
    detail = {}
    if os.environ.get("XAI_API_KEY") or _secret("XAI_API_KEY"):
        detail["note"] = ("XAI_API_KEY is available (env or ~/.config/motd/env); per the grok README an exported "
                          "API key takes precedence over this login, so usage bills the xAI API team")
    if not entries:
        return _result("grok", detail=detail, error="grok CLI not logged in to grok.com (~/.grok/auth.json)")
    e = max(entries, key=lambda v: _epoch(v.get("expires_at")) or 0)
    claims = _jwt_claims(e["key"])
    plan = "tier %s" % claims["tier"] if claims.get("tier") is not None else None
    exp = _epoch(e.get("expires_at")) or int(claims.get("exp") or 0)
    detail.update({"token_expires_at": exp, "auth_mode": e.get("auth_mode")})
    if exp < time.time() + 30:
        return _result("grok", plan=plan, detail=detail, error=(
            "grok.com session expired %s (7-day tokens); run `grok login` (not refreshing here)" % _fmt(exp)))
    version = (_read_json(os.path.join(HOME, ".grok", "version.json")) or {}).get("version") or "0.2.101"
    status, d, ms = _http(GROK_BILLING_URL, {"Authorization": "Bearer " + e["key"], "X-XAI-Token-Auth": "xai-grok-cli",
                                             "x-grok-client-version": version, "Accept": "application/json"})
    if status != 200 or not isinstance(d, dict):
        return _result("grok", plan=plan, latency_ms=ms, detail=detail, error=_err(status, d))
    b = d.get("credits") if isinstance(d.get("credits"), dict) else d
    period = b.get("currentPeriod") if isinstance(b.get("currentPeriod"), dict) else {}
    end = period.get("end") or b.get("billingPeriodEnd")
    windows = []
    if b.get("creditUsagePercent") is not None:
        windows.append(_win(str(b.get("billingCycle") or "period"), b["creditUsagePercent"], end))
    credits = {k: b.get(k) for k in ("monthlyLimit", "includedUsed", "totalUsed", "onDemandCap", "onDemandUsed",
                                     "prepaidBalance", "on_demand_enabled", "isUnifiedBillingUser") if k in b}
    detail["response_keys"] = sorted(b.keys())[:20]
    return _result("grok", plan=b.get("subscription_tier") or plan, windows=windows, credits=credits or None,
                   source="api", latency_ms=ms, detail=detail)


# ---------------------------------------------------------------- xAI API team (management key)

def fetch_xai_api():
    """Prepaid balance + month-to-date postpaid spend for the xAI API team (needs BillingRead on the key)."""
    key = _secret("XAI_MGMT_KEY")
    if not key:
        return _result("xai_api", error="XAI_MGMT_KEY not set (env or ~/.config/motd/env)")
    hdrs = {"Authorization": "Bearer " + key, "Accept": "application/json"}
    st, v, ms = _http(XAI_MGMT_URL + "/auth/management-keys/validation", hdrs)
    if st != 200 or not isinstance(v, dict):
        return _result("xai_api", latency_ms=ms, error=_err(st, v))
    team = v.get("scopeId") if v.get("scope") == "SCOPE_TEAM" else v.get("teamId")
    if not team:
        return _result("xai_api", latency_ms=ms, error="management key is not team-scoped (scope=%s)" % v.get("scope"))
    base = "%s/v1/billing/teams/%s" % (XAI_MGMT_URL, urllib.parse.quote(team, safe=""))
    st_b, bal, ms_b = _http(base + "/prepaid/balance", hdrs)
    st_i, inv, ms_i = _http(base + "/postpaid/invoice/preview", hdrs)
    ms += ms_b + ms_i
    detail = {"key_acls": len(v.get("acls") or [])}
    if st_b != 200 and st_i != 200:
        err = _err(st_b, bal)
        if st_b == 403:
            err += " -> grant the management key billing read (console.x.ai > Settings > Management Keys)"
        return _result("xai_api", latency_ms=ms, detail=detail, error=err)
    # Amounts are integer US cents per the API reference; prepaid purchases are negative ledger values.
    credits, windows = {}, []
    if st_b == 200 and isinstance(bal, dict):
        total = _num((bal.get("total") or {}).get("val"))
        credits["prepaid_balance_usd"] = None if total is None else round(-total / 100.0, 2)
    if st_i == 200 and isinstance(inv, dict):
        ci = inv.get("coreInvoice") or {}
        spent = _num(ci.get("amountAfterVat"))
        limit = _num(inv.get("effectiveSpendingLimit"))
        credits.update({"postpaid_mtd_usd": _cents(spent), "spending_limit_usd": _cents(limit),
                        "prepaid_used_usd": _cents((ci.get("prepaidCreditsUsed") or {}).get("val"))})
        cyc = inv.get("billingCycle") or {}
        if limit and spent is not None and cyc.get("year") and cyc.get("month"):
            y, m = int(cyc["year"]), int(cyc["month"])
            nxt = datetime.datetime(y + (m == 12), m % 12 + 1, 1, tzinfo=datetime.timezone.utc)
            windows.append(_win("month", spent / limit * 100.0, int(nxt.timestamp())))
    return _result("xai_api", plan="xAI API team", windows=windows, credits=credits, source="api",
                   latency_ms=ms, detail=detail)


# ---------------------------------------------------------------- orchestration

FETCHERS = {"claude": fetch_claude, "codex": fetch_codex, "cursor": fetch_cursor,
            "grok": fetch_grok, "xai_api": fetch_xai_api}


def _safe(name):
    try:
        return FETCHERS[name]()
    except Exception as e:  # never let one provider break the collector
        return _result(name, error="internal %s: %s" % (type(e).__name__, _scrub(e)[:160]))


def fetch_all(names=None):
    names = list(names or FETCHERS)
    with ThreadPoolExecutor(max_workers=len(names)) as pool:
        return list(pool.map(_safe, names))


def run_remote(host, names=None, timeout=60):
    """Run this module on `host` over ssh (source on stdin); tokens stay on that host."""
    with open(os.path.abspath(__file__)) as fh:
        src = fh.read()
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._@-]*$", str(host)):  # an option-like name must never reach ssh
        return [_result(n, host=str(host)[:40], error="invalid peer name") for n in (names or FETCHERS)]
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "--", host, "python3", "-", "--json"] + list(names or FETCHERS)
    try:
        p = subprocess.run(cmd, input=src, capture_output=True, text=True, timeout=timeout)
        return json.loads(p.stdout)
    except Exception as e:
        return [_result(n, host=host, error="remote %s: %s" % (type(e).__name__, _scrub(e)[:120]))
                for n in (names or FETCHERS)]


def first_success(name, hosts=()):
    """Local first, then each ssh host. Claude and Codex share one account fleet-wide, so any
    host holding a live token answers for all of them."""
    res = _safe(name)
    tried = [res]
    for h in hosts:
        if res.get("error") is None:
            break
        res = run_remote(h, [name])[0]
        tried.append(res)
    if res.get("error") is not None:
        res["detail"]["tried"] = ["%s: %s" % (r.get("host"), (r.get("error") or "")[:80]) for r in tried]
    return res


def summary_line(r):
    def when(t):
        return time.strftime("%a %H:%M", time.localtime(t)) if t else "?"
    parts = ["%s %s%% (%s)" % (w["label"], "?" if w.get("used_pct") is None else ("%g" % w["used_pct"]),
                               when(w.get("resets_at"))) for w in r.get("windows") or []]
    tail = r["error"] if r.get("error") else " | ".join(parts)
    return "%-8s %-14s %-28s %-8s %6s  %s" % (r["provider"], r.get("host"), str(r.get("plan"))[:28],
                                             r.get("source") or "-", "%sms" % r.get("latency_ms") if r.get("latency_ms") is not None else "-", tail)


def main(argv):
    as_json = "--json" in argv
    host = argv[argv.index("--host") + 1] if "--host" in argv[:-1] else None
    names = [a for a in argv if a in FETCHERS] or list(FETCHERS)
    results = run_remote(host, names) if host else fetch_all(names)
    if as_json:
        print(json.dumps(results))
        return 0
    for r in results:
        print(summary_line(r))
    print(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

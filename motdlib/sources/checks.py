"""Config-driven checks: describe a thing to watch in config.json, no Python needed.

    "checks": [
      {"name": "api", "group": "services", "type": "http", "url": "https://example.com/healthz",
       "json": {"entries": "stats.entries"}, "show": "{status} · {entries} entries",
       "rules": [{"metric": "entries", "op": "falsy", "sev": "warn", "msg": "index is empty"}]},
      {"name": "backups", "type": "files", "glob": "/backups/*.tar.zst",
       "show": "{count} files · newest {newest_age_h}",
       "rules": [{"metric": "newest_age", "op": "gt", "value": 90000, "sev": "crit", "msg": "no backup in 25h"}]}
    ]

Types (what each puts in the metrics a `show` template and `rules` can use):
  http   GET a URL: status, ms, up, plus the `json` map {name: "a.b.0.c"} from the reply
  files  a glob: count, bytes, max_bytes, newest_age, recent_24h (and max_lines if named)
  jsonl  append-only JSON-lines events folded to the latest status per id: total, one
         counter per status value, events_24h. Keys: id, status, order (default "ts")
  command  an argv list (never a shell): exit, ok, stdout1; `parse` json|kv|lines adds
         more, and any kv value that is a unix timestamp also gets `<key>_age`
  tls    days_left, verify_error for host[:port] certificates (warn 14d, crit 5d)
  dns    resolved, addrs, ip, match (when `expect` is given) for `host`
  tcp    open, ms

Rules: {"metric", "op", "value", "sev": warn|crit, "msg"} with op lt le gt ge eq ne
truthy falsy missing. `msg` and `show` are str.format templates over the metrics, with
`<metric>_h` human forms (bytes, ages in seconds). Other keys: "hosts" (names or #tags
to run on), "ttl" seconds (default 300), "strikes" (consecutive failures before an alert,
default 2 for http/tcp/dns/tls, else 1), "group" (a panel `checks:<group>` shows it).
${VAR} in a url or header expands from the collector's env, so tokens stay in the env file.
"""
from __future__ import annotations

import collections
import glob
import json
import os
import re
import socket
import ssl
import string
import time

from .. import core
from ..registry import source

MAX_FILES, MAX_BYTES = 5000, 4 << 20
OPS = {
    "lt": lambda a, b: a is not None and a < b, "le": lambda a, b: a is not None and a <= b,
    "gt": lambda a, b: a is not None and a > b, "ge": lambda a, b: a is not None and a >= b,
    "eq": lambda a, b: a == b, "ne": lambda a, b: a != b,
    "truthy": lambda a, b: bool(a), "falsy": lambda a, b: not a, "missing": lambda a, b: a is None,
}
SEVS = ("warn", "crit")
_STRIKY = ("http", "tcp", "dns", "tls")


class _Safe(dict):
    def __missing__(self, key):
        return "?"


def fmt(template: str, metrics: dict) -> str:
    try:
        return string.Formatter().vformat(template, (), _Safe(metrics))
    except (ValueError, KeyError, IndexError, TypeError):
        return template


def _path(obj, path: str):
    """'a.b.0.c' → obj['a']['b'][0]['c'], None when any step is absent."""
    for part in str(path).split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list) and part.isdigit() and int(part) < len(obj):
            obj = obj[int(part)]
        else:
            return None
    return obj


def _human(metrics: dict) -> dict:
    out = dict(metrics)
    for k, v in metrics.items():
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            continue
        if k.endswith("age"):
            out[k + "_h"] = core.human_age(v)
        elif "bytes" in k:
            out[k + "_h"] = core.human_bytes(v)
    return out


def num(v, default: float) -> float:
    """A numeric config option; a typo ("5m") falls back to the default instead of raising."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return float(default)


def _expand(text, env) -> str:
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", lambda m: env.get(m.group(1), ""), str(text))


# ── runners: each returns a metrics dict (or raises) ────────────────────────
def run_http(c, env) -> dict:
    url = _expand(c.get("url", ""), env)
    if not url.startswith(("http://", "https://")):
        raise ValueError("url must be http(s)")
    hdrs = {k: _expand(v, env) for k, v in (c.get("headers") or {}).items()}
    try:
        r = core.http(url, headers=hdrs, timeout=min(num(c.get("timeout"), 8), 15))
    except Exception as e:  # noqa: BLE001 — DNS, refused, TLS, timeout: the endpoint is down, not the check broken
        return {"status": 0, "ms": 0, "up": False, "error": type(e).__name__}
    want = c.get("expect_status")
    m = {"status": r.status, "ms": r.ms, "up": (r.status == want) if want else 200 <= r.status < 400}
    for name, path in (c.get("json") or {}).items():
        m[name] = _path(r.body, path) if isinstance(r.body, (dict, list)) else None
    return m


def run_files(c, env) -> dict:
    paths = [p for p in glob.glob(os.path.expanduser(str(c.get("glob", ""))), recursive=True)[:MAX_FILES] if os.path.isfile(p)]
    stats = []
    for p in paths:
        try:
            st = os.stat(p)
        except OSError:
            continue
        stats.append((p, st.st_size, st.st_mtime))
    now = core.now()
    m = {"count": len(stats), "bytes": sum(s[1] for s in stats), "max_bytes": max((s[1] for s in stats), default=0),
         "newest_age": (now - max(s[2] for s in stats)) if stats else None,
         "oldest_age": (now - min(s[2] for s in stats)) if stats else None,
         "recent_24h": sum(1 for s in stats if now - s[2] < 86400)}
    if "lines" in json.dumps(c):
        m["max_lines"] = max((core.read_text(s[0], MAX_BYTES).count("\n") for s in stats), default=0)
    return m


def run_jsonl(c, env) -> dict:
    idk, stk, ordk = c.get("id", "id"), c.get("status", "status"), c.get("order", "ts")
    latest, events_24h, budget = {}, 0, 20 << 20
    cutoff = time.strftime("%Y-%m-%dT%H:%M", time.gmtime(time.time() - 86400))
    for p in sorted(glob.glob(os.path.expanduser(str(c.get("glob", ""))), recursive=True)[:MAX_FILES]):
        try:
            fh = open(p, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                budget -= len(line)
                if budget < 0:
                    break
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(e, dict) or e.get(idk) is None or e.get(stk) is None:
                    continue
                key = str(e.get(ordk, ""))
                cur = latest.get(e[idk])
                if cur is None or key >= cur[0]:
                    latest[e[idk]] = (key, str(e[stk]))
                if key >= cutoff:
                    events_24h += 1
    counts = collections.Counter(v[1] for v in latest.values())
    m = {"total": len(latest), "events_24h": events_24h}
    m.update(counts)
    return m


def run_command(c, env) -> dict:
    argv = c.get("argv")
    if not (isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv)):
        raise ValueError("argv must be a list of strings")
    rc, out, err = core.run(argv, timeout=min(num(c.get("timeout"), 10), 30))
    m = {"exit": rc, "ok": rc == 0, "stdout1": (out.strip().splitlines() or [""])[0][:200]}
    parse = c.get("parse")
    if parse == "json":
        try:
            body = json.loads(out)
        except ValueError:
            body = None
        for name, path in (c.get("json") or {}).items():
            m[name] = _path(body, path)
    elif parse == "kv":
        for line in out.splitlines():
            k, sep, v = line.partition("=")
            if sep:
                m[k.strip()] = v.strip()
                if re.match(r"^@?\d{9,10}$", v.strip()):
                    m[k.strip() + "_age"] = core.now() - int(v.strip().lstrip("@"))
    elif parse == "lines":
        m["lines"] = len(out.splitlines())
    if rc == 127:
        raise ValueError(err.strip() or "command not found")
    return m


def run_tls(c, env) -> dict:
    host, port = str(c.get("host", "")), int(num(c.get("port"), 443))
    ctx = ssl.create_default_context()
    m = {"days_left": None, "verify_error": None}
    try:
        with socket.create_connection((host, port), timeout=6) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
            m["days_left"] = int((ssl.cert_time_to_seconds(s.getpeercert()["notAfter"]) - core.now()) // 86400)
    except ssl.SSLCertVerificationError as e:
        m["verify_error"] = (e.verify_message or "verify failed")[:80]
    return m


def run_dns(c, env) -> dict:
    name = str(c.get("host", ""))
    try:
        addrs = sorted({a[4][0] for a in socket.getaddrinfo(name, None)})
    except OSError:
        addrs = []
    m = {"resolved": bool(addrs), "addrs": len(addrs), "ip": addrs[0] if addrs else ""}
    if c.get("expect") is not None:
        want = [c["expect"]] if isinstance(c["expect"], str) else list(c["expect"])
        m["match"] = bool(set(addrs) & set(want))
    return m


def run_tcp(c, env) -> dict:
    t0 = time.monotonic()
    try:
        socket.create_connection((str(c.get("host", "127.0.0.1")), int(num(c.get("port"), 0))), timeout=4).close()
        return {"open": True, "ms": int((time.monotonic() - t0) * 1000)}
    except OSError:
        return {"open": False, "ms": 0}


RUNNERS = {"http": run_http, "files": run_files, "jsonl": run_jsonl, "command": run_command,
           "tls": run_tls, "dns": run_dns, "tcp": run_tcp}
DEFAULT_SHOW = {"http": "{status} · {ms}ms", "files": "{count} files", "jsonl": "{total} items",
                "command": "{stdout1}", "tls": "{days_left} days left", "dns": "{ip}", "tcp": "{state_word} · {ms}ms"}


def default_rules(c) -> list:
    t = c.get("type")
    if t == "http":
        return [{"metric": "up", "op": "falsy", "sev": "crit", "msg": "%s is down (HTTP {status})" % c.get("name", "http")}]
    if t == "tcp":
        return [{"metric": "open", "op": "falsy", "sev": "crit", "msg": "%s is not accepting connections" % c.get("name", "tcp")}]
    if t == "dns":
        rules = [{"metric": "resolved", "op": "falsy", "sev": "crit", "msg": "%s does not resolve" % c.get("name", "dns")}]
        if c.get("expect") is not None:
            rules.append({"metric": "match", "op": "falsy", "sev": "warn", "msg": "%s resolves to {ip}, not the expected address" % c.get("name", "dns")})
        return rules
    if t == "tls":
        n = c.get("name", "tls")
        return [{"metric": "verify_error", "op": "truthy", "sev": "crit", "msg": "%s certificate: {verify_error}" % n},
                {"metric": "days_left", "op": "lt", "value": c.get("crit_days", 5), "sev": "crit", "msg": "%s certificate expires in {days_left} days" % n},
                {"metric": "days_left", "op": "lt", "value": c.get("warn_days", 14), "sev": "warn", "msg": "%s certificate expires in {days_left} days" % n}]
    if t == "command":
        return [{"metric": "ok", "op": "falsy", "sev": "warn", "msg": "%s exited {exit}" % c.get("name", "command")}]
    return []


def evaluate(c, metrics) -> tuple:
    """(state, [(sev, msg)]) from the check's rules (defaults per type when none are given)."""
    hit = []
    shown = fmt  # alias for readability below
    for r in c.get("rules") if c.get("rules") is not None else default_rules(c):
        op = OPS.get(r.get("op"))
        sev = r.get("sev") if r.get("sev") in SEVS else "warn"
        if not op:
            continue
        v = metrics.get(r.get("metric"))
        try:
            fired = op(v, r.get("value"))
        except TypeError:
            fired = False
        if v is None and r.get("op") not in ("missing", "falsy"):
            fired = False  # an absent metric is "unknown", not a threshold breach
        if fired:
            hit.append((sev, shown(r.get("msg") or "%s: %s %s %s" % (c.get("name"), r.get("metric"), r.get("op"), r.get("value")), _human(metrics))))
    state = "crit" if any(s == "crit" for s, _ in hit) else "warn" if hit else "ok"
    return state, hit


def applies(c, host) -> bool:
    want = c.get("hosts")
    return not want or any(h == host.name or h in host.tags for h in want)


def run_check(c, env, prev) -> dict:
    t = c.get("type")
    rec = {"name": str(c.get("name") or t), "group": c.get("group") or "", "type": t, "ts": core.now()}
    try:
        if t not in RUNNERS:
            raise ValueError("unknown check type %r" % t)
        metrics = RUNNERS[t](c, env)
    except Exception as e:  # noqa: BLE001 — a bad check must not take the others down
        rec.update(state="unknown", text=str(e)[:80], metrics={}, error=str(e)[:160], streak=0, alerts=[])
        return rec
    state, hits = evaluate(c, metrics)
    streak = (int((prev or {}).get("streak", 0)) + 1) if state != "ok" else 0
    strikes = int(num(c.get("strikes"), 2 if t in _STRIKY else 1))
    h = _human(metrics)
    h.setdefault("state_word", "open" if metrics.get("open") else "closed")
    rec.update(state=state, metrics={k: v for k, v in metrics.items() if isinstance(v, (str, int, float, bool, type(None)))},
               text=fmt(c.get("show") or DEFAULT_SHOW.get(t, ""), h), streak=streak,
               alerts=[{"sev": s, "msg": m} for s, m in hits] if streak >= strikes else [])
    return rec


def _wants_checks(host) -> bool:
    return any(p == "checks" or p.startswith("checks:") for p in host.panels)


@source("checks", ttl=60, timeout=30, hosts=_wants_checks)
def checks(ctx):
    """The config.json "checks" list: http, files, jsonl, command, tls, dns, tcp."""
    cfg = [c for c in core.config().get("checks") or [] if isinstance(c, dict) and applies(c, ctx.host)]
    prev = {(r.get("name"), r.get("type")): r for r in (ctx.prev or {}).get("results") or []}
    now = core.now()
    results, jobs = {}, {}
    for i, c in enumerate(cfg):
        old = prev.get((str(c.get("name") or c.get("type")), c.get("type")))
        if old and now - old.get("ts", 0) < num(c.get("ttl"), 300):
            results[i] = old
        else:
            jobs[i] = (lambda c=c, old=old: run_check(c, ctx.env, old))
    ran = core.parallel(jobs, timeout=24)
    for i, c in enumerate(cfg):
        results.setdefault(i, ran.get(i) or {"name": str(c.get("name") or c.get("type")), "group": c.get("group") or "",
                                              "type": c.get("type"), "ts": now, "state": "unknown", "text": "timed out",
                                              "metrics": {}, "streak": 0, "alerts": []})
    rows = [results[i] for i in range(len(cfg))]
    data = {"results": rows}
    al = [a for r in rows for a in r.get("alerts") or []]
    if al:
        data["alerts"] = al
    return data

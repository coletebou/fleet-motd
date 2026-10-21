"""Paths, cache records, machine identity, config, secrets, and process/HTTP helpers."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

HOME = os.path.expanduser("~")
CONFIG_DIR = os.environ.get("MOTD_CONFIG_DIR") or os.path.join(
    os.environ.get("XDG_CONFIG_HOME") or os.path.join(HOME, ".config"), "motd")
CACHE_DIR = os.environ.get("MOTD_CACHE_DIR") or os.path.join(HOME, ".cache", "motd", "v2")
SRC_DIR = os.path.join(CACHE_DIR, "src")
HUB_DIR = os.path.join(CACHE_DIR, "hub")
STATE_DIR = os.path.join(CACHE_DIR, "state")
LOCK_PATH = os.path.join(CACHE_DIR, "collect.lock")
SNAPSHOT_PATH = os.path.join(CACHE_DIR, "snapshot.json")
BUNDLE_PATH = os.path.join(HUB_DIR, "bundle.json")
LOG_PATH = os.path.join(CACHE_DIR, "collect.log")
IS_MAC = sys.platform == "darwin"


def now() -> float:
    return time.time()


def utc_epoch(stamp: str) -> int:
    """'2026-10-16T12:00:00…' (UTC; fractions and zone suffix ignored) → epoch secs, 0 if unparseable."""
    import calendar
    try:
        return calendar.timegm(time.strptime(stamp[:19], "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return 0


def ensure_dirs() -> None:
    for d in (CACHE_DIR, SRC_DIR, HUB_DIR, STATE_DIR):
        os.makedirs(d, mode=0o700, exist_ok=True)


def read_json(path: str):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def write_json_atomic(path: str, obj) -> None:
    tmp = "%s.tmp.%d" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, separators=(",", ":"), default=str)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def read_text(path: str, limit: int = 1 << 20) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def mtime(path: str) -> float:
    try:
        return os.stat(path).st_mtime
    except OSError:
        return 0.0


# ── Machine identity ────────────────────────────────────────────────────────
def machine_id() -> str:
    """MOTD_MACHINE if set (a collector under launchd/systemd has no shell profile),
    else the short hostname. Host profiles in config.json are keyed by this name."""
    return os.environ.get("MOTD_MACHINE") or socket.gethostname().split(".")[0].lower()


def config() -> dict:
    """~/.config/motd/config.json (MOTD_CONFIG_DIR overrides the directory); {} if absent."""
    cfg = read_json(os.path.join(CONFIG_DIR, "config.json"))
    return cfg if isinstance(cfg, dict) else {}


# ── Secrets ─────────────────────────────────────────────────────────────────
# ~/.config/motd/env holds `KEY=value` or `export KEY=value` lines (blank lines and
# `#` comments ignored; `$HOME` and `~` expand). It is parsed, never executed. Only
# the collector calls this; values never reach a cache file, a log line, or argv.
_SECRETS = None


def secrets() -> dict:
    global _SECRETS
    if _SECRETS is not None:
        return _SECRETS
    env = dict(os.environ)
    for line in read_text(os.environ.get("MOTD_ENV_FILE") or os.path.join(CONFIG_DIR, "env")).splitlines():
        line = line.strip()
        if line.startswith("export "):
            line = line[7:].lstrip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        env[k.strip()] = os.path.expanduser(v.replace("$HOME", HOME))
    _SECRETS = env
    return env


# ── Processes ───────────────────────────────────────────────────────────────
def run(argv, timeout: float = 4.0, env=None, input_text=None, cwd=None):
    """Run argv, never raising. Returns (rc, stdout, stderr); rc 124 = timeout."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           env=env, input=input_text, cwd=cwd, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found: %s" % argv[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %.1fs" % timeout
    except OSError as e:
        return 126, "", str(e)


def which(name: str, extra=()):
    """shutil.which plus the places launchd/systemd PATHs leave out."""
    import shutil
    found = shutil.which(name)
    if found:
        return found
    for d in (os.path.join(HOME, ".local/bin"), "/opt/homebrew/bin", "/usr/local/bin",
              "/usr/bin", "/bin", "/usr/sbin", "/snap/bin") + tuple(extra):
        p = os.path.join(d, name)
        if os.access(p, os.X_OK):
            return p
    return None


# ── HTTP ────────────────────────────────────────────────────────────────────
class Resp:
    __slots__ = ("status", "body", "ms", "headers")

    def __init__(self, status, body, ms, headers=None):
        self.status, self.body, self.ms, self.headers = status, body, ms, headers or {}

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


def http(url, method="GET", headers=None, data=None, json_body=None, timeout=6.0,
         basic=None, raw=False) -> Resp:
    """Small urllib wrapper. Raises on transport errors (DNS, TLS, timeout);
    HTTP errors come back as a Resp with the status so callers can branch."""
    import base64
    import urllib.error
    import urllib.parse
    import urllib.request
    hdrs = {"User-Agent": "fleet-motd/1", "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode()
        hdrs["Content-Type"] = "application/json"
    elif data is not None:
        body = data if isinstance(data, bytes) else urllib.parse.urlencode(data).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    if basic:
        tok = base64.b64encode(("%s:%s" % basic).encode()).decode()
        hdrs["Authorization"] = "Basic " + tok
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload, status, rh = r.read(), r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        payload, status, rh = (e.read() or b""), e.code, dict(e.headers or {})
    ms = int((time.monotonic() - t0) * 1000)
    if raw:
        return Resp(status, payload, ms, rh)
    text = payload.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text) if text.strip() else None
    except ValueError:
        parsed = text
    return Resp(status, parsed, ms, rh)


# ── Formatting ──────────────────────────────────────────────────────────────
def human_age(seconds: float, suffix: str = "") -> str:
    s = int(max(0, seconds))
    if s < 60:
        out = "%ds" % s
    elif s < 3600:
        out = "%dm" % (s // 60)
    elif s < 86400:
        h, m = divmod(s // 60, 60)
        out = "%dh%02dm" % (h, m) if h < 10 and m else "%dh" % h
    elif s < 86400 * 14:
        d, h = divmod(s // 3600, 24)
        out = "%dd%dh" % (d, h) if h and d < 3 else "%dd" % d
    else:
        out = "%dw" % (s // (86400 * 7))
    return out + suffix


def human_bytes(n: float, unit: str = "") -> str:
    n = float(n or 0)
    for u in ("B", "K", "M", "G", "T", "P"):
        if abs(n) < 1024 or u == "P":
            if u == "B":
                return "%d%s" % (n, unit or "B")
            return ("%.1f%s" % (n, u)) if n < 10 else ("%.0f%s" % (n, u))
        n /= 1024.0


def human_num(n: float) -> str:
    n = float(n or 0)
    for div, suf in ((1e9, "B"), (1e6, "M"), (1e3, "k")):
        if abs(n) >= div:
            v = n / div
            return ("%.1f%s" % (v, suf)) if v < 10 else ("%.0f%s" % (v, suf))
    return "%d" % n


def money(n, cur: str = "$") -> str:
    if n is None:
        return "?"
    n = float(n)
    if abs(n) >= 1000:
        return "%s%s" % (cur, human_num(n))
    return ("%s%.2f" % (cur, n)) if abs(n) < 100 else ("%s%.0f" % (cur, n))


def pct(used, total) -> float:
    try:
        return 100.0 * float(used) / float(total) if total else 0.0
    except (TypeError, ValueError):
        return 0.0


def parallel(jobs: dict, timeout: float = 3.0) -> dict:
    """Run zero-arg callables concurrently (subprocess waits release the GIL).
    Plain threads: concurrent.futures drags in logging (~4 ms of import)."""
    import threading
    res = {}

    def runner(key, fn):
        try:
            res[key] = fn()
        except Exception:  # noqa: BLE001 — a failed probe renders as missing
            res[key] = None
    threads = [threading.Thread(target=runner, args=(k, f), daemon=True) for k, f in jobs.items()]
    for t in threads:
        t.start()
    deadline = time.monotonic() + timeout
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    return res

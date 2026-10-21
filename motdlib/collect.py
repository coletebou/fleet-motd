"""The collector: run due sources concurrently, write one record each.

Single instance per host (flock). Each source enforces its own I/O timeouts;
the run as a whole has a deadline, after which unfinished threads are
abandoned (the process exits with os._exit so a hung socket can't pin it).
A failed source keeps its last good data, marked ok=false with the error, so
the dashboard degrades to "stale" instead of going blank.
"""
from __future__ import annotations

import fcntl
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, wait

from . import core, registry
from .registry import SOURCES, Ctx, applies, src_path

DEADLINE = float(os.environ.get("MOTD_COLLECT_DEADLINE", "50"))


def _redact(text: str, env: dict) -> str:
    """Belt and braces: scrub any secret-looking env value from error text."""
    if not text:
        return text
    for k, v in env.items():
        if v and len(v) >= 12 and v in text and any(s in k for s in ("KEY", "TOKEN", "SECRET", "PASS", "AUTH")):
            text = text.replace(v, "<redacted:%s>" % k)
    return text[:300]


def _soft_failure(data) -> bool:
    """A result that reports its own failure instead of raising: the vendored
    probes return {error, status: unknown} or {error, windows: []}."""
    if not isinstance(data, dict) or not data.get("error"):
        return False
    if "windows" in data:
        return not data.get("windows")
    return data.get("status") in (None, "unknown")


def is_due(src, host, now, cache) -> bool:
    rec = core.read_json(src_path(src.name))
    if src.scope == "global" and not host.hub:
        hub_rec = (cache.bundle.get("sources") or {}).get(src.name)
        if hub_rec and now - hub_rec.get("ts", 0) < src.fallback:
            return False
    if not rec:
        return True
    age = now - rec.get("ts", 0)
    if rec.get("skip"):
        return age >= 6 * 3600
    # Soft failures (expired login, send-only key) are not transient: normal cadence.
    return age >= (src.ttl if rec.get("ok") or rec.get("soft") else src.retry)


def run_one(src, host, env) -> dict:
    prev = core.read_json(src_path(src.name)) or {}
    missing = registry.missing_env(src, env)
    t0 = time.monotonic()
    rec = {"v": 2, "name": src.name, "host": host.name}
    if missing:
        rec.update(ok=False, skip=True, error="missing env: " + ", ".join(missing), data=prev.get("data"))
    else:
        try:
            data = src.fn(Ctx(host, env, prev.get("data")))
            if not _soft_failure(data):
                rec.update(ok=True, data=data, last_ok=core.now())
            else:
                # Keep the last good reading (marked kept) across consecutive soft failures.
                keep = prev.get("data") if (prev.get("ok") or prev.get("kept")) else None
                rec.update(ok=False, soft=True, kept=keep is not None,
                           error=_redact(str(data.get("error")), env)[:200],
                           data=keep if keep is not None else data, last_ok=prev.get("last_ok"),
                           fails=int(prev.get("fails", 0)) + 1)
        except Exception as e:  # noqa: BLE001 — a source must never take the run down
            rec.update(ok=False, error=_redact("%s: %s" % (type(e).__name__, e), env),
                       data=prev.get("data"), last_ok=prev.get("last_ok"), fails=int(prev.get("fails", 0)) + 1)
    rec["ts"] = core.now()
    rec["ms"] = int((time.monotonic() - t0) * 1000)
    core.write_json_atomic(src_path(src.name), rec)
    return rec


def _lock():
    core.ensure_dirs()
    fh = open(core.LOCK_PATH, "a+")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    return fh


def lock_free() -> bool:
    fh = _lock()
    if fh is None:
        return False
    fh.close()
    return True


def _log(line: str) -> None:
    try:
        if core.mtime(core.LOG_PATH) and os.path.getsize(core.LOG_PATH) > 256 * 1024:
            os.replace(core.LOG_PATH, core.LOG_PATH + ".1")
        with open(core.LOG_PATH, "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%S ") + line + "\n")
    except OSError:
        pass


PHASE2 = ("fleet",)  # needs this run's fresh records + snapshot first


def collect(force=False, only=None, quiet=True) -> int:
    fh = _lock()
    if fh is None:
        if not quiet:
            print("motd: a collector is already running", file=sys.stderr)
        return 0
    from . import hosts, snapshot, sources  # noqa: F401 — importing sources registers them
    host = hosts.current()
    env = core.secrets()
    cache = registry.Cache()
    now = core.now()
    picked = set(only or ())
    todo = [s for s in SOURCES.values()
            if applies(s, host) and s.name not in PHASE2 and (not picked or s.name in picked)
            and (force or picked or is_due(s, host, now, cache))]
    t0 = time.monotonic()
    scheduled = len(todo)
    ex = ThreadPoolExecutor(max_workers=10)
    futs = {ex.submit(run_one, s, host, env): s for s in todo}
    done, pending = wait(futs, timeout=DEADLINE)
    results = [f.result() for f in done]
    try:
        snapshot.write(host)
    except Exception as e:  # noqa: BLE001
        _log("snapshot failed: %s" % e)
    fleet = SOURCES.get("fleet")
    if fleet and applies(fleet, host) and (not picked or "fleet" in picked) \
            and (force or picked or is_due(fleet, host, now, registry.Cache())):
        left = max(8.0, DEADLINE - (time.monotonic() - t0))
        scheduled += 1
        f2 = ex.submit(run_one, fleet, host, env)
        d2, p2 = wait([f2], timeout=left)
        results += [f.result() for f in d2]
        pending |= p2
    took = time.monotonic() - t0
    errs = ["%s: %s" % (r["name"], r.get("error")) for r in results if not r.get("ok") and not r.get("skip")]
    _log("ran %d/%d sources in %.1fs%s%s" % (
        len(results), scheduled, took,
        " · timed out: " + ",".join(futs[f].name for f in pending if f in futs) if pending else "",
        " · errors: " + " | ".join(errs) if errs else ""))
    try:
        from . import notify
        nres = notify.run(host, registry.Cache(), env)
        if nres["sent"] or nres["errors"]:
            _log("notify: %d event(s)%s" % (nres["sent"], " · errors: " + "; ".join(nres["errors"]) if nres["errors"] else ""))
    except Exception as e:  # noqa: BLE001 — notifications must never break collection
        _log("notify failed: %s" % e)
    if not quiet:
        for r in sorted(results, key=lambda r: r["name"]):
            state = "ok  " if r.get("ok") else ("skip" if r.get("skip") else "FAIL")
            print("%-4s %-18s %6dms  %s" % (state, r["name"], r.get("ms", 0), r.get("error") or ""))
        for f in pending:
            print("TIME %-18s (abandoned at deadline)" % (futs[f].name if f in futs else "fleet"))
        print("— %d sources in %.1fs" % (len(results), took))
    sys.stdout.flush()
    if pending:
        os._exit(0)  # a stuck thread must not keep the process alive
    ex.shutdown(wait=False)
    fh.close()
    return 0


def spawn_background() -> bool:
    """Fire-and-forget `motd collect` for the login path (stale-while-revalidate).
    Rate-limited so twenty tmux panes opening at once spawn one collector."""
    import subprocess
    stamp = os.path.join(core.STATE_DIR, "last_spawn")
    if core.now() - core.mtime(stamp) < 30 or not lock_free():
        return False
    try:
        core.ensure_dirs()
        with open(stamp, "w") as f:
            f.write(str(int(core.now())))
        entry = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "motd.py")
        log = open(core.LOG_PATH, "a")
        subprocess.Popen([sys.executable, "-I", entry, "collect", "--quiet"], stdin=subprocess.DEVNULL,
                         stdout=log, stderr=log, start_new_session=True, close_fds=True)
        return True
    except OSError:
        return False

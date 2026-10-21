"""Source registry and the cache view the renderer reads.

A source is a function decorated with @source(...). It receives a Ctx and
returns a JSON-able dict; it may include "alerts": [{"sev", "msg"}] and must
never put a credential in its result. Scopes:
  local  — about this host; every host collects its own.
  global — about the fleet or a SaaS account; the hub collects it and ships it
           to peers in hub/bundle.json. A peer falls back to collecting a
           global source itself only when the hub copy is older than
           `fallback` seconds and the peer has the credentials.

Config: a source named in config.json's "disable" list never runs; one in
"enable" runs even if it is opt-in (`optin=True`, used by sources that read a
local login token, such as the Claude and Codex usage probes).
"""
from __future__ import annotations

import os

from . import core

SOURCES = {}

class Source:
    def __init__(self, name, fn, ttl, timeout, scope, hosts, needs, retry, fallback, desc, optin=False, needs_any=()):
        self.name, self.fn, self.ttl, self.timeout = name, fn, ttl, timeout
        self.scope, self.hosts, self.needs = scope, hosts, tuple(needs)
        self.retry = retry if retry is not None else min(ttl, 180)
        self.fallback = fallback if fallback is not None else max(3 * ttl, 2700)
        self.desc = desc
        self.optin = optin
        self.needs_any = tuple(needs_any)


def source(name, ttl=600, timeout=10.0, scope="local", hosts=None, needs=(), retry=None,
           fallback=None, desc="", optin=False, needs_any=()):
    """hosts: None (everywhere), a tuple of machine ids and/or #tags, or a callable(host).
    optin: off unless config.json "enable" lists it.
    needs: env keys that must all be set; needs_any: at least one of these must be.
    timeout: the source's expected worst case. Threads cannot be preempted, so each
    source enforces its own I/O timeouts (core.http/run); `motd doctor` flags
    runs that overshoot this budget and the collector deadline caps them all."""
    def deco(fn):
        SOURCES[name] = Source(name, fn, ttl, timeout, scope, hosts, needs, retry, fallback,
                               desc or (fn.__doc__ or "").strip().split("\n")[0], optin, needs_any)
        return fn
    return deco


def missing_env(src, env) -> list:
    """Env keys that keep a source from running: any of `needs` unset, or none of `needs_any` set."""
    miss = [k for k in src.needs if not env.get(k)]
    if src.needs_any and not any(env.get(k) for k in src.needs_any):
        miss.append("one of " + "/".join(src.needs_any))
    return miss


def serves(src, host) -> bool:
    """The source is switched on in config.json (opt-in sources must be enabled)."""
    cfg = core.config()
    if src.name in (cfg.get("disable") or ()):
        return False
    return not src.optin or src.name in (cfg.get("enable") or ())


def applies(src, host) -> bool:
    if not serves(src, host):
        return False
    if src.hosts is None:
        return True
    if callable(src.hosts):
        return bool(src.hosts(host))
    return any(h == host.name or h in host.tags for h in src.hosts)


class Ctx:
    """What a source sees: its host profile, the merged env (shell + secrets),
    and its own previous data (for deltas and history rings)."""

    def __init__(self, host, env, prev):
        self.host, self.env, self.prev = host, env, prev or {}

    http = staticmethod(core.http)


def src_path(name: str) -> str:
    return os.path.join(core.SRC_DIR, name + ".json")


class Cache:
    """Read-only view over local records and the hub bundle; picks the freshest."""

    def __init__(self):
        self._recs = {}
        self.bundle = core.read_json(core.BUNDLE_PATH) or {}

    def rec(self, name):
        src = SOURCES.get(name)
        if src is not None and not serves(src, None):  # switched off in config: show nothing, not stale data
            return None
        if name not in self._recs:
            local = core.read_json(src_path(name))
            hub = (self.bundle.get("sources") or {}).get(name)
            cands = [r for r in (local, hub) if isinstance(r, dict) and r.get("data") is not None]
            # Prefer a successful record whose data carries no soft error (a peer's
            # "token expired" must not shadow the hub's live usage); then the newest.
            cands.sort(key=lambda r: (bool(r.get("ok")),
                                      not (isinstance(r.get("data"), dict) and r["data"].get("error")),
                                      r.get("ts", 0)), reverse=True)
            self._recs[name] = cands[0] if cands else (local if isinstance(local, dict) else None)
        return self._recs[name]

    def data(self, name, default=None):
        r = self.rec(name)
        d = r.get("data") if r else None
        return d if d is not None else default

    def age(self, name) -> float:
        r = self.rec(name)
        return core.now() - r.get("ts", 0) if r else 1e12

    def error(self, name):
        r = self.rec(name)
        return None if not r or r.get("ok") else (r.get("error") or "failed")

    def fleet_hosts(self, hub: bool) -> dict:
        """The fleet table: the hub's own `fleet` record, or a peer's copy from the bundle."""
        if hub:
            return (self.data("fleet") or {}).get("hosts") or {}
        return (self.bundle.get("fleet") or {}).get("hosts") or {}

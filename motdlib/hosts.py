"""Host profiles, read from ~/.config/motd/config.json.

A profile is keyed by the machine name (`MOTD_MACHINE`, else the short hostname):

    {"hosts": {"my-server": {"label": "server", "banner": "default", "tags": ["#linux", "#server"],
        "peers": ["my-laptop"], "repos": ["~/code/app"], "weather": false,
        "units": [["nginx", "nginx", "system"], ["myapp", "app", "user"]],
        "agents": [["com.example.job", "job"]], "mounts": ["/", "/data"],
        "ports": [[3000, "api"]], "accent": ["sky", "violet", "rose"],
        "panels": ["system", "services", "agents", "fleet", "repo"]}}}

`units` are [unit, label, scope] with scope "system" or "user"; several units may
share a label (shown as one cell). `agents` are launchd labels on a Mac (a label
ending in ".*" matches every loaded job with that prefix). The host tagged `#hub`
collects the global (SaaS) sources and ships them to its `peers` over ssh.
A host with no profile gets a generic one, so a bare install still renders.
"""
from __future__ import annotations

import os

import re

from . import core, theme

# Gradient stops (see theme.PALETTE) used when a profile has no "accent".
DEFAULT_ACCENT = ("gold_l", "gold", "amber")
DEFAULT_PANELS = ["system", "services", "agents", "fleet", "repo"]


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]*$")  # a peer is an ssh destination: never option-like


def _accent(raw):
    """Palette names (or [r, g, b]) from config; a typo falls back instead of crashing every login."""
    stops = [s for s in (raw or ()) if (isinstance(s, str) and s in theme.PAL) or
             (isinstance(s, (list, tuple)) and len(s) == 3 and all(isinstance(c, int) for c in s))]
    return tuple(tuple(s) if isinstance(s, list) else s for s in stops) if len(stops) >= 2 else DEFAULT_ACCENT


def _rows(raw, n, ok=lambda r: True):
    """Config list-of-lists entries with exactly n fields that pass `ok`; malformed ones are dropped."""
    return [tuple(r) for r in raw or () if isinstance(r, (list, tuple)) and len(r) == n and ok(r)]


class Host:
    def __init__(self, name: str, prof: dict):
        self.name = name
        self.label = prof.get("label", name)
        self.banner = prof.get("banner")
        self.tags = set(prof.get("tags", ()))
        self.hub = "#hub" in self.tags
        self.peers = [p for p in prof.get("peers", ()) if isinstance(p, str) and _NAME.match(p)]
        self.repos = [os.path.expanduser(p) for p in prof.get("repos", ())]
        self.weather = bool(prof.get("weather", False))
        self.units = _rows(prof.get("units"), 3, lambda u: u[2] in ("system", "user"))
        self.agents = _rows(prof.get("agents"), 2)
        self.mounts = list(prof.get("mounts", ["/"]))
        self.panels = list(prof.get("panels", DEFAULT_PANELS))
        self.ports = _rows(prof.get("ports"), 2, lambda p: isinstance(p[0], int))   # (port, label) served on loopback
        self.reach = prof.get("reach") or {}                      # per-host override of config "reach"
        self.hints = tuple(prof.get("hints", ("ai", "fleet", "alerts", "doctor")))
        self.compact = tuple(prof.get("compact", ("system", "services", "agents", "fleet")))
        self.accent = _accent(prof.get("accent"))

    @property
    def server(self) -> bool:
        return "#server" in self.tags


def current() -> Host:
    name = core.machine_id()
    cfg = core.config()
    prof = (cfg.get("hosts") or {}).get(name)
    if prof is None:
        tags = {"#mac" if core.IS_MAC else "#linux"}
        if os.path.isdir("/mnt/c/Windows"):
            tags.add("#wsl")
        prof = dict(label=name, tags=sorted(tags | {"#dev"}))
    return Host(name, prof)


def fleet_order() -> list:
    """Display order of the fleet table (config "fleet_order"); unlisted hosts follow, sorted."""
    return list(core.config().get("fleet_order") or [])


def short(name: str) -> str:
    """Short display name for a host (config "short": {"long-hostname": "short"})."""
    return (core.config().get("short") or {}).get(name, name)

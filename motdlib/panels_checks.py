"""The `checks` panel (every check) and `checks:<group>` (one group), from sources/checks.py."""
from __future__ import annotations

from . import core, theme as T
from .panels import builder, kv
from .render import Panel


def build(x, group=None):
    data = x.cache.data("checks")
    if not data:
        return None
    rows_in = [r for r in data.get("results") or [] if group is None or r.get("group") == group]
    if not rows_in:
        return None
    w = min(14, max(len(r["name"]) for r in rows_in))
    rows, lvl = [], "ok"
    for r in rows_in:
        st = r.get("state", "unknown")
        lvl = T.worst(lvl, st if st in ("warn", "crit") else "ok")
        text = r.get("text") or ""
        rows.append(T.dot(st) + " " + T.dim(r["name"][:w].ljust(w)) + " " + (T.c(text, "red" if st == "crit" else "amber") if st in ("warn", "crit") else text))
    return Panel("checks", (group or "checks").upper(), rows, lvl, x.stale_note("checks", 4, 900))


@builder("checks")
def p_checks(x):
    return build(x)


def group_builder(group):
    return lambda x: build(x, group)

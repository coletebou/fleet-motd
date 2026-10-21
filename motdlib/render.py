"""Layout: gradient banner + side facts, attention strip, masonry panel grid, footer.

Width-adaptive: 3 columns ≥ ~180 cols, 2 ≥ ~118, otherwise 1; below 70
columns the banner and side facts collapse to a title line (phone SSH).
"""
from __future__ import annotations

import os
import shutil
import time

from . import alerts, core, registry, theme as T

GAP = 3
MIN_COL = 58


class Panel:
    def __init__(self, key, title, lines, level="ok", note=""):
        self.key, self.title, self.lines, self.level, self.note = key, title, lines, level, note

    def render(self, cw: int, accent) -> list:
        title = T.c(self.title, T.gradient(accent, 0.15), bold=True)
        note = T.dim(self.note) if self.note else ""
        mark = (" " + T.dot(self.level)) if self.level in ("warn", "crit") else ""
        rule_w = cw - T.width(title) - T.width(mark) - T.width(note) - (3 if note else 2)
        head = " " + title + mark + " " + T.rule(max(2, rule_w)) + ((" " + note) if note else "")
        return [head] + [" " + T.fit(l, cw - 1) for l in self.lines]


class RCtx:
    """Everything a panel builder needs."""

    def __init__(self, host, cache, lv, al, cw):
        self.host, self.cache, self.lv, self.alerts, self.cw = host, cache, lv, al, cw
        self.v = lv["vitals"]

    def stale_note(self, name, ttl_mult=4, floor=1800) -> str:
        """'12m' when a source is older than expected, '✖ 3h' when its last run failed."""
        rec = self.cache.rec(name)
        if not rec:
            return "no data"
        age = core.now() - rec.get("ts", 0)
        if not rec.get("ok") and not rec.get("skip"):
            since = core.now() - (rec.get("last_ok") or rec.get("ts", 0))
            return "✖ " + core.human_age(since)
        src = registry.SOURCES.get(name)
        ttl = src.ttl if src else 600
        return core.human_age(age) if age > max(ttl * ttl_mult, floor) else ""


def term_width() -> int:
    env = os.environ.get("MOTD_WIDTH")
    if env and env.isdigit():
        return int(env)
    return max(40, min(220, shutil.get_terminal_size((120, 40)).columns))


def layout(width: int):
    n = max(1, min(3, (width + GAP) // (MIN_COL + GAP)))
    if n == 3 and width < 180:
        n = 2
    cw = (width - (n - 1) * GAP) // n
    return n, cw


def grid(panels, width, accent) -> list:
    n, cw = layout(width)
    cols, heights = [[] for _ in range(n)], [0] * n
    for p in panels:
        block = p.render(cw, accent) + [""]
        i = heights.index(min(heights))
        cols[i] += block
        heights[i] += len(block)
    tall = max(heights) if heights else 0
    out = []
    for r in range(tall):
        cells = [T.pad(col[r] if r < len(col) else "", cw) for col in cols]
        out.append((" " * GAP).join(cells).rstrip())
    while out and not out[-1].strip():
        out.pop()
    return out


# ── Header ──────────────────────────────────────────────────────────────────
BUNDLED_BANNERS = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "banners")


def _banner_text(name: str) -> str:
    """A profile's "banner" is a name: ~/.config/motd/banners/<name>.txt wins over the bundled one."""
    for d in (os.path.join(core.CONFIG_DIR, "banners"), BUNDLED_BANNERS):
        txt = core.read_text(os.path.join(d, name + ".txt"))
        if txt:
            return txt
    return ""


def banner_lines(host) -> list:
    lines = [l.rstrip() for l in _banner_text(host.banner).splitlines()] if host.banner else []
    while lines and not lines[-1].strip():
        lines.pop()
    while lines and not lines[0].strip():
        lines.pop(0)
    return [l.rstrip() for l in lines]


def paint(lines, stops) -> list:
    """Diagonal gradient in truecolor, one color per row otherwise."""
    if not lines:
        return []
    rows, cols = len(lines), max(T.width(l) for l in lines)
    out = []
    for r, line in enumerate(lines):
        if T.MODE != "truecolor":
            out.append(T.c(line, T.gradient(stops, r / max(1, rows - 1))))
            continue
        buf, last = [], None
        for ci, ch in enumerate(line):
            if ch == " ":
                buf.append(ch)
                continue
            rgb = T.gradient(stops, 0.7 * ci / max(1, cols - 1) + 0.3 * r / max(1, rows - 1))
            if rgb != last:
                buf.append(T.fg(rgb))
                last = rgb
            buf.append(ch)
        out.append("".join(buf) + T.RESET)
    return out


def _clock(host) -> str:
    t = time.time()
    if host.server:
        utc = time.strftime("%a %b %d · %H:%M UTC", time.gmtime(t))
        try:
            from zoneinfo import ZoneInfo
            import datetime
            cfg = core.config()
            tz = cfg.get("tz") or (cfg.get("weather") or {}).get("tz")
            if not tz:
                return utc
            local = datetime.datetime.fromtimestamp(t, ZoneInfo(tz)).strftime("%H:%M %Z")
            return utc + T.dim("  ·  " + local)
        except Exception:  # noqa: BLE001
            return utc
    return time.strftime("%a %b %d · %H:%M %Z", time.localtime(t)) + T.dim(time.strftime("  ·  %H:%M UTC", time.gmtime(t)))


def side_facts(host, cache, lv, al, last_seen) -> list:
    v = lv["vitals"]
    mid = T.gradient(host.accent, 0.5)
    facts = [T.c("◆ ", mid) + T.c(host.name, mid, bold=True) + T.dim("  ·  " + str(v.get("os", "")))]
    facts.append(_clock(host))
    w = cache.data("weather") if host.weather else None
    if w and w.get("temp") is not None:
        bits = ["%s %s°%s %s" % (w.get("icon", ""), w["temp"], w.get("unit", "F"), w.get("desc", ""))]
        if w.get("hi") is not None:
            bits.append(T.dim("H ") + "%s" % w["hi"] + T.dim(" L ") + "%s" % w["lo"])
        if w.get("rain"):
            bits.append("%s%% rain" % w["rain"])
        if w.get("sunset"):
            bits.append(T.dim("sunset ") + w["sunset"])
        facts.append(T.dim(" · ").join(bits))
    ts = cache.data("tailscale") or {}
    ipbits = [T.dim("up ") + core.human_age(v.get("uptime", 0))]
    if ts.get("ip"):
        ipbits.append(T.dim("ts ") + ts["ip"])
    if v.get("ip"):
        ipbits.append(T.dim("ip " if host.server else "lan ") + v["ip"])
    facts.append(T.dim(" · ").join(ipbits))
    nc = sum(1 for a in al if a["sev"] == "crit")
    nw = sum(1 for a in al if a["sev"] == "warn")
    if nc or nw:
        parts = []
        if nc:
            parts.append(T.c("● %d critical" % nc, "red", bold=True))
        if nw:
            parts.append(T.c("● %d warning%s" % (nw, "" if nw == 1 else "s"), "amber"))
        facts.append("  ".join(parts))
    else:
        facts.append(T.c("✔ all systems nominal", "green", bold=True))
    snap_mtime = core.mtime(core.SNAPSHOT_PATH)
    data_age = core.now() - snap_mtime if snap_mtime else None
    tail = []
    if last_seen:
        fresh = sum(1 for a in al if a.get("new") and a["sev"] in ("crit", "warn"))
        tail.append(T.dim("last visit ") + core.human_age(core.now() - last_seen, " ago") +
                    (T.dim(" · ") + T.c("%d new alert%s" % (fresh, "" if fresh == 1 else "s"), "sky", bold=True) if fresh else ""))
    if data_age is None:
        tail.append(T.c("collecting first data…", "sky"))
    elif data_age > 900:
        tail.append(T.c("data %s old · refreshing" % core.human_age(data_age), "amber"))
    if tail:
        facts.append(T.dim(" · ").join(tail))
    return facts


def header(host, cache, lv, al, W, last_seen) -> list:
    facts = side_facts(host, cache, lv, al, last_seen)
    art = banner_lines(host)
    aw = max((T.width(l) for l in art), default=0)
    fw = max(T.width(f) for f in facts)
    if not art or W < aw + 2:
        return [""] + [" " + f for f in facts]
    painted = paint(art, host.accent)
    if W >= aw + 4 + min(fw, 46):
        top = max(0, (len(painted) - len(facts)) // 2)
        rows = []
        for i, line in enumerate(painted):
            j = i - top
            fact = facts[j] if 0 <= j < len(facts) else ""
            rows.append(" " + T.pad(line, aw) + "   " + T.fit(fact, W - aw - 5))
        # Facts that outrun the art continue below it, in the same column.
        extra = [" " * (aw + 4) + f for f in facts[len(painted) - top:]]
        return [""] + rows + extra
    return [""] + [" " + l for l in painted] + [""] + [" " + f for f in facts]


# ── Attention strip ─────────────────────────────────────────────────────────
def attention(al, W, limit=10) -> list:
    shown = [a for a in al if a["sev"] in ("crit", "warn")]
    if not shown:
        return []
    nc = sum(1 for a in shown if a["sev"] == "crit")
    color = "red" if nc else "amber"
    head = " " + T.c("▌", color) + T.c("ATTENTION", color, bold=True) + "  " + T.rule(max(4, W - 14), "faint")
    items = []
    for a in shown[:limit]:
        g, col = alerts.GLYPH.get(a["sev"], ("·", "dim"))
        badge = T.c("NEW ", "sky", bold=True) if a.get("new") else ""
        items.append(T.c(g, col) + " " + badge + (T.c(a["msg"], "fg") if a["sev"] == "crit" else a["msg"]))
    more = len(shown) - limit
    if more > 0:
        items.append(T.dim("… %d more · motd alerts" % more))
    if W >= 120 and len(items) > 3:
        cw = (W - 4 - GAP) // 2
        half = (len(items) + 1) // 2
        rows = []
        for i in range(half):
            left = T.pad(items[i], cw)
            right = items[half + i] if half + i < len(items) else ""
            rows.append("   " + left + " " * GAP + T.fit(right, cw))
        return [head] + rows
    return [head] + ["   " + T.fit(i, W - 4) for i in items]


# ── Footer ──────────────────────────────────────────────────────────────────
def _quote(cache) -> str:
    import random
    q = cache.data("quotes") or {}
    pool = q.get("items") or []
    if not pool:
        txt = core.read_text(os.path.join(core.CACHE_DIR, "fortunes.txt"))
        pool = [l.strip() for l in txt.splitlines() if 8 < len(l.strip()) < 160]
    if pool:
        return random.choice(pool)
    return ""


def _qotd() -> str:
    path = os.path.expanduser(core.config().get("qotd_file") or "")
    lines = [l.strip() for l in core.read_text(path).splitlines() if l.strip()] if path else []
    if not lines:
        return ""
    return lines[int(time.strftime("%j")) % len(lines)]


def footer(host, cache, W, t0) -> list:
    out = []
    q = _quote(cache)
    if q:
        out.append(" " + T.c("❝ ", "faint") + T.c(T.fit(q, W - 6), "sky") + T.c(" ❞", "faint"))
    qd = _qotd()
    if qd:
        out.append(" " + T.dim("QOTD ") + T.c(T.fit(qd, W - 7), "gold_h"))
    ms = int((time.monotonic() - t0) * 1000)
    hints = T.dim("motd ") + T.dim(" · ").join(T.c(cmd, "slate") for cmd in host.hints + ("-h",))
    right = T.dim("rendered %dms" % ms)
    gap = W - 1 - T.width(hints) - T.width(right)
    out.append(" " + hints + (" " * gap + right if gap > 2 else ""))
    return out


# ── Entry ───────────────────────────────────────────────────────────────────
def render(host, cache, width=None, only=None, login=False) -> str:
    from . import panels
    t0 = time.monotonic()
    W = width or term_width()
    repos = host.repos if "repo" in (only or host.panels) else []
    lv = alerts.probe_all(host, repos=repos)
    al = alerts.gather(host, cache, lv)
    last_seen = panels.visit(host, login, al)
    compact = not only and W < 100 and not os.environ.get("MOTD_FULL")
    _, cw = layout(W)
    ctx = RCtx(host, cache, lv, al, cw)
    keys = only or host.panels
    if compact:  # phone-width ssh: the essentials, one column
        keys = [k for k in host.panels if k in host.compact][:4]
    built = []
    for key in keys:
        fn = panels.resolve(key)
        if fn:
            try:
                p = fn(ctx)
            except Exception as e:  # noqa: BLE001 — one broken panel must not blank the MOTD
                p = Panel(key, key.upper(), [T.c("panel error: %s" % e, "red")], "warn")
            if p and p.lines:
                built.append(p)
    out = []
    if not only:
        out += header(host, cache, lv, al, W, last_seen)
        att = attention(al, W, 5 if compact else 10)
        if att:
            out += [""] + att
        out.append("")
    out += grid(built, W, host.accent)
    if not only:
        out.append("")
        if compact:
            hidden = len(host.panels) - len(built)
            out.append(" " + T.dim("%d more panels · " % hidden) + T.c("motd all", "slate") + T.dim(" (or widen the window)"))
        else:
            out += footer(host, cache, W, t0)
    return "\n".join(out)

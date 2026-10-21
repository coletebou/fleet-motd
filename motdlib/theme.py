"""Colors, gradients, bars, and ANSI-aware width math.

Palette: gold primary, amber accent, green/red status, plus sky, violet, rose,
sage and teal swatches for host accents.
Color depth: truecolor when the terminal says so (or is a known RGB terminal),
xterm-256 approximations otherwise, 16-color as a last resort, none for
NO_COLOR / TERM=dumb / MOTD_COLOR=none.
"""
from __future__ import annotations

import os
import re
import unicodedata

PAL = {
    "gold": (201, 180, 88), "gold_l": (232, 222, 176), "gold_h": (212, 196, 120),
    "amber": (245, 158, 11), "amber_l": (251, 191, 36),
    "green": (34, 197, 94), "green_l": (74, 222, 128),
    "red": (239, 68, 68), "red_l": (248, 113, 113),
    "sage": (138, 178, 148), "sky": (118, 176, 224), "rose": (222, 132, 152),
    "violet": (164, 148, 224), "sand": (214, 182, 134), "slate": (150, 162, 180),
    "moss": (128, 160, 108),
    "teal": (0, 190, 194), "teal_l": (126, 232, 220),
    "fg": (228, 228, 228), "text2": (176, 176, 176), "dim": (120, 120, 120),
    "faint": (72, 72, 72), "ghost": (48, 48, 48),
}
SEV_COLOR = {"ok": "green", "warn": "amber", "crit": "red", "info": "sky", "unknown": "dim", "stale": "dim"}


def _detect_mode() -> str:
    forced = os.environ.get("MOTD_COLOR", "").lower()
    if forced in ("truecolor", "256", "16", "none"):
        return forced
    term = os.environ.get("TERM", "")
    if "NO_COLOR" in os.environ or term == "dumb":
        return "none"
    ct = os.environ.get("COLORTERM", "").lower()
    if ct in ("truecolor", "24bit"):
        return "truecolor"
    rgb_terms = ("ghostty", "kitty", "wezterm", "alacritty", "foot", "iterm", "contour")
    if any(t in term for t in rgb_terms) or os.environ.get("WT_SESSION") \
            or os.environ.get("TERM_PROGRAM", "") in ("ghostty", "iTerm.app", "WezTerm", "vscode", "WarpTerminal"):
        return "truecolor"
    if "256" in term or term.startswith(("tmux", "screen", "xterm")):
        return "256"
    return "16"


MODE = _detect_mode()
RESET = "" if MODE == "none" else "\033[0m"
BOLD = "" if MODE == "none" else "\033[1m"


def _cube(v: int) -> int:
    """One channel's level (0-5) in the xterm-256 6×6×6 color cube."""
    if v < 48:
        return 0
    if v < 115:
        return 1
    return (v - 35) // 40


def _rgb256(r: int, g: int, b: int) -> int:
    if abs(r - g) < 10 and abs(g - b) < 10:  # near-grey → grayscale ramp
        if r < 8:
            return 16
        if r > 238:
            return 231
        return 232 + round((r - 8) / 247 * 24)
    return 16 + 36 * _cube(r) + 6 * _cube(g) + _cube(b)


def _rgb16(r: int, g: int, b: int) -> int:
    bright = max(r, g, b) > 200
    code = (1 if r > 127 else 0) | (2 if g > 127 else 0) | (4 if b > 127 else 0)
    if code == 0 and max(r, g, b) > 90:
        return 90  # bright black = grey
    return (90 if bright else 30) + code


def fg(color) -> str:
    if MODE == "none":
        return ""
    r, g, b = PAL[color] if isinstance(color, str) else color
    if MODE == "truecolor":
        return "\033[38;2;%d;%d;%dm" % (r, g, b)
    if MODE == "256":
        return "\033[38;5;%dm" % _rgb256(r, g, b)
    return "\033[%dm" % _rgb16(r, g, b)


def c(text, color, bold=False) -> str:
    if MODE == "none" or text == "":
        return str(text)
    return (BOLD if bold else "") + fg(color) + str(text) + RESET


def sev(text, level, bold=False) -> str:
    return c(text, SEV_COLOR.get(level, "fg"), bold)


def dim(text) -> str:
    return c(text, "dim")


def lerp(a, b, t: float):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def gradient(stops, t: float):
    """Color at position t∈[0,1] along a list of palette names or RGB tuples."""
    pts = [PAL[s] if isinstance(s, str) else s for s in stops]
    if len(pts) == 1:
        return pts[0]
    t = min(1.0, max(0.0, t))
    seg = t * (len(pts) - 1)
    i = min(int(seg), len(pts) - 2)
    return lerp(pts[i], pts[i + 1], seg - i)


# ── ANSI-aware width ────────────────────────────────────────────────────────
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ZERO = {0x200D, 0xFE0E, 0xFE0F, 0x20E3}


def strip(s: str) -> str:
    return _ANSI.sub("", s)


def _cw(ch: str, nxt: str = "") -> int:
    o = ord(ch)
    if o < 32 or 0x7F <= o < 0xA0 or o in _ZERO or 0x1F3FB <= o <= 0x1F3FF:
        return 0
    if unicodedata.combining(ch):
        return 0
    if unicodedata.east_asian_width(ch) in ("W", "F") or 0x1F300 <= o <= 0x1FAFF:
        return 2
    if nxt == "️":  # text symbol forced to emoji presentation (☀️, ⛅️)
        return 2
    return 1


def width(s: str) -> int:
    t = strip(s)
    return sum(_cw(ch, t[i + 1] if i + 1 < len(t) else "") for i, ch in enumerate(t))


def fit(s: str, w: int, ellipsis: str = "…") -> str:
    """Truncate an ANSI string to display width w, keeping escape codes intact."""
    if w <= 0:
        return ""
    if width(s) <= w:
        return s
    out, used, i, n = [], 0, 0, len(s)
    budget = w - width(ellipsis)
    while i < n:
        m = _ANSI.match(s, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            continue
        ch = s[i]
        cw = _cw(ch, s[i + 1] if i + 1 < n else "")
        if used + cw > budget:
            break
        out.append(ch)
        used += cw
        i += 1
    return "".join(out) + RESET + dim(ellipsis)


def pad(s: str, w: int, align: str = "<") -> str:
    s = fit(s, w)
    gap = w - width(s)
    if gap <= 0:
        return s
    if align == ">":
        return " " * gap + s
    if align == "^":
        return " " * (gap // 2) + s + " " * (gap - gap // 2)
    return s + " " * gap


# ── Glyphs ──────────────────────────────────────────────────────────────────
GLYPH = {"ok": "●", "warn": "●", "crit": "●", "info": "●", "unknown": "○", "stale": "◌", "off": "○"}


def dot(level: str) -> str:
    return sev(GLYPH.get(level, "●"), level)


def worst(*levels) -> str:
    order = {"crit": 4, "warn": 3, "unknown": 2, "stale": 2, "info": 1, "ok": 0, None: -1}
    best = None
    for lv in levels:
        if order.get(lv, -1) > order.get(best, -1):
            best = lv
    return best or "ok"


def level_for(value: float, warn: float, crit: float) -> str:
    if value >= crit:
        return "crit"
    if value >= warn:
        return "warn"
    return "ok"


SPARK = "▁▂▃▄▅▆▇█"


def spark(values, warn: float = 70, crit: float = 90, w: int = 0) -> str:
    """Percent samples (0-100) as a sparkline, each cell colored by its own level.
    `w` keeps only the newest w samples."""
    vals = [max(0.0, min(100.0, float(v))) for v in values if v is not None]
    if w:
        vals = vals[-w:]
    out = []
    for v in vals:
        out.append(c(SPARK[min(7, int(v / 100.0 * 8))], SEV_COLOR[level_for(v, warn, crit)]))
    return "".join(out)


def bar(p: float, w: int = 10, warn: float = 70, crit: float = 90) -> str:
    """Heavy-line meter. Truecolor: btop-style heat gradient along the bar;
    otherwise one color for the bar's overall severity."""
    p = max(0.0, min(100.0, float(p or 0)))
    cells = p / 100.0 * w
    full = int(cells)
    half = cells - full >= 0.5
    out = []
    for i in range(w):
        if i < full or (i == full and half):
            ch = "━" if i < full else "╸"
            if MODE == "truecolor":
                t = (i + 0.5) / w * 100.0
                rgb = gradient(("green", "green", "amber", "red"), min(1.0, t / max(crit, 1.0)))
                out.append(fg(rgb) + ch)
            else:
                out.append(fg(SEV_COLOR[level_for(p, warn, crit)]) + ch)
        else:
            out.append(fg("ghost") + "─")
    return "".join(out) + RESET


def rule(w: int, color: str = "faint", ch: str = "─") -> str:
    return c(ch * max(0, w), color)

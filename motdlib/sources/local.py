"""Host-local sources: weather, process census, Tailscale, sites, repos, quotes."""
from __future__ import annotations

import json
import os
import re
import urllib.parse

from .. import core
from ..registry import source

WMO = {0: ("☀️", "clear"), 1: ("🌤️", "mostly clear"), 2: ("⛅", "partly cloudy"), 3: ("☁️", "overcast"),
       45: ("🌫️", "fog"), 48: ("🌫️", "rime fog"), 51: ("🌦️", "drizzle"), 53: ("🌦️", "drizzle"),
       55: ("🌦️", "drizzle"), 61: ("🌧️", "rain"), 63: ("🌧️", "rain"), 65: ("🌧️", "heavy rain"),
       71: ("🌨️", "snow"), 73: ("🌨️", "snow"), 75: ("❄️", "heavy snow"), 80: ("🌦️", "showers"),
       81: ("🌧️", "showers"), 82: ("⛈️", "violent showers"), 95: ("⛈️", "thunderstorm"),
       96: ("⛈️", "thunderstorm"), 99: ("⛈️", "thunderstorm")}


@source("weather", ttl=1800, timeout=8, scope="global")
def weather(ctx):
    """Weather from config.json "weather" {place, lat, lon, tz, unit}: Open-Meteo, wttr.in fallback."""
    w = core.config().get("weather") or {}
    place = w.get("place") or "New York"
    lat, lon = str(w.get("lat", "40.71")), str(w.get("lon", "-74.01"))
    tz = urllib.parse.quote(w.get("tz") or "America/New_York", safe="")
    metric = w.get("unit") == "metric"
    url = ("https://api.open-meteo.com/v1/forecast?latitude=%s&longitude=%s"
           "&current=temperature_2m,apparent_temperature,weather_code,wind_speed_10m,relative_humidity_2m"
           "&daily=temperature_2m_max,temperature_2m_min,precipitation_probability_max,sunrise,sunset"
           "&temperature_unit=%s&wind_speed_unit=%s&timezone=%s&forecast_days=1"
           % (lat, lon, "celsius" if metric else "fahrenheit", "kmh" if metric else "mph", tz))
    try:
        r = ctx.http(url, timeout=5)
        if r.ok and isinstance(r.body, dict):
            cur, day = r.body["current"], r.body["daily"]
            icon, desc = WMO.get(int(cur.get("weather_code", -1)), ("·", "?"))
            return {"place": place, "icon": icon, "desc": desc, "temp": round(cur["temperature_2m"]),
                    "feels": round(cur["apparent_temperature"]), "wind": round(cur.get("wind_speed_10m", 0)),
                    "hum": cur.get("relative_humidity_2m"), "hi": round(day["temperature_2m_max"][0]),
                    "lo": round(day["temperature_2m_min"][0]), "rain": day["precipitation_probability_max"][0],
                    "sunset": (day.get("sunset") or [""])[0][-5:], "sunrise": (day.get("sunrise") or [""])[0][-5:],
                    "src": "open-meteo", "unit": "C" if metric else "F"}
    except Exception:  # noqa: BLE001 — fall through to wttr
        pass
    r = ctx.http("https://wttr.in/%s?%s&format=%%c|%%t|%%C" % (place.replace(" ", "+"), "m" if metric else "u"), timeout=5, headers={"Accept": "text/plain"})
    if r.ok and isinstance(r.body, str) and r.body.count("|") == 2:
        icon, temp, desc = [p.strip() for p in r.body.split("|")]
        return {"place": place, "icon": icon, "desc": desc.lower(),
                "temp": int(re.sub(r"[^\d-]", "", temp) or 0), "src": "wttr", "unit": "C" if metric else "F"}
    raise RuntimeError("all weather sources failed (HTTP %s)" % r.status)


def _etime(e: str) -> int:
    """BSD ps etime "[[dd-]hh:]mm:ss" → seconds."""
    days = 0
    if "-" in e:
        d, e = e.split("-", 1)
        days = int(d) if d.isdigit() else 0
    secs = 0
    for part in e.split(":"):
        secs = secs * 60 + (int(part) if part.isdigit() else 0)
    return days * 86400 + secs


def _ps_rows():
    """[(pid, ppid, user, rss_bytes, stat, args, has_tty, age_s)] for every process."""
    rows = []
    if core.IS_MAC:
        rc, out, _ = core.run(["/bin/ps", "-axww", "-o", "pid=,ppid=,user=,rss=,stat=,tty=,etime=,args="], 8)
        for line in out.splitlines():
            parts = line.split(None, 7)
            if len(parts) == 8 and parts[0].isdigit():
                rows.append((int(parts[0]), int(parts[1]), parts[2], int(parts[3]) * 1024, parts[4], parts[7],
                             parts[5] not in ("??", "?"), _etime(parts[6])))
        return rows
    import pwd
    page = os.sysconf("SC_PAGE_SIZE")
    hz = os.sysconf("SC_CLK_TCK")
    up = float((core.read_text("/proc/uptime").split() or ["0"])[0])
    users = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            stat = core.read_text("/proc/%s/stat" % d)
            rpar = stat.rfind(")")
            fields = stat[rpar + 2:].split()
            uid = os.stat("/proc/" + d).st_uid
            with open("/proc/%s/cmdline" % d, "rb") as f:
                args = f.read(4096).replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except (OSError, IndexError):
            continue
        if uid not in users:
            try:
                users[uid] = pwd.getpwuid(uid).pw_name
            except KeyError:
                users[uid] = str(uid)
        comm = stat[stat.find("(") + 1:rpar]
        rows.append((int(d), int(fields[1]), users[uid], int(fields[21]) * page, fields[0], args or "[%s]" % comm,
                     fields[4] != "0", int(up - int(fields[19]) / hz)))
    return rows


_CODEX = re.compile(r"(?:^|/)codex(?:-[a-z0-9_]+(?:-[a-z0-9_]+)*)?(?:\s|$)")
_CLAUDE = re.compile(r"(?:^|/)claude(?:\s|$)|@anthropic-ai/claude-code")


def _short_name(args: str) -> str:
    m = re.search(r"/([^/]+)\.app/", args)
    if m:
        return m.group(1)
    first = args.split()[0] if args.split() else "?"
    return os.path.basename(first)[:24]


@source("procs", ttl=120, timeout=12)
def procs(ctx):
    """Process census: Claude/Codex agents, MCP orphans, zombies, top memory."""
    rows = _ps_rows()
    me = {"total": len(rows), "claude": 0, "zombies": 0, "orphan_claude": [],
          "codex": {"total": 0}, "playwright": {"total": 0, "orphans": 0}}
    for pid, ppid, user, rss, stat, args, has_tty, age in rows:
        head = args.split(" -", 1)[0]
        if "Z" in stat:
            me["zombies"] += 1
        if _CLAUDE.search(head) and "Claude.app" not in args:
            me["claude"] += 1
            # What _claude_orphan_warning used to scan for at every login.
            if not has_tty and age > 300 and "--dangerously" in args:
                me["orphan_claude"].append(pid)
        elif _CODEX.search(head) and "node " not in head[:6] and "high-fd" not in head:
            toks = args.split()
            sub = next((t for t in toks[1:] if not t.startswith("-")), "tui")
            sub = sub if sub in ("app-server", "exec", "mcp-server", "proto", "login", "resume") else "tui"
            me["codex"]["total"] += 1
            me["codex"][sub] = me["codex"].get(sub, 0) + 1
            if ppid == 1:
                me["codex"]["orphaned"] = me["codex"].get("orphaned", 0) + 1
        if "@playwright/mcp" in args or "playwright-mcp" in head:
            if not args.startswith(("npm ", "sh ", "/bin/sh")):
                me["playwright"]["total"] += 1
                if ppid == 1:
                    me["playwright"]["orphans"] += 1
    top = sorted(rows, key=lambda r: r[3], reverse=True)[:5]
    me["top"] = [{"name": _short_name(r[5]), "rss": r[3], "user": r[2]} for r in top]
    me["orphan_claude"] = me["orphan_claude"][:12]
    # Codex app-servers are often held open on purpose; only parentless ones are leftovers.
    alerts = []
    if me["codex"].get("orphaned", 0) >= 3:
        alerts.append({"sev": "warn", "msg": "%d orphaned codex daemons on %s" % (me["codex"]["orphaned"], ctx.host.label)})
    if me["orphan_claude"]:
        alerts.append({"sev": "warn", "msg": "%d orphaned claude process(es) on %s" % (
            len(me["orphan_claude"]), ctx.host.label)})
    if me["playwright"]["orphans"] >= 5:
        alerts.append({"sev": "warn", "msg": "%d orphaned playwright-mcp procs" % me["playwright"]["orphans"]})
    if me["zombies"] >= 25:
        alerts.append({"sev": "warn", "msg": "%d zombie processes" % me["zombies"]})
    if alerts:
        me["alerts"] = alerts
    return me


WIN_TS = "/mnt/c/Program Files/Tailscale/tailscale.exe"
MAC_TS = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"


def _tailscale_bin(host=None):
    # WSL can share the Windows node through mirrored networking while its own
    # tailscaled sits logged out, so ask the Windows CLI.
    if host is not None and "#wsl" in host.tags and os.path.exists(WIN_TS):
        return WIN_TS
    return core.which("tailscale") or (MAC_TS if os.path.exists(MAC_TS) else None)


def _ts_epoch(stamp) -> int:
    """A tailscale status timestamp → epoch secs; its zero time ("0001-01-01…") means never."""
    return core.utc_epoch(stamp) if stamp and not stamp.startswith("0001") else 0


@source("tailscale", ttl=300, timeout=8)
def tailscale(ctx):
    """Local tailscaled view: self IP, backend state, peers online, key expiry."""
    ts = _tailscale_bin(ctx.host)
    if not ts:
        return {"installed": False}
    rc, out, err = core.run([ts, "status", "--json"], 8)
    try:
        st = json.loads(out)
    except ValueError:
        return {"installed": True, "state": "error", "error": (err or out)[:120]}
    selfn = st.get("Self") or {}
    peers = list((st.get("Peer") or {}).values())
    now = core.now()
    rows = [{"name": (p.get("HostName") or p.get("DNSName", "?").split(".")[0]).lower(),
             "online": bool(p.get("Online")), "seen": _ts_epoch(p.get("LastSeen", "")),
             "expiry": _ts_epoch(p.get("KeyExpiry", "")), "os": p.get("OS", "")} for p in peers]
    soon = [r for r in rows if r["expiry"] and r["expiry"] - now < 14 * 86400]
    self_exp = _ts_epoch(selfn.get("KeyExpiry", ""))
    data = {"installed": True, "state": st.get("BackendState"), "ip": (selfn.get("TailscaleIPs") or [""])[0],
            "online": sum(1 for r in rows if r["online"]), "peers": len(rows), "rows": rows,
            "self_expiry": self_exp, "tailnet": (st.get("CurrentTailnet") or {}).get("Name", "")}
    alerts = []
    if data["state"] != "Running":
        alerts.append({"sev": "crit", "msg": "tailscale %s on %s" % (data["state"], ctx.host.label)})
    if self_exp and self_exp - now < 14 * 86400:
        alerts.append({"sev": "warn", "msg": "tailscale key on %s expires in %s" % (
            ctx.host.label, core.human_age(self_exp - now))})
    for r in soon[:3]:
        alerts.append({"sev": "warn", "msg": "tailscale key %s expires in %s" % (r["name"], core.human_age(r["expiry"] - now))})
    if alerts:
        data["alerts"] = alerts
    return data


def _sites() -> list:
    """config.json "sites": [["label", "https://url"], ...] — public endpoints to probe."""
    return [(str(i[0]), str(i[1])) for i in core.config().get("sites") or () if len(i) >= 2]


@source("sites", ttl=300, timeout=12, scope="global")
def sites(ctx):
    """Public endpoints: HTTP status + latency, probed in parallel."""
    from concurrent.futures import ThreadPoolExecutor
    targets = _sites()
    if not targets:
        return {"rows": [], "up": 0, "total": 0}

    def probe(item):
        label, url = item
        try:
            r = core.http(url, timeout=8, raw=True, headers={"Accept": "*/*"})
            return {"label": label, "url": url, "status": r.status, "ms": r.ms, "up": r.status < 500}
        except Exception as e:  # noqa: BLE001
            return {"label": label, "url": url, "status": 0, "ms": 0, "up": False, "error": type(e).__name__}
    with ThreadPoolExecutor(max_workers=len(targets)) as ex:
        rows = list(ex.map(probe, targets))
    was_down = {r["label"] for r in (ctx.prev or {}).get("rows") or [] if not r.get("up")}
    down = [r for r in rows if not r["up"] and r["label"] in was_down]  # two strikes, as in _sys.flap_guard
    data = {"rows": rows, "up": sum(1 for r in rows if r["up"]), "total": len(rows)}
    if down:
        data["alerts"] = [{"sev": "crit", "msg": "%s down (%s)" % (r["label"], r.get("error") or r["status"])}
                          for r in down]
    return data


@source("repos", ttl=120, timeout=10, hosts=("#dev",))
def repos(ctx):
    """Untracked-file counts (too slow for the login path; tracked state is live)."""
    out = {}
    for p in ctx.host.repos:
        rc, txt, _ = core.run(["git", "-C", p, "status", "--porcelain", "-unormal"], 8)
        if rc == 0:
            lines = txt.splitlines()
            out[p] = {"untracked": sum(1 for l in lines if l.startswith("??")),
                      "changed": sum(1 for l in lines if not l.startswith("??"))}
    return {"repos": out}


@source("quotes", ttl=7 * 86400, timeout=10, scope="global", retry=6 * 3600)
def quotes(ctx):
    """A week's pool of short quotes for the footer (zenquotes, fortune fallback)."""
    items = []
    try:
        r = ctx.http("https://zenquotes.io/api/quotes", timeout=6)
        if r.ok and isinstance(r.body, list):
            for q in r.body:
                text, who = (q.get("q") or "").strip(), (q.get("a") or "").strip()
                if text and len(text) < 150 and "zenquotes" not in text.lower():
                    items.append("%s — %s" % (text, who) if who else text)
    except Exception:  # noqa: BLE001
        pass
    if len(items) < 20:
        fortune = core.which("fortune", ("/usr/games",))
        for _ in range(40 if fortune else 0):
            rc, out, _err = core.run([fortune, "-s", "-n", "140"], 2)
            line = " ".join(out.split())
            if rc == 0 and 10 < len(line) < 150 and line not in items:
                items.append(line)
    if not items:
        raise RuntimeError("no quote source reachable")
    return {"items": items[:120]}

"""Cheap probes run at render time (and for the fleet snapshot).

Budget: a few ms on Linux (procfs + statvfs, one systemctl call per scope) and
~10 ms on macOS (one sysctl, one vm_stat, one launchctl list). Anything slower
belongs in a collector source instead.
"""
from __future__ import annotations

import os
import platform
import re
import socket

from . import core


def _meminfo() -> dict:
    out = {}
    for line in core.read_text("/proc/meminfo").splitlines():
        k, _, rest = line.partition(":")
        parts = rest.split()
        if parts:
            out[k] = int(parts[0]) * 1024
    return out


def _disk(mount: str):
    try:
        st = os.statvfs(mount)
        # A profile mount that is only a directory on / (no instance store
        # attached to /mnt/nvme yet) would repeat the root disk. Not on macOS:
        # the Data volume reports the same st_dev as / through its firmlink.
        if not core.IS_MAC and mount != "/" and os.stat(mount).st_dev == os.stat("/").st_dev:
            return None
    except OSError:
        return None
    total = st.f_blocks * st.f_frsize
    if total <= 0:
        return None
    avail = st.f_bavail * st.f_frsize
    used = total - st.f_bfree * st.f_frsize
    return {"mount": mount, "used": used, "total": used + avail, "pct": core.pct(used, used + avail)}


def _primary_ip() -> str:
    """Source address of the default route; no packet is sent for UDP connect."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.connect(("1.1.1.1", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return ""


def _os_linux() -> str:
    m = re.search(r'^PRETTY_NAME="?([^"\n]+)', core.read_text("/etc/os-release"), re.M)
    return m.group(1) if m else "Linux"


def _disks(mounts, budget: float = 0.8):
    """statvfs each mount in a daemon thread: a dead network mount (FUSE/CIFS) can
    block statvfs indefinitely, and a login must never wait on it."""
    import threading
    import time
    res = {}
    threads = [threading.Thread(target=lambda m=m: res.__setitem__(m, _disk(m)), daemon=True) for m in mounts]
    for t in threads:
        t.start()
    deadline = time.monotonic() + budget
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    return [res[m] for m in mounts if res.get(m)], [m for m in mounts if m not in res]


def vitals(host, disks: bool = True) -> dict:
    v = {"cores": os.cpu_count() or 1, "ip": _primary_ip()}
    try:
        v["load"] = list(os.getloadavg())
    except OSError:
        v["load"] = [0.0, 0.0, 0.0]
    if core.IS_MAC:
        rc, out, _ = core.run(["/usr/sbin/sysctl", "-n", "hw.memsize", "vm.swapusage", "kern.boottime"], 2)
        lines = out.splitlines()
        total = int(lines[0]) if lines and lines[0].isdigit() else 0
        sw = re.findall(r"(total|used) = ([\d.]+)M", lines[1] if len(lines) > 1 else "")
        swd = {k: float(x) * 1048576 for k, x in sw}
        bt = re.search(r"sec = (\d+)", lines[2] if len(lines) > 2 else "")
        rc, vm, _ = core.run(["/usr/bin/vm_stat"], 2)
        page = int((re.search(r"page size of (\d+)", vm) or [0, 16384])[1])

        def pages(key):
            return int((re.search(r"%s:\s+(\d+)" % key, vm) or [0, 0])[1])
        used = (pages("Pages active") + pages("Pages wired down") + pages("Pages occupied by compressor")) * page
        v["mem"] = {"used": used, "total": total}
        v["swap"] = {"used": swd.get("used", 0), "total": swd.get("total", 0)}
        v["uptime"] = core.now() - int(bt.group(1)) if bt else 0
        v["os"] = "macOS " + (platform.mac_ver()[0] or "?")
        # The root volume is a firmlink pair; meter its Data half. Other configured volumes stay.
        mounts = ["/System/Volumes/Data" if m == "/" else m for m in host.mounts]
    else:
        mi = _meminfo()
        total = mi.get("MemTotal", 0)
        v["mem"] = {"used": total - mi.get("MemAvailable", 0), "total": total}
        v["swap"] = {"used": mi.get("SwapTotal", 0) - mi.get("SwapFree", 0), "total": mi.get("SwapTotal", 0)}
        up = core.read_text("/proc/uptime").split()
        v["uptime"] = float(up[0]) if up else 0
        v["procs"] = sum(1 for d in os.listdir("/proc") if d.isdigit())
        v["os"] = _os_linux()
        mounts = list(host.mounts)
        if os.path.isdir("/mnt/c") and "/mnt/c" not in mounts:
            mounts.append("/mnt/c")
    v["disks"], v["stalled"] = _disks(mounts) if disks else ([], [])
    for d in v["disks"]:
        if d["mount"] == "/System/Volumes/Data":
            d["mount"] = "/"
        elif d["mount"] == "/mnt/c":
            d["mount"] = "C:"
    return v


def parse_show(out: str) -> list:
    """`systemctl show` output (one blank-line separated block per unit) → [{Property: value}]."""
    blocks, cur = [], {}
    for line in out.splitlines() + [""]:
        if not line.strip():
            if cur:
                blocks.append(cur)
            cur = {}
            continue
        k, _, val = line.partition("=")
        cur[k] = val
    return blocks


def _systemctl_show(units, user=False) -> dict:
    """{unit: {ActiveState, SubState, Result, NRestarts, LoadState}} in one call."""
    if not units:
        return {}
    argv = ["systemctl"] + (["--user"] if user else []) + [
        "show", "--no-pager", "-p", "Id,LoadState,ActiveState,SubState,Result,NRestarts"]
    argv += [u if "." in u.split("@")[-1] else u + ".service" for u in units]
    rc, out, _ = core.run(argv, 3)
    res = {}
    for b in parse_show(out):
        if b.get("Id"):  # profiles name units bare ("docker") or in full ("snap.x.y.service")
            res[b["Id"]] = res[b["Id"].rsplit(".", 1)[0]] = b
    return res


def units(host) -> list:
    """[(label, level, detail)] with same-label units merged (e.g. gh-runners 3/3)."""
    if core.IS_MAC or not host.units:
        return []
    sysu = [u for u, _, s in host.units if s == "system"]
    usru = [u for u, _, s in host.units if s == "user"]
    st = _systemctl_show(sysu)
    st.update({("user:" + k): v for k, v in _systemctl_show(usru, user=True).items()})
    groups = {}  # label → unit states, in profile order
    for unit, label, scope in host.units:
        key = ("user:" + unit) if scope == "user" else unit
        groups.setdefault(label, []).append(st.get(key) or {})
    out = []
    for label, infos in groups.items():
        present = [i for i in infos if i.get("LoadState") not in (None, "", "not-found")]
        if not present:
            continue
        up = sum(1 for i in present if i.get("ActiveState") == "active")
        failed = any(i.get("ActiveState") == "failed" for i in present)
        restarts = sum(int(i.get("NRestarts") or 0) for i in present)
        if up == len(present):
            lvl = "ok"
        elif failed or up == 0:
            lvl = "crit"
        else:
            lvl = "warn"
        if len(present) > 1:
            detail = "%d/%d" % (up, len(present))
        elif up:
            detail = ""
        else:
            detail = present[0].get("SubState") or present[0].get("ActiveState") or "?"
        if restarts >= 3 and lvl == "ok":
            detail = (detail + " ↻%d" % restarts).strip()
        out.append((label, lvl, detail))
    return out


def failed_units() -> list:
    if core.IS_MAC:
        return []
    names = []
    for user in (False, True):
        argv = ["systemctl"] + (["--user"] if user else []) + [
            "list-units", "--state=failed", "--no-legend", "--plain", "--no-pager"]
        rc, out, _ = core.run(argv, 3)
        for line in out.splitlines():
            parts = line.split()
            if parts and not parts[0].startswith("session-"):
                names.append(("user:" if user else "") + parts[0])
    return names


def tmux() -> dict:
    tm = core.which("tmux")
    if not tm:
        return {"sessions": 0, "windows": 0, "attached": 0}
    rc, out, _ = core.run([tm, "list-windows", "-a", "-F", "#{session_name}\t#{session_attached}"], 2)
    if rc != 0:
        return {"sessions": 0, "windows": 0, "attached": 0}
    rows = [l.split("\t") for l in out.splitlines() if l]
    sess = {r[0]: r[1] for r in rows if len(r) == 2}
    return {"sessions": len(sess), "windows": len(rows),
            "attached": sum(1 for a in sess.values() if a not in ("0", ""))}


def launchd(host) -> list:
    """Mac LaunchAgents: daemons must have a PID; interval jobs a zero last exit."""
    if not core.IS_MAC or not host.agents:
        return []
    rc, out, _ = core.run(["/bin/launchctl", "list"], 2)
    table = {}
    for line in out.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) == 3:
            table[parts[2]] = (parts[0], parts[1])
    res = []
    for label, short in host.agents:
        if label.endswith(".*"):  # every loaded job under a prefix, named by the rest
            prefix = label[:-1]
            jobs = [(l, l[len(prefix):][:14])
                    for l in sorted(table) if l.startswith(prefix)]
        else:
            jobs = [(label, short)] if label in table else []
        for job, name in jobs:
            pid, status = table[job]
            if pid != "-":
                res.append((name, "ok", ""))
            elif status in ("0", "-"):
                res.append((name, "ok", "idle"))
            else:
                res.append((name, "crit", "exit %s" % status))
    return res


def ports(items) -> list:
    """[(port, label, open)] for loopback TCP ports; a refused connect returns at once."""
    out = []
    for port, label in items:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            out.append((port, label, True))
        except OSError:
            out.append((port, label, False))
    return out


def repo(path: str):
    """Branch, dirty count, ahead/behind, last commit age; None if not a repo."""
    path = os.path.expanduser(path)
    if not os.path.isdir(os.path.join(path, ".git")) and not os.path.isfile(os.path.join(path, ".git")):
        return None
    rc, out, _ = core.run(["git", "-C", path, "status", "--porcelain=v2", "--branch", "-uno"], 3)
    if rc != 0:
        return None
    r = {"path": path, "branch": "?", "ahead": 0, "behind": 0, "dirty": 0}
    for line in out.splitlines():
        if line.startswith("# branch.head "):
            r["branch"] = line.split(" ", 2)[2]
        elif line.startswith("# branch.ab "):
            a, b = line.split()[2:4]
            r["ahead"], r["behind"] = int(a), -int(b)
        elif not line.startswith("#"):
            r["dirty"] += 1
    rc, last, _ = core.run(["git", "-C", path, "log", "-1", "--format=%ct"], 3)
    r["last"] = int(last.strip()) if last.strip().isdigit() else None
    return r

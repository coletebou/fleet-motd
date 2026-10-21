"""Dev-ops panels: Docker stacks, pull/merge requests, EC2 instances, and access
(AWS credentials, the private-network route, endpoints). Each shows only on hosts
whose "panels" list it, and its source says "unconfigured" until config.json has
the matching section (see sources/devops.py)."""
from __future__ import annotations

from . import core, theme as T
from .panels import SEP, builder, cells, kv
from .render import Panel
from .sources import devops

W = 10  # label column


def _short_type(t: str) -> str:
    return (t or "?").replace("xlarge", "xl").replace("large", "l").replace("medium", "m")


def _ago(t) -> str:
    return core.human_age(core.now() - t) if t else "?"


def _age3(t) -> str:
    """At most four cells: 7m, 5h, 12d."""
    if not t:
        return "?"
    s = max(0, core.now() - t)
    if s < 3600:
        return "%dm" % (s // 60)
    if s < 172800:
        return "%dh" % (s // 3600)
    return "%dd" % (s // 86400)


def _exited(f) -> str:
    """'llm exited 1 10m ago', red while the crash is under 6h old (devops.RECENT_FAIL_S)."""
    ago = f.get("ago")
    color = "red" if (ago or 1e9) < 21600 else "dim"
    return "%s %s" % (f["name"], T.c("exited %s" % f["code"], color)) + (T.dim(" " + core.human_age(ago, " ago")) if ago else "")


@builder("docker")
def p_docker(x):
    rows, lvl = [], "ok"
    st = x.cache.data("docker") or {}
    dk = st.get("docker")
    if dk == "up":
        projs = st.get("projects") or []
        up = [p for p in projs if p["running"] or p["restarting"]]  # crash-looping is not stopped
        for i, p in enumerate(up[:4]):
            l2 = "warn" if p["unhealthy"] or p["restarting"] else "ok"
            lvl = T.worst(lvl, l2)
            want = p["total"] - p["done"]
            bits = [T.sev("%d/%d up" % (p["running"], want), "ok" if p["running"] >= want else "warn")]
            if p["starting"]:
                bits.append(T.c("%d starting" % p["starting"], "sky"))
            if p["done"]:
                bits.append(T.dim("%d one-shot done" % p["done"]))
            rows.append(kv("stack" if i == 0 else "", T.dot(l2) + " " + T.c(p["name"], "fg", bold=True) + "  " + SEP.join(bits), W))
            issues = ["%s %s" % (n, T.c("unhealthy", "amber")) for n in p["unhealthy"]]
            issues += ["%s %s" % (n, T.c("restarting", "amber")) for n in p["restarting"]]
            issues += [_exited(f) for f in p["failed"][:3]]
            if issues:
                rows.append(kv("", T.c("▲ ", "amber") + SEP.join(issues[:4]), W))
        if len(up) > 4:
            rows.append(kv("", T.dim("+%d more running stacks" % (len(up) - 4)), W))
        down = [p["name"] for p in projs if not (p["running"] or p["restarting"])]
        if down:
            more = " +%d" % (len(down) - 5) if len(down) > 5 else ""
            rows.append(kv("" if up else "stack", T.dot("unknown") + T.dim(" stopped: " + ", ".join(down[:5]) + more), W))
        if not projs:
            rows.append(kv("stack", T.dot("unknown") + T.dim(" no compose stacks"), W))
    elif dk == "down":
        rows.append(kv("docker", T.dot("unknown") + T.dim(" engine not running"), W))
    elif dk == "missing":
        rows.append(kv("docker", T.dim("not installed"), W))
    elif not st:
        rows.append(kv("stack", T.dim("waiting for the collector…"), W))
    if not rows:
        return None
    return Panel("docker", "DOCKER", rows, lvl, x.stale_note("docker", 5, 900))


_MERGE = {"mergeable": ("ok", ""), "conflicts": ("warn", "conflicts"), "unknown": ("unknown", "")}


@builder("mrs")
def p_mrs(x):
    d = x.cache.data("mrs")
    if not d:
        return Panel("mrs", "PULL REQUESTS", [T.dim("waiting for the collector…")], "unknown")
    if d.get("installed") is False:  # no gh/glab on this box, or no config: no panel
        return None
    noun, prefix = d.get("noun", "MR"), d.get("prefix", "!")
    title = "PULL REQUESTS" if noun == "PR" else "MERGE REQUESTS"
    rows, lvl = [], "ok"
    mine = d.get("mine")
    if mine is None:  # never had a list: say why
        err = d.get("error") or "no data"
        hint = "off VPN?" if "unreachable" in err.lower() or "timeout" in err.lower() else ""
        rows.append(T.dot("unknown") + " " + T.dim(err[:x.cw - 20]) + ((" · " + T.c(hint, "sky")) if hint else ""))
        return Panel("mrs", title, rows, "unknown")
    conf = sum(1 for m in mine if m["merge"] == "conflicts")
    chg = sum(1 for m in mine if m["changes"])
    appr = sum(1 for m in mine if m["approvals"])
    bits = [T.c("%d open" % len(mine), "fg", bold=True)]
    if appr:
        bits.append(T.c("%d approved" % appr, "green"))
    if conf:
        bits.append(T.c("%d conflicted" % conf, "amber"))
    if chg:
        bits.append(T.c("%d to fix" % chg, "red"))
    rows.append(kv("mine", SEP.join(bits), W))
    if conf or chg:
        lvl = "warn"
    tw = max(12, x.cw - 1 - 2 - 7 - 12 - 5)
    for m in mine[:5]:
        l2, word = _MERGE.get(m["merge"], ("unknown", ""))
        if m["changes"]:
            l2, status = "crit", T.c("✖ changes", "red")
        elif word:
            status = T.c(word, "amber")
        elif m["approvals"]:
            status = T.c("✔%d" % m["approvals"], "green")
        else:
            status = T.dim("review")
        rows.append(T.dot(l2) + " " + T.pad(T.c("%s%s" % (prefix, m["n"]), "violet"), 6) + " " + T.pad(m["title"], tw) + " " +
                    T.pad(status, 10, ">") + " " + T.dim(T.pad(_age3(m["updated"]), 4, ">")))
    if len(mine) > 5:
        rows.append(T.dim("  … %d more" % (len(mine) - 5)))
    asg = d.get("assigned") or []
    if asg:
        rows.append(kv("review", T.c("%d waiting on you" % len(asg), "sky") + T.dim(" · " + " ".join("%s%s" % (prefix, a["n"]) for a in asg[:5])), W))
    total = "%s%s open" % (d.get("open", 0), "+" if d.get("truncated") else "")
    stale = x.stale_note("mrs", 4, 3600)
    return Panel("mrs", title, rows, lvl, "%s · %s" % (d.get("repo", ""), total) + (" · " + stale if stale else ""))


@builder("ec2")
def p_ec2(x):
    d = x.cache.data("ec2_fleet")
    if not d or d.get("unconfigured"):
        return None
    rows, stopped = [], []
    for r in d.get("rows") or []:
        if r["state"] != "running":
            stopped.append(r["name"] + ("" if r["state"] == "stopped" else "(%s)" % r["state"]))
            continue
        rows.append(T.dot("ok") + " " + T.pad(T.c(r["name"], "fg"), 15) + " " +
                    T.pad(T.dim(_short_type(r["type"])), 9) + " " + T.pad(T.dim(r["ip"] or "-"), 14) +
                    T.dim("up " + _ago(r["launched"])))
    if stopped:
        rows += [T.dot("unknown") + " " + T.dim(l) for l in cells(stopped, x.cw - 3, 8)][:3]
    if not rows:
        rows.append(T.dim("no instances match the configured filters"))
    note = "%d/%d running" % (d.get("running", 0), d.get("total", 0))
    if d.get("src") == "cache":
        note += " · cached " + _ago(d.get("asof"))
    stale = x.stale_note("ec2_fleet", 4, 3600)
    return Panel("ec2", "EC2", rows, "ok", note + (" · " + stale if stale else ""))


def _sts_row(a) -> str:
    if not a.get("cli"):
        return T.dim("aws CLI not installed")
    s = a.get("sts") or {}
    state = s.get("state")
    if a.get("static"):
        how = " · keys"
    elif (a.get("sso") or {}).get("profiles"):
        how = " · sso"
    else:
        how = ""
    tail = T.dim(how + (" · " + _age3(s["at"]) if s.get("at") else ""))
    if state == "ok":
        return T.dot("ok") + " " + T.c(s.get("principal") or "?", "fg") + T.dim(" @ ") + str(s.get("account")) + tail
    if state == "rejected":
        return T.dot("crit") + " " + T.c("rejected: %s" % s.get("error"), "red") + T.dim(" · run ") + T.c(s.get("hint") or "aws sso login", "sky")
    if state == "none":
        return T.dot("unknown") + T.dim(" no credentials configured")
    if state == "unreachable":
        return T.dot("unknown") + T.dim(" sts unreachable (%s)" % s.get("error", "network"))
    return T.dot("unknown") + T.dim(" %s" % (s.get("error") or "not checked yet"))


def _cloud_row(c) -> str:
    """One gcp/azure row: who, where, and why not when it is not ok."""
    if not c.get("cli"):
        return T.dim("CLI not installed")
    st = c.get("state")
    who = c.get("account") or "?"
    where = c.get("project") or c.get("subscription") or ""
    if st == "ok":
        exp = c.get("expires")
        tail = T.dim(" · token %s left" % core.human_age(exp - core.now())) if exp and exp > core.now() else ""
        return T.dot("ok") + " " + T.c(who, "fg") + (T.dim(" @ ") + where if where else "") + tail
    if st == "rejected":
        return T.dot("crit") + " " + T.c("rejected", "red") + T.dim(" · run ") + T.c(c.get("hint") or "log in", "sky")
    if st == "none":
        return T.dot("unknown") + T.dim(" not logged in")
    if st == "unreachable":
        return T.dot("unknown") + T.dim(" API unreachable")
    return T.dot("unknown") + T.dim(" " + str(c.get("error") or "not checked yet")[:60])


def _vpc_cell(v) -> str:
    if v.get("ok"):
        return T.dot("ok") + " " + v["alias"] + T.dim(" %dms" % v["ms"])
    return T.dot("warn") + " " + v["alias"] + T.dim(" " + v.get("error", "down"))


@builder("access")
def p_access(x):
    rows, lvl = [], "ok"
    a = x.cache.data("aws_auth")
    if a and not a.get("unconfigured"):
        rows.append(kv("aws", _sts_row(a), W))
        if (a.get("sts") or {}).get("state") == "rejected":
            lvl = "crit"
        sso = a.get("sso") or {}
        if sso.get("profiles"):
            exp = sso.get("expires")
            left = (exp - core.now()) if exp else None
            # With a refresh token the CLI renews an expired access token itself;
            # the STS row above is the verdict, this is the token's own clock.
            refreshable = sso.get("refreshable")
            renew = T.dim(" · renews") if refreshable else ""
            if left and left > 0:
                txt = T.dot("warn" if left < 3600 and not refreshable else "ok") + " token %s left" % core.human_age(left) + renew
            elif left:
                txt = T.dot("unknown") + T.dim(" token expired %s" % core.human_age(-left, " ago")) + (
                    renew or T.dim(" · log in again"))
            else:
                txt = T.dot("unknown") + T.dim(" not logged in")
            rows.append(kv("sso", txt + (T.dim(" · " + str(sso["account"])) if sso.get("account") else ""), W))
    for key, label in (("gcp_auth", "gcp"), ("azure_auth", "azure")):
        c = x.cache.data(key)
        if not c or c.get("unconfigured"):
            continue
        rows.append(kv(label, _cloud_row(c), W))
        if c.get("state") == "rejected":
            lvl = T.worst(lvl, "crit")
    r = x.cache.data("reach")
    if r and not r.get("unconfigured"):
        vpc = r.get("vpc") or []
        if vpc:
            if any(v.get("ok") for v in vpc):
                txt = "  ".join(_vpc_cell(v) for v in vpc)
            else:
                txt = T.dot("unknown") + T.dim(" no route to the private network")
            rows.append(kv("vpc", txt, W))
        eps = r.get("endpoints") or []
        items = []
        for e in eps:
            if e.get("ok"):
                l2 = "ok"
                detail = T.dim(str(e["status"])) + (T.c(" ⇄", "sky") if e.get("via") == "socks" else "")
            elif e.get("status", 0) >= 500:
                l2, detail = "warn", T.c(str(e["status"]), "amber")
                lvl = T.worst(lvl, "warn")
            else:
                l2 = "unknown"
                why = "no dns" if e.get("dns") is False and not e.get("status") else (e.get("error") or "down")
                detail = T.dim(why[:10])
            items.append(T.dot(l2) + " " + (e["label"] if l2 != "unknown" else T.dim(e["label"])) + " " + detail)
        lines = cells(items, x.cw - 1 - W, 17)
        rows += [kv("endpoints" if i == 0 else "", l, W) for i, l in enumerate(lines)]
        if r.get("hint") and any(not e.get("ok") for e in eps):
            rows.append(kv("", T.dim(str(r["hint"])[:x.cw - W - 2]), W))
    if not rows:
        return None
    return Panel("access", "ACCESS", rows, lvl, x.stale_note("reach", 4, 3600))

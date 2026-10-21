"""Panels for AI limits, edge, infra, and money."""
from __future__ import annotations

import time

from . import core, hosts, theme as T
from .panels import SEP, builder, cells, kv
from .render import Panel


def _reset(t) -> str:
    if not t:
        return ""
    left = t - core.now()
    if left <= 0:
        return "now"
    return ("↻" + core.human_age(left)) if left < 86400 else time.strftime("↻%a %H:%M", time.localtime(t))


def _window(w, bw=8) -> str:
    p = w.get("used_pct")
    if p is None:
        return T.dim("%s —" % w["label"])
    return T.dim(w["label"] + " ") + T.bar(p, bw, 75, 90) + " " + T.sev("%2d%%" % round(p), T.level_for(p, 75, 90))


@builder("ai")
def p_ai(x):
    rows, lvl = [], "ok"
    bw = 8 if x.cw < 64 else 10
    for name, key in (("claude", "claude_usage"), ("codex", "codex_usage"),
                      ("cursor", "cursor_usage"), ("grok", "grok_usage")):
        d = x.cache.data(key)
        if not d:
            continue
        plan = str(d.get("plan") or "").replace("default_claude_", "").replace("max (max_20x)", "max20x")
        if name == "claude" and "20x" in plan:
            plan = "max20x"
        else:
            plan = plan.split(" (")[0]
        head = T.c(name, "fg") + " " + T.dim(plan[:7])
        wins = [w for w in d.get("windows") or [] if w.get("label") != "api"]
        if d.get("error") and not wins:
            err = d["error"]
            hint = "login expired · run `%s login`" % name if "expired" in err else err[:60]
            rows.append(T.pad(head, 15) + T.dim(hint))
            continue
        main = wins[:2] if name != "cursor" else wins[:1]
        line = T.pad(head, 15) + "  ".join(_window(w, bw) for w in main)
        soon = min((w.get("resets_at") or 0 for w in main if w.get("resets_at")), default=0)
        if soon:
            line += " " + T.dim(_reset(soon))
        rows.append(line)
        extra = []
        if name == "claude":  # per-model weekly windows, below the 5h/7d bars
            extra = ["%s %d%%" % (w["label"], w.get("used_pct") or 0) for w in wins[2:]]
        cr = d.get("credits") or {}
        if name == "codex" and cr.get("balance") is not None:
            extra.append("%s credits" % core.human_num(cr["balance"]))
        if name == "cursor":
            if cr.get("included_limit_usd"):
                extra.append("$%.0f/$%.0f incl" % (cr.get("included_used_usd") or 0, cr["included_limit_usd"]))
            if cr.get("bonus_usd"):
                extra.append("$%.0f bonus" % cr["bonus_usd"])
            if cr.get("on_demand_used_usd"):
                extra.append(T.c("$%.0f on-demand" % cr["on_demand_used_usd"], "amber"))
        if extra:
            rows.append(" " * 15 + SEP.join(T.dim(e) if "\033" not in e else e for e in extra))
        for a in d.get("alerts") or []:
            lvl = T.worst(lvl, a.get("sev"))
    lf = (x.cache.data("langfuse") or {}).get("details") or {}
    if lf.get("projects"):
        bits = ["%s %s" % (p.get("project", "?"), T.dim("%s traces" % core.human_num(p.get("traces_24h") or 0)) +
                           (SEP + core.money(p["cost_24h_usd"]) if p.get("cost_24h_usd") else ""))
                for p in lf["projects"][:3]]
        rows.append(kv("langfuse", SEP.join(bits) + T.dim(" · 24h · v%s" % lf.get("version", "?")), 15))
    if not rows:
        return None
    return Panel("ai", "AI LIMITS", rows, lvl, x.stale_note("claude_usage", 4, 1800))


def _det(x, name) -> dict:
    return (x.cache.data(name) or {}).get("details") or {}


def _st(x, name) -> str:
    return (x.cache.data(name) or {}).get("status") or "unknown"


@builder("edge")
def p_edge(x):
    rows, lvl = [], "ok"
    ur = _det(x, "uptimerobot")
    if ur:
        down = ur.get("down") or []
        l2 = _st(x, "uptimerobot")
        lvl = T.worst(lvl, l2)
        txt = "%d/%d monitors up" % (ur.get("up", 0), ur.get("total", 0)) + (
            T.dim(" · %d ignored" % ur["ignored"]) if ur.get("ignored") else "")
        if down:
            txt += SEP + T.c(", ".join("%s %.0fd" % (d["name"][:24], d.get("down_days") or 0) for d in down[:2]), "red")
        rows.append(kv("uptime", T.dot(l2) + " " + txt, 9))
    si = x.cache.data("sites")
    if si:
        items = []
        for r in si.get("rows") or []:
            if r["up"]:
                ms = r.get("ms") or 0
                items.append(T.dot("ok") + " " + r["label"] + " " + T.sev("%d" % ms, "ok" if ms < 600 else "warn"))
            else:
                items.append(T.dot("crit") + " " + T.c(r["label"], "red") + " " + T.dim(str(r.get("error") or r.get("status"))))
                lvl = T.worst(lvl, "warn")
        lines = cells(items, x.cw - 10, 15)
        rows += [kv("sites" if i == 0 else "", l, 9) for i, l in enumerate(lines)]
    cf = _det(x, "cloudflare")
    if cf:
        tu = cf.get("tunnels") or {}
        rec = tu.get("down_recent") or []
        l2 = "crit" if rec else "ok"
        lvl = T.worst(lvl, l2)
        rows.append(kv("tunnels", T.dot(l2) + " %d/%d up" % (tu.get("healthy", 0), tu.get("healthy", 0) + len(rec)) +
                       (T.c(" · down: " + ", ".join(rec[:3]), "red") if rec else "") +
                       T.dim(" · %d retired" % tu.get("stale_down", 0) if tu.get("stale_down") else ""), 9))
        tr = cf.get("traffic_24h") or {}
        if tr:
            p5 = tr.get("pct_5xx") or 0
            rows.append(kv("cf 24h", "%s req" % core.human_num(tr.get("requests", 0)) + SEP +
                           T.sev("%d 5xx (%.1f%%)" % (tr.get("http_5xx", 0), p5), T.level_for(p5, 1, 5)) + SEP +
                           "%s threats" % core.human_num(tr.get("threats", 0)) + SEP + T.dim("%s uniq" % core.human_num(tr.get("uniques", 0))), 9))
        em = cf.get("email_routing") or {}
        if em:
            ok = em.get("enabled") and em.get("status") == "ready"
            rows.append(kv("email", T.dot("ok" if ok else "warn") + " routing %s" % em.get("status", "?") +
                           SEP + "%s delivered 24h" % ((em.get("last_24h") or {}).get("delivered", "?")), 9))
    ve = _det(x, "vercel")
    if ve:
        st = ve.get("prod_states") or {}
        bad = (ve.get("failing_24h") or []) + (ve.get("failing_7d") or [])
        if ve.get("failing_24h"):
            l2 = "crit"
        elif bad:
            l2 = "warn"
        else:
            l2 = "ok"
        lvl = T.worst(lvl, l2)
        rows.append(kv("vercel", T.dot(l2) + " %d ready" % st.get("READY", 0) + SEP + "%d building" % len(ve.get("building") or []) +
                       (T.c(" · failing: " + ", ".join(bad[:3]), "red") if bad else "") +
                       (T.dim(" · stale error: " + ", ".join(ve.get("stale_errors")[:2])) if ve.get("stale_errors") else ""), 9))
    if not rows:
        return None
    return Panel("edge", "EDGE", rows, lvl, x.stale_note("cloudflare", 4, 1800))


@builder("infra")
def p_infra(x):
    rows, lvl = [], "ok"
    hz = _det(x, "hetzner")
    if hz:
        items = []
        for s in hz.get("servers") or []:
            l2 = "ok" if s.get("status") == "running" else "crit"
            lvl = T.worst(lvl, l2)
            items.append(T.dot(l2) + " " + hosts.short(s["name"]) + T.dim(" %s · %s%% out" % (s.get("type"), s.get("traffic_out_pct", 0))))
        rows.append(kv("hetzner", "  ".join(items), 10))
        bx = hz.get("storage_box") or {}
        if bx:
            p = bx.get("used_pct") or 0
            rows.append(kv("box", T.dot(T.level_for(p, 80, 90)) + " %s " % bx.get("name", "storage box") + T.bar(p, 10, 80, 90) +
                           " " + T.sev("%d%%" % p, T.level_for(p, 80, 90)) +
                           T.dim(" %.2f/%.0f TiB" % (bx.get("used_tib") or 0, bx.get("quota_tib") or 0)), 10))
    ts = x.cache.data("tailscale") or {}
    if ts.get("installed"):
        nxt = min((r["expiry"] for r in ts.get("rows") or [] if r.get("expiry")), default=0)
        l2 = "ok" if ts.get("state") == "Running" or "#wsl" in x.host.tags else "crit"
        # +1: the status counts peers; the fleet view includes this node too.
        rows.append(kv("tailscale", T.dot(l2) + " %d/%d online" % (ts.get("online", 0) + 1, ts.get("peers", 0) + 1) +
                       (T.dim(" · next key expiry %s" % core.human_age(nxt - core.now())) if nxt else ""), 10))
    gh = _det(x, "github")
    if gh:
        repos = gh.get("repos") or []
        bits = []
        for r in repos:
            name = r["repo"].split("/")[-1]
            fail = r.get("ci_failing") or []
            l2 = "crit" if fail or r.get("head_rollup") == "FAILURE" else "ok"
            lvl = T.worst(lvl, l2)
            bits.append(T.dot(l2) + " " + name + (T.c(" ✖ " + ", ".join(fail)[:38], "red") if fail else T.dim(" ✔")))
        prs = sum(r.get("open_prs") or 0 for r in repos)
        cr = sum(r.get("changes_requested") or 0 for r in repos)
        rows.append(kv("github", "  ".join(bits), 10))
        rows.append(kv("", T.dim("%d open PRs" % prs) + (SEP + T.c("%d changes requested" % cr, "amber") if cr else ""), 10))
    se = _det(x, "sentry")
    if se:
        n = se.get("unresolved_issues_24h", 0)
        l2 = _st(x, "sentry")
        lvl = T.worst(lvl, l2)
        top = sorted((se.get("by_project") or {}).items(), key=lambda kv_: -kv_[1])[:2]
        rows.append(kv("sentry", T.dot(l2) + " %d unresolved · %d events 24h" % (n, se.get("events_24h", 0)) +
                       (T.dim(" (" + ", ".join("%s %d" % t for t in top) + ")") if top else ""), 10))
    aw = x.cache.data("aws")
    if aw:
        l2 = aw.get("status", "unknown")
        lvl = T.worst(lvl, l2 if l2 in ("warn", "crit") else "ok")
        rows.append(kv("aws", T.dot(l2) + " " + aw.get("summary", ""), 10))
    if not rows:
        return None
    return Panel("infra", "INFRA", rows, lvl, x.stale_note("hetzner", 4, 3600))


@builder("biz")
def p_biz(x):
    rows, lvl = [], "ok"
    st = _det(x, "stripe")
    if st:
        sub_info = st.get("subscriptions") or {}
        subs = sub_info.get("by_status") or {}
        mrr = (sub_info.get("mrr_est") or {}).get("usd")
        rows.append(kv("stripe", T.dot(_st(x, "stripe")) + " " + T.c(core.money((st.get("available") or {}).get("usd", 0)), "fg", bold=True) +
                       T.dim(" available") + SEP + "%d active" % subs.get("active", 0) +
                       (SEP + "MRR %s" % core.money(mrr) if mrr is not None else "") +
                       (T.c(" · %d past due" % subs.get("past_due"), "red") if subs.get("past_due") else "") +
                       T.dim(" · " + st.get("key_mode", "").replace("sk_", "")), 11))
    spend = _det(x, "ai_spend")
    if spend:
        parts = []
        for k in ("anthropic", "openai"):
            d = (spend.get(k) or {}).get("details") or {}
            if d.get("mtd_usd") is not None:
                parts.append("%s %s" % (k, T.c(core.money(d["mtd_usd"]), "fg")))
        rows.append(kv("api mtd", SEP.join(parts) or T.dim("n/a"), 11))
        orouter = spend.get("openrouter") or {}
        orr = orouter.get("details") or {}
        if orr.get("remaining_usd") is not None:
            l2 = orouter.get("status", "ok")
            lvl = T.worst(lvl, l2)
            rows.append(kv("openrouter", T.dot(l2) + " %s left" % core.money(orr["remaining_usd"]) +
                           T.dim(" of %s (%.0f%%)" % (core.money(orr.get("credits_total_usd")), orr.get("remaining_pct") or 0)), 11))
        xa = spend.get("xai") or {}
        if xa.get("status") == "unknown":
            rows.append(kv("xai", T.dot("unknown") + T.dim(" billing hidden: grant BillingRead to XAI_MGMT_KEY"), 11))
    hz = _det(x, "hetzner")
    if hz.get("est_monthly_usd"):
        rows.append(kv("hetzner", "~%s/mo" % core.money(hz["est_monthly_usd"]) + T.dim(" run-rate (no billing API)"), 11))
    cu = (x.cache.data("cursor_usage") or {}).get("credits") or {}
    if cu.get("on_demand_used_usd"):
        rows.append(kv("cursor", T.c(core.money(cu["on_demand_used_usd"]), "amber") + T.dim(" on-demand this cycle"), 11))
    if not rows:
        return None
    return Panel("biz", "MONEY", rows, lvl, x.stale_note("stripe", 4, 7200))

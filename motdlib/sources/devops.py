"""Dev-ops sources, each opt-in by listing its panel in a host's "panels":

  docker    containers grouped by compose project (up/total, unhealthy, restarting)
  aws_auth  the credentials the AWS CLI would use (static keys, SSO token expiry)
            and an STS GetCallerIdentity check. config "aws": {region, login_hint}
  ec2_fleet EC2 instances matching tag filters. config "ec2": {region, filters,
            cache_file}
  mrs       your open pull/merge requests and ones assigned to you, through the
            `gh` or `glab` CLI you are already logged in with. config "mrs":
            {provider: github|gitlab, repo, host}
  reach     the route to a private network (a TCP connect to :22 of ssh aliases)
            and a list of endpoints, optionally through a SOCKS proxy.
            config "reach" (global or per host): {ssh, endpoints, socks, hint}

What is merely environmental (off VPN, Docker Desktop not started, no AWS login
on this box) renders as state and never alerts. Alerts are for things to act on:
an unhealthy or crash-looping container, AWS credentials that exist but are
rejected, your requests with conflicts or changes requested, an endpoint
answering 5xx twice in a row.
"""
from __future__ import annotations

import configparser
import json
import os
import re
import socket
import time

from .. import core
from ..registry import source


def _wants(panel):
    return lambda host: panel in host.panels


# ── Docker compose stacks ───────────────────────────────────────────────────
_PS_FORMAT = ('{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Label "com.docker.compose.project"}}'
              '\t{{.Label "com.docker.compose.service"}}')
_EXITED = re.compile(r"Exited \((-?\d+)\)\s+(?:Less than a second|(?:About\s+)?(an?|\d+)\s+"
                     r"(second|minute|hour|day|week|month|year)s?)\s+ago")
_UNIT_S = {"second": 1, "minute": 60, "hour": 3600, "day": 86400, "week": 604800, "month": 2592000, "year": 31536000}
RECENT_FAIL_S = 6 * 3600  # an older crash is history, not news


def _exit_info(status: str):
    """'Exited (1) 3 hours ago' → (1, 10800); (None, None) when unparseable."""
    m = _EXITED.search(status or "")
    if not m:
        code = re.search(r"Exited \((-?\d+)\)", status or "")
        return (int(code.group(1)) if code else None), None
    if m.group(2) is None:  # "Less than a second ago"
        return int(m.group(1)), 0
    n = 1 if m.group(2) in ("a", "an") else int(m.group(2))
    return int(m.group(1)), n * _UNIT_S[m.group(3)]


def parse_ps(text: str) -> dict:
    """`docker ps -a` rows (_PS_FORMAT) → per compose project counts and problems."""
    projects = {}
    other = {"running": 0, "total": 0}
    for line in (text or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        name, state, status, project, service = parts[:5]
        if not project:
            other["total"] += 1
            other["running"] += state == "running"
            continue
        p = projects.setdefault(project, {"name": project, "running": 0, "total": 0, "done": 0, "starting": 0,
                                          "unhealthy": [], "restarting": [], "failed": []})
        p["total"] += 1
        label = service or name
        if state == "running":
            p["running"] += 1
            if "(unhealthy)" in status:
                p["unhealthy"].append(label)
            elif "health: starting" in status:
                p["starting"] += 1
        elif state == "restarting":
            p["restarting"].append(label)
        elif state in ("exited", "dead"):
            code, ago = _exit_info(status)
            if code == 0:
                p["done"] += 1  # one-shots (migrations) finish with 0 by design
            elif code not in (130, 143):  # SIGINT/SIGTERM: `compose stop`, not a crash
                p["failed"].append({"name": label, "code": code, "ago": ago})
    rows = sorted(projects.values(), key=lambda p: (not active(p), p["name"]))
    return {"projects": rows, "other": other}


def active(p) -> bool:
    """Running, or crash-looping: a project whose containers all restart is not stopped."""
    return bool(p["running"] or p["restarting"])


def stack_alerts(projects) -> list:
    out = []
    for p in projects:
        if not active(p):
            continue  # a stopped stack is a choice, not a fault
        bits = []
        for key in ("unhealthy", "restarting"):
            if p[key]:
                bits.append("%d %s (%s)" % (len(p[key]), key, ", ".join(p[key][:3])))
        fresh = [f for f in p["failed"] if f.get("ago") is not None and f["ago"] < RECENT_FAIL_S]
        if fresh:
            bits.append("%s exited %s" % (", ".join(f["name"] for f in fresh[:3]),
                                         "/".join(sorted({str(f["code"]) for f in fresh}))))
        if bits:
            out.append({"sev": "warn", "msg": "%s stack: %s" % (p["name"], "; ".join(bits))})
    return out


def _docker_bin():
    return core.which("docker", ("/Applications/Docker.app/Contents/Resources/bin",
                                 os.path.join(core.HOME, ".orbstack", "bin"), os.path.join(core.HOME, ".docker", "bin")))


@source("docker", ttl=120, timeout=10, hosts=_wants("docker"))
def docker(ctx):
    """Docker containers per compose project."""
    dk = _docker_bin()
    if not dk:
        return {"docker": "missing"}
    rc, out, err = core.run([dk, "ps", "-a", "--format", _PS_FORMAT], 8)
    if rc != 0:
        low = (err or "").lower()
        if rc == 124 or "cannot connect" in low or "daemon running" in low or "error during connect" in low:
            return {"docker": "down"}
        raise RuntimeError("docker ps rc %d: %s" % (rc, (err or out).strip()[:160]))
    data = parse_ps(out)
    data["docker"] = "up"
    al = stack_alerts(data["projects"])
    if al:
        data["alerts"] = al
    return data


# ── AWS credentials ─────────────────────────────────────────────────────────
_AWS_DIR = os.path.join(core.HOME, ".aws")
STS_RECHECK_S = 1800  # GetCallerIdentity again after this, or as soon as the credential files change


def _ini(path: str) -> dict:
    cp = configparser.RawConfigParser()
    try:
        cp.read(path, encoding="utf-8")
    except (configparser.Error, OSError, UnicodeDecodeError):
        return {}
    return {s: dict(cp.items(s)) for s in cp.sections()}


def aws_files(aws_dir: str = _AWS_DIR) -> dict:
    """What the credential files say, without the network: static-key profiles,
    SSO profiles and the newest SSO access token's expiry. Never reads a key out."""
    creds_path, cfg_path = os.path.join(aws_dir, "credentials"), os.path.join(aws_dir, "config")
    creds, cfg = _ini(creds_path), _ini(cfg_path)
    sso = [s.replace("profile ", "", 1) for s, kv in cfg.items()
           if not s.startswith("sso-session") and (kv.get("sso_session") or kv.get("sso_start_url"))]
    account = next((kv["sso_account_id"] for kv in cfg.values() if kv.get("sso_account_id")), None)
    expires, refreshable = 0, False
    cache = os.path.join(aws_dir, "sso", "cache")
    try:
        names = os.listdir(cache)
    except OSError:
        names = []
    for n in names:
        if not n.endswith(".json") or n.startswith("botocore-client"):
            continue
        j = core.read_json(os.path.join(cache, n)) or {}
        # Only AWS SSO tokens carry startUrl (other CLIs, e.g. kiro, share this dir).
        if isinstance(j, dict) and j.get("startUrl") and j.get("accessToken") and j.get("expiresAt"):
            exp = core.utc_epoch(str(j["expiresAt"]))
            if exp >= expires:
                expires, refreshable = exp, bool(j.get("refreshToken"))
    return {"static": sorted(s for s, kv in creds.items() if kv.get("aws_access_key_id")),
            "sso": {"profiles": sso, "account": account, "expires": expires or None, "refreshable": refreshable},
            "fp": [core.mtime(creds_path), core.mtime(cfg_path), expires,
                   bool(os.environ.get("AWS_ACCESS_KEY_ID")), os.environ.get("AWS_PROFILE") or ""]}


def _region(section: str = "aws") -> str:
    """config.json "<section>".region, else the shell's AWS_REGION, else us-east-1."""
    return ((core.config().get(section) or {}).get("region") or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1")


def _aws_env(region: str) -> dict:
    """The collector's own environment (what a fresh shell's `aws` would see) pinned to
    one region. A Bedrock bearer token, which tools may export, does not belong in an
    EC2/STS call."""
    env = dict(os.environ)
    env.pop("AWS_BEARER_TOKEN_BEDROCK", None)
    env.update(AWS_REGION=region, AWS_DEFAULT_REGION=region, AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off")
    return env


_REJECTED = {"ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "SignatureDoesNotMatch",
             "AccessDenied", "AccessDeniedException", "UnrecognizedClientException", "InvalidAccessKeyId",
             "AuthFailure", "UnauthorizedOperation"}
_REJECTED_TEXT = ("token has expired", "sso session", "error loading sso token", "refresh failed",
                  "security token included in the request is invalid")


def classify_sts(rc: int, out: str, err: str) -> dict:
    """An `aws` call's outcome → ok | rejected (credentials exist, AWS says no) |
    none (nothing configured) | unreachable (network) | error (anything else)."""
    if rc == 0:
        try:
            j = json.loads(out)
        except ValueError:
            return {"state": "error", "error": "unparseable sts reply"}
        arn = j.get("Arn") or ""
        tail = arn.split(":", 5)[-1] if arn.count(":") >= 5 else arn
        principal = ("role/" + tail.split("/")[1]) if tail.startswith("assumed-role/") else tail
        return {"state": "ok", "account": j.get("Account"), "principal": principal}
    text = " ".join((err or out or "").split())
    low = text.lower()
    m = re.search(r"\(([A-Za-z]+)\)", text)
    code = m.group(1) if m else ""
    if rc == 124 or any(s in low for s in ("could not connect", "connect timeout", "read timeout",
                                           "name or service not known", "nodename nor servname")):
        state = "unreachable"
    elif "unable to locate credentials" in low or "could not be found" in low:
        state = "none"
    elif code in _REJECTED or any(s in low for s in _REJECTED_TEXT):
        state = "rejected"
    else:
        state = "error"
    return {"state": state, "error": code or text[:100] or "rc %d" % rc}


@source("aws_auth", ttl=300, timeout=20, hosts=_wants("access"))
def aws_auth(ctx):
    """AWS credentials: static keys, SSO expiry, and an STS identity check."""
    region = _region()
    f = aws_files()
    aws = core.which("aws")
    data = {"cli": bool(aws), "region": region, "static": f["static"], "sso": f["sso"]}
    if not aws:
        return data
    prev = (ctx.prev or {}).get("sts") or {}
    if (prev and prev.get("fp") == f["fp"] and core.now() - prev.get("at", 0) < STS_RECHECK_S
            and prev.get("state") != "unreachable"):
        data["sts"] = prev
    else:
        rc, out, err = core.run([aws, "sts", "get-caller-identity", "--output", "json", "--region", region],
                                15, env=_aws_env(region))
        data["sts"] = dict(classify_sts(rc, out, err), at=core.now(), fp=f["fp"])
    if data["sts"]["state"] == "rejected":
        hint = (core.config().get("aws") or {}).get("login_hint") or "aws sso login"
        data["sts"]["hint"] = hint
        data["alerts"] = [{"sev": "warn", "msg": "AWS credentials rejected (%s) · run %s" % (data["sts"]["error"], hint)}]
    return data


# ── GCP and Azure credentials ───────────────────────────────────────────────
_GCP_REJECTED = ("reauthentication", "invalid_grant", "problem refreshing", "token has been expired", "refresh token")
_AZ_REJECTED = ("aadsts", "refresh token", "expired", "interactive authentication is needed")


def classify_cli(rc: int, err: str, rejected_words, none_words) -> str:
    """A cloud CLI's outcome → ok | rejected | none | unreachable | error."""
    low = " ".join((err or "").split()).lower()
    if rc == 0:
        return "ok"
    if rc == 124 or any(s in low for s in ("unable to connect", "connection", "timed out", "name resolution", "network")):
        return "unreachable"
    if any(s in low for s in rejected_words):  # before none: an expired-token error also says "run az login"
        return "rejected"
    if any(s in low for s in none_words):
        return "none"
    return "error"


@source("gcp_auth", ttl=600, timeout=25, hosts=_wants("access"))
def gcp_auth(ctx):
    """gcloud: the active account and project, proven by one read-only API call."""
    cfg = core.config().get("gcp")
    if cfg is None:
        return {"unconfigured": True}
    gc = core.which("gcloud")
    if not gc:
        return {"cli": False}
    rc, out, err = core.run([gc, "auth", "list", "--filter=status:ACTIVE", "--format=value(account)"], 10)
    account = out.strip().splitlines()[0] if rc == 0 and out.strip() else ""
    project = (cfg or {}).get("project") or core.run([gc, "config", "get-value", "project"], 8)[1].strip()
    data = {"cli": True, "account": account, "project": project}
    if not account:
        data.update(state="none", error="no active account")
        return data
    if not project or not re.match(r"^[a-z][a-z0-9\-]{4,61}[a-z0-9]$", project):
        data.update(state="error", error="no project set")
        return data
    rc, _, err = core.run([gc, "projects", "describe", project, "--format=value(projectId)"], 20)
    state = classify_cli(rc, err, _GCP_REJECTED, ("you do not currently have an active account",))
    data.update(state=state, error=None if state == "ok" else (err.strip().splitlines() or ["rc %d" % rc])[-1][:100])
    if state == "rejected":
        hint = (cfg or {}).get("login_hint") or "gcloud auth login"
        data["hint"] = hint
        data["alerts"] = [{"sev": "warn", "msg": "GCP credentials rejected · run %s" % hint}]
    return data


@source("azure_auth", ttl=600, timeout=25, hosts=_wants("access"))
def azure_auth(ctx):
    """az: the signed-in account and its access-token expiry (the token itself is never read)."""
    cfg = core.config().get("azure")
    if cfg is None:
        return {"unconfigured": True}
    az = core.which("az")
    if not az:
        return {"cli": False}
    rc, out, err = core.run([az, "account", "show", "-o", "json"], 15)
    if rc != 0:
        state = classify_cli(rc, err, _AZ_REJECTED, ("az login", "please run 'az login'"))
        data = {"cli": True, "state": state, "error": (err.strip().splitlines() or ["rc %d" % rc])[-1][:100]}
    else:
        try:
            acct = json.loads(out)
        except ValueError:
            acct = {}
        data = {"cli": True, "account": (acct.get("user") or {}).get("name") or "", "subscription": acct.get("name") or ""}
        # --query keeps the access token itself out of our output.
        rc2, out2, err2 = core.run([az, "account", "get-access-token", "--query", "expiresOn", "-o", "tsv"], 15)
        if rc2 == 0:
            data.update(state="ok", expires=core.utc_epoch(out2.strip().replace(" ", "T")) or None)
        else:
            state = classify_cli(rc2, err2, _AZ_REJECTED, ("az login",))
            data.update(state=state, error=(err2.strip().splitlines() or ["rc %d" % rc2])[-1][:100])
    if data.get("state") == "rejected":
        hint = (cfg or {}).get("login_hint") or "az login"
        data["hint"] = hint
        data["alerts"] = [{"sev": "warn", "msg": "Azure credentials rejected · run %s" % hint}]
    return data


# ── EC2 instances ───────────────────────────────────────────────────────────
_EC2_QUERY = ("Reservations[].Instances[].[Tags[?Key==`Name`]|[0].Value,InstanceType,PrivateIpAddress,"
              "InstanceId,LaunchTime,State.Name]")


def parse_instances(text: str) -> list:
    """describe-instances text output (name, type, ip, id, launched, state) → rows."""
    rows = []
    for line in (text or "").splitlines():
        p = line.split("\t")
        if len(p) < 6 or not p[3].startswith("i-"):
            continue
        name, itype, ip, iid, launched, state = p[:6]
        rows.append({"name": iid if name in ("None", "") else name, "type": itype,
                     "ip": "" if ip in ("None", "") else ip, "id": iid,
                     "launched": core.utc_epoch(launched), "state": state})
    order = {"running": 0, "pending": 1, "stopping": 2, "stopped": 3}
    return sorted(rows, key=lambda r: (order.get(r["state"], 4), r["name"]))


_TAG_KEY, _TAG_VAL = re.compile(r"^[A-Za-z0-9:_./-]+$"), re.compile(r"^[A-Za-z0-9:_./@=+-]+$")


def _ec2_filters(cfg: dict) -> list:
    """config "ec2".filters {"Owner": ["a", "b"]} → ["Name=tag:Owner,Values=a,b", ...]."""
    out = []
    for tag, values in (cfg.get("filters") or {}).items():
        vals = [str(v) for v in ([values] if isinstance(values, str) else values)]
        if _TAG_KEY.match(tag) and vals and all(_TAG_VAL.match(v) for v in vals):
            out.append("Name=tag:%s,Values=%s" % (tag, ",".join(vals)))
    return out


@source("ec2_fleet", ttl=600, timeout=25, hosts=_wants("ec2"))
def ec2_fleet(ctx):
    """EC2 instances matching config "ec2".filters, or a cached TSV when AWS says no."""
    cfg = core.config().get("ec2") or {}
    if not cfg:
        return {"unconfigured": True}
    region = _region("ec2")
    cache_file = os.path.expanduser(cfg.get("cache_file") or "")
    aws, err = core.which("aws"), "aws CLI not installed"
    if aws:
        argv = [aws, "--region", region, "ec2", "describe-instances", "--filters"] + _ec2_filters(cfg) + [
            "Name=instance-state-name,Values=running,stopped,stopping,pending",
            "--query", _EC2_QUERY, "--output", "text"]
        rc, out, e = core.run(argv, 20, env=_aws_env(region))
        if rc == 0:
            rows = parse_instances(out)
            return {"src": "aws", "asof": core.now(), "rows": rows, "region": region,
                    "running": sum(1 for r in rows if r["state"] == "running"), "total": len(rows)}
        err = classify_sts(rc, out, e)["error"]  # never empty for a non-zero rc
    rows = parse_instances(core.read_text(cache_file)) if cache_file else []
    if rows:
        return {"src": "cache", "asof": core.mtime(cache_file), "rows": rows, "error": err, "region": region,
                "running": sum(1 for r in rows if r["state"] == "running"), "total": len(rows)}
    raise RuntimeError("describe-instances failed (%s) and no cache" % err)


# ── Pull / merge requests (gh or glab) ──────────────────────────────────────
_SAFE_REPO = re.compile(r"^[A-Za-z0-9_.\-]+(/[A-Za-z0-9_.\-]+)*$")
_SAFE_HOST = re.compile(r"^[A-Za-z0-9.\-]+(:\d+)?$")
GH_FIELDS = "number,title,mergeable,reviewDecision,updatedAt,headRefName,latestReviews"


def _gh_row(i) -> dict:
    merge = {"CONFLICTING": "conflicts", "MERGEABLE": "mergeable"}.get(i.get("mergeable"), "unknown")
    return {"n": i.get("number"), "title": (i.get("title") or "")[:120], "merge": merge,
            "approvals": sum(1 for r in i.get("latestReviews") or [] if r.get("state") == "APPROVED"),
            "changes": 1 if i.get("reviewDecision") == "CHANGES_REQUESTED" else 0,
            "updated": core.utc_epoch(str(i.get("updatedAt") or "")), "branch": i.get("headRefName") or ""}


def _gl_row(i) -> dict:
    status = i.get("detailed_merge_status") or ""
    merge = "conflicts" if i.get("has_conflicts") or status == "conflict" else "mergeable" if status == "mergeable" else "unknown"
    return {"n": i.get("iid"), "title": (i.get("title") or "")[:120], "merge": merge,
            "approvals": 0, "changes": 1 if status == "requested_changes" else 0,
            "updated": core.utc_epoch(str(i.get("updated_at") or "")), "branch": i.get("source_branch") or ""}


def summarize(mine, assigned) -> dict:
    """Normalized rows → mine + assigned-to-me, newest first (assigned excludes your own)."""
    own = {m["n"] for m in mine}
    mine = sorted(mine, key=lambda r: -r["updated"])
    assigned = sorted((r for r in assigned if r["n"] not in own), key=lambda r: -r["updated"])
    return {"mine": mine[:20], "assigned": assigned[:10]}


def mr_alerts(mine, noun: str = "MR", prefix: str = "!") -> list:
    out = []
    conf = ["%s%s" % (prefix, m["n"]) for m in mine if m["merge"] == "conflicts"]
    chg = ["%s%s" % (prefix, m["n"]) for m in mine if m["changes"]]
    if conf:
        out.append({"sev": "warn", "msg": "%d of your %ss %s merge conflicts (%s)" % (
            len(conf), noun, "has" if len(conf) == 1 else "have", ", ".join(conf[:4]))})
    if chg:
        out.append({"sev": "warn", "msg": "changes requested on %s" % ", ".join(chg[:4])})
    return out


def _json_run(argv, timeout=20):
    rc, out, err = core.run(argv, timeout)
    if rc != 0:
        raise RuntimeError((err or out).strip().splitlines()[-1][:160] if (err or out).strip() else "rc %d" % rc)
    try:
        return json.loads(out or "null")
    except ValueError:
        raise RuntimeError("unparseable reply") from None


def _fetch_github(cfg, gh):
    repo = cfg["repo"]
    base = [gh, "pr", "list", "--repo", repo, "--state", "open", "--json", GH_FIELDS]
    jobs = {"mine": lambda: _json_run(base + ["--author", "@me", "--limit", "50"]),
            "review": lambda: _json_run(base + ["--search", "review-requested:@me", "--limit", "20"]),
            "assignee": lambda: _json_run(base + ["--search", "assignee:@me", "--limit", "20"]),
            "all": lambda: _json_run([gh, "pr", "list", "--repo", repo, "--state", "open", "--json", "number", "--limit", "100"])}
    res = _gather(jobs)
    mine = [_gh_row(i) for i in res["mine"]]
    asg = [_gh_row(i) for i in (res["review"] or []) + (res["assignee"] or [])]
    return mine, asg, len(res["all"]), len(res["all"]) >= 100


def _fetch_gitlab(cfg, glab):
    import urllib.parse
    proj = urllib.parse.quote(str(cfg["repo"]), safe="")
    host = ["--hostname", cfg["host"]] if cfg.get("host") else []

    def q(scope):
        url = "projects/%s/merge_requests?state=opened&per_page=100%s" % (proj, ("&scope=" + scope) if scope else "")
        return lambda: _json_run([glab, "api"] + host + [url])
    res = _gather({"mine": q("created_by_me"), "assigned": q("assigned_to_me"), "all": q("")})
    return ([_gl_row(i) for i in res["mine"]], [_gl_row(i) for i in res["assigned"]],
            len(res["all"]), len(res["all"]) >= 100)


def _api(url, env_headers, what):
    """GET JSON from a forge API; RuntimeError with a short reason otherwise (soft failure upstream)."""
    try:
        r = core.http(url, headers=env_headers, timeout=10)
    except Exception as e:  # noqa: BLE001 — DNS, TLS, timeout: the forge is unreachable
        raise RuntimeError("%s unreachable (%s)" % (what, type(e).__name__)) from None
    if r.status in (401, 403):
        raise RuntimeError("%s: HTTP %d (token rejected)" % (what, r.status))
    if not r.ok or not isinstance(r.body, (dict, list)):
        raise RuntimeError("%s: HTTP %s" % (what, r.status))
    return r.body


def _gitea_row(i, reviews=()) -> dict:
    latest = {}
    for rv in reviews or ():  # oldest first: the last word per reviewer wins
        who = (rv.get("user") or {}).get("login")
        if who and rv.get("state") in ("APPROVED", "REQUEST_CHANGES", "COMMENT"):
            latest[who] = rv["state"]
    merge = "unknown" if i.get("mergeable") is None else ("mergeable" if i.get("mergeable") else "conflicts")
    return {"n": i.get("number"), "title": (i.get("title") or "")[:120], "merge": merge,
            "approvals": sum(1 for s in latest.values() if s == "APPROVED"),
            "changes": 1 if "REQUEST_CHANGES" in latest.values() else 0,
            "updated": core.utc_epoch(str(i.get("updated_at") or "")), "branch": (i.get("head") or {}).get("ref") or ""}


def _fetch_gitea(cfg, env):
    """Gitea / Forgejo: {provider: gitea, url: https://host, repo: owner/name, token_env: GITEA_TOKEN}."""
    tok = env.get(cfg.get("token_env") or "GITEA_TOKEN") or ""
    if not tok:
        raise RuntimeError("set %s in the env file" % (cfg.get("token_env") or "GITEA_TOKEN"))
    base = cfg["url"].rstrip("/") + "/api/v1"
    h = {"Authorization": "token " + tok}
    me = (_api(base + "/user", h, "gitea") or {}).get("login")
    pulls = _api(base + "/repos/%s/pulls?state=open&limit=50" % cfg["repo"], h, "gitea") or []
    mine_raw = [p for p in pulls if (p.get("user") or {}).get("login") == me]
    revs = _gather({str(p["number"]): (lambda n=p["number"]: _api(base + "/repos/%s/pulls/%d/reviews" % (cfg["repo"], n), h, "gitea"))
                    for p in mine_raw[:10]}) if mine_raw else {}
    mine = [_gitea_row(p, revs.get(str(p["number"]))) for p in mine_raw]
    asg = [_gitea_row(p) for p in pulls if (p.get("user") or {}).get("login") != me and me in
           {u.get("login") for u in (p.get("assignees") or []) + (p.get("requested_reviewers") or [])}]
    return mine, asg, len(pulls), len(pulls) >= 50


def _bb_row(i) -> dict:
    parts = i.get("participants") or []
    return {"n": i.get("id"), "title": (i.get("title") or "")[:120], "merge": "unknown",
            "approvals": sum(1 for p in parts if p.get("approved")),
            "changes": 1 if any(p.get("state") == "changes_requested" for p in parts) else 0,
            "updated": core.utc_epoch(str(i.get("updated_on") or "")),
            "branch": ((i.get("source") or {}).get("branch") or {}).get("name") or ""}


def _fetch_bitbucket(cfg, env):
    """Bitbucket Cloud: {provider: bitbucket, repo: workspace/slug}; BITBUCKET_TOKEN, or
    BITBUCKET_USER + BITBUCKET_APP_PASSWORD, in the env file."""
    import base64
    if env.get("BITBUCKET_TOKEN"):
        h = {"Authorization": "Bearer " + env["BITBUCKET_TOKEN"]}
    elif env.get("BITBUCKET_USER") and env.get("BITBUCKET_APP_PASSWORD"):
        h = {"Authorization": "Basic " + base64.b64encode(("%s:%s" % (env["BITBUCKET_USER"], env["BITBUCKET_APP_PASSWORD"])).encode()).decode()}
    else:
        raise RuntimeError("set BITBUCKET_TOKEN (or BITBUCKET_USER and BITBUCKET_APP_PASSWORD) in the env file")
    api = "https://api.bitbucket.org/2.0"
    me = (_api(api + "/user", h, "bitbucket") or {}).get("uuid")
    page = _api(api + "/repositories/%s/pullrequests?state=OPEN&pagelen=50&fields=%%2Bvalues.participants,%%2Bvalues.reviewers"
                % cfg["repo"], h, "bitbucket") or {}
    pulls = page.get("values") or []
    mine = [_bb_row(p) for p in pulls if (p.get("author") or {}).get("uuid") == me]
    asg = [_bb_row(p) for p in pulls if (p.get("author") or {}).get("uuid") != me and
           me in {r.get("uuid") for r in p.get("reviewers") or []}]
    return mine, asg, page.get("size", len(pulls)), bool(page.get("next"))


PROVIDERS = {"github": ("PR", "#"), "gitlab": ("MR", "!"), "gitea": ("PR", "#"), "forgejo": ("PR", "#"),
             "bitbucket": ("PR", "#")}


def _gather(jobs: dict) -> dict:
    """Run the jobs concurrently; the first failure of any raises (a partial list would mislead)."""
    out = {}
    errs = []

    def wrap(k, fn):
        def run():
            try:
                out[k] = fn()
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        return run
    core.parallel({k: wrap(k, fn) for k, fn in jobs.items()}, timeout=30)
    if errs:
        raise errs[0]
    if len(out) != len(jobs):
        raise RuntimeError("timeout")
    return out


@source("mrs", ttl=900, timeout=40, hosts=_wants("mrs"))
def mrs(ctx):
    """Your open pull/merge requests and ones waiting on you: GitHub/GitLab through gh/glab,
    Gitea/Forgejo and Bitbucket Cloud through their APIs with a token from the env file."""
    cfg = core.config().get("mrs") or {}
    provider = cfg.get("provider")
    url_ok = re.match(r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~\-/]*)?$", str(cfg.get("url") or ""))
    if provider not in PROVIDERS or not _SAFE_REPO.match(str(cfg.get("repo") or "")) or (
            cfg.get("host") and not _SAFE_HOST.match(str(cfg["host"]))) or (provider in ("gitea", "forgejo") and not url_ok):
        return {"installed": False, "error": 'config "mrs" needs provider (%s), repo, and url for gitea' % "|".join(PROVIDERS)}
    noun, prefix = PROVIDERS[provider]
    if provider in ("github", "gitlab"):
        cli = core.which("gh" if provider == "github" else "glab")
        if not cli:
            return {"installed": False}  # no CLI on this box: no panel, no nagging
        fetch = lambda: (_fetch_github if provider == "github" else _fetch_gitlab)(cfg, cli)  # noqa: E731
    elif provider == "bitbucket":
        fetch = lambda: _fetch_bitbucket(cfg, ctx.env)  # noqa: E731
    else:
        fetch = lambda: _fetch_gitea(cfg, ctx.env)  # noqa: E731
    try:
        mine, asg, total, truncated = fetch()
    except RuntimeError as e:
        # Off VPN the forge is unreachable. {error, status: unknown} is a soft failure:
        # the collector keeps the last good record and the panel shows the stale list.
        return {"up": True, "error": str(e)[:160], "status": "unknown"}
    data = dict(summarize(mine, asg), up=True, repo=cfg["repo"], open=total, truncated=truncated,
                me=True, noun=noun, prefix=prefix, provider=provider)
    al = mr_alerts(data["mine"], noun, prefix)
    if al:
        data["alerts"] = al
    return data


# ── Reachability: a private network route and a list of endpoints ───────────
def _reach_cfg(host) -> dict:
    return host.reach or core.config().get("reach") or {}


def _endpoint_items(cfg: dict) -> list:
    """[(label, url, verify_tls)] from config "reach".endpoints: [label, url] or [label, url, false]."""
    out = []
    for e in cfg.get("endpoints") or []:
        if len(e) >= 2 and str(e[1]).startswith(("http://", "https://")):
            out.append((str(e[0]), str(e[1]), e[2] if len(e) > 2 else True))
    return out


def _resolve(host: str):
    try:
        return socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)[0][4][0]
    except (OSError, IndexError):
        return None


def _why(e) -> str:
    """A transport failure in two words (URLError wraps the cause in .reason)."""
    import ssl
    import urllib.error
    r = e.reason if isinstance(e, urllib.error.URLError) else e
    if isinstance(r, ssl.SSLError):
        return "tls error"
    if isinstance(r, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(r, ConnectionRefusedError):
        return "refused"
    if isinstance(r, socket.gaierror):
        return "no dns"
    return "no route" if isinstance(r, OSError) else "down"


def _get(url: str, verify: bool, timeout: float = 6.0):
    """(status, ms, why). Redirects are not followed: a 302 to a login page is up."""
    import ssl
    import urllib.error
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    t0, why = time.monotonic(), None
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "fleet-motd/1"}), timeout=timeout) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    except Exception as e:  # noqa: BLE001 — DNS, refused, TLS, timeout
        status, why = 0, _why(e)
    return status, int((time.monotonic() - t0) * 1000), why


def _get_socks(url: str, verify: bool, proxy: str):
    """The same GET through a SOCKS5 proxy "host:port" (names resolve at the proxy)."""
    curl = core.which("curl")
    if not curl:
        return 0, 0, "no curl"
    argv = [curl, "-sS", "-o", "/dev/null", "-w", "%{http_code} %{time_total}", "--max-time", "6",
            "--socks5-hostname", proxy] + ([] if verify else ["-k"]) + [url]
    rc, out, _ = core.run(argv, 8)
    parts = out.split()
    if rc == 0 and len(parts) == 2 and parts[0].isdigit():
        return int(parts[0]), int(float(parts[1]) * 1000), None
    return 0, 0, "curl rc %d" % rc


def _ssh_opt(cfg: str, key: str, default: str) -> str:
    """The value of the first `key value` line in `ssh -G` output."""
    return next((l.split(None, 1)[1].strip() for l in cfg.splitlines() if l.lower().startswith(key + " ")), default)


def _vpc_probe(alias: str) -> dict:
    """ssh -G gives the alias' address offline; a TCP connect to :22 proves the route."""
    ssh = core.which("ssh") or "/usr/bin/ssh"
    rc, out, _ = core.run([ssh, "-G", alias], 3)
    host, port = _ssh_opt(out, "hostname", ""), _ssh_opt(out, "port", "22")
    if not host:
        return {"alias": alias, "ok": False, "error": "no ssh config"}
    t0 = time.monotonic()
    try:
        socket.create_connection((host, int(port) if port.isdigit() else 22), timeout=3).close()
        return {"alias": alias, "ip": host, "ok": True, "ms": int((time.monotonic() - t0) * 1000)}
    except OSError as e:
        return {"alias": alias, "ip": host, "ok": False, "error": _why(e)}


def _endpoint(item, proxy):
    label, url, verify = item
    host = url.split("/")[2].split(":")[0]
    dns = _resolve(host) is not None
    status, ms, err = _get(url, verify) if dns else (0, 0, "no dns")
    via = "direct"
    if not status and proxy:
        via = "socks"
        status, ms, socks_err = _get_socks(url, verify, proxy)
        err = err or socks_err
    return {"label": label, "status": status, "ms": ms, "ok": 0 < status < 500, "dns": dns,
            "via": via if status else None, "error": None if status else err}


_SSH_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]*$")  # never an option: `ssh -G -oProxyCommand=...`


@source("reach", ttl=600, timeout=20, hosts=_wants("access"))
def reach(ctx):
    """A private-network route (ssh :22) and endpoints, directly or through a SOCKS proxy."""
    cfg = _reach_cfg(ctx.host)
    aliases = [a for a in cfg.get("ssh") or [] if isinstance(a, str) and _SSH_ALIAS.match(a)]
    eps = _endpoint_items(cfg)
    if not (aliases or eps):
        return {"unconfigured": True}
    proxy = cfg.get("socks") if re.match(r"^[A-Za-z0-9.\-]+:\d+$", str(cfg.get("socks") or "")) else None
    jobs = {"vpc:" + a: (lambda a=a: _vpc_probe(a)) for a in aliases}
    jobs.update({"ep:" + e[0]: (lambda e=e: _endpoint(e, proxy)) for e in eps})
    res = core.parallel(jobs, timeout=16)
    vpc = [res.get("vpc:" + a) or {"alias": a, "ok": False, "error": "timeout"} for a in aliases]
    out = [res.get("ep:" + e[0]) or {"label": e[0], "status": 0, "ok": False, "error": "timeout"} for e in eps]
    data = {"vpc": vpc, "endpoints": out, "socks": proxy, "hint": cfg.get("hint")}
    # Two strikes: a 5xx now and on the previous run (deploys restart things).
    was = {r["label"] for r in (ctx.prev or {}).get("endpoints") or [] if r.get("status", 0) >= 500}
    bad = [r for r in out if r["status"] >= 500 and r["label"] in was]
    if bad:
        data["alerts"] = [{"sev": "warn", "msg": "%s answers HTTP %d" % (r["label"], r["status"])} for r in bad]
    return data

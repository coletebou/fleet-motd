#!/usr/bin/env python3
"""Offline checks for fleet-motd: width math, cache ranking,
due/fallback logic, flap guard, secret redaction, bundle scope, and a render
smoke test at phone, laptop and wide widths against a synthetic cache."""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="motd-test-")
os.environ["MOTD_CACHE_DIR"] = TMP          # paths are resolved at import time
os.environ["MOTD_CONFIG_DIR"] = os.path.join(TMP, "config")  # never read the developer's own config
os.environ["MOTD_COLOR"] = "truecolor"
os.environ.pop("NO_COLOR", None)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motdlib import alerts, collect, core, hosts, registry, render, theme as T  # noqa: E402
from motdlib import sources  # noqa: E402,F401
from motdlib.sources import _sys, fleet  # noqa: E402


HUB = hosts.Host("hub", {"label": "hub", "tags": ["#linux", "#server", "#hub"], "peers": ["web"],
                         "units": [["myapp-web", "web", "system"]], "mounts": ["/"],
                         "panels": ["system", "services", "agents", "fleet", "ai", "edge", "infra", "biz", "repo"]})
WEB = hosts.Host("web", {"label": "web", "tags": ["#linux", "#server"], "units": [["myapp-web", "web", "system"]]})
DEVBOX = hosts.Host("devbox", {"label": "devbox", "tags": ["#linux", "#dev"], "ports": [[3000, "api"]],
                               "panels": ["system", "services", "docker", "mrs", "ec2", "access"]})
LAPTOP = hosts.Host("laptop", {"label": "laptop", "tags": ["#mac", "#dev"], "panels": ["system", "agents", "fleet", "ai"]})


def write_config(cfg):
    os.makedirs(core.CONFIG_DIR, exist_ok=True)
    Path(core.CONFIG_DIR, "config.json").write_text(json.dumps(cfg))


def reset_notify_state():
    try:
        os.remove(os.path.join(core.STATE_DIR, "notify.json"))
    except OSError:
        pass


def put(name, data, ok=True, age=0.0, **extra):
    core.ensure_dirs()
    rec = {"v": 2, "name": name, "ts": time.time() - age, "ok": ok, "data": data}
    rec.update(extra)
    core.write_json_atomic(registry.src_path(name), rec)


class Width(unittest.TestCase):
    def test_ansi_and_emoji_width(self):
        self.assertEqual(T.width(T.c("hello", "gold")), 5)
        self.assertEqual(T.width("☀️ 61°F"), 7)          # VS16 forces emoji width 2
        self.assertEqual(T.width("━━╸──"), 5)

    def test_fit_keeps_width_and_escapes(self):
        s = T.fit(T.c("hello world", "gold"), 7)
        self.assertEqual(T.width(s), 7)
        self.assertTrue(T.strip(s).endswith("…"))
        self.assertEqual(T.width(T.pad(T.c("ab", "red"), 6, ">")), 6)

    def test_bar_is_exactly_w_cells(self):
        for p in (0, 1, 49.9, 50, 99.9, 100, 140):
            self.assertEqual(T.width(T.bar(p, 12)), 12, p)


class CacheRanking(unittest.TestCase):
    def test_soft_error_never_shadows_good_hub_data(self):
        write_config({"enable": ["claude_usage"]})  # opt-in sources are hidden until enabled
        put("claude_usage", {"error": "token expired", "windows": []}, age=0)
        core.write_json_atomic(core.BUNDLE_PATH, {"ts": time.time(), "sources": {"claude_usage": {
            "ts": time.time() - 300, "ok": True, "data": {"windows": [{"label": "5h", "used_pct": 10}]}}}})
        c = registry.Cache()
        self.assertEqual(c.data("claude_usage")["windows"][0]["used_pct"], 10)

    def test_newest_wins_among_equals(self):
        put("weather", {"temp": 1}, age=10)
        core.write_json_atomic(core.BUNDLE_PATH, {"sources": {"weather": {"ts": time.time(), "ok": True, "data": {"temp": 2}}}})
        self.assertEqual(registry.Cache().data("weather")["temp"], 2)


class Due(unittest.TestCase):
    def setUp(self):
        self.peer = WEB
        self.hub = HUB

    def test_peer_skips_global_while_hub_copy_is_fresh(self):
        src = registry.SOURCES["sites"]
        core.write_json_atomic(core.BUNDLE_PATH, {"sources": {"sites": {"ts": time.time() - 60, "ok": True, "data": {}}}})
        self.assertFalse(collect.is_due(src, self.peer, time.time(), registry.Cache()))
        try:  # the hub ignores the bundle: no local record means due
            os.remove(registry.src_path("sites"))
        except OSError:
            pass
        self.assertTrue(collect.is_due(src, self.hub, time.time(), registry.Cache()))

    def test_peer_falls_back_when_hub_goes_quiet(self):
        src = registry.SOURCES["sites"]
        core.write_json_atomic(core.BUNDLE_PATH, {"sources": {"sites": {"ts": time.time() - 99999, "ok": True, "data": {}}}})
        try:
            os.remove(registry.src_path("sites"))
        except OSError:
            pass
        self.assertTrue(collect.is_due(src, self.peer, time.time(), registry.Cache()))

    def test_skip_records_wait_six_hours(self):
        put("cursor_usage", None, ok=False, age=3600, skip=True)
        self.assertFalse(collect.is_due(registry.SOURCES["cursor_usage"], self.hub, time.time(), registry.Cache()))


class Guards(unittest.TestCase):
    def test_flap_guard_needs_two_strikes(self):
        now = [{"label": "api", "ok": False}, {"label": "brain", "ok": True}]
        self.assertEqual(_sys.flap_guard(now, [{"label": "api", "ok": True}]), [])
        self.assertEqual([r["label"] for r in _sys.flap_guard(now, [{"label": "api", "ok": False}])], ["api"])

    def test_redact_scrubs_secret_values(self):
        fake = "-".join(["fixture", "not", "a", "real", "credential"])  # built at runtime: no scanner bait
        env = {"STRIPE_SECRET_KEY": fake, "HOME": "/home/x"}
        out = collect._redact("boom: %s failed" % fake, env)
        self.assertNotIn(fake, out)
        self.assertIn("<redacted:STRIPE_SECRET_KEY>", out)

    def test_bundle_carries_only_global_sources(self):
        put("procs", {"total": 1})
        put("weather", {"temp": 70})
        b = fleet.build_bundle(HUB, {})
        self.assertIn("weather", b["sources"])
        self.assertNotIn("procs", b["sources"])


class ReviewRegressions(unittest.TestCase):
    """Locks in the 2026-10-16 review fixes."""

    def test_soft_failure_keeps_last_good_reading(self):
        from motdlib.registry import Source
        calls = {"n": 0}

        def fn(ctx):
            calls["n"] += 1
            return {"windows": [{"label": "5h", "used_pct": 7}]} if calls["n"] == 1 else \
                {"windows": [], "error": "token expired"}
        src = Source("soft_probe", fn, 600, 5, "local", None, (), None, None, "")
        host = HUB
        self.assertTrue(collect.run_one(src, host, {})["ok"])
        for _ in range(2):  # consecutive soft failures keep the reading
            rec = collect.run_one(src, host, {})
            self.assertFalse(rec["ok"])
            self.assertTrue(rec["kept"])
            self.assertEqual(rec["data"]["windows"][0]["used_pct"], 7)
        self.assertFalse(collect.is_due(src, host, time.time(), registry.Cache()))  # normal TTL, not retry

    def test_parallel_uses_one_shared_deadline(self):
        t0 = time.monotonic()
        out = core.parallel({str(i): (lambda: time.sleep(2)) for i in range(4)}, timeout=0.4)
        self.assertLess(time.monotonic() - t0, 1.2)
        self.assertEqual(out, {})

    def test_hung_mount_is_reported_not_waited_on(self):
        from motdlib import live
        real = live._disk
        live._disk = lambda m: (time.sleep(3) if m == "/hang" else real(m))
        try:
            t0 = time.monotonic()
            disks, stalled = live._disks(["/", "/hang"], budget=0.3)
        finally:
            live._disk = real
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertEqual(stalled, ["/hang"])
        self.assertTrue(disks)

    def test_snapshot_publishes_only_own_alerts(self):
        from motdlib import snapshot
        put("cursor_usage", {"windows": [], "alerts": [{"sev": "warn", "msg": "GLOBAL-ALERT"}]})
        core.write_json_atomic(core.BUNDLE_PATH, {"ts": time.time(), "sources": {}, "fleet": {"hosts": {
            "web": {"ok": True, "seen": time.time(), "snap": {"ts": time.time(), "label": "web",
                                                                  "alerts": [{"sev": "crit", "msg": "PEER-ALERT"}]}}}}})
        host = LAPTOP
        msgs = " ".join(a["msg"] for a in snapshot.build(host)["alerts"])
        self.assertNotIn("GLOBAL-ALERT", msgs)
        self.assertNotIn("PEER-ALERT", msgs)

    def test_failed_unit_with_short_label_alerts_once(self):
        host = WEB
        lv = {"vitals": {"disks": [], "mem": {"used": 1, "total": 10}, "swap": {"used": 0, "total": 0},
                         "load": [0.1, 0.1, 0.1], "cores": 8},
              "failed": ["myapp-web.service"], "units": [("web", "crit", "failed")], "launchd": []}
        msgs = [a["msg"] for a in alerts.gather(host, registry.Cache(), lv) if "web" in a["msg"]]
        self.assertEqual(msgs, ["myapp-web.service failed on web"])

    def test_infra_panel_survives_null_pr_counts(self):
        put("github", {"status": "ok", "summary": "x", "details": {"repos": [
            {"repo": "octocat/hello", "open_prs": None, "changes_requested": None, "ci_failing": []}]}})
        host = HUB
        out = T.strip(render.render(host, registry.Cache(), width=160, only=["infra"]))
        self.assertNotIn("panel error", out)
        self.assertIn("0 open PRs", out)


class ConfigGating(unittest.TestCase):
    """config.json decides which hosts exist and which sources run."""

    def setUp(self):
        write_config({})

    def test_unknown_host_gets_a_generic_profile(self):
        os.environ["MOTD_MACHINE"] = "no-such-box"
        try:
            h = hosts.current()
        finally:
            del os.environ["MOTD_MACHINE"]
        self.assertEqual((h.name, h.hub, h.peers), ("no-such-box", False, []))
        self.assertIn("system", h.panels)

    def test_profile_comes_from_config(self):
        write_config({"hosts": {"boxy": {"label": "b", "tags": ["#hub", "#server"], "peers": ["x"],
                                         "units": [["nginx", "nginx", "system"]], "repos": ["~/code/a"]}},
                      "fleet_order": ["boxy"], "short": {"boxy": "bx"}})
        os.environ["MOTD_MACHINE"] = "boxy"
        try:
            h = hosts.current()
        finally:
            del os.environ["MOTD_MACHINE"]
        self.assertTrue(h.hub and h.server)
        self.assertEqual(h.units, [("nginx", "nginx", "system")])
        self.assertEqual(h.repos, [os.path.expanduser("~/code/a")])
        self.assertEqual((hosts.fleet_order(), hosts.short("boxy"), hosts.short("other")), (["boxy"], "bx", "other"))

    def test_usage_probes_are_opt_in(self):
        src = registry.SOURCES["claude_usage"]
        self.assertFalse(registry.applies(src, HUB))
        write_config({"enable": ["claude_usage"]})
        self.assertTrue(registry.applies(src, HUB))

    def test_disable_switches_a_default_source_off(self):
        self.assertTrue(registry.applies(registry.SOURCES["procs"], HUB))
        write_config({"disable": ["procs"]})
        self.assertFalse(registry.applies(registry.SOURCES["procs"], HUB))

    def test_needs_any_skips_a_source_with_none_of_its_keys(self):
        src = registry.SOURCES["ai_spend"]
        self.assertEqual(registry.missing_env(src, {}), ["one of " + "/".join(src.needs_any)])
        self.assertEqual(registry.missing_env(src, {"OPENAI_ADMIN_KEY": "x"}), [])
        rec = collect.run_one(src, HUB, {})
        self.assertTrue(rec["skip"])
        self.assertIn("missing env", rec["error"])

    def test_hub_only_fleet_source(self):
        self.assertTrue(registry.applies(registry.SOURCES["fleet"], HUB))
        self.assertFalse(registry.applies(registry.SOURCES["fleet"], WEB))

    def test_env_file_is_parsed_not_executed(self):
        marker = os.path.join(TMP, "executed")
        Path(core.CONFIG_DIR).mkdir(parents=True, exist_ok=True)
        Path(core.CONFIG_DIR, "env").write_text(
            "# comment\nexport A_KEY=one\nB_TOKEN='two words'\nC=$HOME/x\n$(touch %s)\n`touch %s`\n" % (marker, marker))
        core._SECRETS = None
        try:
            env = core.secrets()
        finally:
            core._SECRETS = None
        self.assertEqual((env["A_KEY"], env["B_TOKEN"], env["C"]), ("one", "two words", core.HOME + "/x"))
        self.assertFalse(os.path.exists(marker))

    def test_launchd_prefix_rows(self):
        from motdlib import live
        real = core.run
        core.run = lambda argv, timeout=4.0, **k: (0, "PID\tStatus\tLabel\n12\t0\tcom.example.daemon\n"
                                                      "-\t0\tcom.example.job-a\n-\t78\tcom.example.job-b\n", "")
        host = hosts.Host("m", {"agents": [["com.example.*", None]]})
        real_mac, core.IS_MAC = core.IS_MAC, True
        try:
            rows = live.launchd(host)
        finally:
            core.run, core.IS_MAC = real, real_mac
        self.assertEqual(rows, [("daemon", "ok", ""), ("job-a", "ok", "idle"), ("job-b", "crit", "exit 78")])


class DevOpsParsers(unittest.TestCase):
    def setUp(self):
        from motdlib.sources import devops
        self.d = devops

    def test_docker_ps_groups_projects_and_flags_real_problems(self):
        ps = "\n".join([
            "shop-web-1\trunning\tUp 2 hours (unhealthy)\tshop\tweb",
            "shop-api-1\trunning\tUp 2 hours (healthy)\tshop\tapi",
            "shop-cache-1\trestarting\tRestarting (1) 5 seconds ago\tshop\tcache",
            "shop-migrate-1\texited\tExited (0) 2 hours ago\tshop\tmigrate",
            "shop-worker-1\texited\tExited (1) 12 minutes ago\tshop\tworker",
            "shop-old-1\texited\tExited (2) 3 days ago\tshop\told",
            "shop-42-db-1\texited\tExited (143) 1 day ago\tshop-42\tdb",
            "loose\trunning\tUp 1 hour\t\t",
        ])
        d = self.d.parse_ps(ps)
        shop, wt = d["projects"]
        self.assertEqual((shop["name"], shop["running"], shop["total"], shop["done"]), ("shop", 2, 6, 1))
        self.assertEqual((shop["unhealthy"], shop["restarting"]), (["web"], ["cache"]))
        self.assertEqual([(f["name"], f["code"], f["ago"]) for f in shop["failed"]], [("worker", 1, 720), ("old", 2, 259200)])
        self.assertEqual((wt["name"], wt["running"], wt["failed"]), ("shop-42", 0, []))  # SIGTERM is a stop
        self.assertEqual(d["other"], {"running": 1, "total": 1})
        msgs = [a["msg"] for a in self.d.stack_alerts(d["projects"])]
        self.assertEqual(msgs, ["shop stack: 1 unhealthy (web); 1 restarting (cache); worker exited 1"])  # old crash: history

    def test_docker_exit_durations(self):
        self.assertEqual(self.d._exit_info("Exited (1) Less than a second ago"), (1, 0))
        self.assertEqual(self.d._exit_info("Exited (137) About a minute ago"), (137, 60))
        self.assertEqual(self.d._exit_info("Exited (3)"), (3, None))

    def test_crash_looping_stack_is_not_stopped_and_stopped_is_quiet(self):
        d = self.d.parse_ps("kb-1\trestarting\tRestarting (1) 4 seconds ago\tkb\tkb")
        self.assertEqual([a["msg"] for a in self.d.stack_alerts(d["projects"])], ["kb stack: 1 restarting (kb)"])
        put("docker", dict(d, docker="up"))
        out = T.strip(render.render(DEVBOX, registry.Cache(), width=160, only=["docker"]))
        self.assertIn("kb  0/1 up", out)
        self.assertNotIn("stopped: kb", out)
        self.assertEqual(self.d.stack_alerts(self.d.parse_ps("x-1\texited\tExited (1) 1 minute ago\tx\tx")["projects"]), [])

    def test_transport_failures_get_short_names(self):
        import socket
        import ssl
        import urllib.error
        self.assertEqual(self.d._why(ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER]")), "tls error")
        self.assertEqual(self.d._why(urllib.error.URLError(socket.gaierror(8, "x"))), "no dns")
        self.assertEqual(self.d._why(urllib.error.URLError(ConnectionRefusedError())), "refused")
        self.assertEqual(self.d._why(urllib.error.URLError(OSError(65, "x"))), "no route")

    def test_aws_files_reads_names_and_expiry_never_keys(self):
        d = tempfile.mkdtemp(dir=TMP)
        os.makedirs(os.path.join(d, "sso", "cache"))
        Path(d, "credentials").write_text("[default]\naws_access_key_id = AKIDEXAMPLE\naws_secret_access_key = x\n[empty]\nregion = y\n")
        Path(d, "config").write_text("[profile sso]\nsso_session = acme\nsso_account_id = 123456789012\n[sso-session acme]\nsso_start_url = https://x\n")
        Path(d, "sso", "cache", "a.json").write_text(json.dumps(
            {"startUrl": "https://x", "accessToken": "t", "expiresAt": "2030-01-01T00:00:00Z", "refreshToken": "r"}))
        Path(d, "sso", "cache", "other-cli.json").write_text(json.dumps({"accessToken": "t", "expiresAt": "2031-01-01T00:00:00Z"}))
        f = self.d.aws_files(d)
        self.assertEqual((f["static"], f["sso"]["profiles"], f["sso"]["account"]), (["default"], ["sso"], "123456789012"))
        self.assertEqual(f["sso"]["expires"], core.utc_epoch("2030-01-01T00:00:00"))  # not the other CLI's 2031
        self.assertTrue(f["sso"]["refreshable"])
        self.assertNotIn("AKIDEXAMPLE", json.dumps(f))

    def test_sts_outcomes(self):
        ok = self.d.classify_sts(0, '{"Account": "1", "Arn": "arn:aws:iam::1:user/me"}', "")
        self.assertEqual((ok["state"], ok["principal"]), ("ok", "user/me"))
        role = self.d.classify_sts(0, '{"Account": "1", "Arn": "arn:aws:sts::1:assumed-role/Dev/s"}', "")
        self.assertEqual(role["principal"], "role/Dev")
        for err, state in (("An error occurred (ExpiredToken) when calling", "rejected"),
                           ("An error occurred (InvalidClientTokenId) when calling", "rejected"),
                           ("Unable to locate credentials. You can configure", "none"),
                           ('Could not connect to the endpoint URL: "https://sts"', "unreachable"),
                           ("An error occurred (Throttling) when calling", "error")):
            self.assertEqual(self.d.classify_sts(255, "", err)["state"], state, err)
        self.assertEqual(self.d.classify_sts(124, "", "timeout after 15s")["state"], "unreachable")

    def test_aws_region_comes_from_config_then_env(self):
        write_config({"aws": {"region": "eu-west-2"}, "ec2": {"region": "us-gov-east-1"}})
        self.assertEqual((self.d._region(), self.d._region("ec2")), ("eu-west-2", "us-gov-east-1"))
        write_config({})
        os.environ.pop("AWS_REGION", None)
        os.environ.pop("AWS_DEFAULT_REGION", None)
        self.assertEqual(self.d._region(), "us-east-1")
        self.assertNotIn("AWS_BEARER_TOKEN_BEDROCK", self.d._aws_env("us-east-1"))

    def test_instances_and_tag_filters(self):
        rows = self.d.parse_instances("web-2\tc7g.xlarge\tNone\ti-2\t2026-10-01T00:00:00+00:00\tstopped\n"
                                      "web-1\tc5.xlarge\t10.0.0.9\ti-1\t2026-10-15T12:00:00+00:00\trunning\n"
                                      "garbage line\n")
        self.assertEqual([(r["name"], r["ip"], r["state"]) for r in rows], [("web-1", "10.0.0.9", "running"), ("web-2", "", "stopped")])
        self.assertEqual(self.d._ec2_filters({"filters": {"Owner": ["a", "b"], "Env": "prod"}}),
                         ["Name=tag:Owner,Values=a,b", "Name=tag:Env,Values=prod"])
        self.assertEqual(self.d._ec2_filters({"filters": {"Owner": ["a b; rm"], "bad key": ["x"], "Empty": []}}), [])

    def test_github_rows_and_alerts(self):
        rows = [self.d._gh_row({"number": 7, "title": "t", "mergeable": "CONFLICTING", "reviewDecision": "",
                                "updatedAt": "2026-10-16T10:00:00Z", "latestReviews": [{"state": "APPROVED"}, {"state": "COMMENTED"}]}),
                self.d._gh_row({"number": 8, "title": "u", "mergeable": "MERGEABLE", "reviewDecision": "CHANGES_REQUESTED",
                                "updatedAt": "2026-10-16T11:00:00Z", "latestReviews": []})]
        self.assertEqual([(r["n"], r["merge"], r["approvals"], r["changes"]) for r in rows], [(7, "conflicts", 1, 0), (8, "mergeable", 0, 1)])
        s = self.d.summarize(rows, rows + [{"n": 9, "title": "x", "merge": "unknown", "approvals": 0, "changes": 0, "updated": 1, "branch": ""}])
        self.assertEqual(([m["n"] for m in s["mine"]], [m["n"] for m in s["assigned"]]), ([8, 7], [9]))  # your own never "assigned"
        self.assertEqual([a["msg"] for a in self.d.mr_alerts(s["mine"], "PR", "#")],
                         ["1 of your PRs has merge conflicts (#7)", "changes requested on #8"])

    def test_gitlab_rows(self):
        a = self.d._gl_row({"iid": 3, "title": "t", "detailed_merge_status": "conflict", "updated_at": "2026-10-16T10:00:00Z", "source_branch": "f"})
        b = self.d._gl_row({"iid": 4, "title": "u", "detailed_merge_status": "requested_changes", "has_conflicts": False})
        c = self.d._gl_row({"iid": 5, "title": "v", "detailed_merge_status": "mergeable"})
        self.assertEqual((a["merge"], b["changes"], c["merge"]), ("conflicts", 1, "mergeable"))

    def test_mrs_source_end_to_end_with_a_fake_cli(self):
        write_config({"mrs": {"provider": "github", "repo": "octocat/hello"}})
        calls = []

        def fake_run(argv, timeout=4.0, **k):
            calls.append(argv)
            if "--search" in argv and "review-requested:@me" in argv:
                return 0, json.dumps([{"number": 11, "title": "r", "mergeable": "UNKNOWN", "updatedAt": "2026-10-16T09:00:00Z"}]), ""
            if "--search" in argv:
                return 0, "[]", ""
            if "--author" in argv:
                return 0, json.dumps([{"number": 10, "title": "mine", "mergeable": "CONFLICTING", "updatedAt": "2026-10-16T10:00:00Z"}]), ""
            return 0, json.dumps([{"number": 10}, {"number": 11}, {"number": 12}]), ""
        real_run, real_which = core.run, core.which
        core.run, core.which = fake_run, lambda name, extra=(): "/usr/bin/" + name
        try:
            data = self.d.mrs(None)
            write_config({"mrs": {"provider": "github", "repo": "bad repo; x"}})
            bad = self.d.mrs(None)
            write_config({"mrs": {"provider": "github", "repo": "octocat/hello"}})
            core.run = lambda argv, timeout=4.0, **k: (1, "", "HTTP 401: Bad credentials")
            err = self.d.mrs(None)
        finally:
            core.run, core.which = real_run, real_which
        self.assertEqual(([m["n"] for m in data["mine"]], [m["n"] for m in data["assigned"]], data["open"], data["prefix"]),
                         ([10], [11], 3, "#"))
        self.assertEqual(data["alerts"][0]["msg"], "1 of your PRs has merge conflicts (#10)")
        self.assertTrue(all("--repo" in c and "octocat/hello" in c for c in calls))
        self.assertIs(bad["installed"], False)
        self.assertEqual((err["status"], err["error"]), ("unknown", "HTTP 401: Bad credentials"))

    def test_reach_refuses_option_like_ssh_aliases_and_bad_endpoints(self):
        host = hosts.Host("h", {"reach": {"ssh": ["-oProxyCommand=touch /x", "good-box"],
                                          "endpoints": [["ok", "https://example.test/"], ["bad", "file:///etc/passwd"]],
                                          "socks": "127.0.0.1:1080"}})
        probed = []
        real = (self.d._vpc_probe, self.d._endpoint)
        self.d._vpc_probe = lambda a: probed.append(a) or {"alias": a, "ok": True, "ms": 1}
        self.d._endpoint = lambda item, proxy: {"label": item[0], "status": 200, "ms": 1, "ok": True, "dns": True, "via": "direct", "error": None}
        try:
            data = self.d.reach(registry.Ctx(host, {}, None))
        finally:
            self.d._vpc_probe, self.d._endpoint = real
        self.assertEqual(probed, ["good-box"])
        self.assertEqual([e["label"] for e in data["endpoints"]], ["ok"])
        self.assertEqual(data["socks"], "127.0.0.1:1080")

    def test_reach_two_strikes_for_5xx(self):
        host = hosts.Host("h", {"reach": {"endpoints": [["api", "https://example.test/"]]}})
        real = self.d._endpoint
        self.d._endpoint = lambda item, proxy: {"label": "api", "status": 503, "ms": 1, "ok": False, "dns": True, "via": "direct", "error": None}
        try:
            first = self.d.reach(registry.Ctx(host, {}, None))
            second = self.d.reach(registry.Ctx(host, {}, first))
        finally:
            self.d._endpoint = real
        self.assertNotIn("alerts", first)
        self.assertEqual(second["alerts"][0]["msg"], "api answers HTTP 503")

    def test_sources_follow_the_panels_a_host_lists(self):
        for name, panel in (("docker", "docker"), ("mrs", "mrs"), ("ec2_fleet", "ec2"), ("aws_auth", "access"), ("reach", "access")):
            self.assertTrue(registry.applies(registry.SOURCES[name], DEVBOX), name)
            self.assertFalse(registry.applies(registry.SOURCES[name], WEB), name)

    def test_devops_panels_render_within_width(self):
        write_config({})
        now = time.time()
        put("docker", {"docker": "up", "projects": [
            {"name": "shop", "running": 4, "total": 6, "done": 1, "starting": 1, "unhealthy": ["web"], "restarting": [],
             "failed": [{"name": "worker", "code": 1, "ago": 600}]}], "other": {"running": 0, "total": 0}})
        put("mrs", {"up": True, "repo": "octocat/hello", "open": 12, "truncated": False, "me": True, "noun": "PR", "prefix": "#",
                    "mine": [{"n": 10, "title": "feat: a deliberately long pull request title that must be cut", "merge": "conflicts",
                              "approvals": 0, "changes": 0, "updated": now - 7200},
                             {"n": 11, "title": "fix: x", "merge": "mergeable", "approvals": 2, "changes": 1, "updated": now - 90000}],
                    "assigned": [{"n": 12}]})
        put("ec2_fleet", {"src": "aws", "asof": now, "running": 1, "total": 2, "rows": [
            {"name": "web-1", "type": "c7g.4xlarge", "ip": "10.0.0.9", "id": "i-1", "launched": now - 9e5, "state": "running"},
            {"name": "web-2", "type": "c7g.4xlarge", "ip": "", "id": "i-2", "launched": 0, "state": "stopped"}]})
        put("aws_auth", {"cli": True, "region": "us-east-1", "static": [], "sso": {"profiles": ["sso"], "account": "123", "expires": now + 3000, "refreshable": False},
                         "sts": {"state": "rejected", "error": "ExpiredToken", "hint": "aws sso login", "at": now - 60}})
        put("reach", {"socks": None, "hint": "connect the VPN", "vpc": [{"alias": "box", "ok": False, "error": "timeout"}],
                      "endpoints": [{"label": "git", "status": 302, "ok": True, "via": "direct"},
                                    {"label": "app", "status": 0, "ok": False, "dns": False, "error": "no dns"},
                                    {"label": "api", "status": 502, "ok": False, "dns": True}]})
        for w in (60, 120, 200):
            out = render.render(DEVBOX, registry.Cache(), width=w)
            plain = T.strip(out)
            for line in out.splitlines():
                self.assertLessEqual(T.width(line), w + 1, "%d: %r" % (w, T.strip(line)))
            self.assertNotIn("panel error", plain, w)
            self.assertNotIn("[38;", plain, w)
        full = T.strip(render.render(DEVBOX, registry.Cache(), width=200))
        for needle in ("shop", "#10", "EC2", "rejected: ExpiredToken", "aws sso login", "no route to the private network", "connect the VPN"):
            self.assertIn(needle, full)
        self.assertIn("PULL REQUESTS", full)


class ReviewFindings(unittest.TestCase):
    """Locks in the pre-release review fixes."""

    def setUp(self):
        write_config({})

    def test_hostile_or_malformed_config_cannot_crash_or_reach_ssh(self):
        h = hosts.Host("x", {"peers": ["-oProxyCommand=touch /x", "good", 5], "accent": ["skyy", "violet"],
                             "units": [["nginx"], ["a", "b", "system"], ["a", "b", "weird"]],
                             "ports": [["x", "bad"], [80, "web"]], "agents": [["only-one"]]})
        self.assertEqual((h.peers, h.accent, h.units, h.ports, h.agents),
                         (["good"], hosts.DEFAULT_ACCENT, [("a", "b", "system")], [(80, "web")], []))
        render.render(h, registry.Cache(), width=100)  # no KeyError from a typo'd accent
        from motdlib.sources import usage_probe
        res = usage_probe.run_remote("-oProxyCommand=x", ["claude"])
        self.assertIn("invalid peer name", res[0]["error"])
        self.assertIn('"--", peer, REMOTE', Path(fleet.__file__).read_text())

    def test_disabled_source_disappears_from_cached_panels(self):
        put("stripe", {"status": "ok", "summary": "x", "details": {"available": {"usd": 1}, "subscriptions": {}}})
        self.assertIsNotNone(registry.Cache().rec("stripe"))
        write_config({"disable": ["stripe"]})
        self.assertIsNone(registry.Cache().rec("stripe"))

    def test_resend_runs_with_only_the_full_access_key(self):
        src = registry.SOURCES["resend"]
        self.assertEqual(registry.missing_env(src, {"RESEND_FULL_API_KEY": "k"}), [])
        self.assertTrue(registry.missing_env(src, {}))

    def test_no_default_ignore_list_for_uptime_monitors(self):
        captured = {}
        from motdlib.sources import cloud
        real = cloud._sp().fetch_uptimerobot
        cloud._sp().fetch_uptimerobot = lambda env: captured.update(env) or {"status": "ok", "summary": "", "details": {}, "error": None}
        try:
            cloud.uptimerobot(registry.Ctx(HUB, {"UPTIMEROBOT_API_KEY": "k"}, None))
        finally:
            cloud._sp().fetch_uptimerobot = real
        self.assertFalse(captured.get("PROBE_UPTIMEROBOT_IGNORE"))

    def test_aws_cli_uses_the_merged_env(self):
        from motdlib.sources import saas_probe as sp
        seen = {}
        real_run, real_bin = sp._run, sp._aws_bin
        sp._aws_bin = lambda: "/usr/bin/aws"
        sp._run = lambda cmd, env=None, **k: seen.update(env or {}) or type("P", (), {"returncode": 0, "stdout": "{}", "stderr": ""})()
        try:
            sp._aws_cli(["sts", "get-caller-identity"], "p", "us-east-1", {"AWS_CONFIG_FILE": "/from/motd/env", "AWS_REGION": ""})
        finally:
            sp._run, sp._aws_bin = real_run, real_bin
        self.assertEqual(seen["AWS_CONFIG_FILE"], "/from/motd/env")
        self.assertNotIn("AWS_REGION", seen)

    def test_configured_ports_alert_on_servers_and_show_on_services(self):
        lv = {"vitals": {"disks": [], "mem": {"used": 1, "total": 10}, "swap": {"used": 0, "total": 0}, "load": [0.1] * 3, "cores": 8},
              "failed": [], "units": [], "launchd": [], "ports": [(3000, "web", False), (22, "ssh", True)]}
        srv = hosts.Host("s", {"label": "s", "tags": ["#server"], "ports": [[3000, "web"]]})
        dev = hosts.Host("d", {"label": "d", "tags": ["#dev"], "ports": [[3000, "web"]]})
        self.assertIn("web not listening on :3000 on s", [a["msg"] for a in alerts.gather(srv, registry.Cache(), lv)])
        self.assertEqual([a for a in alerts.gather(dev, registry.Cache(), lv) if "listening" in a["msg"]], [])
        from motdlib import panels
        ctx = render.RCtx(srv, registry.Cache(), lv, [], 80)
        self.assertIn("web :3000", T.strip("\n".join(panels.p_services(ctx).lines)))

    def test_mac_keeps_configured_mounts_and_header_follows_config_tz(self):
        from motdlib import live
        real = live._disks
        got = {}
        live._disks = lambda mounts, budget=0.8: got.update(m=mounts) or ([], [])
        real_mac = core.IS_MAC
        try:
            core.IS_MAC = True
            try:
                live.vitals(hosts.Host("m", {"mounts": ["/", "/Volumes/Ext"]}))
            except Exception:  # noqa: BLE001 — sysctl/vm_stat are absent off macOS; only the mount list matters
                pass
        finally:
            core.IS_MAC, live._disks = real_mac, real
        if got:
            self.assertEqual(got["m"], ["/System/Volumes/Data", "/Volumes/Ext"])
        srv = hosts.Host("s", {"tags": ["#server"]})
        self.assertNotIn("EDT", T.strip(render._clock(srv)))
        write_config({"tz": "Asia/Tokyo"})
        self.assertIn("JST", T.strip(render._clock(srv)))

    def test_weather_unit_is_carried_and_rendered(self):
        write_config({"weather": {"place": "Berlin", "lat": 52.5, "lon": 13.4, "tz": "Europe/Berlin", "unit": "metric"}})
        from motdlib.sources import local
        seen = {}

        class R:
            ok, body = True, {"current": {"weather_code": 0, "temperature_2m": 20.4, "apparent_temperature": 19, "wind_speed_10m": 3},
                              "daily": {"temperature_2m_max": [22], "temperature_2m_min": [11], "precipitation_probability_max": [0]}}
        ctx = registry.Ctx(HUB, {}, None)
        ctx.http = staticmethod(lambda url, **k: seen.update(url=url) or R)
        data = local.weather(ctx)
        self.assertEqual(data["unit"], "C")
        self.assertIn("temperature_unit=celsius", seen["url"])
        put("weather", data)
        w_host = hosts.Host("w", {"weather": True})
        self.assertIn("20°C", T.strip(render.render(w_host, registry.Cache(), width=120)))

    def test_peer_alias_that_differs_from_machine_name_is_flagged(self):
        real = fleet._exchange
        fleet._exchange = lambda peer, payload: {"ok": True, "snap": {"host": "web-01", "ts": time.time()}, "ms": 1}
        try:
            data = fleet.fleet(registry.Ctx(HUB, {}, None))
        finally:
            fleet._exchange = real
        self.assertIn("reports itself as web-01", data["alerts"][0]["msg"])


class ChecksFramework(unittest.TestCase):
    """The config-driven checks source (sources/checks.py)."""

    def setUp(self):
        write_config({})
        from motdlib.sources import checks
        self.ck = checks

    def test_templates_paths_and_humanizing(self):
        ck = self.ck
        self.assertEqual(ck._path({"a": {"b": [1, {"c": 7}]}}, "a.b.1.c"), 7)
        self.assertIsNone(ck._path({"a": 1}, "a.b"))
        m = ck._human({"newest_age": 7200, "bytes": 2048, "count": 3})
        self.assertEqual((m["newest_age_h"], m["bytes_h"]), ("2h", "2.0K"))
        self.assertEqual(ck.fmt("{count} files · {nope}", m), "3 files · ?")
        self.assertEqual(ck.fmt("{broken", m), "{broken")

    def test_rules_ops_and_missing_metrics(self):
        ck = self.ck
        c = {"name": "x", "rules": [{"metric": "n", "op": "gt", "value": 5, "sev": "crit", "msg": "n is {n}"},
                                    {"metric": "n", "op": "gt", "value": 1, "sev": "warn", "msg": "n high"},
                                    {"metric": "gone", "op": "lt", "value": 1, "sev": "crit"},
                                    {"metric": "gone", "op": "missing", "sev": "warn", "msg": "gone is absent"}]}
        state, hits = ck.evaluate(c, {"n": 9})
        self.assertEqual((state, hits), ("crit", [("crit", "n is 9"), ("warn", "n high"), ("warn", "gone is absent")]))
        self.assertEqual(ck.evaluate({"rules": []}, {"n": 1})[0], "ok")

    def test_files_check_counts_ages_and_lines(self):
        d = tempfile.mkdtemp(dir=TMP)
        for i, (name, body, age) in enumerate((("a.log", "1\n2\n3\n", 0), ("b.log", "x\n", 7200))):
            p = os.path.join(d, name)
            Path(p).write_text(body)
            os.utime(p, (time.time() - age, time.time() - age))
        c = {"type": "files", "glob": d + "/*.log", "rules": [{"metric": "max_lines", "op": "ge", "value": 3}]}
        m = self.ck.run_files(c, {})
        self.assertEqual((m["count"], m["max_lines"], m["recent_24h"]), (2, 3, 2))
        self.assertTrue(7000 < m["oldest_age"] < 7300 and m["newest_age"] < 60)
        self.assertEqual(self.ck.run_files({"glob": d + "/none*"}, {})["newest_age"], None)

    def test_jsonl_folds_to_the_latest_status_per_id(self):
        d = tempfile.mkdtemp(dir=TMP)
        today = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        Path(d, "a.jsonl").write_text("\n".join(json.dumps(e) for e in (
            {"id": "1", "status": "open", "ts": "2026-01-01T00:00"}, {"id": "2", "status": "open", "ts": "2026-01-02T00:00"},
            {"id": "1", "status": "done", "ts": today}, {"id": "3"}, "not json")) + "\nnot json\n")
        m = self.ck.run_jsonl({"glob": d + "/*.jsonl"}, {})
        self.assertEqual((m["total"], m["open"], m["done"], m["events_24h"]), (2, 1, 1, 1))

    def test_command_never_uses_a_shell_and_parses_kv_and_json(self):
        ck = self.ck
        m = ck.run_command({"argv": ["printf", "Result=success\nExecMainExitTimestamp=@%d\n" % (time.time() - 3600)], "parse": "kv"}, {})
        self.assertEqual((m["exit"], m["Result"]), (0, "success"))
        self.assertTrue(3500 < m["ExecMainExitTimestamp_age"] < 3700)
        j = ck.run_command({"argv": ["printf", '{"a": {"b": 4}}'], "parse": "json", "json": {"b": "a.b"}}, {})
        self.assertEqual(j["b"], 4)
        marker = os.path.join(TMP, "shelled")
        ck.run_command({"argv": ["echo", "$(touch %s)" % marker]}, {})
        self.assertFalse(os.path.exists(marker))
        with self.assertRaises(ValueError):
            ck.run_command({"argv": "echo hi"}, {})
        with self.assertRaises(ValueError):
            ck.run_command({"argv": ["definitely-not-a-command-xyz"]}, {})

    def test_http_tcp_and_dns_against_loopback(self):
        import http.server
        import socketserver
        import threading

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                code = 503 if self.path == "/down" else 200
                body = json.dumps({"stats": {"entries": 12}, "ok": True}).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]
        try:
            ok = self.ck.run_http({"url": "http://127.0.0.1:%d/h" % port, "json": {"entries": "stats.entries"}}, {})
            down = self.ck.run_http({"url": "http://127.0.0.1:%d/down" % port}, {})
            self.assertEqual((ok["status"], ok["up"], ok["entries"]), (200, True, 12))
            self.assertEqual((down["status"], down["up"]), (503, False))
            self.assertTrue(self.ck.run_tcp({"host": "127.0.0.1", "port": port}, {})["open"])
            # A refused connection is "down", not a broken check. Simulated: under WSL mirrored
            # networking a closed loopback port times out instead of refusing.
            import socket
            real_cc = socket.create_connection
            socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError(111, "refused"))
            try:
                self.assertFalse(self.ck.run_http({"url": "http://127.0.0.1:1/"}, {})["up"])
                self.assertFalse(self.ck.run_tcp({"host": "127.0.0.1", "port": 1}, {})["open"])
            finally:
                socket.create_connection = real_cc
            with self.assertRaises(ValueError):
                self.ck.run_http({"url": "file:///etc/passwd"}, {})
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertTrue(self.ck.run_dns({"host": "localhost", "expect": ["127.0.0.1", "::1"]}, {})["match"])
        import socket
        real = socket.getaddrinfo
        socket.getaddrinfo = lambda *a, **k: (_ for _ in ()).throw(socket.gaierror(8, "no such host"))
        try:
            self.assertFalse(self.ck.run_dns({"host": "gone.example"}, {})["resolved"])
        finally:
            socket.getaddrinfo = real

    def test_env_vars_expand_in_headers_without_being_stored(self):
        self.assertEqual(self.ck._expand("Bearer ${TOK}", {"TOK": "s3cret"}), "Bearer s3cret")
        self.assertEqual(self.ck._expand("${NOPE}x", {}), "x")

    def test_tls_default_rules_and_strikes(self):
        ck = self.ck
        c = {"name": "site", "type": "tls", "host": "x"}
        self.assertEqual(ck.evaluate(c, {"days_left": 3, "verify_error": None})[0], "crit")
        state, hits = ck.evaluate(c, {"days_left": 10, "verify_error": None})
        self.assertEqual((state, hits[0][1]), ("warn", "site certificate expires in 10 days"))
        self.assertEqual(ck.evaluate(c, {"days_left": 60, "verify_error": None})[0], "ok")
        self.assertEqual(ck.evaluate(c, {"days_left": None, "verify_error": "certificate has expired"})[0], "crit")
        real = ck.RUNNERS["tcp"]
        ck.RUNNERS["tcp"] = lambda c, env: {"open": False, "ms": 0}
        try:
            first = ck.run_check({"name": "p", "type": "tcp", "port": 1}, {}, None)
            second = ck.run_check({"name": "p", "type": "tcp", "port": 1}, {}, first)
        finally:
            ck.RUNNERS["tcp"] = real
        self.assertEqual((first["alerts"], first["state"]), ([], "crit"))  # one miss is not an outage
        self.assertEqual(second["alerts"][0]["msg"], "p is not accepting connections")
        self.assertEqual(first["text"], "closed · 0ms")

    def test_a_broken_check_is_unknown_not_fatal_and_ttl_caches(self):
        write_config({"checks": [{"name": "bad", "type": "nope"}, {"name": "ok", "type": "command", "argv": ["true"], "ttl": 3600}]})
        host = hosts.Host("h", {"panels": ["checks"]})
        first = self.ck.checks(registry.Ctx(host, {}, None))
        self.assertEqual([r["state"] for r in first["results"]], ["unknown", "ok"])
        self.assertNotIn("alerts", first)
        again = self.ck.checks(registry.Ctx(host, {}, first))
        self.assertEqual(again["results"][1]["ts"], first["results"][1]["ts"])  # within ttl: not re-run

    def test_hosts_filter_gating_and_group_panels(self):
        write_config({"checks": [{"name": "a", "group": "g1", "type": "command", "argv": ["true"]},
                                 {"name": "b", "group": "g2", "type": "command", "argv": ["true"], "hosts": ["#server"]},
                                 {"name": "c", "group": "g1", "type": "command", "argv": ["true"], "hosts": ["elsewhere"]}]})
        dev = hosts.Host("d", {"tags": ["#dev"], "panels": ["system", "checks:g1", "checks"]})
        srv = hosts.Host("s", {"tags": ["#server"], "panels": ["system"]})
        self.assertTrue(registry.applies(registry.SOURCES["checks"], dev))
        self.assertFalse(registry.applies(registry.SOURCES["checks"], srv))  # no checks panel listed
        data = self.ck.checks(registry.Ctx(dev, {}, None))
        self.assertEqual([r["name"] for r in data["results"]], ["a"])
        put("checks", data)
        out = T.strip(render.render(dev, registry.Cache(), width=120))
        self.assertIn("G1", out)
        self.assertIn("CHECKS", out)
        self.assertEqual(T.strip(render.render(dev, registry.Cache(), width=120, only=["checks:g2"])).strip(), "")


class Notify(unittest.TestCase):
    def setUp(self):
        write_config({})
        reset_notify_state()
        from motdlib import notify
        self.n = notify

    def test_plan_new_repeat_resolved_and_severity_floor(self):
        n = self.n
        cur = [{"sev": "crit", "msg": "disk / 93% full on web"}, {"sev": "warn", "msg": "swap 81% on web"}]
        ev, st = n.plan(cur, {}, 1000, "crit", 3600)
        self.assertEqual([(e["kind"], e["msg"]) for e in ev], [("new", "disk / 93% full on web")])
        ev, st = n.plan([{"sev": "crit", "msg": "disk / 94% full on web"}], st, 2000, "crit", 3600)
        self.assertEqual(ev, [])  # digits folded: same alert, nothing new
        ev, st = n.plan([{"sev": "crit", "msg": "disk / 94% full on web"}], st, 5000, "crit", 3600)
        self.assertEqual([e["kind"] for e in ev], ["repeat"])
        ev, st = n.plan([], st, 5100, "crit", 3600)
        self.assertEqual([e["kind"] for e in ev], ["resolved"])
        self.assertEqual(st, {})
        ev, _ = n.plan(cur, {}, 1, "warn")
        self.assertEqual(len(ev), 2)

    def test_targets_get_the_right_payloads_and_bad_ones_report(self):
        import http.server
        import socketserver
        import threading
        got = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                got.append((self.path, dict(self.headers), body))
                self.send_response(500 if self.path == "/fail" else 200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        ev = [{"kind": "new", "sev": "crit", "msg": "api is down"}]
        env = {"TOPIC": "alerts"}
        try:
            self.assertEqual(self.n.send({"type": "ntfy", "url": base + "/${TOPIC}"}, env, "web", ev), "")
            self.assertEqual(self.n.send({"type": "slack", "url": base + "/slack"}, env, "web", ev), "")
            self.assertEqual(self.n.send({"type": "discord", "url": base + "/discord"}, env, "web", ev), "")
            self.assertEqual(self.n.send({"type": "webhook", "url": base + "/hook"}, env, "web", ev), "")
            self.assertEqual(self.n.send({"type": "webhook", "url": base + "/fail"}, env, "web", ev), "webhook: HTTP 500")
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIn("url is not http(s)", self.n.send({"type": "slack", "url": "${UNSET}"}, {}, "web", ev))
        self.assertIn("unknown target type", self.n.send({"type": "pager", "url": base}, {}, "web", ev))
        ntfy, slack, discord, hook = got[:4]
        self.assertEqual((ntfy[0], ntfy[1]["Priority"], ntfy[1]["Title"]), ("/alerts", "5", "web: 1 alert"))
        self.assertIn("api is down", ntfy[2].decode())
        self.assertIn("api is down", json.loads(slack[2])["text"])
        self.assertIn("api is down", json.loads(discord[2])["content"])
        self.assertEqual(json.loads(hook[2])["events"][0]["msg"], "api is down")

    def test_run_keeps_unsent_alerts_for_the_next_run(self):
        write_config({"notify": {"targets": [{"type": "webhook", "url": "https://hook.test/x"}]}})
        calls = []
        real_send, real_cur = self.n.send, self.n.current_alerts
        self.n.current_alerts = lambda host, cache: [{"sev": "crit", "msg": "db down", "src": "live"}]
        try:
            self.n.send = lambda t, env, label, ev: calls.append(ev) or "webhook: HTTP 502"
            self.n.run(WEB, registry.Cache(), {})
            self.n.send = lambda t, env, label, ev: calls.append(ev) or ""
            self.n.run(WEB, registry.Cache(), {})
            self.n.run(WEB, registry.Cache(), {})
        finally:
            self.n.send, self.n.current_alerts = real_send, real_cur
        self.assertEqual([[e["kind"] for e in c] for c in calls], [["new"], ["new"]])  # retried once, then quiet

    def test_peers_send_only_their_own_alerts(self):
        found = [{"sev": "crit", "msg": "local", "src": "live"}, {"sev": "crit", "msg": "web: peer", "src": "peer"}]
        real = alerts.gather
        alerts.gather = lambda host, cache, lv: list(found)
        real_probe = alerts.probe_all
        alerts.probe_all = lambda host, *a, **k: {}
        try:
            self.assertEqual([a["msg"] for a in self.n.current_alerts(WEB, registry.Cache())], ["local"])
            self.assertEqual(len(self.n.current_alerts(HUB, registry.Cache())), 2)
        finally:
            alerts.gather, alerts.probe_all = real, real_probe


class TrendsAndInit(unittest.TestCase):
    def setUp(self):
        write_config({})

    def test_history_ring_and_sparkline(self):
        from motdlib import snapshot
        path = os.path.join(TMP, "hist-%d.json" % time.time_ns())
        t = 1_000_000.0
        for i in range(60):
            snapshot.record_history({"ts": t + i * 300, "load": i % 6, "cores": 6, "mem": 40 + i % 10,
                                     "disks": [{"m": "/", "p": 50}, {"m": "/data", "p": 70}]}, path)
        snapshot.record_history({"ts": t + 59 * 300 + 30, "load": 6, "cores": 6, "mem": 99, "disks": []}, path)  # too soon
        h = core.read_json(path)
        self.assertEqual(len(h["ts"]), snapshot.HISTORY_LEN)
        self.assertEqual((h["disk"][-1], h["mem"][-1]), (70, 49))
        sp = T.spark([0, 50, 100, 120, None], w=3)
        self.assertEqual(T.strip(sp), "▅██")
        self.assertEqual(T.width(T.spark(range(0, 100, 5), w=8)), 8)

    def test_trend_row_renders_within_width(self):
        from motdlib import snapshot
        core.ensure_dirs()
        path = snapshot.history_path()
        try:
            os.remove(path)
        except OSError:
            pass
        for i in range(10):
            snapshot.record_history({"ts": time.time() - (10 - i) * 300, "load": i, "cores": 8, "mem": 50 + i,
                                     "disks": [{"m": "/", "p": 60}]})
        for w in (60, 120, 200):
            out = render.render(LAPTOP, registry.Cache(), width=w, only=["system"])
            self.assertIn("trend", T.strip(out))
            for line in out.splitlines():
                self.assertLessEqual(T.width(line), w + 1)
        os.remove(path)

    def test_init_dump_is_valid_compact_json(self):
        from motdlib import init
        obj = {"hosts": {"a": {"units": [["nginx", "nginx", "system"]], "tags": ["#linux"]}}, "x": {}}
        text = init.dump(obj)
        self.assertEqual(json.loads(text), obj)
        self.assertIn('["nginx", "nginx", "system"]', text)

    def test_init_profile_from_detected_state(self):
        from motdlib import init
        real = (core.run, core.which, init.is_server, init.repos, core.IS_MAC)

        def fake_run(argv, timeout=4.0, **k):
            if argv[:2] == ["systemctl", "list-units"]:
                return 0, "nginx.service loaded active running nginx\npostgresql@16-main.service loaded active running pg\n" \
                          "cron.service loaded active running cron\n", ""
            if argv[:3] == ["systemctl", "--user", "list-units"]:
                return 0, "myapp.service loaded active running x\ndbus.service loaded active running y\n", ""
            if argv[:2] == ["git", "-C"]:
                return 0, "git@github.com:octocat/hello.git\n", ""
            return 1, "", ""
        core.run = fake_run
        core.which = lambda name, extra=(): "/usr/bin/" + name if name in ("docker", "gh") else None
        init.is_server = lambda: False
        init.repos = lambda limit=3: ["~/code/hello"]
        core.IS_MAC = False
        try:
            prof, extra, notes = init.profile("box")
        finally:
            core.run, core.which, init.is_server, init.repos, core.IS_MAC = real
        self.assertEqual([u[0] for u in prof["units"]], ["nginx", "postgresql@16-main", "myapp"])  # cron and dbus are noise
        self.assertIn("docker", prof["panels"])
        self.assertEqual(extra["mrs"], {"provider": "github", "repo": "octocat/hello"})
        self.assertIn("mrs", prof["panels"])

    def test_init_write_keeps_a_backup_and_refuses_to_clobber(self):
        from motdlib import init
        write_config({"hosts": {"other": {"label": "o"}}, "sites": [["a", "https://a.test"]]})
        real = init.profile
        init.profile = lambda name: ({"label": name, "panels": ["system"]}, {}, [])
        os.environ["MOTD_MACHINE"] = "newbox"
        try:
            self.assertEqual(init.run(["--write"]), 0)
            cfg = core.config()
            self.assertEqual(sorted(cfg["hosts"]), ["newbox", "other"])
            self.assertEqual(cfg["sites"], [["a", "https://a.test"]])
            self.assertTrue(os.path.exists(os.path.join(core.CONFIG_DIR, "config.json.bak")))
            self.assertEqual(init.run(["--write"]), 1)
            self.assertEqual(init.run(["--write", "--force"]), 0)
        finally:
            init.profile = real
            del os.environ["MOTD_MACHINE"]


class MoreForgesAndClouds(unittest.TestCase):
    def setUp(self):
        write_config({})
        from motdlib.sources import devops
        self.d = devops

    def _fake_http(self, routes):
        calls = []

        def fake(url, method="GET", headers=None, **k):
            calls.append((url, headers or {}))
            for prefix, (status, body) in routes.items():
                if url.startswith(prefix):
                    return core.Resp(status, body, 5)
            return core.Resp(404, {"message": "nope"}, 5)
        return fake, calls

    def test_gitea_rows_reviews_and_assignment(self):
        write_config({"mrs": {"provider": "forgejo", "url": "https://git.test", "repo": "me/app"}})
        api = "https://git.test/api/v1"
        fake, calls = self._fake_http({
            api + "/user": (200, {"login": "me"}),
            api + "/repos/me/app/pulls/3/reviews": (200, [{"user": {"login": "ann"}, "state": "REQUEST_CHANGES"},
                                                          {"user": {"login": "ann"}, "state": "APPROVED"},
                                                          {"user": {"login": "bob"}, "state": "APPROVED"}]),
            api + "/repos/me/app/pulls?": (200, [
                {"number": 3, "title": "mine", "mergeable": False, "updated_at": "2026-10-16T10:00:00Z", "user": {"login": "me"}, "head": {"ref": "f"}},
                {"number": 4, "title": "theirs", "mergeable": True, "user": {"login": "ann"}, "requested_reviewers": [{"login": "me"}]},
                {"number": 5, "title": "other", "user": {"login": "bob"}}])})
        real = core.http
        core.http = fake
        try:
            data = self.d.mrs(registry.Ctx(DEVBOX, {"GITEA_TOKEN": "t0k"}, None))
            missing = self.d.mrs(registry.Ctx(DEVBOX, {}, None))
        finally:
            core.http = real
        self.assertEqual([(m["n"], m["merge"], m["approvals"], m["changes"]) for m in data["mine"]], [(3, "conflicts", 2, 0)])
        self.assertEqual([m["n"] for m in data["assigned"]], [4])
        self.assertEqual((data["prefix"], data["open"]), ("#", 3))
        self.assertTrue(all(h.get("Authorization") == "token t0k" for _, h in calls))
        self.assertEqual(missing["status"], "unknown")
        self.assertIn("GITEA_TOKEN", missing["error"])

    def test_bitbucket_rows_and_auth(self):
        write_config({"mrs": {"provider": "bitbucket", "repo": "team/app"}})
        api = "https://api.bitbucket.org/2.0"
        fake, calls = self._fake_http({
            api + "/user": (200, {"uuid": "{me}"}),
            api + "/repositories/team/app/pullrequests": (200, {"size": 2, "values": [
                {"id": 7, "title": "mine", "updated_on": "2026-10-16T10:00:00Z", "author": {"uuid": "{me}"},
                 "source": {"branch": {"name": "f"}}, "participants": [{"approved": True}, {"state": "changes_requested"}]},
                {"id": 8, "title": "review me", "author": {"uuid": "{ann}"}, "reviewers": [{"uuid": "{me}"}]}]})})
        real = core.http
        core.http = fake
        try:
            data = self.d.mrs(registry.Ctx(DEVBOX, {"BITBUCKET_USER": "me", "BITBUCKET_APP_PASSWORD": "pw"}, None))
            core.http = lambda *a, **k: core.Resp(401, {}, 1)
            rejected = self.d.mrs(registry.Ctx(DEVBOX, {"BITBUCKET_TOKEN": "x"}, None))
        finally:
            core.http = real
        self.assertEqual([(m["n"], m["approvals"], m["changes"], m["branch"]) for m in data["mine"]], [(7, 1, 1, "f")])
        self.assertEqual([m["n"] for m in data["assigned"]], [8])
        self.assertTrue(calls[0][1]["Authorization"].startswith("Basic "))
        self.assertIn("token rejected", rejected["error"])

    def test_unknown_provider_and_bad_gitea_url_hide_the_panel(self):
        for cfg in ({"provider": "svn", "repo": "a/b"}, {"provider": "gitea", "repo": "a/b", "url": "javascript:x"}):
            write_config({"mrs": cfg})
            self.assertIs(self.d.mrs(registry.Ctx(DEVBOX, {}, None))["installed"], False)

    def _cloud(self, fn, script, cfg):
        write_config(cfg)
        real_run, real_which = core.run, core.which
        core.which = lambda name, extra=(): "/usr/bin/" + name
        core.run = lambda argv, timeout=4.0, **k: script(argv)
        try:
            return fn(registry.Ctx(DEVBOX, {}, None))
        finally:
            core.run, core.which = real_run, real_which

    def test_gcp_states(self):
        ok = self._cloud(self.d.gcp_auth, lambda a: (0, "me@example.com\n" if "auth" in a else "proj-12345\n", ""), {"gcp": {}})
        self.assertEqual((ok["state"], ok["account"], ok["project"]), ("ok", "me@example.com", "proj-12345"))
        rej = self._cloud(self.d.gcp_auth, lambda a: (1, "", "ERROR: Reauthentication required.") if "describe" in a else
                          (0, "me@example.com\n", ""), {"gcp": {"project": "proj-12345"}})
        self.assertEqual(rej["state"], "rejected")
        self.assertIn("gcloud auth login", rej["alerts"][0]["msg"])
        none = self._cloud(self.d.gcp_auth, lambda a: (0, "", ""), {"gcp": {}})
        self.assertEqual(none["state"], "none")
        self.assertTrue(self._cloud(self.d.gcp_auth, lambda a: (0, "", ""), {})["unconfigured"])

    def test_azure_states_never_capture_the_token(self):
        seen = []

        def script(a):
            seen.append(a)
            if a[1:3] == ["account", "show"]:
                return 0, json.dumps({"name": "Pay-As-You-Go", "user": {"name": "me@example.com"}}), ""
            return 0, "2030-01-01 00:00:00.000000\n", ""
        ok = self._cloud(self.d.azure_auth, script, {"azure": {}})
        self.assertEqual((ok["state"], ok["subscription"]), ("ok", "Pay-As-You-Go"))
        self.assertEqual(ok["expires"], core.utc_epoch("2030-01-01T00:00:00"))
        tok = [a for a in seen if "get-access-token" in a][0]
        self.assertEqual(tok[tok.index("--query") + 1], "expiresOn")
        none = self._cloud(self.d.azure_auth, lambda a: (1, "", "ERROR: Please run 'az login' to setup account."), {"azure": {}})
        self.assertEqual(none["state"], "none")
        rej = self._cloud(self.d.azure_auth, lambda a: (0, "{}", "") if "show" in a else
                          (1, "", "AADSTS700082: The refresh token has expired"), {"azure": {"login_hint": "az login --tenant x"}})
        self.assertEqual((rej["state"], rej["hint"]), ("rejected", "az login --tenant x"))

    def test_access_panel_shows_cloud_rows(self):
        put("gcp_auth", {"cli": True, "state": "ok", "account": "me@example.com", "project": "proj-12345"})
        put("azure_auth", {"cli": True, "state": "rejected", "hint": "az login"})
        out = T.strip(render.render(DEVBOX, registry.Cache(), width=160, only=["access"]))
        self.assertIn("me@example.com @ proj-12345", out)
        self.assertIn("rejected · run az login", out)


class BranchReviewFindings(unittest.TestCase):
    """Locks in the second pre-release review's fixes."""

    def setUp(self):
        write_config({})
        reset_notify_state()

    def test_discord_payload_is_capped_whatever_the_batch_size(self):
        from motdlib import notify
        seen = {}
        real = core.http
        core.http = lambda url, **k: seen.update(k["json_body"]) or core.Resp(204, None, 1)
        try:
            ev = [{"kind": "new", "sev": "crit", "msg": "service-%03d is down on a host with a long name" % i} for i in range(200)]
            self.assertEqual(notify.send({"type": "discord", "url": "https://discord.test/hook"}, {}, "hub", ev), "")
        finally:
            core.http = real
        self.assertLessEqual(len(seen["content"]), 2000)

    def test_alert_identity_folds_measurements_but_keeps_names(self):
        k = alerts.key
        self.assertEqual(k("disk / 91% full on web"), k("disk / 92% full on web"))
        self.assertEqual(k("load 3.2 on 8 cores (web)"), k("load 4.1 on 8 cores (web)"))
        self.assertNotEqual(k("web-01: disk / 93% full"), k("web-02: disk / 93% full"))
        self.assertNotEqual(k("api1 is not accepting connections"), k("api2 is not accepting connections"))
        self.assertNotEqual(k("changes requested on #10"), k("changes requested on #11"))

    def test_a_clear_is_remembered_even_without_resolved_messages(self):
        from motdlib import notify
        write_config({"notify": {"targets": [{"type": "webhook", "url": "https://hook.test/x"}], "resolved": False}})
        now_alerts = [[{"sev": "crit", "msg": "db down", "src": "live"}], [], [{"sev": "crit", "msg": "db down", "src": "live"}]]
        sent = []
        real_send, real_cur = notify.send, notify.current_alerts
        notify.send = lambda t, env, label, ev: sent.append([e["kind"] for e in ev]) or ""
        try:
            for batch in now_alerts:
                notify.current_alerts = lambda host, cache, b=batch: list(b)
                notify.run(WEB, registry.Cache(), {})
        finally:
            notify.send, notify.current_alerts = real_send, real_cur
        self.assertEqual(sent, [["new"], ["new"]])  # the second incident is news, not suppressed

    def test_example_backup_check_fires_when_no_backup_exists(self):
        from motdlib.sources import checks
        ex = json.loads(Path(__file__).resolve().parents[1].joinpath("config.example.json").read_text())
        backup = next(c for c in ex["checks"] if c["name"] == "backups")
        d = tempfile.mkdtemp(dir=TMP)
        state, hits = checks.evaluate(backup, checks.run_files(dict(backup, glob=d + "/*.tar.zst"), {}))
        self.assertEqual((state, hits[0][1]), ("crit", "no backups found"))

    def test_expired_azure_login_is_rejected_not_absent(self):
        from motdlib.sources import devops
        err = "AADSTS700082: The refresh token has expired due to inactivity. To re-authenticate, please run `az login`."
        self.assertEqual(devops.classify_cli(1, err, devops._AZ_REJECTED, ("az login",)), "rejected")
        self.assertEqual(devops.classify_cli(1, "Please run 'az login' to setup account.", devops._AZ_REJECTED, ("az login",)), "none")

    def test_a_malformed_ttl_affects_only_its_own_check(self):
        from motdlib.sources import checks
        write_config({"checks": [{"name": "bad", "type": "command", "argv": ["true"], "ttl": "5m", "strikes": "x", "timeout": "y"},
                                 {"name": "good", "type": "command", "argv": ["true"]}]})
        host = hosts.Host("h", {"panels": ["checks"]})
        first = checks.checks(registry.Ctx(host, {}, None))
        again = checks.checks(registry.Ctx(host, {}, first))
        self.assertEqual([r["state"] for r in again["results"]], ["ok", "ok"])

    def test_one_sender_per_alert_across_hub_and_peers(self):
        from motdlib import notify
        found = [{"sev": "crit", "msg": "local", "src": "live"}, {"sev": "crit", "msg": "web: peer", "src": "peer"}]
        real_g, real_p = alerts.gather, alerts.probe_all
        alerts.gather = lambda host, cache, lv: list(found)
        alerts.probe_all = lambda host, *a, **k: {}
        try:
            core.write_json_atomic(core.BUNDLE_PATH, {"ts": time.time(), "sources": {}})
            self.assertEqual(notify.current_alerts(WEB, registry.Cache()), [])  # the hub speaks for this peer
            core.write_json_atomic(core.BUNDLE_PATH, {"ts": time.time() - 7200, "sources": {}})
            self.assertEqual([a["msg"] for a in notify.current_alerts(WEB, registry.Cache())], ["local"])  # hub gone quiet
            self.assertEqual(len(notify.current_alerts(HUB, registry.Cache())), 2)
            write_config({"notify": {"sender": "each"}})
            core.write_json_atomic(core.BUNDLE_PATH, {"ts": time.time(), "sources": {}})
            self.assertEqual([a["msg"] for a in notify.current_alerts(WEB, registry.Cache())], ["local"])
            self.assertEqual([a["msg"] for a in notify.current_alerts(HUB, registry.Cache())], ["local"])
        finally:
            alerts.gather, alerts.probe_all = real_g, real_p
            os.remove(core.BUNDLE_PATH)


class RenderSmoke(unittest.TestCase):
    def test_every_host_renders_within_width(self):
        write_config({"enable": ["claude_usage"]})
        put("procs", {"total": 900, "claude": 3, "codex": {"total": 2, "tui": 2}, "zombies": 0,
                      "playwright": {"total": 1, "orphans": 0}, "top": [], "orphan_claude": []})
        put("claude_usage", {"plan": "max (default_claude_max_20x)", "windows": [
            {"label": "5h", "used_pct": 22, "resets_at": time.time() + 3600}, {"label": "7d", "used_pct": 91, "resets_at": time.time() + 86400}],
            "alerts": [{"sev": "crit", "msg": "Claude 7d at 91%"}]})
        for host in (HUB, WEB, LAPTOP):
            for w in (60, 120, 200):
                out = render.render(host, registry.Cache(), width=w)
                plain = T.strip(out)
                for line in out.splitlines():
                    self.assertLessEqual(T.width(line), w + 1, "%s@%d: %r" % (host.name, w, T.strip(line)))
                self.assertNotIn("panel error", plain, "%s@%d" % (host.name, w))
                self.assertNotIn("\x1b", plain, "%s@%d: a cut escape sequence" % (host.name, w))
                self.assertIn("Claude 7d at 91%", plain)

    def test_fresh_install_renders_without_any_config(self):
        write_config({})
        out = T.strip(render.render(hosts.current(), registry.Cache(), width=100))
        self.assertIn("SYSTEM", out)
        self.assertNotIn("panel error", out)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=1)
    finally:
        import shutil
        shutil.rmtree(TMP, ignore_errors=True)

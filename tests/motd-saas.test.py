#!/usr/bin/env python3
"""Offline tests for motd/motdlib/sources/saas_probe.py (no network except a loopback server).
Python 3.9+, stdlib only:  python3 tests/motd-saas.test.py
"""
import base64
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

# Vendored module lives with the MOTD sources (Tailscale probe dropped; see its docstring).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "motdlib", "sources"))
import saas_probe as sp  # noqa: E402

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
CANARY = "CANARYSECRETVALUE0123456789abcdefXYZ"  # 36 chars: long enough for _scrub's token mask


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(**kw):
    return iso(NOW - timedelta(**kw))


def ms_ago(**kw):
    return int((NOW - timedelta(**kw)).timestamp() * 1000)


class Router(object):
    """Fake for sp._http. routes: {(METHOD, exact_url): (status, obj) | callable(**req) -> (status, obj) | Exception}."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []
        self.unexpected = []

    def __call__(self, method, url, headers=None, params=None, data=None, form=None, basic=None, timeout=None):
        req = dict(method=method, url=url, headers=headers or {}, params=params or {}, data=data, form=form, basic=basic)
        self.calls.append(req)
        h = self.routes.get((method, url))
        if h is None:
            self.unexpected.append("%s %s" % (method, url))
            raise sp.ProbeError("unexpected request")
        if isinstance(h, Exception):
            raise h
        status, obj = h(**req) if callable(h) else h
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        return sp.Resp(status, {}, body, 5)


def assert_shape(tc, res):
    tc.assertEqual(set(res), {"status", "summary", "details", "error"})
    tc.assertIn(res["status"], ("ok", "warn", "crit", "unknown"))
    tc.assertIsInstance(res["summary"], str)
    tc.assertLessEqual(len(res["summary"]), 60, res["summary"])
    tc.assertIsInstance(res["details"], dict)
    tc.assertTrue(res["error"] is None or isinstance(res["error"], str))
    json.dumps(res)  # must be JSON-safe


class Base(unittest.TestCase):
    def run_fetch(self, fn, env, routes, now=True):
        router = Router(routes)
        patches = [mock.patch.object(sp, "_http", router)]
        if now:
            patches.append(mock.patch.object(sp, "_now", lambda: NOW))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        res = fn(env)
        assert_shape(self, res)
        self.assertEqual(router.unexpected, [], "unexpected requests")
        return res, router


# --------------------------------------------------------------------------
class LoopbackServer(object):
    def __enter__(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, code, body, ctype="application/json", extra=None):
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def _handle(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode() if n else ""
                if self.path.startswith("/ok"):
                    self._reply(200, {"a": 1})
                elif self.path.startswith("/401"):
                    self._reply(401, {"message": "bad token"})
                elif self.path.startswith("/redir"):
                    self._reply(302, b"", extra={"Location": "/ok"})
                elif self.path.startswith("/text"):
                    self._reply(200, b"not json", ctype="text/plain")
                elif self.path.startswith("/slow"):
                    time.sleep(1.5)
                    self._reply(200, {"slow": True})
                elif self.path.startswith("/echo"):
                    self._reply(200, {"method": self.command, "path": self.path, "body": body,
                                      "auth": self.headers.get("Authorization"), "ctype": self.headers.get("Content-Type"),
                                      "ua": self.headers.get("User-Agent"), "x": self.headers.get("X-Test")})
                else:
                    self._reply(404, {"message": "nope"})

            do_GET = do_POST = _handle

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def url(self, path):
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def __exit__(self, *a):
        self.srv.shutdown()
        self.srv.server_close()


class TestTransport(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(os.environ, {"no_proxy": "127.0.0.1,localhost", "NO_PROXY": "127.0.0.1,localhost"})
        p.start()
        self.addCleanup(p.stop)
        for k in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
            os.environ.pop(k, None)
        # rebuild the opener so it re-reads the (cleaned) proxy environment
        o = mock.patch.object(sp, "_OPENER", sp.urllib.request.build_opener(sp._NoRedirect))
        o.start()
        self.addCleanup(o.stop)

    def test_get_json_ok_and_headers(self):
        with LoopbackServer() as s:
            r = sp._http("GET", s.url("/echo"), headers={"X-Test": "1"}, params={"q": ["a", "b"], "z": 1})
            j = r.json()
            self.assertEqual((r.status, j["method"], j["x"]), (200, "GET", "1"))
            self.assertIn("q=a&q=b&z=1", j["path"])
            self.assertTrue(j["ua"].startswith("saas-probe"))
            self.assertEqual(sp._get_json(s.url("/ok")), {"a": 1})

    def test_basic_auth_form_and_json_post(self):
        with LoopbackServer() as s:
            j = sp._http("GET", s.url("/echo"), basic=("user", "pw")).json()
            self.assertEqual(j["auth"], "Basic " + base64.b64encode(b"user:pw").decode())
            j = sp._http("POST", s.url("/echo"), form={"api_key": "k", "format": "json"}).json()
            self.assertEqual((j["method"], j["body"], j["ctype"]), ("POST", "api_key=k&format=json", "application/x-www-form-urlencoded"))
            j = sp._http("POST", s.url("/echo"), data={"query": "{x}"}).json()
            self.assertEqual((json.loads(j["body"]), j["ctype"]), ({"query": "{x}"}, "application/json"))

    def test_http_error_is_returned_not_raised(self):
        with LoopbackServer() as s:
            r = sp._http("GET", s.url("/401"))
            self.assertEqual((r.status, r.ok), (401, False))
            with self.assertRaises(sp.ProbeError) as cm:
                sp._get_json(s.url("/401"), label="svc ")
            self.assertEqual(str(cm.exception), "svc HTTP 401: bad token")
            with self.assertRaises(sp.ProbeError) as cm:
                sp._get_json(s.url("/text"))
            self.assertIn("non-JSON", str(cm.exception))

    def test_redirects_are_never_followed(self):
        with LoopbackServer() as s:
            r = sp._http("GET", s.url("/redir"), headers={"Authorization": "Bearer x"})
            self.assertEqual(r.status, 302)  # surfaced, credentials not forwarded anywhere

    def test_timeout_and_refused(self):
        with LoopbackServer() as s:
            t0 = time.monotonic()
            with self.assertRaises(sp.ProbeError) as cm:
                sp._http("GET", s.url("/slow"), timeout=0.3)
            self.assertEqual(str(cm.exception), "timeout")
            self.assertLess(time.monotonic() - t0, 1.2)
            port = s.port
        with self.assertRaises(sp.ProbeError) as cm:  # server closed: nothing listens
            sp._http("GET", "http://127.0.0.1:%d/ok" % port, timeout=1)
        self.assertIn(str(cm.exception), ("connection refused", "connection reset", "network error (OSError)"))

    def test_non_http_schemes_are_refused(self):
        for url in ("file:///etc/passwd", "ftp://example.com/x", "gopher://x"):
            with self.assertRaises(sp.ProbeError) as cm:
                sp._http("GET", url)
            self.assertEqual(str(cm.exception), "unsupported URL scheme")

    def test_dns_failure(self):
        with self.assertRaises(sp.ProbeError) as cm:
            sp._http("GET", "http://nonexistent-host.invalid/", timeout=2)
        self.assertIn(str(cm.exception), ("dns lookup failed", "timeout", "network error (gaierror)"))


class TestHelpers(unittest.TestCase):
    def test_parse_ts(self):
        p = sp._parse_ts
        self.assertEqual(p("2026-10-16T09:40:00.1Z"), datetime(2026, 10, 16, 9, 40, 0, 100000, tzinfo=timezone.utc))
        self.assertEqual(p("2026-10-16 09:12:33.123456+00"), datetime(2026, 10, 16, 9, 12, 33, 123456, tzinfo=timezone.utc))
        self.assertEqual(p("2026-10-16T09:40:00+05:30"), datetime(2026, 10, 16, 4, 10, 0, tzinfo=timezone.utc))
        self.assertEqual(p("2026-06-01T00:00:00.123456789Z"), datetime(2026, 6, 1, 0, 0, 0, 123456, tzinfo=timezone.utc))
        for bad in ("0001-01-01T00:00:00Z", "garbage", None, 5, "", "2026-13-45T25:61:61Z", "9999-12-31T23:59:59-05:00"):
            self.assertIsNone(p(bad), bad)

    def test_scrub_masks_key_like_text_and_caps_length(self):
        out = sp._scrub("The endpoint cannot be accessed with management key xai-...54nd because; token " + CANARY + " end")
        self.assertNotIn(CANARY, out)
        self.assertNotIn("54nd", out)
        self.assertLessEqual(len(sp._scrub("x " * 200)), 90)

    def test_redaction_skips_plain_words_but_catches_secrets(self):
        env = {"STRIPE_SECRET_KEY": "sk_live_" + "a1" * 20, "AUTOREVIEW_CLAUDE_AUTH": "subscription",
               "CF_EMAIL": "me@example.com", "PATH": "/usr/bin:/bin:/usr/local/bin", "SHORT_TOKEN": "abc"}
        text = "x sk_live_%s y subscription z me@example.com /usr/bin:/bin:/usr/local/bin abc" % ("a1" * 20)
        out = sp._redact_text(text, env)
        self.assertNotIn("sk_live_a1", out)
        self.assertNotIn("me@example.com", out)
        self.assertIn("subscription", out)  # plain word under an AUTH-named var is not redacted
        self.assertIn("/usr/bin:/bin:/usr/local/bin", out)  # non-sensitive name untouched

    def test_clip_worst_normalize(self):
        self.assertEqual(len(sp._clip("x" * 100)), 60)
        self.assertTrue(sp._clip("x" * 100).endswith("..."))
        self.assertEqual(sp._worst(["ok", "warn", "unknown"]), "warn")
        self.assertEqual(sp._worst(["ok", "crit", "warn"]), "crit")
        self.assertEqual(sp._worst(["unknown", "unknown"]), "unknown")
        self.assertEqual(sp._worst([]), "unknown")
        n = sp._normalize({"status": "bogus", "summary": "s" * 99, "details": None, "error": 5})
        self.assertEqual((n["status"], len(n["summary"]), n["details"], n["error"]), ("unknown", 60, {}, "5"))
        self.assertEqual(sp._normalize("garbage")["status"], "unknown")

    def test_pmap_never_raises(self):
        def boom():
            raise ValueError("x " + CANARY)
        out = sp._pmap({"a": lambda: 1, "b": boom, "c": lambda: (_ for _ in ()).throw(sp.ProbeError("net"))})
        self.assertEqual(out["a"], (1, None))
        self.assertEqual(out["c"], (None, "net"))
        self.assertTrue(out["b"][1].startswith("ValueError"))
        self.assertNotIn(CANARY, out["b"][1])


# --------------------------------------------------------------------------
# service logic (payload shapes are copied from real responses captured on 2026-10-16)
# --------------------------------------------------------------------------
CFB = sp.CF_BASE
CF_ENV = {"CF_EMAIL": "me@example.com", "CF_GLOBAL_API_KEY": CANARY, "CLOUDFLARE_ACCOUNT_ID": "ACCT", "CF_ZONE_ID": "ZONE"}


def cf_routes(tunnels=None, zones=None, requests=10000, s5xx=20, email=None, gql_error=False):
    tunnels = tunnels if tunnels is not None else [{"name": "t%d" % i, "status": "healthy"} for i in range(5)]
    zones = zones if zones is not None else [{"name": "example.com", "status": "active"}]
    email = email if email is not None else {"enabled": True, "status": "ready", "synced": True}

    def gql(**req):
        if gql_error:
            return 200, {"data": None, "errors": [{"message": "query failed " + CANARY}]}
        q = req["data"]["query"]
        if "httpRequests1hGroups" in q:
            sm = [{"edgeResponseStatus": 200, "requests": requests - s5xx}, {"edgeResponseStatus": 502, "requests": s5xx}]
            grp = {"sum": {"requests": requests, "cachedRequests": 8, "threats": 3, "responseStatusMap": sm}, "uniq": {"uniques": 42}}
            return 200, {"data": {"viewer": {"zones": [{"httpRequests1hGroups": [grp]}]}}, "errors": None}
        return 200, {"data": {"viewer": {"zones": [{"emailRoutingAdaptiveGroups": [{"count": 5, "dimensions": {"status": "delivered"}}]}]}}, "errors": None}

    return {("GET", CFB + "/accounts/ACCT/cfd_tunnel"): (200, {"success": True, "result": tunnels}),
            ("GET", CFB + "/zones"): (200, {"success": True, "result": zones}),
            ("GET", CFB + "/zones/ZONE/email/routing"): (200, {"success": True, "result": email}),
            ("POST", CFB + "/graphql"): gql}


class TestCloudflare(Base):
    def test_healthy_ignores_retired_tunnels(self):
        tun = [{"name": "t%d" % i, "status": "healthy"} for i in range(5)]
        tun += [{"name": "old%d" % i, "status": "down", "conns_inactive_at": ago(days=60)} for i in range(4)]
        res, rt = self.run_fetch(sp.fetch_cloudflare, CF_ENV, cf_routes(tunnels=tun))
        self.assertEqual(res["status"], "ok", res)
        self.assertEqual(res["summary"], "5/5 tunnels up, 10.0k req/24h, 20 5xx (0.2%)")
        self.assertEqual(res["details"]["tunnels"], {"total": 9, "healthy": 5, "degraded": 0, "down_recent": [], "stale_down": 4,
                                                     "by_status": {"healthy": ["t0", "t1", "t2", "t3", "t4"], "down": ["old0", "old1", "old2", "old3"]}})
        self.assertEqual(res["details"]["traffic_24h"]["cached_pct"], 0.08)
        self.assertEqual(res["details"]["email_routing"]["last_24h"], {"delivered": 5})
        hdr = rt.calls[0]["headers"]
        self.assertEqual((hdr["X-Auth-Email"], hdr["X-Auth-Key"]), (CF_ENV["CF_EMAIL"], CANARY))
        self.assertTrue(all(c["url"].startswith("https://api.cloudflare.com/") for c in rt.calls))

    def test_recent_down_is_crit_degraded_is_warn(self):
        tun = [{"name": "ok", "status": "healthy"}, {"name": "fresh", "status": "down", "conns_inactive_at": ago(hours=3)}]
        res, _ = self.run_fetch(sp.fetch_cloudflare, CF_ENV, cf_routes(tunnels=tun))
        self.assertEqual((res["status"], res["details"]["tunnels"]["down_recent"]), ("crit", ["fresh"]))
        res, _ = self.run_fetch(sp.fetch_cloudflare, CF_ENV, cf_routes(tunnels=[{"name": "d", "status": "degraded"}]))
        self.assertEqual(res["status"], "warn")

    def test_5xx_thresholds(self):
        for req, e5, want in ((10000, 20, "ok"), (10000, 100, "warn"), (10000, 500, "crit"), (10, 10, "ok")):
            res, _ = self.run_fetch(sp.fetch_cloudflare, CF_ENV, cf_routes(requests=req, s5xx=e5))
            self.assertEqual(res["status"], want, (req, e5, res["summary"]))

    def test_email_routing_not_ready_and_inactive_zone_warn(self):
        res, _ = self.run_fetch(sp.fetch_cloudflare, CF_ENV, cf_routes(email={"enabled": False, "status": "disabled"}))
        self.assertEqual(res["status"], "warn")
        res, _ = self.run_fetch(sp.fetch_cloudflare, CF_ENV, cf_routes(zones=[{"name": "x.com", "status": "pending"}]))
        self.assertEqual((res["status"], res["details"]["zones"]["not_active"]), ("warn", ["x.com"]))

    def test_partial_and_total_failure(self):
        r = cf_routes()
        r[("GET", CFB + "/accounts/ACCT/cfd_tunnel")] = (403, {"success": False, "errors": [{"message": "Invalid key " + CANARY}]})
        res, _ = self.run_fetch(sp.fetch_cloudflare, CF_ENV, r)
        self.assertEqual(res["status"], "warn")
        self.assertIn("tunnels", res["details"]["partial_errors"])
        self.assertNotIn(CANARY, json.dumps(res))
        dead = {k: sp.ProbeError("timeout") for k in cf_routes()}
        res, _ = self.run_fetch(sp.fetch_cloudflare, CF_ENV, dead)
        self.assertEqual(res["status"], "unknown")

    def test_graphql_error_does_not_leak_and_missing_env(self):
        res, _ = self.run_fetch(sp.fetch_cloudflare, CF_ENV, cf_routes(gql_error=True))
        self.assertNotIn(CANARY, json.dumps(res))
        self.assertEqual(res["status"], "warn")  # tunnels/zones fine, traffic query failed
        res = sp.fetch_cloudflare({})
        self.assertEqual((res["status"], res["error"]), ("unknown", "missing env: CF_EMAIL,CF_GLOBAL_API_KEY"))


VBASE = "https://api.vercel.com/v9/projects"


def vproj(name, state, **age):
    prod = {"readyState": state, "createdAt": ms_ago(**age)} if state else {}
    return {"name": name, "targets": {"production": prod} if prod else {}}


class TestVercel(Base):
    def go(self, projects, env=None, page2=None):
        pages = [(200, {"projects": projects, "pagination": {"count": len(projects), "next": 123 if page2 else None}})]
        if page2:
            pages.append((200, {"projects": page2, "pagination": {"count": len(page2), "next": None}}))
        it = iter(pages)
        return self.run_fetch(sp.fetch_vercel, env or {"VERCEL_TOKEN": CANARY}, {("GET", VBASE): lambda **r: next(it)})

    def test_ok_with_canceled_and_building(self):
        res, rt = self.go([vproj("a", "READY", hours=2), vproj("b", "CANCELED", minutes=5), vproj("c", "BUILDING", minutes=1), vproj("d", None)])
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["summary"], "4 projects, prod ok (1 READY, 1 building)")
        self.assertEqual(res["details"]["prod_states"], {"READY": 1, "CANCELED": 1, "BUILDING": 1, "NONE": 1})
        self.assertEqual(res["details"]["prod_by_project"], {"a": "READY", "b": "CANCELED", "c": "BUILDING", "d": "NONE"})
        self.assertEqual(rt.calls[0]["headers"]["Authorization"], "Bearer " + CANARY)
        self.assertNotIn("teamId", rt.calls[0]["params"])

    def test_error_age_decides_severity(self):
        res, _ = self.go([vproj("api", "ERROR", hours=3)])
        self.assertEqual((res["status"], res["summary"]), ("crit", "prod deploy ERROR: api"))
        res, _ = self.go([vproj("api", "ERROR", days=3)])
        self.assertEqual(res["status"], "warn")
        res, _ = self.go([vproj("apps", "ERROR", days=200)])
        self.assertEqual((res["status"], res["details"]["stale_errors"]), ("ok", ["apps"]))

    def test_pagination_team_and_failure(self):
        res, rt = self.go([vproj("a", "READY", days=1)], env={"VERCEL_TOKEN": "t", "VERCEL_TEAM_ID": "team_x"}, page2=[vproj("b", "READY", days=1)])
        self.assertEqual(res["details"]["projects"], 2)
        self.assertEqual(rt.calls[0]["params"]["teamId"], "team_x")
        self.assertEqual(rt.calls[1]["params"]["until"], 123)
        res, _ = self.run_fetch(sp.fetch_vercel, {"VERCEL_TOKEN": "t"}, {("GET", VBASE): (401, {"error": {"message": "Not authorized"}})})
        self.assertEqual((res["status"], res["error"]), ("unknown", "vercel HTTP 401: Not authorized"))
        self.assertEqual(sp.fetch_vercel({})["error"], "missing env: VERCEL_TOKEN")


V3 = "https://api.uptimerobot.com/v3/monitors"
V2 = "https://api.uptimerobot.com/v2/getMonitors"


def m3(name, status, dur=100):
    return {"friendlyName": name, "status": status, "currentStateDuration": dur, "httpPassword": CANARY, "apiKey": CANARY}


class TestUptimeRobot(Base):
    ENV = {"UPTIMEROBOT_API_KEY": CANARY}

    def test_v3_all_up_unescapes_names(self):
        res, rt = self.run_fetch(sp.fetch_uptimerobot, self.ENV, {("GET", V3): (200, {"data": [m3("a &#40;x&#41;", "UP"), m3("b", "UP")], "nextLink": None})})
        self.assertEqual((res["status"], res["summary"]), ("ok", "2/2 monitors up"))
        self.assertEqual(res["details"]["states"], {"a (x)": "up", "b": "up"})
        self.assertEqual(res["details"]["other"], 0)
        self.assertEqual(rt.calls[0]["headers"]["Authorization"], "Bearer " + CANARY)
        self.assertNotIn(CANARY, json.dumps(res))  # v3 payloads carry apiKey/httpPassword fields: never copied

    def test_v3_down_duration_decides_severity(self):
        week = 7 * 86400
        res, _ = self.run_fetch(sp.fetch_uptimerobot, self.ENV, {("GET", V3): (200, {"data": [m3("up", "UP"), m3("Old Bridge &#40;ob&#41;", "DOWN", 81 * 86400)]})})
        self.assertEqual((res["status"], res["summary"]), ("warn", "1/2 up; down: Old Bridge (ob) 81d"))
        res, _ = self.run_fetch(sp.fetch_uptimerobot, self.ENV, {("GET", V3): (200, {"data": [m3("api", "DOWN", 3600), m3("p", "PAUSED")]})})
        self.assertEqual((res["status"], res["details"]["paused"]), ("crit", 1))
        res, _ = self.run_fetch(sp.fetch_uptimerobot, self.ENV, {("GET", V3): (200, {"data": [m3("x", "DOWN", week + 1)]})})
        self.assertEqual(res["status"], "warn")

    def test_ignore_list(self):
        env = dict(self.ENV, PROBE_UPTIMEROBOT_IGNORE="old bridge, other")
        res, _ = self.run_fetch(sp.fetch_uptimerobot, env, {("GET", V3): (200, {"data": [m3("up", "UP"), m3("Old Bridge", "DOWN", 9e6)]})})
        self.assertEqual((res["status"], res["details"]["ignored"], res["details"]["total"]), ("ok", 1, 1))

    def test_v2_fallback_when_v3_rejected(self):
        def v2(**req):
            self.assertEqual(req["form"]["api_key"], CANARY)
            self.assertEqual(req["method"], "POST")
            return 200, {"stat": "ok", "pagination": {"offset": 0, "limit": 50, "total": 3},
                         "monitors": [{"friendly_name": "a", "status": 2}, {"friendly_name": "b", "status": 9}, {"friendly_name": "c", "status": 0}]}
        res, _ = self.run_fetch(sp.fetch_uptimerobot, self.ENV, {("GET", V3): (401, {"message": "bad"}), ("POST", V2): v2})
        self.assertEqual((res["status"], res["details"]["api"], res["details"]["v3_error"]), ("crit", "v2", "v3 HTTP 401: bad"))
        res, _ = self.run_fetch(sp.fetch_uptimerobot, self.ENV, {("GET", V3): (500, {}), ("POST", V2): (200, {"stat": "fail"})})
        self.assertEqual(res["status"], "unknown")
        self.assertIn("v3:", res["error"])

    def test_nextlink_only_followed_on_own_host(self):
        pages = iter([(200, {"data": [m3("a", "UP")], "nextLink": "https://evil.example/steal"}), (200, {"data": [m3("b", "UP")]})])
        res, rt = self.run_fetch(sp.fetch_uptimerobot, self.ENV, {("GET", V3): lambda **r: next(pages)})
        self.assertEqual(res["details"]["total"], 2)
        self.assertTrue(all(c["url"] == V3 for c in rt.calls))  # evil host never contacted
        self.assertEqual(rt.calls[1]["params"]["cursor"], "https://evil.example/steal")


HC, HZ = sp.HCLOUD, sp.HETZNER


def hz_server(name, status="running", out_gb=100):
    return {"name": name, "status": status, "location": {"name": "ash"}, "included_traffic": 4398046511104,
            "outgoing_traffic": out_gb * 10 ** 9, "backup_window": None,
            "server_type": {"name": "cpx41", "prices": [{"location": "ash", "price_monthly": {"gross": "141.4900000000000000"}}]}}


def hz_box(used, quota=5497558138880, status="active"):
    return {"storage_boxes": [{"name": "box", "status": status, "location": {"name": "fsn1"}, "stats": {"size": used},
                               "storage_box_type": {"size": quota, "prices": [{"location": "fsn1", "price_monthly": {"gross": "13.0000"}}]}}]}


def hz_routes(servers=None, box=None):
    servers = servers if servers is not None else [hz_server("a"), hz_server("b")]
    return {("GET", HC + "/servers"): (200, {"servers": servers}),
            ("GET", HC + "/volumes"): (200, {"volumes": [{"size": 400}, {"size": 400}]}),
            ("GET", HC + "/pricing"): (200, {"pricing": {"volume": {"price_per_gb_month": {"gross": "0.0767"}}}}),
            ("GET", HZ + "/storage_boxes"): (200, box or hz_box(1219778052096))}


class TestHetzner(Base):
    ENV = {"HCLOUD_TOKEN": CANARY}

    def test_ok_estimate_and_storage_box_on_new_api(self):
        res, rt = self.run_fetch(sp.fetch_hetzner, self.ENV, hz_routes())
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["summary"], "2/2 servers up, box 22%, ~$357/mo")
        self.assertEqual(res["details"]["est_monthly_usd"], 357.34)  # 2*141.49 + 800*0.0767 + 13.00
        self.assertEqual(res["details"]["storage_box"]["quota_tib"], 5.0)
        self.assertIn("not exposed", res["details"]["cost_mtd"])
        self.assertIn(("GET", HZ + "/storage_boxes"), [(c["method"], c["url"]) for c in rt.calls])

    def test_server_state_and_box_fill_thresholds(self):
        res, _ = self.run_fetch(sp.fetch_hetzner, self.ENV, hz_routes(servers=[hz_server("a"), hz_server("b", "off")]))
        self.assertEqual(res["status"], "crit")
        self.assertTrue(res["summary"].startswith("server b off"))
        res, _ = self.run_fetch(sp.fetch_hetzner, self.ENV, hz_routes(servers=[hz_server("a", "migrating")]))
        self.assertEqual(res["status"], "warn")
        for frac, want in ((0.5, "ok"), (0.85, "warn"), (0.95, "crit")):
            res, _ = self.run_fetch(sp.fetch_hetzner, self.ENV, hz_routes(box=hz_box(int(5497558138880 * frac))))
            self.assertEqual(res["status"], want, frac)
        res, _ = self.run_fetch(sp.fetch_hetzner, self.ENV, hz_routes(servers=[hz_server("a", out_gb=4200)]))
        self.assertEqual(res["status"], "warn")  # 95% of included traffic

    def test_non_usd_estimate_is_labelled_with_its_currency(self):
        r = hz_routes()
        r[("GET", HC + "/pricing")] = (200, {"pricing": {"currency": "EUR", "volume": {"price_per_gb_month": {"gross": "0.0767"}}}})
        res, _ = self.run_fetch(sp.fetch_hetzner, self.ENV, r)
        self.assertNotIn("est_monthly_usd", res["details"])
        self.assertEqual((res["details"]["est_monthly"], res["details"]["currency"]), (357.34, "EUR"))
        self.assertTrue(res["summary"].endswith("~357 EUR/mo"))

    def test_partial_data_and_total_failure(self):
        r = hz_routes()
        r[("GET", HC + "/pricing")] = (500, {})
        res, _ = self.run_fetch(sp.fetch_hetzner, self.ENV, r)
        self.assertEqual(res["status"], "ok")  # estimate is an extra: its failure does not downgrade status
        self.assertNotIn("est_monthly_usd", res["details"])
        r[("GET", HZ + "/storage_boxes")] = (401, {"message": "unauthorized"})
        res, _ = self.run_fetch(sp.fetch_hetzner, self.ENV, r)
        self.assertEqual(res["status"], "warn")
        res, _ = self.run_fetch(sp.fetch_hetzner, self.ENV, {k: sp.ProbeError("timeout") for k in hz_routes()})
        self.assertEqual(res["status"], "unknown")


def ts_dev(host, online=True, expires_in_days=200, disabled=False, tags=None):
    return {"hostname": host, "name": host + ".tail.ts.net", "connectedToControl": online, "lastSeen": ago(minutes=1),
            "keyExpiryDisabled": disabled, "expires": iso(NOW + timedelta(days=expires_in_days)), "tags": tags or []}


def ts_cli_json(peers, self_expiry_days=200):
    def peer(h, online=True, days=100, tags=None):
        d = {"HostName": h, "Online": online, "LastSeen": "0001-01-01T00:00:00Z" if online else ago(hours=5), "Tags": tags}
        if days is not None:
            d["KeyExpiry"] = iso(NOW + timedelta(days=days))
        return d
    return json.dumps({"BackendState": "Running", "Health": [],
                       "Self": {"HostName": "me", "Online": True, "KeyExpiry": iso(NOW + timedelta(days=self_expiry_days))},
                       "Peer": {"nodekey:%d" % i: peer(*p) for i, p in enumerate(peers)}})


GHB = sp.GH
GH_ENV = {"GITHUB_PERSONAL_ACCESS_TOKEN": "stale_pat_token_value", "PROBE_GH_REPOS": "octocat/acme,octocat/widgets",
          "PROBE_GH_USER": "octocat"}


def gh_run(name, concl, **age):
    return {"name": name, "conclusion": concl, "status": "completed" if concl else "in_progress", "updated_at": ago(**age)}


class TestGitHub(Base):
    def routes(self, runs_bl, runs_tg=None, gql=None, valid=("Bearer gho_good",)):
        gql = gql or {"data": {"o0": {"issueCount": 36}, "c0": {"issueCount": 0}, "h0": {"ref": {"target": {"statusCheckRollup": {"state": "SUCCESS"}}}},
                               "o1": {"issueCount": 7}, "c1": {"issueCount": 0}, "h1": {"ref": {"target": {"statusCheckRollup": {"state": "SUCCESS"}}}}}}
        runs_tg = runs_tg if runs_tg is not None else [gh_run("Widgets checks and deploy", "success", days=3)]

        def rate(**req):
            return (200, {}) if req["headers"].get("Authorization") in valid else (401, {"message": "Bad credentials"})
        return {("GET", GHB + "/rate_limit"): rate,
                ("POST", GHB + "/graphql"): (200, gql),
                ("GET", GHB + "/repos/octocat/acme/actions/runs"): (200, {"workflow_runs": runs_bl}),
                ("GET", GHB + "/repos/octocat/widgets/actions/runs"): (200, {"workflow_runs": runs_tg})}

    def go(self, runs_bl, env=None, **kw):
        with mock.patch.object(sp, "_gh_cli_token", return_value="gho_good") as cli:
            res, rt = self.run_fetch(sp.fetch_github, env if env is not None else GH_ENV, self.routes(runs_bl, **kw))
        return res, rt, cli

    def test_green_and_token_falls_back_to_gh_cli_when_env_pat_is_stale(self):
        res, rt, cli = self.go([gh_run("Deploy API", "success", hours=1), gh_run("Secret Scan", "success", hours=1)])
        self.assertEqual((res["status"], res["details"]["token_source"]), ("ok", "gh"))
        self.assertEqual(res["summary"], "CI green x2; 43 open PRs, 0 need changes")
        probes = [c["headers"]["Authorization"] for c in rt.calls if c["url"].endswith("/rate_limit")]
        self.assertEqual(probes, ["Bearer gho_good"])  # order: GH_TOKEN, GITHUB_TOKEN, gh, then the generic PAT var
        gql = [c for c in rt.calls if c["url"].endswith("/graphql")][0]["data"]["query"]
        for needle in ("author:octocat", "review:changes_requested", "repo:octocat/acme", "repo:octocat/widgets", "refs/heads/master"):
            self.assertIn(needle, gql)
        runs = [c for c in rt.calls if "/actions/runs" in c["url"]]
        self.assertTrue(all(c["params"]["event"] == "push" and c["params"]["branch"] == "master" for c in runs))

    def test_env_token_wins_when_valid(self):
        with mock.patch.object(sp, "_gh_cli_token", return_value="gho_good") as cli:
            res, _ = self.run_fetch(sp.fetch_github, {"GH_TOKEN": "gho_good", "PROBE_GH_REPOS": "octocat/acme,octocat/widgets", "PROBE_GH_USER": "octocat"}, self.routes([gh_run("x", "success", hours=1)]))
        self.assertEqual(res["details"]["token_source"], "env")
        cli.assert_not_called()

    def test_generic_pat_used_when_gh_is_unavailable_and_stale_one_is_skipped(self):
        with mock.patch.object(sp, "_gh_cli_token", return_value=None):
            res, rt = self.run_fetch(sp.fetch_github, GH_ENV, self.routes([gh_run("x", "success", hours=1)], valid=("Bearer stale_pat_token_value",)))
        self.assertEqual((res["status"], res["details"]["token_source"]), ("ok", "env"))

    def test_no_valid_token(self):
        with mock.patch.object(sp, "_gh_cli_token", return_value=None):
            res, _ = self.run_fetch(sp.fetch_github, GH_ENV, self.routes([], valid=()))
        self.assertEqual((res["status"], res["summary"]), ("unknown", "no valid GitHub token"))

    def test_ci_verdict_uses_latest_conclusive_run_per_workflow(self):
        res, _, _ = self.go([gh_run("Deploy", "failure", hours=2), gh_run("Deploy", "success", days=1)])
        self.assertEqual((res["status"], res["summary"]), ("crit", "acme CI failing: Deploy"))
        res, _, _ = self.go([gh_run("Deploy", "success", hours=2), gh_run("Deploy", "failure", days=1)])
        self.assertEqual(res["status"], "ok")  # recovered
        res, _, _ = self.go([gh_run("Deploy", "cancelled", minutes=5), gh_run("Deploy", "skipped", minutes=6), gh_run("Deploy", "success", hours=3)])
        self.assertEqual(res["status"], "ok")  # cancelled/skipped never decide
        res, _, _ = self.go([gh_run("Deploy", None, minutes=1), gh_run("Deploy", "success", hours=3)])
        self.assertEqual((res["status"], res["details"]["repos"][0]["ci_pending"]), ("ok", 1))

    def test_old_failure_is_stale_not_an_incident(self):
        res, _, _ = self.go([gh_run("Quarterly job", "failure", days=30)])
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["details"]["repos"][0]["ci_stale_failing"], ["Quarterly job"])

    def test_changes_requested_and_rollup(self):
        gql = {"data": {"o0": {"issueCount": 3}, "c0": {"issueCount": 2}, "h0": {"ref": {"target": {"statusCheckRollup": {"state": "SUCCESS"}}}},
                        "o1": {"issueCount": 0}, "c1": {"issueCount": 0}, "h1": {"ref": {"target": {"statusCheckRollup": {"state": "FAILURE"}}}}}}
        res, _, _ = self.go([gh_run("x", "success", hours=1)], gql=gql)
        self.assertEqual(res["status"], "crit")  # widgets HEAD checks FAILURE outranks the acme PR warning
        self.assertIn("widgets HEAD checks FAILURE", res["summary"])
        gql["data"]["h1"]["ref"]["target"]["statusCheckRollup"]["state"] = "SUCCESS"
        res, _, _ = self.go([gh_run("x", "success", hours=1)], gql=gql)
        self.assertEqual((res["status"], res["summary"]), ("warn", "acme: 2 PR(s) need changes"))

    def test_graphql_failure_is_partial_and_env_validation(self):
        res, _, _ = self.go([gh_run("x", "success", hours=1)], gql={"errors": [{"message": "rate limited"}]})
        self.assertEqual(res["status"], "warn")
        self.assertIn("gql", res["details"]["partial_errors"])
        self.assertEqual(res["summary"], "partial data (gql)")
        res = sp.fetch_github({"PROBE_GH_REPOS": "bad repo; DROP"})
        self.assertEqual(res["status"], "unknown")


SB = "https://sentry.io/api/0/organizations/"
US = "https://us.sentry.io/api/0/organizations/acme"


class TestSentry(Base):
    ENV = {"SENTRY_AUTH_TOKEN": CANARY}

    def routes(self, rows, orgs=None):
        orgs = orgs if orgs is not None else [{"slug": "acme", "links": {"regionUrl": "https://us.sentry.io"}}]
        return {("GET", SB): (200, orgs), ("GET", US + "/events/"): (200, {"data": rows}),
                ("GET", US + "/projects/"): (200, [{"slug": "p%d" % i} for i in range(8)])}

    def test_quiet_and_query_shape(self):
        res, rt = self.run_fetch(sp.fetch_sentry, self.ENV, self.routes([]))
        self.assertEqual((res["status"], res["summary"]), ("ok", "0 unresolved issues in 24h (8 projects)"))
        ev = [c for c in rt.calls if c["url"].endswith("/events/")][0]["params"]
        self.assertEqual((ev["statsPeriod"], ev["query"], ev["dataset"], ev["project"]), ("24h", "is:unresolved", "errors", "-1"))
        self.assertEqual(ev["field"], ["project", "count_unique(issue)", "count()"])
        self.assertTrue(all(c["headers"]["Authorization"] == "Bearer " + CANARY for c in rt.calls))

    def test_severity_by_volume(self):
        res, _ = self.run_fetch(sp.fetch_sentry, self.ENV, self.routes([{"project": "bad-chat", "count_unique(issue)": 3, "count()": 10}]))
        self.assertEqual((res["status"], res["summary"]), ("warn", "3 unresolved issues, 10 events/24h (bad-chat)"))
        res, _ = self.run_fetch(sp.fetch_sentry, self.ENV, self.routes([{"project": "api", "count_unique(issue)": 12, "count()": 40}]))
        self.assertEqual(res["status"], "crit")
        res, _ = self.run_fetch(sp.fetch_sentry, self.ENV, self.routes([{"project": "api", "count_unique(issue)": 2, "count()": 500}]))
        self.assertEqual(res["status"], "crit")

    def test_token_never_sent_to_non_sentry_region_host(self):
        orgs = [{"slug": "acme", "links": {"regionUrl": "https://evil.example.com"}}]
        res, rt = self.run_fetch(sp.fetch_sentry, self.ENV, {("GET", SB): (200, orgs)})
        self.assertEqual(res["status"], "unknown")
        self.assertEqual([c["url"] for c in rt.calls], [SB])

    def test_failures(self):
        res, _ = self.run_fetch(sp.fetch_sentry, self.ENV, {("GET", SB): (401, {"detail": "Invalid token"})})
        self.assertEqual((res["status"], res["error"]), ("unknown", "sentry HTTP 401: Invalid token"))
        r = self.routes([])
        r[("GET", US + "/events/")] = (403, {"detail": "no event:read"})
        res, _ = self.run_fetch(sp.fetch_sentry, self.ENV, r)
        self.assertEqual(res["status"], "unknown")
        self.assertEqual(sp.fetch_sentry({})["error"], "missing env: SENTRY_AUTH_TOKEN")


STR = sp.STRIPE


def sub(status, amount=1000, interval="month", count=1, qty=1, cur="usd"):
    return {"status": status, "items": {"data": [{"quantity": qty, "price": {"currency": cur, "unit_amount": amount,
                                                                              "recurring": {"interval": interval, "interval_count": count}}}]}}


class TestStripe(Base):
    ENV = {"STRIPE_SECRET_KEY": "sk_live_" + "a1" * 20}

    def routes(self, subs, has_more=False):
        return {("GET", STR + "/balance"): (200, {"available": [{"currency": "usd", "amount": 934}], "pending": [{"currency": "usd", "amount": 0}]}),
                ("GET", STR + "/subscriptions"): (200, {"data": subs, "has_more": has_more})}

    def test_ok_summary_mode_and_mrr(self):
        res, rt = self.run_fetch(sp.fetch_stripe, self.ENV, self.routes([sub("active"), sub("canceled"), sub("canceled")]))
        self.assertEqual((res["status"], res["summary"]), ("ok", "live, $9.34 avail, 1 active, 0 past due"))
        self.assertEqual(res["details"]["key_mode"], "sk_live")
        self.assertEqual(res["details"]["subscriptions"]["mrr_est"], {"usd": 10.0})
        self.assertEqual(rt.calls[1]["params"], {"status": "all", "limit": 100})
        self.assertTrue(all(c["method"] == "GET" for c in rt.calls))  # never writes
        self.assertNotIn(self.ENV["STRIPE_SECRET_KEY"], json.dumps(res))

    def test_mrr_normalisation(self):
        subs = [sub("active", 12000, "year"), sub("active", 500, "month", qty=3), sub("active", 700, "week"), sub("active", 3000, "month", count=3)]
        res, _ = self.run_fetch(sp.fetch_stripe, self.ENV, self.routes(subs))
        want = 12000 / 12.0 / 100 + 1500 / 100.0 + 700 * 52 / 12.0 / 100 + 3000 / 3.0 / 100
        self.assertAlmostEqual(res["details"]["subscriptions"]["mrr_est"]["usd"], round(want, 2), places=2)

    def test_past_due_warns_truncation_and_test_mode(self):
        res, _ = self.run_fetch(sp.fetch_stripe, self.ENV, self.routes([sub("active"), sub("past_due"), sub("unpaid")], has_more=True))
        self.assertEqual(res["status"], "warn")
        self.assertIn("2 past due", res["summary"])
        self.assertIn("1 active+", res["summary"])
        res, _ = self.run_fetch(sp.fetch_stripe, {"STRIPE_SECRET_KEY": "rk_test_" + "b2" * 20}, self.routes([]))
        self.assertEqual((res["details"]["key_mode"], res["summary"].split(",")[0]), ("rk_test", "test"))

    def test_partial_restricted_key_and_total_failure(self):
        r = self.routes([])
        r[("GET", STR + "/subscriptions")] = (403, {"error": {"message": "This key lacks permission"}})
        res, _ = self.run_fetch(sp.fetch_stripe, self.ENV, r)
        self.assertEqual(res["status"], "warn")
        self.assertIn("subs", res["details"]["partial_errors"])
        res, _ = self.run_fetch(sp.fetch_stripe, self.ENV, {k: (401, {"error": {"message": "Invalid API Key"}}) for k in self.routes([])})
        self.assertEqual(res["status"], "unknown")
        self.assertEqual(sp.fetch_stripe({})["error"], "missing env: STRIPE_SECRET_KEY")


RS = sp.RESEND
RESEND_ENV = {"RESEND_API_KEY": "re_" + "k9" * 18}
RESTRICTED = (401, {"statusCode": 401, "name": "restricted_api_key", "message": "This API key is restricted to only send emails"})


def email(event, **age):
    return {"id": "e", "to": ["someone@example.com"], "subject": "private", "last_event": event,
            "created_at": iso(NOW - timedelta(**age)).replace("T", " ").replace("Z", "+00")}


class TestResend(Base):
    def test_send_only_key_is_valid_but_unreadable(self):
        res, rt = self.run_fetch(sp.fetch_resend, RESEND_ENV, {("GET", RS + "/domains"): RESTRICTED})
        self.assertEqual((res["status"], res["error"]), ("unknown", "restricted_api_key"))
        self.assertEqual((res["details"]["key_valid"], res["details"]["can_read"]), (True, False))
        self.assertEqual(len(rt.calls), 1)  # nothing else is attempted with a key that cannot read

    def test_invalid_key_is_crit(self):
        res, _ = self.run_fetch(sp.fetch_resend, RESEND_ENV, {("GET", RS + "/domains"): (400, {"statusCode": 400, "message": "API key is invalid", "name": "validation_error"})})
        self.assertEqual((res["status"], res["summary"]), ("crit", "Resend key rejected"))
        res, _ = self.run_fetch(sp.fetch_resend, RESEND_ENV, {("GET", RS + "/domains"): (429, {"message": "slow down"})})
        self.assertEqual(res["status"], "unknown")

    def routes(self, domains, emails):
        return {("GET", RS + "/domains"): (200, {"data": domains}), ("GET", RS + "/emails"): emails}

    def test_full_access_paths(self):
        dom = [{"name": "mail.test", "status": "verified"}]
        res, _ = self.run_fetch(sp.fetch_resend, RESEND_ENV, self.routes(dom, (200, {"data": [email("delivered", hours=1), email("delivered", days=3)], "has_more": False})))
        self.assertEqual((res["status"], res["summary"]), ("ok", "1/1 domains verified, 1 emails/24h"))
        self.assertEqual(res["details"]["emails_24h"]["by_last_event"], {"delivered": 1})
        self.assertNotIn("example.com", json.dumps(res))  # recipient addresses never copied
        res, _ = self.run_fetch(sp.fetch_resend, RESEND_ENV, self.routes([{"name": "x.io", "status": "pending"}], (200, {"data": []})))
        self.assertEqual(res["status"], "warn")
        res, _ = self.run_fetch(sp.fetch_resend, RESEND_ENV, self.routes([{"name": "x.io", "status": "failed"}], (200, {"data": []})))
        self.assertEqual(res["status"], "crit")
        many = [email("bounced", minutes=5)] * 3 + [email("delivered", minutes=5)] * 27
        res, _ = self.run_fetch(sp.fetch_resend, RESEND_ENV, self.routes(dom, (200, {"data": many})))
        self.assertEqual(res["status"], "crit")  # 10% bounce on 30 emails
        res, _ = self.run_fetch(sp.fetch_resend, RESEND_ENV, self.routes(dom, (200, {"data": [email("bounced", hours=1), email("delivered", hours=1)]})))
        self.assertEqual(res["status"], "warn")  # small sample: warn, not crit
        res, _ = self.run_fetch(sp.fetch_resend, RESEND_ENV, self.routes(dom, (500, {})))
        self.assertEqual((res["status"], "emails_error" in res["details"]), ("ok", True))


H1, H2 = "http://100.0.0.1:3151", "http://stale.example.ts.net:3150"
LF_ENV = {"LANGFUSE_HOST": H1, "LANGFUSE_BASE_URL": H2, "LANGFUSE_PUBLIC_KEY": "pk-lf-" + "1" * 10, "LANGFUSE_SECRET_KEY": "sk-lf-" + "2" * 10,
          "LANGFUSE_PUBLIC_KEY_2": "pk-lf-bad", "LANGFUSE_SECRET_KEY_2": "sk-lf-" + "3" * 10}


def lf_routes(base=H1, health=True, metrics=True, bad_key=None):
    def project(**req):
        who = req["basic"][0]
        if who == bad_key:
            return 401, {"message": "Invalid credentials"}
        return 200, {"data": [{"name": "Gizmo" if who == LF_ENV["LANGFUSE_PUBLIC_KEY"] else "Acme"}]}

    def mx(**req):
        n = 0 if req["basic"][0] == LF_ENV["LANGFUSE_PUBLIC_KEY"] else 7
        q = json.loads(req["params"]["query"])
        assert q["view"] == "traces" and q["fromTimestamp"] < q["toTimestamp"]
        return 200, {"data": [{"count_count": n, "sum_totalCost": None if n == 0 else 1.5}]}

    r = {("GET", base + "/api/public/health"): (200, {"status": "OK", "version": "3.225.2"}) if health else sp.ProbeError("timeout"),
         ("GET", base + "/api/public/projects"): project,
         ("GET", base + "/api/public/metrics"): mx if metrics else (404, {"message": "no"}),
         ("GET", base + "/api/public/traces"): (200, {"meta": {"totalItems": 4}})}
    return r


class TestLangfuse(Base):
    def test_ok_two_projects_and_auth_is_basic(self):
        r = lf_routes()
        r[("GET", H2 + "/api/public/health")] = sp.ProbeError("dns lookup failed")
        res, rt = self.run_fetch(sp.fetch_langfuse, LF_ENV, r)
        self.assertEqual(res["status"], "ok", res)
        self.assertEqual(res["summary"], "v3.225.2 ok; Gizmo 0tr/$0.00; Acme 7tr/$1.50")
        self.assertFalse(res["details"]["used_fallback_url"])
        proj = [c for c in rt.calls if c["url"].endswith("/projects")]
        self.assertEqual({c["basic"][0] for c in proj}, {LF_ENV["LANGFUSE_PUBLIC_KEY"], LF_ENV["LANGFUSE_PUBLIC_KEY_2"]})
        self.assertNotIn("sk-lf-", json.dumps(res))

    def test_fallback_url_and_dead(self):
        r = lf_routes(base=H2)
        r[("GET", H1 + "/api/public/health")] = sp.ProbeError("connection refused")
        res, _ = self.run_fetch(sp.fetch_langfuse, LF_ENV, r)
        self.assertEqual((res["status"], res["details"]["used_fallback_url"]), ("ok", True))
        dead = {("GET", H1 + "/api/public/health"): sp.ProbeError("timeout"), ("GET", H2 + "/api/public/health"): sp.ProbeError("dns lookup failed")}
        res, _ = self.run_fetch(sp.fetch_langfuse, LF_ENV, dead)
        self.assertEqual((res["status"], res["summary"]), ("crit", "Langfuse unreachable"))
        res, _ = self.run_fetch(sp.fetch_langfuse, LF_ENV, {("GET", H1 + "/api/public/health"): (200, {"status": "DEGRADED"}), ("GET", H2 + "/api/public/health"): (503, {})})
        self.assertEqual(res["status"], "crit")

    def test_metrics_fallback_and_bad_key(self):
        res, _ = self.run_fetch(sp.fetch_langfuse, dict(LF_ENV, LANGFUSE_BASE_URL=""), lf_routes(metrics=False))
        self.assertEqual([p["traces_24h"] for p in res["details"]["projects"]], [4, 4])  # traces?limit=1 meta.totalItems
        res, _ = self.run_fetch(sp.fetch_langfuse, dict(LF_ENV, LANGFUSE_BASE_URL=""), lf_routes(bad_key=LF_ENV["LANGFUSE_PUBLIC_KEY_2"]))
        self.assertEqual(res["status"], "warn")
        self.assertIn("HTTP 401", res["summary"])
        env = {"LANGFUSE_HOST": H1}
        res, _ = self.run_fetch(sp.fetch_langfuse, env, lf_routes())
        self.assertEqual(res["status"], "warn")  # healthy server but no key pairs configured
        self.assertEqual(sp.fetch_langfuse({})["error"], "missing env: LANGFUSE_HOST")


OR, AN, OA = "https://openrouter.ai/api/v1", "https://api.anthropic.com/v1/organizations/cost_report", "https://api.openai.com/v1/organization/costs"
XAI = "https://management-api.x.ai"
TEAM = "01234567-89ab-cdef-0123-456789abcdef"
AI_ENV = {"OPENROUTER_MGMT_KEY": CANARY, "ANTHROPIC_ADMIN_KEY": "sk-ant-admin01-" + "a" * 30, "OPENAI_ADMIN_KEY": "sk-admin-" + "b" * 30,
          "XAI_MGMT_KEY": "xai-" + "c" * 40}


def or_routes(total=1150, used=1107.03):
    return {("GET", OR + "/credits"): (200, {"data": {"total_credits": total, "total_usage": used}}),
            ("GET", OR + "/key"): (200, {"data": {"label": CANARY, "name": CANARY, "limit": None, "usage_monthly": 0.12, "is_management_key": True}})}


class TestAISpend(Base):
    def test_openrouter_thresholds_and_label_never_read(self):
        for total, used, want in ((1150, 1107.03, "warn"), (1150, 1145, "crit"), (1150, 100, "ok")):
            res, _ = self.run_fetch(sp.fetch_openrouter, AI_ENV, or_routes(total, used))
            self.assertEqual(res["status"], want, (used, res["summary"]))
            self.assertNotIn(CANARY, json.dumps(res))
        res, _ = self.run_fetch(sp.fetch_openrouter, AI_ENV, or_routes(1150, 1107.03))
        self.assertEqual((res["summary"], res["details"]["remaining_usd"], res["details"]["remaining_pct"]), ("$42.97 left of $1150 credits", 42.97, 3.7))
        res, rt = self.run_fetch(sp.fetch_openrouter, {"OPENROUTER_API_KEY": "fallback_key_value"}, or_routes())
        self.assertEqual(rt.calls[0]["headers"]["Authorization"], "Bearer fallback_key_value")  # MGMT key absent -> API key

    def test_anthropic_sums_cents_over_pages_and_ignores_other_currencies(self):
        pages = iter([(200, {"data": [{"starting_at": "2026-10-01T00:00:00Z", "results": [{"currency": "USD", "amount": "12.5"}]},
                                      {"starting_at": "2026-10-02T00:00:00Z", "results": []}], "has_more": True, "next_page": "tok2"}),
                      (200, {"data": [{"starting_at": "2026-10-15T00:00:00Z", "results": [{"currency": "USD", "amount": "27.5"}, {"currency": "EUR", "amount": "999"}]}],
                             "has_more": False, "next_page": None})])
        res, rt = self.run_fetch(sp.fetch_anthropic, AI_ENV, {("GET", AN): lambda **r: next(pages)})
        self.assertEqual((res["status"], res["summary"]), ("ok", "MTD $0.40 (through 2026-10-15)"))  # 40 cents
        self.assertEqual(rt.calls[0]["params"]["starting_at"], "2026-10-01T00:00:00Z")
        self.assertEqual(rt.calls[1]["params"]["page"], "tok2")
        self.assertEqual(rt.calls[0]["headers"]["anthropic-version"], "2023-06-01")

    def test_openai_sums_dollars_over_pages(self):
        b = lambda day, v: {"start_time": int(datetime(2026, 10, day, tzinfo=timezone.utc).timestamp()), "results": [{"amount": {"value": v, "currency": "usd"}}]}
        pages = iter([(200, {"data": [b(1, 0.017), b(2, 0.5)], "has_more": True, "next_page": "p2"}), (200, {"data": [b(16, 1.25)], "has_more": False})])
        res, rt = self.run_fetch(sp.fetch_openai, AI_ENV, {("GET", OA): lambda **r: next(pages)})
        self.assertEqual((res["status"], res["details"]["mtd_usd"], res["details"]["last_bucket"]), ("ok", 1.77, "2026-10-16"))
        self.assertEqual(rt.calls[0]["params"]["start_time"], 1790812800)  # 2026-10-01T00:00:00Z

    def test_xai_billing_permission_missing_vs_granted(self):
        base = {("GET", XAI + "/auth/management-keys/validation"): (200, {"teamId": TEAM, "acls": []})}
        deny = dict(base)
        deny[("GET", "%s/v1/billing/teams/%s/prepaid/balance" % (XAI, TEAM))] = (403, {"code": 7, "message": "BillingRead denied for management key xai-...54nd"})
        res, _ = self.run_fetch(sp.fetch_xai, AI_ENV, deny)
        self.assertEqual((res["status"], res["summary"], res["error"]), ("unknown", "xAI mgmt key lacks BillingRead permission", "HTTP 403 BillingRead"))
        self.assertNotIn("54nd", json.dumps(res))
        allow = dict(base)
        allow[("GET", "%s/v1/billing/teams/%s/prepaid/balance" % (XAI, TEAM))] = (200, {"total": {"val": "-5000"}})
        res, _ = self.run_fetch(sp.fetch_xai, AI_ENV, allow)
        self.assertEqual((res["status"], res["details"]["prepaid_total_raw"]), ("ok", "-5000"))
        res, _ = self.run_fetch(sp.fetch_xai, AI_ENV, {("GET", XAI + "/auth/management-keys/validation"): (401, {"message": "bad"})})
        self.assertEqual(res["status"], "unknown")

    def test_aggregate_is_worst_known_and_unknown_only_when_all_unknown(self):
        pages_an = (200, {"data": [{"starting_at": "2026-10-15T00:00:00Z", "results": [{"currency": "USD", "amount": "272"}]}], "has_more": False})
        pages_oa = (200, {"data": [{"start_time": 1792000000, "results": [{"amount": {"value": 8.21, "currency": "usd"}}]}], "has_more": False})
        routes = dict(or_routes())
        routes.update({("GET", AN): pages_an, ("GET", OA): pages_oa, ("GET", XAI + "/auth/management-keys/validation"): (401, {"message": "bad"})})
        res, _ = self.run_fetch(sp.fetch_ai_spend, AI_ENV, routes)
        self.assertEqual(res["status"], "warn")  # openrouter low balance; xAI unknown is ignored
        self.assertEqual(res["summary"], "MTD A$2.72 O$8.21 | OR $43 left | xAI n/a")
        self.assertEqual(set(res["details"]), {"openrouter", "anthropic", "openai", "xai"})
        res, _ = self.run_fetch(sp.fetch_ai_spend, {}, {})
        self.assertEqual(res["status"], "unknown")
        self.assertIn("openrouter", res["error"])
        self.assertEqual(res["summary"], "MTD A n/a O n/a | OR n/a | xAI n/a")  # no invented "$0 left" when data is missing


AWS_CFG = "[default]\nregion = us-east-1\n\n[sso-session acme]\nsso_start_url = https://x.awsapps.com/start\n\n[profile acme-admin]\nsso_session = acme\nsso_account_id = 123456789012\n"
SSO_EXPIRED = "\nError when retrieving token from sso: Token has expired and refresh failed\n"
NO_CREDS = 'Unable to locate credentials. You can configure credentials by running "aws configure".\n'


class TestAWS(Base):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False)
        self.tmp.write(AWS_CFG)
        self.tmp.close()
        self.addCleanup(os.unlink, self.tmp.name)
        self.env = {"AWS_CONFIG_FILE": self.tmp.name}
        self.calls = []
        p = mock.patch.object(sp, "_aws_bin", return_value="/fake/aws")
        p.start()
        self.addCleanup(p.stop)

    def fake(self, sts_ok=("acme-admin",), ec2=None, ce="123.456"):
        def _run(cmd, timeout=None, env=None):
            self.calls.append(cmd)
            prof = cmd[cmd.index("--profile") + 1]
            region = cmd[cmd.index("--region") + 1] if "--region" in cmd else None
            if cmd[1] == "sts":
                if prof in sts_ok:
                    return subprocess.CompletedProcess(cmd, 0, json.dumps({"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/Role/me@example.com"}), "")
                return subprocess.CompletedProcess(cmd, 254, "", SSO_EXPIRED if prof == "acme-admin" else NO_CREDS)
            if cmd[1] == "ec2":
                v = (ec2 or {}).get(region, [])
                return subprocess.CompletedProcess(cmd, 0, json.dumps(v), "") if v != "ERR" else subprocess.CompletedProcess(cmd, 255, "", "AccessDenied")
            if cmd[1] == "ce":
                return subprocess.CompletedProcess(cmd, 0, json.dumps({"ResultsByTime": [{"Total": {"UnblendedCost": {"Amount": ce}}}]}), "")
            raise AssertionError(cmd)
        p = mock.patch.object(sp, "_run", _run)
        p.start()
        self.addCleanup(p.stop)

    def test_profiles_parsed_without_sso_sessions(self):
        self.assertEqual(sp._aws_profiles(self.env), ["default", "acme-admin"])
        self.assertEqual(sp._aws_profiles({"AWS_CONFIG_FILE": self.tmp.name, "AWS_PROFILE": "acme-admin"}), ["acme-admin", "default"])

    def test_expired_sso_is_warn_with_the_fix_in_the_summary(self):
        self.fake(sts_ok=())
        res, _ = self.run_fetch(sp.fetch_aws, self.env, {})
        self.assertEqual((res["status"], res["error"]), ("warn", "sso-expired"))
        self.assertEqual(res["summary"], "SSO token expired: aws sso login --profile acme-admin")
        self.assertEqual(res["details"]["profile_errors"], {"default": "no-credentials", "acme-admin": "sso-expired"})

    def test_no_credentials_anywhere_is_unknown(self):
        self.fake(sts_ok=())
        with mock.patch.object(sp, "_aws_profiles", return_value=["default"]):
            res, _ = self.run_fetch(sp.fetch_aws, self.env, {})
        self.assertEqual((res["status"], res["error"]), ("unknown", "no-credentials"))

    def test_success_counts_ec2_hides_account_and_skips_cost_explorer(self):
        self.fake(ec2={"us-east-1": [{"n": "a", "t": "m5"}, {"n": None, "t": "m5"}], "us-west-2": [{"n": "w", "t": "c5"}]})
        res, _ = self.run_fetch(sp.fetch_aws, self.env, {})
        self.assertEqual((res["status"], res["summary"]), ("ok", "acct ...9012, 3 EC2 running"))
        self.assertEqual(res["details"]["account_last4"], "9012")
        self.assertNotIn("123456789012", json.dumps(res))
        self.assertNotIn("example.com", json.dumps(res))  # role session name (an email) is not copied
        self.assertFalse(any(c[1] == "ce" for c in self.calls), "Cost Explorer bills $0.01/call: must be opt-in")
        self.assertEqual({c[c.index("--region") + 1] for c in self.calls if c[1] == "ec2"}, {"us-east-1", "us-west-2"})

    def test_cost_explorer_only_when_opted_in_and_ec2_error_is_partial(self):
        self.fake(ec2={"us-east-1": [], "us-west-2": "ERR"})
        res, _ = self.run_fetch(sp.fetch_aws, dict(self.env, PROBE_AWS_CE="1"), {})
        self.assertEqual(res["details"]["mtd_unblended_usd"], 123.46)
        self.assertEqual(sum(1 for c in self.calls if c[1] == "ce"), 1)
        self.assertEqual((res["status"], res["details"]["ec2_running"]["us-west-2"]), ("warn", {"error": "access-denied"}))

    def test_cli_missing(self):
        with mock.patch.object(sp, "_aws_bin", return_value=None):
            res = sp.fetch_aws(self.env)
        self.assertEqual(res["status"], "unknown")


SID = "AC" + "0123456789abcdef" * 2
TW = "https://api.twilio.com/2010-04-01/Accounts/" + SID


class TestTwilio(Base):
    ENV = {"TWILIO_ACCOUNT_SID": SID, "TWILIO_AUTH_TOKEN": CANARY}

    def routes(self, balance="42.5000", count="7"):
        return {("GET", TW + "/Balance.json"): (200, {"balance": balance, "currency": "USD"}),
                ("GET", TW + "/Usage/Records/Today.json"): (200, {"usage_records": [{"category": "sms", "count": count}]})}

    def test_without_creds_is_unknown_and_makes_no_request(self):
        res, rt = self.run_fetch(sp.fetch_twilio, {}, {})
        self.assertEqual((res["status"], res["error"]), ("unknown", "missing env: TWILIO_ACCOUNT_SID,TWILIO_AUTH_TOKEN"))
        self.assertEqual(rt.calls, [])

    def test_live_path_uses_basic_auth_and_thresholds(self):
        res, rt = self.run_fetch(sp.fetch_twilio, self.ENV, self.routes())
        self.assertEqual((res["status"], res["summary"]), ("ok", "$42.50 balance, 7 SMS today"))
        self.assertTrue(all(c["basic"] == (SID, CANARY) for c in rt.calls))
        self.assertNotIn(SID, json.dumps(res))
        for bal, want in (("3.00", "crit"), ("15.00", "warn"), ("50.00", "ok")):
            res, _ = self.run_fetch(sp.fetch_twilio, self.ENV, self.routes(balance=bal))
            self.assertEqual(res["status"], want, bal)

    def test_bad_sid_and_failures(self):
        res = sp.fetch_twilio({"TWILIO_ACCOUNT_SID": "../../etc", "TWILIO_AUTH_TOKEN": "x"})
        self.assertEqual(res["status"], "unknown")
        r = self.routes()
        r[("GET", TW + "/Usage/Records/Today.json")] = (500, {})
        res, _ = self.run_fetch(sp.fetch_twilio, self.ENV, r)
        self.assertEqual(res["status"], "warn")


class TestRunnerAndLeaks(unittest.TestCase):
    def stubs(self):
        def boom(env):
            raise RuntimeError("kaboom " + CANARY)
        return (("good", lambda env: sp._res("ok", "fine", {"x": 1})), ("bad", boom), ("junk", lambda env: "not a dict"),
                ("slow", lambda env: (time.sleep(0.3), sp._res("warn", "w"))[1]))

    def test_run_all_isolates_failures_and_runs_in_parallel(self):
        with mock.patch.object(sp, "FETCHERS", self.stubs()):
            t0 = time.monotonic()
            out = sp.run_all({})
            wall = time.monotonic() - t0
        r = out["results"]
        self.assertEqual(list(r), ["good", "bad", "junk", "slow"])  # registry order preserved
        self.assertEqual((r["good"]["status"], r["bad"]["status"], r["junk"]["status"], r["slow"]["status"]), ("ok", "unknown", "unknown", "warn"))
        self.assertEqual(r["bad"]["summary"], "internal error")
        self.assertNotIn(CANARY, json.dumps(out))
        self.assertEqual(set(out["timing_ms"]), set(r))
        for v in r.values():
            self.assertEqual(set(v), {"status", "summary", "details", "error"})
        self.assertLess(wall, 0.6)
        with mock.patch.object(sp, "FETCHERS", self.stubs()):
            self.assertEqual(list(sp.run_all({}, only=["slow", "good"])["results"]), ["good", "slow"])

    def test_deadline_reports_hung_fetchers_without_waiting_for_them(self):
        stubs = (("fast", lambda env: sp._res("ok", "fine")), ("hung", lambda env: (time.sleep(2.0), sp._res("ok", "late"))[1]))
        with mock.patch.object(sp, "FETCHERS", stubs):
            t0 = time.monotonic()
            out = sp.run_all({}, deadline=0.3)
            self.assertLess(time.monotonic() - t0, 1.0)
        self.assertEqual(out["deadline_hit"], ["hung"])
        self.assertEqual((out["results"]["fast"]["status"], out["results"]["hung"]["status"], out["results"]["hung"]["error"]),
                         ("ok", "unknown", "deadline exceeded"))
        with mock.patch.object(sp, "FETCHERS", stubs[:1]):
            self.assertNotIn("deadline_hit", sp.run_all({}))

    def test_source_audit_only_read_only_verbs_and_commands(self):
        """Guard rail: a future edit must not add a mutating HTTP verb or CLI subcommand unnoticed."""
        import re
        with open(sp.__file__) as fh:
            src = fh.read()
        self.assertEqual(len(re.findall(r'_http\("POST"', src)), 3)  # Cloudflare GraphQL, GitHub GraphQL, UptimeRobot v2 getMonitors
        self.assertEqual(re.findall(r'"(?:PUT|PATCH|DELETE)"', src), [])
        aws = set(re.findall(r'_aws_cli\(\["(\w+)", "([\w-]+)"', src))
        self.assertEqual(aws, {("sts", "get-caller-identity"), ("ec2", "describe-instances"), ("ce", "get-cost-and-usage")})
        self.assertEqual(set(re.findall(r'_run\(\[b, ([^\]]+)\]', src)), {'"auth", "token"'})

    def test_registry_covers_all_twelve_services(self):
        names = [n for n, _ in sp.FETCHERS]
        self.assertEqual(names, ["cloudflare", "vercel", "uptimerobot", "hetzner", "github", "sentry", "stripe", "resend",
                                 "langfuse", "ai_spend", "aws", "twilio"])
        for n, fn in sp.FETCHERS:
            assert_shape(self, fn({"__empty__": ""}) if n in ("cloudflare", "vercel", "stripe", "resend", "sentry", "twilio", "uptimerobot", "hetzner") else sp._res("ok", "x"))

    def run_main(self, argv, env=None):
        import contextlib
        import io
        buf = io.StringIO()
        with mock.patch.dict(os.environ, env or {}), contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = sp.main(argv)
        return rc, buf.getvalue()

    def test_main_json_lines_only_and_final_redaction(self):
        secret = "tok_" + "z9" * 14

        def leaky(env):  # simulates a fetcher bug that echoes a credential into its summary/details
            return sp._res("ok", "echo " + secret, {"k": secret})
        with mock.patch.object(sp, "FETCHERS", (("leaky", leaky), ("good", lambda e: sp._res("ok", "fine")))):
            rc, text = self.run_main([], {"LEAK_SECRET_TOKEN": secret})
            self.assertEqual(rc, 0)
            self.assertNotIn(secret, text)
            self.assertEqual(list(json.loads(text)["results"]), ["leaky", "good"])
            rc, text = self.run_main(["--lines"], {"LEAK_SECRET_TOKEN": secret})
            self.assertNotIn(secret, text)
            self.assertIn("wall time", text.splitlines()[-1])
            rc, text = self.run_main(["--only", "good", "--compact"])
            self.assertEqual(list(json.loads(text)["results"]), ["good"])
            self.assertEqual(len(text.strip().splitlines()), 1)
        with self.assertRaises(SystemExit) as cm:
            self.run_main(["--only", "nosuchservice"])
        self.assertEqual(cm.exception.code, 2)

    def test_every_fetcher_survives_garbage_responses_without_leaking(self):
        """Fuzz: every fetcher gets 200-with-garbage and 500-with-secret-echo from every URL; none may raise or leak."""
        env = {k: CANARY for k in ("CF_EMAIL", "CF_GLOBAL_API_KEY", "VERCEL_TOKEN", "UPTIMEROBOT_API_KEY", "HCLOUD_TOKEN", "TAILSCALE_API_KEY",
                                    "SENTRY_AUTH_TOKEN", "STRIPE_SECRET_KEY", "RESEND_API_KEY", "OPENROUTER_MGMT_KEY", "ANTHROPIC_ADMIN_KEY",
                                    "OPENAI_ADMIN_KEY", "XAI_MGMT_KEY")}
        env.update({"CLOUDFLARE_ACCOUNT_ID": "ACCT", "CF_ZONE_ID": "ZONE", "LANGFUSE_HOST": "http://h:1", "LANGFUSE_PUBLIC_KEY": "pk",
                    "LANGFUSE_SECRET_KEY": CANARY, "TWILIO_ACCOUNT_SID": SID, "TWILIO_AUTH_TOKEN": CANARY, "AWS_CONFIG_FILE": "/nonexistent"})
        for mode in ("garbage", "error", "empty_obj", "list"):
            def fake(method, url, headers=None, params=None, data=None, form=None, basic=None, timeout=None, mode=mode):
                if mode == "garbage":
                    return sp.Resp(200, {}, b"<html>oops " + CANARY.encode() + b"</html>", 1)
                if mode == "error":
                    return sp.Resp(500, {}, json.dumps({"message": "boom " + CANARY, "errors": [{"message": CANARY}]}).encode(), 1)
                if mode == "list":
                    return sp.Resp(200, {}, b"[1, 2, 3]", 1)
                return sp.Resp(200, {}, b"{}", 1)
            with mock.patch.object(sp, "_http", fake), mock.patch.object(sp, "_run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", CANARY)), \
                    mock.patch.object(sp, "_gh_cli_token", return_value=CANARY), mock.patch.object(sp, "_aws_bin", return_value=None), \
                    mock.patch.object(sp, "_first_existing", lambda c: None):
                for name, fn in sp.FETCHERS:
                    res = sp._normalize(fn(env))
                    assert_shape(self, res)
                    self.assertNotIn(CANARY, json.dumps(res), "%s leaked in mode %s" % (name, mode))


    def test_deeply_nested_junk_degrades_gracefully_through_the_production_wrapper(self):
        """Schema drift: junk elements / non-dict values nested everywhere must not surface as 'internal error'."""
        bad_el = [1, None, "x", [], {"targets": 5, "status": 5, "price": 5, "recurring": 5, "items": 5, "location": 5, "stats": 5,
                                     "storage_box_type": 5, "server_type": 5, "links": 5, "amount": 5, "dimensions": 5, "uniq": 5, "sum": 5}]
        junk = {k: bad_el for k in ("projects", "data", "monitors", "servers", "volumes", "storage_boxes", "devices", "keys", "workflow_runs",
                                    "usage_records", "results", "available", "pending", "responseStatusMap", "emailRoutingAdaptiveGroups",
                                    "httpRequests1hGroups", "zones", "prices", "items", "result")}
        junk.update({"pagination": 5, "meta": 5, "stat": "ok", "total": 5, "balance": "x", "viewer": 5, "pricing": 5, "status": "OK",
                     "teamId": "01234567-89ab-cdef-0123-456789abcdef", "has_more": False, "version": 5})
        env = {k: CANARY for k in ("CF_EMAIL", "CF_GLOBAL_API_KEY", "VERCEL_TOKEN", "UPTIMEROBOT_API_KEY", "HCLOUD_TOKEN", "TAILSCALE_API_KEY",
                                    "SENTRY_AUTH_TOKEN", "STRIPE_SECRET_KEY", "RESEND_API_KEY", "OPENROUTER_MGMT_KEY", "ANTHROPIC_ADMIN_KEY",
                                    "OPENAI_ADMIN_KEY", "XAI_MGMT_KEY")}
        env.update({"CLOUDFLARE_ACCOUNT_ID": "ACCT", "CF_ZONE_ID": "ZONE", "LANGFUSE_HOST": "http://h:1", "LANGFUSE_PUBLIC_KEY": "pk",
                    "LANGFUSE_SECRET_KEY": CANARY, "TWILIO_ACCOUNT_SID": SID, "TWILIO_AUTH_TOKEN": CANARY})

        def fake(method, url, headers=None, params=None, data=None, form=None, basic=None, timeout=None):
            return sp.Resp(200, {}, json.dumps(bad_el if url.endswith("/organizations/") else junk).encode(), 1)
        with mock.patch.object(sp, "_http", fake), mock.patch.object(sp, "_run", lambda *a, **k: subprocess.CompletedProcess(a, 0, json.dumps(bad_el), "")), \
                mock.patch.object(sp, "_gh_cli_token", return_value=CANARY), mock.patch.object(sp, "_aws_bin", return_value="/fake/aws"), \
                mock.patch.object(sp, "_first_existing", lambda c: "/fake/bin"), mock.patch.object(sp, "_aws_profiles", return_value=["p"]):
            for name, fn in sp.FETCHERS:
                res, _ = sp._timed(fn, env)
                assert_shape(self, res)
                self.assertNotEqual(res["summary"], "internal error", "%s raised on nested junk: %s" % (name, res["error"]))
                self.assertNotIn(CANARY, json.dumps(res))


if __name__ == "__main__":
    unittest.main()

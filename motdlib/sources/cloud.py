"""SaaS / infra sources over the vendored saas_probe fetchers.

Global (hub-collected, shipped to peers): Cloudflare, Vercel, UptimeRobot,
Hetzner, GitHub, Sentry, Stripe, Resend, Twilio, Langfuse, AI spend, AWS.
Each reads its credentials from the collector's env (~/.config/motd/env) and is
skipped, not alarmed on, when they are absent. Nothing secret is cached or logged.
"""
from __future__ import annotations

import os

from ..registry import source


def _sp():
    """The vendored fetchers on first use: ~33 ms of import that the login render,
    which only needs this module's source registrations, never pays."""
    from . import saas_probe
    return saas_probe

def _wrap(name: str, res: dict, quiet_unknown=True) -> dict:
    """Normalize, and turn warn/crit into one alert carrying the summary."""
    out = _sp()._normalize(res)
    if out["status"] in ("warn", "crit"):
        out["alerts"] = [{"sev": out["status"], "msg": "%s: %s" % (name, out["summary"])}]
    elif out["status"] == "unknown" and not quiet_unknown and out.get("error"):
        out["alerts"] = [{"sev": "warn", "msg": "%s: %s" % (name, out["error"][:80])}]
    return out


def _run(fn, env: dict, **extra):
    e = dict(env)
    e.update(extra)
    try:
        return fn(e)
    except Exception as ex:  # noqa: BLE001 — fetchers are hardened, but never trust that at login
        return _sp()._res("unknown", "internal error", {}, "%s: %s" % (type(ex).__name__, _sp()._scrub(ex)))


@source("cloudflare", ttl=600, timeout=25, scope="global", needs=("CF_EMAIL", "CF_GLOBAL_API_KEY"))
def cloudflare(ctx):
    """Tunnels, zone status, 24h edge traffic, Email Routing."""
    return _wrap("cloudflare", _run(_sp().fetch_cloudflare, ctx.env))


@source("vercel", ttl=900, timeout=20, scope="global", needs=("VERCEL_TOKEN",))
def vercel(ctx):
    """Latest production deployment state per project."""
    return _wrap("vercel", _run(_sp().fetch_vercel, ctx.env))


@source("uptimerobot", ttl=300, timeout=15, scope="global", needs=("UPTIMEROBOT_API_KEY",))
def uptimerobot(ctx):
    """External uptime monitors."""
    return _wrap("uptime", _run(_sp().fetch_uptimerobot, ctx.env))


@source("hetzner", ttl=1800, timeout=20, scope="global", needs=("HCLOUD_TOKEN",))
def hetzner(ctx):
    """Cloud servers, Storage Box usage, price-list run-rate."""
    return _wrap("hetzner", _run(_sp().fetch_hetzner, ctx.env))


@source("github", ttl=600, timeout=25, scope="global", needs=("PROBE_GH_REPOS", "PROBE_GH_USER"))
def github(ctx):
    """CI verdict on master, open PRs, changes requested (PROBE_GH_REPOS)."""
    return _wrap("github", _run(_sp().fetch_github, ctx.env))


@source("sentry", ttl=900, timeout=20, scope="global", needs=("SENTRY_AUTH_TOKEN",))
def sentry(ctx):
    """Unresolved issues and events in the last 24h."""
    return _wrap("sentry", _run(_sp().fetch_sentry, ctx.env))


@source("stripe", ttl=1800, timeout=15, scope="global", needs=("STRIPE_SECRET_KEY",))
def stripe(ctx):
    """Balance, subscriptions, MRR estimate (GET only)."""
    return _wrap("stripe", _run(_sp().fetch_stripe, ctx.env))


@source("resend", ttl=1800, timeout=15, scope="global", needs_any=("RESEND_API_KEY", "RESEND_FULL_API_KEY"))
def resend(ctx):
    """Domains and recent sends. RESEND_API_KEY is send-only; reading needs RESEND_FULL_API_KEY."""
    key = ctx.env.get("RESEND_FULL_API_KEY") or ctx.env.get("RESEND_API_KEY")
    return _wrap("resend", _run(_sp().fetch_resend, ctx.env, RESEND_API_KEY=key))


@source("langfuse", ttl=900, timeout=20, scope="global", needs_any=("LANGFUSE_PUBLIC_KEY", "LANGFUSE_PUBLIC_KEY_2"))
def langfuse(ctx):
    """Langfuse health + 24h traces/cost per project."""
    return _wrap("langfuse", _run(_sp().fetch_langfuse, ctx.env))


@source("ai_spend", ttl=3600, timeout=25, scope="global",
        needs_any=("ANTHROPIC_ADMIN_KEY", "OPENAI_ADMIN_KEY", "OPENROUTER_MGMT_KEY", "OPENROUTER_API_KEY", "XAI_MGMT_KEY"))
def ai_spend(ctx):
    """Month-to-date API spend: Anthropic, OpenAI, OpenRouter credits, xAI."""
    return _wrap("ai spend", _run(_sp().fetch_ai_spend, ctx.env))


@source("aws", ttl=3600, timeout=25, scope="global")
def aws(ctx):
    """STS identity, EC2 count, Cost Explorer (opt-in via PROBE_AWS_CE=1)."""
    return _wrap("aws", _run(_sp().fetch_aws, ctx.env))


@source("twilio", ttl=1800, timeout=20, scope="global", needs=("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"))
def twilio(ctx):
    """Twilio balance + today's SMS."""
    return _wrap("twilio", _run(_sp().fetch_twilio, ctx.env))

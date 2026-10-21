# fleet-motd

A login dashboard for a handful of machines. It shows host vitals, services,
Claude/Codex agent activity, and (if you give it keys) the state of the SaaS you
run, plus a fleet table with one row per host and a ranked list of alerts.

- **Fast.** A login never touches the network. It reads cached JSON and renders in
  about 25 ms in-process and 50-100 ms as a process.
- **Stdlib only.** Plain Python 3 (developed on 3.12, syntax-checked against 3.8), no packages, no daemon. A timer runs the collector.
- **Fleet-aware.** One host is the hub. It collects the SaaS sources and swaps a
  bundle and a snapshot with each peer over your existing ssh aliases, so peers
  show the same panels without holding any API key.
- **Honest.** A failing source keeps its last good data and renders as stale. A
  source with no credentials is skipped, not flagged. `motd doctor` says why.

```
  __  __  ___ _____ ____     ◆ my-laptop  ·  Ubuntu 24.04 LTS
 |  \/  |/ _ \_   _|  _ \    Wed Oct 21 · 12:27 EDT
 | |\/| | | | || | | | | |   🌤️ 62°F mostly clear · H 76 L 44
 | |  | | |_| || | | |_| |   up 49m · lan 192.168.1.174
 |_|  |_|\___/ |_| |____/    ● 1 critical

 SYSTEM ● ─────────────────────────────────────    AGENTS ───────────────────────────
 cpu   ━━━━━━━━───────────────────  1.88 load      procs    3 claude · 1 codex
 mem   ━━━━───────────────────────   16%           tmux     2 sessions · 5 windows
 disk  ━━━────────────────────────   12%           FLEET ●
```

## Install

```sh
git clone https://github.com/coletebou/fleet-motd && cd fleet-motd
./install.sh          # timer (systemd user unit or LaunchAgent) + ~/.config/motd seeded
python3 motd.py init --write    # a profile for this machine from what runs here
$EDITOR ~/.config/motd/config.json
python3 motd.py collect --force && python3 motd.py doctor
```

Then print it at login (zsh shown; use `$-` for bash):

```sh
[[ -o login || -n "$SSH_CONNECTION" ]] && python3 /path/to/fleet-motd/motd.py --login
alias motd='python3 /path/to/fleet-motd/motd.py'
```

`./install.sh --uninstall` removes the timer and leaves your config and cache.

## Commands

```
motd                 the dashboard
motd all             every panel, even on a narrow terminal
motd <panel> ...     just those panels: system services agents fleet ai edge infra biz repo
                     docker mrs ec2 access checks checks:<group>
motd init            print a starting profile for this machine (--write saves it, --force replaces)
motd alerts          every current alert, ranked, with its source
motd notify-test     send a test message to every notify target
motd collect         refresh due sources now (--force, --only a,b, --quiet)
motd doctor          per-source freshness, last error, missing keys, timer state
motd json [source]   raw cached records (no secrets are ever stored)
```

Environment: `MOTD_WIDTH=N`, `MOTD_COLOR=truecolor|256|16|none`, `NO_COLOR`,
`MOTD_DISABLE=1` (skip the login MOTD), `MOTD_MACHINE=name`, `MOTD_CONFIG_DIR`,
`MOTD_CACHE_DIR`.

## Configuration

`~/.config/motd/config.json` (see [`config.example.json`](config.example.json)):

| Key | Meaning |
|---|---|
| `hosts` | Profiles keyed by machine name (`MOTD_MACHINE`, else the short hostname). A host with no profile gets a generic one. |
| `hosts.*.tags` | `#hub` makes it the collector for global sources and the peer exchange; `#server`, `#dev`, `#mac`, `#linux`, `#wsl` are used for layout and gating. |
| `hosts.*.peers` | ssh aliases the hub exchanges with; each must equal that machine's own name (`MOTD_MACHINE` or hostname) and have fleet-motd installed. A mismatch raises an alert saying which name to use. |
| `hosts.*.units` | `[unit, label, "system"\|"user"]` systemd units shown on the services panel. Same label = one cell. |
| `hosts.*.agents` | macOS launchd labels (`"com.example.*"` matches every loaded job with that prefix). |
| `hosts.*.mounts`, `ports`, `repos` | Disks to meter, `[port, label]` loopback listeners (shown on the services panel; a closed one alerts on `#server` hosts), git repos to summarize. |
| `hosts.*.panels` | Panel order. `compact` (phone width) and `hints` are also overridable. |
| `hosts.*.banner`, `accent` | Banner name (`banners/<name>.txt`, or `~/.config/motd/banners/`) and gradient stops. |
| `fleet_order`, `short` | Fleet table order and short names. |
| `sites` | `[label, url]` endpoints probed from the hub; two failures in a row raise an alert. |
| `weather` | `{place, lat, lon, tz, unit: "imperial"\|"metric"}`; shown on hosts with `"weather": true`. |
| `tz` | IANA zone for the second clock in a `#server` host's header (falls back to `weather.tz`; none if neither). |
| `qotd_file` | A text file with one line per day for the footer's question of the day. |
| `enable` / `disable` | Source names to switch on (opt-in sources) or off. |
| `checks` | Config-described checks; see [Checks](#checks-describe-anything-to-watch-in-config). |
| `docker` panel | Needs nothing: compose projects from `docker ps`. |
| `mrs` | `{provider, repo, ...}`: your open PRs/MRs and ones waiting on you. `github` and `gitlab` (`host?` for self-hosted) use the `gh`/`glab` login you already have; `gitea`/`forgejo` take `url` and a `GITEA_TOKEN` (or `token_env`); `bitbucket` (Cloud, `repo: workspace/slug`) takes `BITBUCKET_TOKEN` or `BITBUCKET_USER` + `BITBUCKET_APP_PASSWORD`. |
| `ec2` | `{region, filters: {"Tag": ["value", ...]}, cache_file?}`: instances matching the tag filters; `cache_file` is a describe-instances text dump to fall back on. |
| `aws` | `{region, login_hint}` for the `access` panel's credential check. |
| `gcp`, `azure` | `{}` (or `{project, login_hint}` / `{login_hint}`) to add `gcloud` / `az` credential rows to the `access` panel. |
| `notify` | `{targets: [{type: ntfy\|slack\|discord\|webhook, url, token?}], min_sev: "crit", repeat_after: 21600, resolved: true, sender: "hub"\|"each"}`; see [Notifications](#notifications). |
| `reach` | `{ssh: [alias...], endpoints: [[label, url, verifyTls?]...], socks: "host:port", hint}`, global or per host. `ssh` aliases get a TCP :22 connect (proves a VPN/VPC route); endpoints are probed directly, then through `socks` if that fails. |

API keys go in `~/.config/motd/env` (`KEY=value` lines, parsed and never executed;
`chmod 600`). If a key is already in the collector's environment it is used too. See
[`env.example`](env.example).

## Sources

Local to each host: `procs` (Claude/Codex/MCP process census), `tailscale`,
`repos`, and the dev-ops sources below. Global (collected by the hub, shipped to peers): `weather`, `quotes`,
`sites`, and these SaaS probes, each read-only and skipped without its key:
Cloudflare, Vercel, UptimeRobot, Hetzner, GitHub, Sentry, Stripe, Resend, Twilio,
Langfuse, AI API spend, AWS.

**Dev-ops panels** switch on by listing them in a host's `panels`:

| Panel | Shows | Alerts |
|---|---|---|
| `docker` | compose stacks: up/total, starting, one-shots done, unhealthy, restarting, recent exits | an unhealthy or crash-looping container, a fresh non-zero exit in a running stack |
| `mrs` | your open PRs/MRs with merge state, approvals, changes requested; ones waiting on you | conflicts, changes requested |
| `ec2` | running and stopped instances matching your tag filters | none |
| `access` | AWS identity (STS) and SSO token clock, GCP and Azure accounts, private-network route, endpoints | credentials that exist but are rejected; an endpoint answering 5xx twice in a row |

Being off VPN, Docker not running or no AWS login renders as state, not an alert.

### Checks: describe anything to watch in config

The `checks` list covers whatever has no built-in source: your notes system, backups,
cron jobs, health endpoints, certificates. Each check is one JSON object; list
`checks` (every check) or `checks:<group>` (one group, titled by the group) in a
host's `panels`.

| Type | Keys | Metrics for `show` and `rules` |
|---|---|---|
| `http` | `url`, `headers`, `expect_status`, `json: {name: "a.b.0.c"}` | `status`, `ms`, `up`, your `json` fields |
| `files` | `glob` (`**` works) | `count`, `bytes`, `max_bytes`, `newest_age`, `oldest_age`, `recent_24h`, `max_lines` |
| `jsonl` | `glob`, `id`, `status`, `order` | `total`, `events_24h`, one count per status value |
| `command` | `argv` (a list, never a shell), `parse: json\|kv\|lines`, `json` | `exit`, `ok`, `stdout1`, parsed fields; a kv unix timestamp `X` also gets `X_age` |
| `tls` | `host`, `port`, `warn_days`, `crit_days` | `days_left`, `verify_error` |
| `dns` | `host`, `expect` | `resolved`, `addrs`, `ip`, `match` |
| `tcp` | `host`, `port` | `open`, `ms` |

An absent metric (no file matched a glob, say) never trips a threshold rule; use
`missing`, `falsy` or `count eq 0` to alert on absence. Every metric ending in `age` (seconds) or containing `bytes` also gets a `_h` human
form (`{newest_age_h}` → `3h`). `rules` are `{metric, op, value, sev, msg}` with
`op` one of `lt le gt ge eq ne truthy falsy missing`; `http`, `tcp`, `dns`, `tls`
and `command` have sensible default rules. Network checks alert after two failures
in a row (`strikes`), others after one. Other keys: `group`, `hosts` (names or
`#tags` to run on), `ttl` (seconds between runs, default 300). `${VAR}` in a `url`
or header expands from `~/.config/motd/env`, so tokens stay out of `config.json`.

```json
"checks": [
  {"name": "search", "group": "knowledge", "type": "http", "url": "https://notes.example.com/healthz",
   "json": {"ok": "ok", "entries": "index.entries"}, "show": "{entries} entries",
   "rules": [{"metric": "ok", "op": "falsy", "sev": "crit", "msg": "search index unhealthy"},
             {"metric": "entries", "op": "falsy", "sev": "warn", "msg": "search index is empty"}]},
  {"name": "notes", "group": "knowledge", "type": "files", "glob": "~/notes/**/*.md",
   "show": "{count} files · {recent_24h} touched today"},
  {"name": "MEMORY.md", "group": "knowledge", "type": "files", "glob": "~/notes/MEMORY.md",
   "show": "{max_bytes_h} · {max_lines} lines",
   "rules": [{"metric": "max_bytes", "op": "ge", "value": 22000, "sev": "warn", "msg": "MEMORY.md near its size budget"}]},
  {"name": "todos", "group": "knowledge", "type": "jsonl", "glob": "~/notes/todos/*.jsonl",
   "show": "{open} open · {done} done · +{events_24h} today"},
  {"name": "nightly", "group": "jobs", "type": "command", "parse": "kv",
   "argv": ["systemctl", "--user", "show", "nightly.service", "--timestamp=unix", "-p", "Result,ExecMainExitTimestamp"],
   "show": "{Result} · {ExecMainExitTimestamp_age_h} ago",
   "rules": [{"metric": "Result", "op": "ne", "value": "success", "sev": "crit", "msg": "nightly job: {Result}"},
             {"metric": "ExecMainExitTimestamp_age", "op": "gt", "value": 129600, "sev": "warn", "msg": "nightly job has not run in 36h"}]},
  {"name": "backups", "group": "jobs", "type": "files", "glob": "/backups/*.tar.zst", "hosts": ["#server"],
   "show": "{count} · newest {newest_age_h} ago",
   "rules": [{"metric": "count", "op": "eq", "value": 0, "sev": "crit", "msg": "no backups found"},
             {"metric": "newest_age", "op": "gt", "value": 93600, "sev": "crit", "msg": "no backup in 26h"}]},
  {"name": "example.com", "group": "certs", "type": "tls", "host": "example.com"}
]
```

### Notifications

The collector can push alerts so you hear about them away from a terminal. After
each run it compares the current alerts with what it last sent: new ones go out in
one batched message per target, one still firing after `repeat_after` seconds goes
out again, and a cleared one sends a "resolved" line. By default the hub is the one
sender: it reports its own, fleet-wide and its peers' critical alerts, and a peer
speaks for itself only while its hub has gone quiet (30 minutes without a bundle).
`"sender": "each"` makes every host send its own alerts instead (use it with
`min_sev: "warn"`, since peers ship only critical alerts to the hub). If every target fails, the
alerts are retried on the next run. Keep webhook secrets in the env file:

```json
"notify": {"targets": [{"type": "ntfy", "url": "https://ntfy.sh/${NTFY_TOPIC}"},
                       {"type": "slack", "url": "${SLACK_WEBHOOK_URL}"}],
           "min_sev": "crit"}
```

`slack` and `discord` post their webhook formats; `webhook` posts
`{host, title, text, events, ts}` JSON. `motd notify-test` checks the wiring, and
`motd doctor` shows the last send and any errors.

### Trends

Each collector run appends cpu (load as a share of cores), memory and the fullest
disk to a four-hour ring, and the system panel draws them as sparklines once there
are three samples.

**Opt-in** (`"enable": [...]`): `claude_usage`, `codex_usage`, `cursor_usage`,
`grok_usage`. These read the local login of the respective CLI (Claude Code's
credentials file or macOS Keychain item, Codex's `auth.json`, ...) and ask the
vendor's own usage endpoint for your plan limits. Those endpoints are not public
APIs and can change or be restricted without notice; enable them only for your own
accounts.

Writing a source is one decorated function (`motdlib/registry.py`): return a
JSON-able dict, optionally with `"alerts": [{"sev": "warn", "msg": "..."}]`, never a
secret. TTL, timeout, retry cadence, host gating and required keys are decorator
arguments.

## How it works

The renderer reads `~/.cache/motd/v2/`; the collector (`motd collect`, every five
minutes from the timer, and detached at login when something is due) refreshes each
source on its own TTL with its own timeouts, under a single-instance lock. Secrets
are scrubbed from error text and are never written to the cache. The hub pushes
`hub/bundle.json` to each peer and pulls the peer's `snapshot.json` in the same ssh
call. If the hub goes quiet a peer falls back to collecting a global source itself,
only if it has the key.

## Tests

```sh
python3 tests/motd.test.py && python3 tests/motd-saas.test.py
```

Offline: they pass with only a loopback interface, and never read your config.

## License

MIT.

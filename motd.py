#!/usr/bin/env python3
"""motd: a cached, fleet-aware login dashboard.

  motd                  full dashboard (what zshrc prints at login)
  motd all              every panel, even on a narrow terminal
  motd <panel>...       just those panels: system services agents fleet ai edge
                        infra biz repo docker mrs ec2 access checks checks:<group>
  motd alerts           every current alert, ranked
  motd init [--write] [--force]
                        a starting profile for this machine from what runs here
  motd collect [--force] [--only a,b] [--quiet]
                        refresh due sources now (the timer runs this every 5 min)
  motd notify-test      send a test message to every config "notify" target
  motd doctor           per-source health: scope, cadence, age, last error, creds
  motd json [source]    raw cached records (no secrets are ever stored)

Config: ~/.config/motd/config.json (hosts, sites, weather) and ~/.config/motd/env
(API keys); see README.md.

Env: MOTD_WIDTH=N (force width) · MOTD_COLOR=truecolor|256|16|none ·
     MOTD_DISABLE=1 (skip the login MOTD) · MOTD_MACHINE=name · MOTD_CONFIG_DIR · MOTD_CACHE_DIR · NO_COLOR
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))


def _due_any(host, cache) -> bool:
    from motdlib import collect, core, registry
    now = core.now()
    return any(collect.is_due(s, host, now, cache) for s in registry.SOURCES.values()
               if registry.applies(s, host) and s.name != "fleet")


def main(argv) -> int:
    from motdlib import core, hosts, registry
    args = argv[1:]
    flags = {a for a in args if a.startswith("-")}
    words = [a for a in args if not a.startswith("-")]
    if "-h" in flags or "--help" in flags:
        print(__doc__.strip())
        return 0
    words = [w for w in words if w not in ("full", "fast")]  # legacy services-status modes
    cmd = words[0] if words else "show"
    host = hosts.current()

    if cmd == "init":
        from motdlib import init
        return init.run(args)

    if cmd == "collect":
        from motdlib import collect
        only = None
        if "--only" in args:
            i = args.index("--only")
            only = [s for s in (args[i + 1] if i + 1 < len(args) else "").split(",") if s]
        return collect.collect(force="--force" in flags, only=only, quiet="--quiet" in flags)

    from motdlib import sources  # noqa: F401 — register all sources
    cache = registry.Cache()

    if cmd == "json":
        import json
        if len(words) > 1:
            src = registry.SOURCES.get(words[1])
            if src and not registry.serves(src, host):
                print("motd: %s is not a %s source" % (words[1], host.identity), file=sys.stderr)
                return 2
            print(json.dumps(cache.rec(words[1]), indent=2, default=str))
        else:
            print(json.dumps({n: cache.rec(n) for n in sorted(registry.SOURCES)
                              if registry.serves(registry.SOURCES[n], host)}, indent=2, default=str))
        return 0

    if cmd == "notify-test":
        from motdlib import notify
        res = notify.run(host, cache, core.secrets(), test=True)
        if not (core.config().get("notify") or {}).get("targets"):
            print("motd: no notify targets in config.json", file=sys.stderr)
            return 2
        print("sent to %d target(s)%s" % (len((core.config().get("notify") or {}).get("targets")) - len(res["errors"]),
                                         "; errors: " + "; ".join(res["errors"]) if res["errors"] else ""))
        return 1 if res["errors"] else 0

    if cmd == "doctor":
        from motdlib import doctor
        return doctor.run(host, cache)

    if cmd == "alerts":
        from motdlib import alerts, theme as T
        found = alerts.gather(host, cache, alerts.probe_all(host))
        if not found:
            print(T.c("✔ no alerts", "green"))
        for a in found:
            g, col = alerts.GLYPH.get(a["sev"], ("·", "sky"))
            print("%s %s %s" % (T.c(g, col), a["msg"], T.dim("[%s]" % a.get("src", ""))))
        return 0

    from motdlib import collect, panels, render
    only = None
    if cmd == "all":
        os.environ["MOTD_FULL"] = "1"
        cmd = "show"
    if cmd != "show":
        only = [w for w in words if panels.resolve(w)]
        unknown = [w for w in words if not panels.resolve(w)]
        if unknown:
            print("motd: unknown command or panel: %s (motd -h)" % ", ".join(unknown), file=sys.stderr)
            return 2
    login = "--login" in flags
    if login and os.environ.get("MOTD_DISABLE"):
        return 0
    sys.stdout.write(render.render(host, cache, only=only, login=login) + "\n")
    sys.stdout.flush()
    if "--no-refresh" not in flags and _due_any(host, cache):
        collect.spawn_background()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)

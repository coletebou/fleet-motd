"""`motd init`: write a starting host profile for this machine from what is running here.

Detects the OS tags, whether this is a server (no graphical target), running
services worth watching, Mac LaunchAgents, real mounts, Docker, recently used git
repos, a GitHub or GitLab remote for the PR panel, and AWS/GCP/Azure CLIs.
Prints the merged config.json by default; --write saves it (keeping a .bak), and
--force replaces an existing profile for this host.
"""
from __future__ import annotations

import json
import os
import re
import shutil

from . import core

# System services worth a cell on the services panel (prefix match; templates allowed).
INTERESTING = ("nginx", "caddy", "apache2", "httpd", "haproxy", "traefik", "docker", "podman", "k3s", "kubelet",
               "postgresql", "mysql", "mariadb", "redis", "valkey", "mongod", "clickhouse", "elasticsearch",
               "rabbitmq", "nats", "cloudflared", "tailscaled", "wg-quick@", "ssh", "sshd", "fail2ban", "crowdsec",
               "prometheus", "grafana", "node_exporter", "loki", "syncthing@", "restic", "borg", "ollama", "minio")
USER_NOISE = re.compile(r"^(dbus|pipewire|wireplumber|gpg-agent|xdg-|at-spi|gvfs|pulseaudio|ssh-agent|systemd-|dconf|"
                        r"evolution|tracker|gnome-|org\.gnome|obex|filter-chain|app-|snap\.|motd-collect|init)")
REAL_FS = ("ext4", "xfs", "btrfs", "zfs", "f2fs", "bcachefs", "apfs", "hfs")


def _systemd(user=False) -> list:
    argv = ["systemctl"] + (["--user"] if user else []) + ["list-units", "--type=service", "--state=running",
                                                         "--no-legend", "--plain", "--no-pager"]
    rc, out, _ = core.run(argv, 5)
    return [l.split()[0][:-len(".service")] for l in out.splitlines() if l.split() and l.split()[0].endswith(".service")] if rc == 0 else []


def units() -> list:
    out = []
    for u in _systemd():
        if any(u == p or (u.startswith(p) and (p.endswith("@") or u[len(p):][:1] in ("-", "@", "."))) for p in INTERESTING):
            out.append([u, u[:16], "system"])
    for u in _systemd(user=True):
        if not USER_NOISE.match(u):
            out.append([u, u[:16], "user"])
    return out[:16]


def agents() -> list:
    rc, out, _ = core.run(["/bin/launchctl", "list"], 3)
    labels = [l.split("\t")[2] for l in out.splitlines()[1:] if l.count("\t") == 2] if rc == 0 else []
    keep = [l for l in labels if not l.startswith(("com.apple.", "application.", "com.openssh", "0x"))]
    return [[l, l.split(".")[-1][:12]] for l in sorted(keep)][:12]


def mounts() -> list:
    if core.IS_MAC:
        vols = [os.path.join("/Volumes", v) for v in sorted(os.listdir("/Volumes"))] if os.path.isdir("/Volumes") else []
        return ["/"] + [v for v in vols if not os.path.islink(v)][:3]
    found = ["/"]
    for line in core.read_text("/proc/mounts").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] in REAL_FS and parts[1] not in found and \
                not parts[1].startswith(("/boot", "/snap", "/var/lib/docker", "/run", "/sys", "/proc", "/mnt/wslg", "/usr/lib/wsl")):
            found.append(parts[1].replace("\\040", " "))
    return found[:5]


def repos(limit=3) -> list:
    cands = []
    for base in ("~/code", "~/src", "~/projects", "~/dev"):
        b = os.path.expanduser(base)
        if not os.path.isdir(b):
            continue
        for name in os.listdir(b):
            p = os.path.join(b, name)
            if os.path.isdir(os.path.join(p, ".git")):
                cands.append((core.mtime(os.path.join(p, ".git", "index")) or core.mtime(p), p))
    return ["~" + p[len(core.HOME):] if p.startswith(core.HOME) else p for _, p in sorted(cands, reverse=True)[:limit]]


def forge(repo_paths) -> dict:
    """{"provider", "repo"[, "host"]} from the first repo whose origin is GitHub or GitLab and whose CLI is here."""
    for rp in repo_paths:
        rc, url, _ = core.run(["git", "-C", os.path.expanduser(rp), "remote", "get-url", "origin"], 3)
        m = re.match(r"^(?:git@|ssh://git@|https://)([^/:]+)[/:](.+?)(?:\.git)?/?$", url.strip()) if rc == 0 else None
        if not m:
            continue
        host, path = m.group(1), m.group(2)
        if host == "github.com" and core.which("gh"):
            return {"provider": "github", "repo": path}
        if "gitlab" in host and core.which("glab"):
            return dict({"provider": "gitlab", "repo": path}, **({} if host == "gitlab.com" else {"host": host}))
    return {}


def is_server() -> bool:
    if core.IS_MAC or os.path.isdir("/mnt/c/Windows"):
        return False
    rc, out, _ = core.run(["systemctl", "get-default"], 3)
    return rc == 0 and out.strip() != "graphical.target"


def profile(name: str) -> tuple:
    """(host profile, global additions, notes for the user)."""
    notes = []
    tags = ["#mac" if core.IS_MAC else "#linux"]
    if os.path.isdir("/mnt/c/Windows"):
        tags.append("#wsl")
    server = is_server()
    tags.append("#server" if server else "#dev")
    prof = {"label": name, "banner": "default", "tags": tags}
    panels = ["system", "services", "agents", "fleet"]
    if core.IS_MAC:
        prof["agents"] = agents()
    else:
        prof["units"] = units()
    prof["mounts"] = mounts()
    extra = {}
    if core.which("docker", ("/Applications/Docker.app/Contents/Resources/bin",)):
        panels.append("docker")
    rp = [] if server else repos()
    if rp:
        prof["repos"] = rp
        panels.append("repo")
        f = forge(rp)
        if f:
            extra["mrs"] = f
            panels.append("mrs")
            notes.append("mrs: watching %s %s (change \"mrs\".repo to taste)" % (f["provider"], f["repo"]))
    clouds = [c for c, probe in (("aws", os.path.isdir(os.path.join(core.HOME, ".aws"))), ("gcp", bool(core.which("gcloud"))),
                                  ("azure", bool(core.which("az")))) if probe]
    if clouds:
        panels.append("access")
        for c in clouds:
            extra.setdefault(c, {})
        notes.append("access: checking %s credentials" % ", ".join(clouds))
    prof["panels"] = panels
    ts = core.which("tailscale")
    if ts:
        rc, out, _ = core.run([ts, "status", "--json"], 5)
        try:
            peers = sorted(((p.get("HostName") or "").lower() for p in (json.loads(out).get("Peer") or {}).values() if p.get("Online")))
        except ValueError:
            peers = []
        if peers:
            notes.append("tailnet peers online: %s. To make this the hub, add \"#hub\" to tags and the peers "
                         "(ssh aliases, each running fleet-motd) to \"peers\"" % ", ".join(peers[:8]))
    notes.append("weather: add {\"place\", \"lat\", \"lon\", \"tz\"} under \"weather\" and \"weather\": true here")
    return prof, extra, notes


def dump(obj, ind: int = 0) -> str:
    """JSON with nested objects indented and short scalar lists ([unit, label, scope]) on one line."""
    pad, inner = "  " * ind, "  " * (ind + 1)
    if isinstance(obj, dict):
        if not obj:
            return "{}"
        return "{\n" + ",\n".join(inner + json.dumps(k) + ": " + dump(v, ind + 1) for k, v in obj.items()) + "\n" + pad + "}"
    if isinstance(obj, list):
        flat = json.dumps(obj, ensure_ascii=False)
        if all(not isinstance(v, (dict, list)) for v in obj) and len(flat) <= 100:
            return flat
        return "[\n" + ",\n".join(inner + dump(v, ind + 1) for v in obj) + "\n" + pad + "]"
    return json.dumps(obj, ensure_ascii=False)


def run(argv) -> int:
    import sys
    write, force = "--write" in argv, "--force" in argv
    name = core.machine_id()
    cfg_path = os.path.join(core.CONFIG_DIR, "config.json")
    cfg = core.config()
    hosts_cfg = cfg.setdefault("hosts", {})
    if name in hosts_cfg and not force:
        print("motd init: %s already has a profile in %s (--force replaces it)" % (name, cfg_path), file=sys.stderr)
        return 1
    prof, extra, notes = profile(name)
    hosts_cfg[name] = prof
    for k, v in extra.items():
        cfg.setdefault(k, v)
    text = dump(cfg) + "\n"
    if write:
        os.makedirs(core.CONFIG_DIR, exist_ok=True)
        if os.path.exists(cfg_path):
            shutil.copy2(cfg_path, cfg_path + ".bak")
        tmp = cfg_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, cfg_path)
        print("wrote %s (profile for %s)" % (cfg_path, name), file=sys.stderr)
    else:
        sys.stdout.write(text)
        print("(dry run: `motd init --write` saves this to %s)" % cfg_path, file=sys.stderr)
    for n in notes:
        print("· " + n, file=sys.stderr)
    return 0

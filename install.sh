#!/usr/bin/env bash
# Install the collector timer for this user and seed ~/.config/motd.
#   ./install.sh              install (systemd user timer on Linux, LaunchAgent on macOS)
#   ./install.sh --uninstall  remove the timer; leaves config and cache alone
set -euo pipefail

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
motd_py="$here/motd.py"
cfg="${MOTD_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/motd}"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
agent="$HOME/Library/LaunchAgents/com.motd-collect.plist"

# MOTD_CONFIG_DIR / MOTD_MACHINE chosen at install time must reach the timer's collector too.
render() {
  MOTD_PY="$motd_py" python3 - "$1" <<'PY'
import os, sys
from xml.sax.saxutils import escape
pairs = [(k, os.environ[k]) for k in ("MOTD_CONFIG_DIR", "MOTD_MACHINE", "MOTD_CACHE_DIR") if os.environ.get(k)]
text = open(sys.argv[1]).read()
sysd = "".join("Environment=%s=%s\n" % (k, v) for k, v in pairs)
plist = "".join("        <key>%s</key>\n        <string>%s</string>\n" % (k, escape(v)) for k, v in pairs)
sys.stdout.write(text.replace("__MOTD_PY__", os.environ["MOTD_PY"]).replace("__HOME__", os.path.expanduser("~"))
                 .replace("__ENV_SYSTEMD__\n", sysd).replace("__ENV_PLIST__\n", plist))
PY
}

if [[ "${1:-}" == "--uninstall" ]]; then
  if [[ "$(uname)" == "Darwin" ]]; then
    launchctl bootout "gui/$(id -u)/com.motd-collect" 2>/dev/null || true
    rm -f "$agent"
  else
    systemctl --user disable --now motd-collect.timer 2>/dev/null || true
    rm -f "$unit_dir/motd-collect.service" "$unit_dir/motd-collect.timer"
    systemctl --user daemon-reload 2>/dev/null || true
  fi
  echo "timer removed (config in $cfg and the cache are untouched)"
  exit 0
fi


mkdir -p "$cfg"
[[ -e "$cfg/config.json" ]] || cp "$here/config.example.json" "$cfg/config.json"
if [[ ! -e "$cfg/env" ]]; then cp "$here/env.example" "$cfg/env"; fi
chmod 600 "$cfg/env"

if [[ "$(uname)" == "Darwin" ]]; then
  mkdir -p "$HOME/Library/LaunchAgents" "$HOME/.local/state/logs"
  render "$here/deploy/com.motd-collect.plist" > "$agent"
  launchctl bootout "gui/$(id -u)/com.motd-collect" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$agent"
else
  mkdir -p "$unit_dir"
  render "$here/deploy/motd-collect.service" > "$unit_dir/motd-collect.service"
  cp "$here/deploy/motd-collect.timer" "$unit_dir/motd-collect.timer"
  systemctl --user daemon-reload
  systemctl --user enable --now motd-collect.timer
fi

cat <<MSG
Installed. Next:
  1. Edit $cfg/config.json (your hostname is "$(hostname -s | tr '[:upper:]' '[:lower:]')"; or set MOTD_MACHINE).
  2. Show it at login: add to ~/.zshrc or ~/.bashrc
       [[ -o login || -n "\$SSH_CONNECTION" ]] && python3 "$motd_py" --login   # zsh
     and a shortcut:  alias motd='python3 "$motd_py"'
  3. python3 "$motd_py" collect --force --quiet; python3 "$motd_py" doctor
MSG

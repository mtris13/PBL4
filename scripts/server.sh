#!/usr/bin/env bash
# Run as the ordinary Linux desktop user, never with sudo.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Linux ]]; then
  echo "Server script requires Linux. Use run-client.cmd on Windows." >&2
  exit 1
fi
if [[ "$EUID" == 0 ]]; then
  echo "Run without sudo; these are your user's services." >&2
  exit 1
fi
action="${1:-help}"
units=(pbl4-shop.service pbl4-nginx.service pbl4-security.service pbl4-logrotate.timer)
case "$action" in
  setup)
    address="${2:-}"
    if [[ -z "$address" ]]; then
      echo "Usage: bash scripts/server.sh setup YOUR_SERVER_LAN_IP"
      echo "Find it with: ip -br -4 address"
      exit 2
    fi
    for program in python3 nginx systemctl; do
      command -v "$program" >/dev/null || { echo "Missing $program. Read docs/DEMO.md."; exit 2; }
    done
    python3 -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12+ required"'
    # Validate before creating or replacing generated configuration.
    python3 -c 'import sys; from deploy.arch.render import build_files; from pathlib import Path; build_files(Path.cwd().as_posix(), lan_address=sys.argv[1])' "$address"
    if [[ ! -x .venv/bin/python ]]; then
      python3 -m venv .venv
    fi
    .venv/bin/python -m pip install -r requirements-lock.txt
    .venv/bin/python -m pip check
    .venv/bin/python -m deploy.arch.render --lan-address "$address"
    nginx -t -p "$PWD/runtime/arch/" -c "$PWD/runtime/arch/nginx.conf"
    mkdir -p "$HOME/.config/systemd/user"
    for file in runtime/arch/pbl4-*.service runtime/arch/pbl4-*.timer; do
      install -m 644 "$file" "$HOME/.config/systemd/user/"
    done
    systemctl --user daemon-reload
    systemctl --user enable "${units[@]}"
    systemctl --user restart "${units[@]}"
    .venv/bin/python scripts/server_health.py
    echo
    echo "SERVER READY. Client URL: http://$address:8080"
    echo "Next: configure the exact client firewall rule in docs/DEMO.md."
    echo "Keep this Linux user logged in and disable sleep during the demo."
    ;;
  start)
    systemctl --user restart "${units[@]}"
    .venv/bin/python scripts/server_health.py
    ;;
  status)
    systemctl --user --no-pager status "${units[@]}" || true
    .venv/bin/python scripts/server_health.py
    ;;
  logs)
    journalctl --user -u pbl4-shop -u pbl4-nginx -u pbl4-security -n 60 --no-pager
    ;;
  stop)
    systemctl --user stop pbl4-logrotate.timer pbl4-logrotate.service pbl4-security.service pbl4-nginx.service pbl4-shop.service
    echo "Stopped demo services. Database and logs are preserved."
    ;;
  *)
    echo "Usage: bash scripts/server.sh {setup SERVER_IP|start|status|logs|stop}"
    ;;
esac

#!/usr/bin/env bash
# HODLXXI Admin Helper
# Usage:
#   ./hodlxxi-admin.sh <command>
#
# Commands:
#   status      - show systemd service status
#   start       - start hodlxxi.service
#   stop        - stop hodlxxi.service
#   restart     - restart hodlxxi.service
#   logs        - follow logs
#   health      - check OAuth2/OIDC status + discovery
#   oauth-demo  - run the "HODLXXI OAuth2 Live Demo.sh" helper
#   help        - show this help

set -euo pipefail

SERVICE_NAME="hodlxxi.service"
APP_DIR="/srv/ubid"
BASE_URL="${BASE_URL:-https://hodlxxi.com}"

if [[ $# -lt 1 ]]; then
  set +u
  cmd="help"
else
  cmd="$1"
fi

ensure_root_or_sudo() {
  # If not root, prepend sudo to system commands
  if [[ "$EUID" -ne 0 ]]; then
    SUDO="sudo"
  else
    SUDO=""
  fi
}

show_help() {
  cat <<'HLP'
HODLXXI Admin Helper

Usage:
  ./hodlxxi-admin.sh <command>

Commands:
  status      - show systemd service status
  start       - start hodlxxi.service
  stop        - stop hodlxxi.service
  restart     - restart hodlxxi.service
  logs        - follow service logs (Ctrl+C to exit)
  health      - check OAuth2/OIDC status + discovery
  oauth-demo  - run "HODLXXI OAuth2 Live Demo.sh" from /srv/ubid
  help        - show this help
HLP
}

case "$cmd" in
  status)
    ensure_root_or_sudo
    $SUDO systemctl status "$SERVICE_NAME"
    ;;

  start)
    ensure_root_or_sudo
    $SUDO systemctl start "$SERVICE_NAME"
    echo "✅ Started $SERVICE_NAME"
    ;;

  stop)
    ensure_root_or_sudo
    $SUDO systemctl stop "$SERVICE_NAME"
    echo "🛑 Stopped $SERVICE_NAME"
    ;;

  restart)
    ensure_root_or_sudo
    echo "🔄 Restarting $SERVICE_NAME..."
    $SUDO systemctl restart "$SERVICE_NAME"
    $SUDO systemctl status "$SERVICE_NAME" --no-pager -n 5
    ;;

  logs)
    ensure_root_or_sudo
    echo "📜 Tailing logs for $SERVICE_NAME (Ctrl+C to exit)..."
    $SUDO journalctl -u "$SERVICE_NAME" -n 50 -f
    ;;

  health)
    echo "🌐 Checking health for $BASE_URL"
    echo
    echo "== /oauthx/status =="
    curl -sS "$BASE_URL/oauthx/status" | jq . || curl -sS "$BASE_URL/oauthx/status"
    echo
    echo "== /.well-known/openid-configuration =="
    curl -sS "$BASE_URL/.well-known/openid-configuration" | jq . || curl -sS "$BASE_URL/.well-known/openid-configuration"
    ;;

  oauth-demo)
    cd "$APP_DIR"
    if [[ -f "HODLXXI OAuth2 Live Demo.sh" ]]; then
      echo "🚀 Running HODLXXI OAuth2 Live Demo..."
      bash "HODLXXI OAuth2 Live Demo.sh"
    else
      echo "❌ HODLXXI OAuth2 Live Demo.sh not found in $APP_DIR"
      exit 1
    fi
    ;;

  help|--help|-h)
    show_help
    ;;

  *)
    echo "Unknown command: $cmd"
    echo
    show_help
    exit 1
    ;;
esac

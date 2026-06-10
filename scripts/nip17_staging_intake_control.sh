#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-status}"
SERVICE="${NIP17_STAGING_SERVICE:-ubid-staging}"
BASE="${NIP17_STAGING_BASE:-http://127.0.0.1:5055}"
DROPIN_DIR="/etc/systemd/system/${SERVICE}.service.d"
DROPIN_FILE="${DROPIN_DIR}/60-nip17-staging-intake.conf"

if [ "$SERVICE" != "ubid-staging" ]; then
  echo "ERROR: refusing to manage non-staging service: $SERVICE" >&2
  exit 2
fi

show_status() {
  echo "== service =="
  systemctl is-active "$SERVICE" || true
  systemctl show "$SERVICE" -p MainPID -p Environment --no-pager || true

  PID="$(systemctl show "$SERVICE" -p MainPID --value || true)"
  if [ -n "${PID:-}" ] && [ "$PID" != "0" ] && [ -r "/proc/$PID/environ" ]; then
    echo
    echo "== process env =="
    tr '\0' '\n' < "/proc/$PID/environ" | grep '^NIP17_MESSAGES_ENABLED=' || true
  fi

  echo
  echo "== local NIP17 policy =="
  curl -sS -H "X-Forwarded-Proto: https" \
    "${BASE}/.well-known/nostr-dm-policy.json" \
    | python -m json.tool \
    | grep -E '"enabled"|"intake_enabled"|"relay_publishing"'
}

case "$ACTION" in
  enable)
    echo "== enable staging-only NIP17 intake =="
    mkdir -p "$DROPIN_DIR"
    printf '%s\n' '[Service]' 'Environment=NIP17_MESSAGES_ENABLED=1' > "$DROPIN_FILE"
    systemctl daemon-reload
    systemctl restart "$SERVICE"
    sleep 3
    show_status
    ;;

  disable)
    echo "== disable staging-only NIP17 intake =="
    rm -f "$DROPIN_FILE"
    systemctl daemon-reload
    systemctl restart "$SERVICE"
    sleep 3
    show_status
    ;;

  status)
    show_status
    ;;

  *)
    echo "Usage: $0 {enable|disable|status}" >&2
    exit 2
    ;;
esac

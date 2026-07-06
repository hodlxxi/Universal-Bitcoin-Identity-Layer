#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-${1:-http://127.0.0.1:5000}}"
TMP_DIR="$(mktemp -d)"
COOKIE_JAR="$TMP_DIR/cookies.txt"
trap 'rm -rf "$TMP_DIR"' EXIT

fail(){ echo "FAIL: $*" >&2; exit 1; }
pass(){ echo "PASS: $*"; }

fetch_body_status(){
  local url="$1" out="$2"
  curl -ksS -o "$out" -w '%{http_code}' "$url"
}

status=$(fetch_body_status "$BASE_URL/turn_credentials" "$TMP_DIR/turn.json")
[[ "$status" == "200" ]] || fail "/turn_credentials expected HTTP 200, got $status"
python - "$TMP_DIR/turn.json" <<'PY' || fail "/turn_credentials missing JSON iceServers"
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    data = json.load(f)
assert isinstance(data.get('iceServers'), list) and data['iceServers']
PY
pass "/turn_credentials returns HTTP 200 with iceServers"

status=$(fetch_body_status "$BASE_URL/api/debug/session" "$TMP_DIR/session.json")
[[ "$status" == "200" ]] || fail "/api/debug/session expected HTTP 200, got $status"
python - "$TMP_DIR/session.json" <<'PY' || fail "/api/debug/session did not return JSON object"
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    data = json.load(f)
assert isinstance(data, dict) and data.get('ok') is True
PY
pass "/api/debug/session returns HTTP 200 JSON"

curl -ksS -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d '{"pin":""}' \
  "$BASE_URL/guest_login" > "$TMP_DIR/guest.json"
python - "$TMP_DIR/guest.json" <<'PY' || fail "/guest_login did not return ok JSON"
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    data = json.load(f)
assert data.get('ok') is True
PY
pass "guest login succeeded"

status=$(curl -ksS -b "$COOKIE_JAR" -c "$COOKIE_JAR" -o "$TMP_DIR/app.html" -w '%{http_code}' "$BASE_URL/app")
[[ "$status" == "200" ]] || fail "/app expected HTTP 200 after guest login, got $status"
pass "/app returns HTTP 200 after guest login"

status=$(curl -ksS -b "$COOKIE_JAR" -c "$COOKIE_JAR" -o "$TMP_DIR/socketio.txt" -w '%{http_code}' \
  "$BASE_URL/socket.io/?EIO=4&transport=polling")
[[ "$status" == "200" ]] || fail "Socket.IO polling expected HTTP 200, got $status"
pass "Socket.IO polling endpoint returns HTTP 200"

for marker in getIceServers RTCPeerConnection 'rtc:signal' remoteDescription flushPendingIce; do
  grep -q "$marker" "$TMP_DIR/app.html" || fail "/app HTML missing $marker"
  pass "/app HTML contains $marker"
done

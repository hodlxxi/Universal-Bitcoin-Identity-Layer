#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://hodlxxi.com}"
REDIRECT_URI="${REDIRECT_URI:-https://example.com/callback}"
CLIENT_NAME="${CLIENT_NAME:-OAuth Demo Client}"
SCOPE="${SCOPE:-read_limited}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd curl
require_cmd python

json_get() {
  python - <<PY
import json,sys
print(json.load(sys.stdin).get("$1",""))
PY
}

register_payload=$(python - <<PY
import json
print(json.dumps({"client_name": "$CLIENT_NAME", "redirect_uris": ["$REDIRECT_URI"]}))
PY
)

register_resp=$(curl -sS -X POST "$BASE_URL/oauth/register" \
  -H "Content-Type: application/json" \
  -d "$register_payload")

echo "Register response: $register_resp"

CLIENT_ID=$(printf '%s' "$register_resp" | json_get client_id)
CLIENT_SECRET=$(printf '%s' "$register_resp" | json_get client_secret)

if [[ -z "$CLIENT_ID" || -z "$CLIENT_SECRET" ]]; then
  echo "Failed to register client." >&2
  exit 1
fi

CODE_VERIFIER=$(python - <<PY
import secrets
print(secrets.token_urlsafe(48))
PY
)

CODE_CHALLENGE=$(python - <<PY
import hashlib,base64,sys
verifier = sys.argv[1].encode("utf-8")
digest = hashlib.sha256(verifier).digest()
print(base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="))
PY
"$CODE_VERIFIER")

NONCE=$(python - <<PY
import secrets
print(secrets.token_urlsafe(16))
PY
)

AUTH_URL="$BASE_URL/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=$SCOPE&state=demo-state&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&nonce=$NONCE"

echo "\nOpen this URL in a browser after logging in:"
echo "$AUTH_URL"

echo "\nPaste the full redirect URL here:"
read -r REDIRECTED

AUTH_CODE=$(python - <<PY
import sys
from urllib.parse import urlparse, parse_qs
u = urlparse(sys.argv[1])
print(parse_qs(u.query).get("code", [""])[0])
PY
"$REDIRECTED")

if [[ -z "$AUTH_CODE" ]]; then
  echo "No authorization code found." >&2
  exit 1
fi

token_resp=$(curl -sS -X POST "$BASE_URL/oauth/token" \
  -d grant_type=authorization_code \
  -d client_id="$CLIENT_ID" \
  -d client_secret="$CLIENT_SECRET" \
  -d code="$AUTH_CODE" \
  -d code_verifier="$CODE_VERIFIER")

echo "\nToken response: $token_resp"

ACCESS_TOKEN=$(printf '%s' "$token_resp" | json_get access_token)
REFRESH_TOKEN=$(printf '%s' "$token_resp" | json_get refresh_token)

if [[ -z "$ACCESS_TOKEN" || -z "$REFRESH_TOKEN" ]]; then
  echo "Missing access/refresh token in response." >&2
  exit 1
fi

introspect_resp=$(curl -sS -X POST "$BASE_URL/oauth/introspect" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d token="$ACCESS_TOKEN")

echo "\nIntrospection response: $introspect_resp"

protected_resp=$(curl -sS -X GET "$BASE_URL/api/demo/protected" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "\nProtected response: $protected_resp"

refresh_resp=$(curl -sS -X POST "$BASE_URL/oauth/token" \
  -d grant_type=refresh_token \
  -d client_id="$CLIENT_ID" \
  -d client_secret="$CLIENT_SECRET" \
  -d refresh_token="$REFRESH_TOKEN")

echo "\nRefresh response: $refresh_resp"

NEW_ACCESS_TOKEN=$(printf '%s' "$refresh_resp" | json_get access_token)

if [[ -z "$NEW_ACCESS_TOKEN" ]]; then
  echo "Missing new access token." >&2
  exit 1
fi

protected_resp2=$(curl -sS -X GET "$BASE_URL/api/demo/protected" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN")

echo "\nProtected response (refreshed token): $protected_resp2"

cat <<PSQL

PSQL queries to verify stored rows:
  SELECT client_id, user_id, code, is_used, expires_at FROM oauth_codes WHERE client_id = '$CLIENT_ID' ORDER BY created_at DESC LIMIT 5;
  SELECT client_id, user_id, access_token, refresh_token, is_revoked, access_token_expires_at FROM oauth_tokens WHERE client_id = '$CLIENT_ID' ORDER BY created_at DESC LIMIT 5;
PSQL

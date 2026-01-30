#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://hodlxxi.com}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:8080/callback}"
SCOPE="${SCOPE:-read_limited}"

echo "== Register client =="
client_json=$(curl -sS -X POST "${BASE_URL}/oauth/register" \
  -H "Content-Type: application/json" \
  -d "{\"redirect_uris\":[\"${REDIRECT_URI}\"]}")
client_id=$(python - <<'PY'
import json,sys
data=json.load(sys.stdin)
print(data["client_id"])
PY
<<<"${client_json}")
client_secret=$(python - <<'PY'
import json,sys
data=json.load(sys.stdin)
print(data["client_secret"])
PY
<<<"${client_json}")

echo "client_id=${client_id}"
echo "client_secret=${client_secret}"

echo "== Build PKCE =="
code_verifier=$(python - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)
code_challenge=$(python - <<'PY'
import base64,hashlib,sys
verifier=sys.argv[1]
digest=hashlib.sha256(verifier.encode()).digest()
print(base64.urlsafe_b64encode(digest).decode().rstrip("="))
PY
"${code_verifier}")
state=$(python - <<'PY'
import secrets
print(secrets.token_hex(8))
PY
)

auth_url="${BASE_URL}/oauth/authorize?response_type=code&client_id=${client_id}&redirect_uri=${REDIRECT_URI}&scope=${SCOPE}&state=${state}&code_challenge=${code_challenge}&code_challenge_method=S256"
echo "Open this URL in a browser (log in if needed) and paste the redirect URL:"
echo "${auth_url}"
read -r redirect_url

code=$(python - <<'PY'
import sys,urllib.parse as up
url=sys.argv[1]
parsed=up.urlparse(url)
qs=up.parse_qs(parsed.query)
print(qs["code"][0])
PY
"${redirect_url}")

echo "== Exchange code for tokens =="
token_json=$(curl -sS -X POST "${BASE_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=${code}&redirect_uri=${REDIRECT_URI}&client_id=${client_id}&client_secret=${client_secret}&code_verifier=${code_verifier}")
access_token=$(python - <<'PY'
import json,sys
data=json.load(sys.stdin)
print(data["access_token"])
PY
<<<"${token_json}")
refresh_token=$(python - <<'PY'
import json,sys
data=json.load(sys.stdin)
print(data["refresh_token"])
PY
<<<"${token_json}")

echo "access_token=${access_token}"
echo "refresh_token=${refresh_token}"

echo "== Introspect access token =="
curl -sS -X POST "${BASE_URL}/oauth/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "${client_id}:${client_secret}" \
  -d "token=${access_token}" | python -m json.tool

echo "== Call protected API =="
curl -sS -H "Authorization: Bearer ${access_token}" "${BASE_URL}/api/demo/protected" | python -m json.tool

echo "== Refresh token =="
refresh_json=$(curl -sS -X POST "${BASE_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=${refresh_token}&client_id=${client_id}&client_secret=${client_secret}")
new_access_token=$(python - <<'PY'
import json,sys
data=json.load(sys.stdin)
print(data["access_token"])
PY
<<<"${refresh_json}")

echo "new_access_token=${new_access_token}"

echo "== Call protected API with refreshed token =="
curl -sS -H "Authorization: Bearer ${new_access_token}" "${BASE_URL}/api/demo/protected" | python -m json.tool

echo "== Postgres validation queries =="
cat <<EOF
-- Run in psql:
select code, client_id, user_id, scope, is_used, expires_at from oauth_codes where client_id = '${client_id}' order by created_at desc limit 5;
select id, client_id, user_id, scope, is_revoked, access_token_expires_at, refresh_token_expires_at from oauth_tokens where client_id = '${client_id}' order by created_at desc limit 5;
EOF

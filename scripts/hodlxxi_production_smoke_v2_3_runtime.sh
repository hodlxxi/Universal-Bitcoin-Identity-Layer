#!/usr/bin/env bash
# HODLXXI production smoke test v2.3-runtime
#
# Purpose:
# - prove red-team remediation/runtime patches after PR #165-#174
# - keep v2.2 as the broad production smoke
# - add docs/OIDC/API-auth/debug-session/decode/route-ownership evidence
#
# Usage:
#   BASE_URL=https://hodlxxi.com REPO_DIR=/srv/ubid EXPECT_ROUTE_COUNT=94 \
#     ./scripts/hodlxxi_production_smoke_v2_3_runtime.sh
#
# Optional env:
#   BASE_URL=https://hodlxxi.com
#   REPO_DIR=/srv/ubid
#   EXPECT_ROUTE_COUNT=94
#   STRICT_ROUTE_COUNT=0

set -uo pipefail

BASE_URL="${BASE_URL:-https://hodlxxi.com}"
REPO_DIR="${REPO_DIR:-}"
EXPECT_ROUTE_COUNT="${EXPECT_ROUTE_COUNT:-94}"
STRICT_ROUTE_COUNT="${STRICT_ROUTE_COUNT:-0}"
COOKIE_JAR="${COOKIE_JAR:-/tmp/hodlxxi_v23_runtime.cookies}"
TMP_DIR="${TMP_DIR:-/tmp/hodlxxi_v23_runtime}"

mkdir -p "$TMP_DIR"
rm -f "$COOKIE_JAR"

PASS=0
WARN=0
FAIL=0
PASS_ITEMS=()
WARN_ITEMS=()
FAIL_ITEMS=()

green="$(printf '\033[32m')"
yellow="$(printf '\033[33m')"
red="$(printf '\033[31m')"
blue="$(printf '\033[34m')"
reset="$(printf '\033[0m')"

pass(){ echo -e "${green}PASS${reset} $*"; PASS=$((PASS+1)); PASS_ITEMS+=("$*"); }
warn(){ echo -e "${yellow}WARN${reset} $*"; WARN=$((WARN+1)); WARN_ITEMS+=("$*"); }
fail(){ echo -e "${red}FAIL${reset} $*"; FAIL=$((FAIL+1)); FAIL_ITEMS+=("$*"); }
info(){ echo -e "${blue}INFO${reset} $*"; }

section(){
  echo
  echo "============================================================"
  echo "$*"
  echo "============================================================"
}

need_cmd(){
  if command -v "$1" >/dev/null 2>&1; then
    pass "dependency present: $1"
  else
    fail "missing dependency: $1"
  fi
}

status(){
  curl -ksS -o /dev/null -w "%{http_code}" "$1" 2>/dev/null || echo "000"
}

headers(){
  curl -ksS -D - -o /dev/null "$1" 2>/dev/null || true
}

body_to_file(){
  local url="$1"
  local out="$2"
  if curl -ksS "$url" > "$out" 2>/dev/null; then
    pass "$url fetched into $(basename "$out")"
  else
    fail "$url could not be fetched"
  fi
}

assert_status(){
  local url="$1"
  local expected="$2"
  local got
  got="$(status "$url")"
  if [[ "$got" == "$expected" ]]; then
    pass "$url -> HTTP $got"
  else
    fail "$url -> expected HTTP $expected, got $got"
  fi
}

assert_status_in(){
  local url="$1"
  shift
  local got
  got="$(status "$url")"
  local code
  for code in "$@"; do
    if [[ "$got" == "$code" ]]; then
      pass "$url -> HTTP $got"
      return 0
    fi
  done
  fail "$url -> expected one of [$*], got $got"
}

json_assert(){
  local file="$1"
  local expr="$2"
  if jq -e "$expr" "$file" >/dev/null 2>&1; then
    pass "$(basename "$file") satisfies jq: $expr"
  else
    fail "$(basename "$file") does not satisfy jq: $expr"
    jq . "$file" 2>/dev/null | sed 's/^/  /' || sed 's/^/  /' "$file" || true
  fi
}

post_json_file(){
  local url="$1"
  local payload="$2"
  local out="$3"
  curl -ksS -H "Content-Type: application/json" -X POST --data "$payload" "$url" > "$out" 2>/dev/null
}

post_json_status(){
  local url="$1"
  local payload="$2"
  curl -ksS -H "Content-Type: application/json" -X POST --data "$payload" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000"
}

post_json_cookie_file(){
  local url="$1"
  local payload="$2"
  local out="$3"
  curl -ksS -b "$COOKIE_JAR" -c "$COOKIE_JAR" -H "Content-Type: application/json" -X POST --data "$payload" "$url" > "$out" 2>/dev/null
}

post_json_cookie_status(){
  local url="$1"
  local payload="$2"
  curl -ksS -b "$COOKIE_JAR" -c "$COOKIE_JAR" -H "Content-Type: application/json" -X POST --data "$payload" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000"
}

print_summary(){
  echo
  echo "============================================================"
  echo "FINAL SUMMARY — v2.3 runtime remediation smoke"
  echo "============================================================"
  echo "BASE_URL=$BASE_URL"
  echo "REPO_DIR=${REPO_DIR:-not-set}"
  echo "PASS=$PASS"
  echo "WARN=$WARN"
  echo "FAIL=$FAIL"

  if (( WARN > 0 )); then
    echo
    echo "Warnings:"
    for item in "${WARN_ITEMS[@]}"; do echo "  - $item"; done
  fi

  if (( FAIL > 0 )); then
    echo
    echo "Failures:"
    for item in "${FAIL_ITEMS[@]}"; do echo "  - $item"; done
  fi
}

section "0) Dependencies"
need_cmd curl
need_cmd jq
need_cmd python3

section "1) Restored public docs/OIDC runtime surfaces"
assert_status "$BASE_URL/docs" 200
assert_status "$BASE_URL/docs/" 200
assert_status "$BASE_URL/docs/principles" 200
assert_status "$BASE_URL/oidc" 200
assert_status "$BASE_URL/oauthx/docs" 200
assert_status "$BASE_URL/.well-known/openid-configuration" 200

oidc_file="$TMP_DIR/openid_configuration.json"
body_to_file "$BASE_URL/.well-known/openid-configuration" "$oidc_file"
json_assert "$oidc_file" '. | type == "object"'
json_assert "$oidc_file" '(.issuer // .authorization_endpoint // .token_endpoint) | type == "string"'

section "2) Safe debug session endpoint"
debug_anon="$TMP_DIR/debug_session_anon.json"
body_to_file "$BASE_URL/api/debug/session" "$debug_anon"
json_assert "$debug_anon" '. | type == "object"'

if grep -Eiq 'macaroon|RPC_PASSWORD|SECRET_KEY|session=|private_key|privkey' "$debug_anon"; then
  fail "/api/debug/session appears to expose sensitive material"
else
  pass "/api/debug/session does not expose obvious secrets"
fi

section "3) API auth blueprint behavior"
sample_pubkey="021111111111111111111111111111111111111111111111111111111111111111"
challenge_file="$TMP_DIR/api_challenge.json"

post_json_file "$BASE_URL/api/challenge" "{\"pubkey\":\"$sample_pubkey\"}" "$challenge_file"
json_assert "$challenge_file" '.ok == true'
json_assert "$challenge_file" '(.challenge_id // .challenge // .k1) | type == "string"'

verify_missing_status="$(post_json_status "$BASE_URL/api/verify" "{\"pubkey\":\"$sample_pubkey\"}")"
if [[ "$verify_missing_status" == "400" ]]; then
  pass "/api/verify missing signature -> HTTP 400"
else
  fail "/api/verify missing signature expected HTTP 400, got $verify_missing_status"
fi

psbt_bad_status="$(post_json_status "$BASE_URL/api/verify" '{"psbt":"not-a-valid-psbt"}')"
if [[ "$psbt_bad_status" == "400" ]]; then
  pass "/api/verify invalid PSBT compatibility path -> HTTP 400"
else
  fail "/api/verify invalid PSBT expected HTTP 400, got $psbt_bad_status"
fi

section "4) Guest session + decode compatibility"
guest_file="$TMP_DIR/guest_login.json"
post_json_cookie_file "$BASE_URL/guest_login" '{"pin":""}' "$guest_file"
json_assert "$guest_file" '.ok == true'

debug_guest="$TMP_DIR/debug_session_guest.json"
curl -ksS -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$BASE_URL/api/debug/session" > "$debug_guest" 2>/dev/null || true
json_assert "$debug_guest" '. | type == "object"'

decode_script_status="$(post_json_cookie_status "$BASE_URL/api/decode_raw_script" '{"script":"51"}')"
if [[ "$decode_script_status" == "200" ]]; then
  pass "/api/decode_raw_script accepts modern field script -> HTTP 200"
else
  fail "/api/decode_raw_script script field expected HTTP 200, got $decode_script_status"
fi

decode_raw_status="$(post_json_cookie_status "$BASE_URL/api/decode_raw_script" '{"raw_script":"51"}')"
if [[ "$decode_raw_status" == "200" ]]; then
  pass "/api/decode_raw_script accepts legacy field raw_script -> HTTP 200"
else
  fail "/api/decode_raw_script raw_script field expected HTTP 200, got $decode_raw_status"
fi

decode_file="$TMP_DIR/decode_raw_script.json"
post_json_cookie_file "$BASE_URL/api/decode_raw_script" '{"raw_script":"51"}' "$decode_file"
json_assert "$decode_file" '. | type == "object"'
json_assert "$decode_file" '(.asm? // .type? // .p2sh? // .segwit? // .address? // .script_hex? // .raw_script?) != null'

section "5) Agent/public runtime surfaces still healthy"
assert_status "$BASE_URL/.well-known/agent.json" 200
assert_status "$BASE_URL/agent/capabilities" 200
assert_status "$BASE_URL/agent/capabilities/schema" 200
assert_status "$BASE_URL/agent/reputation" 200
assert_status "$BASE_URL/agent/attestations" 200
assert_status "$BASE_URL/agent/chain/health" 200
assert_status "$BASE_URL/agent/skills" 200
assert_status "$BASE_URL/api/public/status" 200

cap_file="$TMP_DIR/capabilities.json"
body_to_file "$BASE_URL/agent/capabilities" "$cap_file"
json_assert "$cap_file" '.job_types | type == "object"'
json_assert "$cap_file" '(.job_types | length) >= 4'
json_assert "$cap_file" '.job_types.covenant_decode? != null'
json_assert "$cap_file" '.job_types.covenant_visualize? != null'
json_assert "$cap_file" '.job_types.ping? != null'
json_assert "$cap_file" '.job_types.verify_signature? != null'

section "6) Security header snapshot"
root_headers="$TMP_DIR/root.headers"
headers "$BASE_URL/" > "$root_headers"

for h in strict-transport-security content-security-policy x-content-type-options referrer-policy; do
  if grep -iq "^$h:" "$root_headers"; then
    pass "security header present: $h"
  else
    warn "security header missing or not visible at edge: $h"
  fi
done

section "7) Optional local runtime route ownership proof"
if [[ -n "$REPO_DIR" && -d "$REPO_DIR/.git" ]]; then
  (
    cd "$REPO_DIR" || exit 1

    echo "== git =="
    git branch --show-current
    git rev-parse HEAD
    git status --short

    echo
    echo "== route ownership =="
    python3 - <<'PY'
from wsgi import app

targets = [
    "/api/debug/session",
    "/api/challenge",
    "/api/verify",
    "/verify_signature",
    "/login",
    "/logout",
    "/home",
    "/app",
    "/docs",
    "/oidc",
    "/.well-known/agent.json",
    "/agent/capabilities",
    "/api/public/status",
]

rules = list(app.url_map.iter_rules())
print(f"ROUTE_COUNT={len(rules)}")
for path in targets:
    matches = [r for r in rules if r.rule == path]
    if matches:
        for r in matches:
            print(f"{path} -> {r.endpoint}")
    else:
        print(f"{path} -> MISSING")
PY
  ) > "$TMP_DIR/local_runtime_snapshot.txt" 2>&1

  cat "$TMP_DIR/local_runtime_snapshot.txt" | sed 's/^/  /'

  route_count="$(grep '^ROUTE_COUNT=' "$TMP_DIR/local_runtime_snapshot.txt" | head -n1 | cut -d= -f2 || true)"
  if [[ "$route_count" == "$EXPECT_ROUTE_COUNT" ]]; then
    pass "local runtime route count matches EXPECT_ROUTE_COUNT=$EXPECT_ROUTE_COUNT"
  else
    if [[ "$STRICT_ROUTE_COUNT" == "1" ]]; then
      fail "local runtime route count mismatch: expected $EXPECT_ROUTE_COUNT got ${route_count:-unknown}"
    else
      warn "local runtime route count mismatch: expected $EXPECT_ROUTE_COUNT got ${route_count:-unknown}"
    fi
  fi

  for expected in \
    "/api/debug/session -> debug_session.api_debug_session" \
    "/api/challenge -> api_auth.api_challenge" \
    "/api/verify -> api_auth.api_verify" \
    "/login -> auth.login" \
    "/logout -> auth.logout" \
    "/home -> ui.home" \
    "/app -> ui.legacy_chat_route"
  do
    if grep -Fq "$expected" "$TMP_DIR/local_runtime_snapshot.txt"; then
      pass "route ownership confirmed: $expected"
    else
      warn "route ownership not confirmed exactly: $expected"
    fi
  done
else
  warn "REPO_DIR not set or not a git repo; skipping local route ownership proof"
fi

print_summary

if (( FAIL > 0 )); then
  exit 1
fi
exit 0

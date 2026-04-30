#!/usr/bin/env bash
# HODLXXI production smoke test v2.2
#
# Production notes:
# - this does not pay invoices; it only checks unpaid request/receipt flows
# - it hits the live site, so use it for real public smoke checks
#
# Goals:
# - keep running after individual assertion failures
# - print a final PASS/WARN/FAIL summary every time
# - discover advertised job types from /agent/capabilities
# - auto-test each advertised job type with a best-effort smoke request
#
# Usage:
#   chmod +x ./scripts/hodlxxi_production_smoke_v2_2.sh
#   ./scripts/hodlxxi_production_smoke_v2_2.sh
#
# Optional env vars:
#   BASE_URL=https://hodlxxi.com
#   COOKIE_JAR=/tmp/hodlxxi_production_smoke.cookies
#   TMP_DIR=/tmp/hodlxxi_production_smoke
#   WAIT_SECONDS=15
#   EXPECT_SERVICE_NAME="HODLXXI Agent UBID"   # exact check if you want it
#   STRICT_SERVICE_NAME=0                       # set 1 to fail instead of warn
#   STRICT_REQUEST_ERRORS=0                    # set 1 to fail on structured job errors

set -uo pipefail

BASE_URL="${BASE_URL:-https://hodlxxi.com}"
COOKIE_JAR="${COOKIE_JAR:-/tmp/hodlxxi_production_smoke.cookies}"
TMP_DIR="${TMP_DIR:-/tmp/hodlxxi_production_smoke}"
WAIT_SECONDS="${WAIT_SECONDS:-15}"
EXPECT_SERVICE_NAME="${EXPECT_SERVICE_NAME:-}"
STRICT_SERVICE_NAME="${STRICT_SERVICE_NAME:-0}"
STRICT_REQUEST_ERRORS="${STRICT_REQUEST_ERRORS:-0}"

mkdir -p "$TMP_DIR"
rm -f "$COOKIE_JAR"

RED="$(printf '\033[31m')"
GRN="$(printf '\033[32m')"
YLW="$(printf '\033[33m')"
BLU="$(printf '\033[34m')"
RST="$(printf '\033[0m')"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

PASS_ITEMS=()
FAIL_ITEMS=()
WARN_ITEMS=()

pass() {
  local msg="$*"
  echo -e "${GRN}PASS${RST} ${msg}"
  PASS_COUNT=$((PASS_COUNT + 1))
  PASS_ITEMS+=("$msg")
}

fail() {
  local msg="$*"
  echo -e "${RED}FAIL${RST} ${msg}"
  FAIL_COUNT=$((FAIL_COUNT + 1))
  FAIL_ITEMS+=("$msg")
}

warn() {
  local msg="$*"
  echo -e "${YLW}WARN${RST} ${msg}"
  WARN_COUNT=$((WARN_COUNT + 1))
  WARN_ITEMS+=("$msg")
}

info() {
  echo -e "${BLU}INFO${RST} $*"
}

section() {
  echo
  echo "============================================================"
  echo "$*"
  echo "============================================================"
}

need_cmd() {
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    pass "dependency present: $cmd"
    return 0
  fi
  fail "missing required command: $cmd"
  return 1
}

cleanup() {
  :
}
trap cleanup EXIT

print_summary() {
  echo
  echo "============================================================"
  echo "FINAL SUMMARY"
  echo "============================================================"
  echo "BASE_URL=$BASE_URL"
  echo "PASS=$PASS_COUNT"
  echo "WARN=$WARN_COUNT"
  echo "FAIL=$FAIL_COUNT"

  if (( WARN_COUNT > 0 )); then
    echo
    echo "Warnings:"
    local item
    for item in "${WARN_ITEMS[@]}"; do
      echo "  - $item"
    done
  fi

  if (( FAIL_COUNT > 0 )); then
    echo
    echo "Failures:"
    local item
    for item in "${FAIL_ITEMS[@]}"; do
      echo "  - $item"
    done
  fi
}

http_headers() {
  local url="$1"
  curl -ksS -D - -o /dev/null "$url" 2>/dev/null || return 1
}

http_body() {
  local url="$1"
  curl -ksS "$url" 2>/dev/null || return 1
}

http_status() {
  local url="$1"
  curl -ksS -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || return 1
}

write_url_to_file() {
  local url="$1"
  local outfile="$2"
  if curl -ksS "$url" > "$outfile" 2>/dev/null; then
    pass "$url fetched into $(basename "$outfile")"
    return 0
  fi
  fail "$url could not be fetched"
  return 1
}

assert_http_status() {
  local url="$1"
  local expected="$2"
  local got
  got="$(http_status "$url")" || {
    fail "$url -> could not fetch HTTP status"
    return 0
  }

  if [[ "$got" == "$expected" ]]; then
    pass "$url -> HTTP $got"
  else
    fail "$url -> expected HTTP $expected, got $got"
  fi
}

assert_http_status_in() {
  local url="$1"
  shift
  local got
  got="$(http_status "$url")" || {
    fail "$url -> could not fetch HTTP status"
    return 0
  }

  local code
  for code in "$@"; do
    if [[ "$got" == "$code" ]]; then
      pass "$url -> HTTP $got"
      return 0
    fi
  done

  fail "$url -> expected one of [$*], got $got"
}

assert_location_contains() {
  local url="$1"
  local needle="$2"
  local headers
  headers="$(http_headers "$url")" || {
    fail "$url -> could not fetch headers"
    return 0
  }

  if grep -qi '^Location:' <<<"$headers" && grep -Fqi "$needle" <<<"$headers"; then
    pass "$url Location contains '$needle'"
  else
    fail "$url missing expected Location containing '$needle'"
    echo "$headers" | sed 's/^/  /'
  fi
}

assert_file_contains() {
  local file="$1"
  local needle="$2"
  local label="$3"
  if grep -Fqi "$needle" "$file" 2>/dev/null; then
    pass "$label contains '$needle'"
  else
    warn "$label missing '$needle'"
  fi
}

assert_json_field_from_url() {
  local url="$1"
  local jq_expr="$2"
  local body
  body="$(http_body "$url")" || {
    fail "$url -> could not fetch body for jq assertion: $jq_expr"
    return 0
  }

  if jq -e "$jq_expr" >/dev/null 2>&1 <<<"$body"; then
    pass "$url satisfies jq: $jq_expr"
  else
    fail "$url does not satisfy jq: $jq_expr"
    echo "$body" | sed 's/^/  /'
  fi
}

assert_json_field_from_file() {
  local file="$1"
  local jq_expr="$2"
  if jq -e "$jq_expr" "$file" >/dev/null 2>&1; then
    pass "$(basename "$file") satisfies jq: $jq_expr"
  else
    fail "$(basename "$file") does not satisfy jq: $jq_expr"
    jq . "$file" 2>/dev/null | sed 's/^/  /' || sed 's/^/  /' "$file" 2>/dev/null || true
  fi
}

wait_for_service() {
  local ok=0
  info "Waiting for $BASE_URL to become reachable..."

  local i
  for i in $(seq 1 "$WAIT_SECONDS"); do
    if curl -ksS -o /dev/null "$BASE_URL/login" 2>/dev/null; then
      ok=1
      break
    fi
    sleep 1
  done

  if (( ok == 1 )); then
    pass "$BASE_URL became reachable"
  else
    fail "$BASE_URL did not become reachable within ${WAIT_SECONDS}s"
  fi
}

json_get_file() {
  local file="$1"
  local expr="$2"
  jq -r "$expr" "$file" 2>/dev/null || true
}

post_json() {
  local url="$1"
  local payload="$2"
  curl -ksS -H "Content-Type: application/json" -X POST --data "$payload" "$url" 2>/dev/null || return 1
}

post_json_cookie() {
  local url="$1"
  local payload="$2"
  curl -ksS -b "$COOKIE_JAR" -c "$COOKIE_JAR" -H "Content-Type: application/json" -X POST --data "$payload" "$url" 2>/dev/null || return 1
}

get_cookie_to_file() {
  local url="$1"
  local outfile="$2"
  if curl -ksS -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$url" > "$outfile" 2>/dev/null; then
    pass "$url fetched with cookie into $(basename "$outfile")"
  else
    fail "$url could not be fetched with cookie"
  fi
}

check_service_name_policy() {
  local wk_file="$1"
  local service_name

  service_name="$(jq -r '
    .service_name // .name // .service.name // .service.title // empty
  ' "$wk_file" 2>/dev/null)"

  if [[ -n "$service_name" && "$service_name" != "null" ]]; then
    pass ".well-known service name detected: $service_name"
  else
    fail ".well-known/agent.json missing recognizable service name field"
    return 0
  fi

  if [[ -n "$EXPECT_SERVICE_NAME" ]]; then
    if [[ "$service_name" == "$EXPECT_SERVICE_NAME" ]]; then
      pass ".well-known service name matches EXPECT_SERVICE_NAME"
    else
      if [[ "$STRICT_SERVICE_NAME" == "1" ]]; then
        fail ".well-known service name mismatch: expected '$EXPECT_SERVICE_NAME', got '$service_name'"
      else
        warn ".well-known service name mismatch: expected '$EXPECT_SERVICE_NAME', got '$service_name'"
      fi
    fi
  fi
}

consistency_check() {
  local wk_file="$1"
  local cap_file="$2"
  local rep_file="$3"
  local out_file="$TMP_DIR/consistency_check.txt"

  if python3 - "$wk_file" "$cap_file" "$rep_file" > "$out_file" 2>&1 <<'PY'
import json, sys

wk = json.load(open(sys.argv[1]))
cap = json.load(open(sys.argv[2]))
rep = json.load(open(sys.argv[3]))

errors = []

svc = (
    wk.get("service_name")
    or wk.get("name")
    or (wk.get("service") or {}).get("name")
    or (wk.get("service") or {}).get("title")
)
if not isinstance(svc, str) or not svc.strip():
    errors.append("missing string service name in .well-known/agent.json")

job_types = cap.get("job_types", {})
if not isinstance(job_types, dict) or not job_types:
    errors.append("capabilities.job_types missing or empty")

cov = job_types.get("covenant_visualize", {})
out = cov.get("output_schema", {})
if cov:
    if "trust_score" not in out:
        errors.append("covenant_visualize.output_schema missing trust_score")
    if "confidence" not in out:
        errors.append("covenant_visualize.output_schema missing confidence")

if "completed_jobs" not in rep:
    errors.append("reputation missing completed_jobs")

if errors:
    print("\n".join(errors))
    raise SystemExit(1)

print("ok")
PY
  then
    pass "Cross-endpoint consistency checks passed"
  else
    fail "Cross-endpoint consistency checks failed"
    sed 's/^/  /' "$out_file"
  fi
}

is_known_job_type() {
  case "$1" in
    ping|covenant_visualize|covenant_decode|verify_signature) return 0 ;;
    *) return 1 ;;
  esac
}

build_job_request_json() {
  local job_type="$1"
  local cap_file="$2"
  local out_file="$3"

  if python3 - "$job_type" "$cap_file" > "$out_file" <<'PY'
import json, sys, time

job_type = sys.argv[1]
cap = json.load(open(sys.argv[2]))
schema = (cap.get("job_types", {}).get(job_type, {}) or {}).get("input_schema", {}) or {}
nonce = f"{int(time.time())}-{job_type}"

sample_pubkey = "02" + ("11" * 32)
sample_sig = "30440220" + ("11" * 32) + "0220" + ("22" * 32)
sample_script_asm = (
    "OP_IF 021111111111111111111111111111111111111111111111111111111111111111 "
    "OP_CHECKSIG OP_ELSE 500000 OP_CHECKLOCKTIMEVERIFY OP_DROP "
    "031111111111111111111111111111111111111111111111111111111111111111 "
    "OP_CHECKSIG OP_ENDIF"
)
sample_script_hex = "51"
sample_descriptor = f"wpkh({sample_pubkey})"

if job_type == "ping":
    body = {
        "job_type": "ping",
        "payload": {"smoke_test": True, "nonce": nonce},
    }
elif job_type == "covenant_visualize":
    body = {
        "job_type": job_type,
        "input": {"script_asm": f"{sample_script_asm} {nonce}"},
    }
elif job_type == "covenant_decode":
    body = {
        "job_type": job_type,
        "input": {"script_hex": sample_script_hex},
    }
elif job_type == "verify_signature":
    body = {
        "job_type": job_type,
        "input": {
            "message": f"smoke test {nonce}",
            "pubkey": sample_pubkey,
            "signature": sample_sig,
        },
    }
else:
    obj = {}
    for key, desc in schema.items():
        hint = f"{key} {desc}".lower()
        if key == "payload":
            obj[key] = {"smoke_test": True, "nonce": nonce}
        elif "script_hex" in key or ("hex" in hint and "pubkey" not in hint and "signature" not in hint):
            obj[key] = sample_script_hex
        elif "script_asm" in key or "asm" in hint:
            obj[key] = f"{sample_script_asm} {nonce}"
        elif "descriptor" in key or "descriptor" in hint:
            obj[key] = sample_descriptor
        elif key == "network" or "network" in hint:
            obj[key] = "bitcoin"
        elif key == "message" or "message" in hint:
            obj[key] = f"smoke test {nonce}"
        elif key == "pubkey" or "pubkey" in hint:
            obj[key] = sample_pubkey
        elif key == "signature" or "signature" in hint:
            obj[key] = sample_sig
        elif "amount" in key or "sats" in key or "amount" in hint or "sats" in hint:
            obj[key] = 1
        elif "count" in key or "limit" in key:
            obj[key] = 1
        else:
            obj[key] = f"smoke-{key}-{nonce}"

    if list(obj.keys()) == ["payload"]:
        body = {"job_type": job_type, "payload": obj["payload"]}
    elif obj:
        body = {"job_type": job_type, "input": obj}
    else:
        body = {"job_type": job_type}

print(json.dumps(body))
PY
  then
    pass "built smoke request for advertised job_type '$job_type'"
  else
    fail "could not build smoke request for advertised job_type '$job_type'"
    return 1
  fi
}

handle_structured_job_error() {
  local job_type="$1"
  local resp_file="$2"
  local known="$3"
  local err

  err="$(jq -r '.error // .message // empty' "$resp_file" 2>/dev/null)"
  if [[ "$err" == "unsupported_job_type" ]]; then
    fail "advertised job_type '$job_type' returned unsupported_job_type"
  else
    if [[ "$STRICT_REQUEST_ERRORS" == "1" && "$known" == "known" ]]; then
      fail "$job_type returned structured error"
    else
      warn "$job_type returned structured error for smoke fixture${known:+ ($known fixture class)}"
    fi
    jq . "$resp_file" 2>/dev/null | sed 's/^/  /' || sed 's/^/  /' "$resp_file"
  fi
}

smoke_one_job_type() {
  local job_type="$1"
  local cap_file="$2"
  local req_file="$TMP_DIR/request_${job_type}.json"
  local resp_file="$TMP_DIR/response_${job_type}.json"
  local kind="generic"

  if is_known_job_type "$job_type"; then
    kind="known"
  fi

  build_job_request_json "$job_type" "$cap_file" "$req_file" || return 0

  if post_json "${BASE_URL}/agent/request" "$(cat "$req_file")" > "$resp_file"; then
    pass "$job_type request returned a response"
  else
    fail "$job_type request failed"
    return 0
  fi

  if jq -e '(.error // empty) != "" or (.message // empty) != ""' "$resp_file" >/dev/null 2>&1; then
    handle_structured_job_error "$job_type" "$resp_file" "$kind"
    return 0
  fi

  if jq -e '(.job_id | type == "string") and (.status == "invoice_pending" or .status == "done")' "$resp_file" >/dev/null 2>&1; then
    local job_status
    job_status="$(json_get_file "$resp_file" '.status')"
    pass "$job_type request returned acceptable status: ${job_status}"

    if [[ "$job_status" == "invoice_pending" ]]; then
      assert_json_field_from_file "$resp_file" '.invoice | type == "string"'
      assert_json_field_from_file "$resp_file" '.payment_hash | type == "string"'
    else
      if jq -e '(.invoice | type == "string") and (.payment_hash | type == "string")' "$resp_file" >/dev/null 2>&1; then
        pass "${job_type} done response still includes invoice/payment_hash"
      else
        warn "${job_type} done response omits invoice and/or payment_hash"
      fi
    fi

    local job_id
    job_id="$(json_get_file "$resp_file" '.job_id')"
    if [[ -n "$job_id" && "$job_id" != "null" ]]; then
      local job_file="$TMP_DIR/job_${job_type}.json"
      if write_url_to_file "${BASE_URL}/agent/jobs/${job_id}" "$job_file"; then
        assert_json_field_from_file "$job_file" ".job_id == \"${job_id}\""
        assert_json_field_from_file "$job_file" '.status | type == "string"'
      fi
    else
      fail "$job_type response did not yield a usable job_id"
    fi
    return 0
  fi

  fail "$job_type returned unexpected response shape"
  jq . "$resp_file" 2>/dev/null | sed 's/^/  /' || sed 's/^/  /' "$resp_file"
}

main() {
  section "0) Dependencies"
  need_cmd curl
  need_cmd jq
  need_cmd python3

  section "1) Reachability"
  wait_for_service

  section "2) Public browser pages before login"
  assert_http_status "${BASE_URL}/login" 200
  assert_http_status "${BASE_URL}/playground" 200
  assert_http_status_in "${BASE_URL}/" 200 302
  assert_http_status_in "${BASE_URL}/home" 302 303
  assert_location_contains "${BASE_URL}/home" "/login?next=/home"
  assert_http_status_in "${BASE_URL}/app" 302 303
  assert_location_contains "${BASE_URL}/app" "/login?next=/app"
  assert_http_status_in "${BASE_URL}/account" 302 303
  assert_location_contains "${BASE_URL}/account" "/login?next=/account"
  assert_http_status_in "${BASE_URL}/onboard" 302 303
  assert_location_contains "${BASE_URL}/onboard" "/home#onboard"
  assert_http_status_in "${BASE_URL}/oneword" 302 303
  assert_location_contains "${BASE_URL}/oneword" "/home"
  assert_http_status_in "${BASE_URL}/upgrade" 302 303
  assert_location_contains "${BASE_URL}/upgrade" "/login?next=/upgrade"
  assert_http_status_in "${BASE_URL}/explorer" 302 303
  assert_location_contains "${BASE_URL}/explorer" "/home#explorer"

  section "3) Login page structure"
  local login_html="$TMP_DIR/login.html"
  if write_url_to_file "${BASE_URL}/login" "$login_html"; then
    assert_file_contains "$login_html" "HODLXXI" "/login"
    assert_file_contains "$login_html" "challenge" "/login"
    assert_file_contains "$login_html" "Lightning" "/login"
    assert_file_contains "$login_html" "Nostr" "/login"
    assert_file_contains "$login_html" "Guest" "/login"
  fi

  section "4) Guest login flow"
  local guest_json="$TMP_DIR/guest_login.json"
  if post_json_cookie "${BASE_URL}/guest_login" '{"pin":""}' > "$guest_json"; then
    pass "/guest_login returned a response"
    assert_json_field_from_file "$guest_json" '.ok == true'
    assert_json_field_from_file "$guest_json" '.label | type == "string"'
  else
    fail "/guest_login request failed"
  fi

  section "5) Browser pages after guest login"
  local home_after="$TMP_DIR/home_after_guest.html"
  local app_after="$TMP_DIR/app_after_guest.html"
  local account_after="$TMP_DIR/account_after_guest.html"

  get_cookie_to_file "${BASE_URL}/home" "$home_after"
  get_cookie_to_file "${BASE_URL}/app" "$app_after"
  get_cookie_to_file "${BASE_URL}/account" "$account_after"

  if grep -Fqi "HODLXXI" "$home_after" 2>/dev/null; then
    pass "/home after guest login renders expected HTML marker"
  else
    fail "/home after guest login missing expected HTML marker"
  fi

  if grep -Fqi "HODLXXI" "$app_after" 2>/dev/null; then
    pass "/app after guest login renders expected HTML marker"
  else
    fail "/app after guest login missing expected HTML marker"
  fi

  local app_status_after
  app_status_after="$(curl -ksS -b "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "${BASE_URL}/app" 2>/dev/null || true)"
  if [[ "$app_status_after" == "200" ]]; then
    pass "/app after guest login -> HTTP 200"
  else
    fail "/app after guest login expected HTTP 200, got ${app_status_after:-unknown}"
  fi

  section "6) Logout"
  local logout_headers="$TMP_DIR/logout.headers"
  if curl -ksS -b "$COOKIE_JAR" -c "$COOKIE_JAR" -D "$logout_headers" -o /dev/null "${BASE_URL}/logout" 2>/dev/null; then
    pass "/logout returned headers"
    if grep -qi '^Location: /login' "$logout_headers"; then
      pass "/logout redirects to /login"
    else
      fail "/logout did not redirect to /login"
      sed 's/^/  /' "$logout_headers"
    fi
  else
    fail "/logout request failed"
  fi

  local post_logout_app_status
  post_logout_app_status="$(curl -ksS -b "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "${BASE_URL}/app" 2>/dev/null || true)"
  if [[ "$post_logout_app_status" == "302" || "$post_logout_app_status" == "303" ]]; then
    pass "/app after logout is gated again"
  else
    fail "/app after logout expected redirect, got HTTP ${post_logout_app_status:-unknown}"
  fi

  section "7) Agent public surfaces"
  local wk_file="$TMP_DIR/well_known_agent.json"
  local cap_file="$TMP_DIR/capabilities.json"
  local rep_file="$TMP_DIR/reputation.json"

  assert_http_status "${BASE_URL}/.well-known/agent.json" 200
  assert_http_status "${BASE_URL}/agent/capabilities" 200
  assert_http_status "${BASE_URL}/agent/capabilities/schema" 200
  assert_http_status "${BASE_URL}/agent/reputation" 200
  assert_http_status "${BASE_URL}/agent/attestations" 200
  assert_http_status "${BASE_URL}/agent/chain/health" 200
  assert_http_status "${BASE_URL}/agent/skills" 200

  write_url_to_file "${BASE_URL}/.well-known/agent.json" "$wk_file"
  write_url_to_file "${BASE_URL}/agent/capabilities" "$cap_file"
  write_url_to_file "${BASE_URL}/agent/reputation" "$rep_file"

  assert_json_field_from_file "$wk_file" '((.service_name // .name // .service.name // .service.title) | type) == "string"'
  assert_json_field_from_file "$wk_file" '.endpoints.capabilities == "/agent/capabilities"'
  assert_json_field_from_file "$cap_file" '.job_types | type == "object"'
  assert_json_field_from_file "$cap_file" '(.job_types | length) > 0'
  assert_json_field_from_file "$rep_file" '.completed_jobs | type == "number"'
  assert_json_field_from_url "${BASE_URL}/agent/attestations" '.attestations? or .items? or .events? or .count? or .attestations_count?'
  assert_json_field_from_url "${BASE_URL}/agent/chain/health" '.ok == true or .active == true or .count >= 0'
  assert_json_field_from_url "${BASE_URL}/agent/skills" '.items | type == "array"'

  if jq -e '.job_types.ping? != null' "$cap_file" >/dev/null 2>&1; then
    assert_json_field_from_file "$cap_file" '.job_types.ping.price_sats | type == "number"'
  fi
  if jq -e '.job_types.covenant_visualize? != null' "$cap_file" >/dev/null 2>&1; then
    assert_json_field_from_file "$cap_file" '.job_types.covenant_visualize.output_schema.trust_score? != null'
  fi

  section "8) Agent request smoke (capability-aware)"
  mapfile -t advertised_job_types < <(jq -r '.job_types | keys[]?' "$cap_file" 2>/dev/null)
  if (( ${#advertised_job_types[@]} == 0 )); then
    fail "No advertised job_types found in /agent/capabilities"
  else
    pass "Discovered ${#advertised_job_types[@]} advertised job_type(s)"
    local job_type
    for job_type in "${advertised_job_types[@]}"; do
      info "Auto-testing advertised job_type: ${job_type}"
      smoke_one_job_type "$job_type" "$cap_file"
    done
  fi

  section "9) Negative-path checks"
  assert_http_status_in "${BASE_URL}/agent/jobs/not-a-real-job-id" 404 400
  assert_http_status_in "${BASE_URL}/agent/verify/not-a-real-job-id" 404 400

  section "10) Consistency checks"
  check_service_name_policy "$wk_file"
  consistency_check "$wk_file" "$cap_file" "$rep_file"

  print_summary

  if (( FAIL_COUNT > 0 )); then
    return 1
  fi
  return 0
}

main "$@"

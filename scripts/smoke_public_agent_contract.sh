#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-https://hodlxxi.com}"
OPERATOR_ENDPOINT="/.well-known/hodlxxi-operator.json"
OPERATOR_PUBKEY="023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
AGENT_PUBKEY="02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92"
MISSING_JOB_ID="00000000-0000-0000-0000-000000000000"
FAILURES=0

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing required command: $1" >&2
    exit 1
  }
}

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILURES=$((FAILURES + 1)); }

check() {
  local message="$1"
  shift
  if "$@"; then
    pass "$message"
  else
    fail "$message"
  fi
}

curl_json() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local body_file status
  body_file="$(mktemp)"
  if [[ "$method" == "POST" ]]; then
    status="$(curl -sS -o "$body_file" -w '%{http_code}' \
      -H 'content-type: application/json' \
      -X POST \
      --data "$data" \
      "$BASE$path")"
  else
    status="$(curl -sS -o "$body_file" -w '%{http_code}' "$BASE$path")"
  fi
  printf '%s\n%s\n' "$status" "$(cat "$body_file")"
  rm -f "$body_file"
}

get_status() {
  curl -sS -o /dev/null -w '%{http_code}' "$BASE$1"
}

get_body() {
  curl -fsS "$BASE$1"
}

jq_equals() {
  local json="$1"
  local filter="$2"
  local expected="$3"
  [[ "$(jq -r "$filter" <<<"$json")" == "$expected" ]]
}

jq_true() {
  local json="$1"
  local filter="$2"
  jq -e "$filter" >/dev/null <<<"$json"
}

need curl
need jq

for path in \
  "/login" \
  "/.well-known/agent.json" \
  "/agent/capabilities" \
  "/agent/discovery" \
  "$OPERATOR_ENDPOINT" \
  "/agent/reputation" \
  "/agent/attestations" \
  "/agent/chain/health"; do
  status="$(get_status "$path")"
  if [[ "$status" == "200" ]]; then
    pass "HTTP 200 $path"
  else
    fail "HTTP 200 $path (got $status)"
  fi
done

operator_json="$(get_body "$OPERATOR_ENDPOINT")"
agent_json="$(get_body '/.well-known/agent.json')"
capabilities_json="$(get_body '/agent/capabilities')"
discovery_json="$(get_body '/agent/discovery')"

check "operator schema is hodlxxi.operator_continuity.v1" jq_equals "$operator_json" '.schema' 'hodlxxi.operator_continuity.v1'
check "operator_id is E923" jq_equals "$operator_json" '.operator_id' 'E923'
check "operator_pubkey matches E923 key" jq_equals "$operator_json" '.operator_pubkey' "$OPERATOR_PUBKEY"
check "agent_pubkey matches public agent key" jq_equals "$operator_json" '.agent_pubkey' "$AGENT_PUBKEY"
check "key_status is active" jq_equals "$operator_json" '.key_status' 'active'
check "covenant.status is declared_unfunded" jq_equals "$operator_json" '.covenant.status' 'declared_unfunded'
check "covenant.verified_on_chain is false" jq_true "$operator_json" '.covenant.verified_on_chain == false'
check "covenant.time_locked_capital_proof_exposed is false" jq_true "$operator_json" '.covenant.time_locked_capital_proof_exposed == false'

check "agent.json advertises operator continuity" jq_true "$agent_json" ".endpoints.operator_continuity == \"$OPERATOR_ENDPOINT\" and .discovery.operator_continuity == \"$OPERATOR_ENDPOINT\""
check "capabilities advertises operator continuity" jq_true "$capabilities_json" ".endpoints.operator_continuity == \"$OPERATOR_ENDPOINT\""
check "discovery advertises operator continuity" jq_true "$discovery_json" ".discovery.operator_continuity == \"$OPERATOR_ENDPOINT\""

if [[ -x scripts/verify_operator_continuity.sh ]]; then
  if BASE="$BASE" bash scripts/verify_operator_continuity.sh; then
    pass "operator continuity verifier script passed"
  else
    fail "operator continuity verifier script passed"
  fi
else
  fail "scripts/verify_operator_continuity.sh is executable"
fi

request_payload='{"job_type":"ping","payload":{"message":"public agent contract smoke unpaid verifier"}}'
request_response="$(curl_json POST '/agent/request' "$request_payload")"
request_status="$(sed -n '1p' <<<"$request_response")"
request_body="$(sed '1d' <<<"$request_response")"

if [[ "$request_status" == "200" || "$request_status" == "201" || "$request_status" == "202" ]]; then
  pass "POST /agent/request created unpaid job (HTTP $request_status)"
else
  fail "POST /agent/request created unpaid job (got HTTP $request_status)"
fi

job_id="$(jq -r '.job_id // empty' <<<"$request_body")"
request_state="$(jq -r '.status // empty' <<<"$request_body")"
payment_hash_present="$(jq -r 'has("payment_hash") and (.payment_hash != null and .payment_hash != "")' <<<"$request_body")"
invoice_present="$(jq -r 'has("invoice") and (.invoice != null and .invoice != "")' <<<"$request_body")"
echo "INFO: job_id=$job_id status=$request_state payment_hash_present=$payment_hash_present invoice_present=$invoice_present"
check "job_id returned from /agent/request" test -n "$job_id"

job_response="$(curl_json GET "/agent/jobs/$job_id")"
job_status="$(sed -n '1p' <<<"$job_response")"
job_body="$(sed '1d' <<<"$job_response")"
[[ "$job_status" == "200" ]] && pass "GET /agent/jobs/<job_id> HTTP 200" || fail "GET /agent/jobs/<job_id> HTTP 200 (got $job_status)"
check "job status is invoice_pending" jq_equals "$job_body" '.status' 'invoice_pending'
check "job result is null" jq_true "$job_body" '.result == null'
check "job receipt is null" jq_true "$job_body" '.receipt == null'

verify_response="$(curl_json GET "/agent/verify/$job_id")"
verify_status="$(sed -n '1p' <<<"$verify_response")"
verify_body="$(sed '1d' <<<"$verify_response")"
[[ "$verify_status" == "409" ]] && pass "GET /agent/verify/<job_id> HTTP 409" || fail "GET /agent/verify/<job_id> HTTP 409 (got $verify_status)"
check "verify status is no_receipt" jq_equals "$verify_body" '.status' 'no_receipt'
check "verify valid is false" jq_true "$verify_body" '.valid == false'
check "verify verification is unavailable" jq_equals "$verify_body" '.verification' 'unavailable'
check "verify job_status is invoice_pending" jq_equals "$verify_body" '.job_status' 'invoice_pending'
check "verify receipt is null" jq_true "$verify_body" '.receipt == null'
check "verify reason is receipt_not_issued" jq_equals "$verify_body" '.reason' 'receipt_not_issued'

missing_response="$(curl_json GET "/agent/verify/$MISSING_JOB_ID")"
missing_status="$(sed -n '1p' <<<"$missing_response")"
missing_body="$(sed '1d' <<<"$missing_response")"
[[ "$missing_status" == "404" ]] && pass "GET /agent/verify/<missing_job_id> HTTP 404" || fail "GET /agent/verify/<missing_job_id> HTTP 404 (got $missing_status)"
check "missing verifier error is not_found" jq_equals "$missing_body" '.error' 'not_found'
check "missing verifier verification is unavailable" jq_equals "$missing_body" '.verification' 'unavailable'

if [[ "$FAILURES" -eq 0 ]]; then
  echo "PASS: public agent contract smoke succeeded"
else
  echo "FAIL: public agent contract smoke failed ($FAILURES checks failed)"
  exit 1
fi

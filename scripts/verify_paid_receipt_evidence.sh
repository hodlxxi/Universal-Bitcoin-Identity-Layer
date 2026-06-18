#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-https://hodlxxi.com}"
BASE="${BASE%/}"
JOB_ID="${JOB_ID:-1013ca86-f09e-40d3-b6ea-862620890b36}"
EXPECTED_AGENT_PUBKEY="${EXPECTED_AGENT_PUBKEY:-02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92}"
EXPECTED_EVENT_HASH="${EXPECTED_EVENT_HASH:-529245bed836a0adf9fdd57ac46d2276e7ab85ce3e52ab8dcbb6f8ac9f9bdd44}"
EXPECTED_PAYMENT_HASH="${EXPECTED_PAYMENT_HASH:-f6530836330ca1047f8d92a638c70d64597a34f299b49ef94c3aac621e1b82c1}"
EXPECTED_REQUEST_HASH="${EXPECTED_REQUEST_HASH:-d666c1696c7b7d03e80c762aecfedfcfbd6686334045ec2b84f94f691a646c0a}"
EXPECTED_RESULT_HASH="${EXPECTED_RESULT_HASH:-d7fc571c7e5c5c98146fd1f6f94eda75717d04de7438713b24a3423d204d9e9b}"
EXPECTED_PREV_EVENT_HASH="${EXPECTED_PREV_EVENT_HASH:-68d8123685788df1dba5b3ed0dfc965119771faf36961ce15fe2ce2ec2719ca0}"
STRICT_LATEST="${STRICT_LATEST:-0}"
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
  local path="$1"
  local body_file status
  body_file="$(mktemp)"
  status="$(curl -sS -o "$body_file" -w '%{http_code}' "$BASE$path")"
  printf '%s\n%s\n' "$status" "$(cat "$body_file")"
  rm -f "$body_file"
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

job_response="$(curl_json "/agent/jobs/$JOB_ID")"
job_status="$(sed -n '1p' <<<"$job_response")"
job_body="$(sed '1d' <<<"$job_response")"
[[ "$job_status" == "200" ]] && pass "GET /agent/jobs/$JOB_ID HTTP 200" || fail "GET /agent/jobs/$JOB_ID HTTP 200 (got $job_status)"
check "job_id matches" jq_equals "$job_body" '.job_id' "$JOB_ID"
check "job status is done" jq_equals "$job_body" '.status' 'done'
check "job result is present" jq_true "$job_body" '.result != null'
check "job receipt is present" jq_true "$job_body" '.receipt != null'
check "receipt event_type is job_receipt" jq_equals "$job_body" '.receipt.event_type' 'job_receipt'
check "receipt version is 1.0" jq_equals "$job_body" '.receipt.version' '1.0'
check "receipt agent_pubkey matches" jq_equals "$job_body" '.receipt.agent_pubkey' "$EXPECTED_AGENT_PUBKEY"
check "receipt request_hash matches" jq_equals "$job_body" '.receipt.request_hash' "$EXPECTED_REQUEST_HASH"
check "receipt result_hash matches" jq_equals "$job_body" '.receipt.result_hash' "$EXPECTED_RESULT_HASH"
check "receipt prev_event_hash matches" jq_equals "$job_body" '.receipt.prev_event_hash' "$EXPECTED_PREV_EVENT_HASH"
check "receipt signature is present" jq_true "$job_body" '(.receipt.signature // "") != ""'

verify_response="$(curl_json "/agent/verify/$JOB_ID")"
verify_status="$(sed -n '1p' <<<"$verify_response")"
verify_body="$(sed '1d' <<<"$verify_response")"
[[ "$verify_status" == "200" ]] && pass "GET /agent/verify/$JOB_ID HTTP 200" || fail "GET /agent/verify/$JOB_ID HTTP 200 (got $verify_status)"
check "verifier job_id matches" jq_equals "$verify_body" '.job_id' "$JOB_ID"
check "verifier status is verified" jq_equals "$verify_body" '.status' 'verified'
check "verifier valid is true" jq_true "$verify_body" '.valid == true'
check "verifier event_hash matches" jq_equals "$verify_body" '.event_hash' "$EXPECTED_EVENT_HASH"
check "verifier receipt is present" jq_true "$verify_body" '.receipt != null'
check "verifier attestation is present" jq_true "$verify_body" '.attestation != null'
check "verifier receipt agent_pubkey matches" jq_equals "$verify_body" '.receipt.agent_pubkey' "$EXPECTED_AGENT_PUBKEY"
check "verifier receipt request_hash matches" jq_equals "$verify_body" '.receipt.request_hash' "$EXPECTED_REQUEST_HASH"
check "verifier receipt result_hash matches" jq_equals "$verify_body" '.receipt.result_hash' "$EXPECTED_RESULT_HASH"
check "verifier receipt prev_event_hash matches" jq_equals "$verify_body" '.receipt.prev_event_hash' "$EXPECTED_PREV_EVENT_HASH"
check "verifier receipt signature is present" jq_true "$verify_body" '(.receipt.signature // "") != ""'

attestations_response="$(curl_json '/agent/attestations?limit=50')"
attestations_status="$(sed -n '1p' <<<"$attestations_response")"
attestations_body="$(sed '1d' <<<"$attestations_response")"
[[ "$attestations_status" == "200" ]] && pass "GET /agent/attestations?limit=50 HTTP 200" || fail "GET /agent/attestations?limit=50 HTTP 200 (got $attestations_status)"
attestation="$(jq --arg job_id "$JOB_ID" '[.. | objects | select(.job_id? == $job_id)] | first // null' <<<"$attestations_body")"
check "matching attestation exists" jq_true "$attestation" '. != null'
check "attestation event_hash matches" jq_equals "$attestation" '.event_hash' "$EXPECTED_EVENT_HASH"
check "attestation prev_event_hash matches" jq_equals "$attestation" '.prev_event_hash' "$EXPECTED_PREV_EVENT_HASH"
check "attestation request_hash matches" jq_equals "$attestation" '.request_hash' "$EXPECTED_REQUEST_HASH"
check "attestation result_hash matches" jq_equals "$attestation" '.result_hash' "$EXPECTED_RESULT_HASH"
check "attestation payment_hash matches" jq_equals "$attestation" '.payment_hash' "$EXPECTED_PAYMENT_HASH"
check "attestation agent_pubkey matches if present" jq_true "$attestation" "(.agent_pubkey == null) or (.agent_pubkey == \"$EXPECTED_AGENT_PUBKEY\")"
check "attestation signature is present" jq_true "$attestation" '(.signature // "") != ""'

health_response="$(curl_json '/agent/chain/health')"
health_status="$(sed -n '1p' <<<"$health_response")"
health_body="$(sed '1d' <<<"$health_response")"
[[ "$health_status" == "200" ]] && pass "GET /agent/chain/health HTTP 200" || fail "GET /agent/chain/health HTTP 200 (got $health_status)"
check "chain_ok is true" jq_true "$health_body" '.chain_ok == true'
check "latest_event_hash is present" jq_true "$health_body" '(.latest_event_hash // "") != ""'
latest_event_hash="$(jq -r '.latest_event_hash // empty' <<<"$health_body")"
echo "INFO: latest_event_hash=$latest_event_hash"
if [[ "$STRICT_LATEST" == "1" ]]; then
  check "latest_event_hash matches expected event hash" jq_equals "$health_body" '.latest_event_hash' "$EXPECTED_EVENT_HASH"
else
  pass "STRICT_LATEST=0; latest_event_hash may be newer than documented event"
fi

reputation_response="$(curl_json '/agent/reputation')"
reputation_status="$(sed -n '1p' <<<"$reputation_response")"
reputation_body="$(sed '1d' <<<"$reputation_response")"
[[ "$reputation_status" == "200" ]] && pass "GET /agent/reputation HTTP 200" || fail "GET /agent/reputation HTTP 200 (got $reputation_status)"
check "evidenced_completed_jobs is at least 1" jq_true "$reputation_body" '(.evidenced_completed_jobs | numbers) >= 1'
check "completed_jobs covers evidenced_completed_jobs when numeric" jq_true "$reputation_body" 'if ((.completed_jobs | type) == "number" and (.evidenced_completed_jobs | type) == "number") then .completed_jobs >= .evidenced_completed_jobs else true end'

completed_jobs="$(jq -r '.completed_jobs // "unknown"' <<<"$reputation_body")"
evidenced_completed_jobs="$(jq -r '.evidenced_completed_jobs // "unknown"' <<<"$reputation_body")"
attestations_count="$(jq -r 'if type == "array" then length else (.count // (.items | length? // "unknown")) end' <<<"$attestations_body")"
latest_event_timestamp="$(jq -r '.latest_event_timestamp // .latest_timestamp // "unknown"' <<<"$health_body")"

printf '\nSafe summary:\n'
printf 'BASE=%s\n' "$BASE"
printf 'JOB_ID=%s\n' "$JOB_ID"
printf 'event_hash=%s\n' "$EXPECTED_EVENT_HASH"
printf 'agent_pubkey=%s\n' "$EXPECTED_AGENT_PUBKEY"
printf 'request_hash=%s\n' "$EXPECTED_REQUEST_HASH"
printf 'result_hash=%s\n' "$EXPECTED_RESULT_HASH"
printf 'payment_hash=%s\n' "$EXPECTED_PAYMENT_HASH"
printf 'chain_ok=%s\n' "$(jq -r '.chain_ok // false' <<<"$health_body")"
printf 'completed_jobs=%s evidenced_completed_jobs=%s\n' "$completed_jobs" "$evidenced_completed_jobs"
printf 'attestations_count=%s latest_event_timestamp=%s\n' "$attestations_count" "$latest_event_timestamp"

if [[ "$FAILURES" -eq 0 ]]; then
  echo "PASS: paid receipt evidence verified"
else
  echo "FAIL: paid receipt evidence verification failed ($FAILURES checks failed)"
  exit 1
fi

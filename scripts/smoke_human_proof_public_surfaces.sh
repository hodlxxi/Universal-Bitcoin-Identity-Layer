#!/usr/bin/env bash
set -Eeuo pipefail

BASE_URL="${BASE_URL:-https://hodlxxi.com}"
BASE_URL="${BASE_URL%/}"

printf '%s\n' "Human Proof public surface smoke check"
printf '%s\n' "Safety: read-only GET checks only; creates no jobs, invoices, payments, or database mutations."
printf 'Base URL: %s\n' "$BASE_URL"

check_get() {
  local path="$1"
  local expected_status="$2"
  local tmp_body
  tmp_body="$(mktemp)"
  local status

  status="$(curl --silent --show-error --location --get --max-time 20 --connect-timeout 10 --output "$tmp_body" --write-out '%{http_code}' "$BASE_URL$path")"
  printf '%s -> status %s (expected %s)\n' "$path" "$status" "$expected_status"

  if [[ "$status" != "$expected_status" ]]; then
    printf 'Unexpected status for %s. Bounded body preview follows (max 500 bytes):\n' "$path" >&2
    head -c 500 "$tmp_body" >&2 || true
    printf '\n' >&2
    rm -f "$tmp_body"
    return 1
  fi

  rm -f "$tmp_body"
}

check_get "/demo" "200"
check_get "/agent/verify" "200"
check_get "/agent/capabilities" "200"
check_get "/agent/attestations" "200"
check_get "/agent/reputation" "200"
check_get "/agent/chain/health" "200"
check_get "/agent/verify/unknown-human-proof-mvp-job-id" "404"
check_get "/agent/receipt-proof" "200"
check_get "/.well-known/agent.json" "200"

printf '%s\n' "Human Proof public surface smoke check passed."

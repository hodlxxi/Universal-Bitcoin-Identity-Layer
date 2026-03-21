#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://www.hodlxxi.com}"
MESSAGE="${MESSAGE:-hello}"
SIGNATURE_HEX="${SIGNATURE_HEX:-deadbeef}"
PUBKEY_HEX="${PUBKEY_HEX:-021111111111111111111111111111111111111111111111111111111111111111}"

curl -sS   -X POST "$BASE_URL/agent/request"   -H 'Content-Type: application/json'   -d "{"job_type":"verify_signature","payload":{"message":"$MESSAGE","signature":"$SIGNATURE_HEX","pubkey":"$PUBKEY_HEX"}}"

echo

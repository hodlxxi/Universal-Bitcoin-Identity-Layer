#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://www.hodlxxi.com}"
SCRIPT_HEX="${SCRIPT_HEX:-51b1}"

curl -sS   -X POST "$BASE_URL/agent/request"   -H 'Content-Type: application/json'   -d "{"job_type":"covenant_decode","payload":{"script_hex":"$SCRIPT_HEX"}}"

echo

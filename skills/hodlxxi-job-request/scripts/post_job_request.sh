#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://www.hodlxxi.com}"
JOB_TYPE="${JOB_TYPE:-ping}"
PAYLOAD_JSON="${PAYLOAD_JSON:-{"message":"hello"}}"

curl -sS   -X POST "$BASE_URL/agent/request"   -H 'Content-Type: application/json'   -d "{"job_type":"$JOB_TYPE","payload":$PAYLOAD_JSON}"

echo

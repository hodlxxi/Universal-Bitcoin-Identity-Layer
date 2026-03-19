#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://www.hodlxxi.com}"
JOB_ID="${1:-${JOB_ID:-}}"

if [[ -z "$JOB_ID" ]]; then
  echo "usage: JOB_ID=<job-id> $0" >&2
  exit 1
fi

curl -sS "$BASE_URL/agent/jobs/$JOB_ID"
echo

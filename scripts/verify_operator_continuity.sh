#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-https://hodlxxi.com}"
OPERATOR_PUBKEY="023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
AGENT_PUBKEY="02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92"
FAILURES=0

need() { command -v "$1" >/dev/null 2>&1 || { echo "FAIL: missing required command: $1"; exit 1; }; }
fetch() { curl -fsS "$BASE$1"; }
check() { if "$@"; then echo "PASS: $*"; else echo "FAIL: $*"; FAILURES=$((FAILURES + 1)); fi; }

need curl
need jq

operator_json="$(fetch '/.well-known/hodlxxi-operator.json')"
agent_json="$(fetch '/.well-known/agent.json')"
capabilities_json="$(fetch '/agent/capabilities')"
discovery_json="$(fetch '/agent/discovery')"
status_json="$(fetch '/api/public/status')"

check jq -e . >/dev/null <<<"$operator_json"
check test "$(jq -r '.operator_pubkey' <<<"$operator_json")" = "$OPERATOR_PUBKEY"
check test "$(jq -r '.operator_id' <<<"$operator_json")" = "E923"
check test "$(jq -r '.agent_pubkey' <<<"$operator_json")" = "$AGENT_PUBKEY"
check test "$(jq -r '.covenant.status' <<<"$operator_json")" = "declared_unfunded"
check test "$(jq -r '.covenant.verified_on_chain' <<<"$operator_json")" = "false"
check test "$(jq -r '.agent_pubkey' <<<"$agent_json")" = "$AGENT_PUBKEY"
check test "$(jq -r '.agent_pubkey' <<<"$capabilities_json")" = "$AGENT_PUBKEY"

discovery_agent="$(jq -r '.agent_pubkey // empty' <<<"$discovery_json")"
if [[ -n "$discovery_agent" ]]; then
  check test "$discovery_agent" = "$AGENT_PUBKEY"
else
  echo "PASS: /agent/discovery has no agent_pubkey to compare"
fi

check jq -e . >/dev/null <<<"$status_json"

if [[ "$FAILURES" -eq 0 ]]; then
  echo "PASS: operator continuity verification succeeded"
else
  echo "FAIL: operator continuity verification failed ($FAILURES checks failed)"
  exit 1
fi

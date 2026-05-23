#!/usr/bin/env bash
set -euo pipefail

BASE="${1:-https://hodlxxi.com}"
JOB_FILE="/tmp/hodlxxi_agent_job.json"

echo "== HODLXXI external paid-call ping demo =="
echo "Base: ${BASE}"

echo
for path in \
  "/.well-known/agent.json" \
  "/agent/discovery" \
  "/agent/capabilities" \
  "/agent/nostr/announcement"; do
  echo "-- GET ${path}"
  code="$(curl -sS -o /tmp/hodlxxi_surface.json -w '%{http_code}' "${BASE}${path}")"
  echo "HTTP ${code}"
  jq . /tmp/hodlxxi_surface.json
  echo
done

echo "-- POST /agent/request (job_type=ping)"
curl -sS -X POST "${BASE}/agent/request" \
  -H 'Content-Type: application/json' \
  -d '{
    "job_type": "ping",
    "payload": {
      "message": "external paid call demo ping",
      "origin": "external-builder-script"
    }
  }' | tee "${JOB_FILE}" | jq .

echo
JOB_ID="$(jq -r '.job_id // .id // .job.id // empty' "${JOB_FILE}")"
if [[ -z "${JOB_ID}" ]]; then
  echo "ERROR: could not extract job_id from ${JOB_FILE}" >&2
  exit 1
fi

echo "job_id: ${JOB_ID}"

echo
INVOICE_FIELD="$(jq -r '
  if .invoice then "invoice"
  elif .payment_request then "payment_request"
  elif (.payment and .payment.payment_request) then "payment.payment_request"
  elif (.payment and .payment.invoice) then "payment.invoice"
  elif .bolt11 then "bolt11"
  else ""
  end
' "${JOB_FILE}")"

if [[ -n "${INVOICE_FIELD}" ]]; then
  echo "invoice/payment field present: ${INVOICE_FIELD}"
  echo "Manually pay the returned Lightning invoice using software you control."
else
  echo "No recognized invoice/payment field found in response."
fi

echo
echo "After manual payment, polling job status..."
for i in {1..10}; do
  echo "poll #${i}"
  curl -sS "${BASE}/agent/jobs/${JOB_ID}" | tee /tmp/hodlxxi_job_status.json | jq .
  status="$(jq -r '.status // .job.status // empty' /tmp/hodlxxi_job_status.json)"
  if [[ "${status}" != "invoice_pending" && -n "${status}" ]]; then
    echo "status moved to: ${status}"
    break
  fi
  sleep 3
done

echo
echo "-- Verify surfaces"
curl -sS "${BASE}/agent/verify/${JOB_ID}" | jq .
curl -sS "${BASE}/agent/trust/events" | jq .
curl -sS "${BASE}/agent/reputation" | jq .

echo
echo "Done. Verify don't trust."

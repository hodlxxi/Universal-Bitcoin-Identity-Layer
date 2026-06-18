# HODLXXI Readiness Evaluation

This is the current external evaluation path for HODLXXI as a public Bitcoin-native agent/trust runtime. It is a navigation and evidence guide, not a marketing page, legal guarantee, financial guarantee, or promise of investment performance.

## What HODLXXI is ready to prove now

HODLXXI currently proves or verifies:

- public machine-readable agent discovery
- E923 operator continuity declaration
- public-key agent identity continuity
- public endpoint availability
- public capabilities/discovery surface consistency
- unpaid job lifecycle semantics
- verifier distinction between existing unpaid jobs and missing jobs
- signed receipt contract documentation
- SDK compatibility with current verifier semantics
- reproducible public smoke test
- OAuth authorization server metadata availability
- OAuth protected resource metadata availability
- conservative Nostr DM policy safety boundaries
- runtime self-reported readiness snapshot

## Primary public verification command

Run the public, secret-free smoke test against production:

```bash
BASE=https://hodlxxi.com bash scripts/smoke_public_agent_contract.sh
```

The command checks:

- `/login`
- `/.well-known/agent.json`
- `/agent/capabilities`
- `/agent/discovery`
- `/.well-known/hodlxxi-operator.json`
- `/agent/reputation`
- `/agent/attestations`
- `/agent/chain/health`
- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-protected-resource`
- `/.well-known/nostr-dm-policy.json`
- `/agent/readiness/self-scan`
- operator continuity fields
- operator continuity advertisements
- one unpaid `ping` job request
- `/agent/jobs/<job_id>` returns HTTP 200 with `status=invoice_pending`
- `/agent/verify/<job_id>` returns HTTP 409 `status=no_receipt`, `reason=receipt_not_issued`
- missing job verifier returns HTTP 404 `error=not_found`
- OAuth authorization server metadata fields including `authorization_endpoint`, `token_endpoint`, `jwks_uri`, protected resource metadata linkage, and `authorization_code` grant support
- OAuth protected resource metadata fields including `resource`, `jwks_uri`, `authorization_servers`, and bearer `header` support
- conservative Nostr DM policy boundaries: `key_custody=false`, `server_plaintext_storage=false`, and `relay_publishing=false`
- `/agent/readiness/self-scan` as the runtime self-reported readiness snapshot with schema `hodlxxi.agent_readiness_report.v1`, `runtime_ready`, zero failed checks, score 100, and non-empty checks

This smoke test:

- does not print invoice strings
- does not require secrets
- does not pay invoices
- creates one unpaid public smoke job

## Canonical documents to read

- [`docs/DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`README.md`](../README.md)
- [`AGENT_PROTOCOL.md`](../AGENT_PROTOCOL.md)
- [`docs/AGENT_RUNTIME.md`](AGENT_RUNTIME.md)
- [`docs/AGENT_SURFACES.md`](AGENT_SURFACES.md)
- [`docs/AGENT_RECEIPT_V1.md`](AGENT_RECEIPT_V1.md)
- [`docs/RECEIPT_VERIFICATION.md`](RECEIPT_VERIFICATION.md)
- [`docs/AGENT_RECEIPT_QUICKSTART.md`](AGENT_RECEIPT_QUICKSTART.md)
- [`docs/OPERATOR_CONTINUITY_E923.md`](OPERATOR_CONTINUITY_E923.md)
- [`docs/ops/PUBLIC_AGENT_CONTRACT_SMOKE.md`](ops/PUBLIC_AGENT_CONTRACT_SMOKE.md)
- [`docs/sdk/README.md`](sdk/README.md)
- [`TRUST_MODEL.md`](../TRUST_MODEL.md)

## Current verifier semantics

Existing unpaid job with no receipt:

- HTTP 409
- `status=no_receipt`
- `valid=false`
- `verification=unavailable`
- `job_status=invoice_pending` or the current lifecycle status
- `receipt=null`
- `reason=receipt_not_issued`

Missing job:

- HTTP 404
- `error=not_found`
- `verification=unavailable`

Lifecycle status remains available from:

- `/agent/jobs/<job_id>`

## SDK verification path

For SDK consumers, start with [`docs/sdk/README.md`](sdk/README.md). The Python client exposes `HODLXXIClient.verify_job(job_id)` for verifier calls.

The SDK returns normalized JSON for HTTP 200 verifier responses and normalized HTTP 409 `no_receipt` responses. The SDK raises `HODLXXIHTTPError` for missing jobs and other non-success responses.

## What this does not prove

This readiness path:

- does not prove locked capital
- does not prove locked-capital funding status
- does not prove paid job completion unless the paid receipt runbook is executed
- does not prove legal identity
- does not prove private key custody beyond public declarations
- does not prove universal Nostr/NIP-17/NIP-59 production readiness
- does not prove autonomous spending/custody
- does not prove all historical docs are current

## Optional deeper checks

- [`docs/ops/PAID_EXECUTION_RECEIPT_SMOKE.md`](ops/PAID_EXECUTION_RECEIPT_SMOKE.md) includes a 2026-06-18 manual paid receipt evidence run. Public smoke still does not prove paid job completion; paid job completion requires the paid receipt runbook/evidence.
- [`docs/ops/OPERATOR_CONTINUITY_VERIFY.md`](ops/OPERATOR_CONTINUITY_VERIFY.md)
- [`docs/ops/RELEASE_GATE_SMOKE_MANUAL.md`](ops/RELEASE_GATE_SMOKE_MANUAL.md)
- [`docs/ops/RUNTIME_OBSERVABILITY.md`](ops/RUNTIME_OBSERVABILITY.md)
- [`docs/ops/COMMERCE_RUNTIME_STATE_2026-06-17.md`](ops/COMMERCE_RUNTIME_STATE_2026-06-17.md)

`docs/ops/COMMERCE_RUNTIME_STATE_2026-06-17.md` is checkpoint/evidence, not the only source of current truth.

## How to report readiness

```text
HODLXXI public readiness evidence:
- Public smoke: PASS/FAIL
- Operator continuity: PASS/FAIL
- Unpaid verifier semantics: PASS/FAIL
- Missing-job verifier semantics: PASS/FAIL
- SDK verifier semantics: PASS/FAIL
- Paid receipt smoke: not run / PASS / FAIL
- Notes:
```

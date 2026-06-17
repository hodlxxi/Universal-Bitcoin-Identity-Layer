<!-- HODLXXI_AGENT_READINESS_REPORT_V1 -->
# HODLXXI Agent Readiness Report v1

HODLXXI Agent Readiness Report v1 is the first productized report contract built on top of the runtime.

It turns the runtime positioning into a concrete external workflow:

`scan target -> evaluate public agent surfaces -> produce report -> issue receipt -> expose attestation`

The public HODLXXI self-scan endpoint is an intermediate runtime surface: it produces a live report for the current runtime, but does not create a paid job, issue a receipt, or publish an attestation.

The report is not a marketplace, exchange, wallet, custody system, or legal certification. It is a machine-readable operational readiness artifact for public-key agents and services.

## 1. Product role

The readiness report is an entry use case for the HODLXXI runtime.

It demonstrates the core runtime loop:

`public key -> capability -> paid job -> result -> receipt -> attestation -> reputation`

The runtime remains the product. The readiness report is a productized workflow on top of it.

## 2. v1 scope

Readiness Report v1 checks public machine-readable surfaces that an external agent or service may expose.

Required HODLXXI source surfaces for producing and verifying a report:

- `/.well-known/agent.json`
- `/agent/capabilities`
- `/agent/capabilities/schema`
- `/.well-known/nostr-dm-policy.json`
- `/api/public/status`
- `/health/ready`
- `/agent/reputation`
- `/agent/attestations`
- `/agent/chain/health`
- `/agent/verify/<job_id>`
- `/reports/<report_id>.json`
- `/verify/report/<report_id>`

Optional supporting surfaces:

- `/.well-known/openid-configuration`
- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-protected-resource`
- `/oauth/jwks.json`
- `/agent/skills`
- `/agent/marketplace/listing`
- `/agent/nostr/announcement`

### Public HODLXXI self-scan endpoint

HODLXXI exposes a public runtime self-scan endpoint:

`GET /agent/readiness/self-scan`

This endpoint returns a live JSON report for the current HODLXXI runtime using schema:

`hodlxxi.agent_readiness_report.v1`

The self-scan report includes `summary.status`, `summary.score`, `checks`, `verification`, and `report_sha256`.

The self-scan endpoint is not a paid job endpoint. It must not claim receipt or attestation issuance. Until paid report generation is added, the report should expose:

- `receipt.status = not_issued`
- `attestation.status = not_issued`

## 3. Required JSON shape

A v1 report must be JSON and must contain these top-level fields:

- `schema`
- `report_id`
- `target`
- `scanner`
- `summary`
- `checks`
- `receipt`
- `attestation`
- `verification`
- `generated_at`
- `report_sha256`

The schema value must be:

`hodlxxi.agent_readiness_report.v1`

## 4. Required check ids

A v1 report should include these check ids when relevant:

- `well_known_agent_json`
- `agent_capabilities`
- `agent_capabilities_schema`
- `nostr_dm_policy`
- `public_status`
- `health_ready`
- `reputation_surface`
- `attestations_surface`
- `chain_health_surface`
- `receipt_verification_surface`
- `report_json_surface`
- `human_verify_report_surface`

Allowed check statuses:

- `pass`
- `warn`
- `fail`
- `not_applicable`
- `unknown`

## 5. Receipt linkage

When the report is produced as a runtime job, it should link to:

- `job_id`
- `request_hash`
- `result_hash`
- `/agent/verify/<job_id>`

The receipt binds the report result to runtime behavior. It should be verifiable without trusting the UI.

## 6. Attestation linkage

The report should link to public runtime history:

- `/agent/attestations`
- `/agent/attestations?limit=1`
- `/agent/reputation`
- `/agent/chain/health`

## 7. Verification paths

The report should expose both machine and human verification paths:

- `/reports/<report_id>.json`
- `/verify/report/<report_id>`
- `/agent/verify/<job_id>`

## 8. Non-goals

Readiness Report v1 must not claim to provide:

- custody
- exchange execution
- P2P trade matching
- securities, tax, or legal advice
- proof that a service is safe to use with money
- proof that a service operator is honest
- private vulnerability scanning
- authenticated account scanning
- private-key handling

The report only records public machine-readable observations and links those observations to runtime receipts and attestations.

## 9. Implementation sequence

Recommended PR sequence:

1. Contract document and tests.
2. Static report builder for local HODLXXI self-scan.
3. Public runtime endpoint for local HODLXXI self-scan.
4. Paid job type for external report generation.
5. Receipt verification integration.
6. Public attestation export.
7. Human report page polish.

<!-- END_HODLXXI_AGENT_READINESS_REPORT_V1 -->

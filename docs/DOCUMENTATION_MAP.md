# HODLXXI Documentation Map

This file is the operator/developer map for navigating the repository's many docs. It classifies docs by current status so readers can find the right source quickly. It does not rewrite history, and it does not claim every older document is current.

## Start here

Primary entry points:

- `README.md` — top-level product/runtime overview
- `docs/READINESS_EVALUATION.md` — current external evaluation path for public agent/runtime readiness
- `AGENT_PROTOCOL.md` — public agent protocol and machine-readable surfaces
- `docs/README.md` — docs index
- `docs/AGENT_RUNTIME.md` — current runtime index
- `docs/AGENT_SURFACES.md` — current public agent surfaces
- `docs/ops/PUBLIC_AGENT_CONTRACT_SMOKE.md` — public production smoke proof
- `docs/sdk/README.md` — Python SDK

## Current runtime truth

Use these documents as the current implementation/runtime reference before relying on older checkpoints or conceptual pages:

- `AGENT_PROTOCOL.md` — public agent protocol, discovery documents, job flow, and verifier contract.
- `docs/AGENT_RUNTIME.md` — current runtime index for agent endpoints and operational boundaries.
- `docs/AGENT_SURFACES.md` — current public agent discovery, capabilities, receipts, attestations, and marketplace surfaces.
- `docs/API_REFERENCE.md` — API endpoint reference.
- `docs/AGENT_RECEIPT_V1.md` — signed receipt schema and verification boundaries.
- `docs/RECEIPT_VERIFICATION.md` — external local receipt verification algorithm and deterministic canonical JSON/hash fixtures.
- `docs/AGENT_RECEIPT_QUICKSTART.md` — developer quickstart for requesting jobs and verifying receipts.
- `docs/OPERATOR_CONTINUITY_E923.md` — current operator continuity declaration for runtime identity continuity.
- `TRUST_MODEL.md` — normative trust language and verification boundaries.

Current verifier semantics:

- An existing unpaid job with no receipt returns HTTP 409 with `status=no_receipt` and `reason=receipt_not_issued`.
- A missing job returns HTTP 404 with `error=not_found`.
- Lifecycle status remains available from `/agent/jobs/<job_id>`.

## Production verification and ops

Current or recent operational verification references:

- `docs/READINESS_EVALUATION.md`
- `docs/ops/PUBLIC_AGENT_CONTRACT_SMOKE.md`
- `scripts/smoke_public_agent_contract.sh`
- `docs/ops/PAID_EXECUTION_RECEIPT_SMOKE.md`
- `docs/ops/OPERATOR_CONTINUITY_VERIFY.md`
- `docs/ops/RELEASE_GATE_SMOKE_MANUAL.md`
- `docs/ops/RUNTIME_OBSERVABILITY.md`
- `docs/ops/COMMERCE_RUNTIME_STATE_2026-06-17.md`

`docs/ops/PUBLIC_AGENT_CONTRACT_SMOKE.md` is the current public, secret-free smoke test. `docs/ops/COMMERCE_RUNTIME_STATE_2026-06-17.md` is a checkpoint/evidence document, not the only source of current truth. If it mentions older pre-normalization behavior, prefer current runtime docs and smoke tests.

## SDK and external developer docs

Developer-facing integration references:

- `docs/OIDC_INTEGRATION.md` — canonical third-party Sign in with HODLXXI relying-party guide.
- `docs/sdk/README.md`
- `docs/sdk/AUTH_CHALLENGE_FLOW.md`
- `docs/sdk/NOSTR_AUTH_CHALLENGE_FLOW.md`
- `docs/EXTERNAL_PAID_CALL_DEMO.md`
- `docs/MCP_READONLY_WRAPPER.md`
- `docs/AGENT_NIP90_COMPATIBILITY.md`
- `docs/AGENT_DVM_COMPATIBILITY.md`

SDK `verify_job()` understands the normalized HTTP 409 `no_receipt` verifier state.

## Historical checkpoints

These docs are useful as evidence/history, but should not be treated as always-current runbooks unless linked by current ops docs. Examples include:

Many historical checkpoint documents now include a standard status note at the top to prevent confusing old deployment evidence with current implementation truth.

- `docs/ops/*2026-05-*.md`
- `HARDENING_SPRINT_2026-05-04.md`
- `RED_TEAM_REMEDIATION_STATUS_2026-04-29.md`
- `RUNTIME_TRANSITION_STATUS.md`
- `STATE_OF_PRODUCT_AND_RUNTIME.md`
- `TODO_GRANT_GRADE_REMEDIATION.md`
- `docs/HODLXXI_AGENT_PROTOCOL_V0.2.md`

## Experimental / staging / roadmap docs

These are useful for future development, staging, compatibility, and design intent, but should not be presented as current production readiness evidence unless a current smoke/runbook says so:

- `docs/NIP17_RUNTIME_PLAN.md`
- `docs/milestones/NIP17_SITE_LOCAL_MESSAGING_V0.md`
- `docs/ops/NIP17_*.md`
- `docs/ops/NIP59_*.md`
- `docs/HERALD_*.md`
- `examples/herald/*`
- `examples/nostr/*`

## Static website and conceptual docs

- `app/static/docs/docs/README.md` — static docs index.
- `app/static/docs/docs/*` — conceptual/public-facing reference docs.

These docs are not authoritative for current runtime behavior, API semantics, production readiness, operator continuity, or verifier semantics unless they point back to current runtime/readiness docs. Current implementation truth starts from `docs/READINESS_EVALUATION.md` and `docs/DOCUMENTATION_MAP.md`.

## Archive candidates / low-value docs

See `docs/ARCHIVE_CANDIDATES.md` for the controlled index of low-value, stale, superseded, or review-before-removal docs. Listing a file there does not delete it and does not authorize removal without a separate focused review PR.

Current candidate paths:

- `docs/CI_PING.md`
- `docs/UI_UNIFICATION.md`
- `docs/agent_ubid_plan.md`
- `docs/clawhub/*`
- `docs/schemas/external_agent_record.schema.json`
- `examples/social/first_external_paid_call_post.md`

Do not delete them in this PR. Use `docs/ARCHIVE_CANDIDATES.md` and a future focused cleanup PR to decide whether to archive, move, remove, or keep any candidate.

## Safety / non-claims

- Current docs and smoke tests do not prove locked capital.
- Operator continuity is a public declaration, not legal identity proof.
- Public smoke does not prove paid job completion unless the paid receipt runbook is executed.
- Public smoke does not require or print secrets or invoice strings.
- Static/conceptual docs may discuss broader vision; current runtime docs and smoke tests are the implementation truth.

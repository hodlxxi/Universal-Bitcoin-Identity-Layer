# HODLXXI Agent Delegation v0

## Goal

Define the first HODLXXI delegated-identity record contract before adding runtime delegation endpoints or storage.

A delegation record is a bounded, signed statement that one agent identity may act within explicit scopes and limits for another identity. It is not a QR Pointer, not consent by scan, not human approval, not raw execution authority, and not an audit log by itself.

This PR is canon/schema only. It does not add `/.well-known/agent-delegation.json`, `/agent/delegations`, `/agent/delegations/<delegation_id>`, database tables, migrations, background jobs, approval flows, QR routes, analytics, or third-party providers.

## Existing architecture

HODLXXI already exposes public agent discovery, capabilities, receipt verification, attestations, reputation, and QR Pointer v0 docs/schema. Delegation v0 extends that architecture as a future identity-layer contract, not as a runtime behavior in this PR.

Relevant existing surfaces remain unchanged:

- `/.well-known/agent.json`
- `/.well-known/hodlxxi-operator.json`
- `/agent/discovery`
- `/agent/capabilities`
- `/agent/verify/<job_id>`
- `/agent/attestations`
- `/agent/trust/events`
- `/agent/reputation`
- `/agent/chain/health`

## Runtime surface

None in v0 canon/schema phase.

Future runtime work may publish a delegation index and addressable delegation records only after this contract has tests and review.

## Endpoints

No endpoint is added in this PR.

Reserved future endpoints:

- `GET /.well-known/agent-delegation.json` for delegation discovery.
- `GET /agent/delegations` for a read-only delegation index.
- `GET /agent/delegations/<delegation_id>` for one addressable delegation record.
- `GET /agent/delegations/schema` for the active runtime schema, if served later.

Reserved endpoints must remain read-only until approval, policy, execution, receipt, and audit contracts exist.

## JSON schemas

The repository schema is `docs/schemas/agent_delegation_v0.schema.json`.

The schema defines a delegation record with:

- stable `delegation_id`;
- `issuer` identity;
- `subject` identity;
- explicit `authority.scopes`;
- optional `authority.resources`;
- deterministic `limits`;
- explicit `status`;
- `issued_at` and optional `expires_at`;
- `verification` metadata;
- explicit `non_claims`;
- required `signature` reserved for the future signed runtime profile.

## Capability changes

None in this PR.

Delegation records must not be advertised through `/agent/capabilities` until a runtime endpoint exists and returns deterministic, tested records.

## Database models

None in this PR.

Future storage must preserve append-only auditability where practical and must not overwrite historical delegation state without an explicit revocation event or status transition record.

## Definition

A HODLXXI delegated identity is:

- an agent or operator identity identified by public-key material or a stable runtime identity reference;
- granted only bounded scopes by an issuer;
- constrained by expiration, status, limits, and optional resource bindings;
- verifiable through canonical JSON and signature verification once runtime signing is implemented;
- revocable by explicit status transition in a future runtime profile.

A delegation record may describe authority only within the exact scope and limits encoded in the record. Anything outside the record is denied by default.

## Explicit non-claims

A delegation record does not prove human identity.

A delegation record does not prove legal authority.

A delegation record does not prove human consent unless a separate human approval contract exists and is referenced.

A delegation record does not prove operator approval unless signed by an operator key or linked to a signed operator approval record.

A delegation record does not create payment authority.

A delegation record does not authorize unrestricted command execution.

A delegation record does not prove job execution.

A delegation record does not issue a receipt.

A delegation record does not create an attestation by itself.

A delegation record does not create reputation or trust score by itself.

A delegation record does not prove human presence.

A delegation record is not an audit log.

A QR Pointer to a delegation record does not prove delegation by itself; it only opens the delegation verification surface.

## Authority model

Delegation v0 uses allowlisted capability-style scopes rather than raw permissions.

Initial scope families are intentionally narrow:

- `identity.read`
- `delegation.read`
- `receipt.read`
- `attestation.read`
- `trust.read`
- `job.propose`
- `message.propose`
- `operator.inspect_runtime`
- `operator.inspect_git`
- `operator.inspect_logs`
- `operator.run_smoke`
- `operator.restart_staging`
- `operator.verify_deploy`

Scopes are not shell commands. Operator scopes name future explicit tools and must never imply unrestricted command execution.

## Limits

A delegation record may include deterministic limits, such as:

- `max_requests_per_day`;
- `max_sats_per_request`;
- `max_sats_per_day`;
- `allowed_job_types`;
- `allowed_paths`;
- `not_before`;
- `expires_at`.

Absence of a limit must not be interpreted as unlimited authority. Runtime policy should fail closed when a requested action needs a limit that is missing.

## Verification model

A future verifier must:

1. Parse the record as JSON.
2. Reject unknown top-level fields unless a future schema explicitly permits them.
3. Verify `schema == hodlxxi.agent_delegation.v0`.
4. Verify `status == active` for authority use.
5. Verify `issued_at`, `not_before`, and `expires_at`.
6. Verify `issuer` and `subject` identity fields.
7. Verify that requested action is inside `authority.scopes`, `authority.resources`, and `limits`.
8. Verify canonical JSON signature over the unsigned delegation payload.
9. Verify revocation status from the current runtime surface if served later.
10. Deny by default on mismatch, missing required field, stale record, revoked status, unsupported scope, or failed signature.

## Threat model

### Overbroad delegation

A record can accidentally grant too much authority. The schema uses explicit scopes and limits, and future policy must deny anything not explicitly listed.

### Raw execution escalation

Delegation must never expose unrestricted command execution. Operator tasks must be explicit tools with bounded behavior and auditable outputs.

### Consent laundering

A delegation record can be misrepresented as human consent. The record must carry non-claims and must reference a separate human approval contract before any consent claim is made.

### QR laundering

A QR Pointer to a delegation record only opens a verification surface. Scanning the QR must not create delegation, consent, approval, trust, payment, or execution.

### Stale or revoked records

Printed or copied records can outlive their validity. Verifiers must check `status`, expiration, and future revocation surfaces.

### Identity confusion

Issuer and subject keys must be explicit. Display names are optional metadata and must not be treated as cryptographic identity.

### Third-party provider leakage

Delegation records must not place private identity data, bearer tokens, secrets, or private delegation details into third-party URLs.

## Tests

This PR adds docs/schema contract tests only.

The tests should confirm:

- the canon doc exists;
- the schema exists and is referenced;
- required identity, authority, limits, verification, signature, and non-claim fields are present;
- valid minimal delegation records pass the local contract subset;
- raw execution scopes, sensitive fields, missing non-claims, and unlimited authority markers are rejected.

## Documentation

This document is the canonical delegation v0 planning contract until a runtime endpoint exists.

Future docs must distinguish:

- delegation discovery;
- delegation verification;
- human approval;
- policy enforcement;
- execution;
- receipt issuance;
- attestation;
- audit history.

## Migration safety

No migration is included.

Future migrations must be additive and must not break existing public agent, receipt, QR Pointer, attestation, or reputation surfaces.

## Operator workflow

### Create

Draft a delegation record with issuer, subject, scopes, resources, limits, status, timestamps, verification metadata, non-claims, and signature.

### Verify

Validate the record against the schema, verify canonical signature, check status/expiration/revocation, and confirm the requested action is inside scope and limits.

### Revoke

Publish an explicit revoked status or revocation record in a future runtime surface. Do not delete historical delegation evidence silently.

### Audit

Audit delegation creation, update, and revocation separately from execution receipts and trust events.

### Rollback

For this docs/schema PR, revert the commit. For future runtime PRs, disable delegation endpoints without changing receipt verification, attestation history, or QR Pointer verifier links.

## PR breakdown/context

Recommended sequence:

1. Delegation v0 docs/schema/tests only.
2. Read-only delegation index with no active delegations.
3. Addressable delegation records backed by static fixtures or local records.
4. Delegation signature verification helper and tests.
5. QR Pointer integration with delegation records, discovery-only.
6. Policy engine enforcement for delegated requests.
7. Human approval protocol for consent-bearing actions.

## Verification procedure

For this PR:

1. Confirm only docs/schema/tests changed.
2. Confirm no runtime endpoints, capability payloads, models, migrations, QR routes, analytics, or third-party providers were added.
3. Run delegation docs/schema contract tests.
4. Run QR Pointer schema/docs tests to preserve QR non-claims.
5. Run public surface contract tests to prove existing public surfaces did not change.

## Rollback procedure

Revert the commit that adds this document, schema, and tests.

No production data, routes, migrations, or external providers are affected.

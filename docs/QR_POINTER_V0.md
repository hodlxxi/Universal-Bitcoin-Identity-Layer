# HODLXXI QR Pointer v0

## Purpose

QR Pointer v0 defines a conservative HODLXXI canon for QR codes before any runtime implementation exists.

A QR Pointer is a discovery pointer to a bounded HODLXXI runtime surface. Its purpose is to help a human or agent open a verification surface, then verify signatures, receipts, attestations, policies, or runtime metadata using the target surface itself.

QR Pointer v0 is intentionally documentation-only. It does not add a Flask route, storage table, mutable registry, analytics event, approval flow, delegation flow, payment flow, or QR image generation.

## Status

- Status: canon/docs only.
- Runtime status: not live.
- Endpoint status: no QR Pointer endpoint is added in v0.
- Schema status: `docs/schemas/qr_pointer_v0.schema.json` records the documentation-phase contract for future validation. It is not served by the runtime in v0.
- Storage status: no pointer storage or database migration is added in v0.

This document describes safety boundaries for future PRs. It must not be read as evidence that `/qr/<token>` or any QR Pointer runtime route exists.

## Definition

A QR Pointer is:

- a discovery pointer to a bounded HODLXXI runtime surface;
- optionally signed in a future schema;
- optionally revocable in a future schema;
- safe to print because it does not itself convey authority;
- safe to copy because replaying it only reopens a discovery or verification surface.

A scan is only a navigation event. The verifier must still inspect the target runtime surface and verify any signatures, receipts, attestations, policy records, or delegation records according to their own contracts.

## Non-goals

QR Pointer v0 does not implement:

- runtime routing;
- `/qr/<token>`;
- QR token storage;
- database migrations;
- external QR provider integration;
- QR analytics;
- approval behavior;
- delegation behavior;
- authorization behavior;
- execution behavior;
- payment behavior;
- receipt issuance;
- trust scoring;
- reputation updates;
- audit log creation.

## Safe target classes

A future QR Pointer may point to a bounded public HODLXXI surface when opening that surface does not itself create authority, consent, approval, payment, execution, or trust.

Conservative safe target classes include:

- `/.well-known/agent.json` for agent discovery;
- `/.well-known/hodlxxi-operator.json` for operator continuity discovery;
- `/.well-known/agent-delegation.json` only after a future PR implements that surface;
- `/agent/discovery` for agent discovery metadata;
- `/agent/capabilities` for capability discovery;
- `/agent/verify/<job_id>` for receipt verification discovery;
- `/agent/jobs/<job_id>` only when exposing the job id is privacy-safe;
- `/agent/attestations` for public attestation history;
- `/agent/trust/events` for public trust-event discovery;
- `/agent/reputation` for public aggregate history;
- `/agent/chain/health` for public chain-health discovery;
- `/agent/marketplace/listing` for directory-facing discovery;
- `/agent/skills` for public skill discovery;
- `/agent/delegations/<delegation_id>` only after delegation records exist and only when the record is safe to disclose;
- `/agent/attestations/<attestation_id>` only if that addressable attestation surface is later supported;
- `/agent/trust/events/<event_id>` only if that addressable event surface is later supported;
- `/agent/request/<request_id>` only when privacy-safe and only as a discovery surface, not as approval.

## Unsafe target classes

A QR Pointer must not point to a target where a scan or simple HTTP open is treated as:

- consent;
- approval;
- delegation;
- authorization;
- execution;
- payment;
- receipt issuance;
- attestation creation;
- trust score creation;
- reputation update;
- audit-log creation;
- account login;
- session binding;
- secret disclosure;
- private delegation data disclosure;
- mutable third-party redirect verification;
- unrestricted command execution.

## Explicit non-claims

A QR Pointer does not prove identity.

A QR Pointer does not prove human identity.

A QR Pointer does not prove consent.

A QR Pointer does not prove approval.

A QR Pointer does not prove delegation.

A QR Pointer does not prove authorization.

A QR Pointer does not prove execution.

A QR Pointer does not prove receipt validity.

A QR Pointer does not prove payment.

A QR Pointer does not prove satisfaction.

A QR Pointer does not prove obligation.

A QR Pointer does not prove trust.

A QR Pointer does not prove reputation.

A QR Pointer does not prove human presence.

A QR Pointer does not prove operator approval.

A QR Pointer does not prove that the printed QR was not substituted.

A QR Pointer does not prove that a third-party QR provider is trustworthy.

A QR Pointer is not an audit log.

## Runtime relationship

QR Pointer v0 is a canon document over existing and planned HODLXXI runtime surfaces. It does not change current public surfaces and does not advertise a live QR route.

Existing runtime surfaces remain authoritative for their own contracts, including:

- `/.well-known/agent.json`;
- `/.well-known/hodlxxi-operator.json`;
- `/agent/discovery`;
- `/agent/capabilities`;
- `/agent/request`;
- `/agent/jobs/<job_id>`;
- `/agent/verify/<job_id>`;
- `/agent/attestations`;
- `/agent/trust/events`;
- `/agent/reputation`;
- `/agent/chain/health`;
- `/agent/marketplace/listing`;
- `/agent/skills`.

Future QR Pointer work must extend existing runtime surfaces where possible. It must not redefine identity, delegation, approval, receipts, attestations, reputation, or audit semantics.

## Future endpoint direction

A future PR may introduce a read-only local landing surface such as `/qr/<token>`, but only after schema and validation tests exist.

If such a route is introduced later, it must:

- be read-only;
- resolve only to an allowlisted bounded runtime surface;
- avoid scan analytics by default;
- avoid external mutable redirects as the verification path;
- fail closed for unknown, expired, revoked, unsafe, or malformed pointers;
- state that scanning does not imply consent, approval, delegation, authorization, or trust;
- avoid creating sessions, receipts, attestations, trust scores, reputation changes, or audit events merely because a scan occurred.

This PR does not add that route.

## Future JSON schema direction

The documentation-phase schema is checked in at `docs/schemas/qr_pointer_v0.schema.json`. It is a repository contract for validation tests and future implementation planning; it is not served by the runtime in v0.

A future QR Pointer schema should remain explicit and minimal. Candidate fields include:

- `schema`: stable schema identifier;
- `pointer_id`: stable local identifier;
- `target_path`: relative HODLXXI runtime path;
- `target_class`: allowlisted class such as `agent_discovery`, `receipt_verification`, or `delegation_discovery`;
- `created_at`: RFC 3339 timestamp;
- `expires_at`: optional RFC 3339 timestamp;
- `revocation_status`: `active`, `revoked`, or `expired`;
- `non_claims`: explicit machine-readable non-claims;
- `privacy_class`: public, pseudonymous, or sensitive;
- `signature`: optional future signature over canonical JSON.

The schema should avoid embedding private identity data, private delegation data, secrets, bearer tokens, payment credentials, session identifiers, or third-party mutable redirect state.

## Pointer lifecycle

A future pointer lifecycle should be explicit:

1. Create a pointer record with a bounded target class.
2. Validate the target against the allowlist.
3. Render or export a QR code from the canonical local pointer URL or direct safe target.
4. Print or publish the pointer with non-claim language nearby when practical.
5. Verify by opening the target runtime surface and checking its native contract.
6. Revoke by marking the pointer revoked in the local registry if a registry exists.
7. Audit by reviewing pointer records and target runtime records separately.
8. Roll back by disabling the pointer route or removing the pointer from the local registry.

## Revocation semantics

Revocation of a future QR Pointer should mean that the pointer should no longer resolve as an active discovery link.

Revocation must not be overloaded to mean:

- the underlying identity is revoked;
- a human withdrew consent;
- a delegation is revoked;
- an approval is revoked;
- a receipt is invalid;
- a payment is reversed;
- a trust event is deleted;
- an audit history is erased.

A printed QR code may remain physically available after revocation. Verifiers must treat printed pointers as stale until the runtime target or pointer registry confirms current status.

## Privacy rules

A QR Pointer must not contain:

- private delegation data;
- private identity data;
- bearer tokens;
- session identifiers;
- passwords;
- API keys;
- payment secrets;
- invoice preimages;
- sensitive request payloads;
- mutable third-party redirect state required for verification.

URLs should be short, bounded, and minimally identifying. If a future pointer references a job, request, delegation, attestation, or trust event, the target must be safe to disclose to anyone who can see or copy the printed code.

## Third-party QR provider rules

Third-party QR providers are optional presentation or printing adapters only.

They must not become part of the HODLXXI trust base.

HODLXXI verification must work without the third-party provider.

A third-party provider must not be required to resolve identity, consent, approval, delegation, authorization, receipt validity, payment, trust, or reputation.

Mutable third-party redirects must not be treated as verification. If a provider URL is used for convenience, the verifier still needs to reach and inspect the bounded HODLXXI runtime surface.

Private delegation or identity data must not be placed into third-party QR URLs.

## Threat model

### QR substitution

An attacker may replace a printed QR code with another QR code. A QR Pointer does not prove that the printed code was not substituted. Operators should pair printed pointers with human-readable domain/path text and encourage verifiers to inspect the destination domain and runtime signatures.

### Mutable redirects

A mutable redirect can change after printing. HODLXXI verification must not depend on mutable third-party redirects. Prefer direct HODLXXI runtime URLs or local pointer records whose behavior is controlled by the runtime.

### Phishing

A QR can send users to a lookalike domain. UI copy should say open verification surface and verify runtime signatures, not trust the QR.

### Third-party analytics leakage

External QR providers can log scans, IP addresses, user agents, and locations. Early QR Pointer PRs must not add analytics. Export adapters must be optional and must not carry private data.

### Scan-as-consent fallacy

Scanning a code is not consent. No runtime behavior may treat a scan as consent, approval, delegation, authorization, payment, execution, or receipt acceptance.

### Identity laundering

A QR can display a legitimate-looking destination while implying stronger identity claims than the runtime proves. QR Pointer text must preserve explicit non-claims and direct verifiers to cryptographic/runtime evidence.

### Stale or revoked printed codes

Printed QR codes can outlive their intended context. Future pointer registries must support fail-closed expired or revoked states. Verifiers should prefer current runtime status over printed context.

### Privacy leaks through URL tokens

A URL token can leak through logs, screenshots, browser history, referrers, and chat previews. Pointer URLs must not contain secrets or sensitive private data.

### Replay and copy risk

Anyone can copy or replay a QR Pointer. This is acceptable only because replaying it should reopen a discovery or verification surface and should not create side effects.

### Overclaiming in UI text

Unsafe phrases can make users believe the QR is proof. Avoid phrases such as trusted QR, verified by QR, scan to approve, scan to delegate, or scan proves identity. Prefer discovery pointer, open verification surface, verify signatures and runtime surfaces, scan does not imply consent, scan does not imply approval, scan does not imply delegation, and scan does not imply trust.

## Operator workflow

### Create

Choose an existing bounded runtime surface. Confirm that opening it is safe for anyone who can copy the QR. Do not include private data or secrets.

### Print

Print the QR with human-readable destination context and non-claim language when practical. Avoid text that implies approval, delegation, identity proof, or trust.

### Verify

Open the target runtime surface. Verify the surface according to its native contract, such as checking agent metadata, signatures, receipt hashes, attestation history, or policy/delegation records once those records exist.

### Revoke

If a future pointer registry exists, mark the pointer revoked or expired. If the QR points directly to an existing runtime surface, revoke or update only the underlying object according to that object's own contract.

### Audit

Audit pointer creation and pointer registry changes separately from receipts, attestations, trust events, approvals, and delegations. A scan alone is not an audit event in v0.

### Rollback

For docs-only v0, rollback means removing or reverting this canon document. For a future runtime route, rollback should disable the pointer route or static pointer registry without affecting existing agent discovery, receipt verification, delegation, or attestation surfaces.

## Verification procedure

For v0 docs-only review:

1. Confirm this document exists.
2. Confirm it states no runtime endpoint is added in the v0 docs-only phase.
3. Confirm the repository schema validates only bounded discovery or verification pointer shapes.
4. Confirm it says a QR Pointer does not prove identity, consent, delegation, approval, trust, receipt validity, payment, obligation, or human presence.
5. Confirm no Flask routes, capabilities payloads, database models, migrations, QR storage, analytics, dependencies, or external provider integrations changed.
6. Confirm public surface contract tests still pass.

For future runtime PRs, verification must additionally prove fail-closed target validation, no scan side effects, no private-data leakage, and clear non-claim UI/API text.

## Rollback procedure

For this PR:

1. Revert the commit that adds `docs/QR_POINTER_V0.md` and any docs-contract test.
2. Confirm no runtime files changed.
3. Run the same narrow checks used for this PR.

For future runtime PRs:

1. Disable the QR Pointer route or registry.
2. Keep existing HODLXXI public surfaces available.
3. Preserve audit and receipt history.
4. Publish an operator note if printed pointers may already exist.

## PR roadmap

- PR 1 — docs/canon only.
- PR 2 — JSON Schema and validation tests.
- PR 3 — read-only local `/qr/<token>` landing surface behind a static pointer registry.
- PR 4 — integrate QR Pointer with `/agent/verify/<job_id>` as a discovery-only receipt verification link. The verifier may return a `qr_pointer` object that reopens the same verifier surface, but the pointer does not prove receipt validity or payment by itself.
- PR 5 — integrate with delegation surfaces only after delegation records exist under the Agent Delegation v0 contract.
- PR 6 — optional external QR provider/export adapter with no trust-base expansion.

## Decision gates

Before implementing any QR Pointer runtime behavior, require affirmative answers to these gates:

- Is the target a bounded runtime surface?
- Does opening the target avoid side effects?
- Does the pointer avoid private data and secrets?
- Does the UI avoid implying identity, consent, approval, delegation, authorization, trust, payment, or receipt validity?
- Can verification work without a third-party QR provider?
- Is revocation or expiry behavior explicit?
- Are replay and copy safe because they only reopen discovery or verification?
- Are tests in place before runtime implementation?
- Is rollback possible without changing unrelated public surfaces?

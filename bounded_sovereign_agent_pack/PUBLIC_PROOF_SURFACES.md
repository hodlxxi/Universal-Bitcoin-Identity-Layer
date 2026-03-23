# Public Proof Surfaces

## Purpose

Map bounded-sovereignty claims to actual public endpoints and clearly mark what already exists versus what would be new.

## Existing Public Surfaces

### Identity and discovery
- `GET /.well-known/agent.json`
- `GET /agent/capabilities`
- `GET /agent/capabilities/schema`
- `GET /agent/skills`
- `GET /agent/marketplace/listing`

### Execution and receipts
- `POST /agent/request`
- `GET /agent/jobs/<job_id>`
- `GET /agent/verify/<job_id>`

### History and integrity
- `GET /agent/attestations`
- `GET /agent/reputation`
- `GET /agent/chain/health`

## What These Surfaces Already Prove

- Stable agent identity tied to a secp256k1 pubkey.
- Signed capability payloads.
- Payment-before-completion job flow.
- Signed receipt verification for completed jobs.
- Public receipt history and simple continuity checks.

## What They Do Not Yet Prove

- Active bounded-sovereignty policy.
- Published spend budgets.
- Operator-approval state for sensitive actions.
- Publicly replayable action-decision history.
- Any runtime independence from the operator.

## Proposed New Proof Surfaces

### Policy surfaces
- `GET /agent/policy/manifest`
- `GET /agent/policy/spending`
- `GET /agent/policy/digests`

### History surfaces
- `GET /agent/actions`
- `GET /agent/actions/<action_id>`
- `GET /agent/actions/chain/health`

### Summary surface
- Extend `/agent/reputation` or `/agent/marketplace/listing` with bounded-sovereignty summary fields only after the new policy and action surfaces exist.

## Publication Rules

- New proof surfaces must reuse the existing agent identity and signature verification path where practical.
- Public summaries should explicitly mark fields as `existing_runtime_surface`, `partially_present`, or `new_surface` in docs until code lands.
- Discovery docs must not advertise bounded-sovereignty endpoints before they exist in runtime.

## Reviewer Checklist

A reviewer evaluating future bounded-sovereignty claims should be able to answer:
- What policy is active?
- What budget is active?
- Which actions are impossible versus operator-approved versus policy-allowed?
- What signed history supports the claim?
- Does the public chain remain internally consistent?

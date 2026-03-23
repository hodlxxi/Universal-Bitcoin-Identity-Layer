# Patch Targets

## Purpose

List the concrete repository files and modules that a later runtime bounded-sovereignty patch should touch, plus why each target matters.

## Existing Targets

### `wsgi.py`
- Current runtime entrypoint still imports the legacy monolith.
- Any claim about active bounded sovereignty must reflect whichever runtime entrypoint is actually deployed.

### `app/app.py`
- Legacy runtime entrypoint currently owns the WSGI app and still matters for production truth.
- If bounded-sovereignty state is surfaced in the deployed app, this file or its imports may need compatibility wiring.

### `app/factory.py`
- Registers the current blueprints and is the clean place to wire new public proof endpoints once factory runtime becomes primary.

### `app/blueprints/agent.py`
- Primary target for new public proof surfaces, policy digests, action-log summaries, and runtime enforcement hooks.
- Existing request/receipt flow already lives here.

### `app/agent_signer.py`
- Existing signing helper for capabilities and receipts.
- Likely place to reuse canonical signing helpers for manifest digests or action-log attestations.

### `app/models.py`
- Existing home of `AgentJob` and `AgentEvent`.
- Correct place for any additive `BoundedAction`/policy-state model rather than inventing a disconnected store.

### `app/payments/ln.py`
- Existing Lightning invoice creation and settlement surface.
- Relevant only for documenting budget enforcement and payment-linked action records; not for adding autonomous spend execution yet.

### `app/billing_clients.py`
- Existing PAYG budget logic for OAuth client billing.
- Useful as design precedent for decrementing balances and exposing payment-required responses.

### `docs/AGENT_SURFACES.md`
- Existing operator-facing explanation of discovery and trust surfaces.
- Must stay consistent with any new public proof endpoints or policy claims.

### `TRUST_MODEL.md`
- Existing normative trust language.
- Must remain conservative about operator binding, optional time-locked capital, and bounded-risk claims.

### `AGENT_PROTOCOL.md`
- Existing protocol contract.
- Must only advertise bounded-sovereignty surfaces after those surfaces actually exist.

## New Targets

### `tools/verify_bounded_sovereign_pack.py`
- Lightweight documentation verifier added by this PR.
- Keeps pack structure and required section names auditable.

### `bounded_sovereign_agent_pack/`
- The documentation pack itself.
- Source of truth for bounded-sovereignty design intent until runtime patches exist.

## Non-Targets For This PR
- `app/payments/ln.py` logic changes.
- Bitcoin wallet send flows.
- Deployment or infrastructure manifests.
- Root or shell execution paths.
- Broad app architecture refactors.

# Implementation Plan (8 Steps)

## Objective

Define the minimum dependency-ordered path for adding bounded operational sovereignty later without changing unrelated production behavior now.

## Dependency Notes

This order assumes the current agent runtime remains payment-gated, operator-managed, and receipt-driven. Later steps should not start until earlier policy and logging surfaces exist.

## Step 1 — Freeze the current truth
- Finalize this pack and keep it aligned with `wsgi.py`, `app/blueprints/agent.py`, `app/agent_signer.py`, `app/payments/ln.py`, and `app/models.py`.
- Treat existing code as the baseline contract.

## Step 2 — Add a policy manifest artifact
- Introduce a machine-readable policy manifest describing allowed job classes, disabled capabilities, budget ceilings, receipt requirements, and operator override rules.
- Publish whether each field is new, derived from existing runtime behavior, or aspirational.

## Step 3 — Add a spending policy artifact
- Separate monetary budget rules from general capability rules.
- Define zero-by-default behavior for wallet-spend, L1 signing, channel management, shell execution, and privileged admin operations.

## Step 4 — Extend the action history model
- Add a bounded-sovereignty action log that records proposed action, policy decision, actor type, result, and linked receipt/event hashes.
- Keep this additive to `AgentJob` and `AgentEvent`; do not replace them.

## Step 5 — Expose public proof surfaces
- Publish the active policy manifest digest, spending policy digest, and action log summaries on explicit public endpoints.
- Reuse the existing agent pubkey and receipt verification surfaces rather than inventing a second identity model.

## Step 6 — Add policy checks to selected jobs
- Start with the current `ping`, `verify_signature`, and `covenant_decode` job family as no-spend examples.
- Only after policy checks are stable should any wallet-adjacent action class be proposed.

## Step 7 — Add operator approval pathways for sensitive actions
- Require explicit operator approval for any future action class that could touch funds, secrets, system controls, or irreversible state.
- Make approvals visible in the action log.

## Step 8 — Add end-to-end verification and tests
- Verify that a third party can inspect the manifest, confirm the active limits, replay signed history, and detect unauthorized or out-of-policy actions.
- Add tests only for the minimal policy layer introduced, not a broad autonomy framework.

## Exit Criteria
- A reviewer can name the active policy, the hard spending limits, the actor that performed each action, and the signed history that backs the claim.
- No documentation claims exceed what the runtime actually enforces.

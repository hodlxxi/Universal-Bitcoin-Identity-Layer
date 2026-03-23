# Minimal Patch Sketches

## Purpose

Show the smallest credible runtime additions implied by this pack, without implementing them in this PR.

## Sketch 1 — Signed policy manifest helper
- Reuse `canonical_json_bytes`, `sign_message`, and `get_agent_pubkey_hex` from `app/agent_signer.py`.
- Build a policy manifest from the existing job registry and limits in `app/blueprints/agent.py`.
- Publish it on a new read-only endpoint.

## Sketch 2 — Additive bounded-action model
- Add one new SQLAlchemy model beside `AgentJob` and `AgentEvent` in `app/models.py`.
- Record policy decision, actor type, authority basis, and linked hashes.
- Keep it append-only.

## Sketch 3 — Enforcement wrapper around existing jobs
- Before `_job_result()` runs, evaluate requested action against the active manifest.
- For current no-spend jobs, the wrapper would mostly record allow/deny decisions rather than change behavior.

## Sketch 4 — Public digest summary
- Extend `/agent/reputation` or add a new endpoint to return current `policy_digest`, `spending_policy_digest`, and action counts.
- Keep the existing receipt surfaces unchanged.

## Sketch 5 — Operator approval record
- For any future sensitive action, add a logged approval object tied to operator identity and policy digest.
- Do not let approval bypass logging or budget checks.

## Out of Scope In This PR
- Implementing spend-capable runtime actions.
- Changing Lightning payment logic.
- Exposing wallet-send or Bitcoin Core signing routes to the agent.
- Moving production runtime from `app.app` to the factory.
- Broad architecture refactors.

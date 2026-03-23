# IMPLEMENTATION_PLAN_8_STEPS

## Step 1 — Lock runtime truth and choose the enforcement path
- **Goal:** Make bounded sovereignty changes land in the runtime actually served today.
- **Exact repo areas touched:** `wsgi.py`, `app/app.py`, `app/factory.py`, `README.md`, `docs/AGENT_SURFACES.md`.
- **Expected result:** A documented decision that first-stage sovereignty enforcement lives in the monolith-backed runtime path, with factory parity added only where safe.
- **Risk:** Low. Mostly clarification, but missing this step would cause ghost patches that never affect production.
- **Verification method:** Confirm every planned new route/helper is reachable from the path booted by `wsgi.py`.
- **Why first:** Without runtime truth, every later step can drift into a non-live codepath.
- **What should NOT be touched yet:** No route migration or factory-only rewrite.

## Step 2 — Add a policy manifest model and signer-backed publication route
- **Goal:** Publish a machine-readable signed policy document describing bounded authority.
- **Exact repo areas touched:** `app/models.py`, `app/blueprints/agent.py`, `app/agent_signer.py`, optional checked-in example under `.well-known/`.
- **Expected result:** `GET /agent/policy` (or extension of `/.well-known/agent.json`) returns a signed manifest including identity key, allowed actions, escalation-required actions, forbidden actions, spend limits, policy version, and previous-policy hash.
- **Risk:** Low to medium. Main risk is format churn if the first schema is too large.
- **Verification method:** Fetch the route, verify required fields, validate signature against the advertised agent pubkey.
- **Why second:** Every bounded action and budget event needs a policy version anchor.
- **What should NOT be touched yet:** No operational execution changes before the policy exists.

## Step 3 — Introduce an append-only action log distinct from job receipts
- **Goal:** Record sovereign operational decisions as signed history.
- **Exact repo areas touched:** `app/models.py`, `app/blueprints/agent.py`, maybe a small helper module such as `app/agent_action_log.py`.
- **Expected result:** A new append-only log path stores entries for action requests, allow/deny decisions, execution results, spend decisions, and manifest publications.
- **Risk:** Medium. Needs careful schema choice to avoid mixing user receipts with admin/operational actions ambiguously.
- **Verification method:** Create a manifest publication event and verify it appears in `GET /agent/actions` with linked continuity hashes and a valid signature.
- **Why third:** Auditability should exist before granting any new self-executed power.
- **What should NOT be touched yet:** No outbound payment execution; no log deletion/update paths.

## Step 4 — Add a central policy check function and deny-by-default decision flow
- **Goal:** Ensure all sovereign actions pass through one explicit gate.
- **Exact repo areas touched:** `app/blueprints/agent.py`, plus a new helper such as `app/agent_policy.py`.
- **Expected result:** A reusable `check_policy(action, amount, context)` function returns `allow`, `escalate`, or `deny`, and logs the decision.
- **Risk:** Medium. Existing direct route handlers may bypass it unless refactored carefully.
- **Verification method:** Unit tests for allow/deny/escalate paths across representative actions and spend categories.
- **Why fourth:** This is the enforcement core; spending and operational control should not precede it.
- **What should NOT be touched yet:** No broad access to current admin routes.

## Step 5 — Add a bounded capability executor for a narrow operational action set
- **Goal:** Give the agent limited operational control without widening it to root/admin powers.
- **Exact repo areas touched:** `app/blueprints/agent.py`, optional helper module `app/agent_capabilities.py`.
- **Expected result:** The agent can invoke only a small approved list such as `publish_policy_manifest`, `publish_budget_summary`, `publish_continuity_checkpoint`, `refresh_public_status_snapshot`, and `reconcile_inbound_treasury_funding`.
- **Risk:** Medium. The action list must remain explicitly narrow.
- **Verification method:** Each allowed action produces a signed action-log entry and any forbidden action is denied and logged.
- **Why fifth:** Once policy and logging exist, a tiny executor can safely sit on top.
- **What should NOT be touched yet:** No systemd restarts, shell execution, wallet export, or mutable log administration.

## Step 6 — Add a limited operational budget and spending policy wrapper
- **Goal:** Introduce a small treasury abstraction and limited spending authority.
- **Exact repo areas touched:** `app/models.py`, `app/payments/ln.py`, `app/blueprints/agent.py`, optional helper `app/agent_budget.py`.
- **Expected result:** The runtime can track agent budget balances, inbound funding events, reserved floor, per-period self-spend caps, and deny-by-default spend classes.
- **Risk:** High relative to earlier steps because money movement semantics become real here.
- **Verification method:** Simulate budget funding, confirm policy-limited self-spend decisions, verify that over-limit requests are denied and logged.
- **Why sixth:** Budget/spending should only be introduced after policy and append-only decision logging exist.
- **What should NOT be touched yet:** No unrestricted outbound invoice payment capability.

## Step 7 — Publish public proof surfaces for policy, budget, and continuity
- **Goal:** Turn internal bounded authority into publicly verifiable autonomy claims.
- **Exact repo areas touched:** `app/blueprints/agent.py`, `.well-known/agent.json`, `docs/AGENT_SURFACES.md`, maybe `README.md`.
- **Expected result:** Public routes expose current signed policy manifest, signed budget summary, signed action log feed, and continuity/version checkpoints.
- **Risk:** Medium. Needs careful redaction to avoid leaking secrets or operationally sensitive internals.
- **Verification method:** External verifier can fetch documents, confirm signatures, compare policy version/hash, and inspect log continuity.
- **Why seventh:** Publishing proof surfaces is more credible after the internal machinery is already implemented.
- **What should NOT be touched yet:** No overstated marketing claims about independence or decentralization.

## Step 8 — Tighten tests, docs, and freeze forbidden powers
- **Goal:** Make bounded sovereignty operationally safe and maintainable.
- **Exact repo areas touched:** `tests/`, `README.md`, `TRUST_MODEL.md`, `AGENT_PROTOCOL.md`, `docs/AGENT_SURFACES.md`.
- **Expected result:** Tests cover manifest signing, action-log continuity, deny-by-default behavior, and spend-cap enforcement; docs clearly state centralization truths and forbidden powers.
- **Risk:** Low to medium. Mostly documentation discipline and regression prevention.
- **Verification method:** New tests pass; docs consistently use “bounded operational sovereignty,” “policy-bounded authority,” and related terms.
- **Why eighth:** This locks the implementation after the minimal runtime pieces exist.
- **What should NOT be touched yet:** No architecture rewrite or migration to a totally new service boundary.

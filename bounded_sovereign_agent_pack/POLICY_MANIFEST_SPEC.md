# Policy Manifest Spec

## Purpose

Define a future machine-readable manifest that states the agent's **policy-bounded authority** in a way that can be signed, reviewed, and compared with runtime behavior.

## Current Repo Truth

- The repo already exposes signed capabilities and signed receipts.
- The repo does **not** yet expose a signed policy manifest or a policy digest endpoint.
- Current effective policy is implicit in code: supported job types, payment-before-work, daily job cap, payload-size cap, and dev-only operator override behavior.

## Proposed Artifact Status

- **New artifact:** policy manifest JSON document.
- **Partially present inputs:** job registry, pricing, limits, and trust model fields from `app/blueprints/agent.py`.
- **Existing signing surface to reuse:** `app/agent_signer.py`.

## Required Fields

### Identity
- `manifest_version`
- `agent_pubkey`
- `generated_at`
- `signature`
- `sig_scheme`

### Authority scope
- `allowed_job_types`
- `forbidden_capabilities`
- `requires_operator_approval`
- `disabled_by_default`

### Runtime guardrails
- `payment_required_before_execution`
- `max_jobs_per_day`
- `max_payload_bytes`
- `receipt_required_for_completion`
- `history_anchor_required`

### Administrative boundaries
- `wallet_spend_enabled`
- `bitcoin_core_signing_enabled`
- `shell_execution_enabled`
- `root_privilege_enabled`
- `dev_override_endpoints`

### Change control
- `policy_digest`
- `supersedes_policy_digest`
- `change_reason`
- `operator_contact`

## Normative Rules

- Default all sensitive capabilities to `false`.
- A future manifest must distinguish between "allowed without approval" and "allowed only with operator approval".
- If a capability is not listed, verifiers should treat it as disallowed.
- The manifest must be signed by the same agent identity currently used for capabilities and receipts, or explicitly publish a separate governance key relationship.

## Initial Safe Baseline

A truthful first manifest for the current repo would declare:
- only `ping`, `verify_signature`, and `covenant_decode` as allowed job types;
- payment required before completion;
- wallet spend disabled;
- Bitcoin Core signing disabled for agent autonomy;
- shell/root execution disabled;
- operator override limited to the dev-only mark-paid endpoint and not available in production mode.

## Verification Expectations

A third party should be able to:
- fetch the manifest;
- verify its signature;
- compare its limits to `/agent/capabilities`;
- compare its history requirements to `/agent/attestations` and `/agent/chain/health`;
- detect drift when the runtime exposes an unsupported action or missing guardrail.

# Action Log Spec

## Purpose

Define the minimal additive history model needed to make bounded operational sovereignty claims auditable.

## Current Repo Truth

- `AgentJob` already records requested work, payment linkage, status, and result hashes.
- `AgentEvent` already records signed receipt events and a simple hash chain.
- The repo does **not** yet have a first-class action log that records policy decisions, operator approvals, or blocked actions.

## Proposed Artifact Status

- **Existing:** `AgentJob` and `AgentEvent`.
- **New:** an additive bounded-action log model and optional public summary surface.
- **Not recommended:** replacing current receipt history.

## Required Record Shape

### Core identifiers
- `action_id`
- `job_id` (nullable only for operator-only governance actions)
- `event_hash` (nullable until a receipt exists)
- `prev_action_hash`

### Actor and authority
- `actor_type` (`agent_runtime`, `operator`, `verifier`, `system`)
- `actor_pubkey` or operator identifier
- `authority_basis` (`policy_allowed`, `operator_approved`, `denied`, `observation_only`)

### Decision and execution
- `action_type`
- `requested_capability`
- `policy_digest`
- `decision` (`allowed`, `denied`, `requires_operator_approval`, `executed`, `failed`)
- `decision_reason`
- `execution_status`

### Economic linkage
- `payment_hash`
- `sats_authorized`
- `sats_consumed`

### Integrity fields
- `timestamp`
- `action_hash`
- `signature`

## Normative Rules

- Every executed bounded-sovereignty action should create at least one action-log record.
- Sensitive denied attempts should also be logged; otherwise the public history can overstate safety.
- The action log should be append-only and hash-linked, similar to `AgentEvent`.
- A public verifier must be able to distinguish policy-allowed execution from operator-approved exceptions.

## Relationship To Existing Models

- `AgentJob` remains the request/payment record.
- `AgentEvent` remains the signed receipt record.
- The proposed action log becomes the policy-decision record that bridges the two.

## Minimal Safe Rollout

Start with action-log coverage for existing no-spend jobs only:
- record policy check pass/fail;
- link the resulting receipt hash when present;
- do not yet extend the model to unrestricted wallet or system actions.

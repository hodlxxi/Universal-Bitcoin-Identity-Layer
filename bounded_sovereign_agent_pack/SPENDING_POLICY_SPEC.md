# Spending Policy Spec

## Purpose

Define the monetary and wallet-safety constraints that must exist before any future bounded-sovereignty feature is allowed to touch funds.

## Current Repo Truth

- The current agent runtime charges for work via Lightning invoices.
- The current agent runtime does **not** autonomously spend Lightning funds, spend on-chain funds, open channels, close channels, or sign Bitcoin transactions on behalf of an autonomous policy layer.
- `app/billing_clients.py` provides a useful precedent for balance decrement logic, but it is OAuth client billing, not agent self-spend authority.

## Proposed Artifact Status

- **New artifact:** spending-policy document or JSON surface.
- **Existing related surface:** payment hashes and invoice records.
- **Not present today:** budget buckets, spend authorizations, wallet delegation, or autonomous treasury logic.

## Required Limits

### Global limits
- `daily_spend_sats`
- `per_action_spend_sats`
- `concurrent_authorizations`
- `max_unsettled_exposure_sats`

### Scope limits
- `allowed_payment_types`
- `allowed_destinations`
- `forbidden_destinations`
- `wallets_in_scope`
- `networks_in_scope`

### Approval gates
- `operator_approval_threshold_sats`
- `manual_review_required_for_new_destination`
- `manual_review_required_for_l1_signing`
- `manual_review_required_for_channel_ops`

### Hard disabled capabilities
- on-chain key export
- unrestricted Bitcoin Core wallet RPC
- arbitrary shell execution
- root privilege escalation
- unrestricted destination spend

## Normative Rules

- Default budget must be zero until an operator explicitly publishes nonzero limits.
- Spending authority should be separate from identity signing authority whenever possible.
- Any future spend-capable action must be both policy-logged and receipt-linked.
- Any runtime without a published spending policy should be treated as **non-spend-capable**, even if it can create invoices.

## Safe Initial Baseline

For the current repo, the truthful spending policy is:
- inbound invoice collection allowed;
- autonomous outbound spend disallowed;
- on-chain signing disallowed;
- channel-management actions disallowed;
- operator must remain in direct control of any wallet-sensitive operation.

## Public Verifiability Requirements

A verifier should be able to confirm:
- whether the active spend budget is zero or nonzero;
- whether the runtime can only receive payments or can also spend;
- which actions require operator approval;
- whether any historical action exceeded the published budget.

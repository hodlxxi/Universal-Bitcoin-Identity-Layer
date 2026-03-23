# SPENDING_POLICY_SPEC

## Purpose

Define the minimal safe spending model for bounded operational sovereignty in the current HODLXXI runtime.

This spec is intentionally conservative because current repo reality supports **inbound Lightning revenue**, but does **not** yet expose a safe outbound spending engine.

## Repo-grounded starting point

Current Lightning/runtime reality:

- invoice creation exists
- invoice settlement checks exist
- internal loopback invoice creation exists
- OAuth/client PAYG balance crediting exists
- no general outbound Lightning payment function is exposed in runtime code
- no safe outbound treasury policy layer exists

That means the first spending model should start with **budget accounting and authorization semantics first**, while keeping outbound payment execution disabled or tightly stubbed until policy/logging are in place.

## Budget model

Recommended minimal budget object:

```json
{
  "budget_id": "agent_ops_main",
  "currency": "sats",
  "available_sats": 0,
  "reserved_floor_sats": 0,
  "pending_inbound_sats": 0,
  "spent_24h_sats": 0,
  "spent_30d_sats": 0,
  "policy_version": "2026-03-23.1",
  "updated_at": "2026-03-23T00:00:00Z"
}
```

This can be funded from:

- agent job revenue
- explicit operator treasury top-ups
- other inbound Lightning funding recorded as treasury-funding events

## Payment classes

### 1. Self-allowed payments

These are payments the agent may eventually authorize **without per-action operator approval**, but only within tiny policy limits.

Recommended first-stage allowed classes:

- `observability_service_fee`
- `small_automation_maintenance_fee`
- `bounded_data_publication_fee`

Constraints:

- per-action cap
- hourly cap
- daily cap
- reserve floor must remain untouched
- all payments logged publicly as signed action entries

If outbound execution is not yet implemented, the policy may list these classes as “allowed in principle, execution disabled.”

### 2. Delayed or co-signed payments

These are actions that may be requested by the agent but must require countersign or operator confirmation.

Recommended classes:

- `service_provider_invoice`
- `infrastructure_topup`
- `liquidity_rebalance`
- `key_rotation_support_cost`
- any spend above self-allowed cap

Required behavior:

- log request as `escalate`
- keep execution pending until countersign approval
- publish result after approval or rejection

### 3. Forbidden payments

These must be denied by policy.

Recommended forbidden classes:

- `wallet_sweep`
- `peer_transfer`
- `operator_cashout`
- `exchange_withdrawal`
- `self_dealing_payment`
- `unclassified_payment`
- any payment missing a known spend class

## Decision logic

Recommended order:

1. verify spend class exists
2. verify class is not forbidden
3. verify policy version is active
4. verify amount is within class cap
5. verify time-window caps are respected
6. verify reserve floor remains intact
7. return `allow`, `escalate`, or `deny`
8. record signed action-log entry before final execution result publication

## Public budget proof

The runtime should publish a signed public budget summary with:

- budget ID
- available balance or redacted balance band
- reserve floor
- total inbound funded amount
- total self-spent amount
- pending escalations count
- policy version
- timestamp
- signature

If exact balance disclosure is sensitive, publish bands or capped summaries rather than raw wallet data.

## Execution guidance

### Phase 1

- implement budget ledger
- implement policy decisions
- implement action logging
- keep outbound execution disabled

### Phase 2

- add one narrow outbound payment adapter only if the operator can provision a restricted macaroon or other limited wallet credential
- enforce per-payment caps in code
- deny unknown payment classes

### Phase 3

- only after stable auditability, consider limited autonomous settlement for a tiny subset of recurring operational expenses

## Non-goals

- not a general wallet architecture
- not a multisig treasury redesign
- not a hot-wallet autonomy model
- not a claim of full financial independence

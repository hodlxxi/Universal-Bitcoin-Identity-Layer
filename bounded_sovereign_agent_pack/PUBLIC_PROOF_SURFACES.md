# PUBLIC_PROOF_SURFACES

## Purpose

Define the public endpoints/documents the agent should expose to support **publicly verifiable autonomy claims** for bounded operational sovereignty.

The goal is to extend existing surfaces, not replace them.

## Existing proof surfaces to keep

Already present and useful:

- `GET /.well-known/agent.json`
- `GET /agent/capabilities`
- `GET /agent/attestations`
- `GET /agent/reputation`
- `GET /agent/chain/health`
- `GET /agent/marketplace/listing`
- `GET /health`
- `GET /oauthx/status`
- `GET /api/public/status`

## Recommended new surfaces

### 1. `GET /agent/policy`
- **Purpose:** publish the current signed public policy manifest
- **Public or restricted:** public
- **Required fields:** `policy_version`, `effective_at`, `agent_pubkey`, `self_executed_actions`, `escalation_required_actions`, `forbidden_actions`, `spending_policy`, `previous_policy_hash`, `signature`
- **Signature expectations:** signed by agent key; optional operator countersignature block
- **Where it fits:** referenced from `/.well-known/agent.json`, `/agent/capabilities`, and `/agent/marketplace/listing`

### 2. `GET /agent/budget`
- **Purpose:** publish a signed budget statement for the limited operational budget
- **Public or restricted:** public, but may be partially redacted
- **Required fields:** `budget_id`, `currency`, `available_summary`, `reserve_floor_sats`, `spent_24h_sats`, `spent_30d_sats`, `pending_escalations`, `policy_version`, `timestamp`, `signature`
- **Signature expectations:** signed by agent key
- **Where it fits:** linked from policy manifest and marketplace listing

### 3. `GET /agent/actions`
- **Purpose:** public-safe signed action history for sovereign operational decisions
- **Public or restricted:** public, redacted projection if necessary
- **Required fields:** per-entry `timestamp`, `action.type`, `decision.result`, `result.status`, `policy_version`, `prev_entry_hash`, `signature`
- **Signature expectations:** each entry signed; feed may also expose current head hash
- **Where it fits:** sibling to `/agent/attestations`

### 4. `GET /agent/actions/chain/health`
- **Purpose:** verify continuity of the sovereign action log
- **Public or restricted:** public
- **Required fields:** `count`, `chain_ok`, `latest_entry_hash`, `latest_prev_entry_hash`, `agent_pubkey`
- **Signature expectations:** route output need not be separately signed if underlying entries are signed, but signing is preferable for snapshots
- **Where it fits:** parallel to `/agent/chain/health`

### 5. `GET /agent/continuity`
- **Purpose:** publish signed continuity/version checkpoint across manifest, receipt chain, and action-log chain
- **Public or restricted:** public
- **Required fields:** `policy_hash`, `receipt_chain_head`, `action_log_chain_head`, `software_version`, `timestamp`, `signature`
- **Signature expectations:** signed snapshot by agent key
- **Where it fits:** referenced from well-known agent document

### 6. `GET /agent/proofs`
- **Purpose:** compact directory-friendly index of all public proof surfaces
- **Public or restricted:** public
- **Required fields:** URLs for policy, capabilities, budget, action log, receipts, reputation, chain health, continuity checkpoint
- **Signature expectations:** optional; can be embedded inside `/.well-known/agent.json`
- **Where it fits:** convenience surface for third-party verifiers

## Surfaces that should remain private or partially public

### A. Detailed treasury internals

Do not publish:

- raw wallet credentials
- raw invoice preimages
- unrestricted transaction-level internal notes
- macaroon paths or secret-bearing configuration

### B. Escalation metadata

You may publish that an escalation occurred, but keep private:

- operator approval tokens
- private counterparties if unnecessary
- internal machine identifiers

### C. Full internal action payloads

Public feeds should expose enough to verify bounded autonomy claims, not enough to leak secrets or widen attack surface.

## Recommended discovery integration

Update `/.well-known/agent.json` to include a `proof_surfaces` block such as:

```json
{
  "proof_surfaces": {
    "policy": "/agent/policy",
    "budget": "/agent/budget",
    "actions": "/agent/actions",
    "actions_chain_health": "/agent/actions/chain/health",
    "receipts": "/agent/attestations",
    "receipt_chain_health": "/agent/chain/health",
    "reputation": "/agent/reputation",
    "continuity": "/agent/continuity"
  }
}
```

This keeps the proof story machine-discoverable and aligned with existing route patterns.

# POLICY_MANIFEST_SPEC

## Purpose

Define a **machine-readable public policy manifest** for the current HODLXXI agent runtime that supports **policy-bounded authority** without inventing a new protocol stack.

This manifest should be a JSON document published from the existing agent surface, ideally at `GET /agent/policy`, and referenced from both `/.well-known/agent.json` and `/agent/capabilities`.

## Design goals

- fit the current Flask + agent blueprint runtime
- reuse the existing secp256k1 agent signer
- be easy for external verifiers to fetch and validate
- express current authority truth without hype
- deny by default

## Recommended top-level fields

```json
{
  "manifest_type": "agent_policy_manifest",
  "manifest_version": "1.0",
  "policy_version": "2026-03-23.1",
  "effective_at": "2026-03-23T00:00:00Z",
  "previous_policy_hash": "hex-or-null",
  "agent_pubkey": "compressed-secp256k1-hex",
  "operator": {
    "name": "HODLXXI",
    "binding_type": "declared"
  },
  "authority_model": "bounded_operational_sovereignty",
  "runtime_scope": {
    "entrypoint": "wsgi.py -> app.app",
    "execution_surface": "/agent/*"
  },
  "self_executed_actions": [],
  "escalation_required_actions": [],
  "forbidden_actions": [],
  "spending_policy": {},
  "log_policy": {},
  "proof_surfaces": {},
  "signature": {
    "scheme": "secp256k1_ecdsa_sha256",
    "signed_fields": "canonical_json_without_signature",
    "value": "hex"
  },
  "operator_countersignature": {
    "present": false,
    "scheme": null,
    "value": null
  }
}
```

## Required semantics

### 1. Agent identity key

Required fields:

- `agent_pubkey`
- `signature.scheme`
- `signature.value`

The manifest must be signed with the same agent identity key already used for capabilities and receipts.

### 2. Allowed self-executed actions

`self_executed_actions` should list only actions the agent can take **without per-action human approval**.

Recommended first-stage list:

- `publish_policy_manifest_snapshot`
- `publish_budget_summary`
- `publish_continuity_checkpoint`
- `refresh_public_status_snapshot`
- `reconcile_inbound_treasury_funding`
- `record_policy_denial`

Each action item should include:

```json
{
  "action": "publish_budget_summary",
  "description": "Publish signed budget summary from internal ledger state",
  "max_frequency": "1/minute",
  "spend_class": "none",
  "public_log_required": true
}
```

### 3. Actions requiring co-sign / escalation

`escalation_required_actions` should identify actions that may be supported later but must not self-execute.

Recommended first-stage items:

- `change_policy_manifest`
- `rotate_agent_key_reference_metadata`
- `approve_outbound_payment_over_soft_limit`
- `rotate_public_operator_binding`
- `pause_public_execution`
- `resume_public_execution`

Each item should declare `escalation_mode`, for example `operator_countersign`, `operator_api`, or `offline_manual`.

### 4. Forbidden actions

`forbidden_actions` must be explicit and public.

Recommended initial list:

- `root_shell`
- `arbitrary_subprocess`
- `systemd_restart_service`
- `wallet_drain`
- `arbitrary_lightning_payment`
- `secret_export`
- `delete_action_log`
- `rewrite_action_history`
- `silent_policy_change`
- `disable_receipt_verification`

### 5. Spend limits

`spending_policy` should be simple and reflect current runtime realities.

Recommended structure:

```json
{
  "enabled": false,
  "currency": "sats",
  "budget_source": "lightning_inbound_revenue",
  "reserve_floor_sats": 0,
  "self_spend_limits": {
    "per_action_sats": 0,
    "per_hour_sats": 0,
    "per_day_sats": 0
  },
  "allowed_self_spend_classes": [],
  "escalation_required_spend_classes": ["all"],
  "forbidden_spend_classes": ["peer_transfer", "wallet_sweep", "exchange_withdrawal"]
}
```

At first publication, `enabled` may honestly be `false` if outbound spending is not yet implemented.

### 6. Versioning

Use both:

- `manifest_version` for schema version
- `policy_version` for policy content version

Also include:

- `effective_at`
- `previous_policy_hash`

This allows verifiers to track policy continuity.

### 7. Signature format

Use current repo conventions:

- canonical JSON serialization with sorted keys
- secp256k1 ECDSA over SHA-256
- hex-encoded signature

This matches the current signer implementation and avoids introducing a second signature stack.

## Publication guidance

- Public route: `GET /agent/policy`
- Discovery reference: add policy route to `/.well-known/agent.json` and `/agent/capabilities`
- Log requirement: every manifest publication should create a signed action-log entry with `policy_version` and `policy_hash`

## Non-goals

- not a full governance protocol
- not a multisig custody architecture
- not a DAO policy system
- not a legal authority statement

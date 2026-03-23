# ACTION_LOG_SPEC

## Purpose

Define a signed append-only log for sovereign operational decisions that complements, but does not replace, the current signed job receipt chain.

The current `AgentEvent` chain already records paid job receipts. The new action log should record **policy-governed operational actions** so observers can verify bounded authority claims over time.

## Core requirements

- append-only
- signed per entry with the existing agent key
- linked by previous-entry hash
- references the active `policy_version`
- supports public redaction-safe publication
- survives migrations without continuity loss

## Suggested entry format

```json
{
  "entry_type": "agent_action_log",
  "entry_version": "1.0",
  "entry_id": "uuid",
  "timestamp": "2026-03-23T00:00:00Z",
  "policy_version": "2026-03-23.1",
  "policy_hash": "hex",
  "prev_entry_hash": "hex-or-null",
  "request_source": {
    "type": "internal_scheduler|public_api|operator_api|manual_backfill",
    "source_id": "optional-id"
  },
  "action": {
    "type": "publish_budget_summary",
    "category": "publication",
    "requested_parameters": {
      "summary_window": "24h"
    }
  },
  "decision": {
    "result": "allow|deny|escalate",
    "reason": "policy_match|over_limit|forbidden_action|requires_countersign"
  },
  "amount": {
    "currency": "sats",
    "requested": 0,
    "approved": 0
  },
  "result": {
    "status": "success|failed|not_executed|pending_escalation",
    "code": "budget_summary_published",
    "artifact_hash": "optional-hex",
    "public_reference": "/agent/budget"
  },
  "redactions": {
    "applied": false,
    "fields": []
  },
  "signature": {
    "scheme": "secp256k1_ecdsa_sha256",
    "value": "hex"
  }
}
```

## Required fields

Each entry should include at minimum:

- `timestamp`
- `action.type`
- `request_source.type`
- `decision.result`
- `result.status`
- `policy_version`
- `prev_entry_hash`
- `signature.value`

If money is relevant, include:

- `amount.currency`
- `amount.requested`
- `amount.approved`

## Public vs restricted fields

### Public by default

These should usually be public:

- timestamp
- action type
- action category
- decision outcome
- amount class and capped amount if safe
- result status
- policy version
- continuity hashes
- signature

### May need redaction or summarization

These may need redaction in the public feed:

- internal invoice identifiers
- raw request payloads that reveal secrets
- private node topology details
- operator-only escalation notes
- private counterparties or internal hostnames

Recommendation: store a full internal entry and publish a public-safe projection that preserves:

- hash continuity
- result classification
- policy version
- signature validity

## Relationship to current receipt chain

Do not overload the existing job receipt feed with unrelated operational semantics unless schema extension is carefully managed.

Safer initial options:

1. **Parallel table / parallel route**  
   Keep `AgentEvent` for receipts and add `AgentActionLog` for sovereign actions.

2. **Shared ledger with explicit event types**  
   Expand `AgentEvent` only if the team wants one continuity chain for both job receipts and sovereign actions.

Preferred minimum-risk approach: parallel action-log table with the same linked-hash discipline.

## Continuity across migrations

To preserve continuity across schema migrations:

- include `previous_log_head_hash` in migration checkpoints
- publish a `migration_checkpoint` action entry when moving storage format
- keep old hash values stable
- never mutate historical signed payloads
- if redaction rules evolve, publish a new public projection while preserving the original entry hash internally

## Recommended routes

- `GET /agent/actions` — public-safe paginated action log
- `GET /agent/actions/<entry_id>` — single action entry view
- `GET /agent/actions/chain/health` — continuity health for action log
- `GET /agent/actions/latest` — latest head checkpoint

## Verification model

A verifier should be able to:

1. fetch current policy manifest
2. fetch action-log entries
3. validate each signature against `agent_pubkey`
4. check `prev_entry_hash` continuity
5. confirm the action outcome matches the policy version in force at that time

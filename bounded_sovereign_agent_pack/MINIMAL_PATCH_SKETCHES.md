# MINIMAL_PATCH_SKETCHES

These are **patch sketches only**, not full rewrites.

## 1. Capability executor wrapper

```python
# app/agent_policy.py
ALLOWED_SELF_ACTIONS = {
    "publish_budget_summary",
    "publish_continuity_checkpoint",
    "refresh_public_status_snapshot",
    "reconcile_inbound_treasury_funding",
}

FORBIDDEN_ACTIONS = {
    "root_shell",
    "arbitrary_subprocess",
    "wallet_drain",
    "secret_export",
    "delete_action_log",
    "silent_policy_change",
}


def check_policy(action: str, *, amount_sats: int = 0, context: dict | None = None) -> dict:
    policy = load_current_policy_manifest()

    if action in FORBIDDEN_ACTIONS:
        return {"decision": "deny", "reason": "forbidden_action", "policy_version": policy["policy_version"]}

    if action in policy["self_executed_actions"]:
        spend = check_spending_policy(action=action, amount_sats=amount_sats, policy=policy)
        if spend["decision"] != "allow":
            return {**spend, "policy_version": policy["policy_version"]}
        return {"decision": "allow", "reason": "self_allowed", "policy_version": policy["policy_version"]}

    if action in policy["escalation_required_actions"]:
        return {"decision": "escalate", "reason": "requires_countersign", "policy_version": policy["policy_version"]}

    return {"decision": "deny", "reason": "unknown_action", "policy_version": policy["policy_version"]}
```

```python
# app/blueprints/agent.py
CAPABILITY_EXECUTORS = {
    "publish_budget_summary": _publish_budget_summary,
    "publish_continuity_checkpoint": _publish_continuity_checkpoint,
    "refresh_public_status_snapshot": _refresh_public_status_snapshot,
    "reconcile_inbound_treasury_funding": _reconcile_inbound_treasury_funding,
}


def execute_bounded_action(action: str, *, params: dict, request_source: dict):
    decision = check_policy(action, amount_sats=int(params.get("amount_sats", 0) or 0), context=params)
    log_id = record_action_log(action=action, params=params, request_source=request_source, decision=decision)

    if decision["decision"] != "allow":
        return {"ok": False, "decision": decision, "action_log_id": log_id}

    handler = CAPABILITY_EXECUTORS[action]
    result = handler(params)
    finalize_action_log(log_id, result=result)
    return {"ok": True, "decision": decision, "result": result, "action_log_id": log_id}
```

## 2. Policy check function

```python
# app/agent_manifest.py

def build_policy_manifest() -> dict:
    payload = {
        "manifest_type": "agent_policy_manifest",
        "manifest_version": "1.0",
        "policy_version": current_policy_version(),
        "effective_at": iso_now(),
        "previous_policy_hash": load_previous_policy_hash(),
        "agent_pubkey": get_agent_pubkey_hex(),
        "self_executed_actions": [
            "publish_budget_summary",
            "publish_continuity_checkpoint",
            "refresh_public_status_snapshot",
            "reconcile_inbound_treasury_funding",
        ],
        "escalation_required_actions": [
            "change_policy_manifest",
            "pause_public_execution",
            "resume_public_execution",
            "approve_outbound_payment_over_soft_limit",
        ],
        "forbidden_actions": [
            "root_shell",
            "arbitrary_subprocess",
            "wallet_drain",
            "secret_export",
            "delete_action_log",
            "silent_policy_change",
        ],
        "spending_policy": build_spending_policy_block(),
    }
    payload["signature"] = sign_message(canonical_json_bytes(payload))
    return payload
```

## 3. Action log record call

```python
# app/agent_action_log.py

def record_action_log(*, action: str, params: dict, request_source: dict, decision: dict) -> str:
    prev_hash = load_latest_action_log_hash()
    entry = {
        "entry_type": "agent_action_log",
        "entry_id": str(uuid4()),
        "timestamp": iso_now(),
        "policy_version": decision["policy_version"],
        "prev_entry_hash": prev_hash,
        "request_source": request_source,
        "action": {"type": action, "requested_parameters": public_safe_params(params)},
        "decision": {"result": decision["decision"], "reason": decision["reason"]},
        "result": {"status": "pending"},
    }
    entry["signature"] = sign_message(canonical_json_bytes(entry))
    entry_hash = sha256_hex(entry)
    save_action_log(entry=entry, entry_hash=entry_hash, prev_entry_hash=prev_hash)
    return entry["entry_id"]
```

```python

def finalize_action_log(entry_id: str, *, result: dict):
    # append a second result entry rather than mutating the original if strict append-only is desired
    record_action_log(
        action="action_result",
        params={"entry_id": entry_id, "result": public_safe_params(result)},
        request_source={"type": "internal_executor"},
        decision={"decision": "allow", "reason": "result_record", "policy_version": current_policy_version()},
    )
```

## 4. Signed public manifest publication

```python
# app/blueprints/agent.py
@agent_bp.get("/agent/policy")
def agent_policy():
    return jsonify(load_or_build_signed_policy_manifest())
```

```python
# app/blueprints/agent.py -- inside /.well-known/agent.json builder
identity_doc["proof_surfaces"] = {
    "policy": "/agent/policy",
    "budget": "/agent/budget",
    "actions": "/agent/actions",
    "actions_chain_health": "/agent/actions/chain/health",
    "continuity": "/agent/continuity",
}
```

## 5. Spending check wrapper

```python
# app/agent_budget.py

def check_spending_policy(*, action: str, amount_sats: int, policy: dict) -> dict:
    spending = policy.get("spending_policy", {})
    if not spending.get("enabled"):
        return {"decision": "deny", "reason": "spending_disabled"}

    if action not in set(spending.get("allowed_self_spend_classes", [])):
        if action in set(spending.get("escalation_required_spend_classes", [])):
            return {"decision": "escalate", "reason": "spend_requires_countersign"}
        return {"decision": "deny", "reason": "unapproved_spend_class"}

    per_action_cap = int(spending.get("self_spend_limits", {}).get("per_action_sats", 0) or 0)
    if amount_sats > per_action_cap:
        return {"decision": "escalate", "reason": "over_per_action_cap"}

    budget = load_budget_state()
    reserve_floor = int(spending.get("reserve_floor_sats", 0) or 0)
    if budget.available_sats - amount_sats < reserve_floor:
        return {"decision": "deny", "reason": "reserve_floor_breach"}

    if spent_last_24h() + amount_sats > int(spending.get("self_spend_limits", {}).get("per_day_sats", 0) or 0):
        return {"decision": "deny", "reason": "daily_cap_exceeded"}

    return {"decision": "allow", "reason": "within_limits"}
```

## 6. Public budget route sketch

```python
@agent_bp.get("/agent/budget")
def public_budget_summary():
    budget = load_budget_state()
    payload = {
        "statement_type": "agent_budget_summary",
        "budget_id": budget.budget_id,
        "currency": "sats",
        "available_summary": bucketize_balance(budget.available_sats),
        "reserve_floor_sats": budget.reserve_floor_sats,
        "spent_24h_sats": budget.spent_24h_sats,
        "spent_30d_sats": budget.spent_30d_sats,
        "pending_escalations": count_pending_escalations(),
        "policy_version": current_policy_version(),
        "timestamp": iso_now(),
    }
    payload["signature"] = sign_message(canonical_json_bytes(payload))
    return jsonify(payload)
```

## 7. Important implementation note

None of these sketches should be wired to:

- arbitrary shell commands
- `systemctl`
- unrestricted Lightning payments
- wallet export or key export
- mutable history rewriting

That restraint is what keeps the design within **bounded operational sovereignty** instead of accidentally creating an unrestricted operator proxy.

from __future__ import annotations

import json
import re
from pathlib import Path

DOC = Path("docs/AGENT_DELEGATION_V0.md")
SCHEMA = Path("docs/schemas/agent_delegation_v0.schema.json")

REQUIRED_NON_CLAIMS = {
    "does_not_prove_human_consent",
    "does_not_create_payment_authority",
    "does_not_authorize_unrestricted_command_execution",
    "does_not_issue_receipt",
    "is_not_audit_log",
}


def _schema() -> dict:
    return json.loads(SCHEMA.read_text(encoding="utf-8"))


def _valid_delegation(**overrides) -> dict:
    payload = {
        "schema": "hodlxxi.agent_delegation.v0",
        "delegation_id": "deleg_docs_test_1",
        "issuer": {
            "type": "agent",
            "id": "hodlxxi-agent",
            "pubkey": "02" + "1" * 64,
            "well_known": "/.well-known/agent.json",
        },
        "subject": {
            "type": "agent",
            "id": "assistant-agent",
            "pubkey": "02" + "2" * 64,
        },
        "authority": {
            "scopes": ["identity.read", "delegation.read", "receipt.read"],
            "resources": ["/.well-known/agent.json", "/agent/verify/job-123"],
        },
        "limits": {
            "max_requests_per_day": 10,
            "max_sats_per_request": 0,
            "allowed_paths": ["/.well-known/agent.json", "/agent/verify/job-123"],
        },
        "status": "draft",
        "issued_at": "2026-06-30T00:00:00Z",
        "verification": {
            "canonicalization": "json.canonical.v1",
            "signature_scheme": "secp256k1_ecdsa_sha256",
            "signed_payload_hash": "a" * 64,
        },
        "non_claims": [
            "does_not_prove_human_identity",
            "does_not_prove_legal_authority",
            "does_not_prove_human_consent",
            "does_not_prove_operator_approval",
            "does_not_create_payment_authority",
            "does_not_authorize_unrestricted_command_execution",
            "does_not_prove_job_execution",
            "does_not_issue_receipt",
            "does_not_create_attestation",
            "does_not_create_reputation",
            "does_not_prove_human_presence",
            "is_not_audit_log",
        ],
        "signature": "placeholder-signature-for-doc-contract",
    }
    payload.update(overrides)
    return payload


def _validate_contract_subset(payload: dict, schema: dict) -> list[str]:
    errors: list[str] = []
    for key in schema["required"]:
        if key not in payload:
            errors.append(f"missing:{key}")

    allowed_keys = set(schema["properties"])
    for key in payload:
        if key not in allowed_keys:
            errors.append(f"additional:{key}")

    if payload.get("schema") != schema["properties"]["schema"]["const"]:
        errors.append("schema_const")

    delegation_id = payload.get("delegation_id", "")
    if not isinstance(delegation_id, str) or not re.match(
        schema["properties"]["delegation_id"]["pattern"], delegation_id
    ):
        errors.append("delegation_id")

    scopes = payload.get("authority", {}).get("scopes", [])
    allowed_scopes = set(schema["properties"]["authority"]["properties"]["scopes"]["items"]["enum"])
    if not scopes or len(scopes) != len(set(scopes)) or any(scope not in allowed_scopes for scope in scopes):
        errors.append("authority.scopes")

    limits = payload.get("limits", {})
    if "max_requests_per_day" not in limits:
        errors.append("limits.max_requests_per_day")
    elif not 0 <= limits["max_requests_per_day"] <= 1000:
        errors.append("limits.max_requests_per_day")

    status = payload.get("status")
    if status not in schema["properties"]["status"]["enum"]:
        errors.append("status")

    verification = payload.get("verification", {})
    if verification.get("canonicalization") != "json.canonical.v1":
        errors.append("verification.canonicalization")
    if verification.get("signature_scheme") != "secp256k1_ecdsa_sha256":
        errors.append("verification.signature_scheme")
    if not re.match("^[0-9a-f]{64}$", verification.get("signed_payload_hash", "")):
        errors.append("verification.signed_payload_hash")

    non_claims = payload.get("non_claims", [])
    allowed_non_claims = set(schema["properties"]["non_claims"]["items"]["enum"])
    if len(non_claims) < schema["properties"]["non_claims"]["minItems"]:
        errors.append("non_claims.min_items")
    if len(non_claims) != len(set(non_claims)):
        errors.append("non_claims.unique")
    if not REQUIRED_NON_CLAIMS.issubset(set(non_claims)):
        errors.append("non_claims.required_values")
    if any(item not in allowed_non_claims for item in non_claims):
        errors.append("non_claims.enum")

    forbidden_keys = {"secret", "token", "password", "private_key", "seed", "mnemonic", "raw_command", "shell", "sudo"}
    if forbidden_keys.intersection(payload):
        errors.append("forbidden_sensitive_or_raw_authority_key")

    return errors


def test_agent_delegation_v0_doc_and_schema_exist() -> None:
    assert DOC.exists()
    assert SCHEMA.exists()
    assert "docs/schemas/agent_delegation_v0.schema.json" in DOC.read_text(encoding="utf-8")


def test_agent_delegation_v0_schema_declares_bounded_signed_contract() -> None:
    schema = _schema()
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "https://hodlxxi.com/schemas/agent_delegation_v0.schema.json"
    assert schema["properties"]["schema"]["const"] == "hodlxxi.agent_delegation.v0"
    assert "signature" in schema["required"]
    assert "operator.restart_staging" in schema["properties"]["authority"]["properties"]["scopes"]["items"]["enum"]
    assert "does_not_authorize_unrestricted_command_execution" in schema["properties"]["non_claims"]["items"]["enum"]


def test_agent_delegation_v0_valid_minimal_record_shape() -> None:
    assert _validate_contract_subset(_valid_delegation(), _schema()) == []


def test_agent_delegation_v0_rejects_raw_execution_and_sensitive_fields() -> None:
    schema = _schema()
    assert "authority.scopes" in _validate_contract_subset(
        _valid_delegation(authority={"scopes": ["shell.exec"], "resources": ["/agent/verify/job-123"]}), schema
    )
    assert "forbidden_sensitive_or_raw_authority_key" in _validate_contract_subset(
        _valid_delegation(raw_command="uname -a"), schema
    )
    assert "additional:raw_command" in _validate_contract_subset(_valid_delegation(raw_command="uname -a"), schema)


def test_agent_delegation_v0_rejects_missing_limits_and_non_claims() -> None:
    schema = _schema()
    assert "limits.max_requests_per_day" in _validate_contract_subset(_valid_delegation(limits={}), schema)
    assert "non_claims.required_values" in _validate_contract_subset(
        _valid_delegation(non_claims=["does_not_prove_human_identity"] * 8), schema
    )

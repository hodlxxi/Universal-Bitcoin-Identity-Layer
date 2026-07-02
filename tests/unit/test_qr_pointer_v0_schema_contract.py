from __future__ import annotations

import json
import re
from pathlib import Path

SCHEMA = Path("docs/schemas/qr_pointer_v0.schema.json")
DOC = Path("docs/QR_POINTER_V0.md")

REQUIRED_NON_CLAIMS = {
    "does_not_prove_identity",
    "does_not_prove_consent",
    "does_not_prove_delegation",
    "does_not_prove_approval",
    "does_not_prove_trust",
}


def _schema() -> dict:
    return json.loads(SCHEMA.read_text(encoding="utf-8"))


def _valid_pointer(**overrides) -> dict:
    payload = {
        "schema": "hodlxxi.qr_pointer.v0",
        "pointer_id": "qrp-docs-test-1",
        "target_path": "/agent/verify/job-123",
        "target_class": "receipt_verification",
        "created_at": "2026-06-29T00:00:00Z",
        "revocation_status": "active",
        "privacy_class": "public",
        "non_claims": [
            "does_not_prove_identity",
            "does_not_prove_human_identity",
            "does_not_prove_consent",
            "does_not_prove_approval",
            "does_not_prove_delegation",
            "does_not_prove_authorization",
            "does_not_prove_execution",
            "does_not_prove_receipt_validity",
            "does_not_prove_payment",
            "does_not_prove_obligation",
            "does_not_prove_trust",
            "does_not_prove_human_presence",
        ],
    }
    payload.update(overrides)
    return payload


def _allowed_target_patterns(schema: dict) -> list[re.Pattern[str]]:
    patterns: list[re.Pattern[str]] = []
    for option in schema["properties"]["target_path"]["oneOf"]:
        if "const" in option:
            patterns.append(re.compile(f"^{re.escape(option['const'])}$"))
        else:
            patterns.append(re.compile(option["pattern"]))
    return patterns


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

    target = payload.get("target_path", "")
    if not isinstance(target, str) or not any(pattern.match(target) for pattern in _allowed_target_patterns(schema)):
        errors.append("target_path")

    target_class = payload.get("target_class")
    if target_class not in schema["properties"]["target_class"]["enum"]:
        errors.append("target_class")

    if payload.get("revocation_status") not in schema["properties"]["revocation_status"]["enum"]:
        errors.append("revocation_status")

    non_claims = payload.get("non_claims", [])
    allowed_non_claims = set(schema["properties"]["non_claims"]["items"]["enum"])
    if not isinstance(non_claims, list):
        errors.append("non_claims_type")
    else:
        if len(non_claims) < schema["properties"]["non_claims"]["minItems"]:
            errors.append("non_claims_min_items")
        if len(non_claims) != len(set(non_claims)):
            errors.append("non_claims_unique")
        if not REQUIRED_NON_CLAIMS.issubset(set(non_claims)):
            errors.append("non_claims_required_values")
        if any(item not in allowed_non_claims for item in non_claims):
            errors.append("non_claims_enum")

    forbidden_keys = {"secret", "token", "password", "private_key", "session_id", "analytics"}
    if forbidden_keys.intersection(payload):
        errors.append("forbidden_sensitive_key")

    return errors


def test_qr_pointer_v0_schema_exists_and_is_referenced_by_canon_doc() -> None:
    assert SCHEMA.exists()
    assert "docs/schemas/qr_pointer_v0.schema.json" in DOC.read_text(encoding="utf-8")


def test_qr_pointer_v0_schema_declares_docs_phase_contract() -> None:
    schema = _schema()
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "https://hodlxxi.com/schemas/qr_pointer_v0.schema.json"
    assert schema["properties"]["schema"]["const"] == "hodlxxi.qr_pointer.v0"
    assert "signature" not in schema["required"]


def test_qr_pointer_v0_valid_receipt_verification_pointer_shape() -> None:
    errors = _validate_contract_subset(_valid_pointer(), _schema())
    assert errors == []


def test_qr_pointer_v0_rejects_unknown_or_unsafe_targets() -> None:
    schema = _schema()
    assert "target_path" in _validate_contract_subset(_valid_pointer(target_path="/qr/raw-token"), schema)
    assert "target_path" in _validate_contract_subset(_valid_pointer(target_path="https://qr.example/redirect"), schema)
    assert "target_path" in _validate_contract_subset(_valid_pointer(target_path="/agent/request"), schema)


def test_qr_pointer_v0_rejects_missing_non_claims_and_sensitive_fields() -> None:
    schema = _schema()
    assert "non_claims_required_values" in _validate_contract_subset(
        _valid_pointer(non_claims=["does_not_prove_identity"] * 10), schema
    )
    assert "forbidden_sensitive_key" in _validate_contract_subset(_valid_pointer(token="do-not-allow"), schema)
    assert "additional:token" in _validate_contract_subset(_valid_pointer(token="do-not-allow"), schema)

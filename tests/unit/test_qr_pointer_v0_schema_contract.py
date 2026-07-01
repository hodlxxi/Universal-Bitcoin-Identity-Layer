import json
import re
from pathlib import Path

SCHEMA_PATH = Path("docs/schemas/qr_pointer_v0.schema.json")
DOC_PATH = Path("docs/QR_POINTER_V0.md")

REQUIRED_NON_CLAIMS = {
    "does_not_prove_identity",
    "does_not_prove_consent",
    "does_not_prove_delegation",
    "does_not_prove_approval",
    "does_not_prove_trust",
}

VALID_POINTER = {
    "schema": "hodlxxi.qr_pointer.v0",
    "pointer_id": "receipt-demo-01",
    "target_path": "/agent/verify/job_123",
    "target_class": "receipt_verification",
    "created_at": "2026-06-29T00:00:00Z",
    "non_claims": sorted(REQUIRED_NON_CLAIMS),
    "privacy_class": "public",
    "lifecycle": {
        "scan_side_effects": "none",
        "replay_safe": True,
        "copy_safe": True,
    },
}


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _contract_errors(pointer: dict, schema: dict) -> list[str]:
    errors: list[str] = []
    required = set(schema["required"])
    properties = schema["properties"]
    missing = required - set(pointer)
    extra = set(pointer) - set(properties)
    if missing:
        errors.append(f"missing: {sorted(missing)}")
    if extra and schema.get("additionalProperties") is False:
        errors.append(f"extra: {sorted(extra)}")
    if pointer.get("schema") != properties["schema"]["const"]:
        errors.append("schema const mismatch")
    target_path = pointer.get("target_path")
    if not isinstance(target_path, str) or not re.match(properties["target_path"]["pattern"], target_path):
        errors.append("target_path is not a bounded relative path")
    if pointer.get("target_class") not in properties["target_class"]["enum"]:
        errors.append("target_class is not allowlisted")
    non_claims = pointer.get("non_claims")
    allowed_non_claims = set(properties["non_claims"]["items"]["enum"])
    if not isinstance(non_claims, list) or not set(non_claims).issubset(allowed_non_claims):
        errors.append("non_claims contain unknown values")
    if properties["non_claims"]["contains"]["const"] not in set(non_claims or []):
        errors.append("non_claims must include identity non-claim")
    lifecycle = pointer.get("lifecycle") or {}
    if lifecycle.get("scan_side_effects") != "none":
        errors.append("scan side effects must be none")
    if lifecycle.get("replay_safe") is not True or lifecycle.get("copy_safe") is not True:
        errors.append("replay/copy must be safe")
    return errors


def test_qr_pointer_v0_schema_exists_and_is_docs_scoped() -> None:
    schema = _schema()

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "https://hodlxxi.com/schemas/qr_pointer_v0.schema.json"
    assert schema["properties"]["schema"]["const"] == "hodlxxi.qr_pointer.v0"
    assert "does not grant authority" in schema["description"].lower()


def test_qr_pointer_v0_schema_requires_bounded_pointer_fields() -> None:
    schema = _schema()
    required = set(schema["required"])

    assert {
        "schema",
        "pointer_id",
        "target_path",
        "target_class",
        "created_at",
        "non_claims",
        "privacy_class",
        "lifecycle",
    }.issubset(required)
    assert schema["properties"]["target_path"]["pattern"] == "^/[^?#]*$"
    assert schema["additionalProperties"] is False


def test_qr_pointer_v0_schema_preserves_non_claim_enum() -> None:
    schema = _schema()
    non_claims = set(schema["properties"]["non_claims"]["items"]["enum"])

    assert REQUIRED_NON_CLAIMS.issubset(non_claims)
    assert "is_not_an_audit_log" in non_claims
    assert schema["properties"]["non_claims"]["contains"]["const"] == "does_not_prove_identity"


def test_qr_pointer_v0_schema_accepts_bounded_discovery_pointer_fixture() -> None:
    assert _contract_errors(VALID_POINTER, _schema()) == []


def test_qr_pointer_v0_schema_rejects_external_or_side_effect_pointer_fixture() -> None:
    unsafe_pointer = dict(VALID_POINTER)
    unsafe_pointer["target_path"] = "https://example.com/redirect"
    unsafe_pointer["lifecycle"] = {"scan_side_effects": "analytics", "replay_safe": False, "copy_safe": False}

    errors = _contract_errors(unsafe_pointer, _schema())

    assert "target_path is not a bounded relative path" in errors
    assert "scan side effects must be none" in errors
    assert "replay/copy must be safe" in errors


def test_qr_pointer_v0_schema_has_no_runtime_endpoint_claim() -> None:
    doc = DOC_PATH.read_text(encoding="utf-8").lower()

    assert "docs/schemas/qr_pointer_v0.schema.json" in doc
    assert "not a live runtime endpoint" in doc
    assert "this pr does not add that route" in doc

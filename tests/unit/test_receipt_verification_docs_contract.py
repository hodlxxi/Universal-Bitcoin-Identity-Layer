import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_PATH = REPO_ROOT / "docs" / "RECEIPT_VERIFICATION.md"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "agent_receipt_v1"
FIXTURE_FILES = [
    "request_payload.json",
    "result_payload.json",
    "receipt_unsigned.json",
    "receipt_signed.json",
    "verification_no_receipt_409.json",
    "verification_not_found_404.json",
    "README.md",
]


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read_json(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def test_receipt_verification_doc_exists_and_covers_external_contract():
    assert DOC_PATH.exists()
    doc = DOC_PATH.read_text(encoding="utf-8")

    required_terms = [
        "canonical_json_bytes",
        "sort_keys=True",
        'separators=(",", ":")',
        "request_hash",
        "result_hash",
        "event_hash",
        "remove the top-level",
        "signature",
        "ECDSA/SHA-256",
        "agent_pubkey",
        "409",
        "no_receipt",
        "receipt_not_issued",
        "404",
        "not_found",
        "does not prove locked capital",
        "does not prove legal identity",
        "QR verification affordance",
        "QR can carry the verifier URL",
        "QR does not replace receipt verification",
        "/agent/verify/<job_id> remains the verification authority",
        "signed receipt remains the proof artifact",
        "discovery/transport only",
    ]
    for term in required_terms:
        assert term in doc


def test_current_docs_link_to_external_receipt_verification_doc():
    docs = [
        REPO_ROOT / "docs" / "AGENT_RECEIPT_V1.md",
        REPO_ROOT / "docs" / "AGENT_RECEIPT_QUICKSTART.md",
        REPO_ROOT / "docs" / "DOCUMENTATION_MAP.md",
        REPO_ROOT / "docs" / "READINESS_EVALUATION.md",
    ]
    for path in docs:
        text = path.read_text(encoding="utf-8")
        assert "docs/RECEIPT_VERIFICATION.md" in text or "RECEIPT_VERIFICATION.md" in text


def test_agent_receipt_v1_fixtures_exist_and_are_parseable():
    for name in FIXTURE_FILES:
        path = FIXTURE_DIR / name
        assert path.exists(), name
        if path.suffix == ".json":
            json.loads(path.read_text(encoding="utf-8"))


def test_receipt_fixture_hash_vectors_match_canonical_json_contract():
    request_payload = read_json("request_payload.json")
    result_payload = read_json("result_payload.json")
    receipt_unsigned = read_json("receipt_unsigned.json")
    receipt_signed = read_json("receipt_signed.json")

    request_hash = hashlib.sha256(canonical_json_bytes(request_payload)).hexdigest()
    result_hash = hashlib.sha256(canonical_json_bytes(result_payload)).hexdigest()

    assert request_hash == receipt_unsigned["request_hash"]
    assert result_hash == receipt_unsigned["result_hash"]

    for key, value in receipt_unsigned.items():
        assert receipt_signed[key] == value
    assert receipt_signed["signature"]

    event_hash = hashlib.sha256(canonical_json_bytes(receipt_signed)).hexdigest()
    docs = DOC_PATH.read_text(encoding="utf-8")
    fixture_readme = (FIXTURE_DIR / "README.md").read_text(encoding="utf-8")
    assert "event_hash = sha256(canonical_json_bytes(receipt_with_signature)).hexdigest()" in docs
    assert "event_hash = sha256(canonical_json_bytes(receipt_signed)).hexdigest()" in fixture_readme
    assert event_hash in docs
    assert event_hash in fixture_readme


def test_verifier_state_fixtures_match_current_contract():
    no_receipt = read_json("verification_no_receipt_409.json")
    not_found = read_json("verification_not_found_404.json")

    assert no_receipt["status"] == "no_receipt"
    assert no_receipt["valid"] is False
    assert no_receipt["verification"] == "unavailable"
    assert no_receipt["reason"] == "receipt_not_issued"
    assert no_receipt["receipt"] is None
    assert no_receipt["qr_pointer"]["target_path"] == f"/agent/verify/{no_receipt['job_id']}"
    assert no_receipt["qr_pointer"]["target_class"] == "receipt_verification"
    assert "does_not_prove_receipt_validity" in no_receipt["qr_pointer"]["non_claims"]

    assert not_found["error"] == "not_found"
    assert not_found["verification"] == "unavailable"

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_paid_receipt_evidence.sh"
PAID_SMOKE_DOC = ROOT / "docs" / "ops" / "PAID_EXECUTION_RECEIPT_SMOKE.md"
READINESS_DOC = ROOT / "docs" / "READINESS_EVALUATION.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_paid_receipt_evidence_verifier_script_exists_and_is_executable() -> None:
    assert SCRIPT.exists()
    assert os.access(SCRIPT, os.X_OK)


def test_paid_receipt_evidence_verifier_script_contract() -> None:
    text = read(SCRIPT)

    required_markers = [
        "set -euo pipefail",
        "need curl",
        "need jq",
        'BASE="${BASE:-https://hodlxxi.com}"',
        'JOB_ID="${JOB_ID:-1013ca86-f09e-40d3-b6ea-862620890b36}"',
        "/agent/jobs/",
        "/agent/verify/",
        "/agent/attestations?limit=50",
        "/agent/chain/health",
        "/agent/reputation",
        "529245bed836a0adf9fdd57ac46d2276e7ab85ce3e52ab8dcbb6f8ac9f9bdd44",
        "f6530836330ca1047f8d92a638c70d64597a34f299b49ef94c3aac621e1b82c1",
        "d666c1696c7b7d03e80c762aecfedfcfbd6686334045ec2b84f94f691a646c0a",
        "d7fc571c7e5c5c98146fd1f6f94eda75717d04de7438713b24a3423d204d9e9b",
        "68d8123685788df1dba5b3ed0dfc965119771faf36961ce15fe2ce",
        "STRICT_LATEST",
        "PASS: paid receipt evidence verified",
    ]

    for marker in required_markers:
        assert marker in text


def test_paid_receipt_evidence_verifier_has_no_mutating_or_secret_material_markers() -> None:
    text = read(SCRIPT)
    prohibited_markers = [
        "POST /agent/request",
        "invoice=",
        "invoice_present",
        "print_invoice",
        "ln" + "bc",
        "ln" + "tb",
        "ln" + "bcrt",
    ]

    for marker in prohibited_markers:
        assert marker not in text


def test_paid_receipt_evidence_verifier_docs_contract() -> None:
    text = f"{read(PAID_SMOKE_DOC)}\n{read(READINESS_DOC)}".lower()

    required_markers = [
        "scripts/verify_paid_receipt_evidence.sh",
        "public-only",
        "no secrets",
        "does not create a job",
        "does not pay an invoice",
        "does not prove locked capital",
        "does not prove legal identity",
    ]

    for marker in required_markers:
        assert marker in text

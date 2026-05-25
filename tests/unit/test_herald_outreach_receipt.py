import json
import subprocess
import sys
from pathlib import Path

FORBIDDEN_TERMS = [
    "send_payment",
    "payinvoice",
    "lncli payinvoice",
    "NWC_SECRET",
    "NIP47_SECRET",
    "MACAROON",
    "SEED",
    "MNEMONIC",
    "AGENT_PRIVKEY",
    "private_key",
]


def _package(queue_id: str = "heraldq_1") -> dict:
    return {
        "package_schema": "hodlxxi.herald.manual_outreach_package.v1",
        "created_at": "2026-01-01T00:00:00+00:00",
        "source_reviewed_queue": "/tmp/reviewed.json",
        "approved_count": 1,
        "action_taken": "none",
        "items": [
            {
                "queue_id": queue_id,
                "candidate_event_id": "event_1",
                "candidate_author_pubkey": "pubkey_1",
                "suggested_zap_amount_sats": 21,
                "suggested_comment": "hello",
                "proposed_action": "manual_zap_candidate",
            }
        ],
    }


def _run_receipt(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "tools/herald_outreach_receipt.py", *args],
        capture_output=True,
        text=True,
    )


def test_completed_receipt_writes_expected_schema_outcome(tmp_path: Path):
    package_path = tmp_path / "package.json"
    output_path = tmp_path / "receipt.json"
    package_path.write_text(json.dumps(_package(), indent=2), encoding="utf-8")

    proc = _run_receipt(
        "--package",
        str(package_path),
        "--output",
        str(output_path),
        "--queue-id",
        "heraldq_1",
        "--completed",
        "--operator",
        "operator",
        "--note",
        "done",
        "--external-reference",
        "ref",
    )
    assert proc.returncode == 0
    receipt = json.loads(output_path.read_text(encoding="utf-8"))
    assert receipt["receipt_schema"] == "hodlxxi.herald.manual_outreach_receipt.v1"
    assert receipt["outcome"] == "manually_completed"
    assert receipt["queue_id"] == "heraldq_1"
    assert receipt["action_taken"] == "none"
    assert receipt["software_executed_action"] is False


def test_skipped_receipt_writes_manually_skipped(tmp_path: Path):
    package_path = tmp_path / "package.json"
    output_path = tmp_path / "receipt.json"
    package_path.write_text(json.dumps(_package(), indent=2), encoding="utf-8")
    proc = _run_receipt(
        "--package", str(package_path), "--output", str(output_path), "--queue-id", "heraldq_1", "--skipped"
    )
    assert proc.returncode == 0
    receipt = json.loads(output_path.read_text(encoding="utf-8"))
    assert receipt["outcome"] == "manually_skipped"


def test_failed_receipt_writes_manually_failed(tmp_path: Path):
    package_path = tmp_path / "package.json"
    output_path = tmp_path / "receipt.json"
    package_path.write_text(json.dumps(_package(), indent=2), encoding="utf-8")
    proc = _run_receipt(
        "--package", str(package_path), "--output", str(output_path), "--queue-id", "heraldq_1", "--failed"
    )
    assert proc.returncode == 0
    receipt = json.loads(output_path.read_text(encoding="utf-8"))
    assert receipt["outcome"] == "manually_failed"


def test_input_package_not_mutated(tmp_path: Path):
    package_path = tmp_path / "package.json"
    output_path = tmp_path / "receipt.json"
    source = _package()
    package_path.write_text(json.dumps(source, indent=2, sort_keys=True), encoding="utf-8")
    before = package_path.read_text(encoding="utf-8")

    proc = _run_receipt(
        "--package", str(package_path), "--output", str(output_path), "--queue-id", "heraldq_1", "--completed"
    )
    assert proc.returncode == 0
    after = package_path.read_text(encoding="utf-8")
    assert after == before


def test_unknown_queue_id_fails_without_output(tmp_path: Path):
    package_path = tmp_path / "package.json"
    output_path = tmp_path / "receipt.json"
    package_path.write_text(json.dumps(_package(), indent=2), encoding="utf-8")
    proc = _run_receipt(
        "--package", str(package_path), "--output", str(output_path), "--queue-id", "missing", "--completed"
    )
    assert proc.returncode != 0
    assert not output_path.exists()


def test_no_outcome_flag_fails_without_output(tmp_path: Path):
    package_path = tmp_path / "package.json"
    output_path = tmp_path / "receipt.json"
    package_path.write_text(json.dumps(_package(), indent=2), encoding="utf-8")
    proc = _run_receipt("--package", str(package_path), "--output", str(output_path), "--queue-id", "heraldq_1")
    assert proc.returncode != 0
    assert not output_path.exists()


def test_multiple_outcome_flags_fail_without_output(tmp_path: Path):
    package_path = tmp_path / "package.json"
    output_path = tmp_path / "receipt.json"
    package_path.write_text(json.dumps(_package(), indent=2), encoding="utf-8")
    proc = _run_receipt(
        "--package",
        str(package_path),
        "--output",
        str(output_path),
        "--queue-id",
        "heraldq_1",
        "--completed",
        "--failed",
    )
    assert proc.returncode != 0
    assert not output_path.exists()


def test_no_forbidden_terms_in_receipt_files():
    paths = [Path("tools/herald_outreach_receipt.py"), Path("docs/HERALD_OPERATOR_APPROVAL_QUEUE.md")]
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    for term in FORBIDDEN_TERMS:
        assert term not in text

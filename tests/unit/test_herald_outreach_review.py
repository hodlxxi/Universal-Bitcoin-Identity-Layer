import json
import subprocess
import sys
from pathlib import Path


def _queue_item(queue_id: str, status: str = "pending_operator_approval") -> dict:
    return {
        "queue_id": queue_id,
        "status": status,
        "approval_required": True,
        "action_taken": "none",
    }


def _write_queue(path: Path, items: list[dict]) -> None:
    path.write_text(json.dumps(items, indent=2), encoding="utf-8")


def _run_review(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "tools/herald_outreach_review.py", *args],
        capture_output=True,
        text=True,
    )


def test_approve_one_item_changes_status_and_preserves_safety_fields(tmp_path: Path):
    queue_path = tmp_path / "queue.json"
    output_path = tmp_path / "reviewed.json"
    items = [_queue_item("heraldq_a"), _queue_item("heraldq_b")]
    _write_queue(queue_path, items)

    proc = _run_review(
        "--queue",
        str(queue_path),
        "--output",
        str(output_path),
        "--approve",
        "heraldq_a",
        "--reviewer",
        "operator",
        "--reason",
        "good fit",
    )

    assert proc.returncode == 0
    reviewed = json.loads(output_path.read_text(encoding="utf-8"))
    approved = next(x for x in reviewed if x["queue_id"] == "heraldq_a")
    assert approved["status"] == "approved_by_operator"
    assert approved["action_taken"] == "none"
    assert approved["approval_required"] is True
    assert approved["reviewed_by"] == "operator"
    assert approved["review_reason"] == "good fit"
    assert "approved_at" in approved

    unchanged = next(x for x in reviewed if x["queue_id"] == "heraldq_b")
    assert unchanged["status"] == "pending_operator_approval"

    source = json.loads(queue_path.read_text(encoding="utf-8"))
    assert source == items


def test_reject_one_item_changes_status(tmp_path: Path):
    queue_path = tmp_path / "queue.json"
    output_path = tmp_path / "reviewed.json"
    _write_queue(queue_path, [_queue_item("heraldq_a")])

    proc = _run_review("--queue", str(queue_path), "--output", str(output_path), "--reject", "heraldq_a")
    assert proc.returncode == 0

    reviewed = json.loads(output_path.read_text(encoding="utf-8"))
    assert reviewed[0]["status"] == "rejected_by_operator"
    assert reviewed[0]["action_taken"] == "none"
    assert reviewed[0]["approval_required"] is True
    assert "rejected_at" in reviewed[0]


def test_unknown_queue_id_fails_and_does_not_write_output(tmp_path: Path):
    queue_path = tmp_path / "queue.json"
    output_path = tmp_path / "reviewed.json"
    _write_queue(queue_path, [_queue_item("heraldq_a")])

    proc = _run_review("--queue", str(queue_path), "--output", str(output_path), "--approve", "heraldq_missing")
    assert proc.returncode != 0
    assert not output_path.exists()


def test_same_id_in_approve_and_reject_fails_and_no_write(tmp_path: Path):
    queue_path = tmp_path / "queue.json"
    output_path = tmp_path / "reviewed.json"
    _write_queue(queue_path, [_queue_item("heraldq_a")])

    proc = _run_review(
        "--queue",
        str(queue_path),
        "--output",
        str(output_path),
        "--approve",
        "heraldq_a",
        "--reject",
        "heraldq_a",
    )
    assert proc.returncode != 0
    assert not output_path.exists()


def test_no_ids_fails_and_no_write(tmp_path: Path):
    queue_path = tmp_path / "queue.json"
    output_path = tmp_path / "reviewed.json"
    _write_queue(queue_path, [_queue_item("heraldq_a")])

    proc = _run_review("--queue", str(queue_path), "--output", str(output_path))
    assert proc.returncode != 0
    assert not output_path.exists()


def test_cli_prints_json_summary(tmp_path: Path):
    queue_path = tmp_path / "queue.json"
    output_path = tmp_path / "reviewed.json"
    _write_queue(queue_path, [_queue_item("heraldq_a"), _queue_item("heraldq_b")])

    proc = _run_review("--queue", str(queue_path), "--output", str(output_path), "--approve", "heraldq_a")
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["approved_count"] == 1
    assert payload["rejected_count"] == 0
    assert payload["unchanged_count"] == 1
    assert payload["total_count"] == 2
    assert payload["action_taken"] == "none"


def test_no_forbidden_terms_in_p11_review_files():
    forbidden = [
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
    paths = [
        Path("tools/herald_outreach_review.py"),
        Path("docs/HERALD_OPERATOR_APPROVAL_QUEUE.md"),
        Path("examples/herald/herald_outreach_queue.example.json"),
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    for term in forbidden:
        assert term not in text

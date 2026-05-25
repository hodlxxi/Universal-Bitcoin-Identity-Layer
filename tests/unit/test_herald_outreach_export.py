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


def _reviewed_item(queue_id: str, status: str, action_taken: str = "none") -> dict:
    return {
        "queue_id": queue_id,
        "status": status,
        "action_taken": action_taken,
        "candidate_event_id": f"event_{queue_id}",
        "candidate_author_pubkey": f"pub_{queue_id}",
        "suggested_zap_amount_sats": 21,
        "suggested_comment": f"comment for {queue_id}",
        "proposed_action": "manual_zap_candidate",
        "reasons": ["reason a", "reason b"],
        "reviewed_by": "operator",
        "review_reason": "looks good",
    }


def _run_export(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "tools/herald_outreach_export.py", *args],
        capture_output=True,
        text=True,
    )


def test_export_only_approved_items_and_schema(tmp_path: Path):
    reviewed_path = tmp_path / "reviewed.json"
    json_output = tmp_path / "package.json"
    md_output = tmp_path / "package.md"

    reviewed_items = [
        _reviewed_item("a", status="approved_by_operator"),
        _reviewed_item("b", status="pending_operator_approval"),
        _reviewed_item("c", status="rejected_by_operator"),
        _reviewed_item("d", status="approved_by_operator", action_taken="already_done"),
    ]
    reviewed_path.write_text(json.dumps(reviewed_items, indent=2), encoding="utf-8")

    proc = _run_export(
        "--reviewed-queue",
        str(reviewed_path),
        "--json-output",
        str(json_output),
        "--markdown-output",
        str(md_output),
    )
    assert proc.returncode == 0

    package = json.loads(json_output.read_text(encoding="utf-8"))
    assert package["package_schema"] == "hodlxxi.herald.manual_outreach_package.v1"
    assert package["approved_count"] == 1
    assert package["action_taken"] == "none"
    assert len(package["items"]) == 1

    item = package["items"][0]
    assert item["queue_id"] == "a"
    assert item["manual_status"] == "ready_for_human_manual_action"
    assert item["action_taken"] == "none"


def test_markdown_contains_comment_and_safety_warning(tmp_path: Path):
    reviewed_path = tmp_path / "reviewed.json"
    json_output = tmp_path / "package.json"
    md_output = tmp_path / "package.md"

    reviewed_path.write_text(
        json.dumps([_reviewed_item("x", status="approved_by_operator")], indent=2),
        encoding="utf-8",
    )

    proc = _run_export(
        "--reviewed-queue",
        str(reviewed_path),
        "--json-output",
        str(json_output),
        "--markdown-output",
        str(md_output),
    )
    assert proc.returncode == 0

    md = md_output.read_text(encoding="utf-8")
    assert "comment for x" in md
    assert "Nothing has been sent, signed, published, or paid" in md


def test_no_approved_items_is_success_and_empty_package(tmp_path: Path):
    reviewed_path = tmp_path / "reviewed.json"
    json_output = tmp_path / "package.json"
    md_output = tmp_path / "package.md"

    reviewed_path.write_text(
        json.dumps([_reviewed_item("x", status="pending_operator_approval")], indent=2),
        encoding="utf-8",
    )

    proc = _run_export(
        "--reviewed-queue",
        str(reviewed_path),
        "--json-output",
        str(json_output),
        "--markdown-output",
        str(md_output),
    )
    assert proc.returncode == 0

    package = json.loads(json_output.read_text(encoding="utf-8"))
    assert package["approved_count"] == 0
    assert package["items"] == []


def test_no_forbidden_terms_in_export_files():
    paths = [
        Path("tools/herald_outreach_export.py"),
        Path("docs/HERALD_OPERATOR_APPROVAL_QUEUE.md"),
        Path("examples/herald/herald_outreach_queue.example.json"),
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    for term in FORBIDDEN_TERMS:
        assert term not in text

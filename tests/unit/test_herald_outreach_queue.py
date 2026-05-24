import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from app.services.herald_outreach_queue import (
    ACTION_TAKEN_NONE,
    QUEUE_STATUS_PENDING,
    build_outreach_queue,
    make_queue_id,
)


def _candidate(
    event_id="evt1",
    author="a" * 64,
    amount=21,
    action_taken="dry_run_candidate",
):
    return SimpleNamespace(
        event_id=event_id,
        author_pubkey=author,
        score=3.5,
        reasons=["keyword:bitcoin agent"],
        suggested_zap_amount_sats=amount,
        suggested_comment="Signal boost for Bitcoin-native agent identity.",
        action_taken=action_taken,
    )


def test_queue_id_is_deterministic():
    first = make_queue_id(
        candidate_event_id="evt",
        candidate_author_pubkey="a" * 64,
        proposed_action="zap_invite",
        suggested_zap_amount_sats=21,
    )
    second = make_queue_id(
        candidate_event_id="evt",
        candidate_author_pubkey="a" * 64,
        proposed_action="zap_invite",
        suggested_zap_amount_sats=21,
    )
    assert first == second
    assert first.startswith("heraldq_")


def test_queue_item_requires_operator_approval():
    queue = build_outreach_queue(
        candidates=[_candidate()],
        source_mode="fixture",
        created_at="2026-01-01T00:00:00+00:00",
    )

    assert len(queue) == 1
    item = queue[0]
    assert item["status"] == QUEUE_STATUS_PENDING
    assert item["approval_required"] is True
    assert item["action_taken"] == ACTION_TAKEN_NONE
    assert item["proposed_action"] == "zap_invite"
    assert "operator_approval_required" in item["safety"]["non_goals"]


def test_queue_filters_non_dry_run_candidates():
    queue = build_outreach_queue(
        candidates=[
            _candidate(event_id="good", action_taken="dry_run_candidate"),
            _candidate(event_id="skip", action_taken="skipped"),
        ],
        source_mode="fixture",
    )
    assert [item["candidate_event_id"] for item in queue] == ["good"]


def test_cli_fixture_writes_operator_queue(tmp_path: Path):
    queue_path = tmp_path / "queue.json"
    env = dict(os.environ)
    env["HERALD_DISCOVERY_STATE_FILE"] = str(tmp_path / "state.json")

    proc = subprocess.run(
        [
            sys.executable,
            "tools/herald_discovery_scan.py",
            "--fixture",
            "examples/herald/herald_fixture_events.json",
            "--write-outreach-queue",
            str(queue_path),
            "--max-queue-items",
            "10",
        ],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )

    payload = json.loads(proc.stdout)
    assert payload["source_mode"] == "fixture"
    assert payload["outreach_queue_written"] == str(queue_path)
    assert payload["outreach_queue_count"] == 3

    queue = json.loads(queue_path.read_text())
    assert len(queue) == 3
    assert {item["suggested_zap_amount_sats"] for item in queue} == {21, 69, 210}
    assert {item["status"] for item in queue} == {QUEUE_STATUS_PENDING}
    assert {item["action_taken"] for item in queue} == {ACTION_TAKEN_NONE}
    assert all(item["approval_required"] is True for item in queue)


def test_no_forbidden_terms_in_p10_files():
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
        Path("app/services/herald_outreach_queue.py"),
        Path("docs/HERALD_OPERATOR_APPROVAL_QUEUE.md"),
        Path("examples/herald/herald_outreach_queue.example.json"),
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    for term in forbidden:
        assert term not in text

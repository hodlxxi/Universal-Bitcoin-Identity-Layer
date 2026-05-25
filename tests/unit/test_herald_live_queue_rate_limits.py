import json
import os
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


def _run_scan(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["HERALD_DISCOVERY_STATE_FILE"] = str(tmp_path / "state.json")
    return subprocess.run(
        [sys.executable, "tools/herald_discovery_scan.py", *args],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )


def test_fixture_compatibility_no_filters_writes_three_items(tmp_path: Path):
    queue_path = tmp_path / "queue.json"
    proc = _run_scan(
        tmp_path,
        "--fixture",
        "examples/herald/herald_fixture_events.json",
        "--write-outreach-queue",
        str(queue_path),
        "--max-queue-items",
        "10",
    )
    payload = json.loads(proc.stdout)
    assert payload["outreach_queue_count"] == 3
    assert [c["suggested_zap_amount_sats"] for c in payload["top_candidates"][:3]] == [210, 69, 21]


def test_min_score_filters_low_score_candidate(tmp_path: Path):
    queue_path = tmp_path / "queue.json"
    proc = _run_scan(
        tmp_path,
        "--fixture",
        "examples/herald/herald_fixture_events.json",
        "--min-score",
        "5",
        "--write-outreach-queue",
        str(queue_path),
    )
    payload = json.loads(proc.stdout)
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    assert payload["skipped_by_score_count"] == 1
    assert len(queue) == 2
    assert {item["suggested_zap_amount_sats"] for item in queue} == {210, 69}


def test_dedupe_authors_keeps_highest_score(tmp_path: Path):
    queue_path = tmp_path / "queue.json"
    fixture_path = tmp_path / "dupe_fixture.json"
    fixture = json.loads(Path("examples/herald/herald_fixture_events.json").read_text(encoding="utf-8"))
    direct_idx = next(i for i, row in enumerate(fixture) if row.get("id") == "fixture_evt_direct_0004")
    fixture.append({**fixture[direct_idx], "id": "dup_direct_1"})
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    proc = _run_scan(
        tmp_path,
        "--fixture",
        str(fixture_path),
        "--dedupe-authors",
        "--write-outreach-queue",
        str(queue_path),
    )
    payload = json.loads(proc.stdout)
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    assert payload["skipped_by_dedupe_count"] >= 1
    authors = [item["candidate_author_pubkey"] for item in queue]
    assert len(authors) == len(set(authors))


def test_cooldown_skips_previous_and_updates_only_queued(tmp_path: Path):
    queue_path = tmp_path / "queue.json"
    cooldown_path = tmp_path / "cooldown.json"
    cooldown_path.write_text(
        json.dumps(
            {
                "schema": "hodlxxi.herald.live_queue_cooldown.v1",
                "updated_at": "2026-01-01T00:00:00+00:00",
                "entries": [
                    {
                        "candidate_author_pubkey": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                        "candidate_event_id": "fixture_evt_direct_0004",
                        "queued_at": "2099-01-01T00:00:00+00:00",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    proc = _run_scan(
        tmp_path,
        "--fixture",
        "examples/herald/herald_fixture_events.json",
        "--cooldown-state",
        str(cooldown_path),
        "--write-outreach-queue",
        str(queue_path),
    )
    payload = json.loads(proc.stdout)
    queue = json.loads(queue_path.read_text(encoding="utf-8"))

    assert payload["skipped_by_cooldown_count"] == 1
    assert payload["outreach_queue_count"] == 2
    assert len(queue) == 2

    cooldown = json.loads(cooldown_path.read_text(encoding="utf-8"))
    assert cooldown["schema"] == "hodlxxi.herald.live_queue_cooldown.v1"
    assert len(cooldown["entries"]) == 3


def test_live_safety_fields_present_in_cli_json(tmp_path: Path):
    proc = _run_scan(
        tmp_path,
        "--fixture",
        "examples/herald/herald_fixture_events.json",
        "--min-score",
        "3.0",
        "--dedupe-authors",
    )
    payload = json.loads(proc.stdout)
    assert "live_safety" in payload
    assert payload["live_safety"]["min_score"] == 3.0
    assert payload["live_safety"]["dedupe_authors"] is True


def test_no_forbidden_terms_in_p13_files():
    paths = [
        Path("tools/herald_discovery_scan.py"),
        Path("docs/HERALD_OPERATOR_APPROVAL_QUEUE.md"),
        Path("examples/herald/herald_fixture_events.json"),
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    for term in FORBIDDEN_TERMS:
        assert term not in text

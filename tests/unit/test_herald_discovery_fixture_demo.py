from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FORBIDDEN_TERMS = [
    "send" + "_payment",
    "pay" + "in" + "voice",
    "lncli " + "pay" + "in" + "voice",
    "nwc" + "_secret",
    "nip47" + "_secret",
    "maca" + "roon",
    "se" + "ed",
    "mnemo" + "nic",
    "agent" + "_privkey",
]


def test_fixture_file_exists_and_valid_json():
    fixture_path = Path("examples/herald/herald_fixture_events.json")
    assert fixture_path.exists()

    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    assert len(payload) >= 4


def test_cli_fixture_demo_outputs_expected_candidates(tmp_path: Path):
    fixture_path = Path("examples/herald/herald_fixture_events.json")
    state_file = tmp_path / "fixture-demo-state.json"

    env = dict(__import__("os").environ)
    env["HERALD_DISCOVERY_STATE_FILE"] = str(state_file)
    proc = subprocess.run(
        [sys.executable, "tools/herald_discovery_scan.py", "--fixture", str(fixture_path)],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )

    output = json.loads(proc.stdout)
    assert isinstance(output, dict)
    assert output["candidates_found"] >= 3

    candidates = output["top_candidates"]
    suggested_sats = {item["suggested_zap_amount_sats"] for item in candidates}
    assert {21, 69, 210}.issubset(suggested_sats)

    candidate_ids = {item["event_id"] for item in candidates}
    assert "fixture_evt_spam_0001" not in candidate_ids

    allowed_actions = {"dry_run_candidate", "skipped"}
    for row in candidates:
        assert row["action_taken"] in allowed_actions

    assert all("payment_sent" not in row for row in candidates)


def test_no_forbidden_spender_or_private_key_terms_added():
    inspected_files = [
        "tools/herald_discovery_scan.py",
        "examples/herald/herald_fixture_events.json",
        "docs/HERALD_FIXTURE_DEMO.md",
    ]
    combined = "\n".join(Path(path).read_text(encoding="utf-8").lower() for path in inspected_files)

    for term in FORBIDDEN_TERMS:
        assert term not in combined

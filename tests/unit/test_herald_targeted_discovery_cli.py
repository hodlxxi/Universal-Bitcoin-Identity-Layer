from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

FORBIDDEN_TERMS = [
    "send_payment",
    "payinvoice",
    "lncli payinvoice",
    "nwc_secret",
    "nip47_secret",
    "macaroon",
    "seed",
    "mnemonic",
    "agent_privkey",
    "private_key",
]


def _run_scan(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["HERALD_DISCOVERY_STATE_FILE"] = str(tmp_path / f"state-{uuid4().hex}.json")
    return subprocess.run(
        [sys.executable, "tools/herald_discovery_scan.py", *args],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )


def test_list_target_profiles_returns_known_profile_names(tmp_path: Path):
    proc = _run_scan(tmp_path, "--list-target-profiles")
    payload = json.loads(proc.stdout)

    assert list(payload.keys()) == [
        "bitcoin-agents",
        "identity",
        "lightning",
        "ai-agents",
        "nostr-dev",
        "volya",
    ]


def test_profile_recommended_min_score_applies_when_omitted(tmp_path: Path):
    proc = _run_scan(
        tmp_path,
        "--fixture",
        "examples/herald/herald_fixture_events.json",
        "--target-profile",
        "bitcoin-agents",
        "--target-profile",
        "volya",
    )
    payload = json.loads(proc.stdout)

    assert payload["target_profiles"] == ["bitcoin-agents", "volya"]
    assert payload["live_safety"]["min_score"] == 1.0


def test_explicit_min_score_overrides_profile_recommendation(tmp_path: Path):
    proc = _run_scan(
        tmp_path,
        "--fixture",
        "examples/herald/herald_fixture_events.json",
        "--target-profile",
        "volya",
        "--min-score",
        "5",
    )
    payload = json.loads(proc.stdout)

    assert payload["live_safety"]["min_score"] == 5.0


def test_cli_output_includes_target_profiles_search_modes_and_effective_terms(tmp_path: Path):
    proc = _run_scan(
        tmp_path,
        "--fixture",
        "examples/herald/herald_fixture_events.json",
        "--target-profile",
        "bitcoin-agents",
        "--target-profile",
        "ai-agents",
        "--search-mode",
        "mixed",
        "--search-mode",
        "mixed",
        "--search-mode",
        "hashtag",
        "--keyword",
        "custom discovery phrase",
        "--hashtag",
        "#CustomTag",
    )
    payload = json.loads(proc.stdout)

    assert payload["target_profiles"] == ["bitcoin-agents", "ai-agents"]
    assert payload["search_modes"] == ["mixed", "hashtag"]
    assert payload["effective_keywords"][-1] == "custom discovery phrase"
    assert "bitcoin agent" in payload["effective_keywords"]
    assert payload["effective_hashtags"][-1] == "customtag"
    assert "bitcoin" in payload["effective_hashtags"]


def test_fixture_compatibility_still_holds_without_profiles(tmp_path: Path):
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
    queue = json.loads(queue_path.read_text(encoding="utf-8"))

    assert payload["target_profiles"] == []
    assert payload["outreach_queue_count"] == 3
    assert [item["suggested_zap_amount_sats"] for item in payload["top_candidates"][:3]] == [210, 69, 21]
    assert [item["suggested_zap_amount_sats"] for item in queue] == [210, 69, 21]


def test_no_forbidden_spender_or_secret_terms_in_stage_7c6_files():
    paths = [
        Path("app/services/herald_discovery_profiles.py"),
        Path("tools/herald_discovery_scan.py"),
        Path("docs/HERALD_OPERATOR_APPROVAL_QUEUE.md"),
        Path("examples/herald/herald_fixture_events.json"),
    ]
    combined = "\n".join(path.read_text(encoding="utf-8").lower() for path in paths)

    for term in FORBIDDEN_TERMS:
        assert term not in combined

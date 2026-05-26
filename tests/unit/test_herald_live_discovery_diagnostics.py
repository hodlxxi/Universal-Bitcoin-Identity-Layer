import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.services.herald_nostr_discovery import (
    HeraldDiscoveryConfig,
    HeraldNostrDiscoveryEngine,
    HeraldRelayReadonlyClient,
)


class _FakeWebsocket:
    def __init__(self, messages):
        self._messages = list(messages)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def send(self, _):
        return None

    def recv(self, timeout=None):
        if self._messages:
            return self._messages.pop(0)
        return None


def _connector(messages):
    def _connect(*args, **kwargs):
        return _FakeWebsocket(messages)

    return _connect


def _event(content: str, event_id: str = "evt1"):
    return {
        "id": event_id,
        "pubkey": "a" * 64,
        "kind": 1,
        "created_at": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
        "content": content,
        "tags": [],
    }


def _run_scan(tmp_path: Path, *args: str):
    env = dict(os.environ)
    env["HERALD_DISCOVERY_STATE_FILE"] = str(tmp_path / "state.json")
    return subprocess.run(
        [sys.executable, "tools/herald_discovery_scan.py", *args], capture_output=True, text=True, check=True, env=env
    )


def test_prefilter_skips_and_counts_diagnostics():
    msg = [json.dumps(["EVENT", "sub", _event("totally unrelated")]), json.dumps(["EOSE", "sub"])]
    client = HeraldRelayReadonlyClient(relays=["wss://relay.damus.io"], websocket_connect=_connector(msg))
    rows = client.search_recent_notes(
        relays=["wss://relay.damus.io"],
        hashtags=[],
        keywords=["bitcoin"],
        since=datetime.now(timezone.utc) - timedelta(hours=24),
    )
    assert rows == []
    diag = client.diagnostics()
    assert diag["raw_events_seen"] == 1
    assert diag["keyword_prefilter_skipped"] == 1


def test_disable_prefilter_allows_event_then_engine_rejects_low_score(tmp_path: Path):
    msg = [json.dumps(["EVENT", "sub", _event("totally unrelated")]), json.dumps(["EOSE", "sub"])]
    client = HeraldRelayReadonlyClient(
        relays=["wss://relay.damus.io"], websocket_connect=_connector(msg), disable_keyword_prefilter=True
    )
    cfg = HeraldDiscoveryConfig(state_file=tmp_path / "state.json")
    cfg.min_alignment_score = 2.0
    engine = HeraldNostrDiscoveryEngine(config=cfg, relay_client=client)
    rows = engine.discover_and_evaluate()
    assert rows == []
    assert client.diagnostics()["raw_events_seen"] == 1


def test_raw_samples_truncate_content():
    content = "x" * 400
    msg = [json.dumps(["EVENT", "sub", _event(content)]), json.dumps(["EOSE", "sub"])]
    client = HeraldRelayReadonlyClient(
        relays=["wss://relay.damus.io"],
        websocket_connect=_connector(msg),
        disable_keyword_prefilter=True,
        raw_sample_size=1,
    )
    client.search_recent_notes(
        relays=["wss://relay.damus.io"],
        hashtags=[],
        keywords=["bitcoin"],
        since=datetime.now(timezone.utc) - timedelta(hours=24),
    )
    sample = client.diagnostics()["raw_samples"][0]
    assert len(sample["content_head"]) <= 180
    assert "sig" not in sample


def test_cli_keyword_override_and_relay_diagnostics_present(tmp_path: Path):
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps([_event("ubid customword appears here", "evt-custom")]), encoding="utf-8")
    out = _run_scan(tmp_path, "--fixture", str(fixture), "--keyword", "customword")
    payload = json.loads(out.stdout)
    assert payload["candidates_found"] == 1
    assert "relay_diagnostics" in payload


def test_cli_since_hours_override_reflected(tmp_path: Path):
    out = _run_scan(tmp_path, "--fixture", "examples/herald/herald_fixture_events.json", "--since-hours", "1")
    payload = json.loads(out.stdout)
    assert payload["live_safety"]["search_window_hours"] == 1

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.services.herald_nostr_discovery import HeraldRelayReadonlyClient

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
    "private" + "_key",
]


class _FakeWebSocket:
    def __init__(self, messages):
        self.messages = list(messages)
        self.sent = []

    def send(self, data):
        self.sent.append(data)

    def recv(self, timeout=None):
        if not self.messages:
            return None
        return self.messages.pop(0)


class _FakeConnect:
    def __init__(self, messages):
        self.messages = messages

    def __call__(self, *args, **kwargs):
        ws = _FakeWebSocket(self.messages)

        class _Ctx:
            def __enter__(self_non):
                return ws

            def __exit__(self_non, exc_type, exc, tb):
                return False

        return _Ctx()


def test_cli_default_still_noop_returns_zero(tmp_path: Path):
    env = dict(__import__("os").environ)
    env["HERALD_DISCOVERY_STATE_FILE"] = str(tmp_path / "state.json")
    proc = subprocess.run(
        [sys.executable, "tools/herald_discovery_scan.py"], capture_output=True, text=True, check=True, env=env
    )
    payload = json.loads(proc.stdout)
    assert payload["source_mode"] == "noop"
    assert payload["candidates_found"] == 0


def test_cli_fixture_still_returns_expected_tiers(tmp_path: Path):
    fixture_path = Path("examples/herald/herald_fixture_events.json")
    env = dict(__import__("os").environ)
    env["HERALD_DISCOVERY_STATE_FILE"] = str(tmp_path / "state.json")
    proc = subprocess.run(
        [sys.executable, "tools/herald_discovery_scan.py", "--fixture", str(fixture_path)],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    payload = json.loads(proc.stdout)
    assert payload["source_mode"] == "fixture"
    assert payload["candidates_found"] >= 3
    sats = {row["suggested_zap_amount_sats"] for row in payload["top_candidates"]}
    assert {21, 69, 210}.issubset(sats)


def test_adapter_has_no_forbidden_action_methods():
    client = HeraldRelayReadonlyClient()
    for attr in ["publish", "send_dm", "sign_event", "send_payment", "execute_zap"]:
        assert not hasattr(client, attr)


def test_adapter_normalizes_kind_1_events_only():
    messages = [
        json.dumps(
            [
                "EVENT",
                "sub",
                {"id": "bad", "pubkey": "b" * 64, "kind": 7, "created_at": 1710000000, "content": "x", "tags": []},
            ]
        ),
        json.dumps(
            [
                "EVENT",
                "sub",
                {
                    "id": "ok",
                    "pubkey": "a" * 64,
                    "kind": 1,
                    "created_at": 1710000001,
                    "content": "bitcoin agent",
                    "tags": [["t", "bitcoin"]],
                },
            ]
        ),
        json.dumps(["EOSE", "sub"]),
    ]
    client = HeraldRelayReadonlyClient(websocket_connect=_FakeConnect(messages), max_events=10, timeout_seconds=1)
    rows = client.search_recent_notes(
        relays=["wss://relay.example"],
        hashtags=["bitcoin"],
        keywords=[],
        since=__import__("datetime").datetime.fromtimestamp(1700000000, __import__("datetime").timezone.utc),
    )
    assert len(rows) == 1
    assert rows[0]["id"] == "ok"
    assert rows[0]["kind"] == 1


def test_adapter_network_errors_fail_closed():
    class _Boom:
        def __call__(self, *args, **kwargs):
            raise RuntimeError("network down")

    client = HeraldRelayReadonlyClient(websocket_connect=_Boom())
    rows = client.search_recent_notes(
        relays=["wss://relay.example"],
        hashtags=[],
        keywords=[],
        since=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
    )
    assert rows == []
    assert client.warnings


def test_no_forbidden_terms_introduced():
    inspected_files = [
        "app/services/herald_nostr_discovery.py",
        "tools/herald_discovery_scan.py",
        "docs/HERALD_RELAY_READONLY_ADAPTER.md",
    ]
    combined = "\n".join(Path(path).read_text(encoding="utf-8").lower() for path in inspected_files)
    for term in FORBIDDEN_TERMS:
        assert term not in combined

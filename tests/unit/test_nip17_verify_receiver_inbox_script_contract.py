"""NIP-17 receiver inbox verifier script contract tests."""

import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.database import session_scope
from app.models import NIP17Envelope
from scripts import nip17_verify_receiver_inbox as tool


def _hex64() -> str:
    return f"{uuid4().hex}{uuid4().hex}"


def _insert_envelope(*, receiver_pubkey: str, content: str = "DO-NOT-LEAK-CONTENT") -> str:
    event_id = _hex64()
    with session_scope() as session:
        session.add(
            NIP17Envelope(
                event_id=event_id,
                envelope_hash=_hex64(),
                wrapper_pubkey="b" * 64,
                receiver_pubkey=receiver_pubkey,
                kind=1059,
                event_created_at=1779570000,
                envelope_json={
                    "id": event_id,
                    "kind": 1059,
                    "content": content,
                    "sig": "d" * 128,
                },
                source="test",
                status="received",
                received_at=datetime.now(timezone.utc),
                metadata_json={"safe": True},
            )
        )
    return event_id


def _delete_envelopes(event_ids: list[str]) -> None:
    if not event_ids:
        return
    with session_scope() as session:
        (session.query(NIP17Envelope).filter(NIP17Envelope.event_id.in_(event_ids)).delete(synchronize_session=False))


def test_verify_receiver_inbox_returns_metadata_only(app):
    receiver = _hex64()
    other = _hex64()
    event_ids = [
        _insert_envelope(receiver_pubkey=receiver, content="DO-NOT-LEAK-CONTENT"),
        _insert_envelope(receiver_pubkey=other, content="OTHER-DO-NOT-LEAK"),
    ]

    try:
        result = tool.verify_receiver_inbox(receiver)

        assert result["ok"] is True
        assert result["receiver_pubkey_tail"] == receiver[-8:]
        assert result["total"] == 1
        assert result["count"] == 1

        item = result["items"][0]
        assert item["event_id"] == event_ids[0]
        assert item["receiver_pubkey_tail"] == receiver[-8:]
        assert item["wrapper_pubkey_tail"] == ("b" * 64)[-8:]
        assert item["kind"] == 1059
        assert item["source"] == "test"
        assert item["status"] == "received"

        rendered = json.dumps(result, sort_keys=True)
        assert "envelope_json" not in rendered
        assert "content" not in rendered.lower()
        assert "sig" not in rendered.lower()
        assert "DO-NOT-LEAK" not in rendered
    finally:
        _delete_envelopes(event_ids)


def test_verify_receiver_inbox_rejects_bad_receiver():
    with pytest.raises(ValueError):
        tool.verify_receiver_inbox("not-a-pubkey")


def test_database_target_memory_detection_and_redaction():
    assert tool._is_memory_database_url("sqlite://")
    assert tool._is_memory_database_url("sqlite:///:memory:")
    assert tool._is_memory_database_url("sqlite:///:memory")
    assert not tool._is_memory_database_url("sqlite:////srv/ubid-staging/runtime/staging.db")

    target = tool._safe_database_target("sqlite:////srv/ubid-staging/runtime/staging.db")
    redacted = tool._redact_runtime_path(target)

    assert redacted["scheme"] == "sqlite"
    assert redacted["is_memory"] is False
    assert redacted["database_path"] == "/<staging>/runtime/staging.db"
    assert "password" not in repr(redacted).lower()
    assert "username" not in repr(redacted).lower()

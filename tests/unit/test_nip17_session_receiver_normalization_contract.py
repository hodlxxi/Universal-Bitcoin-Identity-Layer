"""NIP-17 inbox lookup normalizes real session pubkeys to x-only receivers."""

from datetime import datetime, timezone
from uuid import uuid4

from app.database import session_scope
from app.models import NIP17Envelope

XONLY = "3d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
COMPRESSED = "02" + XONLY


def _hex64() -> str:
    return f"{uuid4().hex}{uuid4().hex}"


def _insert_envelope(*, receiver_pubkey: str) -> str:
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
                    "content": "DO-NOT-LEAK",
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


def test_inbox_status_maps_compressed_session_pubkey_to_xonly_receiver(app, client):
    event_id = _insert_envelope(receiver_pubkey=XONLY)

    try:
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = COMPRESSED
            sess["access_level"] = "full"

        response = client.get("/api/messages/nip17/inbox/status")

        assert response.status_code == 200
        payload = response.get_json()

        assert payload["ok"] is True
        assert payload["receiver_pubkey_supported"] is True
        assert payload["receiver_pubkey_tail"] == "59f9e923"
        assert payload["stored_envelopes"] >= 1
    finally:
        _delete_envelopes([event_id])


def test_inbox_envelopes_maps_compressed_session_pubkey_to_xonly_receiver(app, client):
    event_id = _insert_envelope(receiver_pubkey=XONLY)

    try:
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = COMPRESSED
            sess["access_level"] = "full"

        response = client.get("/api/messages/nip17/inbox/envelopes?limit=10")

        assert response.status_code == 200
        payload = response.get_json()

        assert payload["ok"] is True
        assert payload["count"] >= 1
        assert any(item["event_id"] == event_id for item in payload["items"])

        rendered = str(payload)
        assert "DO-NOT-LEAK" not in rendered
        assert "envelope_json" not in rendered
        assert "content" not in rendered.lower()
        assert "sig" not in rendered.lower()
    finally:
        _delete_envelopes([event_id])


def test_inbox_status_accepts_xonly_session_pubkey(app, client):
    event_id = _insert_envelope(receiver_pubkey=XONLY)

    try:
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = XONLY
            sess["access_level"] = "full"

        response = client.get("/api/messages/nip17/inbox/status")

        assert response.status_code == 200
        payload = response.get_json()

        assert payload["receiver_pubkey_supported"] is True
        assert payload["receiver_pubkey_tail"] == "59f9e923"
        assert payload["stored_envelopes"] >= 1
    finally:
        _delete_envelopes([event_id])


def test_inbox_status_rejects_guest_receiver_identity(app, client):
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "guest-random-abc123"
        sess["access_level"] = "limited"

    response = client.get("/api/messages/nip17/inbox/status")

    assert response.status_code == 200
    payload = response.get_json()

    assert payload["ok"] is True
    assert payload["receiver_pubkey_supported"] is False
    assert payload["receiver_pubkey_tail"] is None
    assert payload["stored_envelopes"] == 0


def test_inbox_envelopes_rejects_guest_receiver_identity(app, client):
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "anon_12345678"
        sess["access_level"] = "guest"

    response = client.get("/api/messages/nip17/inbox/envelopes?limit=10")

    assert response.status_code == 200
    payload = response.get_json()

    assert payload["ok"] is True
    assert payload["count"] == 0
    assert payload["items"] == []

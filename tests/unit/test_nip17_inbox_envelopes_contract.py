"""NIP-17 inbox metadata listing contract tests."""

from datetime import datetime, timezone
from uuid import uuid4

from app.database import session_scope
from app.models import NIP17Envelope


def _event_id() -> str:
    return f"{uuid4().hex}{uuid4().hex}"


def _insert_envelope(*, receiver_pubkey: str, content: str = "ciphertext-secret") -> str:
    event_id = _event_id()
    with session_scope() as session:
        session.add(
            NIP17Envelope(
                event_id=event_id,
                envelope_hash=event_id,
                wrapper_pubkey="b" * 64,
                receiver_pubkey=receiver_pubkey,
                kind=1059,
                event_created_at=1,
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


def test_inbox_envelopes_requires_login(client):
    response = client.get("/api/messages/nip17/inbox/envelopes")

    assert response.status_code == 401
    assert response.get_json()["error"] == "unauthorized"


def test_inbox_envelopes_returns_metadata_only_for_session_receiver(client):
    receiver = "c" * 64
    other = "e" * 64
    event_id = _insert_envelope(receiver_pubkey=receiver, content="DO-NOT-LEAK-CIPHERTEXT")
    _insert_envelope(receiver_pubkey=other, content="OTHER-DO-NOT-LEAK")

    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = receiver
        sess["access_level"] = "limited"

    response = client.get("/api/messages/nip17/inbox/envelopes")

    assert response.status_code == 200
    payload = response.get_json()

    assert payload["ok"] is True
    assert payload["receiver_pubkey"] == receiver
    assert payload["count"] == 1
    assert payload["total"] == 1

    item = payload["items"][0]
    assert item["event_id"] == event_id
    assert item["kind"] == 1059
    assert item["receiver_pubkey"] == receiver
    assert item["metadata"] == {"safe": True}

    rendered = repr(payload)
    assert "envelope_json" not in rendered
    assert "content" not in rendered.lower()
    assert "DO-NOT-LEAK-CIPHERTEXT" not in rendered
    assert "OTHER-DO-NOT-LEAK" not in rendered
    assert "sig" not in rendered.lower()


def test_inbox_envelopes_limit_validation(client):
    receiver = "c" * 64
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = receiver
        sess["access_level"] = "limited"

    response = client.get("/api/messages/nip17/inbox/envelopes?limit=0")
    assert response.status_code == 400

    response = client.get("/api/messages/nip17/inbox/envelopes?limit=101")
    assert response.status_code == 400

    response = client.get("/api/messages/nip17/inbox/envelopes?offset=-1")
    assert response.status_code == 400


def test_inbox_envelopes_integer_validation(client):
    receiver = "c" * 64
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = receiver
        sess["access_level"] = "limited"

    response = client.get("/api/messages/nip17/inbox/envelopes?limit=abc")
    assert response.status_code == 400

    response = client.get("/api/messages/nip17/inbox/envelopes?offset=abc")
    assert response.status_code == 400

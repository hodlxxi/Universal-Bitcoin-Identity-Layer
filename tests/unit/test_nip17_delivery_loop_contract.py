"""NIP-17 opaque delivery loop contract.

This proves the minimal safe runtime path:

POST opaque kind-1059 envelope
→ store without plaintext/key custody
→ authenticated receiver sees count
→ authenticated receiver sees metadata-only listing
→ other receiver does not see it

Production intake remains disabled by default; the test enables the flag only
inside the Flask test app config.
"""

from uuid import uuid4

from app.database import session_scope
from app.models import NIP17Envelope

WRAPPER_PUBKEY = "b" * 64
SIG = "d" * 128
OPAQUE_CONTENT = "DO-NOT-ECHO-OPAQUE-CIPHERTEXT"


def _hex64() -> str:
    return f"{uuid4().hex}{uuid4().hex}"


def _gift_wrap_event(*, event_id: str, receiver_pubkey: str) -> dict:
    return {
        "id": event_id,
        "pubkey": WRAPPER_PUBKEY,
        "created_at": 1779570000,
        "kind": 1059,
        "tags": [["p", receiver_pubkey]],
        "content": OPAQUE_CONTENT,
        "sig": SIG,
    }


def _delete_envelopes(event_ids: list[str]) -> None:
    if not event_ids:
        return

    with session_scope() as session:
        (session.query(NIP17Envelope).filter(NIP17Envelope.event_id.in_(event_ids)).delete(synchronize_session=False))


def test_nip17_api_delivery_loop_receiver_sees_metadata_only(app, client):
    receiver = _hex64()
    other_receiver = _hex64()
    event_id = _hex64()
    envelope = _gift_wrap_event(event_id=event_id, receiver_pubkey=receiver)

    try:
        # Production-safe default: intake is disabled unless explicitly enabled.
        disabled = client.post("/api/messages/nip17/envelopes", json={"envelope": envelope})
        assert disabled.status_code == 404
        assert disabled.get_json()["error"] == "not_found"

        app.config["NIP17_MESSAGES_ENABLED"] = True

        posted = client.post("/api/messages/nip17/envelopes", json={"envelope": envelope})
        assert posted.status_code == 202

        posted_payload = posted.get_json()
        assert posted_payload["ok"] is True
        assert posted_payload["accepted"] is True
        assert posted_payload["stored"] is True
        assert posted_payload["duplicate"] is False
        assert posted_payload["kind"] == 1059
        assert posted_payload["event_id"] == event_id
        assert posted_payload["receiver_pubkey"] == receiver
        assert posted_payload["published"] is False
        assert posted_payload["plaintext_seen"] is False

        posted_body = posted.get_data(as_text=True)
        assert OPAQUE_CONTENT not in posted_body
        assert SIG not in posted_body
        assert "envelope_json" not in posted_body
        assert '"content"' not in posted_body

        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = receiver
            sess["access_level"] = "limited"

        status = client.get("/api/messages/nip17/inbox/status")
        assert status.status_code == 200

        status_payload = status.get_json()
        assert status_payload["ok"] is True
        assert status_payload["enabled"] is True
        assert status_payload["stored_envelopes"] == 1
        assert status_payload["receiver_pubkey_supported"] is True
        assert status_payload["plaintext_storage"] is False
        assert status_payload["key_custody"] is False
        assert status_payload["ciphertext_echo"] is False
        assert status_payload["relay_publish"] is False

        listing = client.get("/api/messages/nip17/inbox/envelopes")
        assert listing.status_code == 200

        listing_payload = listing.get_json()
        assert listing_payload["ok"] is True
        assert listing_payload["receiver_pubkey"] == receiver
        assert listing_payload["total"] == 1
        assert listing_payload["count"] == 1

        item = listing_payload["items"][0]
        assert item["event_id"] == event_id
        assert item["receiver_pubkey"] == receiver
        assert item["wrapper_pubkey"] == WRAPPER_PUBKEY
        assert item["kind"] == 1059
        assert item["status"] == "received"
        assert item["source"] == "api"

        rendered_listing = repr(listing_payload)
        assert OPAQUE_CONTENT not in rendered_listing
        assert SIG not in rendered_listing
        assert "envelope_json" not in rendered_listing
        assert "content" not in rendered_listing.lower()

        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = other_receiver
            sess["access_level"] = "limited"

        other_status = client.get("/api/messages/nip17/inbox/status")
        assert other_status.status_code == 200
        assert other_status.get_json()["stored_envelopes"] == 0

        other_listing = client.get("/api/messages/nip17/inbox/envelopes")
        assert other_listing.status_code == 200

        other_payload = other_listing.get_json()
        assert other_payload["receiver_pubkey"] == other_receiver
        assert other_payload["total"] == 0
        assert other_payload["count"] == 0
        assert other_payload["items"] == []

    finally:
        _delete_envelopes([event_id])

"""NIP-17 opaque envelope API contract tests."""

import uuid

from app.services.nip17_storage import get_opaque_nip17_envelope

HEX32_A = "a" * 64
HEX32_B = "b" * 64
HEX32_C = "c" * 64
SIG = "d" * 128


def _event_id(label: str) -> str:
    """Generate an isolated 64-hex NIP-17 event id for this test invocation."""

    return uuid.uuid4().hex + uuid.uuid4().hex


def _gift_wrap_event(event_id=HEX32_A):
    return {
        "id": event_id,
        "pubkey": HEX32_B,
        "created_at": 1779570000,
        "kind": 1059,
        "tags": [["p", HEX32_C]],
        "content": "encrypted-seal-ciphertext",
        "sig": SIG,
    }


def test_nip17_envelope_route_is_registered(app):
    rules = [rule for rule in app.url_map.iter_rules() if rule.rule == "/api/messages/nip17/envelopes"]

    assert rules
    assert "POST" in rules[0].methods


def test_nip17_envelope_route_is_disabled_by_default(client):
    response = client.post("/api/messages/nip17/envelopes", json={"envelope": _gift_wrap_event("1" * 64)})

    assert response.status_code == 404
    assert response.get_json()["error"] == "not_found"


def test_nip17_envelope_route_stores_gift_wrap_when_enabled(app, client):
    app.config["NIP17_MESSAGES_ENABLED"] = True
    event_id = _event_id("stores-gift-wrap-enabled")

    response = client.post("/api/messages/nip17/envelopes", json={"envelope": _gift_wrap_event(event_id)})

    assert response.status_code == 202
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["kind"] == 1059
    assert payload["stored"] is True
    assert payload["duplicate"] is False
    assert payload["published"] is False
    assert payload["plaintext_seen"] is False
    assert payload["event_id"] == event_id
    assert payload["receiver_pubkey"] == HEX32_C

    # Never echo transport ciphertext/content back to caller.
    assert "encrypted-seal-ciphertext" not in response.get_data(as_text=True)

    stored = get_opaque_nip17_envelope(event_id)
    assert stored is not None
    assert stored["event_id"] == event_id
    assert "envelope" not in stored


def test_nip17_envelope_route_is_idempotent_by_event_id(app, client):
    app.config["NIP17_MESSAGES_ENABLED"] = True
    event_id = _event_id("rejects-invalid-envelope")
    envelope = _gift_wrap_event(event_id)

    first = client.post("/api/messages/nip17/envelopes", json={"envelope": envelope})
    second = client.post("/api/messages/nip17/envelopes", json={"envelope": envelope})

    assert first.status_code == 202
    assert second.status_code == 202
    assert first.get_json()["stored"] is True
    assert first.get_json()["duplicate"] is False
    assert second.get_json()["stored"] is False
    assert second.get_json()["duplicate"] is True


def test_nip17_envelope_route_rejects_plaintext_kind14_transport(app, client):
    app.config["NIP17_MESSAGES_ENABLED"] = True
    event_id = _event_id("rejects-plaintext-kind14")
    plaintext_event = {
        "id": event_id,
        "pubkey": HEX32_B,
        "created_at": 1779570000,
        "kind": 14,
        "tags": [["p", HEX32_C]],
        "content": "plaintext message must not be server transport",
    }

    response = client.post("/api/messages/nip17/envelopes", json={"envelope": plaintext_event})

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "invalid_nip59_gift_wrap"
    assert "kind_must_be_1059" in payload["details"]

    # Never echo plaintext body back in errors.
    assert "plaintext message" not in response.get_data(as_text=True)
    assert get_opaque_nip17_envelope(event_id, include_envelope=True) is None


def test_nip17_envelope_route_rejects_missing_envelope_object(app, client):
    app.config["NIP17_MESSAGES_ENABLED"] = True

    response = client.post("/api/messages/nip17/envelopes", json={"kind": 1059})

    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_envelope"

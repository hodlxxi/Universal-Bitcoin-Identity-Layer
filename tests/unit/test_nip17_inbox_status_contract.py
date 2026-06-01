"""NIP-17 read-only inbox status contract tests."""

from app.services.nip17_storage import store_opaque_nip17_envelope

HEX32_A = "a" * 64
HEX32_B = "b" * 64
HEX32_C = "c" * 64
HEX32_D = "d" * 64
SIG = "e" * 128


def _gift_wrap_event(event_id, receiver_pubkey=HEX32_C):
    return {
        "id": event_id,
        "pubkey": HEX32_B,
        "created_at": 1779570000,
        "kind": 1059,
        "tags": [["p", receiver_pubkey]],
        "content": "encrypted-seal-ciphertext",
        "sig": SIG,
    }


def test_nip17_inbox_status_route_is_registered(app):
    rules = [rule for rule in app.url_map.iter_rules() if rule.rule == "/api/messages/nip17/inbox/status"]

    assert rules
    assert "GET" in rules[0].methods


def test_nip17_inbox_status_requires_session(client):
    response = client.get("/api/messages/nip17/inbox/status")

    assert response.status_code == 401
    assert response.get_json()["error"] == "unauthorized"


def test_nip17_inbox_status_counts_only_logged_in_receiver(app, client):
    store_opaque_nip17_envelope(_gift_wrap_event("1" * 64, receiver_pubkey=HEX32_C), source="unit_test")
    store_opaque_nip17_envelope(_gift_wrap_event("2" * 64, receiver_pubkey=HEX32_C), source="unit_test")
    store_opaque_nip17_envelope(_gift_wrap_event("3" * 64, receiver_pubkey=HEX32_D), source="unit_test")

    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = HEX32_C
        sess["access_level"] = "full"

    response = client.get("/api/messages/nip17/inbox/status")

    assert response.status_code == 200
    payload = response.get_json()

    assert payload["ok"] is True
    assert payload["enabled"] is False
    assert payload["stored_envelopes"] == 2
    assert payload["receiver_pubkey_supported"] is True
    assert payload["receiver_pubkey_tail"] == HEX32_C[-8:]
    assert payload["plaintext_storage"] is False
    assert payload["key_custody"] is False
    assert payload["ciphertext_echo"] is False
    assert payload["relay_publish"] is False

    body = response.get_data(as_text=True)
    assert "encrypted-seal-ciphertext" not in body
    assert "envelope_json" not in body
    assert "content" not in payload


def test_nip17_inbox_status_handles_non_nostr_session_pubkey(client):
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "guest-random-abc123"
        sess["access_level"] = "guest"

    response = client.get("/api/messages/nip17/inbox/status")

    assert response.status_code == 200
    payload = response.get_json()

    assert payload["ok"] is True
    assert payload["stored_envelopes"] == 0
    assert payload["receiver_pubkey_supported"] is False
    assert payload["receiver_pubkey_tail"] is None
    assert payload["plaintext_storage"] is False
    assert payload["key_custody"] is False


def test_nip17_inbox_status_does_not_require_intake_enabled(app, client):
    app.config["NIP17_MESSAGES_ENABLED"] = False

    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = HEX32_C
        sess["access_level"] = "full"

    response = client.get("/api/messages/nip17/inbox/status")

    assert response.status_code == 200
    assert response.get_json()["enabled"] is False

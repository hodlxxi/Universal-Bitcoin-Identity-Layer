"""NIP-17 opaque envelope API contract tests."""

HEX32_A = "a" * 64
HEX32_B = "b" * 64
HEX32_C = "c" * 64
SIG = "d" * 128


def _gift_wrap_event():
    return {
        "id": HEX32_A,
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
    response = client.post("/api/messages/nip17/envelopes", json={"envelope": _gift_wrap_event()})

    assert response.status_code == 404
    assert response.get_json()["error"] == "not_found"


def test_nip17_envelope_route_accepts_gift_wrap_when_enabled(app, client):
    app.config["NIP17_MESSAGES_ENABLED"] = True

    response = client.post("/api/messages/nip17/envelopes", json={"envelope": _gift_wrap_event()})

    assert response.status_code == 202
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["kind"] == 1059
    assert payload["stored"] is False
    assert payload["published"] is False
    assert payload["plaintext_seen"] is False

    # Never echo transport ciphertext/content back to caller.
    assert "encrypted-seal-ciphertext" not in response.get_data(as_text=True)


def test_nip17_envelope_route_rejects_plaintext_kind14_transport(app, client):
    app.config["NIP17_MESSAGES_ENABLED"] = True
    plaintext_event = {
        "id": HEX32_A,
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


def test_nip17_envelope_route_rejects_missing_envelope_object(app, client):
    app.config["NIP17_MESSAGES_ENABLED"] = True

    response = client.post("/api/messages/nip17/envelopes", json={"kind": 1059})

    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_envelope"

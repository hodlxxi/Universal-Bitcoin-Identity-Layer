"""NIP-17 runtime metadata contract tests."""


def test_nip17_policy_metadata_reflects_disabled_runtime_flag(app, client, monkeypatch):
    monkeypatch.delenv("NIP17_MESSAGES_ENABLED", raising=False)
    app.config["NIP17_MESSAGES_ENABLED"] = False

    response = client.get("/.well-known/nostr-dm-policy.json")

    assert response.status_code == 200
    nip17 = response.get_json()["nip17"]

    assert nip17["enabled"] is False
    assert nip17["intake_enabled"] is False
    assert nip17["key_custody"] is False
    assert nip17["server_plaintext_storage"] is False
    assert nip17["relay_publishing"] is False
    assert nip17["accepted_transport_kind"] == 1059


def test_nip17_policy_metadata_reflects_enabled_runtime_flag(app, client):
    app.config["NIP17_MESSAGES_ENABLED"] = True

    response = client.get("/.well-known/nostr-dm-policy.json")

    assert response.status_code == 200
    nip17 = response.get_json()["nip17"]

    assert nip17["enabled"] is True
    assert nip17["intake_enabled"] is True
    assert nip17["key_custody"] is False
    assert nip17["server_plaintext_storage"] is False
    assert nip17["relay_publishing"] is False


def test_agent_capabilities_metadata_reflects_enabled_runtime_flag(app, client):
    app.config["NIP17_MESSAGES_ENABLED"] = True

    response = client.get("/agent/capabilities")

    assert response.status_code == 200
    nip17 = response.get_json()["messaging"]["nip17"]

    assert nip17["enabled"] is True
    assert nip17["intake_enabled"] is True
    assert nip17["accepted_transport_kind"] == 1059
    assert nip17["relay_publishing"] is False


def test_well_known_agent_metadata_reflects_enabled_runtime_flag(app, client):
    app.config["NIP17_MESSAGES_ENABLED"] = True

    response = client.get("/.well-known/agent.json")

    assert response.status_code == 200
    nip17 = response.get_json()["messaging"]["nip17"]

    assert nip17["enabled"] is True
    assert nip17["intake_enabled"] is True
    assert nip17["accepted_transport_kind"] == 1059
    assert nip17["relay_publishing"] is False

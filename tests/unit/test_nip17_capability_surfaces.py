"""Phase 1 NIP-17 capability and policy surface contracts."""

NIP17_POLICY_KEYS = {
    "planned",
    "enabled",
    "server_plaintext_storage",
    "key_custody",
    "supported_kinds",
    "nip44_encryption",
    "nip59_gift_wrap",
    "relay_list_kind",
}


def _assert_nip17_policy(policy: dict):
    assert set(policy) >= NIP17_POLICY_KEYS
    assert policy["planned"] is True
    assert policy["enabled"] is False
    assert policy["server_plaintext_storage"] is False
    assert policy["key_custody"] is False
    assert policy["supported_kinds"] == [14, 15]
    assert policy["nip44_encryption"] == "planned"
    assert policy["nip59_gift_wrap"] == "planned"
    assert policy["relay_list_kind"] == 10050


def test_capabilities_exposes_nip17_policy(client):
    response = client.get("/agent/capabilities")
    assert response.status_code == 200

    payload = response.get_json()
    policy = payload["messaging"]["nip17"]

    _assert_nip17_policy(policy)


def test_well_known_agent_exposes_nip17_policy(client):
    response = client.get("/.well-known/agent.json")
    assert response.status_code == 200

    payload = response.get_json()
    policy = payload["messaging"]["nip17"]

    _assert_nip17_policy(policy)


def test_nostr_dm_policy_well_known_endpoint(client):
    response = client.get("/.well-known/nostr-dm-policy.json")
    assert response.status_code == 200

    payload = response.get_json()
    assert payload["service"] == "HODLXXI"
    assert payload["version"] == "1"

    _assert_nip17_policy(payload["nip17"])

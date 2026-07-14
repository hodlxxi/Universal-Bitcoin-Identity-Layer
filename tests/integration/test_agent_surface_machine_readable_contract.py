from __future__ import annotations

SECRET_LIKE_KEYS = {
    "private_key",
    "privkey",
    "seed",
    "mnemonic",
    "xprv",
    "wif",
    "secret",
    "api_key",
    "token",
    "password",
}


def _walk_for_secret_like_keys(value, found: set[str]) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if any(hint in key.lower() for hint in SECRET_LIKE_KEYS):
                found.add(key)
            _walk_for_secret_like_keys(nested, found)
    elif isinstance(value, list):
        for item in value:
            _walk_for_secret_like_keys(item, found)


def test_well_known_contains_capabilities_and_mcp_endpoints(client):
    body = client.get("/.well-known/agent.json").get_json()
    assert "mcp" in body
    assert body["endpoints"]["capabilities"] == "/agent/capabilities"
    assert body["endpoints"]["mcp"] == "/agent/mcp"
    assert body["endpoints"]["mcp_server_card"] == "/.well-known/mcp.json"


def test_capabilities_shape_contract(client):
    body = client.get("/agent/capabilities").get_json()
    assert "mcp" in body
    assert body["endpoints"]["mcp"] == "/agent/mcp"
    assert body["endpoints"]["mcp_server_card"] == "/.well-known/mcp.json"
    assert body["capability_schema"]["version"]
    assert isinstance(body["job_types"], dict)
    assert isinstance(body["endpoints"], dict)
    assert not any("/qr/" in str(value) for value in body["endpoints"].values())
    assert isinstance(body["signature"], str) and body["signature"]


def test_capabilities_schema_required_top_level_keys_declared(client):
    schema = client.get("/agent/capabilities/schema").get_json()
    required = set(schema["required"])
    assert {"agent_pubkey", "endpoints", "job_types", "signature", "version", "timestamp"}.issubset(required)


def test_capabilities_schema_declares_mcp_contract(client):
    schema = client.get("/agent/capabilities/schema").get_json()
    mcp_schema = schema["properties"]["mcp"]
    expected_required = {
        "server_card",
        "endpoint",
        "transport",
        "protocol_version",
        "server_name",
        "server_version",
        "tool_count",
        "enabled",
        "access_mode",
        "authentication",
        "writes_enabled",
        "payments_enabled",
    }

    assert "mcp" in schema["required"]
    assert set(mcp_schema["required"]) == expected_required
    assert set(mcp_schema["properties"]) == expected_required
    assert mcp_schema["additionalProperties"] is False
    assert mcp_schema["properties"]["authentication"]["required"] == ["type"]
    assert mcp_schema["properties"]["authentication"]["additionalProperties"] is False


def test_capabilities_payload_is_compatible_with_published_schema_contract(client):
    payload = client.get("/agent/capabilities").get_json()
    schema = client.get("/agent/capabilities/schema").get_json()

    assert set(schema["required"]).issubset(payload)
    assert not (set(payload) - set(schema["properties"]))

    mcp = payload["mcp"]
    mcp_schema = schema["properties"]["mcp"]
    assert set(mcp_schema["required"]).issubset(mcp)
    assert not (set(mcp) - set(mcp_schema["properties"]))
    assert set(mcp["authentication"]) == set(mcp_schema["properties"]["authentication"]["properties"])


def test_agent_discovery_shape_contract(client):
    body = client.get("/agent/discovery").get_json()
    assert body["schema"] == "hodlxxi.agent.discovery.v1"
    assert body["agent_pubkey"]
    assert body["discovery"]["well_known_agent"] == "/.well-known/agent.json"
    assert body["discovery"]["capabilities"] == "/agent/capabilities"
    assert body["discovery"]["trust_events"] == "/agent/trust/events"
    assert body["trust_surfaces"]["events"] == "/agent/trust/events"
    assert isinstance(body["signature"], str) and body["signature"]


def test_agent_trust_events_shape_contract(client):
    body = client.get("/agent/trust/events").get_json()
    assert body["schema"] == "hodlxxi.agent.trust_events.v1"
    assert body["agent_pubkey"]
    assert isinstance(body["items"], list)
    assert isinstance(body["count"], int)
    assert body["limit"] == 20
    assert body["offset"] == 0


def test_agent_nostr_announcement_shape_contract(client):
    body = client.get("/agent/nostr/announcement").get_json()

    assert body["schema"] == "hodlxxi.agent.nostr_announcement.v1"
    assert body["agent_pubkey"]
    assert body["service_name"] == "HODLXXI Agent UBID"
    assert body["publication_status"] == "template_only_not_published"
    assert body["sig_scheme"] == "secp256k1"
    assert body["nostr"]["nip89_kind"] == 31990
    assert body["nostr"]["nip90_request_kinds"] == ["5000"]
    assert body["nostr"]["nip90_result_kinds"] == ["6000"]
    assert body["nostr"]["nip90_feedback_kind"] == 7000
    assert ["k", "5000"] in body["nostr"]["tags"]
    assert body["links"]["discovery"] == "/agent/discovery"
    assert body["links"]["capabilities"] == "/agent/capabilities"
    assert body["links"]["trust_events"] == "/agent/trust/events"
    assert body["content_template"]["web"] == "https://hodlxxi.com/agent/discovery"
    assert isinstance(body["signature"], str) and body["signature"]


def test_agent_nostr_announcement_propagates_to_capabilities_and_discovery(client):
    capabilities = client.get("/agent/capabilities").get_json()
    discovery = client.get("/agent/discovery").get_json()

    assert capabilities["endpoints"]["nostr_announcement"] == "/agent/nostr/announcement"
    assert discovery["discovery"]["nostr_announcement"] == "/agent/nostr/announcement"


def test_reputation_shape_contract(client):
    body = client.get("/agent/reputation").get_json()
    assert "completed_jobs" in body
    assert "attestations_count" in body


def test_chain_health_shape_contract(client):
    body = client.get("/agent/chain/health").get_json()
    assert "chain_ok" in body
    assert "count" in body


def test_skills_shape_contract(client):
    body = client.get("/agent/skills").get_json()
    assert isinstance(body.get("items"), list)


def test_public_surfaces_do_not_expose_secret_like_fields(client):
    surfaces = [
        "/.well-known/agent.json",
        "/agent/capabilities",
        "/agent/capabilities/schema",
        "/agent/discovery",
        "/agent/nostr/announcement",
        "/agent/trust/events",
        "/agent/reputation",
        "/agent/chain/health",
        "/agent/skills",
        "/agent/marketplace/listing",
    ]
    found: set[str] = set()
    for route in surfaces:
        payload = client.get(route).get_json()
        _walk_for_secret_like_keys(payload, found)

    assert not found, f"secret-like keys leaked in public surfaces: {sorted(found)}"


def test_capabilities_do_not_advertise_qr_or_delegation_runtime_endpoints(client):
    body = client.get("/agent/capabilities").get_json()
    serialized = str(body).lower()

    assert "/qr/" not in serialized
    assert "/.well-known/agent-delegation.json" not in serialized
    assert "/agent/delegations" not in serialized
    assert "/agent/policy" not in serialized

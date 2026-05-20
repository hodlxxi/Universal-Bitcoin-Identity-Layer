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


def test_well_known_contains_capabilities_endpoint(client):
    body = client.get("/.well-known/agent.json").get_json()
    assert body["endpoints"]["capabilities"] == "/agent/capabilities"


def test_capabilities_shape_contract(client):
    body = client.get("/agent/capabilities").get_json()
    assert body["capability_schema"]["version"]
    assert isinstance(body["job_types"], dict)
    assert isinstance(body["endpoints"], dict)
    assert isinstance(body["signature"], str) and body["signature"]


def test_capabilities_schema_required_top_level_keys_declared(client):
    schema = client.get("/agent/capabilities/schema").get_json()
    required = set(schema["required"])
    assert {"agent_pubkey", "endpoints", "job_types", "signature", "version", "timestamp"}.issubset(required)


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

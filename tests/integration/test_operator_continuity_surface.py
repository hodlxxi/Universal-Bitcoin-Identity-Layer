from __future__ import annotations

import importlib

AGENT_PUBKEY = "02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92"
OPERATOR_PUBKEY = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
OPERATOR_ENDPOINT = "/.well-known/hodlxxi-operator.json"


def test_operator_continuity_endpoint_contract(client):
    response = client.get(OPERATOR_ENDPOINT)

    assert response.status_code == 200
    assert response.is_json
    body = response.get_json()
    assert body["schema"] == "hodlxxi.operator_continuity.v1"
    assert body["operator_id"] == "E923"
    assert body["operator_pubkey"] == OPERATOR_PUBKEY
    assert body["agent_pubkey"] == AGENT_PUBKEY
    assert body["covenant"]["status"] == "declared_unfunded"
    assert body["covenant"]["verified_on_chain"] is False
    assert body["covenant"]["time_locked_capital_proof_exposed"] is False

    expected_surfaces = {
        "/.well-known/agent.json",
        "/agent/capabilities",
        "/agent/discovery",
        "/agent/reputation",
        "/agent/attestations",
        "/agent/chain/health",
        "/api/public/status",
    }
    assert expected_surfaces.issubset(set(body["verification"]["runtime_surfaces"]))


def test_operator_continuity_is_advertised_in_agent_surfaces(client):
    agent = client.get("/.well-known/agent.json").get_json()
    capabilities = client.get("/agent/capabilities").get_json()
    discovery = client.get("/agent/discovery").get_json()

    assert agent["endpoints"]["operator_continuity"] == OPERATOR_ENDPOINT
    assert agent["discovery"]["operator_continuity"] == OPERATOR_ENDPOINT
    assert capabilities["endpoints"]["operator_continuity"] == OPERATOR_ENDPOINT
    assert discovery["discovery"]["operator_continuity"] == OPERATOR_ENDPOINT


def test_capabilities_schema_declares_operator_continuity_when_endpoints_are_closed(client):
    schema = client.get("/agent/capabilities/schema").get_json()
    endpoints_schema = schema["properties"]["endpoints"]

    if endpoints_schema.get("additionalProperties") is False:
        assert "operator_continuity" in endpoints_schema["required"]
        assert endpoints_schema["properties"]["operator_continuity"] == {"type": "string", "pattern": "^/"}


def test_wsgi_app_factory_imports():
    wsgi = importlib.import_module("wsgi")

    assert hasattr(wsgi, "app")
    assert wsgi.app.test_client().get(OPERATOR_ENDPOINT).status_code == 200

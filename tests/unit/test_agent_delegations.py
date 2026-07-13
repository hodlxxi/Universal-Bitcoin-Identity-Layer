from __future__ import annotations

import json

from app.agent_signer import canonical_json_bytes, verify_message


def _registered_rules(client) -> set[str]:
    return {rule.rule for rule in client.application.url_map.iter_rules()}


def _signed_payload_without_signature(payload: dict) -> tuple[dict, str]:
    body = dict(payload)
    signature = body.pop("signature")
    return body, signature


def test_agent_delegations_returns_signed_json(client) -> None:
    res = client.get("/agent/delegations")
    assert res.status_code == 200
    body = res.get_json()

    assert body["schema"] == "hodlxxi.agent.delegations.v1"
    assert body["agent"]["agent_pubkey"]
    assert body["operator"]["operator_id"]
    assert body["current_delegations"]
    assert body["planned_scopes"]
    assert body["non_goals"]
    assert body["signature"]


def test_agent_delegations_schema_returns_json(client) -> None:
    res = client.get("/agent/delegations/schema")
    assert res.status_code == 200
    body = res.get_json()
    assert body["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert body["properties"]["schema"]["const"] == "hodlxxi.agent.delegations.v1"
    for key in {
        "schema",
        "version",
        "service",
        "operator",
        "agent",
        "delegation_model",
        "current_delegations",
        "supported_future_delegation_types",
        "planned_scopes",
        "non_goals",
        "next_surfaces",
        "timestamp",
        "sig_scheme",
        "signature",
    }:
        assert key in body["required"]


def test_well_known_agent_delegation_returns_json(client) -> None:
    res = client.get("/.well-known/agent-delegation.json")
    assert res.status_code == 200
    assert res.get_json()["schema"] == "hodlxxi.agent.delegations.v1"


def test_agent_delegations_signature_verifies(client) -> None:
    body = client.get("/agent/delegations").get_json()
    payload, signature = _signed_payload_without_signature(body)
    assert verify_message(canonical_json_bytes(payload), signature, payload["agent"]["agent_pubkey"])


def test_agent_capabilities_exposes_delegations_reference(client) -> None:
    body = client.get("/agent/capabilities").get_json()
    assert body["endpoints"]["delegations"] == "/agent/delegations"
    assert body["endpoints"]["delegations_schema"] == "/agent/delegations/schema"
    assert body["endpoints"]["well_known_delegation"] == "/.well-known/agent-delegation.json"
    assert body["delegations"]["endpoint"] == "/agent/delegations"


def test_agent_discovery_exposes_delegations_reference(client) -> None:
    body = client.get("/agent/discovery").get_json()
    assert body["discovery"]["delegations"] == "/agent/delegations"
    assert body["discovery"]["delegations_schema"] == "/agent/delegations/schema"
    assert body["discovery"]["well_known_delegation"] == "/.well-known/agent-delegation.json"


def test_well_known_agent_exposes_delegations_reference(client) -> None:
    body = client.get("/.well-known/agent.json").get_json()
    assert body["discovery"]["delegations"] == "/agent/delegations"
    assert body["discovery"]["delegations_schema"] == "/agent/delegations/schema"
    assert body["discovery"]["well_known_delegation"] == "/.well-known/agent-delegation.json"


def test_existing_public_surfaces_still_work(client) -> None:
    assert client.get("/.well-known/agent.json").status_code == 200
    assert client.get("/agent/capabilities").status_code == 200
    assert client.get("/agent/discovery").status_code == 200
    assert client.get("/demo").status_code == 200

    rules = _registered_rules(client)
    assert "/agent/request" in rules
    assert "/agent/jobs/<job_id>" in rules
    assert "/agent/verify/<job_id>" in rules


def test_future_policy_and_actions_routes_are_not_registered(client) -> None:
    rules = _registered_rules(client)
    assert "/agent/policy" not in rules
    assert "/agent/actions" not in rules


def test_agent_delegations_do_not_grant_unbounded_authority(client) -> None:
    body = client.get("/agent/delegations").get_json()
    text = json.dumps(body, sort_keys=True).lower()
    assert "descriptive_read_only_v1" in text
    assert "runtime_signed_declaration" in text
    assert "future_personal_agents_may_receive_limited_scopes" in text
    assert "no_unrestricted_shell_access" in text
    assert "no_unbounded_wallet_authority" in text
    assert "no_automatic_production_mutation" in text
    assert "no_custody" in text
    assert "does_not_grant_external_wallet_authority" in text
    assert "does_not_grant_production_mutation_authority" in text
    assert "shell.exec" not in text
    assert "wallet.spend_unrestricted" not in text
    assert "prod.mutate_unrestricted" not in text
    assert "unrestricted_wallet_authority" not in text

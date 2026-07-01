import json

import pytest

from app.blueprints import qr_pointer
from app.blueprints.qr_pointer import DISCOVERY_ONLY_WARNING, validate_target_path


def _html(response):
    return response.get_data(as_text=True)


def test_known_active_token_returns_safe_landing_page(client):
    response = client.get("/qr/agentjsonA1")
    body = _html(response)

    assert response.status_code == 200
    assert "/.well-known/agent.json" in body
    assert "Status: <strong>active</strong>" in body
    assert DISCOVERY_ONLY_WARNING in body
    assert 'href="/.well-known/agent.json"' in body


def test_unknown_token_returns_404(client):
    assert client.get("/qr/unknown000").status_code == 404


@pytest.mark.parametrize("path", ["/qr/../agentjsonA1", "/qr/bad/token", "/qr/%2e%2e%2fagentjsonA1"])
def test_token_with_slash_or_traversal_is_rejected(client, path):
    assert client.get(path).status_code in {400, 404}


def test_revoked_token_returns_410_without_redirect(client):
    response = client.get("/qr/revokedA1", follow_redirects=False)
    body = _html(response)

    assert response.status_code == 410
    assert "revoked" in body
    assert "will not redirect" in body
    assert 300 > response.status_code or response.status_code >= 400
    assert "Location" not in response.headers


def test_expired_token_returns_410_without_redirect(client):
    response = client.get("/qr/expiredA1", follow_redirects=False)
    body = _html(response)

    assert response.status_code == 410
    assert "expired" in body
    assert "will not redirect" in body
    assert "Location" not in response.headers


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com/.well-known/agent.json",
        "//example.com/.well-known/agent.json",
        "/agent/request",
        "/.well-known/agent-delegation.json",
        "/agent/delegations",
        "/agent/delegations/abc",
        "/agent/policy",
    ],
)
def test_forbidden_targets_are_rejected_by_contract(target):
    assert validate_target_path(target) is False


def test_malformed_external_target_fixture_cannot_be_loaded(app, tmp_path, monkeypatch):
    registry = tmp_path / "qr_pointers"
    registry.mkdir()
    (registry / "externalA1.json").write_text(
        json.dumps({"token": "externalA1", "status": "active", "target": "https://example.com"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(qr_pointer, "_registry_dir", lambda: registry)

    with app.app_context():
        assert qr_pointer.load_pointer_record("externalA1") is None


def test_response_does_not_contain_forbidden_authority_claims_or_secret_fields(client):
    response = client.get("/qr/agentjsonA1")
    body = _html(response).lower()

    assert DISCOVERY_ONLY_WARNING.lower() in body
    for secret in ["private_key", "privkey", "macaroon", "cookie", "password", "credential", "approval_token"]:
        assert secret not in body
    for claim in ["proves identity", "proves consent", "proves approval", "proves delegation", "proves authorization"]:
        assert claim not in body


def test_no_automatic_redirect_by_default(client):
    response = client.get("/qr/agentjsonA1", follow_redirects=False)

    assert response.status_code == 200
    assert "Location" not in response.headers


def test_capabilities_do_not_advertise_qr_route(client):
    response = client.get("/agent/capabilities")
    serialized = json.dumps(response.get_json())

    assert response.status_code == 200
    assert "/qr/" not in serialized


def test_existing_public_machine_readable_surfaces_remain_available(client):
    for path in ["/.well-known/agent.json", "/agent/capabilities", "/agent/capabilities/schema"]:
        response = client.get(path)
        assert response.status_code == 200
        assert response.is_json

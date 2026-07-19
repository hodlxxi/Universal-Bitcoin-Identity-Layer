from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

import jwt
import pytest
from flask import Blueprint, g, jsonify

from app.blueprints.oauth import TOKEN_CONTRACT, issue_jwt_compat
from app.db_storage import create_user, store_canonical_jwt_record, store_oauth_client
from app.oauth_utils import require_canonical_bearer
from app.services.action_authorization import ActionDecision, ActionName, ReasonCode
from app.services.current_entitlement import EntitlementDenied, EntitlementUnavailable
from app.services.oauth_scope_policy import SCOPE_POLICY_VERSION
from app.services.oauth_bearer_validation import BearerPrincipal

SUBJECT = "a" * 64


@pytest.fixture(scope="module")
def protected_app():
    from app.factory import create_app

    application = create_app()
    application.config.update(TESTING=True)
    _install(application)
    return application


def _install(app):
    bp = Blueprint(f"canonical_test_{uuid.uuid4().hex}", __name__)

    @bp.get("/test/canonical")
    @require_canonical_bearer(required_scope="self:read", required_action=ActionName.SELF_READ)
    def canonical():
        principal = g.oauth_principal
        entitlement = g.entitlement_decision
        return jsonify(
            {
                "principal": {"sub": principal.subject, "client_id": principal.client_id,
                              "scopes": sorted(principal.scopes), "token_contract": principal.token_contract},
                "entitlement": {"identity": entitlement.identity_class.value,
                                "full_relation": entitlement.current_full_relation_satisfied,
                                "evidence": entitlement.evidence_source},
            }
        )

    app.register_blueprint(bp)


def _real_token(app, *, scope="self:read"):
    suffix = uuid.uuid4().hex
    client_id = f"protected-client-{suffix}"
    secret = f"secret-{suffix}"
    user_id = create_user(SUBJECT)
    store_oauth_client(
        client_id,
        {"client_secret": secret, "client_name": "Protected resource test",
         "redirect_uris": ["https://example.test/callback"], "grant_types": ["authorization_code"],
         "response_types": ["code"], "scope": scope, "metadata": {"trust_class": "public_dynamic"}},
    )
    cfg = app.config["APP_CONFIG"]
    jti = uuid.uuid4().hex
    token = issue_jwt_compat(
        subject=SUBJECT, audience=client_id, jti=jti, scope=scope, token_use="access",
        token_contract=TOKEN_CONTRACT, cfg=cfg,
    )
    claims = jwt.decode(token, options={"verify_signature": False})
    header = jwt.get_unverified_header(token)
    store_canonical_jwt_record(
        jti=jti, digest=hashlib.sha256(token.encode("ascii")).hexdigest(), client_id=client_id,
        user_id=user_id, scope=scope,
        expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc).replace(tzinfo=None),
        metadata={"token_contract": TOKEN_CONTRACT, "token_use": "access", "issuer": claims["iss"],
                  "audience": client_id, "kid": header["kid"], "digest_algorithm": "sha256",
                  "scope_policy_version": SCOPE_POLICY_VERSION},
    )
    return token, client_id, secret, claims


def _principal(scopes=frozenset({"self:read"})):
    now = datetime.now(timezone.utc)
    return BearerPrincipal(SUBJECT, "user", "client", scopes, "identifier", now, now, TOKEN_CONTRACT)


def test_real_end_to_end_token_protected_resource_and_introspection_parity(protected_app):
    app = protected_app
    token, client_id, secret, claims = _real_token(app)
    client = app.test_client()
    with client.session_transaction() as state:
        state["unrelated"] = "preserved"
    response = client.get("/test/canonical", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.get_json()
    assert body["principal"] == {"sub": SUBJECT, "client_id": client_id, "scopes": ["self:read"],
                                 "token_contract": TOKEN_CONTRACT}
    assert body["entitlement"] == {"identity": "limited", "full_relation": False,
                                   "evidence": "active_persisted_user"}
    with client.session_transaction() as state:
        assert dict(state) == {"unrelated": "preserved"}

    introspection = client.post(
        "/oauth/introspect", data={"token": token, "client_id": client_id, "client_secret": secret}
    )
    assert introspection.status_code == 200
    introspected = introspection.get_json()
    assert introspected == {
        "active": True, "client_id": client_id, "sub": SUBJECT, "exp": claims["exp"], "iat": claims["iat"],
        "jti": claims["jti"], "scope": "self:read", "token_type": "Bearer", "token_contract": TOKEN_CONTRACT,
    }


def test_real_token_accepts_case_insensitive_bearer_scheme(protected_app):
    app = protected_app
    token, _, _, _ = _real_token(app)
    for scheme in ("bearer", "BEARER"):
        assert app.test_client().get(
            "/test/canonical", headers={"Authorization": f"{scheme} {token}"}
        ).status_code == 200


def test_header_errors_are_safe(protected_app):
    app = protected_app
    client = app.test_client()
    for headers in ({}, {"Authorization": "Basic x"}, {"Authorization": "Bearer"},
                    {"Authorization": "Bearer  x"}, {"Authorization": "Bearer x,y"}):
        response = client.get("/test/canonical", headers=headers)
        assert response.status_code == 401
        assert response.get_json() == {"error": "invalid_token"}
        assert response.headers["WWW-Authenticate"] == 'Bearer realm="hodlxxi", error="invalid_token"'


def test_missing_scope_returns_exact_403_contract(protected_app):
    app = protected_app
    token, _, _, _ = _real_token(app, scope="profile")
    response = app.test_client().get("/test/canonical", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert response.get_json() == {"error": "insufficient_scope"}
    assert response.headers["WWW-Authenticate"] == (
        'Bearer realm="hodlxxi", error="insufficient_scope", scope="self:read"'
    )


def test_entitlement_denial_unavailable_and_unexpected_failure_contracts(protected_app, monkeypatch):
    app = protected_app
    token, _, _, _ = _real_token(app)
    client = app.test_client()
    monkeypatch.setattr(
        "app.services.current_entitlement.resolve_current_entitlement",
        lambda _subject: (_ for _ in ()).throw(EntitlementDenied()),
    )
    response = client.get("/test/canonical", headers={"Authorization": f"Bearer {token}"})
    assert (response.status_code, response.get_json()) == (403, {"error": "insufficient_entitlement"})
    monkeypatch.setattr(
        "app.services.current_entitlement.resolve_current_entitlement",
        lambda _subject: (_ for _ in ()).throw(EntitlementUnavailable()),
    )
    response = client.get("/test/canonical", headers={"Authorization": f"Bearer {token}"})
    assert (response.status_code, response.get_json()) == (503, {"error": "authorization_unavailable"})
    monkeypatch.setattr(
        "app.services.current_entitlement.resolve_current_entitlement",
        lambda _subject: (_ for _ in ()).throw(RuntimeError("internal detail")),
    )
    response = client.get("/test/canonical", headers={"Authorization": f"Bearer {token}"})
    assert (response.status_code, response.get_json()) == (503, {"error": "authorization_unavailable"})


def test_unexpected_policy_failure_fails_closed_without_500(protected_app, monkeypatch):
    app = protected_app
    token, _, _, _ = _real_token(app)
    monkeypatch.setattr(
        "app.services.action_authorization.authorize_action",
        lambda *_: (_ for _ in ()).throw(RuntimeError("policy detail")),
    )
    response = app.test_client().get("/test/canonical", headers={"Authorization": f"Bearer {token}"})
    assert (response.status_code, response.get_json()) == (503, {"error": "authorization_unavailable"})


def test_normal_policy_denial_is_exact_insufficient_entitlement(protected_app, monkeypatch):
    app = protected_app
    token, _, _, _ = _real_token(app)
    monkeypatch.setattr(
        "app.services.action_authorization.authorize_action",
        lambda *_: ActionDecision(False, ReasonCode.INSUFFICIENT_IDENTITY, SUBJECT, None, "self_read", "self:read",
                                  None, None, False, False),
    )
    response = app.test_client().get("/test/canonical", headers={"Authorization": f"Bearer {token}"})
    assert (response.status_code, response.get_json()) == (403, {"error": "insufficient_entitlement"})


def test_malformed_or_invalid_signature_jwt_is_401_without_legacy_lookup(protected_app, monkeypatch):
    app = protected_app
    monkeypatch.setattr("app.oauth_utils.get_oauth_token", lambda _token: pytest.fail("legacy lookup occurred"))
    for credential in ("abc.def.ghi", "eyJhbGciOiJSUzI1NiJ9.e30.invalidsignature"):
        response = app.test_client().get("/test/canonical", headers={"Authorization": f"Bearer {credential}"})
        assert response.status_code == 401
        assert response.get_json() == {"error": "invalid_token"}


def test_public_agent_mcp_retains_exact_unauthenticated_contract(client):
    response = client.post("/agent/mcp", json={"jsonrpc": "2.0"})
    assert response.status_code == 501
    assert response.get_json() == {
        "error": "not_implemented",
        "error_description": (
            "The Flask monolith does not execute MCP tools. The dedicated read-only MCP sidecar is exposed only "
            "through a separately controlled reverse proxy when HODLXXI_MCP_PUBLIC_ENABLED is explicitly true."
        ),
        "enabled": False,
    }

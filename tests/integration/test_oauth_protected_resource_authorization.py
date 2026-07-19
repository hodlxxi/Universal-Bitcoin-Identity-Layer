from datetime import datetime, timezone

from flask import Blueprint, g, jsonify

from app.oauth_utils import require_canonical_bearer
from app.services.action_authorization import ActionName, IdentityClass
from app.services.current_entitlement import EntitlementDecision, EntitlementUnavailable
from app.services.oauth_bearer_validation import BearerPrincipal, BearerValidationError

SUBJECT = "a" * 64


def _install(app):
    bp = Blueprint("canonical_test", __name__)

    @bp.get("/test/canonical")
    @require_canonical_bearer(required_scope="self:read", required_action=ActionName.SELF_READ)
    def canonical():
        return jsonify({"sub": g.oauth_principal.subject, "identity": g.entitlement_decision.identity_class.value})

    app.register_blueprint(bp)


def _principal(scopes=frozenset({"self:read"})):
    now = datetime.now(timezone.utc)
    return BearerPrincipal(SUBJECT, "user", "client", scopes, "identifier", now, now, "hodlxxi.oauth.access-token.v1")


def test_header_errors_are_safe(app):
    _install(app)
    client = app.test_client()
    for headers in ({}, {"Authorization": "Basic x"}, {"Authorization": "Bearer"}, {"Authorization": "Bearer "}):
        response = client.get("/test/canonical", headers=headers)
        assert response.status_code == 401
        assert response.get_json() == {"error": "invalid_token"}
        assert response.headers["WWW-Authenticate"] == 'Bearer realm="hodlxxi", error="invalid_token"'


def test_exact_scope_and_limited_entitlement_pass(app, monkeypatch):
    _install(app)
    monkeypatch.setattr("app.services.oauth_bearer_validation.validate_canonical_access_token", lambda _token: _principal())
    monkeypatch.setattr(
        "app.services.current_entitlement.resolve_current_entitlement",
        lambda subject: EntitlementDecision(subject, IdentityClass.LIMITED, False, "active_persisted_user"),
    )
    response = app.test_client().get("/test/canonical", headers={"Authorization": "Bearer token"})
    assert response.status_code == 200
    assert response.get_json() == {"sub": SUBJECT, "identity": "limited"}


def test_missing_similar_or_broad_scope_is_insufficient(app, monkeypatch):
    _install(app)
    for scopes in (frozenset(), frozenset({"self:reader"}), frozenset({"read"}), frozenset({"*"})):
        monkeypatch.setattr(
            "app.services.oauth_bearer_validation.validate_canonical_access_token", lambda _token, s=scopes: _principal(s)
        )
        response = app.test_client().get("/test/canonical", headers={"Authorization": "Bearer token"})
        assert response.status_code == 403
        assert response.get_json() == {"error": "insufficient_scope"}
        assert response.headers["WWW-Authenticate"].endswith('scope="self:read"')


def test_entitlement_unavailable_is_503(app, monkeypatch):
    _install(app)
    monkeypatch.setattr("app.services.oauth_bearer_validation.validate_canonical_access_token", lambda _token: _principal())
    monkeypatch.setattr(
        "app.services.current_entitlement.resolve_current_entitlement",
        lambda _subject: (_ for _ in ()).throw(EntitlementUnavailable()),
    )
    response = app.test_client().get("/test/canonical", headers={"Authorization": "Bearer token"})
    assert response.status_code == 503
    assert response.get_json() == {"error": "authorization_unavailable"}


def test_public_agent_mcp_remains_unauthenticated(client):
    assert client.get("/agent/mcp").status_code != 401

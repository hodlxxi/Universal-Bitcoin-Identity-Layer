from datetime import datetime, timedelta
import uuid

import pytest
from flask import Blueprint, jsonify, request

from app.database import session_scope
from app.db_storage import create_user, get_oauth_token, store_oauth_client, store_oauth_token
from app.models import OAuthToken, User
from app.oauth_utils import require_oauth_token
from app.services.bearer_credentials import DEFAULT_MAX_BEARER_LENGTH


@pytest.fixture(scope="module")
def legacy_app():
    from app.factory import create_app

    application = create_app()
    application.config.update(TESTING=True)
    _install(application)
    return application


def _legacy(token=None, *, metadata=None, expires=None):
    suffix = uuid.uuid4().hex
    subject = suffix.rjust(64, "a")[-64:]
    user_id = create_user(subject)
    client_id = f"legacy-client-{suffix}"
    token_id = f"legacy-id-{suffix}"
    token = token or f"opaque-token-{suffix}"
    store_oauth_client(
        client_id,
        {"client_secret": "secret", "client_name": "Legacy", "redirect_uris": ["https://example.test/cb"],
         "grant_types": ["authorization_code"], "response_types": ["code"], "scope": "read_limited"},
    )
    store_oauth_token(
        token_id,
        {"access_token": token, "client_id": client_id, "user_id": user_id, "scope": "read_limited",
         "access_token_expires_at": (expires or datetime.utcnow() + timedelta(hours=1)).isoformat(),
         "metadata": metadata},
    )
    return user_id, token_id, token


def _install(app):
    bp = Blueprint(f"legacy_test_{uuid.uuid4().hex}", __name__)

    @bp.get("/test/legacy")
    @require_oauth_token("read_limited")
    def legacy_route():
        return jsonify({"client_id": request.oauth_client_id, "scope": request.oauth_scope})

    app.register_blueprint(bp)


def test_valid_legacy_opaque_token_through_actual_decorator(legacy_app):
    app = legacy_app
    _, _, token = _legacy()
    for scheme in ("Bearer", "bearer", "BEARER"):
        response = app.test_client().get("/test/legacy", headers={"Authorization": f"{scheme} {token}"})
        assert response.status_code == 200
        assert response.get_json()["scope"] == "read_limited"


def test_malformed_authorization_headers_fail_before_lookup(legacy_app, monkeypatch):
    app = legacy_app
    called = False

    def lookup(_token):
        nonlocal called
        called = True

    monkeypatch.setattr("app.oauth_utils.get_oauth_token", lookup)
    for header in (None, "", "Basic x", "Bearer", "Bearer ", "Bearer  x", "Bearer x y", "Bearer x,y", " Bearer x"):
        headers = {} if header is None else {"Authorization": header}
        assert app.test_client().get("/test/legacy", headers=headers).status_code == 401
    assert called is False


def test_token_size_ceiling_is_enforced_before_database_lookup(legacy_app, monkeypatch):
    app = legacy_app
    monkeypatch.setattr("app.oauth_utils.get_oauth_token", lambda _token: pytest.fail("database lookup occurred"))
    response = app.test_client().get(
        "/test/legacy", headers={"Authorization": "Bearer " + "x" * (DEFAULT_MAX_BEARER_LENGTH + 1)}
    )
    assert response.status_code == 401


def test_expired_revoked_and_inactive_users_fail_closed(legacy_app):
    app = legacy_app
    _, _, expired = _legacy(expires=datetime.utcnow() - timedelta(seconds=1))
    assert app.test_client().get("/test/legacy", headers={"Authorization": f"Bearer {expired}"}).status_code == 401

    user_id, token_id, revoked = _legacy()
    with session_scope() as db:
        db.query(OAuthToken).filter_by(id=token_id).update({"is_revoked": True})
    assert app.test_client().get("/test/legacy", headers={"Authorization": f"Bearer {revoked}"}).status_code == 401

    with session_scope() as db:
        db.query(OAuthToken).filter_by(id=token_id).update({"is_revoked": False})
        db.query(User).filter_by(id=user_id).update({"is_active": False})
    assert app.test_client().get("/test/legacy", headers={"Authorization": f"Bearer {revoked}"}).status_code == 401



def test_missing_user_fails_closed_through_actual_decorator(legacy_app, monkeypatch):
    app = legacy_app
    monkeypatch.setattr(
        "app.oauth_utils.get_oauth_token",
        lambda _token: {"user_id": "missing-user", "scope": "read_limited", "client_id": "legacy-client"},
    )
    monkeypatch.setattr("app.oauth_utils.get_user_by_id", lambda _user_id: None)
    assert app.test_client().get(
        "/test/legacy", headers={"Authorization": "Bearer opaque-missing-user"}
    ).status_code == 401


def test_canonical_records_never_authenticate_as_opaque(legacy_app):
    app = legacy_app
    cases = [("d" * 64, {"token_contract": "hodlxxi.oauth.access-token.v1"}),
             ("canonical-metadata", {"token_use": "access"}),
             ("canonical-digest", {"digest_algorithm": "sha256"})]
    for credential, metadata in cases:
        _legacy(credential, metadata=metadata)
        response = app.test_client().get("/test/legacy", headers={"Authorization": f"Bearer {credential}"})
        assert response.status_code == 401


def test_valid_or_invalid_signature_jwt_shape_never_enters_opaque_lookup(legacy_app, monkeypatch):
    app = legacy_app
    monkeypatch.setattr("app.oauth_utils.get_oauth_token", lambda token: get_oauth_token(token))
    for credential in ("abc.def.ghi", "eyJhbGciOiJSUzI1NiJ9.e30.signature"):
        _legacy(credential)
        assert app.test_client().get(
            "/test/legacy", headers={"Authorization": f"Bearer {credential}"}
        ).status_code == 401


def test_database_failure_fails_closed(legacy_app, monkeypatch):
    app = legacy_app
    monkeypatch.setattr("app.oauth_utils.get_oauth_token", lambda _token: (_ for _ in ()).throw(RuntimeError()))
    assert app.test_client().get(
        "/test/legacy", headers={"Authorization": "Bearer opaque"}
    ).status_code == 401
    monkeypatch.setattr(
        "app.oauth_utils.get_oauth_token",
        lambda _token: {"user_id": "user", "scope": "read_limited", "client_id": "client"},
    )
    monkeypatch.setattr("app.oauth_utils.get_user_by_id", lambda _user_id: (_ for _ in ()).throw(RuntimeError()))
    assert app.test_client().get(
        "/test/legacy", headers={"Authorization": "Bearer opaque"}
    ).status_code == 401


def test_insufficient_scope_does_not_disclose_provided_scopes(legacy_app):
    app = legacy_app
    _, token_id, token = _legacy()
    with session_scope() as db:
        db.query(OAuthToken).filter_by(id=token_id).update({"scope": "openid profile"})
    response = app.test_client().get("/test/legacy", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert response.get_json() == {"error": "insufficient_scope", "required": "read_limited"}
    assert "openid" not in response.get_data(as_text=True)

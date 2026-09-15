import hashlib
import hmac
from types import SimpleNamespace

import pytest
from flask import Flask, session

from app.models import OAuthBrowserGeneration
from app.services.oauth_browser_authentication import (
    BROWSER_GENERATION_KEY,
    protected_browser_logout,
)
from app.services.oauth_session_lifecycle import (
    EXTENSION,
    OAuthSessionUnavailable,
    SqlAlchemyOAuthSessionLifecycle,
)


def _service():
    return SqlAlchemyOAuthSessionLifecycle(
        lambda: None,
        client_id="social",
        token_config={
            "JWT_ISSUER": "https://identity.example",
            "JWKS_DIR": "synthetic",
        },
    )


class _ExactBrowserDb:
    def __init__(self, row):
        self.row = row
        self.seen = []

    def get(self, model, key, *args, **kwargs):
        self.seen.append((model, key))
        assert model is OAuthBrowserGeneration
        return self.row


def test_invalidate_browser_missing_generation_is_idempotent(monkeypatch):
    service = _service()
    db = _ExactBrowserDb(None)

    monkeypatch.setattr(service, "_run", lambda command: command(db))

    reference = "a" * 64
    assert service.invalidate_browser(reference) is None
    assert db.seen == [(OAuthBrowserGeneration, reference)]


def test_invalidate_browser_foreign_client_still_fails_closed(monkeypatch):
    service = _service()
    db = _ExactBrowserDb(SimpleNamespace(client_id="different-client"))

    monkeypatch.setattr(service, "_run", lambda command: command(db))

    with pytest.raises(OAuthSessionUnavailable):
        service.invalidate_browser("b" * 64)


def test_logout_get_does_not_require_generation_to_still_exist(monkeypatch):
    app = Flask(__name__)
    app.secret_key = "unit-test-secret"

    service = _service()

    def forbidden_browser_lookup(_reference):
        raise AssertionError("GET logout must not consult browser generation state")

    monkeypatch.setattr(service, "browser_subject", forbidden_browser_lookup)
    app.extensions[EXTENSION] = service

    with app.test_request_context("/logout", method="GET"):
        session[BROWSER_GENERATION_KEY] = "c" * 64

        response = protected_browser_logout()

        assert response.status_code == 200
        assert b"Log out of UBID?" in response.data
        assert response.headers["Cache-Control"] == "no-store"


def test_logout_post_real_lifecycle_failure_remains_503(monkeypatch):
    app = Flask(__name__)
    app.secret_key = "unit-test-secret"

    service = _service()

    def unavailable(_reference):
        raise OAuthSessionUnavailable()

    monkeypatch.setattr(service, "invalidate_browser", unavailable)
    app.extensions[EXTENSION] = service

    reference = "d" * 64
    csrf = hmac.new(
        app.secret_key.encode("utf-8"),
        b"HODLXXI_BROWSER_LOGOUT_CSRF_V1\0" + reference.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()

    with app.test_request_context(
        "/logout",
        method="POST",
        data={"csrf_token": csrf},
        headers={"Origin": "https://identity.example"},
        content_type="application/x-www-form-urlencoded",
    ):
        session[BROWSER_GENERATION_KEY] = reference

        response, status = protected_browser_logout()

        assert status == 503
        assert response.get_json() == {"error": "authentication_unavailable"}

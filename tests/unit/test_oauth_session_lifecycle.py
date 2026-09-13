"""Offline construction and authority-input boundaries."""

from datetime import datetime

import pytest
from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.services.oauth_session_lifecycle import (
    EXTENSION,
    OAuthSessionUnavailable,
    SqlAlchemyOAuthSessionLifecycle,
    configured_lifecycle,
)


def test_disabled_by_default():
    app = Flask(__name__)
    assert configured_lifecycle(app) is None
    assert not any("mobile" in rule.rule for rule in app.url_map.iter_rules())


@pytest.mark.parametrize("value", [True, {}, "enabled"])
def test_invalid_extension(value):
    app = Flask(__name__)
    app.extensions[EXTENSION] = value
    with pytest.raises(OAuthSessionUnavailable):
        configured_lifecycle(app)


def test_no_implicit_database_or_sqlite_fallback():
    cfg = {"JWT_ISSUER": "https://identity.example", "JWKS_DIR": "synthetic"}
    with pytest.raises(OAuthSessionUnavailable):
        SqlAlchemyOAuthSessionLifecycle(None, client_id="social", token_config=cfg)
    engine = create_engine("sqlite:///:memory:")
    service = SqlAlchemyOAuthSessionLifecycle(sessionmaker(bind=engine), client_id="social", token_config=cfg)
    with pytest.raises(OAuthSessionUnavailable, match="^OAuth session lifecycle unavailable$"):
        service.resolve("fabricated-session-id")
    engine.dispose()


@pytest.mark.parametrize("value", [None, True, "", " social", "s" * 256])
def test_client_is_explicit_and_bounded(value):
    with pytest.raises(OAuthSessionUnavailable):
        SqlAlchemyOAuthSessionLifecycle(lambda: None, client_id=value, token_config={})


@pytest.mark.parametrize("now", [True, 1, datetime(2026, 1, 1)])
def test_clock_does_not_assume_timezone(now):
    service = SqlAlchemyOAuthSessionLifecycle(
        lambda: None,
        client_id="social",
        token_config={"JWT_ISSUER": "https://identity.example", "JWKS_DIR": "x"},
        clock=lambda: now,
    )
    with pytest.raises(OAuthSessionUnavailable):
        service._now()


def test_browser_identity_fields_are_not_resolver_parameters():
    service = SqlAlchemyOAuthSessionLifecycle(
        lambda: None,
        client_id="social",
        token_config={"JWT_ISSUER": "https://identity.example", "JWKS_DIR": "x"},
    )
    for field in ("session_id", "user_id", "subject", "generation", "created_at"):
        with pytest.raises(TypeError):
            service.resolve("synthetic", **{field: "fabricated"})

"""Real, identity-checked disposable PostgreSQL lifecycle and mobile boundary."""

import base64
import hashlib
import os
import re
import subprocess
import sys
import types
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from flask import Flask
from sqlalchemy import event, func, inspect, select
from sqlalchemy.exc import IntegrityError, InternalError
from werkzeug.security import generate_password_hash

import app.database as database
from app.models import (
    OAuthBrowserGeneration,
    OAuthClient,
    OAuthCode,
    OAuthSessionCodeBinding,
    OAuthSessionGeneration,
    OAuthToken,
    Session,
    User,
)
from app.services.oauth_browser_authentication import BROWSER_GENERATION_KEY
from app.services.oauth_session_lifecycle import EXTENSION, OAuthSessionUnavailable, SqlAlchemyOAuthSessionLifecycle
from app.services.social_messaging_mobile_authorization import QR, MobileAuthorizationUnavailable
from app.services.social_messaging_mobile_authorization_storage import SqlAlchemyMobileAuthorizationService
from tests.integration.test_social_messaging_device_binding_authorization_storage_postgresql import (
    postgres_factory as postgres_factory,
)
from tests.integration.test_social_messaging_mobile_authorization_storage_postgresql import (
    mobile_factory as mobile_factory,
)

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/2026-09-13_oauth_session_lifecycle_v1.sql"
SUBJECT, OTHER = "a" * 64, "b" * 64
CLIENT = "synthetic-social"
REDIRECT = "https://social.example/callback"
VERIFIER = "v" * 43
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def generation_factory(mobile_factory):
    engine, factory = mobile_factory
    # Load the actual committed pre-migration model definitions, not current
    # create_all metadata. The SQL migration below is the only lifecycle upgrade.
    baseline = types.ModuleType("oauth_migration_committed_base")
    sys.modules[baseline.__name__] = baseline
    source = subprocess.check_output(
        ["git", "show", "d924953d2bdcdb8b59b76f0269febb252d101a0e:app/models.py"],
        cwd=ROOT,
        text=True,
    )
    exec(compile(source, "<committed OAuth base models>", "exec"), baseline.__dict__)
    with engine.begin() as connection:
        Session.__table__.drop(connection)
        for model in (baseline.Session, baseline.OAuthClient, baseline.OAuthCode, baseline.OAuthToken):
            model.__table__.create(connection)
        assert not inspect(connection).has_table("oauth_browser_generations")
    with engine.connect() as connection:
        transaction = connection.begin()
        connection.exec_driver_sql(MIGRATION.read_text())
        assert inspect(connection).has_table("oauth_session_generations")
        transaction.rollback()
        assert not inspect(connection).has_table("oauth_session_generations")
        assert not inspect(connection).has_table("oauth_session_code_bindings")
        assert not inspect(connection).has_table("oauth_browser_generations")
        assert not any(
            c["name"] == "uq_session_generation_owner" for c in inspect(connection).get_unique_constraints("sessions")
        )
        connection.rollback()
    with engine.begin() as connection:
        connection.exec_driver_sql(MIGRATION.read_text())
    return engine, factory


@pytest.fixture
def state(generation_factory, monkeypatch):
    engine, factory = generation_factory
    with engine.begin() as connection:
        connection.exec_driver_sql("TRUNCATE users, oauth_clients CASCADE")
    ids = {subject: str(uuid.uuid4()) for subject in (SUBJECT, OTHER)}
    now = datetime.now(timezone.utc)
    with factory.begin() as db:
        for subject, user_id in ids.items():
            db.add(User(id=user_id, pubkey=subject, is_active=True, created_at=now.replace(tzinfo=None)))
        for client_id in (CLIENT, "other-client"):
            db.add(
                OAuthClient(
                    client_id=client_id,
                    client_secret=generate_password_hash("synthetic-secret"),
                    client_name="test",
                    redirect_uris=[REDIRECT],
                    grant_types=["authorization_code"],
                    response_types=["code"],
                    scope="openid profile",
                    metadata_json={"trust_class": "public_dynamic"},
                    is_active=True,
                )
            )
    cfg = {"JWT_ISSUER": "https://identity.example", "JWKS_DIR": os.environ["JWKS_DIR"], "TOKEN_TTL": 600}
    ticks = [now]
    service = SqlAlchemyOAuthSessionLifecycle(factory, client_id=CLIENT, token_config=cfg, clock=lambda: ticks[0])
    monkeypatch.setattr(database, "_SessionFactory", factory)
    service.test_browser_references = {}
    for subject in (SUBJECT, OTHER):
        fresh_browser(service, subject)
    return engine, factory, service, ticks, ids, cfg


def fresh_browser(service, subject=SUBJECT, previous=None):
    """Synthetic verified-outcome input for storage tests; real proofs tested below."""
    now = service._now()
    reference = service.complete_verified_login(
        subject=subject,
        challenge="synthetic-verified-login-" + uuid.uuid4().hex,
        challenge_created=now - timedelta(seconds=1),
        challenge_expires=now + timedelta(minutes=5),
        previous_generation=previous,
    )
    service.test_browser_references[subject] = reference
    return reference


def authorize(service, subject=SUBJECT):
    return service.authorize(
        subject=subject,
        browser_generation=service.test_browser_references[subject],
        redirect_uri=REDIRECT,
        scope="openid profile",
        code_challenge=CHALLENGE,
    )


def seed_browser(client, service, subject=SUBJECT):
    with client.session_transaction() as cookie:
        cookie.update(logged_in_pubkey=subject, login_method="nostr", access_level="limited")
        cookie[BROWSER_GENERATION_KEY] = service.test_browser_references[subject]


def csrf(client):
    response = client.get("/logout")
    assert response.status_code == 200
    return re.search(r'name="csrf_token" value="([0-9a-f]{64})"', response.get_data(as_text=True))[1]


def logout(client, proof=None, origin="https://identity.example"):
    return client.post(
        "/logout", data={"csrf_token": csrf(client) if proof is None else proof}, headers={"Origin": origin}
    )


def exchange(service, code=None):
    return service.exchange(
        code=authorize(service) if code is None else code, redirect_uri=REDIRECT, code_verifier=VERIFIER
    )


def token_id(response):
    return jwt.decode(response["access_token"], options={"verify_signature": False})["jti"]


def counts(factory):
    with factory() as db:
        return tuple(
            db.scalar(select(func.count()).select_from(model))
            for model in (OAuthToken, Session, OAuthSessionGeneration)
        )


def test_generation_exact_mapping_expiry_and_no_secrets(state):
    _engine, factory, service, ticks, ids, _cfg = state
    response = exchange(service)
    authority = service.resolve(response["access_token"])
    assert authority.subject == SUBJECT
    assert counts(factory) == (1, 1, 1)
    with factory() as db:
        generation = db.get(OAuthSessionGeneration, token_id(response))
        auth = db.get(Session, authority.session_id)
        token = db.get(OAuthToken, generation.token_id)
        assert generation.session_id == auth.session_id
        assert generation.user_id == auth.user_id == token.user_id == ids[SUBJECT]
        assert generation.client_id == token.client_id == CLIENT
        assert auth.created_at == ticks[0].replace(tzinfo=None)
        assert auth.expires_at == token.access_token_expires_at
        assert auth.expires_at.microsecond == 0
        assert auth.metadata_json is None and token.refresh_token is None
        assert token.access_token == hashlib.sha256(response["access_token"].encode()).hexdigest()
        assert auth.session_id not in response.values()
        assert auth.session_id not in jwt.decode(response["access_token"], options={"verify_signature": False}).values()
    assert service.resolve(response["access_token"]) == authority


@pytest.mark.parametrize("bearer", ["fabricated-session-id", "a" * 64, {}, None])
def test_cannot_resolve_caller_selected_authority(state, bearer):
    with pytest.raises(OAuthSessionUnavailable, match="^OAuth session lifecycle unavailable$"):
        state[2].resolve(bearer)


def test_wrong_client_and_other_user_session_cannot_select_authority(state):
    _engine, factory, service, _ticks, _ids, cfg = state
    other = exchange(service, authorize(service, OTHER))
    actual = service.resolve(other["access_token"])
    with pytest.raises(OAuthSessionUnavailable):
        service.resolve(actual.session_id)
    with pytest.raises(TypeError):
        service.resolve(other["access_token"], subject=SUBJECT)
    wrong = SqlAlchemyOAuthSessionLifecycle(factory, client_id="other-client", token_config=cfg)
    with pytest.raises(OAuthSessionUnavailable):
        wrong.resolve(other["access_token"])


@pytest.mark.parametrize(
    "mutation",
    [
        "revoked",
        "token_expiry",
        "session_expiry",
        "session_inactive",
        "user_inactive",
        "client_inactive",
        "subject_swap",
    ],
)
def test_revocation_and_owner_events_fail_closed_and_do_not_revive(state, mutation):
    _engine, factory, service, ticks, ids, _cfg = state
    response = exchange(service)
    authority = service.resolve(response["access_token"])
    with factory.begin() as db:
        if mutation == "revoked":
            db.get(OAuthToken, token_id(response)).is_revoked = True
        elif mutation == "token_expiry":
            db.get(OAuthToken, token_id(response)).access_token_expires_at = ticks[0].replace(tzinfo=None) - timedelta(
                seconds=1
            )
        elif mutation == "session_expiry":
            db.get(Session, authority.session_id).expires_at = ticks[0].replace(tzinfo=None) - timedelta(seconds=1)
        elif mutation == "session_inactive":
            db.get(Session, authority.session_id).is_active = False
        elif mutation == "user_inactive":
            db.get(User, ids[SUBJECT]).is_active = False
        elif mutation == "client_inactive":
            db.get(OAuthClient, CLIENT).is_active = False
        else:
            db.get(User, ids[SUBJECT]).pubkey = "c" * 64
    with pytest.raises(OAuthSessionUnavailable):
        service.resolve(response["access_token"])
    if mutation != "session_expiry":
        with factory() as db:
            assert db.get(Session, authority.session_id).is_active is False
    if mutation in ("user_inactive", "client_inactive", "subject_swap"):
        with factory.begin() as db:
            db.get(User, ids[SUBJECT]).is_active = True
            db.get(User, ids[SUBJECT]).pubkey = SUBJECT
            db.get(OAuthClient, CLIENT).is_active = True
        with pytest.raises(OAuthSessionUnavailable):
            service.resolve(response["access_token"])


def test_exclusive_expiry_and_no_leeway(state):
    _engine, factory, service, ticks, _ids, _cfg = state
    response = exchange(service)
    with factory() as db:
        expires = db.get(OAuthToken, token_id(response)).access_token_expires_at.replace(tzinfo=timezone.utc)
    ticks[0] = expires
    with pytest.raises(OAuthSessionUnavailable):
        service.resolve(response["access_token"])


def test_replacement_and_mobile_real_next_consumer(state):
    _engine, factory, service, ticks, _ids, _cfg = state
    first = exchange(service)
    old = service.resolve(first["access_token"])
    mobile = SqlAlchemyMobileAuthorizationService(factory, clock=lambda: int(ticks[0].timestamp()) + 1)
    offer, _locator = mobile.create_pairing(
        session_id=old.session_id,
        subject=old.subject,
        desktop_context="d" * 64,
        revision="e" * 64,
    )
    current = service.resolve(exchange(service)["access_token"])
    assert current.session_id != old.session_id
    with pytest.raises(OAuthSessionUnavailable):
        service.resolve(first["access_token"])
    for authority in (old, current):
        with pytest.raises(MobileAuthorizationUnavailable):
            mobile.status(
                offer.pairing_id,
                method=QR,
                session_id=authority.session_id,
                subject=authority.subject,
                context_id="d" * 64,
            )
    mobile.create_pairing(
        session_id=current.session_id,
        subject=current.subject,
        desktop_context="d" * 64,
        revision="e" * 64,
    )


def test_invalidate_idempotent_scoped_and_old_retry_does_not_revoke_replacement(state):
    _engine, _factory, service, _ticks, ids, _cfg = state
    old = exchange(service)
    other = exchange(service, authorize(service, OTHER))
    service.invalidate(old["access_token"])
    for _ in range(2):
        service.invalidate_generation(token_id=token_id(old), user_id=ids[SUBJECT])
    with pytest.raises(OAuthSessionUnavailable):
        service.resolve(old["access_token"])
    replacement = exchange(service)
    service.invalidate_generation(token_id=token_id(old), user_id=ids[SUBJECT])
    with pytest.raises(OAuthSessionUnavailable):
        service.invalidate_generation(token_id=token_id(other), user_id=ids[SUBJECT])
    assert service.resolve(replacement["access_token"]).subject == SUBJECT
    assert service.resolve(other["access_token"]).subject == OTHER


def test_pending_code_cannot_follow_subject_change_or_replacement(state):
    _engine, factory, service, _ticks, ids, _cfg = state
    pending = authorize(service)
    exchange(service)
    with pytest.raises(OAuthSessionUnavailable):
        exchange(service, pending)
    pending = authorize(service)
    with factory.begin() as db:
        db.get(User, ids[SUBJECT]).pubkey = "c" * 64
    with pytest.raises(OAuthSessionUnavailable):
        exchange(service, pending)


@pytest.mark.parametrize("failure", ["session", "relation", "commit"])
def test_issuance_failure_rolls_back_code_token_session_and_replacement(state, failure):
    engine, factory, service, _ticks, _ids, _cfg = state
    old = exchange(service)
    code = authorize(service)
    before = counts(factory)

    def fail_sql(_conn, _cursor, statement, _parameters, _context, _many):
        target = "sessions" if failure == "session" else "oauth_session_generations"
        if statement.startswith("INSERT INTO " + target + " "):
            raise RuntimeError("synthetic private diagnostic")

    def fail_commit(_connection):
        raise RuntimeError("synthetic private diagnostic")

    listener, callback = ("commit", fail_commit) if failure == "commit" else ("before_cursor_execute", fail_sql)
    event.listen(engine, listener, callback)
    try:
        with pytest.raises(OAuthSessionUnavailable, match="^OAuth session lifecycle unavailable$"):
            exchange(service, code)
    finally:
        event.remove(engine, listener, callback)
    assert counts(factory) == before
    with factory() as db:
        assert db.get(OAuthCode, code).is_used is False
    assert service.resolve(old["access_token"]).subject == SUBJECT
    assert service.resolve(exchange(service, code)["access_token"]).subject == SUBJECT


def test_concurrent_code_exchange_one_winner(state):
    _engine, factory, service, _ticks, _ids, _cfg = state
    code = authorize(service)

    def attempt():
        try:
            exchange(service, code)
            return True
        except OAuthSessionUnavailable:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(2)))
    assert sorted(outcomes) == [False, True]
    assert counts(factory) == (1, 1, 1)


@pytest.mark.parametrize(
    "mutation",
    [
        "session_owner",
        "session_generation",
        "session_type",
        "session_extension",
        "mapping",
        "token_extension",
        "token_refresh",
        "code_binding",
    ],
)
def test_relational_and_immutable_guards(state, mutation):
    _engine, factory, service, _ticks, ids, _cfg = state
    pending = authorize(service)
    response = exchange(service)
    authority = service.resolve(response["access_token"])
    with pytest.raises((IntegrityError, InternalError)):
        with factory.begin() as db:
            auth = db.get(Session, authority.session_id)
            if mutation == "session_owner":
                auth.user_id = ids[OTHER]
            elif mutation == "session_generation":
                auth.created_at += timedelta(seconds=1)
            elif mutation == "session_type":
                auth.session_type = "api"
            elif mutation == "session_extension":
                auth.expires_at += timedelta(seconds=1)
            elif mutation == "mapping":
                db.get(OAuthSessionGeneration, token_id(response)).user_id = ids[OTHER]
            elif mutation == "token_extension":
                db.get(OAuthToken, token_id(response)).access_token_expires_at += timedelta(seconds=1)
            elif mutation == "token_refresh":
                db.get(OAuthToken, token_id(response)).refresh_token = "synthetic-refresh"
            else:
                db.get(OAuthSessionCodeBinding, pending).subject = OTHER


def oauth_app(state, monkeypatch):
    from app.blueprints.auth import auth_bp
    from app.blueprints.oauth import oauth_bp

    app = Flask(__name__)
    app.secret_key = "synthetic-cookie-signing-key"
    app.config.update(TESTING=True, APP_CONFIG=state[5])
    app.extensions[EXTENSION] = state[2]
    app.register_blueprint(oauth_bp, url_prefix="/oauth")
    app.register_blueprint(auth_bp)
    monkeypatch.setattr("app.blueprints.oauth.audit_logger.log_event", lambda *a, **kw: None)
    return app


def test_real_oauth_routes_introspection_full_directory_viewer_and_refresh(state, monkeypatch):
    from app.services.oauth_bearer_validation import validate_canonical_access_token
    from app.services.privacy_full_directory_internal_delivery import VIEWER_REQUIRED_SCOPE

    app = oauth_app(state, monkeypatch)
    client = app.test_client()
    seed_browser(client, state[2])
    authorized = client.get(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT,
            "redirect_uri": REDIRECT,
            "scope": "openid profile",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "session_id": "fabricated",
            "subject": OTHER,
        },
    )
    assert authorized.status_code == 302
    code = parse_qs(urlparse(authorized.location).query)["code"][0]
    form = {
        "grant_type": "authorization_code",
        "client_id": CLIENT,
        "client_secret": "synthetic-secret",
        "code": code,
        "redirect_uri": REDIRECT,
        "code_verifier": VERIFIER,
        "session_id": "fabricated",
        "subject": OTHER,
    }
    issued = client.post("/oauth/token", data=form)
    assert issued.status_code == 200
    bearer = issued.get_json()["access_token"]
    assert state[2].resolve(bearer).subject == SUBJECT
    assert issued.headers["Cache-Control"] == "no-store"
    introspection = client.post(
        "/oauth/introspect",
        data={
            "client_id": CLIENT,
            "client_secret": "synthetic-secret",
            "token": bearer,
        },
    )
    assert introspection.get_json()["active"] is True
    with app.app_context():
        viewer = validate_canonical_access_token(bearer, expected_client_id=CLIENT)
        assert VIEWER_REQUIRED_SCOPE in viewer.scopes and viewer.subject == SUBJECT
    assert client.post("/oauth/token", data=form).status_code == 400
    before = counts(state[1])
    refresh = client.post("/oauth/token", data={**form, "grant_type": "refresh_token", "refresh_token": "fabricated"})
    assert refresh.get_json()["error"] == "unsupported_grant_type"
    assert counts(state[1]) == before


def test_ubid_logout_and_verified_replacement_hooks(state, monkeypatch):
    app = oauth_app(state, monkeypatch)
    response = exchange(state[2])
    pending = authorize(state[2])
    client = app.test_client()
    seed_browser(client, state[2])
    assert logout(client).status_code == 302
    with pytest.raises(OAuthSessionUnavailable):
        state[2].resolve(response["access_token"])
    with pytest.raises(OAuthSessionUnavailable):
        exchange(state[2], pending)
    old_reference = state[2].test_browser_references[SUBJECT]
    fresh_browser(state[2])
    response = exchange(state[2])
    other = exchange(state[2], authorize(state[2], OTHER))
    fresh_browser(state[2], OTHER, previous=state[2].test_browser_references[SUBJECT])
    for issued in (response, other):
        with pytest.raises(OAuthSessionUnavailable):
            state[2].resolve(issued["access_token"])
    with pytest.raises(OAuthSessionUnavailable):
        state[2].browser_subject(old_reference)


def test_missing_migration_guards_fail_closed(state):
    engine, _factory, service, _ticks, _ids, _cfg = state
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE oauth_tokens DISABLE TRIGGER trg_oauth_token_session_invalidation")
    try:
        with pytest.raises(OAuthSessionUnavailable):
            authorize(service)
    finally:
        with engine.begin() as connection:
            connection.exec_driver_sql("ALTER TABLE oauth_tokens ENABLE TRIGGER trg_oauth_token_session_invalidation")


def test_stale_validation_cannot_survive_revocation_before_session_read(state, monkeypatch):
    _engine, factory, service, _ticks, _ids, _cfg = state
    response = exchange(service)
    validate = service._validate
    seen = []

    def revoke_after_read(db, bearer):
        viewer = validate(db, bearer)
        if not seen:
            seen.append(True)
            with factory.begin() as other:
                other.get(OAuthToken, viewer.jti).is_revoked = True
        return viewer

    monkeypatch.setattr(service, "_validate", revoke_after_read)
    with pytest.raises(OAuthSessionUnavailable):
        service.resolve(response["access_token"])
    assert seen == [True]


def test_existing_revoke_and_durable_invalidation_owners(state):
    from app.db_storage import delete_session, revoke_oauth_token

    _engine, factory, service, _ticks, _ids, _cfg = state
    response = exchange(service)
    authority = service.resolve(response["access_token"])
    revoke_oauth_token(hashlib.sha256(response["access_token"].encode()).hexdigest())
    with factory() as db:
        assert db.get(Session, authority.session_id).is_active is False
    response = exchange(service)
    authority = service.resolve(response["access_token"])
    delete_session(authority.session_id)
    with pytest.raises(OAuthSessionUnavailable):
        service.resolve(response["access_token"])


def test_unmapped_existing_oauth_token_and_code_are_never_adopted(state, monkeypatch):
    app = oauth_app(state, monkeypatch)
    del app.extensions[EXTENSION]
    browser = app.test_client()
    with browser.session_transaction() as cookie:
        cookie.update(logged_in_pubkey=SUBJECT, login_method="legacy", access_level="limited")
    query = {
        "response_type": "code",
        "client_id": CLIENT,
        "redirect_uri": REDIRECT,
        "scope": "openid profile",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    }

    def code():
        result = browser.get("/oauth/authorize", query_string=query)
        assert result.status_code == 302
        return parse_qs(urlparse(result.location).query)["code"][0]

    stale_code = code()
    issued = browser.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT,
            "client_secret": "synthetic-secret",
            "code": code(),
            "redirect_uri": REDIRECT,
            "code_verifier": VERIFIER,
        },
    )
    assert issued.status_code == 200
    assert counts(state[1]) == (1, 0, 0)
    with pytest.raises(OAuthSessionUnavailable):
        state[2].resolve(issued.get_json()["access_token"])
    app.extensions[EXTENSION] = state[2]
    with pytest.raises(OAuthSessionUnavailable):
        exchange(state[2], stale_code)


def test_logout_storage_failure_preserves_cookie_and_generic_error(state, monkeypatch):
    app = oauth_app(state, monkeypatch)
    browser = app.test_client()
    seed_browser(browser, state[2])
    proof = csrf(browser)

    def fail(_reference):
        raise OAuthSessionUnavailable()

    monkeypatch.setattr(state[2], "invalidate_browser", fail)
    response = logout(browser, proof)
    assert response.status_code == 503
    assert response.get_json() == {"error": "authentication_unavailable"}
    with browser.session_transaction() as cookie:
        assert cookie["logged_in_pubkey"] == SUBJECT


def test_no_entitlement_or_binding_mutation_and_no_privilege_scopes(state):
    from app.models import CurrentEntitlementEvidence
    from app.services.social_messaging_device_storage import SocialMessagingDeviceBindingRow

    _engine, factory, service, _ticks, ids, _cfg = state
    with pytest.raises(OAuthSessionUnavailable):
        service.authorize(
            subject=SUBJECT,
            browser_generation=service.test_browser_references[SUBJECT],
            redirect_uri=REDIRECT,
            scope="operator",
            code_challenge=CHALLENGE,
        )
    response = exchange(service)
    service.resolve(response["access_token"])
    service.invalidate(response["access_token"])
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(CurrentEntitlementEvidence)) == 0
        assert db.scalar(select(func.count()).select_from(SocialMessagingDeviceBindingRow)) == 0
        assert db.get(User, ids[SUBJECT]).metadata_json is None


def test_session_cannot_reactivate_and_code_binding_cannot_be_removed(state):
    _engine, factory, service, _ticks, _ids, _cfg = state
    pending = authorize(service)
    response = exchange(service)
    authority = service.resolve(response["access_token"])
    service.invalidate(response["access_token"])
    with pytest.raises(InternalError):
        with factory.begin() as db:
            db.get(Session, authority.session_id).is_active = True
    with pytest.raises(InternalError):
        with factory.begin() as db:
            db.delete(db.get(OAuthSessionCodeBinding, pending))
    # Normal expiration cleanup of an OAuth code cascades its ephemeral binding.
    with factory.begin() as db:
        db.delete(db.get(OAuthCode, pending))
    with factory() as db:
        assert db.get(OAuthSessionCodeBinding, pending) is None


def test_database_rejects_a_second_active_generation_for_same_owner(state):
    _engine, factory, service, _ticks, ids, _cfg = state
    response = exchange(service)
    with pytest.raises(InternalError):
        with factory.begin() as db:
            original = db.get(OAuthToken, token_id(response))
            second_id = uuid.uuid4().hex
            session_id = uuid.uuid4().hex + uuid.uuid4().hex
            db.add(
                OAuthToken(
                    id=second_id,
                    user_id=ids[SUBJECT],
                    client_id=CLIENT,
                    access_token=hashlib.sha256(second_id.encode()).hexdigest(),
                    token_type="Bearer",
                    scope=original.scope,
                    created_at=original.created_at,
                    access_token_expires_at=original.access_token_expires_at,
                    is_revoked=False,
                    metadata_json=original.metadata_json,
                )
            )
            db.add(
                Session(
                    session_id=session_id,
                    user_id=ids[SUBJECT],
                    session_type="web",
                    created_at=original.created_at,
                    expires_at=original.access_token_expires_at,
                    is_active=True,
                )
            )
            db.flush()
            db.add(
                OAuthSessionGeneration(
                    token_id=second_id,
                    browser_generation_id=service.test_browser_references[SUBJECT],
                    session_id=session_id,
                    user_id=ids[SUBJECT],
                    client_id=CLIENT,
                    subject=SUBJECT,
                )
            )
    assert counts(factory) == (1, 1, 1)


def test_shared_legacy_helper_cannot_establish_authority_from_known_pubkey(state, monkeypatch):
    import app.ubid_membership as membership

    app = oauth_app(state, monkeypatch)
    previous = exchange(state[2])
    with app.test_request_context():
        with pytest.raises(OAuthSessionUnavailable):
            membership.on_successful_login("02" + SUBJECT)
    assert state[2].resolve(previous["access_token"]).subject == SUBJECT


def test_review_admission_paused_before_reservation_logout_commits(state, monkeypatch):
    from threading import Event

    app = oauth_app(state, monkeypatch)
    client = app.test_client()
    seed_browser(client, state[2])
    admitted, resume = Event(), Event()
    original = state[2].authorize

    def paused(**kwargs):
        admitted.set()
        assert resume.wait(10)
        return original(**kwargs)

    monkeypatch.setattr(state[2], "authorize", paused)

    def request_code():
        return client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": CLIENT,
                "redirect_uri": REDIRECT,
                "scope": "openid profile",
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
            },
        )

    with ThreadPoolExecutor(max_workers=1) as pool:
        response = pool.submit(request_code)
        try:
            assert admitted.wait(10)
            state[2].invalidate_subject(SUBJECT)  # Independent connection commits first.
        finally:
            resume.set()
        assert response.result(timeout=10).status_code != 302


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_review_logout_safe_methods_do_not_invalidate(state, monkeypatch, method):
    app = oauth_app(state, monkeypatch)
    issued = exchange(state[2])
    authority = state[2].resolve(issued["access_token"])
    client = app.test_client()
    seed_browser(client, state[2])
    client.open("/logout", method=method)
    assert state[2].resolve(issued["access_token"]) == authority


@pytest.mark.parametrize("logout_first", [True, False])
def test_review_exchange_logout_serialization_both_orders(state, logout_first):
    from threading import Event

    _engine, factory, service, ticks, _ids, _cfg = state
    code = authorize(service)
    reference = service.test_browser_references[SUBJECT]
    reached, resume = Event(), Event()

    def exchange_worker():
        if logout_first:
            reached.set()
            assert resume.wait(10)
            with pytest.raises(OAuthSessionUnavailable):
                exchange(service, code)
            return None
        issued = exchange(service, code)
        authority = service.resolve(issued["access_token"])
        reached.set()  # Both issuance and authoritative read committed.
        assert resume.wait(10)  # Simulate a delayed token response.
        return issued, authority

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(exchange_worker)
        try:
            assert reached.wait(10)
            service.invalidate_browser(reference)  # Its own real connection/commit.
        finally:
            resume.set()
        result = pending.result(timeout=10)
    if result is not None:
        issued, authority = result
        with pytest.raises(OAuthSessionUnavailable):
            service.resolve(issued["access_token"])
        mobile = SqlAlchemyMobileAuthorizationService(factory, clock=lambda: int(ticks[0].timestamp()) + 1)
        with pytest.raises(MobileAuthorizationUnavailable):
            mobile.create_pairing(
                session_id=authority.session_id, subject=authority.subject, desktop_context="d" * 64, revision="e" * 64
            )
    else:
        assert counts(factory) == (0, 0, 0)


def test_review_reserved_code_logout_then_exchange_denied(state):
    service = state[2]
    code = authorize(service)
    with state[1]() as db:
        assert db.get(OAuthSessionCodeBinding, code).browser_generation_id == service.test_browser_references[SUBJECT]
    service.invalidate_browser(service.test_browser_references[SUBJECT])
    with pytest.raises(OAuthSessionUnavailable):
        exchange(service, code)


@pytest.mark.parametrize("replacement_subject", [SUBJECT, OTHER])
def test_review_login_replacement_rejects_old_admission_cookie_and_code(state, monkeypatch, replacement_subject):
    from threading import Event

    service = state[2]
    old_reference = service.test_browser_references[SUBJECT]
    old_code = authorize(service)
    old_issued = exchange(service)
    pending_code = authorize(service)
    reached, resume = Event(), Event()

    def admitted_request():
        reached.set()
        assert resume.wait(10)
        with pytest.raises(OAuthSessionUnavailable):
            service.authorize(
                subject=SUBJECT,
                browser_generation=old_reference,
                redirect_uri=REDIRECT,
                scope="openid",
                code_challenge=CHALLENGE,
            )

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(admitted_request)
        try:
            assert reached.wait(10)
            fresh_browser(service, replacement_subject, previous=old_reference)
        finally:
            resume.set()
        pending.result(timeout=10)
    for code in (old_code, pending_code):
        with pytest.raises(OAuthSessionUnavailable):
            exchange(service, code)
    with pytest.raises(OAuthSessionUnavailable):
        service.resolve(old_issued["access_token"])
    with pytest.raises(OAuthSessionUnavailable):
        service.authorize(
            subject=replacement_subject,
            browser_generation=old_reference,
            redirect_uri=REDIRECT,
            scope="openid",
            code_challenge=CHALLENGE,
        )


@pytest.mark.parametrize("cookie_kind", ["legacy", "revoked", "expired", "wrong_subject"])
def test_review_old_signed_cookie_cannot_bootstrap_browser_authority(state, monkeypatch, cookie_kind):
    app = oauth_app(state, monkeypatch)
    browser = app.test_client()
    seed_browser(browser, state[2])
    reference = state[2].test_browser_references[SUBJECT]
    if cookie_kind == "legacy":
        with browser.session_transaction() as cookie:
            cookie.pop(BROWSER_GENERATION_KEY)
    elif cookie_kind == "revoked":
        state[2].invalidate_browser(reference)
    elif cookie_kind == "expired":
        with state[1]() as db:
            state[3][0] = db.get(OAuthBrowserGeneration, reference).expires_at.replace(tzinfo=timezone.utc)
    else:
        with browser.session_transaction() as cookie:
            cookie["logged_in_pubkey"] = OTHER
    before = counts(state[1])
    result = browser.get(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT,
            "redirect_uri": REDIRECT,
            "scope": "openid",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "browser_generation": state[2].test_browser_references[OTHER],
            "subject": OTHER,
        },
    )
    assert result.status_code in (403, 503)
    assert counts(state[1]) == before


def nostr_login(client, state, monkeypatch, *, key_number=7):
    """Produce a real BIP340 login proof; only public event material crosses HTTP."""
    import json

    from coincurve import PrivateKey

    import app.app as legacy
    from app.auth_api_core import ACTIVE_CHALLENGES

    # The compatibility module initializes its own isolated test database on
    # first import; bind the real route's canonical persistence to this cluster.
    monkeypatch.setattr(database, "_SessionFactory", state[1])
    monkeypatch.setattr(legacy, "get_save_and_check_balances_for_pubkey", lambda _pubkey: (0, 0))
    key = PrivateKey(key_number.to_bytes(32, "big"))
    subject = key.public_key_xonly.format().hex()
    challenge = client.post("/api/challenge", json={"pubkey": subject, "method": "nostr"}).get_json()
    record = dict(ACTIVE_CHALLENGES[challenge["challenge_id"]])
    state[3][0] = datetime.now(timezone.utc)
    stamp = int(state[3][0].timestamp())
    tags = [["challenge", challenge["challenge"]]]
    digest = hashlib.sha256(
        json.dumps([0, subject, stamp, 22242, tags, ""], separators=(",", ":")).encode()
    ).hexdigest()
    event_body = {
        "id": digest,
        "pubkey": subject,
        "created_at": stamp,
        "kind": 22242,
        "tags": tags,
        "content": "",
        "sig": key.sign_schnorr(bytes.fromhex(digest)).hex(),
    }
    form = {"challenge_id": challenge["challenge_id"], "nostr_event": event_body}
    response = client.post("/api/verify", json=form)
    return response, subject, form, record


def test_review_real_verified_login_replay_restart_and_fresh_login(state, monkeypatch):
    from app.auth_api_core import ACTIVE_CHALLENGES
    from app.blueprints.api_auth import api_auth_bp

    app = oauth_app(state, monkeypatch)
    app.register_blueprint(api_auth_bp)
    client = app.test_client()
    response, subject, proof, record = nostr_login(client, state, monkeypatch)
    assert response.status_code == 200
    with client.session_transaction() as cookie:
        reference = cookie[BROWSER_GENERATION_KEY]
    service = state[2]
    code = service.authorize(
        subject=subject, browser_generation=reference, redirect_uri=REDIRECT, scope="openid", code_challenge=CHALLENGE
    )
    issued = exchange(service, code)
    assert service.resolve(issued["access_token"]).subject == subject
    assert logout(client).status_code == 302

    # Recreate the service, and simulate a different worker retaining the old
    # challenge. Its real signature still verifies, but the durable ledger denies it.
    replacement = SqlAlchemyOAuthSessionLifecycle(
        state[1], client_id=CLIENT, token_config=state[5], clock=lambda: state[3][0]
    )
    app.extensions[EXTENSION] = replacement
    ACTIVE_CHALLENGES[proof["challenge_id"]] = record
    assert client.post("/api/verify", json=proof).status_code == 503
    with client.session_transaction() as cookie:
        assert BROWSER_GENERATION_KEY not in cookie
    with pytest.raises(OAuthSessionUnavailable):
        replacement.browser_subject(reference)
    response, fresh_subject, _proof, _record = nostr_login(client, state, monkeypatch)
    assert response.status_code == 200 and fresh_subject == subject
    with client.session_transaction() as cookie:
        new_reference = cookie[BROWSER_GENERATION_KEY]
    assert new_reference != reference
    assert replacement.browser_subject(new_reference) == subject
    code = replacement.authorize(
        subject=subject,
        browser_generation=new_reference,
        redirect_uri=REDIRECT,
        scope="openid",
        code_challenge=CHALLENGE,
    )
    assert replacement.resolve(exchange(replacement, code)["access_token"]).subject == subject


def logout_dispatch_app(state, monkeypatch, registration):
    from flask import render_template_string

    import app.browser_routes as routes

    if registration == "blueprint":
        return oauth_app(state, monkeypatch)
    app = Flask("logout_compatibility")
    app.secret_key = "synthetic-cookie-signing-key"
    app.config.update(TESTING=True, APP_CONFIG=state[5])
    app.extensions[EXTENSION] = state[2]
    monkeypatch.setattr(routes, "_BROWSER_ROUTE_HANDLERS", {})
    if registration == "shared":
        app.add_url_rule("/logout", "logout", routes.perform_browser_logout, methods=["GET", "POST"])
        app.add_url_rule("/login", "login", lambda: "login")
    else:
        routes.register_browser_routes(
            app,
            generate_challenge=lambda: "synthetic",
            get_rpc_connection=lambda: None,
            logger=app.logger,
            render_template_string_func=render_template_string,
            special_names={},
            force_relay=None,
            chat_history=[],
            online_users={},
            purge_old_messages=lambda: None,
        )
        if registration == "monolith_alias":
            import app.app as legacy

            # Importing the compatibility module can register its own handlers.
            # Register this test app last so the actual alias delegates here.
            handler = app.view_functions["logout"]
            routes._BROWSER_ROUTE_HANDLERS["logout"] = handler
            app.view_functions["logout"] = legacy.logout
    return app


@pytest.mark.parametrize("registration", ["blueprint", "compatibility", "monolith_alias", "shared"])
@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_review_logout_dispatch_all_safe_methods(state, monkeypatch, registration, method):
    app = logout_dispatch_app(state, monkeypatch, registration)
    client = app.test_client()
    seed_browser(client, state[2])
    issued = exchange(state[2])
    pending = authorize(state[2])
    reference = state[2].test_browser_references[SUBJECT]
    result = client.open("/logout", method=method)
    assert result.status_code == 200
    with client.session_transaction() as cookie:
        assert cookie[BROWSER_GENERATION_KEY] == reference and cookie["logged_in_pubkey"] == SUBJECT
    assert state[2].resolve(issued["access_token"]).subject == SUBJECT
    with state[1]() as db:
        assert db.get(OAuthCode, pending).is_used is False
        assert db.get(OAuthBrowserGeneration, reference).is_active is True


@pytest.mark.parametrize("registration", ["blueprint", "compatibility", "monolith_alias", "shared"])
def test_review_explicit_csrf_logout_dispatch(state, monkeypatch, registration):
    app = logout_dispatch_app(state, monkeypatch, registration)
    client = app.test_client()
    seed_browser(client, state[2])
    issued = exchange(state[2])
    pending = authorize(state[2])
    assert logout(client).status_code == 302
    with pytest.raises(OAuthSessionUnavailable):
        state[2].resolve(issued["access_token"])
    with pytest.raises(OAuthSessionUnavailable):
        exchange(state[2], pending)
    with client.session_transaction() as cookie:
        assert not cookie


@pytest.mark.parametrize(
    "bad",
    [
        "missing",
        "incorrect",
        "malformed",
        "duplicate",
        "unknown",
        "stale",
        "origin_missing",
        "origin_null",
        "origin_evil",
        "host_spoof",
        "query",
        "json",
    ],
)
def test_review_csrf_or_origin_failure_never_mutates(state, monkeypatch, bad):
    from werkzeug.datastructures import MultiDict

    app = oauth_app(state, monkeypatch)
    client = app.test_client()
    seed_browser(client, state[2])
    proof = csrf(client)
    if bad == "stale":
        fresh_browser(state[2])
        seed_browser(client, state[2])
    issued = exchange(state[2])
    reference = state[2].test_browser_references[SUBJECT]
    data = {"csrf_token": proof}
    headers = {"Origin": "https://identity.example"}
    path = "/logout"
    if bad == "missing":
        data = {}
    elif bad == "incorrect":
        data["csrf_token"] = "0" * 64
    elif bad == "malformed":
        data["csrf_token"] = "invalid"
    elif bad == "duplicate":
        data = MultiDict([("csrf_token", proof), ("csrf_token", proof)])
    elif bad == "unknown":
        data["generation"] = reference
    elif bad == "origin_missing":
        headers = {}
    elif bad == "origin_null":
        headers["Origin"] = "null"
    elif bad == "origin_evil":
        headers["Origin"] = "https://evil.example"
    elif bad == "host_spoof":
        headers.update(Origin="http://localhost", Host="localhost", **{"X-Forwarded-Host": "identity.example"})
    elif bad == "query":
        path += "?csrf_token=forbidden"
    result = (
        client.post(path, json=data, headers=headers)
        if bad == "json"
        else client.post(path, data=data, headers=headers)
    )
    assert result.status_code == 403
    assert state[2].resolve(issued["access_token"]).subject == SUBJECT
    with state[1]() as db:
        assert db.get(OAuthBrowserGeneration, reference).is_active is True


def test_review_old_logout_retry_cannot_revoke_replacement(state, monkeypatch):
    app = oauth_app(state, monkeypatch)
    old_client = app.test_client()
    seed_browser(old_client, state[2])
    old_proof = csrf(old_client)
    old_cookie = old_client.get_cookie("session").value
    old_reference = state[2].test_browser_references[SUBJECT]
    fresh_browser(state[2])
    current = exchange(state[2])
    for _ in range(2):
        old_client.set_cookie("session", old_cookie)
        assert logout(old_client, old_proof).status_code == 302
        assert state[2].resolve(current["access_token"]).subject == SUBJECT
    with state[1]() as db:
        assert db.get(OAuthBrowserGeneration, old_reference).is_active is False


@pytest.mark.parametrize("failure", ["write", "commit"])
def test_review_browser_generation_failure_rolls_back_replacement(state, failure):
    engine, factory, service, ticks, _ids, _cfg = state
    issued = exchange(service)
    old = service.test_browser_references[SUBJECT]
    now = ticks[0]
    kwargs = dict(
        subject=SUBJECT,
        challenge="synthetic-proof-failure-" + uuid.uuid4().hex,
        challenge_created=now - timedelta(seconds=1),
        challenge_expires=now + timedelta(seconds=30),
        previous_generation=old,
    )

    def fail_write(_conn, _cursor, statement, _parameters, _context, _many):
        if statement.startswith("INSERT INTO oauth_browser_generations "):
            raise RuntimeError("synthetic unavailable")

    def fail_commit(_conn):
        raise RuntimeError("synthetic unavailable")

    name, callback = ("commit", fail_commit) if failure == "commit" else ("before_cursor_execute", fail_write)
    event.listen(engine, name, callback)
    try:
        with pytest.raises(OAuthSessionUnavailable):
            service.complete_verified_login(**kwargs)
    finally:
        event.remove(engine, name, callback)
    assert service.browser_subject(old) == SUBJECT
    assert service.resolve(issued["access_token"]).subject == SUBJECT
    new = service.complete_verified_login(**kwargs)
    assert new != old
    service.invalidate_browser(new)
    with pytest.raises(OAuthSessionUnavailable):
        service.complete_verified_login(**kwargs)


@pytest.mark.parametrize("phase", ["reservation", "issuance"])
def test_review_expiry_rechecked_after_blocking_write(state, phase):
    engine, factory, service, ticks, _ids, _cfg = state
    reference = service.test_browser_references[SUBJECT]
    code = authorize(service) if phase == "issuance" else None
    with factory() as db:
        expires = db.get(OAuthBrowserGeneration, reference).expires_at.replace(tzinfo=timezone.utc)
    table = "oauth_tokens" if phase == "issuance" else "oauth_codes"

    def expire(_conn, _cursor, statement, _parameters, _context, _many):
        if statement.startswith("INSERT INTO " + table + " "):
            ticks[0] = expires

    event.listen(engine, "before_cursor_execute", expire)
    try:
        with pytest.raises(OAuthSessionUnavailable):
            exchange(service, code) if phase == "issuance" else authorize(service)
    finally:
        event.remove(engine, "before_cursor_execute", expire)
    assert counts(factory) == (0, 0, 0)


@pytest.mark.parametrize(
    "mutation", ["owner", "subject", "client", "proof", "created", "expiry", "reactivate", "delete"]
)
def test_review_browser_fence_immutable_and_no_resurrection(state, mutation):
    _engine, factory, service, _ticks, ids, _cfg = state
    reference = service.test_browser_references[SUBJECT]
    if mutation == "reactivate":
        service.invalidate_browser(reference)
    with pytest.raises((InternalError, IntegrityError)):
        with factory.begin() as db:
            row = db.get(OAuthBrowserGeneration, reference)
            if mutation == "owner":
                row.user_id = ids[OTHER]
            elif mutation == "subject":
                row.subject = OTHER
            elif mutation == "client":
                row.client_id = "other-client"
            elif mutation == "proof":
                row.proof_id = "0" * 64
            elif mutation == "created":
                row.created_at += timedelta(seconds=1)
            elif mutation == "expiry":
                row.expires_at += timedelta(seconds=1)
            elif mutation == "reactivate":
                row.is_active = True
            else:
                db.delete(row)


@pytest.mark.parametrize("compatibility", [False, True])
def test_review_real_legacy_dispatch_consumed_cookie_challenge_replay(state, monkeypatch, compatibility):
    from types import SimpleNamespace

    import app.app as legacy
    import app.blueprints.auth as auth

    monkeypatch.setattr(database, "_SessionFactory", state[1])
    monkeypatch.setattr(auth, "get_rpc_connection", lambda: SimpleNamespace(verifymessage=lambda *_args: True))
    monkeypatch.setattr(auth, "derive_legacy_address_from_pubkey", lambda _key: "synthetic-address")
    monkeypatch.setattr(legacy, "get_save_and_check_balances_for_pubkey", lambda _key: (0, 0))
    app = oauth_app(state, monkeypatch)
    if compatibility:
        app.view_functions["auth.verify_signature"] = legacy.verify_signature
    client = app.test_client()
    assert client.get("/login").status_code == 200
    original_cookie = client.get_cookie("session").value
    with client.session_transaction() as cookie:
        challenge = cookie["challenge"]
    state[3][0] = datetime.now(timezone.utc)
    payload = {"pubkey": "02" + SUBJECT, "signature": "synthetic-verified-signature", "challenge": challenge}
    result = client.post("/verify_signature", json=payload)
    assert result.status_code == 200
    with client.session_transaction() as cookie:
        reference = cookie[BROWSER_GENERATION_KEY]
    assert state[2].browser_subject(reference) == SUBJECT
    assert logout(client).status_code == 302
    client.set_cookie("session", original_cookie)
    assert client.post("/verify_signature", json=payload).status_code == 503
    with client.session_transaction() as cookie:
        assert BROWSER_GENERATION_KEY not in cookie
    assert client.get("/login").status_code == 200
    with client.session_transaction() as cookie:
        fresh_challenge = cookie["challenge"]
    assert fresh_challenge != challenge
    state[3][0] = datetime.now(timezone.utc)
    assert client.post("/verify_signature", json={**payload, "challenge": fresh_challenge}).status_code == 200
    with client.session_transaction() as cookie:
        assert cookie[BROWSER_GENERATION_KEY] != reference


def test_review_http_generation_commit_failure_does_not_publish_cookie(state, monkeypatch):
    from app.blueprints.api_auth import api_auth_bp

    app = oauth_app(state, monkeypatch)
    app.register_blueprint(api_auth_bp)
    client = app.test_client()
    result, subject, _proof, _record = nostr_login(client, state, monkeypatch)
    assert result.status_code == 200
    with client.session_transaction() as cookie:
        old = cookie[BROWSER_GENERATION_KEY]
    armed = []

    def before_insert(_conn, _cursor, statement, _parameters, _context, _many):
        if statement.startswith("INSERT INTO oauth_browser_generations "):
            armed.append(True)

    def before_commit(_conn):
        if armed:
            raise RuntimeError("synthetic unavailable")

    engine = state[0]
    event.listen(engine, "before_cursor_execute", before_insert)
    event.listen(engine, "commit", before_commit)
    try:
        result, _subject, _proof, _record = nostr_login(client, state, monkeypatch)
        assert result.status_code == 503
    finally:
        event.remove(engine, "before_cursor_execute", before_insert)
        event.remove(engine, "commit", before_commit)
    assert armed
    with client.session_transaction() as cookie:
        assert cookie[BROWSER_GENERATION_KEY] == old
    assert state[2].browser_subject(old) == subject


def test_review_token_expiry_is_capped_by_browser_not_extended_on_replacement(state):
    _engine, factory, service, ticks, _ids, _cfg = state
    reference = service.test_browser_references[SUBJECT]
    with factory() as db:
        browser_expiry = db.get(OAuthBrowserGeneration, reference).expires_at.replace(tzinfo=timezone.utc)
    # Issue near the browser boundary using a real bounded clock. The JWT validator
    # uses wall time, so establish a short-lived browser rather than future JWT iat.
    short = SqlAlchemyOAuthSessionLifecycle(
        factory, client_id=CLIENT, token_config=state[5], clock=lambda: ticks[0], browser_ttl_seconds=30
    )
    short.test_browser_references = {}
    reference = fresh_browser(short)
    first = exchange(short)
    second = exchange(short)
    with factory() as db:
        current = db.get(OAuthBrowserGeneration, reference)
        assert current.expires_at.replace(tzinfo=timezone.utc) < browser_expiry
        assert db.get(OAuthToken, token_id(second)).access_token_expires_at <= current.expires_at
        assert db.get(OAuthToken, token_id(first)).is_revoked is True
        assert current.is_active is True
    assert second["expires_in"] <= 30


def test_review_unrelated_client_and_disabled_logout_keep_compatibility(state, monkeypatch):
    app = oauth_app(state, monkeypatch)
    client = app.test_client()
    # An unrelated OAuth client keeps its original subject admission; it does
    # not accidentally gain a browser fence or a mapped Session.
    with client.session_transaction() as cookie:
        cookie.update(logged_in_pubkey=SUBJECT, login_method="legacy", access_level="limited")
    response = client.get(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": "other-client",
            "redirect_uri": REDIRECT,
            "scope": "openid",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
        },
    )
    assert response.status_code == 302
    code = parse_qs(urlparse(response.location).query)["code"][0]
    with state[1]() as db:
        assert db.get(OAuthSessionCodeBinding, code) is None
    del app.extensions[EXTENSION]
    issued = exchange(state[2])
    assert client.get("/logout").status_code == 302
    assert state[2].resolve(issued["access_token"]).subject == SUBJECT


def test_review_browser_proof_commitment_exact_domain_and_equal_concurrent_consumption(state):
    from threading import Barrier

    _engine, factory, service, ticks, _ids, _cfg = state
    kwargs = dict(
        subject=SUBJECT,
        challenge="synthetic-browser-proof-vector",
        challenge_created=ticks[0] - timedelta(seconds=1),
        challenge_expires=ticks[0] + timedelta(seconds=30),
    )
    start = Barrier(2, timeout=10)

    def consume():
        start.wait()
        try:
            return service.complete_verified_login(**kwargs)
        except OAuthSessionUnavailable:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        references = list(pool.map(lambda _index: consume(), range(2)))
    winners = [reference for reference in references if reference is not None]
    assert len(winners) == 1
    with factory() as db:
        assert (
            db.get(OAuthBrowserGeneration, winners[0]).proof_id
            == hashlib.sha256(b"HODLXXI_BROWSER_LOGIN_PROOF_V1\0synthetic-browser-proof-vector").hexdigest()
        )


@pytest.mark.parametrize("compatibility", [False, True])
def test_review_api_legacy_verified_boundary_creates_browser_generation(state, monkeypatch, compatibility):
    from types import SimpleNamespace

    import app.app as legacy
    from app.blueprints.api_auth import api_auth_bp

    monkeypatch.setattr(database, "_SessionFactory", state[1])
    monkeypatch.setattr(legacy, "get_rpc_connection", lambda: SimpleNamespace(verifymessage=lambda *_args: True))
    monkeypatch.setattr(legacy, "derive_legacy_address_from_pubkey", lambda _key: "synthetic-address")
    monkeypatch.setattr(legacy, "get_save_and_check_balances_for_pubkey", lambda _key: (0, 0))
    app = oauth_app(state, monkeypatch)
    app.register_blueprint(api_auth_bp)
    if compatibility:
        app.view_functions["api_auth.api_challenge"] = legacy.api_challenge
        app.view_functions["api_auth.api_verify"] = legacy.api_verify
    client = app.test_client()
    challenge = client.post("/api/challenge", json={"pubkey": "02" + SUBJECT, "method": "api"}).get_json()
    state[3][0] = datetime.now(timezone.utc)
    response = client.post(
        "/api/verify",
        json={
            "challenge_id": challenge["challenge_id"],
            "pubkey": "02" + SUBJECT,
            "signature": "synthetic-verified",
        },
    )
    assert response.status_code == 200
    with client.session_transaction() as cookie:
        assert cookie["login_method"] == "legacy"
        assert state[2].browser_subject(cookie[BROWSER_GENERATION_KEY]) == SUBJECT


def test_review_code_cannot_rebind_to_another_browser_generation(state):
    code = authorize(state[2])
    fresh_browser(state[2])
    with pytest.raises((InternalError, IntegrityError)):
        with state[1].begin() as db:
            db.get(OAuthSessionCodeBinding, code).browser_generation_id = state[2].test_browser_references[SUBJECT]

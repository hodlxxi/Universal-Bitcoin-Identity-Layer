from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.services.confidential_service_assertion_replay_storage import (
    PostgresConfidentialServiceAssertionReplayStore,
)
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    CredentialUnavailable,
)
from app.services.privacy_full_directory_internal_delivery import (
    PrivacyFullDirectoryInternalDeliveryRuntime,
)

ACKNOWLEDGEMENT = "DISPOSABLE-CONFIDENTIAL-REPLAY-POSTGRES-V1"


@pytest.fixture(scope="module")
def postgres_factory():
    dsn = os.getenv("HODLXXI_DISPOSABLE_POSTGRES_DSN")
    if not dsn:
        pytest.skip("disposable PostgreSQL DSN not provided")
    if os.getenv("HODLXXI_DISPOSABLE_POSTGRES_ACK") != ACKNOWLEDGEMENT:
        pytest.fail("disposable PostgreSQL acknowledgement is required")

    url = make_url(dsn)
    if url.get_backend_name() != "postgresql":
        pytest.fail("disposable PostgreSQL DSN must use PostgreSQL")
    if not re.fullmatch(r"hodlxxi_replay_test_[a-z0-9_]+", url.database or ""):
        pytest.fail("disposable PostgreSQL database name is not marker-owned")
    if url.host not in (None, "", "localhost", "127.0.0.1", "::1"):
        pytest.fail("disposable PostgreSQL must be local")

    schema = f"replay_store_test_{uuid.uuid4().hex}"
    admin_engine = create_engine(dsn, pool_pre_ping=True)
    with admin_engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')

    test_engine = create_engine(
        dsn,
        pool_pre_ping=True,
        connect_args={"options": f"-csearch_path={schema}"},
    )
    migration = Path("migrations/2026-08-31_confidential_service_assertion_replay_markers_v1.sql")
    with test_engine.begin() as connection:
        for statement in migration.read_text(encoding="utf-8").split(";"):
            if statement.strip():
                connection.exec_driver_sql(statement)

    factory = sessionmaker(bind=test_engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        test_engine.dispose()
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        admin_engine.dispose()


def database_now(factory):
    with factory() as session:
        return session.execute(text("SELECT CAST(FLOOR(EXTRACT(EPOCH FROM clock_timestamp())) AS BIGINT)")).scalar_one()


def marker_count(factory, digest):
    with factory() as session:
        return session.execute(
            text(
                "SELECT COUNT(*) FROM confidential_service_assertion_replay_markers " "WHERE jti_sha256 = :jti_sha256"
            ),
            {"jti_sha256": digest},
        ).scalar_one()


def _public_jwk(key, kid):
    value = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    value.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return value


def test_fresh_repeat_different_and_raw_jti_privacy(postgres_factory):
    store = PostgresConfidentialServiceAssertionReplayStore(postgres_factory)
    first = f"fresh-{uuid.uuid4().hex}"
    second = f"different-{uuid.uuid4().hex}"
    deadline = database_now(postgres_factory) + 600

    assert store(first, deadline) is True
    assert store(first, deadline) is False
    assert store(second, deadline) is True

    first_digest = hashlib.sha256(first.encode("utf-8")).hexdigest()
    with postgres_factory() as session:
        rows = session.execute(
            text(
                "SELECT jti_sha256, retention_deadline_exclusive "
                "FROM confidential_service_assertion_replay_markers "
                "WHERE jti_sha256 = :jti_sha256"
            ),
            {"jti_sha256": first_digest},
        ).all()
    assert rows == [(first_digest, deadline)]
    assert first not in repr(rows)


def test_concurrent_same_jti_has_exactly_one_database_authorized_success(postgres_factory):
    store = PostgresConfidentialServiceAssertionReplayStore(postgres_factory)
    jti = f"concurrent-{uuid.uuid4().hex}"
    deadline = database_now(postgres_factory) + 600

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _attempt: store(jti, deadline), range(32)))

    assert results.count(True) == 1
    assert results.count(False) == 31
    assert marker_count(postgres_factory, hashlib.sha256(jti.encode("utf-8")).hexdigest()) == 1


def test_postgresql_primary_key_is_uniqueness_authority(postgres_factory):
    jti = f"constraint-{uuid.uuid4().hex}"
    digest = hashlib.sha256(jti.encode("utf-8")).hexdigest()
    deadline = database_now(postgres_factory) + 600
    store = PostgresConfidentialServiceAssertionReplayStore(postgres_factory)
    assert store(jti, deadline) is True

    with pytest.raises(IntegrityError):
        with postgres_factory() as session:
            session.execute(
                text(
                    "INSERT INTO confidential_service_assertion_replay_markers "
                    "(jti_sha256, retention_deadline_exclusive) "
                    "VALUES (:jti_sha256, :retention_deadline_exclusive)"
                ),
                {
                    "jti_sha256": digest,
                    "retention_deadline_exclusive": deadline,
                },
            )
            session.commit()


def test_past_deadline_fails_closed_without_marker(postgres_factory):
    store = PostgresConfidentialServiceAssertionReplayStore(postgres_factory)
    jti = f"past-{uuid.uuid4().hex}"
    digest = hashlib.sha256(jti.encode("utf-8")).hexdigest()

    assert store(jti, database_now(postgres_factory)) is False
    assert marker_count(postgres_factory, digest) == 0


def test_cleanup_waits_for_exclusive_deadline(postgres_factory):
    store = PostgresConfidentialServiceAssertionReplayStore(postgres_factory)
    jti = f"cleanup-{uuid.uuid4().hex}"
    digest = hashlib.sha256(jti.encode("utf-8")).hexdigest()
    deadline = database_now(postgres_factory) + 2

    assert store(jti, deadline) is True
    assert store.cleanup_expired() == 0
    assert marker_count(postgres_factory, digest) == 1

    timeout = time.monotonic() + 5
    while database_now(postgres_factory) < deadline and time.monotonic() < timeout:
        time.sleep(0.05)
    assert database_now(postgres_factory) >= deadline
    assert store.cleanup_expired() == 1
    assert marker_count(postgres_factory, digest) == 0


def test_cleanup_cannot_weaken_concurrent_fresh_consume(postgres_factory):
    store = PostgresConfidentialServiceAssertionReplayStore(postgres_factory)
    jti = f"cleanup-race-{uuid.uuid4().hex}"
    deadline = database_now(postgres_factory) + 600

    def attempt(index):
        if index % 5 == 0:
            return "cleanup", store.cleanup_expired()
        return "consume", store(jti, deadline)

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(40)))

    consumes = [value for kind, value in results if kind == "consume"]
    cleanups = [value for kind, value in results if kind == "cleanup"]
    assert consumes.count(True) == 1
    assert all(value is False for value in consumes if value is not True)
    assert cleanups == [0] * len(cleanups)


def test_internal_delivery_issuance_uses_durable_postgresql_replay_consumer(postgres_factory, monkeypatch):
    now = database_now(postgres_factory)
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: now)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_id = "social-confidential-backend"
    token_audience = "https://identity.example/internal/v1/social/service-token"
    config = ConfidentialServiceConfig(
        enabled=True,
        client_id=client_id,
        service_principal="service:social-full-directory",
        issuer="https://identity.example",
        token_endpoint_audience=token_audience,
        service_resource_audience="https://identity.example/internal/v1/social/full-directory",
        client_jwks=(_public_jwk(client_key, "client-key"),),
        service_jwks=(_public_jwk(service_key, "service-key"),),
    )
    runtime = PrivacyFullDirectoryInternalDeliveryRuntime(
        service_config=config,
        replay_consumer=PostgresConfidentialServiceAssertionReplayStore(postgres_factory),
        service_signing_key=service_key,
        service_signing_kid="service-key",
        viewer_oauth_client_id="social-browser-client",
        viewer_token_validator=lambda _token: None,
        current_entitlement_resolver=lambda _subject: None,
        full_population_provider=lambda: None,
        alias_secret=b"test-only-alias-secret-material!!",
    )
    jti = f"runtime-wiring-{uuid.uuid4().hex}"
    assertion = jwt.encode(
        {
            "iss": client_id,
            "sub": client_id,
            "aud": token_audience,
            "iat": now,
            "exp": now + 60,
            "jti": jti,
            "token_use": "client_assertion",
            "grant_type": "client_credentials",
            "purpose": "service_client_authentication",
        },
        client_key,
        algorithm="RS256",
        headers={"kid": "client-key"},
    )

    def attempt(_index):
        try:
            return isinstance(runtime.issue_service_token(assertion), str)
        except CredentialUnavailable:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(16)))

    assert results.count(True) == 1
    assert results.count(False) == 15
    with pytest.raises(CredentialUnavailable):
        runtime.issue_service_token(assertion)
    assert marker_count(postgres_factory, hashlib.sha256(jti.encode("utf-8")).hexdigest()) == 1

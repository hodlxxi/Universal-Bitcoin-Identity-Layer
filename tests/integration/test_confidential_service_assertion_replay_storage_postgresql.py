from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import re
import time
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.services.confidential_service_assertion_replay_storage import (
    PostgresConfidentialServiceAssertionReplayStore,
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

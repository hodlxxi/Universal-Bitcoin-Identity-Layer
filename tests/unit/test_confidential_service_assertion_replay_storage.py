from __future__ import annotations

import hashlib
import inspect

import pytest

import app.services.confidential_service_assertion_replay_storage as storage_module
from app.services.confidential_service_assertion_replay_storage import (
    MAX_POSTGRES_BIGINT,
    PostgresConfidentialServiceAssertionReplayStore,
)


class FakeResult:
    def __init__(self, *, scalar=None, rowcount=0):
        self._scalar = scalar
        self.rowcount = rowcount

    def scalar_one_or_none(self):
        return self._scalar


class FakeSession:
    def __init__(self, results=(), error=None, commit_error=None):
        self.results = list(results)
        self.error = error
        self.commit_error = commit_error
        self.calls = []
        self.commits = 0
        self.rollbacks = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, statement, parameters=None):
        self.calls.append((str(statement), parameters))
        if self.error is not None:
            raise self.error
        return self.results.pop(0)

    def commit(self):
        if self.commit_error is not None:
            raise self.commit_error
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


class FakeSessionFactory:
    def __init__(self, session):
        self.session = session
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.session


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_fresh_repeat_and_different_jti_use_only_digest_parameters():
    first = "assertion-jti-one"
    second = "assertion-jti-two"
    session = FakeSession(
        (
            FakeResult(scalar=digest(first)),
            FakeResult(scalar=None),
            FakeResult(scalar=digest(second)),
        )
    )
    store = PostgresConfidentialServiceAssertionReplayStore(FakeSessionFactory(session))

    assert store(first, 2_000_000_000) is True
    assert store(first, 2_000_000_000) is False
    assert store(second, 2_000_000_000) is True
    assert session.commits == 2
    assert session.rollbacks == 1
    assert [call[1]["jti_sha256"] for call in session.calls] == [digest(first), digest(first), digest(second)]
    assert all(first not in repr(call) and second not in repr(call) for call in session.calls)


@pytest.mark.parametrize(
    "jti",
    (
        None,
        123,
        "",
        " leading",
        "trailing ",
        "a" * 129,
        "\ud800",
    ),
)
def test_invalid_jti_fails_closed_without_opening_storage(jti):
    factory = FakeSessionFactory(FakeSession())
    store = PostgresConfidentialServiceAssertionReplayStore(factory)

    assert store(jti, 2_000_000_000) is False
    assert factory.calls == 0


@pytest.mark.parametrize("deadline", (None, True, 1.5, 0, -1, MAX_POSTGRES_BIGINT + 1))
def test_invalid_retention_deadline_fails_closed_without_opening_storage(deadline):
    factory = FakeSessionFactory(FakeSession())
    store = PostgresConfidentialServiceAssertionReplayStore(factory)

    assert store("assertion-jti", deadline) is False
    assert factory.calls == 0


@pytest.mark.parametrize(
    "session",
    (
        FakeSession(error=RuntimeError("database failure containing assertion-jti")),
        FakeSession((FakeResult(scalar=digest("assertion-jti")),), commit_error=RuntimeError("commit failed")),
        FakeSession((FakeResult(scalar="0" * 64),)),
    ),
)
def test_storage_and_ambiguous_results_fail_closed_without_logging(session, caplog):
    raw_jti = "assertion-jti"
    jti_digest = digest(raw_jti)
    store = PostgresConfidentialServiceAssertionReplayStore(FakeSessionFactory(session))

    with caplog.at_level("DEBUG"):
        assert store(raw_jti, 2_000_000_000) is False

    assert raw_jti not in caplog.text
    assert jti_digest not in caplog.text
    assert caplog.records == []


def test_cleanup_is_separate_fail_closed_and_uses_database_clock():
    successful_session = FakeSession((FakeResult(rowcount=3),))
    successful = PostgresConfidentialServiceAssertionReplayStore(FakeSessionFactory(successful_session))
    failed = PostgresConfidentialServiceAssertionReplayStore(
        FakeSessionFactory(FakeSession(error=RuntimeError("cleanup unavailable")))
    )

    assert successful.cleanup_expired() == 3
    assert successful_session.commits == 1
    assert failed.cleanup_expired() == 0
    cleanup_sql = str(storage_module._CLEANUP_SQL).lower()
    assert "retention_deadline_exclusive <=" in cleanup_sql
    assert "clock_timestamp()" in cleanup_sql


def test_atomic_sql_and_callable_contract_are_exact():
    parameters = list(inspect.signature(PostgresConfidentialServiceAssertionReplayStore.__call__).parameters)
    assert parameters == ["self", "jti", "retention_deadline_exclusive"]

    sql = " ".join(str(storage_module._CONSUME_SQL).lower().split())
    assert sql.startswith("insert into confidential_service_assertion_replay_markers")
    assert "on conflict (jti_sha256) do nothing" in sql
    assert "returning jti_sha256" in sql
    assert "clock_timestamp()" in sql
    assert sql.count("insert into") == 1


def test_adapter_has_no_process_local_redis_or_filesystem_fallback():
    source = inspect.getsource(storage_module).lower()
    for forbidden in ("import redis", "import sqlite", "tempfile", "shelve", "_markers = {}", "logging."):
        assert forbidden not in source
    with pytest.raises(ValueError, match="invalid replay store session factory"):
        PostgresConfidentialServiceAssertionReplayStore(None)

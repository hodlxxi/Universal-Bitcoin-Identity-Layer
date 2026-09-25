"""Guarded disposable PostgreSQL 16 ACTIVE alias-namespace tests.

The suite requires an explicit synthetic target on a high loopback TCP port,
with Unix sockets disabled. It never reads DATABASE_URL or defaults to 5432.
"""

from __future__ import annotations

import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue

import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.services import social_messaging_active_alias_namespace_storage as storage

PREFIX = "HODLXXI_ACTIVE_ALIAS_NAMESPACE_TEST_"
ACK = "DISPOSABLE-SOCIAL-ACTIVE-ALIAS-NAMESPACE-POSTGRES-V1"
MIGRATION = Path(__file__).resolve().parents[2] / (
    "migrations/2026-09-24_social_messaging_active_alias_namespace_v1.sql"
)
ALIAS_SECRET = bytes(range(32))
ROTATED_SECRET = bytes(reversed(range(32)))
DENIED = storage.ActiveAliasNamespaceUnavailable
ERROR = "^social messaging active alias namespace unavailable$"


@pytest.fixture(scope="module")
def postgres_target():
    dsn = os.environ.get(PREFIX + "DSN")
    if not dsn:
        pytest.skip("explicit disposable ACTIVE alias-namespace PostgreSQL target not provided")
    assert os.environ.get(PREFIX + "ACK") == ACK
    data = Path(os.environ[PREFIX + "DATA"]).resolve()
    assert data.parent.parent == Path("/tmp")
    assert data.parent.name.startswith("hodlxxi-active-alias-namespace-")
    assert data.name == "data" and (data / "PG_VERSION").read_text().strip() == "16"
    port = int(os.environ[PREFIX + "PORT"])
    url = make_url(dsn)
    assert url.drivername == "postgresql+psycopg2"
    assert url.host == "127.0.0.1" and url.port == port and 49152 <= port <= 65535
    assert url.database == "hodlxxi_active_alias_namespace_test"
    assert url.username == "active_alias_namespace_test" and url.password is None and not url.query
    engine = create_engine(url, poolclass=NullPool, hide_parameters=True)
    try:
        with engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT current_database(), current_setting('data_directory'), "
                    "current_setting('port'), current_setting('listen_addresses'), "
                    "current_setting('unix_socket_directories'), version()"
                )
            ).one()
            assert row[0] == url.database
            assert Path(row[1]).resolve() == data
            assert int(row[2]) == port
            assert row[3:5] == ("127.0.0.1", "")
            assert row[5].startswith("PostgreSQL 16.")
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def database(postgres_target):
    schema = "active_alias_" + uuid.uuid4().hex
    with postgres_target.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    engine = create_engine(
        postgres_target.url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"options": f"-c search_path={schema} -c statement_timeout=10000 -c lock_timeout=5000"},
    )
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(MIGRATION.read_text(encoding="ascii"))
        yield engine, sessionmaker(engine, expire_on_commit=False)
    finally:
        engine.dispose()
        with postgres_target.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')


def commitment(secret, version):
    return storage.active_alias_namespace_secret_commitment(
        alias_secret=secret,
        alias_version=version,
    )


def provision(factory, *, secret=ALIAS_SECRET, version=1):
    with factory.begin() as session:
        session.execute(
            storage.SocialMessagingActiveAliasNamespaceRow.__table__.insert().values(
                alias_version=version,
                secret_commitment=commitment(secret, version),
                lifecycle_state=storage.ACTIVE_NAMESPACE_STATE,
            )
        )


def lock_current(factory, *, secret=ALIAS_SECRET, version=1):
    with factory.begin() as session:
        return storage.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
            session,
            configured_alias_secret=secret,
            configured_alias_version=version,
        ).lock_configured_active_namespace()


def rotate_in_transaction(session, *, old_version, new_secret, new_version):
    table = storage.SocialMessagingActiveAliasNamespaceRow.__table__
    updated = session.execute(
        table.update()
        .where(
            table.c.alias_version == old_version,
            table.c.lifecycle_state == storage.ACTIVE_NAMESPACE_STATE,
        )
        .values(lifecycle_state=storage.RETIRED_NAMESPACE_STATE)
    )
    assert updated.rowcount == 1
    session.execute(
        table.insert().values(
            alias_version=new_version,
            secret_commitment=commitment(new_secret, new_version),
            lifecycle_state=storage.ACTIVE_NAMESPACE_STATE,
        )
    )


def wait_until_blocked(engine, waiter, blocker):
    deadline = time.monotonic() + 4
    with engine.connect() as connection:
        while time.monotonic() < deadline:
            blockers = connection.execute(
                text("SELECT pg_blocking_pids(:pid)"),
                {"pid": waiter},
            ).scalar_one()
            if blocker in blockers:
                return
            time.sleep(0.01)
    pytest.fail("synthetic contender did not wait on the namespace row lock")


def test_migration_is_empty_and_matches_model_with_complete_guards(database):
    engine, factory = database
    inspector = inspect(engine)
    assert inspector.get_table_names() == [storage.NAMESPACE_TABLE]
    columns = inspector.get_columns(storage.NAMESPACE_TABLE)
    table = storage.SocialMessagingActiveAliasNamespaceRow.__table__
    assert {column["name"] for column in columns} == set(table.c.keys())
    for column in columns:
        expected = table.c[column["name"]]
        assert column["nullable"] == expected.nullable
        assert str(column["type"]) == str(expected.type)
        assert column["default"] is None
    with factory() as session:
        assert session.execute(select(table)).all() == []
        assert (
            session.execute(
                text(
                    "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal "
                    "AND tgenabled = 'O' AND tgrelid = to_regclass(:table)"
                ),
                {"table": storage.NAMESPACE_TABLE},
            ).scalar_one()
            == storage._EXPECTED_TRIGGER_COUNT
        )
    with pytest.raises(DENIED, match=ERROR):
        lock_current(factory)


def test_exact_configured_version_and_commitment_are_required_without_secret_storage(database):
    _engine, factory = database
    provision(factory)
    active = lock_current(factory)
    assert active.alias_version == 1
    assert active.secret_commitment == commitment(ALIAS_SECRET, 1)
    assert ALIAS_SECRET.hex() not in active.secret_commitment
    with pytest.raises(DENIED, match=ERROR):
        lock_current(factory, secret=ROTATED_SECRET, version=1)
    with pytest.raises(DENIED, match=ERROR):
        lock_current(factory, secret=ALIAS_SECRET, version=2)


def test_old_and_higher_version_history_never_selects_active_namespace(database):
    _engine, factory = database
    provision(factory, secret=ROTATED_SECRET, version=99)
    with factory.begin() as session:
        rotate_in_transaction(
            session,
            old_version=99,
            new_secret=ALIAS_SECRET,
            new_version=2,
        )
    assert lock_current(factory, secret=ALIAS_SECRET, version=2).alias_version == 2
    with pytest.raises(DENIED, match=ERROR):
        lock_current(factory, secret=ROTATED_SECRET, version=99)


def test_database_denies_multiple_active_illegal_history_mutation_and_truncation(database):
    _engine, factory = database
    provision(factory)
    table = storage.SocialMessagingActiveAliasNamespaceRow.__table__
    statements = (
        table.insert().values(
            alias_version=2,
            secret_commitment=commitment(ROTATED_SECRET, 2),
            lifecycle_state=storage.ACTIVE_NAMESPACE_STATE,
        ),
        table.insert().values(
            alias_version=2,
            secret_commitment=commitment(ROTATED_SECRET, 2),
            lifecycle_state=storage.RETIRED_NAMESPACE_STATE,
        ),
        table.update().values(alias_version=2),
        table.delete(),
        text(f"TRUNCATE {storage.NAMESPACE_TABLE}"),
    )
    for statement in statements:
        with pytest.raises(DBAPIError):
            with factory.begin() as session:
                session.execute(statement)
    assert lock_current(factory).alias_version == 1


def test_rotation_waits_for_locked_reader_then_stale_configuration_denies(database):
    engine, factory = database
    provision(factory)
    pids = Queue()

    def rotate():
        with factory.begin() as session:
            pids.put(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
            rotate_in_transaction(
                session,
                old_version=1,
                new_secret=ROTATED_SECRET,
                new_version=2,
            )
        return "rotated"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as reader_session:
            transaction = reader_session.begin()
            try:
                locked = storage.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
                    reader_session,
                    configured_alias_secret=ALIAS_SECRET,
                    configured_alias_version=1,
                ).lock_configured_active_namespace()
                assert locked.alias_version == 1
                blocker = reader_session.execute(text("SELECT pg_backend_pid()")).scalar_one()
                future = pool.submit(rotate)
                wait_until_blocked(engine, pids.get(timeout=5), blocker)
                assert not future.done()
                transaction.commit()
            finally:
                if transaction.is_active:
                    transaction.rollback()
        assert future.result(timeout=10) == "rotated"

    with pytest.raises(DENIED, match=ERROR):
        lock_current(factory, secret=ALIAS_SECRET, version=1)
    assert lock_current(factory, secret=ROTATED_SECRET, version=2).alias_version == 2


def test_reader_waiting_on_concurrent_rotation_never_accepts_stale_row(database):
    engine, factory = database
    provision(factory)
    pids = Queue()

    def read_stale():
        try:
            with factory.begin() as session:
                pids.put(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
                storage.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
                    session,
                    configured_alias_secret=ALIAS_SECRET,
                    configured_alias_version=1,
                ).lock_configured_active_namespace()
            return "accepted"
        except DENIED:
            return "denied"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as rotation_session:
            transaction = rotation_session.begin()
            try:
                rotate_in_transaction(
                    rotation_session,
                    old_version=1,
                    new_secret=ROTATED_SECRET,
                    new_version=2,
                )
                blocker = rotation_session.execute(text("SELECT pg_backend_pid()")).scalar_one()
                future = pool.submit(read_stale)
                wait_until_blocked(engine, pids.get(timeout=5), blocker)
                assert not future.done()
                transaction.commit()
            finally:
                if transaction.is_active:
                    transaction.rollback()
        assert future.result(timeout=10) == "denied"

    assert lock_current(factory, secret=ROTATED_SECRET, version=2).alias_version == 2


def test_missing_guard_index_autocommit_and_replaced_transaction_fail_closed(database):
    engine, factory = database
    provision(factory)
    with engine.begin() as connection:
        connection.exec_driver_sql(f"DROP TRIGGER trg_social_active_alias_namespace_guard ON {storage.NAMESPACE_TABLE}")
    with pytest.raises(DENIED, match=ERROR):
        lock_current(factory)

    autocommit = engine.execution_options(isolation_level="AUTOCOMMIT")
    with sessionmaker(autocommit).begin() as session:
        with pytest.raises(DENIED, match=ERROR):
            storage.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
                session,
                configured_alias_secret=ALIAS_SECRET,
                configured_alias_version=1,
            )


def test_migration_ddl_is_transactional(postgres_target):
    schema = "active_alias_ddl_" + uuid.uuid4().hex
    with postgres_target.connect() as connection:
        transaction = connection.begin()
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        connection.exec_driver_sql(f'SET LOCAL search_path = "{schema}"')
        connection.exec_driver_sql(MIGRATION.read_text(encoding="ascii"))
        assert connection.execute(
            text("SELECT to_regclass(:table)"),
            {"table": storage.NAMESPACE_TABLE},
        ).scalar_one()
        transaction.rollback()
    with postgres_target.connect() as connection:
        assert (
            connection.execute(
                text("SELECT to_regnamespace(:schema)"),
                {"schema": schema},
            ).scalar_one()
            is None
        )

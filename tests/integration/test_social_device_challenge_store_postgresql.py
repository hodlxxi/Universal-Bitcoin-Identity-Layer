"""Guarded synthetic PostgreSQL only; never use DATABASE_URL or port 5432.

Mirrors the existing disposable Social storage rehearsal: explicit opt-in,
exact target identity, isolated schemas, no fallback. This variant uses a
non-live loopback TCP port and requires Unix sockets to be disabled.
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

from app.services import social_device_challenge_store as storage
from tests.unit.test_social_device_challenge_store import DENIED, ERROR, MIGRATION, VECTORS, arguments, persisted

PREFIX = "HODLXXI_DEVICE_CHALLENGE_TEST_"
ACK = "DISPOSABLE-SOCIAL-DEVICE-CHALLENGE-POSTGRES-V1"
TABLE = storage.SocialDeviceAdmissionChallengeRow.__table__


@pytest.fixture(scope="module")
def postgres_target():
    dsn = os.environ.get(PREFIX + "DSN")
    if not dsn:
        pytest.skip("explicit disposable device-challenge PostgreSQL target not provided")
    assert os.environ.get(PREFIX + "ACK") == ACK
    data = Path(os.environ[PREFIX + "DATA"]).resolve()
    assert data.parent.parent == Path("/tmp")
    assert data.parent.name.startswith("hodlxxi-device-challenge-")
    assert data.name == "data" and (data / "PG_VERSION").read_text().strip() == "16"
    port = int(os.environ[PREFIX + "PORT"])
    url = make_url(dsn)
    assert url.drivername == "postgresql+psycopg2"
    assert url.host == "127.0.0.1" and url.port == port and 49152 <= port <= 65535
    assert url.database == "hodlxxi_device_challenge_test"
    assert url.username == "challenge_test" and url.password is None and not url.query
    engine = create_engine(url, poolclass=NullPool, hide_parameters=True)
    try:
        with engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT current_database(), current_setting('data_directory'), current_setting('port'), "
                    "current_setting('listen_addresses'), current_setting('unix_socket_directories'), version()"
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
    schema = "challenge_" + uuid.uuid4().hex
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


def create(factory, name="ciphertextSubmit"):
    with factory.begin() as session:
        return storage.SqlAlchemyDeviceChallengeStore(session).create_issued(**arguments(name))


def read(factory, challenge_id):
    with factory.begin() as session:
        return storage.SqlAlchemyDeviceChallengeStore(session).read(challenge_id)


def rows(factory):
    with factory() as session:
        return session.execute(select(TABLE)).mappings().all()


def wait_until_blocked(engine, waiter, blocker):
    deadline = time.monotonic() + 4
    with engine.connect() as connection:
        while time.monotonic() < deadline:
            blockers = connection.execute(text("SELECT pg_blocking_pids(:pid)"), {"pid": waiter}).scalar_one()
            if blocker in blockers:
                return
            time.sleep(0.01)
    pytest.fail("synthetic contender did not wait on the authoritative PostgreSQL lock")


@pytest.mark.parametrize("name", VECTORS)
def test_exact_create_read_and_lock_roundtrip(database, name):
    _engine, factory = database
    created = create(factory, name)
    assert rows(factory) == [persisted(name)]
    assert read(factory, created.context.challenge_id) == created
    with factory.begin() as session:
        locked = storage.SqlAlchemyDeviceChallengeStore(session).read_for_update(created.context.challenge_id)
        assert locked == created
        assert locked.inspect_deadline(now=locked.expires_at).disposition == "expired"
    assert rows(factory) == [persisted(name)]


def test_migration_schema_matches_model_and_has_no_extra_owner(database):
    engine, _factory = database
    inspector = inspect(engine)
    assert inspector.get_table_names() == [storage.TABLE]
    columns = inspector.get_columns(storage.TABLE)
    assert {c["name"] for c in columns} == set(TABLE.c.keys())
    for column in columns:
        expected = TABLE.c[column["name"]]
        assert column["nullable"] == expected.nullable
        assert str(column["type"]) == str(expected.type)
        assert column["default"] is None
    assert inspector.get_pk_constraint(storage.TABLE)["constrained_columns"] == ["challenge_id"]
    assert {c["name"] for c in inspector.get_check_constraints(storage.TABLE)} == {
        c.name for c in TABLE.constraints if c.name
    }
    assert inspector.get_foreign_keys(storage.TABLE) == []
    with engine.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM pg_trigger WHERE tgrelid = to_regclass('social_device_admission_challenges') "
                    "AND NOT tgisinternal AND tgenabled = 'O'"
                )
            ).scalar_one()
            == 2
        )


@pytest.mark.parametrize("first_commits", (True, False))
def test_concurrent_creates_have_one_winner_and_rollback_releases_reservation(database, first_commits):
    engine, factory = database
    pids = Queue()

    def contender():
        try:
            with factory.begin() as session:
                pids.put(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
                storage.SqlAlchemyDeviceChallengeStore(session).create_issued(**arguments())
            return "created"
        except DENIED:
            return "denied"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as first:
            transaction = first.begin()
            try:
                storage.SqlAlchemyDeviceChallengeStore(first).create_issued(**arguments())
                first_pid = first.execute(text("SELECT pg_backend_pid()")).scalar_one()
                future = pool.submit(contender)
                wait_until_blocked(engine, pids.get(timeout=5), first_pid)
                assert not future.done()
                if first_commits:
                    transaction.commit()
                else:
                    transaction.rollback()
            finally:
                if transaction.is_active:
                    transaction.rollback()
        assert future.result(timeout=10) == ("denied" if first_commits else "created")
    assert rows(factory) == [persisted()]


def test_read_for_update_waits_and_refreshes_authoritative_state_in_same_transaction(database):
    engine, factory = database
    created = create(factory)
    pids = Queue()

    def waiter():
        with factory.begin() as session:
            store = storage.SqlAlchemyDeviceChallengeStore(session)
            # Populate both ORM identity cache and a prior non-locking read.
            cached = session.get(storage.SocialDeviceAdmissionChallengeRow, created.context.challenge_id)
            assert cached.state == store.read(created.context.challenge_id).state == "issued"
            pids.put(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
            locked = store.read_for_update(created.context.challenge_id)
            return locked

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory.begin() as first:
            store = storage.SqlAlchemyDeviceChallengeStore(first)
            assert store.read_for_update(created.context.challenge_id) == created
            blocker_pid = first.execute(text("SELECT pg_backend_pid()")).scalar_one()
            future = pool.submit(waiter)
            wait_until_blocked(engine, pids.get(timeout=5), blocker_pid)
            # Schema rehearsal only; there is deliberately no transition API.
            first.execute(TABLE.update().values(state="invalidated"))
        locked = future.result(timeout=10)
    assert locked.state == "invalidated"
    assert locked.context.wire == created.context.wire
    assert locked.challenge_wire == created.challenge_wire
    assert rows(factory) == [persisted(state="invalidated")]


def test_transaction_rollback_has_no_partial_rows_and_adapter_cannot_cross_transactions(database):
    _engine, factory = database
    with factory() as session:
        with pytest.raises(RuntimeError, match="synthetic abort"):
            with session.begin():
                store = storage.SqlAlchemyDeviceChallengeStore(session)
                store.create_issued(**arguments())
                store.create_issued(**arguments("enrollmentV2"))
                raise RuntimeError("synthetic abort")
        assert rows(factory) == []
        with session.begin(), pytest.raises(DENIED, match=ERROR):
            store.read(persisted()["challenge_id"])
    create(factory)
    with pytest.raises(DENIED, match=ERROR):
        with factory.begin() as session:
            store = storage.SqlAlchemyDeviceChallengeStore(session)
            store.create_issued(**arguments("enrollmentV2"))
            store.create_issued(**arguments())
    assert rows(factory) == [persisted()]


@pytest.mark.parametrize(
    "column,value",
    [
        ("challenge_id", "ff" * 32),
        ("context_wire", VECTORS["recipientSelfRead"]["contextWire"]),
        ("challenge_wire", VECTORS["recipientSelfRead"]["challengeWire"]),
        ("routing_request_wire", None),
        ("state", "consumed"),
    ],
)
def test_database_rejects_immutable_replacement_and_successful_consumption(database, column, value):
    _engine, factory = database
    create(factory)
    with pytest.raises(DBAPIError):
        with factory.begin() as session:
            session.execute(TABLE.update().values({column: value}))
    assert rows(factory) == [persisted()]


@pytest.mark.parametrize("state", ("expired", "invalidated", "cancelled"))
def test_terminal_evidence_cannot_be_reopened_deleted_truncated_or_recreated(database, state):
    _engine, factory = database
    created = create(factory)
    with factory.begin() as session:
        session.execute(TABLE.update().values(state=state))
    for statement in (
        TABLE.update().values(state="issued"),
        TABLE.update().values(state="consumed"),
        TABLE.delete(),
        text("TRUNCATE social_device_admission_challenges"),
    ):
        with pytest.raises(DBAPIError):
            with factory.begin() as session:
                session.execute(statement)
    with pytest.raises(DENIED, match=ERROR):
        create(factory)
    assert read(factory, created.context.challenge_id).state == state
    assert rows(factory) == [persisted(state=state)]


def test_unknown_expired_and_lock_timeout_fail_closed_without_mutation(database):
    _engine, factory = database
    with pytest.raises(DENIED, match=ERROR):
        read(factory, "ff" * 32)
    created = create(factory)
    with factory.begin() as first:
        locked = storage.SqlAlchemyDeviceChallengeStore(first).read_for_update(created.context.challenge_id)
        assert locked.inspect_deadline(now=locked.expires_at).disposition == "expired"
        with pytest.raises(DENIED, match=ERROR) as failure:
            with factory.begin() as second:
                second.execute(text("SET LOCAL lock_timeout = '50ms'"))
                storage.SqlAlchemyDeviceChallengeStore(second).read_for_update(created.context.challenge_id)
        assert failure.value.__cause__ is failure.value.__context__ is None
    assert rows(factory) == [persisted()]


def test_schema_only_table_without_guards_is_not_a_store(database):
    engine, factory = database
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TRIGGER trg_social_challenge_guard ON social_device_admission_challenges")
    with pytest.raises(DENIED, match=ERROR):
        create(factory)
    assert rows(factory) == []


def test_driver_autocommit_cannot_claim_a_transaction_or_row_lock(database):
    engine, factory = database
    create(factory)
    autocommit = engine.execution_options(isolation_level="AUTOCOMMIT")
    with sessionmaker(autocommit).begin() as session:
        assert session.in_transaction()
        with pytest.raises(DENIED, match=ERROR):
            storage.SqlAlchemyDeviceChallengeStore(session)
    assert rows(factory) == [persisted()]


def test_corrupt_canonical_evidence_rejected_on_real_database_read(database):
    _engine, factory = database
    row = persisted(context_wire=" " + VECTORS["ciphertextSubmit"]["contextWire"])
    # Direct synthetic corruption: SQL checks the key, shared parser checks
    # complete canonical bytes. Never normalize the corrupt string on read.
    with factory.begin() as session:
        session.execute(TABLE.insert().values(**row))
    with pytest.raises(DENIED, match=ERROR):
        read(factory, row["challenge_id"])
    assert rows(factory) == [row]


def test_migration_ddl_is_transactional(postgres_target):
    schema = "challenge_ddl_" + uuid.uuid4().hex
    with postgres_target.connect() as connection:
        transaction = connection.begin()
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        connection.exec_driver_sql(f'SET LOCAL search_path = "{schema}"')
        connection.exec_driver_sql(MIGRATION.read_text(encoding="ascii"))
        assert connection.execute(text("SELECT to_regclass('social_device_admission_challenges')")).scalar_one()
        transaction.rollback()
    with postgres_target.connect() as connection:
        assert connection.execute(text("SELECT to_regnamespace(:name)"), {"name": schema}).scalar_one() is None

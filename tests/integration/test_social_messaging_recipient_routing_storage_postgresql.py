"""Guarded disposable PostgreSQL 16 routing-registry integration tests.

The suite requires an explicit synthetic target on a high loopback TCP port,
with Unix sockets disabled. It never reads DATABASE_URL or defaults to 5432.
"""

from __future__ import annotations

import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from queue import Queue

import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.services import social_messaging_recipient_routing as routing
from app.services import social_messaging_recipient_routing_storage as storage
from tests.unit.test_social_messaging_recipient_routing import (
    ALIAS_SECRET,
    decision_route,
    snapshot_route,
    valid_decision,
    valid_snapshot,
)

PREFIX = "HODLXXI_ROUTING_REGISTRY_TEST_"
ACK = "DISPOSABLE-SOCIAL-ROUTING-REGISTRY-POSTGRES-V1"
MIGRATION = Path(__file__).resolve().parents[2] / (
    "migrations/2026-09-24_social_messaging_recipient_routing_registry_v1.sql"
)
DENIED = routing.RecipientMessagingRoutingUnavailable
ERROR = "^recipient messaging routing unavailable$"

TABLES = (
    storage.RecipientRoutingHandleOwnerRow.__table__,
    storage.RecipientRoutingSnapshotRow.__table__,
    storage.RecipientRoutingSnapshotRouteRow.__table__,
    storage.RecipientRoutingDecisionRow.__table__,
    storage.RecipientRoutingDecisionRouteRow.__table__,
)


@pytest.fixture(scope="module")
def postgres_target():
    dsn = os.environ.get(PREFIX + "DSN")
    if not dsn:
        pytest.skip("explicit disposable routing-registry PostgreSQL target not provided")
    assert os.environ.get(PREFIX + "ACK") == ACK
    data = Path(os.environ[PREFIX + "DATA"]).resolve()
    assert data.parent.parent == Path("/tmp")
    assert data.parent.name.startswith("hodlxxi-routing-registry-")
    assert data.name == "data" and (data / "PG_VERSION").read_text().strip() == "16"
    port = int(os.environ[PREFIX + "PORT"])
    url = make_url(dsn)
    assert url.drivername == "postgresql+psycopg2"
    assert url.host == "127.0.0.1" and url.port == port and 49152 <= port <= 65535
    assert url.database == "hodlxxi_routing_registry_test"
    assert url.username == "routing_registry_test" and url.password is None and not url.query
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
    schema = "routing_" + uuid.uuid4().hex
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


def retain(factory, snapshot=None):
    snapshot = snapshot or valid_snapshot()
    with factory.begin() as session:
        return storage.SqlAlchemyRecipientRoutingRepository(session).retain_snapshot(snapshot)


def record(factory, decision=None):
    decision = decision or valid_decision()
    with factory.begin() as session:
        return storage.SqlAlchemyRecipientRoutingRepository(session).record_decision(decision)


def table_rows(factory, table):
    with factory() as session:
        return session.execute(select(table)).mappings().all()


def wait_until_blocked(engine, waiter, blocker):
    deadline = time.monotonic() + 4
    with engine.connect() as connection:
        while time.monotonic() < deadline:
            blockers = connection.execute(text("SELECT pg_blocking_pids(:pid)"), {"pid": waiter}).scalar_one()
            if blocker in blockers:
                return
            time.sleep(0.01)
    pytest.fail("synthetic contender did not wait on the routing-registry lock")


def test_migration_schema_matches_five_models_and_installs_all_guards(database):
    engine, _factory = database
    inspector = inspect(engine)
    assert set(inspector.get_table_names()) == {table.name for table in TABLES}
    for table in TABLES:
        columns = inspector.get_columns(table.name)
        assert {column["name"] for column in columns} == set(table.c.keys())
        for column in columns:
            expected = table.c[column["name"]]
            assert column["nullable"] == expected.nullable
            assert str(column["type"]) == str(expected.type)
            assert column["default"] is None
    with engine.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal "
                    "AND tgenabled = 'O' AND tgrelid = ANY(ARRAY["
                    "to_regclass(:handles),to_regclass(:snapshots),"
                    "to_regclass(:snapshot_routes),to_regclass(:decisions),"
                    "to_regclass(:decision_routes)])"
                ),
                {
                    "handles": storage.HANDLE_TABLE,
                    "snapshots": storage.SNAPSHOT_TABLE,
                    "snapshot_routes": storage.SNAPSHOT_ROUTE_TABLE,
                    "decisions": storage.DECISION_TABLE,
                    "decision_routes": storage.DECISION_ROUTE_TABLE,
                },
            ).scalar_one()
            == storage._EXPECTED_TRIGGER_COUNT
        )


def test_exact_snapshot_decision_roundtrip_and_idempotent_retries(database):
    _engine, factory = database
    snapshot = valid_snapshot(snapshot_route(1), snapshot_route(2))
    decision = valid_decision(decision_route(1), decision_route(2))
    assert retain(factory, snapshot) == snapshot
    assert retain(factory, snapshot) == snapshot
    with factory.begin() as session:
        repo = storage.SqlAlchemyRecipientRoutingRepository(session)
        assert repo.read_snapshot(snapshot.recipient_package_snapshot_id) == snapshot
    assert record(factory, decision) == decision
    assert record(factory, decision) == decision
    snapshots = table_rows(factory, storage.RecipientRoutingSnapshotRow.__table__)
    decisions = table_rows(factory, storage.RecipientRoutingDecisionRow.__table__)
    assert snapshots[0]["snapshot_wire"].encode("ascii") == routing.canonical_routing_snapshot_bytes(snapshot)
    assert decisions[0]["decision_wire"].encode("ascii") == routing.canonical_routing_decision_bytes(decision)
    assert len(table_rows(factory, storage.RecipientRoutingHandleOwnerRow.__table__)) == 2
    assert len(table_rows(factory, storage.RecipientRoutingSnapshotRouteRow.__table__)) == 2
    assert len(table_rows(factory, storage.RecipientRoutingDecisionRouteRow.__table__)) == 2


def test_same_tuple_renewal_and_alias_rotation_retain_immutable_history(database):
    _engine, factory = database
    original = retain(factory)
    renewal = replace(
        original,
        recipient_package_snapshot_id="sha256:" + "22" * 32,
        issued_at=original.issued_at + 1_000,
        expires_at=original.expires_at + 1_000,
    )
    assert retain(factory, renewal) == renewal
    route = original.routes[0]
    rotated_handle = routing.derive_recipient_device_handle(
        viewer=original.viewer_subject,
        target=original.recipient_subject,
        binding_id=route.binding_id,
        alias_secret=ALIAS_SECRET,
        alias_version=2,
    )
    rotated = replace(
        original,
        alias_version=2,
        recipient_package_snapshot_id="sha256:" + "33" * 32,
        routes=(replace(route, device_handle=rotated_handle),),
    )
    assert retain(factory, rotated) == rotated
    owners = table_rows(factory, storage.RecipientRoutingHandleOwnerRow.__table__)
    assert {(owner["device_handle"], owner["alias_version"]) for owner in owners} == {
        (route.device_handle, 1),
        (rotated_handle, 2),
    }


def test_global_handle_collision_and_namespace_remap_conflict(database):
    _engine, factory = database
    snapshot = retain(factory)
    conflicting = replace(
        snapshot,
        recipient_package_snapshot_id="sha256:" + "44" * 32,
        viewer_subject="02" * 32,
    )
    with pytest.raises(DENIED, match=ERROR):
        retain(factory, conflicting)

    remapped = replace(
        snapshot,
        recipient_package_snapshot_id="sha256:" + "55" * 32,
        routes=(replace(snapshot.routes[0], device_handle="d_" + "A" * 22),),
    )
    with pytest.raises(DENIED, match=ERROR):
        retain(factory, remapped)
    assert len(table_rows(factory, storage.RecipientRoutingHandleOwnerRow.__table__)) == 1


def test_message_id_same_digest_is_idempotent_and_changed_digest_conflicts(database):
    _engine, factory = database
    retain(factory)
    decision = record(factory)
    assert record(factory, decision) == decision
    changed = replace(
        decision,
        envelope_digest="hodlxxi-social-message-envelope-v1-sha256:" + "cd" * 32,
    )
    with pytest.raises(DENIED, match=ERROR):
        record(factory, changed)
    assert (
        table_rows(factory, storage.RecipientRoutingDecisionRow.__table__)[0]["envelope_digest"]
        == decision.envelope_digest
    )


@pytest.mark.parametrize("first_commits", (True, False))
def test_concurrent_snapshot_retry_waits_then_rechecks_authoritative_state(database, first_commits):
    engine, factory = database
    snapshot = valid_snapshot()
    pids = Queue()

    def contender():
        try:
            with factory.begin() as session:
                pids.put(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
                value = storage.SqlAlchemyRecipientRoutingRepository(session).retain_snapshot(snapshot)
                assert value == snapshot
            return "retained"
        except DENIED:
            return "denied"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as first:
            transaction = first.begin()
            try:
                storage.SqlAlchemyRecipientRoutingRepository(first).retain_snapshot(snapshot)
                blocker = first.execute(text("SELECT pg_backend_pid()")).scalar_one()
                future = pool.submit(contender)
                wait_until_blocked(engine, pids.get(timeout=5), blocker)
                assert not future.done()
                if first_commits:
                    transaction.commit()
                else:
                    transaction.rollback()
            finally:
                if transaction.is_active:
                    transaction.rollback()
        assert future.result(timeout=10) == "retained"
    assert len(table_rows(factory, storage.RecipientRoutingSnapshotRow.__table__)) == 1


def test_transaction_rollback_leaves_no_partial_registry_rows(database):
    _engine, factory = database
    with pytest.raises(RuntimeError, match="synthetic abort"):
        with factory.begin() as session:
            repo = storage.SqlAlchemyRecipientRoutingRepository(session)
            repo.retain_snapshot(valid_snapshot())
            repo.record_decision(valid_decision())
            raise RuntimeError("synthetic abort")
    for table in TABLES:
        assert table_rows(factory, table) == []


def test_database_guards_deny_replacement_deletion_truncation_and_incomplete_direct_rows(database):
    _engine, factory = database
    snapshot = retain(factory)
    record(factory)
    statements = (
        storage.RecipientRoutingHandleOwnerRow.__table__.update().values(binding_version=2),
        storage.RecipientRoutingSnapshotRow.__table__.delete(),
        storage.RecipientRoutingSnapshotRouteRow.__table__.delete(),
        storage.RecipientRoutingDecisionRow.__table__.delete(),
        storage.RecipientRoutingDecisionRouteRow.__table__.delete(),
        text(f"TRUNCATE {storage.DECISION_ROUTE_TABLE}"),
    )
    for statement in statements:
        with pytest.raises(DBAPIError):
            with factory.begin() as session:
                session.execute(statement)
    assert retain(factory, snapshot) == snapshot

    with pytest.raises(DBAPIError):
        with factory.begin() as session:
            session.execute(
                storage.RecipientRoutingDecisionRow.__table__.insert().values(
                    message_id="m_" + "A" * 43,
                    envelope_digest="hodlxxi-social-message-envelope-v1-sha256:" + "aa" * 32,
                    snapshot_id=snapshot.recipient_package_snapshot_id,
                    viewer_subject=snapshot.viewer_subject,
                    recipient_subject=snapshot.recipient_subject,
                    expires_at=snapshot.expires_at,
                    route_count=1,
                    decision_wire=routing.canonical_routing_decision_bytes(valid_decision()).decode("ascii"),
                )
            )


def test_missing_guard_autocommit_and_replaced_transaction_fail_closed(database):
    engine, factory = database
    with engine.begin() as connection:
        connection.exec_driver_sql(f"DROP TRIGGER trg_social_routing_handle_guard ON {storage.HANDLE_TABLE}")
    with pytest.raises(DENIED, match=ERROR):
        with factory.begin() as session:
            storage.SqlAlchemyRecipientRoutingRepository(session)

    autocommit = engine.execution_options(isolation_level="AUTOCOMMIT")
    with sessionmaker(autocommit).begin() as session:
        with pytest.raises(DENIED, match=ERROR):
            storage.SqlAlchemyRecipientRoutingRepository(session)


def test_migration_ddl_is_transactional(postgres_target):
    schema = "routing_ddl_" + uuid.uuid4().hex
    with postgres_target.connect() as connection:
        transaction = connection.begin()
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        connection.exec_driver_sql(f'SET LOCAL search_path = "{schema}"')
        connection.exec_driver_sql(MIGRATION.read_text(encoding="ascii"))
        assert connection.execute(text("SELECT to_regclass(:table)"), {"table": storage.HANDLE_TABLE}).scalar_one()
        transaction.rollback()
    with postgres_target.connect() as connection:
        assert connection.execute(text("SELECT to_regnamespace(:schema)"), {"schema": schema}).scalar_one() is None

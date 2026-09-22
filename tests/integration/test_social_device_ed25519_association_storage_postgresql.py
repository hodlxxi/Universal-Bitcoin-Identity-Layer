"""Guarded synthetic PostgreSQL rehearsal; no configured database fallback."""

from __future__ import annotations

import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.services import social_device_ed25519_association_storage as storage
from app.services import social_messaging_device_ed25519_association_lifecycle as lifecycle
from tests.unit.test_social_device_ed25519_association_storage import ERROR, MIGRATION, VECTORS, evidence

PREFIX = "HODLXXI_ED25519_ASSOC_TEST_"
ACK = "DISPOSABLE-SOCIAL-ED25519-ASSOCIATION-POSTGRES-V1"
INITIAL_ID = VECTORS["creationVectors"]["initial"]["associationId"]
ROTATED_ID = VECTORS["creationVectors"]["firstRotation"]["associationId"]
SECOND_ID = VECTORS["creationVectors"]["secondRotation"]["associationId"]
DEVICE = json.loads(VECTORS["enrollmentWires"]["initial"])["deviceId"]
SUBJECT = json.loads(VECTORS["enrollmentWires"]["initial"])["subject"]


@pytest.fixture(scope="module")
def postgres_target():
    dsn = os.environ.get(PREFIX + "DSN")
    if not dsn:
        pytest.skip("explicit disposable Ed25519 PostgreSQL target not provided")
    assert os.environ.get(PREFIX + "ACK") == ACK
    data = Path(os.environ[PREFIX + "DATA"]).resolve()
    assert data.parent.parent == Path("/tmp")
    assert data.parent.name.startswith("hodlxxi-ed25519-assoc-")
    assert data.name == "data" and (data / "PG_VERSION").read_text().strip() == "16"
    port = int(os.environ[PREFIX + "PORT"])
    url = make_url(dsn)
    assert url.drivername == "postgresql+psycopg2"
    assert url.host == "127.0.0.1" and url.port == port and 49152 <= port <= 65535
    assert url.database == "hodlxxi_ed25519_assoc_test"
    assert url.username == "ed25519_test" and url.password is None and not url.query
    engine = create_engine(url, poolclass=NullPool, hide_parameters=True)
    try:
        with engine.connect() as connection:
            identity = connection.execute(
                text(
                    "SELECT current_database(), current_setting('data_directory'), current_setting('port'), "
                    "current_setting('listen_addresses'), current_setting('unix_socket_directories'), version()"
                )
            ).one()
            assert identity[0] == url.database
            assert Path(identity[1]).resolve() == data
            assert int(identity[2]) == port
            assert identity[3:5] == ("127.0.0.1", "")
            assert identity[5].startswith("PostgreSQL 16.")
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def database(postgres_target):
    schema = "ed25519_" + uuid.uuid4().hex
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
            # psycopg2 interprets PL/pgSQL %ROWTYPE through SQLAlchemy's
            # parameter path; the raw cursor runs the migration's exact bytes.
            with connection.connection.cursor() as cursor:
                cursor.execute(MIGRATION.read_text(encoding="ascii"))
        yield engine, sessionmaker(engine, expire_on_commit=False)
    finally:
        engine.dispose()
        with postgres_target.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')


def create(factory, name="initial", *, version=1, epoch=1, predecessor=None):
    value = evidence(name, version=version, epoch=epoch, predecessor=predecessor)
    with factory.begin() as session:
        store = storage.SqlAlchemyEd25519AssociationStore(session)
        if name == "initial":
            return store.establish_initial(value[0], value[1], now=value[2])
        if name == "reenrollment":
            return store.reenroll(
                value[0], value[1], now=value[2], expected_predecessor=predecessor, expected_epoch=epoch - 1
            )
        return store.rotate(
            value[0], value[1], now=value[2], expected_predecessor=predecessor, expected_epoch=epoch - 1
        )


def current(factory):
    with factory.begin() as session:
        return storage.SqlAlchemyEd25519AssociationStore(session).lock_current_association(SUBJECT, DEVICE)


def history(factory):
    with factory.begin() as session:
        return storage.SqlAlchemyEd25519AssociationStore(session).lock_history(SUBJECT, DEVICE)


def wait_until_blocked(engine, waiter, blocker):
    deadline = time.monotonic() + 4
    with engine.connect() as connection:
        while time.monotonic() < deadline:
            blockers = connection.execute(text("SELECT pg_blocking_pids(:pid)"), {"pid": waiter}).scalar_one()
            if blocker in blockers:
                return
            time.sleep(0.01)
    pytest.fail("synthetic contender did not wait on PostgreSQL authority lock")


def test_migration_and_initial_current_history(database):
    engine, factory = database
    inspector = inspect(engine)
    assert set(inspector.get_table_names()) == {storage.CHAIN_TABLE, storage.EVENT_TABLE}
    assert {column["name"] for column in inspector.get_columns(storage.CHAIN_TABLE)} == set(
        storage.SocialDeviceEd25519AssociationChain.__table__.columns.keys()
    )
    assert {column["name"] for column in inspector.get_columns(storage.EVENT_TABLE)} == set(
        storage.SocialDeviceEd25519AssociationEvent.__table__.columns.keys()
    )
    assert {item["name"] for item in inspector.get_check_constraints(storage.CHAIN_TABLE)} == {
        item.name
        for item in storage.SocialDeviceEd25519AssociationChain.__table__.constraints
        if item.name.startswith("ck_")
    }
    assert {item["name"] for item in inspector.get_check_constraints(storage.EVENT_TABLE)} == {
        item.name
        for item in storage.SocialDeviceEd25519AssociationEvent.__table__.constraints
        if item.name.startswith("ck_")
    }
    assert {item["name"] for item in inspector.get_indexes(storage.EVENT_TABLE)} == {
        item.name for item in storage.SocialDeviceEd25519AssociationEvent.__table__.indexes
    }
    assert current(factory) is None
    created = create(factory)
    assert created.association_id == INITIAL_ID
    assert created.association_version == created.authority_epoch == 1
    assert created.state == "active"
    assert current(factory) == created
    with factory() as session:
        transaction = session.begin()
        assert storage.SqlAlchemyEd25519AssociationStore(session).lock_current_association(SUBJECT, DEVICE) == created
        assert transaction.is_active and session.in_transaction()
        transaction.rollback()
    snapshot = history(factory)
    assert snapshot.current.association_id == INITIAL_ID
    assert snapshot.history[0].state == "active"


def test_rotation_invalidation_revocation_reenrollment_and_epoch(database):
    _engine, factory = database
    create(factory)
    rotated = create(factory, "firstRotation", version=2, epoch=2, predecessor=INITIAL_ID)
    assert rotated.association_id == ROTATED_ID
    assert [item.state for item in history(factory).history] == ["rotated", "active"]
    with factory.begin() as session:
        store = storage.SqlAlchemyEd25519AssociationStore(session)
        assert store.invalidate_authority(SUBJECT, DEVICE, expected_association_id=ROTATED_ID, expected_epoch=2)
        assert store.invalidate_authority(SUBJECT, DEVICE, expected_association_id=ROTATED_ID, expected_epoch=3)
    assert current(factory).association_version == 2
    assert current(factory).authority_epoch == 4
    second = create(factory, "secondRotation", version=3, epoch=5, predecessor=ROTATED_ID)
    assert second.association_id == SECOND_ID
    with factory.begin() as session:
        store = storage.SqlAlchemyEd25519AssociationStore(session)
        assert store.revoke(SUBJECT, DEVICE, expected_association_id=SECOND_ID, expected_epoch=5) is None
    assert current(factory) is None
    assert history(factory).authority_epoch == 6
    reenrolled = create(factory, "reenrollment", version=4, epoch=7, predecessor=SECOND_ID)
    assert reenrolled.association_version == 4
    assert reenrolled.authority_epoch == 7
    assert [item.state for item in history(factory).history] == ["rotated", "rotated", "revoked", "active"]


def test_stale_predecessor_and_failed_transition_leave_no_successor(database):
    engine, factory = database
    create(factory)
    create(factory, "firstRotation", version=2, epoch=2, predecessor=INITIAL_ID)
    value = evidence("secondRotation", version=2, epoch=2, predecessor=INITIAL_ID)
    with pytest.raises(storage.SocialDeviceEd25519AssociationStorageUnavailable, match=ERROR):
        with factory.begin() as session:
            storage.SqlAlchemyEd25519AssociationStore(session).rotate(
                value[0], value[1], now=value[2], expected_predecessor=INITIAL_ID, expected_epoch=1
            )
    assert current(factory).association_id == ROTATED_ID
    assert len(history(factory).history) == 2


def test_rollback_preserves_prior_authority(database):
    _engine, factory = database
    create(factory)
    value = evidence("firstRotation", version=2, epoch=2, predecessor=INITIAL_ID)
    with factory() as session:
        transaction = session.begin()
        store = storage.SqlAlchemyEd25519AssociationStore(session)
        assert (
            store.rotate(
                value[0], value[1], now=value[2], expected_predecessor=INITIAL_ID, expected_epoch=1
            ).association_id
            == ROTATED_ID
        )
        transaction.rollback()
    assert current(factory).association_id == INITIAL_ID
    assert len(history(factory).history) == 1


def test_direct_history_rewrite_and_delete_are_denied(database):
    engine, factory = database
    create(factory)
    table = storage.SocialDeviceEd25519AssociationEvent.__table__
    for statement in (
        table.update().values(association_version=2),
        table.delete(),
        text("TRUNCATE social_device_ed25519_association_events"),
    ):
        with pytest.raises(Exception):
            with engine.begin() as connection:
                connection.execute(statement)
    assert current(factory).association_id == INITIAL_ID


@pytest.mark.parametrize("rejection", ("crossSubjectPredecessor", "crossDevicePredecessor"))
def test_direct_current_rewrite_and_cross_pair_predecessor_are_denied(database, rejection):
    engine, factory = database
    create(factory)
    chain = storage.SocialDeviceEd25519AssociationChain.__table__
    with pytest.raises(Exception):
        with engine.begin() as connection:
            connection.execute(chain.update().values(authority_epoch=3))
    candidate = VECTORS["rejectionVectors"][rejection]["candidateEventWire"]
    event = lifecycle.parse_association_event_v1(candidate)
    enrollment = json.loads(event.enrollment_wire)
    with pytest.raises(Exception):
        with engine.begin() as connection:
            connection.execute(
                chain.insert().values(
                    subject=enrollment["subject"],
                    device_id=enrollment["deviceId"],
                    authority_epoch=0,
                    last_association_id=None,
                    last_association_version=None,
                    current_association_id=None,
                    state="empty",
                )
            )
            connection.execute(
                storage.SocialDeviceEd25519AssociationEvent.__table__.insert().values(
                    subject=enrollment["subject"],
                    device_id=enrollment["deviceId"],
                    authority_epoch=2,
                    kind="rotate",
                    association_id=event.association_id,
                    association_version=event.association_version,
                    predecessor_association_id=event.predecessor_association_id,
                    ed25519_public_key=enrollment["ed25519PublicKey"],
                    enrollment_challenge_id=enrollment["enrollmentChallengeId"],
                    event_wire=candidate,
                )
            )
    assert current(factory).association_id == INITIAL_ID


def test_corrupt_persisted_event_fails_closed(database):
    engine, factory = database
    create(factory)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "ALTER TABLE social_device_ed25519_association_events DISABLE TRIGGER trg_social_ed25519_event_guard"
        )
        connection.exec_driver_sql("UPDATE social_device_ed25519_association_events SET event_wire = 'malformed'")
        connection.exec_driver_sql(
            "ALTER TABLE social_device_ed25519_association_events ENABLE TRIGGER trg_social_ed25519_event_guard"
        )
    with pytest.raises(storage.SocialDeviceEd25519AssociationStorageUnavailable, match=ERROR):
        current(factory)


def test_missing_advance_trigger_rejects_authority(database):
    engine, factory = database
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "ALTER TABLE social_device_ed25519_association_events DISABLE TRIGGER trg_social_ed25519_event_advance"
        )
    with pytest.raises(storage.SocialDeviceEd25519AssociationStorageUnavailable, match=ERROR):
        current(factory)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "ALTER TABLE social_device_ed25519_association_events ENABLE TRIGGER trg_social_ed25519_event_advance"
        )


def test_expired_or_untyped_enrollment_cannot_create_authority(database):
    _engine, factory = database
    input_wire, statement, now = evidence()
    for candidate_statement, candidate_now in (
        (statement, statement.expires_at),
        (object(), now),
    ):
        with pytest.raises(storage.SocialDeviceEd25519AssociationStorageUnavailable, match=ERROR):
            with factory.begin() as session:
                storage.SqlAlchemyEd25519AssociationStore(session).establish_initial(
                    input_wire, candidate_statement, now=candidate_now
                )
    assert current(factory) is None


def test_no_resurrection_or_version_rollback_after_revoke(database):
    _engine, factory = database
    create(factory)
    with factory.begin() as session:
        storage.SqlAlchemyEd25519AssociationStore(session).revoke(
            SUBJECT, DEVICE, expected_association_id=INITIAL_ID, expected_epoch=1
        )
    value = evidence("firstRotation", version=2, epoch=3, predecessor=INITIAL_ID)
    with pytest.raises(storage.SocialDeviceEd25519AssociationStorageUnavailable, match=ERROR):
        with factory.begin() as session:
            storage.SqlAlchemyEd25519AssociationStore(session).rotate(
                value[0], value[1], now=value[2], expected_predecessor=INITIAL_ID, expected_epoch=2
            )
    assert current(factory) is None
    assert history(factory).authority_epoch == 2
    with factory.begin() as session:
        reenrolled = storage.SqlAlchemyEd25519AssociationStore(session).reenroll(
            value[0], value[1], now=value[2], expected_predecessor=INITIAL_ID, expected_epoch=2
        )
        assert reenrolled.association_version == 2
        assert reenrolled.authority_epoch == 3
    assert history(factory).history[0].state == "revoked"
    with pytest.raises(storage.SocialDeviceEd25519AssociationStorageUnavailable, match=ERROR):
        with factory.begin() as session:
            storage.SqlAlchemyEd25519AssociationStore(session).reenroll(
                value[0], value[1], now=value[2], expected_predecessor=INITIAL_ID, expected_epoch=2
            )


@pytest.mark.parametrize("first_commits", (True, False))
def test_competing_initial_associations_serialize(database, first_commits):
    engine, factory = database
    value = evidence()
    pids = Queue()

    def contender():
        try:
            with factory.begin() as session:
                pids.put(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
                storage.SqlAlchemyEd25519AssociationStore(session).establish_initial(value[0], value[1], now=value[2])
            return "created"
        except storage.SocialDeviceEd25519AssociationStorageUnavailable:
            return "denied"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as first:
            transaction = first.begin()
            try:
                storage.SqlAlchemyEd25519AssociationStore(first).establish_initial(value[0], value[1], now=value[2])
                blocker = first.execute(text("SELECT pg_backend_pid()")).scalar_one()
                future = pool.submit(contender)
                wait_until_blocked(engine, pids.get(timeout=5), blocker)
                if first_commits:
                    transaction.commit()
                else:
                    transaction.rollback()
            finally:
                if transaction.is_active:
                    transaction.rollback()
        assert future.result(timeout=10) == ("denied" if first_commits else "created")
    assert len(history(factory).history) == 1


def test_competing_rotations_and_stale_predecessor(database):
    engine, factory = database
    create(factory)
    value = evidence("firstRotation", version=2, epoch=2, predecessor=INITIAL_ID)
    pids = Queue()

    def contender():
        try:
            with factory.begin() as session:
                pids.put(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
                storage.SqlAlchemyEd25519AssociationStore(session).rotate(
                    value[0], value[1], now=value[2], expected_predecessor=INITIAL_ID, expected_epoch=1
                )
            return "rotated"
        except storage.SocialDeviceEd25519AssociationStorageUnavailable:
            return "denied"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory.begin() as first:
            storage.SqlAlchemyEd25519AssociationStore(first).rotate(
                value[0], value[1], now=value[2], expected_predecessor=INITIAL_ID, expected_epoch=1
            )
            blocker = first.execute(text("SELECT pg_backend_pid()")).scalar_one()
            future = pool.submit(contender)
            wait_until_blocked(engine, pids.get(timeout=5), blocker)
        assert future.result(timeout=10) == "denied"
    assert current(factory).association_id == ROTATED_ID
    assert len(history(factory).history) == 2


def test_rotation_vs_revocation_and_locked_read_wait_for_coherent_state(database):
    engine, factory = database
    create(factory)
    value = evidence("firstRotation", version=2, epoch=2, predecessor=INITIAL_ID)
    pids = Queue()

    def waiter():
        with factory.begin() as session:
            pids.put(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
            return storage.SqlAlchemyEd25519AssociationStore(session).lock_current_association(SUBJECT, DEVICE)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory.begin() as first:
            storage.SqlAlchemyEd25519AssociationStore(first).rotate(
                value[0], value[1], now=value[2], expected_predecessor=INITIAL_ID, expected_epoch=1
            )
            blocker = first.execute(text("SELECT pg_backend_pid()")).scalar_one()
            future = pool.submit(waiter)
            wait_until_blocked(engine, pids.get(timeout=5), blocker)
        assert future.result(timeout=10).association_id == ROTATED_ID
    with pytest.raises(storage.SocialDeviceEd25519AssociationStorageUnavailable, match=ERROR):
        with factory.begin() as session:
            storage.SqlAlchemyEd25519AssociationStore(session).revoke(
                SUBJECT, DEVICE, expected_association_id=INITIAL_ID, expected_epoch=1
            )
    assert current(factory).association_id == ROTATED_ID


@pytest.mark.parametrize("winner", ("rotate", "revoke"))
def test_rotation_and_revocation_have_one_serial_winner(database, winner):
    engine, factory = database
    create(factory)
    value = evidence("firstRotation", version=2, epoch=2, predecessor=INITIAL_ID)
    pids = Queue()

    def apply(store, operation):
        if operation == "rotate":
            return store.rotate(value[0], value[1], now=value[2], expected_predecessor=INITIAL_ID, expected_epoch=1)
        return store.revoke(SUBJECT, DEVICE, expected_association_id=INITIAL_ID, expected_epoch=1)

    loser = "revoke" if winner == "rotate" else "rotate"

    def contender():
        try:
            with factory.begin() as session:
                pids.put(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
                apply(storage.SqlAlchemyEd25519AssociationStore(session), loser)
            return "won"
        except storage.SocialDeviceEd25519AssociationStorageUnavailable:
            return "denied"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory.begin() as first:
            apply(storage.SqlAlchemyEd25519AssociationStore(first), winner)
            blocker = first.execute(text("SELECT pg_backend_pid()")).scalar_one()
            future = pool.submit(contender)
            wait_until_blocked(engine, pids.get(timeout=5), blocker)
        assert future.result(timeout=10) == "denied"
    current_value = current(factory)
    assert (current_value.association_id if current_value else None) == (ROTATED_ID if winner == "rotate" else None)
    assert history(factory).authority_epoch == 2

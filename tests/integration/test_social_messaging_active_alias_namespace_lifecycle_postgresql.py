"""Disposable PostgreSQL 16 tests for the signed alias lifecycle owner.

The suite accepts only an explicit synthetic target on a high loopback TCP
port with Unix sockets disabled. It never reads DATABASE_URL or port 5432.
"""

from __future__ import annotations

import base64
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.services import social_messaging_active_alias_namespace_lifecycle as lifecycle
from app.services import social_messaging_active_alias_namespace_lifecycle_storage as writer
from app.services import social_messaging_active_alias_namespace_storage as namespace

PREFIX = "HODLXXI_ALIAS_LIFECYCLE_WRITER_TEST_"
ACK = "DISPOSABLE-SOCIAL-ALIAS-LIFECYCLE-WRITER-POSTGRES-V1"
ROOT = Path(__file__).resolve().parents[2]
NAMESPACE_MIGRATION = ROOT / "migrations/2026-09-24_social_messaging_active_alias_namespace_v1.sql"
LIFECYCLE_MIGRATION = ROOT / "migrations/2026-09-25_social_messaging_active_alias_namespace_lifecycle_v1.sql"
KEY_ID = "synthetic-offline-test-v1"
SECRET_V1 = bytes(range(32))
SECRET_V2 = bytes(reversed(range(32)))
SECRET_V2_COMPETITOR = bytes(range(1, 33))
DENIED = writer.AliasNamespaceLifecycleStorageUnavailable
ERROR = "^social messaging alias namespace lifecycle storage unavailable$"


@pytest.fixture(scope="module")
def signer():
    """An in-memory synthetic key; no private bytes are serialized or retained."""

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_key


@pytest.fixture(scope="module")
def postgres_target():
    dsn = os.environ.get(PREFIX + "DSN")
    if not dsn:
        pytest.skip("explicit disposable alias-lifecycle PostgreSQL target not provided")
    assert os.environ.get(PREFIX + "ACK") == ACK
    data = Path(os.environ[PREFIX + "DATA"]).resolve()
    assert data.parent.parent == Path("/tmp")
    assert data.parent.name.startswith("hodlxxi-alias-lifecycle-writer-")
    assert data.name == "data" and (data / "PG_VERSION").read_text().strip() == "16"
    port = int(os.environ[PREFIX + "PORT"])
    url = make_url(dsn)
    assert url.drivername == "postgresql+psycopg2"
    assert url.host == "127.0.0.1" and url.port == port and 49152 <= port <= 65535
    assert url.database == "hodlxxi_alias_lifecycle_writer_test"
    assert url.username == "alias_lifecycle_writer_test"
    assert url.password is None and not url.query
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
    schema = "alias_lifecycle_" + uuid.uuid4().hex
    with postgres_target.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    engine = create_engine(
        postgres_target.url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"options": (f"-c search_path={schema} -c statement_timeout=10000 " "-c lock_timeout=5000")},
    )
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(NAMESPACE_MIGRATION.read_text(encoding="ascii"))
            connection.exec_driver_sql(LIFECYCLE_MIGRATION.read_text(encoding="ascii"))
        yield engine, sessionmaker(engine, expire_on_commit=False)
    finally:
        engine.dispose()
        with postgres_target.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')


def database_now_ms(session):
    return session.execute(text("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")).scalar_one()


def signed_command(
    private_key,
    *,
    action,
    successor_secret,
    successor_version,
    now_ms,
    nonce_seed,
    expected_secret=None,
    expected_version=None,
    expires_after_ms=120_000,
):
    nonce = base64.urlsafe_b64encode(bytes([nonce_seed]) * 32).decode("ascii").rstrip("=")
    fields = {
        "action": action,
        "algorithm": lifecycle.ALGORITHM,
        "audience": lifecycle.AUDIENCE,
        "expectedCommitment": (
            None
            if expected_secret is None
            else namespace.active_alias_namespace_secret_commitment(
                alias_secret=expected_secret,
                alias_version=expected_version,
            )
        ),
        "expectedVersion": expected_version,
        "expiresAtMs": now_ms + expires_after_ms,
        "issuedAtMs": now_ms - 1_000,
        "keyId": KEY_ID,
        "nonce": nonce,
        "schema": lifecycle.SCHEMA,
        "successorCommitment": namespace.active_alias_namespace_secret_commitment(
            alias_secret=successor_secret,
            alias_version=successor_version,
        ),
        "successorVersion": successor_version,
        "version": 1,
    }
    wire = lifecycle.canonical_alias_lifecycle_command_v1(fields)
    signature = (
        base64.urlsafe_b64encode(private_key.sign(lifecycle.SIGNATURE_DOMAIN + b"\x00" + wire))
        .decode("ascii")
        .rstrip("=")
    )
    return wire, signature


def owner(session, public_key, *, secret, version):
    return writer.SqlAlchemyTransactionBoundActiveAliasNamespaceLifecycleOwner(
        session,
        pinned_public_key=public_key,
        pinned_key_id=KEY_ID,
        configured_successor_alias_secret=secret,
        configured_successor_alias_version=version,
    )


def provision(factory, signer, *, nonce_seed=1):
    private_key, public_key = signer
    with factory.begin() as session:
        command = signed_command(
            private_key,
            action="provision",
            successor_secret=SECRET_V1,
            successor_version=1,
            now_ms=database_now_ms(session),
            nonce_seed=nonce_seed,
        )
        result = owner(session, public_key, secret=SECRET_V1, version=1).execute(*command)
        assert result.outcome == "staged"
    return command


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


def test_migration_is_empty_and_installs_exact_deferred_integrity_boundary(database):
    engine, factory = database
    inspector = inspect(engine)
    assert set(inspector.get_table_names()) == {namespace.NAMESPACE_TABLE, writer.EVENT_TABLE}
    with factory() as session:
        assert session.execute(select(namespace.SocialMessagingActiveAliasNamespaceRow.__table__)).all() == []
        assert (
            session.execute(select(writer.SocialMessagingActiveAliasNamespaceLifecycleEventRow.__table__)).all() == []
        )
        trigger_rows = session.execute(
            text(
                "SELECT tgrelid::regclass::text, tgname, tgdeferrable, tginitdeferred "
                "FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O' ORDER BY tgname"
            )
        ).all()
        assert len(trigger_rows) == 6
        deferred = {row[1]: (row[2], row[3]) for row in trigger_rows}
        assert deferred["trg_social_alias_lifecycle_namespace_invariant"] == (True, True)
        assert deferred["trg_social_alias_lifecycle_event_invariant"] == (True, True)


def test_event_guard_overwrites_caller_transaction_id(database, signer):
    _engine, factory = database
    private_key, _public_key = signer
    namespace_table = namespace.SocialMessagingActiveAliasNamespaceRow.__table__
    event_table = writer.SocialMessagingActiveAliasNamespaceLifecycleEventRow.__table__
    with factory() as session:
        transaction = session.begin()
        command = signed_command(
            private_key,
            action="provision",
            successor_secret=SECRET_V1,
            successor_version=1,
            now_ms=database_now_ms(session),
            nonce_seed=16,
        )
        parsed = lifecycle.parse_canonical_alias_lifecycle_command_v1(command[0])
        session.execute(
            namespace_table.insert().values(
                alias_version=1,
                secret_commitment=parsed["successorCommitment"],
                lifecycle_state=namespace.ACTIVE_NAMESPACE_STATE,
            )
        )
        session.execute(
            event_table.insert().values(
                **writer._event_values(parsed, *command),
                staged_top_level_transaction_id="0",
            )
        )
        stored, current = session.execute(
            text(
                f"SELECT staged_top_level_transaction_id::text, "
                f"pg_current_xact_id()::text FROM {writer.EVENT_TABLE}"
            )
        ).one()
        assert stored == current
        assert stored != "0"
        transaction.rollback()


def test_provision_rollback_absent_reconciliation_commit_and_exact_retry(database, signer):
    _engine, factory = database
    private_key, public_key = signer
    with factory() as session:
        transaction = session.begin()
        command = signed_command(
            private_key,
            action="provision",
            successor_secret=SECRET_V1,
            successor_version=1,
            now_ms=database_now_ms(session),
            nonce_seed=2,
        )
        staged = owner(session, public_key, secret=SECRET_V1, version=1).execute(*command)
        assert staged.outcome == "staged"
        transaction.rollback()

    with factory.begin() as session:
        absent = owner(
            session,
            public_key,
            secret=SECRET_V1,
            version=1,
        ).reconcile_uncertain_commit(*command)
        assert absent.outcome == "absent"

    with factory.begin() as session:
        staged = owner(session, public_key, secret=SECRET_V1, version=1).execute(*command)
        assert staged.outcome == "staged"

    with factory.begin() as session:
        committed = owner(session, public_key, secret=SECRET_V1, version=1).execute(*command)
        assert committed.outcome == "committed"
    with factory.begin() as session:
        reconciled = owner(
            session,
            public_key,
            secret=SECRET_V1,
            version=1,
        ).reconcile_uncertain_commit(*command)
        assert reconciled.outcome == "committed"
    with factory.begin() as session:
        locked = namespace.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
            session,
            configured_alias_secret=SECRET_V1,
            configured_alias_version=1,
        ).lock_configured_active_namespace()
        assert locked.alias_version == 1


@pytest.mark.parametrize("savepoint_resolution", ("release", "rollback"))
def test_savepoint_staging_is_never_reported_committed_before_outer_commit(
    database,
    signer,
    savepoint_resolution,
):
    _engine, factory = database
    private_key, public_key = signer
    with factory() as session:
        transaction = session.begin()
        command = signed_command(
            private_key,
            action="provision",
            successor_secret=SECRET_V1,
            successor_version=1,
            now_ms=database_now_ms(session),
            nonce_seed=15,
        )
        nested = session.begin_nested()
        staged = owner(session, public_key, secret=SECRET_V1, version=1).execute(*command)
        assert staged.outcome == "staged"
        xid_evidence = session.execute(
            text(
                f"SELECT xmin::text, pg_typeof(xmin)::text, "
                f"staged_top_level_transaction_id::text, "
                f"pg_typeof(staged_top_level_transaction_id)::text, "
                f"pg_current_xact_id()::text "
                f"FROM {writer.EVENT_TABLE}"
            )
        ).one()
        assert xid_evidence[0] != xid_evidence[2]
        assert xid_evidence[2] == xid_evidence[4]
        assert xid_evidence[1:4:2] == ("xid", "xid8")

        if savepoint_resolution == "release":
            nested.commit()
            with pytest.raises(DENIED, match=ERROR):
                owner(session, public_key, secret=SECRET_V1, version=1).execute(*command)
        else:
            nested.rollback()
            retry = owner(session, public_key, secret=SECRET_V1, version=1).execute(*command)
            assert retry.outcome == "staged"
        transaction.commit()

    with factory.begin() as session:
        retry = owner(session, public_key, secret=SECRET_V1, version=1).execute(*command)
        assert retry.outcome == "committed"


def test_competing_exact_provisioners_serialize_to_one_stage_and_one_history_read(database, signer):
    _engine, factory = database
    private_key, public_key = signer
    with factory() as session:
        command = signed_command(
            private_key,
            action="provision",
            successor_secret=SECRET_V1,
            successor_version=1,
            now_ms=database_now_ms(session),
            nonce_seed=3,
        )

    def compete():
        with factory.begin() as session:
            return owner(session, public_key, secret=SECRET_V1, version=1).execute(*command).outcome

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(compete), pool.submit(compete)]
        outcomes = sorted(future.result(timeout=10) for future in futures)
    assert outcomes == ["committed", "staged"]


def test_competing_rotators_and_reader_writer_interlock(database, signer):
    engine, factory = database
    private_key, public_key = signer
    provision(factory, signer, nonce_seed=4)
    with factory() as session:
        now = database_now_ms(session)
    commands = (
        (
            SECRET_V2,
            signed_command(
                private_key,
                action="rotate",
                expected_secret=SECRET_V1,
                expected_version=1,
                successor_secret=SECRET_V2,
                successor_version=2,
                now_ms=now,
                nonce_seed=5,
            ),
        ),
        (
            SECRET_V2_COMPETITOR,
            signed_command(
                private_key,
                action="rotate",
                expected_secret=SECRET_V1,
                expected_version=1,
                successor_secret=SECRET_V2_COMPETITOR,
                successor_version=2,
                now_ms=now,
                nonce_seed=6,
            ),
        ),
    )

    def compete(secret, command):
        try:
            with factory.begin() as session:
                outcome = owner(session, public_key, secret=secret, version=2).execute(*command)
                return "won", secret, outcome.outcome
        except DENIED:
            return "denied", secret, None

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(compete, *candidate) for candidate in commands]
        outcomes = [future.result(timeout=10) for future in futures]
    winner = next(item for item in outcomes if item[0] == "won")
    assert winner[2] == "staged"
    assert sum(item[0] == "denied" for item in outcomes) == 1
    with factory.begin() as session:
        assert (
            namespace.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
                session,
                configured_alias_secret=winner[1],
                configured_alias_version=2,
            )
            .lock_configured_active_namespace()
            .alias_version
            == 2
        )

    # Use a fresh database state in the same schema by testing a reader lock on
    # the winning generation and a signed generation-3 rotation.
    successor_v3 = bytes(range(32, 64))
    with factory() as session:
        command_v3 = signed_command(
            private_key,
            action="rotate",
            expected_secret=winner[1],
            expected_version=2,
            successor_secret=successor_v3,
            successor_version=3,
            now_ms=database_now_ms(session),
            nonce_seed=7,
        )
    pids = Queue()

    def rotate_waiter():
        with factory.begin() as session:
            pids.put(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
            return owner(session, public_key, secret=successor_v3, version=3).execute(*command_v3).outcome

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as reader_session:
            transaction = reader_session.begin()
            reader = namespace.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
                reader_session,
                configured_alias_secret=winner[1],
                configured_alias_version=2,
            )
            assert reader.lock_configured_active_namespace().alias_version == 2
            blocker = reader_session.execute(text("SELECT pg_backend_pid()")).scalar_one()
            future = pool.submit(rotate_waiter)
            wait_until_blocked(engine, pids.get(timeout=5), blocker)
            assert not future.done()
            transaction.commit()
        assert future.result(timeout=10) == "staged"

    with factory.begin() as session:
        with pytest.raises(namespace.ActiveAliasNamespaceUnavailable):
            namespace.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
                session,
                configured_alias_secret=winner[1],
                configured_alias_version=2,
            ).lock_configured_active_namespace()
    with factory.begin() as session:
        assert (
            namespace.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
                session,
                configured_alias_secret=successor_v3,
                configured_alias_version=3,
            )
            .lock_configured_active_namespace()
            .alias_version
            == 3
        )


def test_deferred_guards_reject_row_event_and_rotation_subsets(database, signer):
    _engine, factory = database
    private_key, _public_key = signer
    namespace_table = namespace.SocialMessagingActiveAliasNamespaceRow.__table__
    event_table = writer.SocialMessagingActiveAliasNamespaceLifecycleEventRow.__table__
    with factory() as session:
        provision_command = signed_command(
            private_key,
            action="provision",
            successor_secret=SECRET_V1,
            successor_version=1,
            now_ms=database_now_ms(session),
            nonce_seed=8,
        )
    parsed = lifecycle.parse_canonical_alias_lifecycle_command_v1(provision_command[0])
    event_values = writer._event_values(parsed, *provision_command)

    with pytest.raises(DBAPIError):
        with factory.begin() as session:
            session.execute(
                namespace_table.insert().values(
                    alias_version=1,
                    secret_commitment=parsed["successorCommitment"],
                    lifecycle_state=namespace.ACTIVE_NAMESPACE_STATE,
                )
            )
    with pytest.raises(DBAPIError):
        with factory.begin() as session:
            session.execute(event_table.insert().values(**event_values))

    provision(factory, signer, nonce_seed=9)
    with factory() as session:
        rotate_command = signed_command(
            private_key,
            action="rotate",
            expected_secret=SECRET_V1,
            expected_version=1,
            successor_secret=SECRET_V2,
            successor_version=2,
            now_ms=database_now_ms(session),
            nonce_seed=10,
        )
    rotate_values = writer._event_values(
        lifecycle.parse_canonical_alias_lifecycle_command_v1(rotate_command[0]),
        *rotate_command,
    )
    with pytest.raises(DBAPIError):
        with factory.begin() as session:
            session.execute(
                namespace_table.update()
                .where(namespace_table.c.alias_version == 1)
                .values(lifecycle_state=namespace.RETIRED_NAMESPACE_STATE)
            )
            session.execute(
                namespace_table.insert().values(
                    alias_version=2,
                    secret_commitment=rotate_values["successor_commitment"],
                    lifecycle_state=namespace.ACTIVE_NAMESPACE_STATE,
                )
            )
    with pytest.raises(DBAPIError):
        with factory.begin() as session:
            session.execute(event_table.insert().values(**rotate_values))


def test_rotation_expiring_while_waiting_on_reader_is_reverified_and_rolled_back(
    database,
    signer,
):
    engine, factory = database
    private_key, public_key = signer
    provision(factory, signer, nonce_seed=13)
    with factory() as session:
        command = signed_command(
            private_key,
            action="rotate",
            expected_secret=SECRET_V1,
            expected_version=1,
            successor_secret=SECRET_V2,
            successor_version=2,
            now_ms=database_now_ms(session),
            nonce_seed=14,
            expires_after_ms=300,
        )
    pids = Queue()

    def rotate_waiter():
        try:
            with factory.begin() as session:
                pids.put(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
                owner(session, public_key, secret=SECRET_V2, version=2).execute(*command)
            return "accepted"
        except DENIED:
            return "denied"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as reader_session:
            transaction = reader_session.begin()
            reader = namespace.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
                reader_session,
                configured_alias_secret=SECRET_V1,
                configured_alias_version=1,
            )
            assert reader.lock_configured_active_namespace().alias_version == 1
            blocker = reader_session.execute(text("SELECT pg_backend_pid()")).scalar_one()
            future = pool.submit(rotate_waiter)
            wait_until_blocked(engine, pids.get(timeout=5), blocker)
            time.sleep(0.4)
            transaction.commit()
        assert future.result(timeout=10) == "denied"

    with factory.begin() as session:
        assert (
            namespace.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
                session,
                configured_alias_secret=SECRET_V1,
                configured_alias_version=1,
            )
            .lock_configured_active_namespace()
            .alias_version
            == 1
        )


def test_event_history_is_immutable_and_structural_sql_is_not_signer_authentication(database, signer):
    _engine, factory = database
    private_key, public_key = signer
    command = provision(factory, signer, nonce_seed=11)
    event_table = writer.SocialMessagingActiveAliasNamespaceLifecycleEventRow.__table__
    statements = (
        event_table.update().values(signature="A" * 86),
        event_table.delete(),
        text(f"TRUNCATE {writer.EVENT_TABLE}"),
    )
    for statement in statements:
        with pytest.raises(DBAPIError):
            with factory.begin() as session:
                session.execute(statement)

    # Exact SQL shape checks cannot replace the pinned Ed25519 verifier.
    wrong_private_key = Ed25519PrivateKey.generate()
    wrong_signature = (
        base64.urlsafe_b64encode(wrong_private_key.sign(lifecycle.SIGNATURE_DOMAIN + b"\x00" + command[0]))
        .decode("ascii")
        .rstrip("=")
    )
    with factory.begin() as session:
        with pytest.raises(DENIED, match=ERROR):
            owner(session, public_key, secret=SECRET_V1, version=1).execute(
                command[0],
                wrong_signature,
            )
    assert private_key is not wrong_private_key


def test_transaction_savepoint_and_guard_identity_are_pinned(database, signer):
    engine, factory = database
    private_key, public_key = signer
    with factory() as session:
        transaction = session.begin()
        command = signed_command(
            private_key,
            action="provision",
            successor_secret=SECRET_V1,
            successor_version=1,
            now_ms=database_now_ms(session),
            nonce_seed=12,
        )
        value = owner(session, public_key, secret=SECRET_V1, version=1)
        assert not hasattr(value, "_configured_successor_alias_secret")
        assert SECRET_V1 not in value.__dict__.values()
        nested = session.begin_nested()
        with pytest.raises(DENIED, match=ERROR):
            value.execute(*command)
        nested.rollback()
        transaction.rollback()

    with engine.begin() as connection:
        connection.exec_driver_sql(f"DROP TRIGGER trg_social_alias_lifecycle_event_invariant ON {writer.EVENT_TABLE}")
    with factory.begin() as session:
        with pytest.raises(DENIED, match=ERROR):
            owner(session, public_key, secret=SECRET_V1, version=1)


def test_migration_ddl_is_transactional(postgres_target):
    schema = "alias_lifecycle_ddl_" + uuid.uuid4().hex
    with postgres_target.connect() as connection:
        transaction = connection.begin()
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        connection.exec_driver_sql(f'SET LOCAL search_path = "{schema}"')
        connection.exec_driver_sql(NAMESPACE_MIGRATION.read_text(encoding="ascii"))
        connection.exec_driver_sql(LIFECYCLE_MIGRATION.read_text(encoding="ascii"))
        assert connection.execute(
            text("SELECT to_regclass(:table)"),
            {"table": writer.EVENT_TABLE},
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

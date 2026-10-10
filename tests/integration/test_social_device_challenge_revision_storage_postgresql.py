"""UNEXECUTED rehearsal source; requires a separately authorized disposable DB.

The future operator must provision the two distinct roles and the exact empty
legacy challenge/consumption schema beforehand. This suite never creates a
cluster, uses DATABASE_URL, provisions roles or falls back to port 5432. The ACK
authorizes applying the new source and dropping its exact synthetic challenge
relations on this disposable target at teardown. Cluster teardown is still the
future operator's responsibility. Offline syntax inspection proves no SQL.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.services import social_device_challenge_revision_storage as storage
from app.services import social_device_challenge_store as legacy
from tests.unit.test_social_device_challenge_store import canonical, persisted

ROOT = Path(__file__).resolve().parents[2]
PREFIX = "UBID_ISSUED_CHALLENGE_REVISION_REHEARSAL_"
ACK = "DISPOSABLE-ISSUED-CHALLENGE-REVISION-V1-APPLY-AND-DROP-SYNTHETIC-TABLES"
DDL_ROLE = "issued_challenge_revision_ddl"
RUNTIME_ROLE = "issued_challenge_revision_runtime"
DATABASE = "issued_challenge_revision_rehearsal"
_TARGET_IDENTITY = None


def recheck(connection, role):
    assert _TARGET_IDENTITY is not None
    data, port = _TARGET_IDENTITY
    identity(connection, data=data, port=port, role=role)


def synthetic_row():
    row = persisted("enrollmentV2")
    challenge_id = uuid.uuid4().hex + uuid.uuid4().hex
    context, challenge = json.loads(row["context_wire"]), json.loads(row["challenge_wire"])
    context["challengeId"] = challenge["enrollmentChallengeId"] = challenge_id
    row.update(challenge_id=challenge_id, context_wire=canonical(context), challenge_wire=canonical(challenge))
    legacy.parse_stored_device_challenge_v1(row)
    return row


def insert(connection, row):
    role = connection.execute(text("SELECT current_user")).scalar_one()
    assert role in (DDL_ROLE, RUNTIME_ROLE)
    recheck(connection, role)
    connection.execute(
        text(
            "INSERT INTO public.social_device_admission_challenges "
            "(challenge_id,context_wire,challenge_wire,routing_request_wire,state) "
            "VALUES (:challenge_id,:context_wire,:challenge_wire,:routing_request_wire,:state)"
        ),
        row,
    )


def identity(connection, *, data, port, role):
    target = connection.execute(
        text(
            "SELECT current_database(), current_user, session_user, "
            "pg_catalog.current_setting('data_directory'), pg_catalog.current_setting('port'), "
            "pg_catalog.current_setting('listen_addresses'), pg_catalog.current_setting('unix_socket_directories')"
        )
    ).one()
    assert target[:3] == (DATABASE, role, role)
    assert Path(target[3]).resolve() == data and int(target[4]) == port
    assert target[5:] == ("127.0.0.1", "")


@pytest.fixture(scope="module")
def target():
    global _TARGET_IDENTITY
    # No connection is even attempted without every explicit target guard.
    if not os.environ.get(PREFIX + "DSN") or not os.environ.get(PREFIX + "DDL_DSN"):
        pytest.skip("separately authorized disposable revision target not supplied")
    assert os.environ.get(PREFIX + "ACK") == ACK
    data = Path(os.environ[PREFIX + "DATA"]).resolve()
    assert data.name == "data" and data.parent.parent == Path("/tmp")
    assert data.parent.name.startswith("ubid-issued-challenge-revision-rehearsal-")
    assert len(data.parent.name.removeprefix("ubid-issued-challenge-revision-rehearsal-")) >= 16
    assert 13 <= int((data / "PG_VERSION").read_text().strip()) <= 16
    port = int(os.environ[PREFIX + "PORT"])
    assert 49152 <= port <= 65535
    urls = [make_url(os.environ[PREFIX + suffix]) for suffix in ("DSN", "DDL_DSN")]
    for url, role in zip(urls, (RUNTIME_ROLE, DDL_ROLE)):
        assert url.drivername == "postgresql+psycopg2" and url.host == "127.0.0.1"
        assert url.port == port and url.database == DATABASE and url.username == role
        assert url.password is None and not url.query
    runtime, ddl = [
        create_engine(
            url,
            poolclass=NullPool,
            hide_parameters=True,
            connect_args={"connect_timeout": 3, "options": "-c lock_timeout=2000 -c statement_timeout=5000"},
        )
        for url in urls
    ]
    _TARGET_IDENTITY = (data, port)
    applied = False
    try:
        for engine, role in ((runtime, RUNTIME_ROLE), (ddl, DDL_ROLE)):
            with engine.connect() as c:
                identity(c, data=data, port=port, role=role)
        old = synthetic_row()
        with ddl.begin() as c:
            recheck(c, DDL_ROLE)
            # An exact synthetic prerequisite schema; no unrelated public tables.
            assert set(
                c.execute(
                    text(
                        "SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                        "WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f')"
                    )
                ).scalars()
            ) == {
                "social_device_admission_challenges",
                "social_device_enrollment_admission_receipts",
                "social_device_ed25519_association_chains",
                "social_device_ed25519_association_events",
            }
            for table in (
                "social_device_admission_challenges",
                "social_device_enrollment_admission_receipts",
                "social_device_ed25519_association_chains",
                "social_device_ed25519_association_events",
            ):
                assert c.execute(text(f"SELECT count(*) FROM public.{table}")).scalar_one() == 0
            assert c.execute(text("SELECT count(*) FROM public.social_device_admission_challenges")).scalar_one() == 0
            assert (
                c.execute(
                    text("SELECT pg_catalog.to_regclass('public.social_device_admission_challenge_revisions')")
                ).scalar_one()
                is None
            )
            insert(c, old)
            c.exec_driver_sql((ROOT / "migrations/2026-10-09_social_device_challenge_revision_v1.sql").read_text())
            c.exec_driver_sql(
                "GRANT SELECT ON public.social_device_admission_challenge_revisions TO issued_challenge_revision_runtime"
            )
        applied = True
        yield runtime, ddl, old
    finally:
        if applied:
            # Exact disposable identity is checked again before destructive test cleanup.
            with ddl.begin() as c:
                identity(c, data=data, port=port, role=DDL_ROLE)
                c.exec_driver_sql(
                    "DROP TRIGGER trg_social_challenge_revision_issue ON public.social_device_admission_challenges"
                )
                c.exec_driver_sql("DROP TABLE public.social_device_admission_challenge_revisions")
                c.exec_driver_sql("DROP FUNCTION public.issue_social_device_challenge_revision_v1()")
                c.exec_driver_sql("DROP FUNCTION public.deny_social_device_challenge_revision_mutation_v1()")
                c.exec_driver_sql("DROP TABLE public.social_device_admission_challenges CASCADE")
                assert c.execute(
                    text(
                        "SELECT pg_catalog.to_regclass('public.social_device_admission_challenge_revisions'), "
                        "pg_catalog.to_regclass('public.social_device_admission_challenges')"
                    )
                ).one() == (None, None)
                assert (
                    c.execute(
                        text(
                            "SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
                            "WHERE n.nspname='public' AND p.proname IN ('issue_social_device_challenge_revision_v1',"
                            "'deny_social_device_challenge_revision_mutation_v1')"
                        )
                    ).scalar_one()
                    == 0
                )
        _TARGET_IDENTITY = None
        runtime.dispose()
        ddl.dispose()


@pytest.fixture(autouse=True)
def recheck_module_target(target):
    runtime, ddl, _ = target
    for engine, role in ((runtime, RUNTIME_ROLE), (ddl, DDL_ROLE)):
        with engine.connect() as c:
            recheck(c, role)


def reader(session, row):
    recheck(session.connection(), RUNTIME_ROLE)
    adapter = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    parsed = legacy.parse_stored_device_challenge_v1(row)
    return adapter, parsed.issued_at


def test_trigger_same_transaction_and_rollback_both_rows(target):
    runtime, _, _ = target
    row = synthetic_row()
    with Session(runtime) as session:
        session.begin()
        recheck(session.connection(), RUNTIME_ROLE)
        store = legacy.SqlAlchemyDeviceChallengeStore(session)
        created = store.create_issued(context_wire=row["context_wire"], challenge_wire=row["challenge_wire"])
        adapter, now = reader(session, row)
        result = adapter.read_issued_with_revision_in_transaction(row["challenge_id"], observed_at=now)
        assert result.challenge == created and result.challenge_revision == 1
        with pytest.raises(legacy.SocialDeviceChallengeStorageUnavailable):
            with session.begin_nested():
                nested_store = legacy.SqlAlchemyDeviceChallengeStore(session)
                nested_store.create_issued(context_wire=row["context_wire"], challenge_wire=row["challenge_wire"])
        session.rollback()
    with runtime.connect() as c:
        recheck(c, RUNTIME_ROLE)
        for table in ("social_device_admission_challenges", "social_device_admission_challenge_revisions"):
            assert (
                c.execute(
                    text(f"SELECT count(*) FROM public.{table} WHERE challenge_id=:id"), {"id": row["challenge_id"]}
                ).scalar_one()
                == 0
            )


def test_preexisting_challenge_is_never_adopted(target):
    runtime, _, old = target
    with Session(runtime) as session, session.begin():
        assert legacy.SqlAlchemyDeviceChallengeStore(session).read(old["challenge_id"]).state == "issued"
        adapter, now = reader(session, old)
        with pytest.raises(storage.SocialDeviceChallengeRevisionStorageUnavailable):
            adapter.read_issued_with_revision_in_transaction(old["challenge_id"], observed_at=now)
        assert adapter._failed


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO public.social_device_admission_challenge_revisions VALUES (:id,1)",
        "UPDATE public.social_device_admission_challenge_revisions SET revision=1 WHERE challenge_id=:id",
        "DELETE FROM public.social_device_admission_challenge_revisions WHERE challenge_id=:id",
        "TRUNCATE public.social_device_admission_challenge_revisions",
        "SELECT public.issue_social_device_challenge_revision_v1()",
        "SELECT public.deny_social_device_challenge_revision_mutation_v1()",
    ],
)
def test_runtime_has_no_mutation_or_function_execute(target, sql):
    runtime, _, old = target
    with runtime.connect() as c:
        recheck(c, RUNTIME_ROLE)
        with pytest.raises(DBAPIError):
            c.execute(text(sql), {"id": old["challenge_id"]})
        c.rollback()


@pytest.mark.parametrize("state", ["expired", "invalidated", "cancelled"])
def test_native_generation_persists_across_permitted_terminal_transition(target, state):
    runtime, _, _ = target
    row = synthetic_row()
    with runtime.connect() as c:
        recheck(c, RUNTIME_ROLE)
        insert(c, row)
        c.execute(
            text("UPDATE public.social_device_admission_challenges SET state=:state WHERE challenge_id=:id"),
            {"state": state, "id": row["challenge_id"]},
        )
        assert (
            c.execute(
                text("SELECT revision FROM public.social_device_admission_challenge_revisions WHERE challenge_id=:id"),
                {"id": row["challenge_id"]},
            ).scalar_one()
            == 1
        )
        c.rollback()


@pytest.mark.parametrize("sql", ["COMMIT", "ROLLBACK"])
def test_raw_root_replacement_detected_even_when_sqlalchemy_objects_survive(target, sql):
    runtime, _, old = target
    with Session(runtime) as session:
        session.begin()
        adapter, now = reader(session, old)
        c = session.connection()
        identities = (session.get_transaction(), c.get_transaction(), c.connection.dbapi_connection)
        recheck(c, RUNTIME_ROLE)
        c.exec_driver_sql(sql)
        assert identities == (session.get_transaction(), c.get_transaction(), c.connection.dbapi_connection)
        with pytest.raises(storage.SocialDeviceChallengeRevisionStorageUnavailable):
            adapter.read_issued_with_revision_in_transaction(old["challenge_id"], observed_at=now)
        assert adapter._failed
        session.rollback()


def test_supported_sqlalchemy_savepoint_replacement_is_denied(target):
    runtime, _, old = target
    with Session(runtime) as session, session.begin():
        nested = session.begin_nested()
        adapter, now = reader(session, old)
        nested.rollback()
        session.begin_nested()
        with pytest.raises(storage.SocialDeviceChallengeRevisionStorageUnavailable):
            adapter.read_issued_with_revision_in_transaction(old["challenge_id"], observed_at=now)


def test_pg_current_xact_id_is_top_level_only_not_raw_savepoint_authentication(target):
    runtime, _, _ = target
    with runtime.connect() as c:
        recheck(c, RUNTIME_ROLE)
        root = c.execute(text("SELECT pg_catalog.pg_current_xact_id()::text")).scalar_one()
        c.exec_driver_sql("SAVEPOINT unsupported_raw_example")
        assert c.execute(text("SELECT pg_catalog.pg_current_xact_id()::text")).scalar_one() == root
        c.exec_driver_sql("ROLLBACK TO SAVEPOINT unsupported_raw_example")
        assert c.execute(text("SELECT pg_catalog.pg_current_xact_id()::text")).scalar_one() == root
        c.exec_driver_sql("RELEASE SAVEPOINT unsupported_raw_example")
        c.rollback()


def test_invalidated_physical_connection_is_denied(target):
    runtime, _, old = target
    with Session(runtime) as session:
        session.begin()
        adapter, now = reader(session, old)
        session.connection().invalidate()
        with pytest.raises(storage.SocialDeviceChallengeRevisionStorageUnavailable):
            adapter.read_issued_with_revision_in_transaction(old["challenge_id"], observed_at=now)
        session.rollback()


@pytest.mark.parametrize(
    "ddl_sql",
    [
        "ALTER TABLE public.social_device_admission_challenges DISABLE TRIGGER trg_social_challenge_revision_issue",
        "DROP TRIGGER trg_social_challenge_revision_issue ON public.social_device_admission_challenges",
        "ALTER FUNCTION public.issue_social_device_challenge_revision_v1() SET search_path=public",
        "ALTER TABLE public.social_device_admission_challenge_revisions DISABLE TRIGGER trg_social_challenge_revision_immutable",
    ],
)
def test_missing_disabled_or_tampered_definition_denies(target, ddl_sql):
    runtime, ddl, old = target
    with Session(runtime) as session, session.begin():
        adapter, _ = reader(session, old)
        with ddl.connect() as c:
            recheck(c, DDL_ROLE)
            before = c.execute(text(storage.CATALOG_SQL)).mappings().all()
            try:
                c.exec_driver_sql(ddl_sql)
                assert_native_catalog_denial(adapter, c)
            finally:
                c.rollback()  # Transactional DDL restores original OIDs/definitions.
                recheck(c, DDL_ROLE)
                after = c.execute(text(storage.CATALOG_SQL)).mappings().all()
                assert [r["guards"] for r in after] == [r["guards"] for r in before]
                c.rollback()


def assert_native_catalog_denial(adapter, owner_connection):
    """Bounded native-catalog -> COMPLETE validator coverage, not a lock/read test.

    Uncommitted ALTER TABLE holds a lock that blocks the restricted reader.
    Capture its actual native catalog in the DDL transaction and pass those exact
    rows to the already-established restricted reader's entire _catalog validator.
    Evaluate the security query for the original restricted role OID in the same
    native catalog snapshot. Only direct-login is retained from that established
    restricted connection; no catalog/grant/owner denial is fabricated.
    """
    rows = owner_connection.execute(text(storage.CATALOG_SQL)).mappings().all()
    parent = next(r for r in rows if r["relation"]["relname"] == legacy.TABLE)
    companion = next(r for r in rows if r["relation"]["relname"] == storage.TABLE)
    security = (
        owner_connection.execute(
            text(storage.SECURITY_SQL.replace("WHERE r.rolname=current_user", "WHERE r.rolname=:runtime_role")),
            {
                "runtime_role": RUNTIME_ROLE,
                "parent": parent["oid"],
                "companion": companion["oid"],
                "parent_owner": parent["owner"],
                "companion_owner": companion["owner"],
                "guard_oids": sorted({g["function"]["oid"] for row in rows for g in row["guards"]}),
            },
        )
        .mappings()
        .one()
    )

    class NativeRows:
        def __init__(self, value):
            self.value = value

        def mappings(self):
            return self

        def all(self):
            return self.value

        def one(self):
            return self.value

    original = adapter._execute

    def snapshot(statement, parameters=None):
        if str(statement) == storage.CATALOG_SQL:
            return NativeRows(rows)
        if str(statement) == storage.SECURITY_SQL:
            return NativeRows(security)
        return original(statement, parameters)

    adapter._execute = snapshot
    try:
        with pytest.raises(storage.SocialDeviceChallengeRevisionStorageUnavailable):
            adapter._catalog()
    finally:
        adapter._execute = original


@pytest.mark.parametrize(
    "ddl_sql",
    [
        "ALTER TABLE public.social_device_admission_challenges DROP CONSTRAINT ck_social_challenge_id; "
        "ALTER TABLE public.social_device_admission_challenges ADD CONSTRAINT ck_social_challenge_id CHECK (challenge_id ~ '^[0-9a-f]+$')",
        "ALTER TABLE public.social_device_admission_challenges DROP CONSTRAINT ck_social_challenge_wire; "
        "ALTER TABLE public.social_device_admission_challenges ADD CONSTRAINT ck_social_challenge_wire CHECK (octet_length(challenge_wire)>0) NOT VALID",
        # Future DDL prerequisite: owner can assign ownership to the runtime role.
        "GRANT CREATE ON SCHEMA public TO issued_challenge_revision_runtime; "
        "ALTER FUNCTION public.guard_social_device_challenge_v1() OWNER TO issued_challenge_revision_runtime; "
        "REVOKE CREATE ON SCHEMA public FROM issued_challenge_revision_runtime",
        "GRANT CREATE ON SCHEMA public TO issued_challenge_revision_runtime; "
        "ALTER SCHEMA public OWNER TO issued_challenge_revision_runtime; "
        "REVOKE CREATE ON SCHEMA public FROM issued_challenge_revision_runtime",
        # Future explicit DDL principal must be authorized to grant its role.
        "GRANT issued_challenge_revision_ddl TO issued_challenge_revision_runtime",
    ],
)
def test_repaired_parent_and_owner_boundaries_native_complete_validator(target, ddl_sql):
    runtime, ddl, old = target
    with Session(runtime) as session, session.begin():
        adapter, _ = reader(session, old)
        with ddl.connect() as c:
            recheck(c, DDL_ROLE)
            before = c.execute(text(storage.CATALOG_SQL)).mappings().all()
            try:
                c.exec_driver_sql(ddl_sql)
                assert_native_catalog_denial(adapter, c)
            finally:
                c.rollback()
                recheck(c, DDL_ROLE)
                after = c.execute(text(storage.CATALOG_SQL)).mappings().all()
                for key in ("constraints", "guards", "namespace", "indexes"):
                    assert [r[key] for r in after] == [r[key] for r in before]
                assert not c.execute(
                    text("SELECT pg_catalog.pg_has_role(:runtime_role,:ddl_role,'MEMBER')"),
                    {"runtime_role": RUNTIME_ROLE, "ddl_role": DDL_ROLE},
                ).scalar_one()
                c.rollback()


def test_shadow_search_path_relation_denies(target):
    runtime, _, old = target
    with Session(runtime) as session, session.begin():
        recheck(session.connection(), RUNTIME_ROLE)
        session.connection().exec_driver_sql("CREATE TEMP TABLE social_device_admission_challenges (challenge_id text)")
        with pytest.raises(storage.SocialDeviceChallengeRevisionStorageUnavailable):
            reader(session, old)


@pytest.mark.parametrize("invalidate", [False, True])
def test_locked_parent_reparse_after_bounded_wait_denies_expired_observation_or_invalidation(target, invalidate):
    # Expiry branch supplies an already-expired observed_at. It proves exclusive
    # rejection after a bounded wait, not clock resampling/deadline crossing.
    runtime, ddl, _ = target
    row = synthetic_row()
    with ddl.begin() as c:
        recheck(c, DDL_ROLE)
        insert(c, row)
    locked, started, release = Event(), Event(), Event()

    def writer():
        with runtime.begin() as c:
            recheck(c, RUNTIME_ROLE)
            c.execute(
                text(
                    "SELECT challenge_id FROM public.social_device_admission_challenges WHERE challenge_id=:id FOR UPDATE"
                ),
                {"id": row["challenge_id"]},
            )
            if invalidate:
                c.execute(
                    text(
                        "UPDATE public.social_device_admission_challenges SET state='invalidated' WHERE challenge_id=:id"
                    ),
                    {"id": row["challenge_id"]},
                )
            locked.set()
            assert release.wait(4)

    def observer():
        assert locked.wait(3)
        with Session(runtime) as session, session.begin():
            adapter, now = reader(session, row)
            started.set()
            if not invalidate:
                now = legacy.parse_stored_device_challenge_v1(row).expires_at
            with pytest.raises(storage.SocialDeviceChallengeRevisionStorageUnavailable):
                adapter.read_issued_with_revision_in_transaction(row["challenge_id"], observed_at=now)
            assert adapter._failed

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(writer), pool.submit(observer)
        try:
            assert started.wait(3)
            # Prove an actual backend wait before releasing the writer.
            until = time.monotonic() + 1
            with ddl.connect() as c:
                while time.monotonic() < until:
                    waiting = c.execute(
                        text(
                            "SELECT count(*) FROM pg_catalog.pg_locks WHERE NOT granted AND locktype='transactionid' AND database IS NULL"
                        )
                    ).scalar_one()
                    if waiting:
                        break
                    time.sleep(0.01)
                assert waiting
        finally:
            release.set()
        a.result(timeout=5)
        b.result(timeout=5)


def test_native_catalog_json_shapes_and_complete_reader_positive(target):
    runtime, _, old = target
    with Session(runtime) as session, session.begin():
        c = session.connection()
        recheck(c, RUNTIME_ROLE)
        rows = c.execute(text(storage.CATALOG_SQL)).mappings().all()
        parent = next(r for r in rows if r["relation"]["relname"] == legacy.TABLE)
        companion = next(r for r in rows if r["relation"]["relname"] == storage.TABLE)
        assert type(parent["oid"]) is int
        assert type(parent["relation"]["oid"]) is str
        assert type(parent["namespace"]["nspowner"]) is str
        assert type(parent["toast"]["relowner"]) is str
        assert type(parent["attributes"][0]["atttypid"]) is str
        constraints = {k["catalog"]["conname"]: k for k in parent["constraints"]}
        assert len(constraints) == 8
        atomic = constraints["trg_social_enrollment_challenge_atomic"]
        assert atomic["definition"] == "TRIGGER DEFERRABLE INITIALLY DEFERRED"
        assert atomic["catalog"]["contype"] == "t"
        assert atomic["catalog"]["conkey"] is None
        assert atomic["catalog"]["connoinherit"] is True
        assert parent["atomic_binding"][0]["constraint"] == int(atomic["catalog"]["oid"])
        assert constraints["ck_social_challenge_wire_id"]["catalog"]["conkey"] == [2, 1, 3]
        for row in rows:
            index = row["indexes"][0]["index"]
            assert index["indkey"] == [1]
            assert index["indclass"] == ["3126"] and index["indcollation"] == ["100"]
            for guard in row["guards"]:
                assert guard["function"]["prosupport"] == "-"
                assert guard["function"]["proargtypes"] == []
                assert guard["trigger"]["tgattr"] == []
                assert guard["trigger"]["tgargs"] == "\\x"
                assert type(guard["function"]["proowner"]) is str
        fk = next(k["catalog"] for k in companion["constraints"] if k["catalog"]["contype"] == "f")
        assert fk["confrelid"] == str(parent["oid"])
        assert fk["conpfeqop"] == fk["conppeqop"] == fk["conffeqop"] == ["98"]
        adapter, _ = reader(session, old)  # Entire native catalog and owner validator.
        adapter._catalog()  # Exact repeat identities must remain accepted.
        adapter._catalog()

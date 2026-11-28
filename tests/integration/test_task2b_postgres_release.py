"""Apply the release plan to the schema snapshot with its original owners and ACLs."""

import os
from pathlib import Path
import subprocess

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from app.models import User
from app.services.automatic_sponsored_admission_v1 import refresh_automatic_imports
from app.services.current_entitlement import resolve_runtime_current_entitlement
from app.services.current_entitlement_evidence_storage import SqlAlchemyTransactionBoundCurrentFullVerifier
from app.services.social_enrollment_v2_catalog_roles import ChallengeWriterCatalogPin, catalog_role_scope
from app.services.social_enrollment_v2_finalization_storage import attest_native_schema
from tests.integration.canon_v2_disposable_pg import disposable_postgres_engine
from tests.integration.test_automatic_sponsored_admission_postgres_v1 import (
    ALICE,
    BOB,
    CHARLIE,
    EARLY,
    LATE,
    MIGRATIONS,
    _leg,
    core,
    imported,
    seed_root,
    stamp,
)

PLAN = Path("docs/data/task2b-canonical-migration-order.txt")
ACL_MIGRATION = "2026-11-24_canonical_membership_roles.sql"
REGISTRATION_READ_MIGRATION = "2026-11-24_canonical_publisher_registration_read.sql"
OWNER = "hodlxxi_canonical_owner"
PUBLISHER = "hodlxxi_canonical_publisher"
PUBLISHER_LOGIN = "task2b_publisher_login"
RUNTIME = "hodlxxi"
FINALIZER = "ubid_v2_prod_finalizer"
CHALLENGE = "ubid_v2_prod_challenge"


def _apply(connection, name):
    connection.exec_driver_sql((Path("migrations") / name).read_text(), execution_options={"no_parameters": True})
    print(f"MIGRATION_PASS={name}", flush=True)


def _restore(engine, dump):
    url = engine.url
    pg_restore = Path(os.environ["TASK2B_PG_BIN"]) / "pg_restore"
    toc = subprocess.check_output([pg_restore, "--list", dump], text=True, timeout=15)
    assert not any(" TABLE DATA " in row or " BLOBS " in row for row in toc.splitlines())
    assert url.port != 5432
    subprocess.run(
        [
            pg_restore,
            "--exit-on-error",
            "--single-transaction",
            "--schema-only",
            "--host",
            url.host,
            "--port",
            str(url.port),
            "--username",
            url.username,
            "--dbname",
            url.database,
            dump,
        ],
        env={**os.environ, "PGPASSWORD": url.password},
        timeout=60,
        check=True,
    )


@pytest.fixture(scope="module")
def roles():
    dump = os.environ.get("TASK2B_PG_SCHEMA_DUMP")
    if not dump:
        pytest.skip("requires the schema-only snapshot and opt-in disposable PG16")
    admin = disposable_postgres_engine(os.environ["CANON_V2_TEST_DATABASE_URL"])
    assert admin.url.port != 5432
    with admin.begin() as db:
        assert db.execute(text("SELECT count(*) FROM pg_tables WHERE schemaname='public'")).scalar_one() == 0
        for login in (RUNTIME, PUBLISHER_LOGIN, FINALIZER, CHALLENGE):
            db.exec_driver_sql(
                f"CREATE ROLE {login} LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB PASSWORD %s",
                (admin.url.password,),
            )
        db.exec_driver_sql(f"CREATE ROLE {OWNER} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB")
        db.exec_driver_sql(f"CREATE ROLE {PUBLISHER} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB")
        db.exec_driver_sql(f"GRANT {PUBLISHER} TO {PUBLISHER_LOGIN} WITH SET FALSE")
        db.exec_driver_sql(f"GRANT pg_read_all_settings TO {FINALIZER}, {CHALLENGE}")
    _restore(admin, dump)

    # Exercise the initial legacy schema grant and ownership in the restored catalog.
    with admin.begin() as db:
        assert db.execute(text("SELECT count(*) FROM public.current_entitlement_evidence")).scalar_one() == 0
        assert (
            db.execute(
                text(
                    "SELECT relowner::regrole::text FROM pg_class WHERE oid = "
                    "'public.current_entitlement_evidence'::regclass"
                )
            ).scalar_one()
            == RUNTIME
        )
        db.exec_driver_sql(f"GRANT CREATE ON SCHEMA public TO {RUNTIME}")
    seed_root(admin)
    with admin.begin() as db:
        before = db.execute(
            text("SELECT md5(row_to_json(e)::text) FROM public.current_entitlement_evidence e")
        ).scalar_one()
        order = tuple(PLAN.read_text().splitlines())
        assert order == (*MIGRATIONS, ACL_MIGRATION, REGISTRATION_READ_MIGRATION)
        for name in order[:-2]:
            _apply(db, name)
        with pytest.raises(DBAPIError, match="canonical runtime retains DDL privileges"):
            with db.begin_nested():
                db.exec_driver_sql("CREATE ROLE task2b_inherited_ddl NOLOGIN")
                db.exec_driver_sql("GRANT CREATE ON SCHEMA public TO task2b_inherited_ddl")
                db.exec_driver_sql("GRANT task2b_inherited_ddl TO hodlxxi")
                _apply(db, ACL_MIGRATION)
        assert db.execute(text("SELECT to_regrole('task2b_inherited_ddl')")).scalar_one() is None
        assert db.execute(text("""
            SELECT relowner::regrole::text FROM pg_class
            WHERE oid = 'public.current_entitlement_evidence'::regclass
        """)).scalar_one() == RUNTIME
        print("ROLE_STAGE_ROLLBACK=PASS", flush=True)
        _apply(db, ACL_MIGRATION)
        _apply(db, REGISTRATION_READ_MIGRATION)
        after = db.execute(
            text("SELECT md5(row_to_json(e)::text) FROM public.current_entitlement_evidence e")
        ).scalar_one()
        assert before == after

    engines = {
        login: create_engine(admin.url.set(username=login), hide_parameters=True)
        for login in (RUNTIME, PUBLISHER_LOGIN, FINALIZER, CHALLENGE)
    }
    try:
        yield admin, engines
    finally:
        for engine in (*engines.values(), admin):
            engine.dispose()


def test_migration_accounts_for_original_ownership_and_seals_routines(roles):
    admin, _ = roles
    with admin.connect() as db:
        owners = db.execute(text("""
            SELECT relname, relowner::regrole::text
            FROM pg_class
            WHERE relnamespace = 'public'::regnamespace
              AND relkind IN ('r', 'v')
              AND (relname LIKE 'canonical_%' OR relname = 'current_entitlement_evidence')
        """)).all()
        assert owners and all(owner == OWNER for _, owner in owners)
        functions = db.execute(
            text("""
            SELECT p.proname, p.prosecdef, p.proconfig,
                EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner)))
                        WHERE grantee <> p.proowner)
            FROM pg_proc p WHERE pronamespace = 'public'::regnamespace AND proowner = to_regrole(:owner)
        """),
            {"owner": OWNER},
        ).all()
        assert len(functions) == 28
        assert sum(definer for _, definer, _, _ in functions) == 21
        assert all(
            config == ["search_path=pg_catalog, pg_temp"] and not external for _, _, config, external in functions
        )


@pytest.mark.parametrize("login", [RUNTIME, PUBLISHER_LOGIN])
@pytest.mark.parametrize(
    "command",
    [
        "SET ROLE hodlxxi_canonical_owner",
        "CREATE TABLE public.task2b_unauthorized (x integer)",
        "CREATE SCHEMA task2b_unauthorized",
        "SET session_replication_role = replica",
        "DROP TABLE public.users CASCADE",
        "ALTER TABLE public.current_entitlement_evidence DISABLE TRIGGER USER",
        "ALTER TABLE public.canonical_auto_effective_edges_v1 DISABLE TRIGGER USER",
        "UPDATE public.current_entitlement_evidence SET evidence_id = evidence_id",
        "UPDATE public.canonical_genesis_records SET record_id = record_id",
        "DELETE FROM public.canonical_auto_effective_edges_v1",
        "DELETE FROM public.current_entitlement_evidence",
        "TRUNCATE public.current_entitlement_evidence CASCADE",
        "TRUNCATE public.canonical_global_outpoint_claims_v2",
        "SELECT public.expire_canonical_multileg_candidate_v2('untrusted')",
    ],
)
def test_runtime_and_publisher_cannot_mutate_history_or_ddl(roles, login, command):
    _, engines = roles
    with engines[login].begin() as db, pytest.raises(DBAPIError) as error:
        db.exec_driver_sql(command)
    assert error.value.orig.pgcode in {"42501", "P0001"}


@pytest.mark.parametrize(
    "table",
    [
        "current_entitlement_evidence",
        "canonical_auto_effective_edges_v1",
        "canonical_auto_effective_outpoints_v1",
        "canonical_auto_entitlement_observations_v1",
        "canonical_auto_admission_revocations_v1",
        "canonical_global_outpoint_claims_v2",
    ],
)
def test_web_runtime_cannot_publish_directly(roles, table):
    _, engines = roles
    with engines[RUNTIME].begin() as db, pytest.raises(DBAPIError) as error:
        db.exec_driver_sql(f"INSERT INTO public.{table} DEFAULT VALUES")
    assert error.value.orig.pgcode == "42501"


def test_distinct_production_roles_can_admit_and_refresh_the_recursive_cascade(roles, core, monkeypatch):
    from app import database

    admin, engines = roles
    web, publisher = engines[RUNTIME], engines[PUBLISHER_LOGIN]
    web_sessions, publisher_sessions = sessionmaker(web), sessionmaker(publisher)
    monkeypatch.setattr(database, "get_session", web_sessions)
    for key in (BOB, CHARLIE):
        with Session(web) as db, db.begin():
            db.add(User(pubkey=key[2:], is_active=True, metadata_json={}))
    monkeypatch.setenv("CANON_V2_BITCOIN_CHAIN", "regtest")
    core.fund(EARLY, LATE)
    parent = imported(web)
    assert refresh_automatic_imports(publisher_sessions)["effective_eligible"] == 1
    assert resolve_runtime_current_entitlement(BOB[2:], session_factory=web_sessions).current_full_relation_satisfied

    child_scripts = (_leg(BOB, CHARLIE, 1776223, 1777000), _leg(CHARLIE, BOB, 1777000, 1777777))
    core.fund(*child_scripts)
    child = imported(web, BOB, child_scripts)
    assert refresh_automatic_imports(publisher_sessions)["effective_eligible"] == 1
    assert resolve_runtime_current_entitlement(
        CHARLIE[2:], session_factory=web_sessions
    ).current_full_relation_satisfied
    for reader in (FINALIZER, CHALLENGE):
        with Session(engines[reader]) as db, db.begin():
            verifier = SqlAlchemyTransactionBoundCurrentFullVerifier(db)
            assert verifier.verify_in_transaction(CHARLIE[2:], now=stamp()).subject == CHARLIE[2:]

    with admin.begin() as db:
        db.exec_driver_sql("SET LOCAL ROLE hodlxxi_canonical_owner")
        db.execute(
            text("""
            INSERT INTO public.canonical_auto_admission_revocations_v1(pair_sha256, revoked_at, reason)
            VALUES (:pair, :now, 'sponsorship_revoked')
        """),
            {"pair": parent, "now": stamp()},
        )
    for subject in (BOB[2:], CHARLIE[2:]):
        assert not resolve_runtime_current_entitlement(
            subject, session_factory=web_sessions
        ).current_full_relation_satisfied
    with admin.connect() as db:
        assert (
            db.execute(
                text("""
            SELECT child_depth FROM public.canonical_auto_effective_edges_v1
            WHERE pair_sha256 IN (:parent, :child) ORDER BY child_depth
        """),
                {"parent": parent, "child": child},
            )
            .scalars()
            .all()
            == [1, 2]
        )


def test_existing_social_finalization_catalog_accepts_protected_ownership(roles):
    _, engines = roles
    with Session(engines[FINALIZER]) as db, db.begin():
        peer = db.execute(text("SELECT oid FROM pg_roles WHERE rolname = :name"), {"name": CHALLENGE}).scalar_one()
        with catalog_role_scope(db, ChallengeWriterCatalogPin(CHALLENGE, peer)):
            assert attest_native_schema(db.connection())
    for reader in (FINALIZER, CHALLENGE):
        with engines[reader].connect() as db:
            assert db.execute(
                text(
                    "SELECT has_table_privilege(current_user, "
                    "'public.canonical_auto_entitlement_observations_v1','SELECT')"
                )
            ).scalar_one()


@pytest.mark.parametrize("table", ["trusted_covenant_registrations", "trusted_covenant_registered_outpoints"])
def test_publisher_can_read_registration_without_mutation(roles, table):
    _, engines = roles
    with engines[PUBLISHER_LOGIN].connect() as db:
        db.exec_driver_sql(f"SELECT * FROM public.{table} LIMIT 1").all()
        assert not db.execute(
            text("SELECT has_any_column_privilege(current_user, :table, 'INSERT,UPDATE,REFERENCES')"),
            {"table": "public." + table},
        ).scalar_one()
        assert not db.execute(
            text("SELECT has_table_privilege(current_user, :table, 'DELETE,TRUNCATE,TRIGGER')"),
            {"table": "public." + table},
        ).scalar_one()

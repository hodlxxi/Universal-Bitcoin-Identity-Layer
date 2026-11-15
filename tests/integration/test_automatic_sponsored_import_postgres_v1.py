"""Disposable PG16 sponsor provenance; synthetic Full is never live authority."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import hashlib
import os
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from app.models import CurrentEntitlementEvidence, User
from app.services.automatic_sponsored_import_v1 import (
    AutomaticSponsoredImportUnavailable,
    prepare_authenticated_sponsored_import,
    record_successful_sponsored_import,
    recover_authenticated_sponsored_imports,
)
from tests.integration.canon_v2_disposable_pg import disposable_postgres_engine
from tests.integration.test_canonical_admission_candidate_postgres_v2 import _seed_full
from tests.unit.test_automatic_sponsored_import_v1 import ALICE, BOB, EARLY, LATE
from tests.unit.test_canonical_admission_proposal_v2 import NOW

MIGRATIONS = (
    Path("migrations/2026-11-15_canonical_auto_sponsored_import_v1.sql"),
    Path("migrations/2026-11-15_canonical_auto_sponsored_import_v1_intents.sql"),
)
TABLES = ("canonical_auto_import_intents_v1", "canonical_auto_import_pairs_v1", "canonical_auto_import_scripts_v1")


@pytest.fixture(scope="module")
def engine():
    url = os.environ.get("CANON_V2_TEST_DATABASE_URL")
    if not url or os.environ.get("CANON_V2_DISPOSABLE_PG_ACK") != "1":
        pytest.skip("marked disposable PostgreSQL and explicit acknowledgement required")
    engine = disposable_postgres_engine(url)
    created = False
    try:
        with engine.begin() as connection:
            for name in (*TABLES, "users", "current_entitlement_evidence"):
                if connection.execute(text("SELECT to_regclass(:name)"), {"name": "public." + name}).scalar_one():
                    raise RuntimeError("disposable_test_database_must_be_empty")
            User.__table__.create(connection)
            CurrentEntitlementEvidence.__table__.create(connection)
            for migration in MIGRATIONS:
                connection.exec_driver_sql(migration.read_text(), execution_options={"no_parameters": True})
        created = True
        yield engine
    finally:
        if created:
            with engine.begin() as connection:
                for name in TABLES:
                    connection.exec_driver_sql("DROP TABLE public." + name)
                connection.exec_driver_sql("DROP FUNCTION public.reject_canonical_auto_import_mutation_v1()")
                CurrentEntitlementEvidence.__table__.drop(connection)
                User.__table__.drop(connection)
        engine.dispose()


@pytest.fixture
def db(engine):
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "TRUNCATE public.canonical_auto_import_intents_v1, public.canonical_auto_import_pairs_v1, "
            "public.canonical_auto_import_scripts_v1, public.current_entitlement_evidence, public.users CASCADE"
        )
    _seed_full(engine, ALICE)
    return engine


def _prepare(db, script, **kwargs):
    return prepare_authenticated_sponsored_import(
        sessionmaker(db), sponsor_session_pubkey=ALICE, raw_script_hex=script, now=kwargs.get("now", NOW)
    )


def _record(db, script, **kwargs):
    return record_successful_sponsored_import(
        sessionmaker(db), sponsor_session_pubkey=ALICE, raw_script_hex=script, now=kwargs.get("now", NOW)
    )


def _counts(db):
    with db.connect() as connection:
        return tuple(connection.execute(text("SELECT count(*) FROM public." + name)).scalar_one() for name in TABLES)


class WatchOnlyWallet:
    def __init__(self, scripts=(EARLY, LATE), *, private_keys=False, include_address=True):
        self.private_keys = private_keys
        self.descriptors = []
        for script in scripts:
            self.descriptors.append({"desc": self.getdescriptorinfo(f"raw({script})")["descriptor"]})
            if include_address:
                self.descriptors.append(
                    {
                        "desc": self.getdescriptorinfo(f"addr({self.decodescript(script)['segwit']['address']})")[
                            "descriptor"
                        ]
                    }
                )

    def getwalletinfo(self):
        return {"descriptors": True, "private_keys_enabled": self.private_keys}

    def getdescriptorinfo(self, value):
        return {"descriptor": value + "#fixture-checksum"}

    def decodescript(self, script):
        sha = hashlib.sha256(bytes.fromhex(script)).hexdigest()
        return {"segwit": {"address": "fixture-p2wsh-" + sha, "hex": "0020" + sha}}

    def listdescriptors(self, private):
        assert private is False
        return {"descriptors": self.descriptors}


@pytest.mark.parametrize("scripts", [(EARLY, LATE), (LATE, EARLY)])
def test_reverse_imports_and_retries_converge_without_granting_authority(db, scripts):
    for script in scripts:
        assert _prepare(db, script) == _prepare(db, script)
        result = _record(db, script)
        assert not result.grants_full
    assert result.candidate_child_xonly == BOB[2:]
    assert _record(db, scripts[0]).candidate_child_xonly == BOB[2:]
    assert _counts(db) == (2, 1, 2)
    with db.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM public.current_entitlement_evidence")).scalar_one() == 1
        assert (
            connection.execute(
                text("SELECT count(*) FROM public.users WHERE pubkey=:child"), {"child": BOB[2:]}
            ).scalar_one()
            == 0
        )


def test_concurrent_imports_serialize_by_current_full_subject(db):
    def action(script):
        _prepare(db, script)
        return _record(db, script)

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = tuple(executor.map(action, (EARLY, LATE, EARLY, LATE)))
    assert any(r.candidate_child_xonly == BOB[2:] for r in results)
    assert _counts(db) == (2, 1, 2)


def test_core_success_without_authenticated_provenance_cannot_journal(db):
    with pytest.raises(AutomaticSponsoredImportUnavailable):
        _record(db, EARLY)
    assert _counts(db) == (0, 0, 0)


def test_core_success_followed_by_journal_failure_recovers_without_new_signature(db):
    _prepare(db, EARLY)
    _prepare(db, LATE)

    class FailedJournalSession(Session):
        def execute(self, statement, *args, **kwargs):
            if str(statement).startswith("INSERT INTO public.canonical_auto_import_scripts_v1"):
                raise RuntimeError("synthetic post-Core journal failure")
            return super().execute(statement, *args, **kwargs)

    with pytest.raises(AutomaticSponsoredImportUnavailable):
        record_successful_sponsored_import(
            sessionmaker(db, class_=FailedJournalSession), sponsor_session_pubkey=ALICE, raw_script_hex=EARLY, now=NOW
        )
    assert _counts(db) == (2, 0, 0)
    results = recover_authenticated_sponsored_imports(sessionmaker(db), trusted_wallet_rpc=WatchOnlyWallet(), now=NOW)
    assert len(results) == 2 and all(not r.grants_full for r in results)
    assert _counts(db) == (2, 1, 2)
    assert (
        recover_authenticated_sponsored_imports(sessionmaker(db), trusted_wallet_rpc=WatchOnlyWallet(), now=NOW) == ()
    )


@pytest.mark.parametrize("wallet", [WatchOnlyWallet(()), WatchOnlyWallet(include_address=False)])
def test_intent_alone_or_partial_core_import_cannot_be_recovered(db, wallet):
    _prepare(db, EARLY)
    assert recover_authenticated_sponsored_imports(sessionmaker(db), trusted_wallet_rpc=wallet, now=NOW) == ()
    assert _counts(db) == (1, 0, 0)


def test_private_key_wallet_is_refused(db):
    _prepare(db, EARLY)
    with pytest.raises(AutomaticSponsoredImportUnavailable):
        recover_authenticated_sponsored_imports(
            sessionmaker(db), trusted_wallet_rpc=WatchOnlyWallet(private_keys=True), now=NOW
        )
    assert _counts(db) == (1, 0, 0)


def test_revoked_sponsor_and_expired_intents_cannot_be_recovered(db):
    _prepare(db, EARLY)
    with db.begin() as connection:
        connection.execute(text("UPDATE public.current_entitlement_evidence SET revoked_at=created_at"))
    with pytest.raises(AutomaticSponsoredImportUnavailable):
        recover_authenticated_sponsored_imports(sessionmaker(db), trusted_wallet_rpc=WatchOnlyWallet(), now=NOW)
    assert (
        recover_authenticated_sponsored_imports(
            sessionmaker(db), trusted_wallet_rpc=WatchOnlyWallet(), now=NOW + timedelta(days=8)
        )
        == ()
    )
    assert _counts(db) == (1, 0, 0)


def test_provenance_is_immutable_and_public_has_no_grants(db):
    _prepare(db, EARLY)
    for operation in (
        "UPDATE public.canonical_auto_import_intents_v1 SET sponsor_depth=1",
        "DELETE FROM public.canonical_auto_import_intents_v1",
    ):
        with pytest.raises(DBAPIError), db.begin() as connection:
            connection.execute(text(operation))
    with db.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM information_schema.table_privileges WHERE "
                    "grantee='PUBLIC' AND table_name=ANY(:names)"
                ),
                {"names": list(TABLES)},
            ).scalar_one()
            == 0
        )


def test_missing_prerequisite_migration_rolls_back_without_damaging_existing_schema(db):
    _prepare(db, EARLY)
    with pytest.raises(DBAPIError), db.begin() as connection:
        for name in TABLES:
            connection.exec_driver_sql("DROP TABLE public." + name)
        connection.exec_driver_sql("DROP FUNCTION public.reject_canonical_auto_import_mutation_v1()")
        connection.exec_driver_sql(MIGRATIONS[1].read_text(), execution_options={"no_parameters": True})
    assert _counts(db) == (1, 0, 0)


def test_runtime_role_can_append_but_cannot_mutate_history_or_own_schema(db):
    _prepare(db, EARLY)
    with db.begin() as connection:
        connection.exec_driver_sql(
            "CREATE ROLE canon_auto_runtime_588 NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT"
        )
        connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO canon_auto_runtime_588")
        connection.exec_driver_sql(
            "GRANT SELECT,INSERT ON public.canonical_auto_import_intents_v1 TO canon_auto_runtime_588"
        )
    try:
        for sql in (
            "UPDATE public.canonical_auto_import_intents_v1 SET sponsor_depth=1",
            "DELETE FROM public.canonical_auto_import_intents_v1",
            "TRUNCATE public.canonical_auto_import_intents_v1",
            "ALTER TABLE public.canonical_auto_import_intents_v1 DISABLE TRIGGER ALL",
        ):
            with pytest.raises(DBAPIError), db.begin() as connection:
                connection.exec_driver_sql("SET LOCAL ROLE canon_auto_runtime_588")
                connection.exec_driver_sql(sql)
        with db.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE canon_auto_runtime_588")
            assert (
                connection.execute(text("SELECT count(*) FROM public.canonical_auto_import_intents_v1")).scalar_one()
                == 1
            )
            connection.exec_driver_sql(
                "INSERT INTO public.canonical_auto_import_intents_v1 "
                "SELECT '00000000-0000-4000-8000-000000000588'::uuid, sponsor_xonly_pubkey, "
                "script_sha256,script_hex,sponsor_depth,sponsor_evidence_id,sponsor_evidence_sha256,"
                "authorized_at,recover_until FROM public.canonical_auto_import_intents_v1 LIMIT 1"
            )
            assert (
                connection.execute(text("SELECT count(*) FROM public.canonical_auto_import_intents_v1")).scalar_one()
                == 2
            )
    finally:
        with db.begin() as connection:
            connection.exec_driver_sql("DROP OWNED BY canon_auto_runtime_588")
            connection.exec_driver_sql("DROP ROLE canon_auto_runtime_588")

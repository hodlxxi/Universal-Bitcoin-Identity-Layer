"""Disposable PostgreSQL integration for the dormant Canon V2 nonce ledger.

These tests must run only against an isolated CI Postgres database.
No production DB or runtime services are connected, and no role is granted.
"""

from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.services.canonical_admission_consent_challenge_storage_v2 import (
    CanonicalAdmissionChallengeReplayV2,
    SqlAlchemyCanonicalAdmissionChallengeLedgerV2,
)
from app.services.canonical_admission_consent_v2 import canonical_admission_consent_message_v2
from app.utils import derive_legacy_address_from_pubkey
from tests.unit.test_canonical_admission_consent_v2 import CHILD_SIG, SPONSOR_SIG, StrictRpc
from tests.unit.test_canonical_admission_proposal_v2 import ALICE, BOB, NOW, _make

TABLE = "public.canonical_admission_consent_challenges_v2"
MIGRATION = Path("migrations/2026-11-13_canonical_admission_consent_challenge_v2.sql")


@pytest.fixture(scope="module")
def postgres_engine():
    import os

    url = os.environ.get("CANON_V2_TEST_DATABASE_URL")
    if not url or os.environ.get("CANON_V2_DISPOSABLE_PG_ACK") != "1":
        pytest.skip("Explicit disposable PostgreSQL URL and acknowledgement required")
    parsed = make_url(url)
    if (
        parsed.drivername != "postgresql+psycopg2"
        or parsed.host not in ("localhost", "127.0.0.1")
        or parsed.database != "canonv2test"
        or parsed.username != "canonv2test"
        or parsed.port != 5432
    ):
        raise RuntimeError("refuse_non_disposable_postgres_target")
    engine = create_engine(url, future=True, pool_pre_ping=True)
    created = False
    try:
        # SQLAlchemy must own the complete DDL transaction. A raw DBAPI
        # cursor followed by SQLAlchemy Connection.commit() did not make
        # the CREATE TABLE visible to the next test connection.
        with engine.begin() as connection:
            existing = connection.execute(
                text("SELECT to_regclass('public.canonical_admission_consent_challenges_v2')")
            ).scalar_one()
            if existing is not None:
                raise RuntimeError("disposable_test_database_must_be_empty")
            # psycopg2 supports the complete migration, including $$ plpgsql
            # function bodies, as one driver SQL command in this transaction.
            connection.exec_driver_sql(MIGRATION.read_text())
        created = True
        yield engine
    finally:
        try:
            # On a refused preexisting table or failed DDL transaction,
            # NEVER drop anything that this fixture did not create.
            if created:
                with engine.begin() as connection:
                    connection.execute(
                        text("DROP TABLE IF EXISTS public.canonical_admission_consent_challenges_v2")
                    )
                    connection.execute(
                        text("DROP FUNCTION IF EXISTS public.guard_canonical_admission_consent_challenge_v2()")
                    )
        finally:
            engine.dispose()

@pytest.fixture
def clean_ledger(postgres_engine):
    with postgres_engine.begin() as conn:
        conn.execute(text(f"TRUNCATE TABLE {TABLE}"))
    return postgres_engine


def _rpc(pending):
    sponsor = (
        derive_legacy_address_from_pubkey(ALICE),
        SPONSOR_SIG,
        canonical_admission_consent_message_v2(pending.challenge, role="sponsor"),
    )
    child = (
        derive_legacy_address_from_pubkey(BOB),
        CHILD_SIG,
        canonical_admission_consent_message_v2(pending.challenge, role="child"),
    )
    return StrictRpc((sponsor, child))


def _issue(engine, proposal):
    with Session(engine) as session:
        with session.begin():
            ledger = SqlAlchemyCanonicalAdmissionChallengeLedgerV2(session, clock=lambda: NOW)
            pending = ledger.issue(proposal, authenticated_sponsor_pubkey=ALICE)
            assert not pending.durable and not pending.grants_full
    return pending


def _consume(engine, proposal, pending):
    rpc = _rpc(pending)
    with Session(engine) as session:
        with session.begin():
            ledger = SqlAlchemyCanonicalAdmissionChallengeLedgerV2(session, clock=lambda: NOW)
            result = ledger.consume(
                proposal,
                challenge_sha256=pending.challenge_sha256,
                authenticated_child_pubkey=BOB,
                sponsor_signature=SPONSOR_SIG,
                child_signature=CHILD_SIG,
                rpc=rpc,
            )
            assert not result.replay_protected and not result.grants_full
    return result, rpc


def test_postgres_issued_challenge_survives_commit_and_consumes_exactly_once(clean_ledger):
    proposal, _, _ = _make()
    pending = _issue(clean_ledger, proposal)
    with clean_ledger.connect() as conn:
        row = conn.execute(
            text(f"SELECT nonce_hex, consumed_at FROM {TABLE} WHERE challenge_sha256=:sha"),
            {"sha": pending.challenge_sha256},
        ).one()
        assert row.nonce_hex == pending.challenge.nonce_hex
        assert row.consumed_at is None

    consumed, rpc = _consume(clean_ledger, proposal, pending)
    assert consumed.challenge_sha256 == pending.challenge_sha256
    assert len(rpc.calls) == 2
    with clean_ledger.connect() as conn:
        row = conn.execute(
            text(f"SELECT consumed_at, verification_sha256 FROM {TABLE} WHERE challenge_sha256=:sha"),
            {"sha": pending.challenge_sha256},
        ).one()
        assert row.consumed_at is not None
        assert row.verification_sha256 == consumed.verification_sha256

    with pytest.raises(CanonicalAdmissionChallengeReplayV2, match="not_issued_or_already_consumed"):
        _consume(clean_ledger, proposal, pending)


def test_real_postgres_transaction_rollback_does_not_consume_nonce(clean_ledger):
    proposal, _, _ = _make()
    pending = _issue(clean_ledger, proposal)
    with Session(clean_ledger) as session:
        with pytest.raises(RuntimeError, match="simulate_rollback"):
            with session.begin():
                ledger = SqlAlchemyCanonicalAdmissionChallengeLedgerV2(session, clock=lambda: NOW)
                result = ledger.consume(
                    proposal,
                    challenge_sha256=pending.challenge_sha256,
                    authenticated_child_pubkey=BOB,
                    sponsor_signature=SPONSOR_SIG,
                    child_signature=CHILD_SIG,
                    rpc=_rpc(pending),
                )
                assert not result.replay_protected
                raise RuntimeError("simulate_rollback")
    with clean_ledger.connect() as conn:
        assert (
            conn.execute(
                text(f"SELECT consumed_at FROM {TABLE} WHERE challenge_sha256=:sha"),
                {"sha": pending.challenge_sha256},
            ).scalar_one()
            is None
        )
    _consume(clean_ledger, proposal, pending)


def test_postgres_trigger_rejects_rewrite_second_consumption_and_deletion(clean_ledger):
    proposal, _, _ = _make()
    pending = _issue(clean_ledger, proposal)
    _consume(clean_ledger, proposal, pending)
    sha = pending.challenge_sha256
    mutations = (
        (f"UPDATE {TABLE} SET consumed_at=consumed_at WHERE challenge_sha256=:sha",),
        (f"UPDATE {TABLE} SET nonce_hex=:nonce WHERE challenge_sha256=:sha",),
        (f"DELETE FROM {TABLE} WHERE challenge_sha256=:sha",),
    )
    for (sql,) in mutations:
        with pytest.raises(DBAPIError):
            with clean_ledger.begin() as conn:
                conn.execute(text(sql), {"sha": sha, "nonce": "0" * 64})
    with clean_ledger.connect() as conn:
        assert (
            conn.execute(
                text(f"SELECT count(*) FROM {TABLE} WHERE challenge_sha256=:sha"),
                {"sha": sha},
            ).scalar_one()
            == 1
        )


def test_postgres_unique_nonce_and_immutable_issuer_constraints(clean_ledger):
    proposal, _, _ = _make()
    pending = _issue(clean_ledger, proposal)
    with pytest.raises(IntegrityError):
        with clean_ledger.begin() as conn:
            conn.execute(
                text(
                    f"INSERT INTO {TABLE} (challenge_sha256, proposal_sha256, nonce_hex, "
                    "sponsor_compressed_pubkey, child_compressed_pubkey, issuer_session_pubkey, "
                    "issued_at, expires_at) VALUES "
                    "(:sha, :proposal, :nonce, :sponsor, :child, :sponsor, :start, :end)"
                ),
                {
                    "sha": "e" * 64,
                    "proposal": pending.challenge.proposal_sha256,
                    "nonce": pending.challenge.nonce_hex,
                    "sponsor": ALICE,
                    "child": BOB,
                    "start": pending.challenge.issued_at,
                    "end": pending.challenge.expires_at,
                },
            )
    with pytest.raises(DBAPIError):
        with clean_ledger.begin() as conn:
            conn.execute(
                text(f"UPDATE {TABLE} SET issuer_session_pubkey=:child WHERE challenge_sha256=:sha"),
                {"child": BOB, "sha": pending.challenge_sha256},
            )


def test_postgres_unconsumed_issuance_is_not_entitlement(clean_ledger):
    proposal, _, _ = _make()
    pending = _issue(clean_ledger, proposal)
    assert pending.grants_full is False
    assert pending.durable is False
    # A committed ledger row has no authorization or entitlement columns.
    with clean_ledger.connect() as conn:
        columns = {
            row.column_name
            for row in conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema='public' AND table_name='canonical_admission_consent_challenges_v2'"
                )
            )
        }
    assert not (columns & {"full", "access_level", "current_entitlement", "role"})

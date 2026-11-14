"""Isolated PostgreSQL 16 tests of multileg 3+2 consent issuance and replay.

Do NOT execute against a non-disposable database. Bitcoin signatures are
strict synthetic RPC fixtures, not cryptographic evidence from Bitcoin Core.
"""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.services.canonical_multileg_consent_storage_v2 import (
    MultiLegConsentReplayV2,
    SqlAlchemyMultiLegConsentLedgerV2,
)
from app.services.canonical_multi_outpoint_admission_proposal_v2 import (
    create_canonical_multi_outpoint_admission_proposal_v2,
)
from tests.unit.test_canonical_admission_consent_v2 import CHILD_SIG, SPONSOR_SIG
from tests.unit.test_canonical_admission_proposal_v2 import ALICE, BOB, NOW, _genesis, _make
from tests.unit.test_canonical_multi_outpoint_admission_proposal_v2 import (
    _new,
    _rpc,
)
from tests.unit.test_canonical_multi_outpoint_mirror_v2 import _observation

TABLE = "public.canonical_multileg_consent_challenges_v2"
MIGRATION = Path("migrations/2026-11-13_canonical_multileg_consent_challenge_v2.sql")


@pytest.fixture(scope="module")
def pg_engine():
    import os

    url = os.environ.get("CANON_V2_TEST_DATABASE_URL")
    if not url or os.environ.get("CANON_V2_DISPOSABLE_PG_ACK") != "1":
        pytest.skip("explicit disposable Postgres environment required")
    parsed = make_url(url)
    if (
        parsed.drivername != "postgresql+psycopg2"
        or parsed.host not in ("localhost", "127.0.0.1")
        or parsed.port != 5432
        or parsed.username != "canonv2test"
        or parsed.database != "canonv2test"
    ):
        raise RuntimeError("refuse_non_disposable_postgres_target")

    engine = create_engine(url, future=True, pool_pre_ping=True)
    created = False
    try:
        with engine.begin() as connection:
            rows = connection.execute(
                text("SELECT to_regclass('public.canonical_multileg_consent_challenges_v2')")
            ).scalar_one()
            if rows is not None:
                raise RuntimeError("disposable_test_database_must_be_empty")
            connection.exec_driver_sql(MIGRATION.read_text())
        created = True
        yield engine
    finally:
        try:
            # Never drop a pre-existing table or a table from failed DDL.
            if created:
                with engine.begin() as connection:
                    connection.execute(text(f"DROP TABLE {TABLE}"))
                    connection.execute(text("DROP FUNCTION public.guard_canonical_multileg_consent_challenge_v2()"))
        finally:
            engine.dispose()


@pytest.fixture
def clean(pg_engine):
    with pg_engine.begin() as connection:
        connection.execute(text(f"TRUNCATE TABLE {TABLE}"))
    return pg_engine


def _issue(engine, proposal=None, *, sponsor=ALICE, now=NOW):
    proposal = _new() if proposal is None else proposal
    with Session(engine) as session:
        with session.begin():
            pending = SqlAlchemyMultiLegConsentLedgerV2(session, clock=lambda: now).issue(
                proposal, authenticated_sponsor_pubkey=sponsor
            )
            assert not pending.durable and not pending.grants_full
            return pending


def _consume(
    engine,
    proposal,
    pending,
    *,
    child=BOB,
    now=NOW,
    rpc=None,
    rollback=False,
):
    with Session(engine) as session:
        with session.begin():
            result = SqlAlchemyMultiLegConsentLedgerV2(session, clock=lambda: now).consume(
                proposal,
                challenge_sha256=pending.challenge_sha256,
                authenticated_child_pubkey=child,
                sponsor_signature=SPONSOR_SIG,
                child_signature=CHILD_SIG,
                rpc=_rpc(proposal, pending.challenge) if rpc is None else rpc,
            )
            assert not result.replay_protected and not result.grants_full and not result.is_effective
            if rollback:
                raise RuntimeError("force_transaction_rollback")
            return result


def _row(engine, pending):
    with engine.connect() as connection:
        return (
            connection.execute(
                text(f"SELECT * FROM {TABLE} WHERE challenge_sha256=:digest"),
                {"digest": pending.challenge_sha256},
            )
            .mappings()
            .one()
        )


def test_postgresql_issues_exact_five_output_digest_and_consumes_once(clean):
    proposal = _new()
    assert len(proposal.mirror.outpoints) == 5
    pending = _issue(clean, proposal)
    row = _row(clean, pending)
    assert row["proposal_schema"] == proposal.schema
    assert row["proposal_sha256"] == pending.challenge.proposal_sha256
    assert row["issuer_session_pubkey"] == ALICE
    assert row["nonce_hex"] == pending.challenge.nonce_hex
    assert row["consumed_at"] is None
    result = _consume(clean, proposal, pending)
    assert result.challenge_sha256 == pending.challenge_sha256
    assert _row(clean, pending)["verification_sha256"] == result.verification_sha256
    assert _row(clean, pending)["consumed_at"] is not None
    with pytest.raises(MultiLegConsentReplayV2, match="missing_or_already_consumed"):
        _consume(clean, proposal, pending)


def test_postgresql_rollback_restores_exactly_one_available_nonce(clean):
    proposal = _new()
    pending = _issue(clean, proposal)
    with pytest.raises(RuntimeError, match="force_transaction_rollback"):
        _consume(clean, proposal, pending, rollback=True)
    assert _row(clean, pending)["consumed_at"] is None
    _consume(clean, proposal, pending)
    with pytest.raises(MultiLegConsentReplayV2):
        _consume(clean, proposal, pending)


def test_altered_single_amount_after_issuance_invalidates_consent(clean):
    proposal = _new()
    pending = _issue(clean, proposal)
    first = proposal.mirror.outpoints[0]
    mirror = replace(
        proposal.mirror,
        outpoints=(replace(first, amount_sats=first.amount_sats + 1), *proposal.mirror.outpoints[1:]),
    )
    # The updated 3+2 proposal remains structurally valid but has a
    # DIFFERENT hash and requires fresh dual-signature consent.
    changed = create_canonical_multi_outpoint_admission_proposal_v2(
        proposal_id=proposal.proposal_id,
        proposed_at=NOW,
        mirror=mirror,
        observation=_observation(mirror),
        sponsor_basis=_genesis(),
        sponsor_import_reference_sha256="1" * 64,
        sponsor_key_proof_reference_sha256="2" * 64,
        child_acceptance_reference_sha256="3" * 64,
    )
    with pytest.raises(MultiLegConsentReplayV2, match="stored_proposal_or_issuer_binding"):
        _consume(clean, changed, pending)
    assert _row(clean, pending)["consumed_at"] is None


def test_refuses_legacy_two_output_proposal_and_wrong_issuer(clean):
    old, _, _ = _make()
    with Session(clean) as session:
        with session.begin():
            ledger = SqlAlchemyMultiLegConsentLedgerV2(session, clock=lambda: NOW)
            with pytest.raises(MultiLegConsentReplayV2, match="multileg_proposal_type_required"):
                ledger.issue(old, authenticated_sponsor_pubkey=ALICE)
    with Session(clean) as session:
        with session.begin():
            ledger = SqlAlchemyMultiLegConsentLedgerV2(session, clock=lambda: NOW)
            with pytest.raises(MultiLegConsentReplayV2, match="issuer_not_sponsor"):
                ledger.issue(_new(), authenticated_sponsor_pubkey=BOB)
    with clean.connect() as connection:
        assert connection.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar_one() == 0


def test_wrong_child_cannot_consume_and_preserves_challenge(clean):
    proposal = _new()
    pending = _issue(clean, proposal)
    with pytest.raises(MultiLegConsentReplayV2, match="consumer_not_child"):
        _consume(clean, proposal, pending, child=ALICE)
    assert _row(clean, pending)["consumed_at"] is None
    _consume(clean, proposal, pending)


def test_expired_nonce_never_consumes_and_wrong_rpc_never_consumes(clean):
    proposal = _new()
    pending = _issue(clean, proposal)
    with pytest.raises(Exception):
        _consume(clean, proposal, pending, now=NOW + timedelta(seconds=300))
    assert _row(clean, pending)["consumed_at"] is None

    class BadRpc:
        def verifymessage(self, *_):
            return False

    with pytest.raises(Exception):
        _consume(clean, proposal, pending, rpc=BadRpc())
    assert _row(clean, pending)["consumed_at"] is None


def test_postgres_trigger_forbids_issuer_rewrite_deletion_and_replay(clean):
    proposal = _new()
    pending = _issue(clean, proposal)
    for statement in (
        f"UPDATE {TABLE} SET issuer_session_pubkey=:child WHERE challenge_sha256=:digest",
        f"UPDATE {TABLE} SET nonce_hex=:nonce WHERE challenge_sha256=:digest",
        f"DELETE FROM {TABLE} WHERE challenge_sha256=:digest",
    ):
        with pytest.raises(DBAPIError):
            with clean.begin() as connection:
                connection.execute(
                    text(statement),
                    {"child": BOB, "nonce": "0" * 64, "digest": pending.challenge_sha256},
                )
    assert _row(clean, pending)["consumed_at"] is None
    _consume(clean, proposal, pending)
    with pytest.raises(DBAPIError):
        with clean.begin() as connection:
            connection.execute(
                text(f"UPDATE {TABLE} SET consumed_at=consumed_at WHERE challenge_sha256=:digest"),
                {"digest": pending.challenge_sha256},
            )


def test_db_prevents_duplicate_nonce_and_reused_receipt(clean):
    proposal = _new()
    pending = _issue(clean, proposal)
    with pytest.raises(IntegrityError):
        with clean.begin() as connection:
            connection.execute(
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
                    "start": NOW,
                    "end": NOW + timedelta(seconds=300),
                },
            )
    assert _row(clean, pending)["nonce_hex"] == pending.challenge.nonce_hex


def test_issued_or_consumed_row_is_not_full_entitlement(clean):
    proposal = _new()
    pending = _issue(clean, proposal)
    _consume(clean, proposal, pending)
    with clean.connect() as connection:
        columns = {
            x.column_name
            for x in connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema='public' AND table_name='canonical_multileg_consent_challenges_v2'"
                )
            )
        }
    assert columns.isdisjoint({"full", "access_level", "current_entitlement", "role", "effective_at"})

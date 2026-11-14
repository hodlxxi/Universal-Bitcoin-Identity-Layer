"""Real isolated PostgreSQL 16 tests for proposed-only atomic multileg intake.

Only the strict disposable CANON_V2_TEST_DATABASE_URL is accepted.
Test signatures are validated by a synthetic StrictRpc stub, not Bitcoin Core.
No Runtime, production database, live roles or migration are touched.
"""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.models import CurrentEntitlementEvidence, User
from app.services.canonical_multileg_candidate_registry_v2 import (
    CanonicalMultiLegCandidateUnavailableV2,
    SqlAlchemyCanonicalMultiLegCandidateRegistryV2,
)
from app.services.canonical_multileg_consent_storage_v2 import (
    SqlAlchemyMultiLegConsentLedgerV2,
)
from app.services.canonical_multi_outpoint_mirror_v2 import (
    create_canonical_multi_outpoint_mirror_v2,
)
from app.services.trusted_covenant_registration import trusted_outpoints_from_registration
from tests.integration.test_canonical_admission_candidate_postgres_v2 import _seed_full
from tests.unit.test_canonical_admission_consent_v2 import CHILD_SIG, SPONSOR_SIG
from tests.unit.test_canonical_admission_proposal_v2 import (
    ALICE,
    BOB,
    CHARLIE,
    NOW,
    _genesis,
    _sources,
)
from tests.unit.test_canonical_multi_outpoint_admission_proposal_v2 import (
    CHILD_ID,
    _new,
    _rpc,
)
from tests.unit.test_canonical_multi_outpoint_mirror_v2 import _observation

CANDIDATES = "public.canonical_multileg_admission_candidates_v2"
OUTPOINTS = "public.canonical_multileg_candidate_outpoints_v2"
NONCES = "public.canonical_multileg_consent_challenges_v2"
MIGRATIONS = (
    Path("migrations/2026-11-13_canonical_multileg_consent_challenge_v2.sql"),
    Path("migrations/2026-11-13_canonical_multileg_admission_candidates_v2.sql"),
)


@pytest.fixture(scope="module")
def postgres_engine():
    import os

    url = os.environ.get("CANON_V2_TEST_DATABASE_URL")
    if not url or os.environ.get("CANON_V2_DISPOSABLE_PG_ACK") != "1":
        pytest.skip("Disposable PostgreSQL and explicit acknowledgement required")
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
            existing = (
                "users",
                "current_entitlement_evidence",
                "canonical_multileg_admission_candidates_v2",
                "canonical_multileg_candidate_outpoints_v2",
                "canonical_multileg_consent_challenges_v2",
            )
            for name in existing:
                if (
                    connection.execute(text("SELECT to_regclass(:table)"), {"table": "public." + name}).scalar_one()
                    is not None
                ):
                    raise RuntimeError("disposable_test_database_must_be_empty")
            User.__table__.create(bind=connection)
            CurrentEntitlementEvidence.__table__.create(bind=connection)
            for migration in MIGRATIONS:
                connection.exec_driver_sql(migration.read_text())
        created = True
        yield engine
    finally:
        try:
            if created:
                with engine.begin() as connection:
                    connection.execute(text(f"DROP TABLE {OUTPOINTS}"))
                    connection.execute(text(f"DROP TABLE {CANDIDATES}"))
                    connection.execute(text(f"DROP TABLE {NONCES}"))
                    connection.execute(text("DROP FUNCTION public.validate_canonical_multileg_candidate_v2()"))
                    connection.execute(text("DROP FUNCTION public.guard_canonical_multileg_candidate_immutable_v2()"))
                    connection.execute(text("DROP FUNCTION public.guard_canonical_multileg_consent_challenge_v2()"))
                    CurrentEntitlementEvidence.__table__.drop(bind=connection)
                    User.__table__.drop(bind=connection)
        finally:
            engine.dispose()


@pytest.fixture
def db(postgres_engine):
    with postgres_engine.begin() as conn:
        conn.execute(text(f"TRUNCATE TABLE {OUTPOINTS}, {CANDIDATES}, {NONCES} CASCADE"))
        conn.execute(text("TRUNCATE TABLE current_entitlement_evidence, users CASCADE"))
    return postgres_engine


def _issue(engine, proposal, sponsor=ALICE):
    with Session(engine) as session:
        with session.begin():
            return SqlAlchemyMultiLegConsentLedgerV2(session, clock=lambda: NOW).issue(
                proposal, authenticated_sponsor_pubkey=sponsor
            )


def _reserve(
    engine,
    proposal,
    nonce,
    *,
    basis=None,
    observation=None,
    sponsor=ALICE,
    child=BOB,
    at=NOW,
    rollback=False,
):
    if basis is None:
        basis = _genesis()
    if observation is None:
        observation = _observation(proposal.mirror)
    with Session(engine) as session:
        with session.begin():
            result = SqlAlchemyCanonicalMultiLegCandidateRegistryV2(
                session, clock=lambda: at
            ).reserve_candidate_in_transaction(
                proposal,
                sponsor_basis=basis,
                current_observation=observation,
                authenticated_sponsor_pubkey=sponsor,
                authenticated_child_pubkey=child,
                challenge_sha256=nonce.challenge_sha256,
                sponsor_signature=SPONSOR_SIG,
                child_signature=CHILD_SIG,
                bitcoin_message_rpc=_rpc(proposal, nonce.challenge),
            )
            assert not result.durable
            assert not result.grants_full
            assert not result.is_effective
            if rollback:
                raise RuntimeError("simulate_transaction_rollback")
            return result


def _counts(engine):
    with engine.connect() as conn:
        return (
            conn.execute(text(f"SELECT count(*) FROM {CANDIDATES}")).scalar_one(),
            conn.execute(text(f"SELECT count(*) FROM {OUTPOINTS}")).scalar_one(),
        )


def _nonce_consumed(engine, nonce):
    with engine.connect() as conn:
        return conn.execute(
            text(f"SELECT consumed_at FROM {NONCES} WHERE challenge_sha256=:sha"),
            {"sha": nonce.challenge_sha256},
        ).scalar_one()


def _child(parent):
    policy, registration, _, snapshot, _ = _sources(sponsor=BOB, child=CHARLIE, depth=1)
    mirror = create_canonical_multi_outpoint_mirror_v2(policy, trusted_outpoints_from_registration(registration))
    return _new(mirror, basis=parent, proposal_id=CHILD_ID, observation=snapshot), snapshot


def test_root_three_plus_two_candidate_commits_exactly_five_and_trust_ceiling(db):
    proposal = _new()
    _seed_full(db, ALICE)
    nonce = _issue(db, proposal)
    result = _reserve(db, proposal, nonce)
    assert result.outpoint_count == 5
    assert (result.earlier_sats, result.later_sats, result.trust_ceiling_sats) == (300000, 300000, 300000)
    assert result.proposal_sha256 == nonce.challenge.proposal_sha256
    assert _counts(db) == (1, 5)
    assert _nonce_consumed(db, nonce) is not None
    with db.connect() as conn:
        header = conn.execute(text(f"SELECT * FROM {CANDIDATES}")).mappings().one()
        legs = conn.execute(text(f"SELECT leg_order, amount_sats FROM {OUTPOINTS}")).all()
    assert header["state"] == "candidate_only_no_full"
    assert header["outpoint_count"] == 5
    assert header["trust_ceiling_sats"] == 300000
    assert sum(amount for leg, amount in legs if leg == "earlier") == 300000
    assert sum(amount for leg, amount in legs if leg == "later") == 300000


def test_roll_back_candidate_five_utxos_and_nonce_in_same_transaction(db):
    proposal = _new()
    _seed_full(db, ALICE)
    nonce = _issue(db, proposal)
    with pytest.raises(RuntimeError, match="simulate_transaction_rollback"):
        _reserve(db, proposal, nonce, rollback=True)
    assert _counts(db) == (0, 0)
    assert _nonce_consumed(db, nonce) is None
    _reserve(db, proposal, nonce)
    assert _counts(db) == (1, 5)


def test_deferred_database_trigger_refuses_header_without_all_outputs(db):
    """Making the deferred completeness gate IMMEDIATE prevents partial inserts."""
    proposal = _new()
    _seed_full(db, ALICE)
    nonce = _issue(db, proposal)
    with pytest.raises(CanonicalMultiLegCandidateUnavailableV2, match="candidate_conflict_or_incomplete"):
        with Session(db) as session:
            with session.begin():
                session.execute(text("SET CONSTRAINTS trg_cmlac_complete IMMEDIATE"))
                SqlAlchemyCanonicalMultiLegCandidateRegistryV2(session, clock=lambda: NOW).reserve_candidate_in_transaction(
                    proposal,
                    sponsor_basis=_genesis(),
                    current_observation=_observation(proposal.mirror),
                    authenticated_sponsor_pubkey=ALICE,
                    authenticated_child_pubkey=BOB,
                    challenge_sha256=nonce.challenge_sha256,
                    sponsor_signature=SPONSOR_SIG,
                    child_signature=CHILD_SIG,
                    bitcoin_message_rpc=_rpc(proposal, nonce.challenge),
                )
    assert _counts(db) == (0, 0)
    assert _nonce_consumed(db, nonce) is None
    _reserve(db, proposal, nonce)
    assert _counts(db) == (1, 5)


def test_no_sponsor_current_full_never_consumes_or_registers(db):
    proposal = _new()
    nonce = _issue(db, proposal)
    with pytest.raises(CanonicalMultiLegCandidateUnavailableV2, match="current_sponsor_full_required"):
        _reserve(db, proposal, nonce)
    assert _counts(db) == (0, 0)
    assert _nonce_consumed(db, nonce) is None


def test_wrong_authenticated_sponsor_or_child_rejected_without_nonce_use(db):
    proposal = _new()
    _seed_full(db, ALICE)
    nonce = _issue(db, proposal)
    for sponsor, child in ((BOB, BOB), (ALICE, ALICE)):
        with pytest.raises(CanonicalMultiLegCandidateUnavailableV2, match="session_identity_mismatch"):
            _reserve(db, proposal, nonce, sponsor=sponsor, child=child)
    assert _nonce_consumed(db, nonce) is None
    assert _counts(db) == (0, 0)


def test_duplicate_child_cannot_use_a_second_valid_nonce_or_proposal(db):
    proposal = _new()
    _seed_full(db, ALICE)
    nonce = _issue(db, proposal)
    _reserve(db, proposal, nonce)
    alternate = replace(proposal, proposal_id="00000000-0000-4000-8000-000000000099")
    second_nonce = _issue(db, alternate)
    with pytest.raises(CanonicalMultiLegCandidateUnavailableV2, match="candidate_conflict_or_incomplete"):
        _reserve(db, alternate, second_nonce)
    assert _counts(db) == (1, 5)
    assert _nonce_consumed(db, second_nonce) is None


def test_existing_child_proposal_requires_independent_full_not_just_parent_candidate(db):
    parent = _new()
    child, observation = _child(parent)
    _seed_full(db, ALICE)
    first_nonce = _issue(db, parent)
    _reserve(db, parent, first_nonce)
    second_nonce = _issue(db, child, BOB)
    with pytest.raises(CanonicalMultiLegCandidateUnavailableV2, match="current_sponsor_full_required"):
        _reserve(db, child, second_nonce, basis=parent, observation=observation, sponsor=BOB, child=CHARLIE)
    assert _counts(db) == (1, 5)
    assert _nonce_consumed(db, second_nonce) is None


def test_bob_current_full_makes_charlie_candidate_possible_but_not_effective(db):
    parent = _new()
    child, observation = _child(parent)
    _seed_full(db, ALICE)
    _seed_full(db, BOB)
    first_nonce = _issue(db, parent)
    _reserve(db, parent, first_nonce)
    second_nonce = _issue(db, child, BOB)
    result = _reserve(db, child, second_nonce, basis=parent, observation=observation, sponsor=BOB, child=CHARLIE)
    assert not result.grants_full
    assert not result.is_effective
    assert _counts(db) == (2, 7)
    with db.connect() as conn:
        rows = conn.execute(
            text(f"SELECT parent_proposal_id FROM {CANDIDATES} WHERE proposal_id=:id"), {"id": child.proposal_id}
        ).one()
    assert rows.parent_proposal_id == parent.proposal_id


def test_parent_proposal_without_registered_candidate_does_not_authorize_reservation(db):
    parent = _new()
    child, observation = _child(parent)
    _seed_full(db, BOB)
    nonce = _issue(db, child, BOB)
    with pytest.raises(CanonicalMultiLegCandidateUnavailableV2, match="parent_candidate_not_matched"):
        _reserve(db, child, nonce, basis=parent, observation=observation, sponsor=BOB, child=CHARLIE)
    assert _nonce_consumed(db, nonce) is None


def test_exact_observation_must_be_current_and_fully_unspent(db):
    proposal = _new()
    _seed_full(db, ALICE)
    nonce = _issue(db, proposal)
    observed = _observation(proposal.mirror)
    first = observed.observations[0]
    changed = replace(observed, observations=(replace(first, unspent=False), *observed.observations[1:]))
    with pytest.raises(CanonicalMultiLegCandidateUnavailableV2, match="multileg_source_not_qualified"):
        _reserve(db, proposal, nonce, observation=changed)
    with pytest.raises(CanonicalMultiLegCandidateUnavailableV2, match="multileg_source_not_qualified"):
        _reserve(db, proposal, nonce, at=NOW + timedelta(seconds=121))
    assert _nonce_consumed(db, nonce) is None


def test_immutable_candidates_and_all_utxo_rows_reject_changes(db):
    proposal = _new()
    _seed_full(db, ALICE)
    nonce = _issue(db, proposal)
    _reserve(db, proposal, nonce)
    queries = (
        f"DELETE FROM {CANDIDATES}",
        f"UPDATE {CANDIDATES} SET state=state",
        f"DELETE FROM {OUTPOINTS}",
        f"UPDATE {OUTPOINTS} SET amount_sats=amount_sats",
    )
    for query in queries:
        with pytest.raises(DBAPIError):
            with db.begin() as conn:
                conn.execute(text(query))
    assert _counts(db) == (1, 5)


def test_database_enforces_global_outpoint_uniqueness(db):
    proposal = _new()
    _seed_full(db, ALICE)
    nonce = _issue(db, proposal)
    _reserve(db, proposal, nonce)
    with db.connect() as conn:
        row = conn.execute(text(f"SELECT * FROM {OUTPOINTS} LIMIT 1")).mappings().one()
    with pytest.raises(IntegrityError):
        with db.begin() as conn:
            conn.execute(
                text(
                    f"INSERT INTO {OUTPOINTS} "
                    "(proposal_id,leg_order,txid,vout,amount_sats,script_pubkey_sha256) "
                    "VALUES (:pid,:leg,:txid,:vout,:amt,:script)"
                ),
                {
                    "pid": proposal.proposal_id,
                    "leg": row["leg_order"],
                    "txid": row["txid"],
                    "vout": row["vout"],
                    "amt": row["amount_sats"],
                    "script": row["script_pubkey_sha256"],
                },
            )
    assert _counts(db) == (1, 5)


def test_refuses_sqlite_or_an_unopened_transaction(db):
    from sqlalchemy import create_engine

    sqlite = create_engine("sqlite:///:memory:")
    try:
        with Session(sqlite) as session:
            with session.begin():
                registrar = SqlAlchemyCanonicalMultiLegCandidateRegistryV2(session, clock=lambda: NOW)
                with pytest.raises(
                    CanonicalMultiLegCandidateUnavailableV2, match="read_committed_pg_transaction_required"
                ):
                    registrar.reserve_candidate_in_transaction(
                        _new(),
                        sponsor_basis=_genesis(),
                        current_observation=_observation(_new().mirror),
                        authenticated_sponsor_pubkey=ALICE,
                        authenticated_child_pubkey=BOB,
                        challenge_sha256="0" * 64,
                        sponsor_signature=SPONSOR_SIG,
                        child_signature=CHILD_SIG,
                        bitcoin_message_rpc=object(),
                    )
    finally:
        sqlite.dispose()

"""Disposable PostgreSQL tests for dormant Canon V2 candidate intake.

Strict target guard. NEVER points at Runtime/production DB.
All signatures in tests are synthetically accepted by a fake Bitcoin RPC.
They are not genuine Bitcoin cryptographic attestations.
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
from app.services.action_authorization import IdentityClass
from app.services.canonical_admission_candidate_registry_v2 import (
    CanonicalAdmissionCandidateUnavailableV2,
    SqlAlchemyCanonicalAdmissionCandidateRegistryV2,
)
from app.services.canonical_admission_consent_challenge_storage_v2 import (
    SqlAlchemyCanonicalAdmissionChallengeLedgerV2,
)
from app.services.canonical_admission_consent_v2 import canonical_admission_consent_message_v2
from app.services.canonical_admission_edge_v2 import (
    CanonicalSponsorLineageNodeEvidenceV2,
    create_canonical_admission_edge_v2,
)
from app.services.current_entitlement_evidence import CONTRACT_VERSION
from app.utils import derive_legacy_address_from_pubkey
from tests.unit.test_canonical_admission_consent_v2 import CHILD_SIG, SPONSOR_SIG, StrictRpc
from tests.unit.test_canonical_admission_edge_v2 import _child, _root
from tests.unit.test_canonical_admission_proposal_v2 import ALICE, BOB, CHARLIE, NOW, _genesis

MIGRATIONS = (
    Path("migrations/2026-11-13_canonical_admission_consent_challenge_v2.sql"),
    Path("migrations/2026-11-13_canonical_admission_candidate_registry_v2.sql"),
)
TABLE = "public.canonical_admission_candidates_v2"
LEGS = "public.canonical_admission_candidate_outpoints_v2"
CHALLENGES = "public.canonical_admission_consent_challenges_v2"


@pytest.fixture(scope="module")
def postgres_engine():
    import os

    url = os.getenv("CANON_V2_TEST_DATABASE_URL")
    if not url or os.getenv("CANON_V2_DISPOSABLE_PG_ACK") != "1":
        pytest.skip("Disposable PostgreSQL and explicit acknowledgement required")
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
        with engine.begin() as connection:
            names = (
                "canonical_admission_candidates_v2",
                "canonical_admission_candidate_outpoints_v2",
                "canonical_admission_consent_challenges_v2",
                "users",
                "current_entitlement_evidence",
            )
            for name in names:
                if connection.execute(text("SELECT to_regclass(:table)"), {"table": f"public.{name}"}).scalar_one():
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
                    connection.execute(text(f"DROP TABLE {LEGS}"))
                    connection.execute(text(f"DROP TABLE {TABLE}"))
                    connection.execute(text(f"DROP TABLE {CHALLENGES}"))
                    connection.execute(text("DROP FUNCTION public.guard_canonical_admission_candidate_v2()"))
                    connection.execute(text("DROP FUNCTION public.guard_canonical_admission_consent_challenge_v2()"))
                    CurrentEntitlementEvidence.__table__.drop(bind=connection)
                    User.__table__.drop(bind=connection)
        finally:
            engine.dispose()


@pytest.fixture
def db(postgres_engine):
    with postgres_engine.begin() as conn:
        conn.execute(text(f"TRUNCATE TABLE {LEGS}, {TABLE}, {CHALLENGES} RESTART IDENTITY CASCADE"))
        conn.execute(text("TRUNCATE TABLE current_entitlement_evidence, users RESTART IDENTITY CASCADE"))
    return postgres_engine


def _seed_full(engine, key, *, full=True):
    xonly = key[2:]
    with Session(engine) as session:
        with session.begin():
            session.add(User(pubkey=xonly, is_active=True, metadata_json={}))
            session.add(
                CurrentEntitlementEvidence(
                    evidence_id=("00000000-0000-4000-8000-000000000071" if key == ALICE
                                 else "00000000-0000-4000-8000-000000000072"),
                    contract_version=CONTRACT_VERSION,
                    subject_pubkey=xonly,
                    identity_class=IdentityClass.FULL.value if full else IdentityClass.LIMITED.value,
                    current_full_relation_satisfied=full,
                    evidence_source="disposable_integration_fixture",
                    evidence_version="v1",
                    source_evidence_sha256="f" * 64,
                    observed_at=NOW - timedelta(seconds=20),
                    valid_until=NOW + timedelta(seconds=300),
                    created_at=NOW - timedelta(seconds=1),
                    revoked_at=None,
                )
            )


def _issue(engine, proposal, sponsor):
    with Session(engine) as session:
        with session.begin():
            return SqlAlchemyCanonicalAdmissionChallengeLedgerV2(
                session, clock=lambda: NOW
            ).issue(proposal, authenticated_sponsor_pubkey=sponsor)


def _rpc(pending, sponsor, child):
    message_sponsor = canonical_admission_consent_message_v2(pending.challenge, role="sponsor")
    message_child = canonical_admission_consent_message_v2(pending.challenge, role="child")
    return StrictRpc(
        (
            (derive_legacy_address_from_pubkey(sponsor), SPONSOR_SIG, message_sponsor),
            (derive_legacy_address_from_pubkey(child), CHILD_SIG, message_child),
        )
    )


def _reserve(
    engine,
    node,
    nodes,
    pending,
    *,
    sponsor=ALICE,
    child=BOB,
    now=NOW,
    rollback=False,
):
    with Session(engine) as session:
        with session.begin():
            result = SqlAlchemyCanonicalAdmissionCandidateRegistryV2(
                session, clock=lambda: now
            ).reserve_candidate_in_transaction(
                node.edge,
                nodes=nodes,
                genesis_evaluation=_genesis(),
                authenticated_sponsor_pubkey=sponsor,
                authenticated_child_pubkey=child,
                challenge_sha256=pending.challenge_sha256,
                sponsor_signature=SPONSOR_SIG,
                child_signature=CHILD_SIG,
                bitcoin_message_rpc=_rpc(pending, sponsor, child),
            )
            assert not result.grants_full and not result.is_effective and not result.durable
            if rollback:
                raise RuntimeError("simulate_transaction_rollback")
            return result


def test_signed_alice_bob_candidate_commits_two_anchors_but_no_full(db):
    proposal, node = _root()
    _seed_full(db, ALICE)
    challenge = _issue(db, proposal, ALICE)
    result = _reserve(db, node, (node,), challenge)
    assert result.edge_id == proposal.proposal_id
    assert result.proposal_sha256 == challenge.challenge.proposal_sha256
    with db.connect() as connection:
        rows = connection.execute(text(f"SELECT * FROM {TABLE}")).mappings().all()
        legs = connection.execute(text(f"SELECT * FROM {LEGS}")).mappings().all()
        consumed = connection.execute(text(f"SELECT consumed_at FROM {CHALLENGES}")).scalar_one()
    assert len(rows) == 1
    assert rows[0]["candidate_state"] == "candidate_only_no_full"
    assert rows[0]["sponsor_xonly_pubkey"] == ALICE[2:]
    assert rows[0]["child_xonly_pubkey"] == BOB[2:]
    assert len(legs) == 2
    assert {leg["leg_order"] for leg in legs} == {"earlier", "later"}
    assert {leg["txid"] for leg in legs} == {"a" * 64, "b" * 64}
    assert consumed is not None


def test_exactly_once_nonce_cannot_be_reused_to_insert_candidate(db):
    proposal, node = _root()
    _seed_full(db, ALICE)
    challenge = _issue(db, proposal, ALICE)
    _reserve(db, node, (node,), challenge)
    with pytest.raises(CanonicalAdmissionCandidateUnavailableV2, match="consent_not_consumable"):
        _reserve(db, node, (node,), challenge)
    with db.connect() as connection:
        assert connection.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar_one() == 1
        assert connection.execute(text(f"SELECT count(*) FROM {LEGS}")).scalar_one() == 2


def test_rollback_rewinds_candidate_two_utxos_and_challenge_consumption(db):
    proposal, node = _root()
    _seed_full(db, ALICE)
    challenge = _issue(db, proposal, ALICE)
    with pytest.raises(RuntimeError, match="simulate_transaction_rollback"):
        _reserve(db, node, (node,), challenge, rollback=True)
    with db.connect() as connection:
        assert connection.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar_one() == 0
        assert connection.execute(text(f"SELECT count(*) FROM {LEGS}")).scalar_one() == 0
        assert connection.execute(text(f"SELECT consumed_at FROM {CHALLENGES}")).scalar_one() is None
    _reserve(db, node, (node,), challenge)


@pytest.mark.parametrize("state", ["missing", "limited"])
def test_no_current_sponsor_full_cannot_consume_challenge_or_reserve(db, state):
    proposal, node = _root()
    if state == "limited":
        _seed_full(db, ALICE, full=False)
    challenge = _issue(db, proposal, ALICE)
    with pytest.raises(CanonicalAdmissionCandidateUnavailableV2, match="sponsor_current_full_unavailable"):
        _reserve(db, node, (node,), challenge)
    with db.connect() as connection:
        assert connection.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar_one() == 0
        assert connection.execute(text(f"SELECT consumed_at FROM {CHALLENGES}")).scalar_one() is None


def test_conflicting_child_and_two_shared_utxos_reject_second_signed_candidate(db):
    proposal, node = _root()
    _seed_full(db, ALICE)
    first = _issue(db, proposal, ALICE)
    _reserve(db, node, (node,), first)
    replacement = replace(proposal, proposal_id="00000000-0000-4000-8000-000000000099")
    other_node = CanonicalSponsorLineageNodeEvidenceV2(
        create_canonical_admission_edge_v2(replacement),
        node.registration,
        node.funding_set,
        node.original_observation,
        node.current_observation,
    )
    second = _issue(db, replacement, ALICE)
    with pytest.raises(CanonicalAdmissionCandidateUnavailableV2, match="candidate_conflict_or_write_failed"):
        _reserve(db, other_node, (other_node,), second)
    with db.connect() as connection:
        assert connection.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar_one() == 1
        assert connection.execute(text(f"SELECT count(*) FROM {LEGS}")).scalar_one() == 2
        state = connection.execute(
            text(f"SELECT consumed_at FROM {CHALLENGES} WHERE challenge_sha256=:sha"),
            {"sha": second.challenge_sha256},
        ).scalar_one()
        assert state is None


def test_bob_cannot_sponsor_charlie_without_current_full_even_if_parent_candidate_exists(db):
    parent, root = _root()
    child_proposal, child = _child(parent)
    _seed_full(db, ALICE)
    root_challenge = _issue(db, parent, ALICE)
    _reserve(db, root, (root,), root_challenge)
    second = _issue(db, child_proposal, BOB)
    with pytest.raises(CanonicalAdmissionCandidateUnavailableV2, match="sponsor_current_full_unavailable"):
        _reserve(db, child, (root, child), second, sponsor=BOB, child=CHARLIE)
    with db.connect() as connection:
        assert connection.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar_one() == 1


def test_bob_with_independently_verified_current_full_can_create_structural_charlie_candidate(db):
    parent, root = _root()
    child_proposal, child = _child(parent)
    _seed_full(db, ALICE)
    _seed_full(db, BOB)
    first = _issue(db, parent, ALICE)
    _reserve(db, root, (root,), first)
    second = _issue(db, child_proposal, BOB)
    result = _reserve(db, child, (root, child), second, sponsor=BOB, child=CHARLIE)
    assert result.edge_id == child_proposal.proposal_id
    with db.connect() as connection:
        rows = connection.execute(text(f"SELECT edge_id, parent_edge_id FROM {TABLE}")).all()
        assert set(rows) == {(parent.proposal_id, None), (child_proposal.proposal_id, parent.proposal_id)}
        assert connection.execute(text(f"SELECT count(*) FROM {LEGS}")).scalar_one() == 4
    # The fixture seeds Bob's current Full in independent test-only tables;
    # it does NOT establish a future real Canon V2 admission transition.


def test_immutable_candidate_and_anchors_cannot_be_rewritten_or_deleted(db):
    proposal, node = _root()
    _seed_full(db, ALICE)
    challenge = _issue(db, proposal, ALICE)
    _reserve(db, node, (node,), challenge)
    statements = (
        f"UPDATE {TABLE} SET candidate_state=candidate_state",
        f"DELETE FROM {TABLE}",
        f"UPDATE {LEGS} SET amount_sats=amount_sats",
        f"DELETE FROM {LEGS}",
    )
    for statement in statements:
        with pytest.raises(DBAPIError):
            with db.begin() as connection:
                connection.execute(text(statement))
    with db.connect() as connection:
        assert connection.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar_one() == 1
        assert connection.execute(text(f"SELECT count(*) FROM {LEGS}")).scalar_one() == 2


def test_wrong_authenticated_key_or_sqlite_fail_before_any_new_rights(db):
    proposal, node = _root()
    _seed_full(db, ALICE)
    challenge = _issue(db, proposal, ALICE)
    with pytest.raises(CanonicalAdmissionCandidateUnavailableV2, match="session_identity_mismatch"):
        _reserve(db, node, (node,), challenge, sponsor=BOB)
    with db.connect() as connection:
        assert connection.execute(text(f"SELECT consumed_at FROM {CHALLENGES}")).scalar_one() is None
    sqlite = create_engine("sqlite:///:memory:")
    try:
        with Session(sqlite) as session:
            with session.begin():
                registry = SqlAlchemyCanonicalAdmissionCandidateRegistryV2(session, clock=lambda: NOW)
                with pytest.raises(CanonicalAdmissionCandidateUnavailableV2, match="read_committed_postgres_transaction_required"):
                    registry.reserve_candidate_in_transaction(
                        node.edge,
                        nodes=(node,),
                        genesis_evaluation=_genesis(),
                        authenticated_sponsor_pubkey=ALICE,
                        authenticated_child_pubkey=BOB,
                        challenge_sha256=challenge.challenge_sha256,
                        sponsor_signature=SPONSOR_SIG,
                        child_signature=CHILD_SIG,
                        bitcoin_message_rpc=_rpc(challenge, ALICE, BOB),
                    )
    finally:
        sqlite.dispose()

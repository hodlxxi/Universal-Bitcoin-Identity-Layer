"""Issue #588: disposable PostgreSQL proof of an atomic effective/evidence binding.

Everything here is SYNTHETIC: signatures, Full source, and chain hashes.
No real Bitcoin or user authority is established by these tests.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.models import CurrentEntitlementEvidence, User
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CONTRACT_VERSION
from app.services.canonical_multi_outpoint_admission_proposal_v2 import (
    canonical_multi_outpoint_admission_proposal_v2_sha256,
)
from tests.integration.test_canonical_admission_candidate_postgres_v2 import _seed_full
from tests.integration.test_canonical_global_outpoint_claims_postgres_v2 import (
    shared_pg as global_shared_pg,
)
from tests.integration.test_canonical_multileg_candidate_postgres_v2 import (
    _issue,
    _reserve,
)
from tests.unit.test_canonical_admission_proposal_v2 import ALICE, BOB
from tests.unit.test_canonical_multi_outpoint_admission_proposal_v2 import _new

EFFECTIVE = "public.canonical_multileg_effective_edges_v2"
LIVE = "public.canonical_multileg_live_outpoint_claims_v2"
GLOBAL = "public.canonical_global_outpoint_claims_v2"
MIGRATION = Path("migrations/2026-11-14_canonical_multileg_effective_edge_v2.sql")
FUNCTIONS = (
    "validate_canonical_multileg_effective_edge_v2",
    "guard_canonical_multileg_effective_edge_v2",
    "guard_effective_multileg_claim_release_v2",
)


@pytest.fixture(scope="module")
def effective_engine(global_shared_pg):
    with global_shared_pg.begin() as connection:
        connection.exec_driver_sql(MIGRATION.read_text())
    yield global_shared_pg
    with global_shared_pg.begin() as connection:
        connection.exec_driver_sql(
            "DROP TRIGGER trg_cmev2_protect_live_child "
            "ON public.canonical_multileg_live_child_claims_v2"
        )
        connection.exec_driver_sql(
            "DROP TRIGGER trg_cmev2_protect_live_outpoints "
            "ON public.canonical_multileg_live_outpoint_claims_v2"
        )
        connection.exec_driver_sql(f"DROP TABLE {EFFECTIVE}")
        for name in FUNCTIONS:
            connection.exec_driver_sql(f"DROP FUNCTION public.{name}()")


@pytest.fixture
def db(effective_engine):
    # This is a deliberately disposable test container. NEVER run on live PG.
    with effective_engine.begin() as connection:
        connection.exec_driver_sql(
            "TRUNCATE public.canonical_multileg_effective_edges_v2, "
            "public.canonical_global_outpoint_claims_v2, "
            "public.canonical_admission_candidate_outpoints_v2, "
            "public.canonical_admission_candidates_v2, "
            "public.canonical_admission_consent_challenges_v2, "
            "public.canonical_multileg_candidate_outpoints_v2, "
            "public.canonical_multileg_admission_candidates_v2, "
            "public.canonical_multileg_consent_challenges_v2, "
            "public.current_entitlement_evidence, public.users CASCADE"
        )
    return effective_engine


def _candidate(engine):
    proposal = _new()
    _seed_full(engine, ALICE)
    challenge = _issue(engine, proposal)
    _reserve(engine, proposal, challenge)
    return proposal


def _stamp():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _evidence(session, *, subject=BOB, source="canonical_v2_effective_admission"):
    at = _stamp()
    eid = "00000000-0000-4000-8000-0000000000b2"
    session.add(User(pubkey=subject[2:], is_active=True, metadata_json={}))
    session.add(
        CurrentEntitlementEvidence(
            evidence_id=eid,
            contract_version=CONTRACT_VERSION,
            subject_pubkey=subject[2:],
            identity_class=IdentityClass.FULL.value,
            current_full_relation_satisfied=True,
            evidence_source=source,
            evidence_version="hodlxxi.canon_v2_effective.v1",
            source_evidence_sha256="b" * 64,
            observed_at=at,
            valid_until=at + timedelta(seconds=300),
            created_at=at,
            revoked_at=None,
        )
    )
    session.flush()
    return eid, at


def _params(proposal, evidence_id, observed_at):
    return {
        "id": proposal.proposal_id,
        "sha": canonical_multi_outpoint_admission_proposal_v2_sha256(proposal),
        "sponsor": ALICE[2:],
        "child": BOB[2:],
        "depth": 1,
        "parent": None,
        "eid": evidence_id,
        "evidence_hash": "b" * 64,
        "tip": "c" * 64,
        "sequence": 7,
        "observed": observed_at,
        "effective": observed_at,
    }


INSERT = (
    f"INSERT INTO {EFFECTIVE} (proposal_id, proposal_sha256, "
    "sponsor_xonly_pubkey, child_xonly_pubkey, child_depth, "
    "parent_proposal_id, entitlement_evidence_id, source_evidence_sha256, "
    "checked_tip_hash, checked_mempool_sequence, observed_at, effective_at) "
    "VALUES (:id, :sha, :sponsor, :child, :depth, :parent, :eid, "
    ":evidence_hash, :tip, :sequence, :observed, :effective)"
)


def test_root_effective_and_child_full_are_bound_in_one_commit(db):
    proposal = _candidate(db)
    with Session(db) as session:
        with session.begin():
            eid, at = _evidence(session)
            session.execute(text(INSERT), _params(proposal, eid, at))
    with db.connect() as connection:
        edge = connection.execute(
            text(f"SELECT * FROM {EFFECTIVE}")
        ).mappings().one()
        assert edge["child_xonly_pubkey"] == BOB[2:]
        assert edge["sponsor_xonly_pubkey"] == ALICE[2:]
        assert edge["entitlement_evidence_id"] == eid
        assert connection.execute(
            text(f"SELECT COUNT(*) FROM {GLOBAL}")
        ).scalar_one() == 5


def test_candidate_cannot_be_effective_without_bound_full_evidence(db):
    proposal = _candidate(db)
    with pytest.raises(DBAPIError):
        with db.begin() as connection:
            connection.execute(
                text(INSERT),
                _params(proposal, "00000000-0000-4000-8000-0000000000b2", _stamp()),
            )
    with db.connect() as connection:
        assert connection.execute(text(f"SELECT count(*) FROM {EFFECTIVE}")).scalar_one() == 0


def test_mismatched_subject_does_not_create_effective_status(db):
    proposal = _candidate(db)
    with pytest.raises(DBAPIError):
        with Session(db) as session:
            with session.begin():
                eid, at = _evidence(session, subject=ALICE)
                session.execute(text(INSERT), _params(proposal, eid, at))
    with db.connect() as connection:
        assert connection.execute(text(f"SELECT count(*) FROM {EFFECTIVE}")).scalar_one() == 0


def test_committed_effective_claims_cannot_be_released_or_replayed(db):
    proposal = _candidate(db)
    with Session(db) as session:
        with session.begin():
            eid, at = _evidence(session)
            session.execute(text(INSERT), _params(proposal, eid, at))
    with pytest.raises(DBAPIError):
        with db.begin() as connection:
            connection.execute(text(f"DELETE FROM {LIVE} WHERE proposal_id=:id"), {"id": proposal.proposal_id})
    with pytest.raises(DBAPIError):
        with db.begin() as connection:
            connection.execute(text(f"DELETE FROM {EFFECTIVE}"))
    with pytest.raises(DBAPIError):
        with db.begin() as connection:
            connection.execute(text(INSERT), _params(proposal, eid, at))
    with db.connect() as connection:
        assert connection.execute(text(f"SELECT COUNT(*) FROM {GLOBAL}")).scalar_one() == 5
        assert connection.execute(text(f"SELECT COUNT(*) FROM {EFFECTIVE}")).scalar_one() == 1


def test_stale_full_source_is_rejected_atomically(db):
    proposal = _candidate(db)
    with pytest.raises(DBAPIError):
        with Session(db) as session:
            with session.begin():
                eid, at = _evidence(session, source="disposable_integration_fixture")
                session.execute(text(INSERT), _params(proposal, eid, at))
    with db.connect() as connection:
        assert connection.execute(text(f"SELECT COUNT(*) FROM {EFFECTIVE}")).scalar_one() == 0
        assert connection.execute(text("SELECT COUNT(*) FROM users WHERE pubkey=:key"), {"key": BOB[2:]}).scalar_one() == 0

"""Disposable PostgreSQL 16 lifecycle: audit-preserving expiry of only candidates.

No Full/effective state can be created or revoked. All historical signed
headers/UTXOs survive. A fresh signature + nonce is required for reentry.
Database clock is authoritative for seven-day expiry; no user timestamp.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.models import CurrentEntitlementEvidence, User
from app.services.action_authorization import IdentityClass
from app.services.canonical_multileg_candidate_expiration_v2 import (
    MultiLegCandidateExpirationUnavailableV2,
    SqlAlchemyMultiLegCandidateExpirationV2,
)
from app.services.canonical_multi_outpoint_admission_proposal_v2 import (
    create_canonical_multi_outpoint_admission_proposal_v2,
)
from app.services.canonical_multi_outpoint_mirror_v2 import create_canonical_multi_outpoint_mirror_v2
from app.services.current_entitlement_evidence import CONTRACT_VERSION
from app.services.trusted_covenant_registration import trusted_outpoints_from_registration
from tests.integration.test_canonical_multileg_candidate_postgres_v2 import (
    CANDIDATES,
    OUTPOINTS,
    db as db,
    postgres_engine as postgres_engine,
    _counts,
    _issue,
    _nonce_consumed,
    _reserve,
)
from tests.unit.test_canonical_admission_proposal_v2 import (
    ALICE,
    BOB,
    CHARLIE,
    NOW,
    _genesis,
    _sources,
)
from tests.unit.test_canonical_multi_outpoint_admission_proposal_v2 import (
    _new,
    _rpc,
)
from tests.unit.test_canonical_admission_consent_v2 import CHILD_SIG, SPONSOR_SIG
from tests.unit.test_canonical_multi_outpoint_mirror_v2 import _bundle, _observation
from app.services.canonical_multileg_candidate_registry_v2 import SqlAlchemyCanonicalMultiLegCandidateRegistryV2
from app.services.canonical_multileg_consent_storage_v2 import SqlAlchemyMultiLegConsentLedgerV2

CLAIMS = "public.canonical_multileg_live_child_claims_v2"
UTXO_CLAIMS = "public.canonical_multileg_live_outpoint_claims_v2"
EXPIRATIONS = "public.canonical_multileg_candidate_expirations_v2"
OLD = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
OLD_ID = "00000000-0000-4000-8000-0000000000f1"
OLD_CHILD_ID = "00000000-0000-4000-8000-0000000000f2"
NEW_ID = "00000000-0000-4000-8000-0000000000f3"


def _full_at(engine, key, at, evidence_id, *, new_user=True):
    with Session(engine) as session:
        with session.begin():
            if new_user:
                session.add(User(pubkey=key[2:], is_active=True, metadata_json={}))
            session.add(
                CurrentEntitlementEvidence(
                    evidence_id=evidence_id,
                    contract_version=CONTRACT_VERSION,
                    subject_pubkey=key[2:],
                    identity_class=IdentityClass.FULL.value,
                    current_full_relation_satisfied=True,
                    evidence_source="disposable_expiry_test_fixture",
                    evidence_version="v1",
                    source_evidence_sha256="f" * 64,
                    observed_at=at - timedelta(seconds=20),
                    valid_until=at + timedelta(seconds=300),
                    created_at=at - timedelta(seconds=1),
                    revoked_at=None,
                )
            )


def _propose(mirror, at, proposal_id, *, basis=None, observation=None):
    if observation is None:
        observation = _observation(mirror)
    observation = replace(observation, observed_at=at)
    proposal = create_canonical_multi_outpoint_admission_proposal_v2(
        proposal_id=proposal_id,
        proposed_at=at,
        mirror=mirror,
        observation=observation,
        sponsor_basis=_genesis() if basis is None else basis,
        sponsor_import_reference_sha256="1" * 64,
        sponsor_key_proof_reference_sha256="2" * 64,
        child_acceptance_reference_sha256="3" * 64,
    )
    return proposal, observation


def _issue_at(engine, proposal, sponsor, at):
    with Session(engine) as session:
        with session.begin():
            return SqlAlchemyMultiLegConsentLedgerV2(session, clock=lambda: at).issue(
                proposal, authenticated_sponsor_pubkey=sponsor
            )


def _reserve_at(engine, proposal, observation, nonce, at, sponsor, child, basis=None):
    with Session(engine) as session:
        with session.begin():
            pending = SqlAlchemyCanonicalMultiLegCandidateRegistryV2(
                session, clock=lambda: at
            ).reserve_candidate_in_transaction(
                proposal,
                sponsor_basis=_genesis() if basis is None else basis,
                current_observation=observation,
                authenticated_sponsor_pubkey=sponsor,
                authenticated_child_pubkey=child,
                challenge_sha256=nonce.challenge_sha256,
                sponsor_signature=SPONSOR_SIG,
                child_signature=CHILD_SIG,
                bitcoin_message_rpc=_rpc(proposal, nonce.challenge),
            )
            assert not pending.is_effective and not pending.grants_full
            return pending


def _historical_root(engine):
    mirror = _bundle()
    proposal, observation = _propose(mirror, OLD, OLD_ID)
    _full_at(engine, ALICE, OLD, "00000000-0000-4000-8000-0000000000e1")
    nonce = _issue_at(engine, proposal, ALICE, OLD)
    _reserve_at(engine, proposal, observation, nonce, OLD, ALICE, BOB)
    assert _counts(engine) == (1, 5)
    return proposal, nonce


def _expire(engine, proposal_id, *, rollback=False):
    with Session(engine) as session:
        with session.begin():
            receipt = SqlAlchemyMultiLegCandidateExpirationV2(session).expire_in_transaction(proposal_id)
            assert not receipt.durable and not receipt.grants_full and not receipt.is_effective
            if rollback:
                raise RuntimeError("abort_expiry_transaction")
            return receipt


def _live_counts(engine):
    with engine.connect() as conn:
        return (
            conn.execute(text(f"SELECT count(*) FROM {CLAIMS}")).scalar_one(),
            conn.execute(text(f"SELECT count(*) FROM {UTXO_CLAIMS}")).scalar_one(),
            conn.execute(text(f"SELECT count(*) FROM {EXPIRATIONS}")).scalar_one(),
        )


def test_candidate_creates_live_claims_not_full(db):
    proposal = _new()
    _full_at(db, ALICE, NOW, "00000000-0000-4000-8000-0000000000e1")
    nonce = _issue(db, proposal)
    result = _reserve(db, proposal, nonce)
    assert not result.is_effective and not result.grants_full
    assert _counts(db) == (1, 5)
    assert _live_counts(db) == (1, 5, 0)


def test_not_yet_seven_days_old_cannot_expire_using_database_clock(db):
    at = datetime.now(timezone.utc).replace(microsecond=0)
    proposal, observation = _propose(_bundle(), at, OLD_ID)
    _full_at(db, ALICE, at, "00000000-0000-4000-8000-0000000000e1")
    nonce = _issue_at(db, proposal, ALICE, at)
    _reserve_at(db, proposal, observation, nonce, at, ALICE, BOB)
    with pytest.raises(MultiLegCandidateExpirationUnavailableV2, match="expiry_not_permitted"):
        _expire(db, proposal.proposal_id)
    assert _live_counts(db) == (1, 5, 0)
    assert _counts(db) == (1, 5)


def test_historical_candidate_expiration_releases_claims_but_preserves_all_proof(db):
    proposal, nonce = _historical_root(db)
    result = _expire(db, proposal.proposal_id)
    assert result.proposal_id == proposal.proposal_id
    assert result.released_outpoints == 5
    assert _live_counts(db) == (0, 0, 1)
    assert _counts(db) == (1, 5)
    assert _nonce_consumed(db, nonce) is not None
    with db.connect() as conn:
        event = conn.execute(text(f"SELECT * FROM {EXPIRATIONS}")).mappings().one()
        header = conn.execute(text(f"SELECT * FROM {CANDIDATES}")).mappings().one()
    assert event["proposal_sha256"] == header["proposal_sha256"]
    assert event["reason"] == "candidate_ttl_expired_no_full"
    assert event["released_outpoint_count"] == 5
    assert header["state"] == "candidate_only_no_full"
    with pytest.raises(MultiLegCandidateExpirationUnavailableV2):
        _expire(db, proposal.proposal_id)


def test_aborted_expiration_restores_all_claims_and_no_event(db):
    proposal, _ = _historical_root(db)
    with pytest.raises(RuntimeError, match="abort_expiry_transaction"):
        _expire(db, proposal.proposal_id, rollback=True)
    assert _live_counts(db) == (1, 5, 0)
    _expire(db, proposal.proposal_id)
    assert _live_counts(db) == (0, 0, 1)


def test_re_registration_after_expiry_needs_new_signed_proposal_and_nonce(db):
    old_proposal, old_nonce = _historical_root(db)
    _expire(db, old_proposal.proposal_id)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    new_proposal, observation = _propose(old_proposal.mirror, now, NEW_ID)
    _full_at(db, ALICE, now, "00000000-0000-4000-8000-0000000000e2", new_user=False)
    fresh = _issue_at(db, new_proposal, ALICE, now)
    _reserve_at(db, new_proposal, observation, fresh, now, ALICE, BOB)
    assert _counts(db) == (2, 10)
    assert _live_counts(db) == (1, 5, 1)
    assert fresh.challenge_sha256 != old_nonce.challenge_sha256
    with db.connect() as conn:
        active = conn.execute(text(f"SELECT proposal_id FROM {CLAIMS}")).scalar_one()
    assert active == new_proposal.proposal_id
    # Old signed nonce cannot authorize the new immutable proposal.
    with pytest.raises(Exception):
        _reserve_at(db, new_proposal, observation, old_nonce, now, ALICE, BOB)
    assert _live_counts(db) == (1, 5, 1)


def test_parent_cannot_expire_while_child_candidate_claims_are_active(db):
    parent, _ = _historical_root(db)
    policy, registration, _, snapshot, _ = _sources(sponsor=BOB, child=CHARLIE, depth=1)
    child_mirror = create_canonical_multi_outpoint_mirror_v2(policy, trusted_outpoints_from_registration(registration))
    child, old_observation = _propose(child_mirror, OLD, OLD_CHILD_ID, basis=parent, observation=snapshot)
    _full_at(db, BOB, OLD, "00000000-0000-4000-8000-0000000000e3")
    nonce = _issue_at(db, child, BOB, OLD)
    _reserve_at(db, child, old_observation, nonce, OLD, BOB, CHARLIE, basis=parent)
    assert _live_counts(db) == (2, 7, 0)
    with pytest.raises(MultiLegCandidateExpirationUnavailableV2):
        _expire(db, parent.proposal_id)
    _expire(db, child.proposal_id)
    _expire(db, parent.proposal_id)
    assert _live_counts(db) == (0, 0, 2)
    assert _counts(db) == (2, 7)


def test_expired_parent_history_is_not_authority_to_create_new_child(db):
    parent, _ = _historical_root(db)
    _expire(db, parent.proposal_id)
    policy, registration, _, observation, _ = _sources(sponsor=BOB, child=CHARLIE, depth=1)
    mirror = create_canonical_multi_outpoint_mirror_v2(policy, trusted_outpoints_from_registration(registration))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    child, obs = _propose(mirror, now, OLD_CHILD_ID, basis=parent, observation=observation)
    _full_at(db, BOB, now, "00000000-0000-4000-8000-0000000000e3")
    nonce = _issue_at(db, child, BOB, now)
    with pytest.raises(Exception):
        _reserve_at(db, child, obs, nonce, now, BOB, CHARLIE, basis=parent)
    assert _live_counts(db) == (0, 0, 1)


def test_extra_output_cannot_be_appended_to_complete_candidate(db):
    proposal = _new()
    _full_at(db, ALICE, NOW, "00000000-0000-4000-8000-0000000000e1")
    nonce = _issue(db, proposal)
    _reserve(db, proposal, nonce)
    with pytest.raises(DBAPIError):
        with db.begin() as conn:
            conn.execute(
                text(
                    f"INSERT INTO {OUTPOINTS} "
                    "(proposal_id,leg_order,txid,vout,amount_sats,script_pubkey_sha256) "
                    "VALUES (:pid,'earlier',:txid,10,100,:script)"
                ),
                {
                    "pid": proposal.proposal_id,
                    "txid": "a" * 64,
                    "script": proposal.mirror.outpoints[0].script_sha256,
                },
            )
    assert _counts(db) == (1, 5)
    assert _live_counts(db) == (1, 5, 0)


def test_immutable_expiration_history_denies_delete_or_mutation(db):
    proposal, _ = _historical_root(db)
    _expire(db, proposal.proposal_id)
    for q in (
        f"DELETE FROM {EXPIRATIONS}",
        f"UPDATE {EXPIRATIONS} SET expired_at=expired_at",
    ):
        with pytest.raises(DBAPIError):
            with db.begin() as conn:
                conn.execute(text(q))
    assert _live_counts(db) == (0, 0, 1)


def test_expiration_requires_postgres_transaction(db):
    sqlite = create_engine("sqlite:///:memory:")
    try:
        with Session(sqlite) as session:
            with session.begin():
                with pytest.raises(MultiLegCandidateExpirationUnavailableV2, match="expiry_not_permitted"):
                    SqlAlchemyMultiLegCandidateExpirationV2(session).expire_in_transaction(OLD_ID)
    finally:
        sqlite.dispose()

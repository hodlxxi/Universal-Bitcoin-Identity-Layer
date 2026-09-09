from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.models import CurrentEntitlementEvidence, User
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.current_entitlement_evidence_storage import (
    CurrentEntitlementEvidenceStorageError,
    SqlAlchemyCurrentEntitlementEvidenceRepository,
    SqlAlchemyTransactionBoundCurrentFullVerifier,
    _subject_lock_keys,
)
from app.services.current_full_entitlement_proof import (
    CurrentFullEntitlementProofState,
    CurrentFullEntitlementProofUnavailable,
    VerifiedCurrentFullEntitlement,
    canonical_full_entitlement_proof_preimage,
    produce_verified_current_full_entitlement,
    validate_verified_current_full_entitlement,
)

SUBJECT = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
OTHER_SUBJECT = "c6047f9441ed7d6d3045406e95c07cd85a49886dd5c2dc239e9e7c5c2f24f044"
USER_ID = "00000000-0000-4000-8000-000000000002"
NOW = datetime(2026, 9, 8, 22, 30, tzinfo=timezone.utc)


def evidence(*, subject=SUBJECT, identity=IdentityClass.FULL, **changes):
    values = dict(
        evidence_id="00000000-0000-4000-8000-000000000001",
        contract_version=CONTRACT_VERSION,
        subject_pubkey=subject,
        identity_class=identity,
        current_full_relation_satisfied=identity is IdentityClass.FULL,
        evidence_source="offline_verifier",
        evidence_version="v1",
        source_evidence_sha256="b" * 64,
        observed_at=NOW - timedelta(seconds=1),
        valid_until=NOW + timedelta(minutes=5),
        revoked_at=None,
        created_at=NOW,
    )
    values.update(changes)
    return CurrentEntitlementEvidenceRecord(**values)


def state(**changes):
    values = dict(
        user_id=USER_ID,
        user_subject=SUBJECT,
        user_is_active=True,
        evidence=evidence(),
    )
    values.update(changes)
    return CurrentFullEntitlementProofState(**values)


def orm_evidence(value=None):
    value = value or evidence()
    values = vars(value).copy()
    values["identity_class"] = value.identity_class.value
    return CurrentEntitlementEvidence(**values)


def test_exact_canonical_preimage_and_fixed_digest_vector():
    expected = (
        b'{"domain":"HODLXXI_FULL_ENTITLEMENT_V1","proof":{"evidence":{"contractVersion":'
        b'"hodlxxi.current_entitlement_evidence.v1","createdAt":"2026-09-08T22:30:00Z",'
        b'"currentFullRelationSatisfied":true,"evidenceId":"00000000-0000-4000-8000-000000000001",'
        b'"evidenceSource":"offline_verifier","evidenceVersion":"v1","identityClass":"full",'
        b'"observedAt":"2026-09-08T22:29:59Z","revokedAt":null,"sourceEvidenceSha256":'
        b'"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","subject":'
        b'"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",'
        b'"validUntil":"2026-09-08T22:35:00Z"},"schema":"hodlxxi.full_entitlement_proof.v1",'
        b'"user":{"id":"00000000-0000-4000-8000-000000000002","isActive":true,"subject":'
        b'"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"},"version":1}}'
    )
    proof = produce_verified_current_full_entitlement(state(), now=NOW)

    assert canonical_full_entitlement_proof_preimage(state()) == expected
    assert proof == VerifiedCurrentFullEntitlement(
        "hodlxxi-full-entitlement-v1-sha256:b4ac158d3851b0d0dde4f76f290e89d8da3b81aef080ff8994dd781bda945b76",
        SUBJECT,
        NOW - timedelta(seconds=1),
        NOW + timedelta(minutes=5),
    )


def test_canonical_preimage_rejects_mapping_inherited_accessor_and_extra_state():
    class InheritedState(CurrentFullEntitlementProofState):
        pass

    current = state()
    for invalid in (
        vars(current.evidence),
        SimpleNamespace(**vars(current.evidence)),
        InheritedState(current.user_id, current.user_subject, current.user_is_active, current.evidence),
        {"state": current, "extra": True},
    ):
        with pytest.raises(CurrentFullEntitlementProofUnavailable):
            canonical_full_entitlement_proof_preimage(invalid)


@pytest.mark.parametrize(
    "invalid",
    (
        state(user_is_active=False),
        state(user_subject=OTHER_SUBJECT),
        state(evidence=evidence(identity=IdentityClass.LIMITED)),
        state(evidence=evidence(revoked_at=NOW)),
        state(evidence=evidence(valid_until=NOW)),
        state(evidence=evidence(observed_at=NOW + timedelta(seconds=1), created_at=NOW + timedelta(seconds=1))),
        state(evidence=evidence(created_at=NOW + timedelta(microseconds=1))),
    ),
)
def test_inactive_limited_revoked_expired_future_mismatched_or_noncanonical_state_is_rejected(invalid):
    with pytest.raises(CurrentFullEntitlementProofUnavailable):
        produce_verified_current_full_entitlement(invalid, now=NOW)


def test_proof_validator_binds_exact_type_subject_and_current_validity():
    proof = produce_verified_current_full_entitlement(state(), now=NOW)
    assert validate_verified_current_full_entitlement(proof, subject=SUBJECT, now=NOW) == proof
    for invalid in (
        None,
        {"proof_id": proof.proof_id},
        proof.proof_id,
        replace(proof, proof_id="invalid"),
        replace(proof, subject=OTHER_SUBJECT),
        replace(proof, valid_from=NOW + timedelta(seconds=1)),
        replace(proof, expires_at=NOW),
    ):
        with pytest.raises(CurrentFullEntitlementProofUnavailable):
            validate_verified_current_full_entitlement(invalid, subject=SUBJECT, now=NOW)


class Result:
    def __init__(self, values=()):
        self.values = list(values)

    def scalars(self):
        return self

    def all(self):
        return self.values


_DEFAULT_ROWS = object()


class TransactionSession:
    def __init__(self, *, user=None, rows=_DEFAULT_ROWS, active=True):
        self.user = user or User(id=USER_ID, pubkey=SUBJECT, is_active=True, metadata_json={})
        self.rows = list((orm_evidence(),) if rows is _DEFAULT_ROWS else rows)
        self.active = active
        self.statements = []

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    def in_transaction(self):
        return self.active

    def execute(self, statement):
        self.statements.append(statement)
        if len(self.statements) == 1:
            return Result()
        if len(self.statements) == 2:
            return Result((self.user,))
        return Result(self.rows)

    def commit(self):
        pytest.fail("transaction-bound verifier committed caller session")

    def rollback(self):
        pytest.fail("transaction-bound verifier rolled back caller session")

    def close(self):
        pytest.fail("transaction-bound verifier closed caller session")


def _postgresql(statement):
    return str(statement.compile(dialect=postgresql.dialect()))


def test_transaction_bound_reader_requires_active_postgresql_transaction_and_locks_authority_rows():
    session = TransactionSession()
    result = SqlAlchemyTransactionBoundCurrentFullVerifier(session).verify_in_transaction(SUBJECT, now=NOW)

    assert result == produce_verified_current_full_entitlement(state(), now=NOW)
    assert len(session.statements) == 3
    assert "pg_advisory_xact_lock" in _postgresql(session.statements[0])
    assert "FOR UPDATE" in _postgresql(session.statements[1])
    assert "users" in _postgresql(session.statements[1])
    assert "FOR UPDATE" in _postgresql(session.statements[2])
    assert "current_entitlement_evidence" in _postgresql(session.statements[2])

    for invalid in (
        TransactionSession(active=False),
        TransactionSession(user=User(id=USER_ID, pubkey=SUBJECT, is_active=False)),
        TransactionSession(rows=()),
    ):
        with pytest.raises(CurrentEntitlementEvidenceStorageError):
            SqlAlchemyTransactionBoundCurrentFullVerifier(invalid).verify_in_transaction(SUBJECT, now=NOW)


def test_transaction_bound_reader_rejects_replaced_and_ambiguous_latest_evidence():
    replacement = evidence(
        identity=IdentityClass.LIMITED,
        evidence_id="00000000-0000-4000-8000-000000000003",
        observed_at=NOW,
        created_at=NOW,
        valid_until=NOW + timedelta(minutes=5),
    )
    with pytest.raises(CurrentEntitlementEvidenceStorageError):
        SqlAlchemyTransactionBoundCurrentFullVerifier(
            TransactionSession(rows=(orm_evidence(replacement), orm_evidence()))
        ).verify_in_transaction(SUBJECT, now=NOW)

    tied = evidence(evidence_id="00000000-0000-4000-8000-000000000004")
    with pytest.raises(CurrentEntitlementEvidenceStorageError):
        SqlAlchemyTransactionBoundCurrentFullVerifier(
            TransactionSession(rows=(orm_evidence(tied), orm_evidence()))
        ).verify_in_transaction(SUBJECT, now=NOW)


class WriterSession:
    def __init__(self, events):
        self.events = events

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.events.append(("close",))

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    def execute(self, statement):
        parameters = tuple(statement.compile().params.values())
        self.events.append(("lock", parameters))
        return Result()

    def add(self, _row):
        self.events.append(("add",))

    def add_all(self, rows):
        self.events.append(("add_all", len(rows)))

    def commit(self):
        self.events.append(("commit",))

    def rollback(self):
        self.events.append(("rollback",))

    def close(self):
        self.events.append(("close",))


def test_all_evidence_writer_paths_take_the_same_subject_lock_in_deterministic_order():
    events = []
    repository = SqlAlchemyCurrentEntitlementEvidenceRepository(lambda: WriterSession(events))
    repository.append(evidence())
    assert events[:2] == [("lock", _subject_lock_keys(SUBJECT)), ("add",)]

    events.clear()
    first = evidence(subject=OTHER_SUBJECT, evidence_id="00000000-0000-4000-8000-000000000010")
    second = evidence(subject=SUBJECT, evidence_id="00000000-0000-4000-8000-000000000011")
    repository.append_pair((first, second))
    assert [event for event in events if event[0] == "lock"] == [
        ("lock", _subject_lock_keys(subject)) for subject in sorted((SUBJECT, OTHER_SUBJECT))
    ]

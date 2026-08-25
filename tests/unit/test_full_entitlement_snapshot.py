from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import uuid

import pytest

from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.current_entitlement_evidence_storage import CompleteLatestEntitlementPopulation
from app.services.full_entitlement_snapshot import (
    FullEntitlementSnapshotReader,
    FullEntitlementSnapshotUnavailable,
)

NOW = datetime(2026, 8, 25, 12, tzinfo=timezone.utc)
SUBJECT_A = "11" * 32
SUBJECT_B = "22" * 32


def evidence(subject=SUBJECT_A, identity=IdentityClass.FULL, **changes):
    values = dict(
        evidence_id=str(uuid.uuid4()),
        contract_version=CONTRACT_VERSION,
        subject_pubkey=subject,
        identity_class=identity,
        current_full_relation_satisfied=identity is IdentityClass.FULL,
        evidence_source="offline_verifier",
        evidence_version="v1",
        source_evidence_sha256="a" * 64,
        observed_at=NOW - timedelta(seconds=10),
        valid_until=NOW + timedelta(minutes=5),
        revoked_at=None,
        created_at=NOW - timedelta(seconds=5),
    )
    values.update(changes)
    return CurrentEntitlementEvidenceRecord(**values)


class Repository:
    def __init__(self, records=(), error=None, partial=False, active_subjects=()):
        self.records = records
        self.error = error
        self.partial = partial
        self.active_subjects = active_subjects
        self.calls = []

    def get_latest_population(self, maximum):
        self.calls.append(maximum)
        if self.error:
            raise self.error
        if self.partial:
            return list(self.records)
        return CompleteLatestEntitlementPopulation(tuple(self.records), maximum, tuple(self.active_subjects))


def unavailable(repository, **kwargs):
    with pytest.raises(FullEntitlementSnapshotUnavailable) as caught:
        FullEntitlementSnapshotReader(repository, clock=lambda: NOW).current_snapshot(**kwargs)
    assert str(caught.value) == "full entitlement snapshot unavailable"


def test_exact_deterministic_full_snapshot_and_validity_bound():
    record = evidence(valid_until=NOW + timedelta(seconds=90))
    repository = Repository([record], active_subjects=(SUBJECT_A,))
    snapshot = FullEntitlementSnapshotReader(repository, clock=lambda: NOW).current_snapshot(maximum=1)
    assert repository.calls == [1]
    assert snapshot == {
        "schema": "hodlxxi.full_entitlement_snapshot.v1",
        "version": 1,
        "source": "hodlxxi-crt",
        "snapshotId": snapshot["snapshotId"],
        "complete": True,
        "issuedAt": int(NOW.timestamp() * 1000),
        "expiresAt": int(record.valid_until.timestamp() * 1000),
        "entitlements": [
            {
                "snapshotId": snapshot["snapshotId"],
                "subject": SUBJECT_A,
                "status": "full",
                "validFrom": int(record.observed_at.timestamp() * 1000),
                "expiresAt": int(record.valid_until.timestamp() * 1000),
                "revoked": False,
            }
        ],
    }
    assert (
        snapshot
        == FullEntitlementSnapshotReader(
            Repository([record], active_subjects=(SUBJECT_A,)), clock=lambda: NOW
        ).current_snapshot()
    )


def test_complete_empty_and_negative_population_are_available():
    empty = FullEntitlementSnapshotReader(Repository([]), clock=lambda: NOW).current_snapshot(maximum=0)
    assert empty["complete"] is True and empty["entitlements"] == []
    assert empty["expiresAt"] == int((NOW + timedelta(minutes=5)).timestamp() * 1000)
    negatives = [
        evidence(identity=IdentityClass.LIMITED),
        evidence(revoked_at=NOW - timedelta(seconds=6)),
        evidence(valid_until=NOW),
    ]
    for record in negatives:
        assert (
            FullEntitlementSnapshotReader(Repository([record]), clock=lambda: NOW).current_snapshot()["entitlements"]
            == []
        )


def test_subject_order_is_required_and_output_is_canonical():
    records = [evidence(SUBJECT_A), evidence(SUBJECT_B)]
    snapshot = FullEntitlementSnapshotReader(
        Repository(records, active_subjects=(SUBJECT_A, SUBJECT_B)), clock=lambda: NOW
    ).current_snapshot()
    assert [item["subject"] for item in snapshot["entitlements"]] == [SUBJECT_A, SUBJECT_B]
    unavailable(Repository(list(reversed(records)), active_subjects=(SUBJECT_A, SUBJECT_B)))
    unavailable(Repository([records[0], records[0]], active_subjects=(SUBJECT_A,)))


def test_bound_partial_malformed_unknown_and_internal_failures_are_generic():
    unavailable(Repository([evidence(), evidence(SUBJECT_B)]), maximum=1)
    unavailable(Repository(error=RuntimeError("database detail")))
    unavailable(Repository([evidence()], partial=True))
    unavailable(Repository([SimpleNamespace(**{**vars(evidence()), "identity_class": "unknown"})]))
    unavailable(Repository([SimpleNamespace(**{**vars(evidence()), "subject_pubkey": "A" * 64})]))
    for maximum in (-1, True, 4097):
        unavailable(Repository([]), maximum=maximum)


def test_current_full_subjects_require_active_persisted_user_proof():
    record = evidence()
    unavailable(Repository([record]))
    unavailable(Repository([record], active_subjects=(SUBJECT_B,)))


def test_ambiguous_latest_failures_are_generic_and_non_leaking():
    with pytest.raises(FullEntitlementSnapshotUnavailable) as caught:
        FullEntitlementSnapshotReader(
            Repository(error=RuntimeError(f"ambiguous latest evidence for {SUBJECT_A}")),
            clock=lambda: NOW,
        ).current_snapshot()
    assert str(caught.value) == "full entitlement snapshot unavailable"
    assert SUBJECT_A not in str(caught.value)


def test_invalid_dependency_and_clock_fail_closed():
    with pytest.raises(FullEntitlementSnapshotUnavailable) as caught:
        FullEntitlementSnapshotReader(object())
    assert str(caught.value) == "full entitlement snapshot unavailable"
    with pytest.raises(FullEntitlementSnapshotUnavailable):
        FullEntitlementSnapshotReader(Repository([]), clock=lambda: datetime(2026, 1, 1)).current_snapshot()
    with pytest.raises(FullEntitlementSnapshotUnavailable):
        FullEntitlementSnapshotReader(Repository([]), clock=0).current_snapshot()
    unavailable(
        Repository(
            [
                evidence(
                    observed_at=NOW + timedelta(seconds=61),
                    created_at=NOW + timedelta(seconds=61),
                    valid_until=NOW + timedelta(seconds=120),
                )
            ]
        )
    )


def test_near_future_latest_evidence_fails_complete_snapshot_closed():
    unavailable(
        Repository(
            [
                evidence(
                    observed_at=NOW + timedelta(seconds=1),
                    created_at=NOW + timedelta(seconds=1),
                )
            ]
        )
    )


def test_sub_millisecond_evidence_deadline_fails_closed():
    unavailable(Repository([evidence(valid_until=NOW + timedelta(microseconds=999))], active_subjects=(SUBJECT_A,)))

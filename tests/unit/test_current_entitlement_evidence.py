from datetime import datetime, timedelta, timezone
import uuid

import pytest

from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import (
    CONTRACT_VERSION,
    CurrentEntitlementEvidenceRecord,
    InvalidCurrentEntitlementEvidence,
)

NOW = datetime(2026, 7, 22, 12, tzinfo=timezone.utc)


def evidence(**changes):
    values = dict(
        evidence_id=str(uuid.uuid4()),
        contract_version=CONTRACT_VERSION,
        subject_pubkey="a" * 64,
        identity_class=IdentityClass.LIMITED,
        current_full_relation_satisfied=False,
        evidence_source="offline_covenant_verifier",
        evidence_version="verifier-v1",
        source_evidence_sha256="b" * 64,
        observed_at=NOW,
        valid_until=NOW + timedelta(minutes=5),
        revoked_at=None,
        created_at=NOW + timedelta(seconds=1),
    )
    values.update(changes)
    return CurrentEntitlementEvidenceRecord(**values)


def test_valid_limited_and_full_evidence_are_immutable_and_utc_normalized():
    limited = evidence(observed_at=NOW.astimezone(timezone(timedelta(hours=2))))
    full = evidence(identity_class=IdentityClass.FULL, current_full_relation_satisfied=True)
    assert limited.observed_at == NOW and limited.observed_at.tzinfo is timezone.utc
    assert full.identity_class is IdentityClass.FULL
    with pytest.raises(Exception):
        limited.evidence_source = "changed"


@pytest.mark.parametrize(
    "changes",
    [
        {"subject_pubkey": "A" * 64},
        {"subject_pubkey": "a" * 63},
        {"source_evidence_sha256": "B" * 64},
        {"evidence_id": "not-a-uuid"},
        {"evidence_id": str(uuid.uuid4()).upper()},
        {"contract_version": "v2"},
        {"evidence_source": ""},
        {"evidence_source": "x" * 129},
        {"evidence_version": " "},
        {"evidence_version": "x" * 65},
        {"identity_class": IdentityClass.FULL},
        {"identity_class": IdentityClass.FULL, "current_full_relation_satisfied": 1},
        {"identity_class": "limited"},
        {"observed_at": NOW.replace(tzinfo=None)},
        {"valid_until": (NOW + timedelta(minutes=5)).replace(tzinfo=None)},
        {"created_at": NOW.replace(tzinfo=None)},
        {"revoked_at": NOW.replace(tzinfo=None)},
        {"valid_until": NOW},
        {"valid_until": NOW + timedelta(seconds=901)},
        {"created_at": NOW - timedelta(seconds=1)},
        {"revoked_at": NOW - timedelta(seconds=1)},
        {"revoked_at": NOW + timedelta(seconds=2), "created_at": NOW + timedelta(seconds=1)},
    ],
)
def test_invalid_evidence_fails_closed(changes):
    with pytest.raises(InvalidCurrentEntitlementEvidence):
        evidence(**changes)

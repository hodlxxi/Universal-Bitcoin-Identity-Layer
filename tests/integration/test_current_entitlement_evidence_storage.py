from datetime import datetime, timedelta, timezone
import uuid

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from app.models import Base, CurrentEntitlementEvidence
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.current_entitlement_evidence_storage import (
    CurrentEntitlementEvidenceStorageError,
    SqlAlchemyCurrentEntitlementEvidenceRepository,
)

NOW = datetime(2026, 7, 22, 12, tzinfo=timezone.utc)


def item(*, subject="a" * 64, identity=IdentityClass.LIMITED, observed=NOW, created=None, revoked=None, eid=None):
    return CurrentEntitlementEvidenceRecord(
        eid or str(uuid.uuid4()),
        CONTRACT_VERSION,
        subject,
        identity,
        identity is IdentityClass.FULL,
        "offline_verifier",
        "v1",
        "b" * 64,
        observed,
        observed + timedelta(minutes=5),
        revoked,
        created or observed + timedelta(seconds=1),
    )


@pytest.fixture
def storage(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'evidence.db'}")
    CurrentEntitlementEvidence.__table__.create(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    return engine, factory, SqlAlchemyCurrentEntitlementEvidenceRepository(factory)


def test_metadata_table_columns_indexes_and_constraints_exist():
    table = CurrentEntitlementEvidence.__table__
    assert set(table.columns.keys()) == {
        "evidence_id",
        "contract_version",
        "subject_pubkey",
        "identity_class",
        "current_full_relation_satisfied",
        "evidence_source",
        "evidence_version",
        "source_evidence_sha256",
        "observed_at",
        "valid_until",
        "revoked_at",
        "created_at",
    }
    assert {index.name for index in table.indexes} >= {
        "idx_current_entitlement_subject",
        "idx_current_entitlement_valid_until",
        "idx_current_entitlement_revoked_at",
        "idx_current_entitlement_subject_observed",
    }
    assert len([constraint for constraint in table.constraints if constraint.name]) >= 10


def test_base_metadata_create_all_materializes_table_and_indexes():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
    assert "current_entitlement_evidence" in inspector.get_table_names()
    assert {index["name"] for index in inspector.get_indexes("current_entitlement_evidence")} >= {
        "idx_current_entitlement_subject",
        "idx_current_entitlement_valid_until",
        "idx_current_entitlement_revoked_at",
        "idx_current_entitlement_subject_observed",
    }


def test_append_retrieve_and_timezone_normalization(storage):
    _, _, repository = storage
    expected = item()
    repository.append(expected)
    actual = repository.get_latest(expected.subject_pubkey)
    assert actual == expected
    assert actual.observed_at.tzinfo is timezone.utc


def test_latest_is_deterministic_and_subjects_are_isolated(storage):
    _, _, repository = storage
    older_full = item(identity=IdentityClass.FULL, observed=NOW)
    latest_limited = item(observed=NOW + timedelta(seconds=2))
    other = item(subject="c" * 64, observed=NOW + timedelta(seconds=10))
    for evidence in (older_full, latest_limited, other):
        repository.append(evidence)
    assert repository.get_latest("a" * 64) == latest_limited
    assert repository.get_latest("c" * 64) == other

    tied_low = item(observed=NOW + timedelta(seconds=3), eid="00000000-0000-0000-0000-000000000001")
    tied_high = item(
        observed=tied_low.observed_at, created=tied_low.created_at, eid="00000000-0000-0000-0000-000000000002"
    )
    repository.append(tied_low)
    repository.append(tied_high)
    assert repository.get_latest("a" * 64) == tied_high


@pytest.mark.parametrize("state", ["revoked", "expired"])
def test_latest_negative_record_is_selected_over_older_full(storage, state):
    _, _, repository = storage
    repository.append(item(identity=IdentityClass.FULL))
    observed = NOW + timedelta(seconds=10)
    latest = item(observed=observed, revoked=observed if state == "revoked" else None)
    if state == "expired":
        latest = CurrentEntitlementEvidenceRecord(**{**vars(latest), "valid_until": observed + timedelta(seconds=1)})
    repository.append(latest)
    assert repository.get_latest("a" * 64) == latest


def test_duplicate_and_database_failures_are_typed(storage):
    engine, _, repository = storage
    evidence = item()
    repository.append(evidence)
    with pytest.raises(CurrentEntitlementEvidenceStorageError, match="storage unavailable"):
        repository.append(evidence)
    engine.dispose()
    engine = create_engine("sqlite:///:memory:")
    broken = SqlAlchemyCurrentEntitlementEvidenceRepository(sessionmaker(bind=engine))
    with pytest.raises(CurrentEntitlementEvidenceStorageError, match="storage unavailable"):
        broken.get_latest("a" * 64)


def test_malformed_persisted_latest_fails_closed(storage):
    engine, _, repository = storage
    repository.append(item(identity=IdentityClass.FULL))
    with engine.begin() as connection:
        connection.execute(text("PRAGMA ignore_check_constraints = ON"))
        connection.execute(
            CurrentEntitlementEvidence.__table__.insert().values(
                **{**vars(item(observed=NOW + timedelta(seconds=2))), "identity_class": "full"}
            )
        )
    with pytest.raises(CurrentEntitlementEvidenceStorageError):
        repository.get_latest("a" * 64)

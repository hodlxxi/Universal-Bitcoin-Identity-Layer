from datetime import datetime, timedelta, timezone
import uuid

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.models import Base, CurrentEntitlementEvidence, User
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.current_entitlement_evidence_storage import (
    CompleteLatestEntitlementPopulation,
    CurrentEntitlementEvidenceStorageError,
    SqlAlchemyCurrentEntitlementEvidenceRepository,
)
from app.services.full_entitlement_snapshot import FullEntitlementSnapshotReader, FullEntitlementSnapshotUnavailable

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
    User.__table__.create(engine)
    CurrentEntitlementEvidence.__table__.create(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    return engine, factory, SqlAlchemyCurrentEntitlementEvidenceRepository(factory)


def add_user(factory, subject="a" * 64, *, active=True):
    with factory() as session:
        session.add(User(pubkey=subject, is_active=active, metadata_json={}))
        session.commit()


def delete_user(factory, subject="a" * 64):
    with factory() as session:
        session.execute(User.__table__.delete().where(User.pubkey == subject))
        session.commit()


def set_user_active(factory, subject="a" * 64, *, active=None):
    with factory() as session:
        session.execute(User.__table__.update().where(User.pubkey == subject).values(is_active=active))
        session.commit()


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


def test_latest_population_is_complete_ordered_bounded_and_negative_latest_wins(storage):
    _, factory, repository = storage
    add_user(factory, "a" * 64)
    add_user(factory, "c" * 64)
    repository.append(item(subject="c" * 64, identity=IdentityClass.FULL))
    repository.append(item(subject="a" * 64, identity=IdentityClass.FULL))
    latest_limited = item(subject="a" * 64, observed=NOW + timedelta(seconds=2))
    repository.append(latest_limited)

    population = repository.get_latest_population(2)
    assert population == CompleteLatestEntitlementPopulation(
        (latest_limited, repository.get_latest("c" * 64)),
        2,
        ("a" * 64, "c" * 64),
    )
    with pytest.raises(CurrentEntitlementEvidenceStorageError):
        repository.get_latest_population(1)
    assert repository.get_latest_population(2) == population


def test_latest_population_empty_and_invalid_bound(storage):
    _, _, repository = storage
    assert repository.get_latest_population(0) == CompleteLatestEntitlementPopulation((), 0)
    for maximum in (-1, True, None):
        with pytest.raises(CurrentEntitlementEvidenceStorageError):
            repository.get_latest_population(maximum)


@pytest.mark.parametrize("user_state", ["inactive", "deleted", "nonexistent", "malformed", "mismatched"])
def test_full_snapshot_rejects_current_full_without_active_persisted_user(storage, user_state):
    _, factory, repository = storage
    subject = "a" * 64
    if user_state == "inactive":
        add_user(factory, subject, active=False)
    elif user_state == "deleted":
        add_user(factory, subject)
        delete_user(factory, subject)
    elif user_state == "malformed":
        add_user(factory, subject)
        set_user_active(factory, subject, active=None)
    elif user_state == "mismatched":
        add_user(factory, "c" * 64)

    repository.append(item(subject=subject, identity=IdentityClass.FULL))

    with pytest.raises(FullEntitlementSnapshotUnavailable) as caught:
        FullEntitlementSnapshotReader(repository, clock=lambda: NOW).current_snapshot(maximum=1)
    assert str(caught.value) == "full entitlement snapshot unavailable"
    assert subject not in str(caught.value)


@pytest.mark.parametrize(
    ("low_identity", "high_identity"),
    [
        (IdentityClass.LIMITED, IdentityClass.FULL),
        (IdentityClass.FULL, IdentityClass.LIMITED),
    ],
)
def test_latest_population_rejects_full_limited_ties_in_both_uuid_orders(storage, low_identity, high_identity):
    _, factory, repository = storage
    add_user(factory, "a" * 64)
    observed = NOW + timedelta(seconds=3)
    created = observed + timedelta(seconds=1)
    repository.append(
        item(
            identity=low_identity,
            observed=observed,
            created=created,
            eid="00000000-0000-0000-0000-000000000001",
        )
    )
    repository.append(
        item(
            identity=high_identity,
            observed=observed,
            created=created,
            eid="00000000-0000-0000-0000-000000000002",
        )
    )

    with pytest.raises(CurrentEntitlementEvidenceStorageError) as caught:
        repository.get_latest_population(1)
    assert str(caught.value) == "current entitlement evidence storage unavailable"
    assert "a" * 64 not in str(caught.value)


def test_latest_population_rejects_duplicate_full_tied_latest(storage):
    _, factory, repository = storage
    add_user(factory, "a" * 64)
    observed = NOW + timedelta(seconds=4)
    created = observed + timedelta(seconds=1)
    repository.append(
        item(
            identity=IdentityClass.FULL,
            observed=observed,
            created=created,
            eid="00000000-0000-0000-0000-000000000001",
        )
    )
    repository.append(
        item(
            identity=IdentityClass.FULL,
            observed=observed,
            created=created,
            eid="00000000-0000-0000-0000-000000000002",
        )
    )

    with pytest.raises(CurrentEntitlementEvidenceStorageError) as caught:
        repository.get_latest_population(1)
    assert str(caught.value) == "current entitlement evidence storage unavailable"
    assert "a" * 64 not in str(caught.value)


def test_latest_population_uses_one_rollback_only_transaction_and_closes_session():
    events = []

    class Transaction:
        is_active = True

        def rollback(self):
            events.append("rollback")
            self.is_active = False

    class Result:
        def all(self):
            events.append("all")
            return []

    class Session:
        transaction = None

        def __enter__(self):
            events.append("enter")
            return self

        def __exit__(self, *_args):
            events.append("close")

        def begin(self):
            assert self.transaction is None
            self.transaction = Transaction()
            events.append("begin")
            return self.transaction

        def execute(self, _statement):
            assert self.transaction is not None and self.transaction.is_active
            events.append("execute_in_transaction")
            return Result()

        def commit(self):
            pytest.fail("population read committed")

        def flush(self):
            pytest.fail("population read flushed")

        def add(self, _value):
            pytest.fail("population read added a row")

        def refresh(self, _value):
            pytest.fail("population read refreshed a row")

    repository = SqlAlchemyCurrentEntitlementEvidenceRepository(Session)
    assert repository.get_latest_population(0) == CompleteLatestEntitlementPopulation((), 0)
    assert events == ["enter", "begin", "execute_in_transaction", "all", "rollback", "close"]


def test_latest_population_failure_rolls_back_and_closes_without_retry():
    events = []

    class Transaction:
        is_active = True

        def rollback(self):
            events.append("rollback")
            self.is_active = False

    class Session:
        def __enter__(self):
            events.append("enter")
            return self

        def __exit__(self, *_args):
            events.append("close")

        def begin(self):
            events.append("begin")
            self.transaction = Transaction()
            return self.transaction

        def execute(self, _statement):
            events.append("execute")
            raise RuntimeError("database detail")

        def commit(self):
            pytest.fail("population read committed")

        def flush(self):
            pytest.fail("population read flushed")

        def add(self, _value):
            pytest.fail("population read added a row")

        def refresh(self, _value):
            pytest.fail("population read refreshed a row")

    repository = SqlAlchemyCurrentEntitlementEvidenceRepository(Session)
    with pytest.raises(CurrentEntitlementEvidenceStorageError) as caught:
        repository.get_latest_population(1)
    assert str(caught.value) == "current entitlement evidence storage unavailable"
    assert events == ["enter", "begin", "execute", "rollback", "close"]


def test_latest_population_is_one_view_when_separate_transaction_commits_during_read(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'consistent.db'}")
    User.__table__.create(engine)
    CurrentEntitlementEvidence.__table__.create(engine)
    with engine.begin() as connection:
        connection.execute(text("PRAGMA journal_mode=WAL"))
    writer_factory = sessionmaker(bind=engine, expire_on_commit=False)
    writer = SqlAlchemyCurrentEntitlementEvidenceRepository(writer_factory)
    original = item(subject="a" * 64, identity=IdentityClass.FULL)
    concurrent = item(subject="c" * 64, identity=IdentityClass.FULL)
    add_user(writer_factory, "a" * 64)
    add_user(writer_factory, "c" * 64)
    writer.append(original)

    class BufferedResult:
        def __init__(self, rows):
            self._rows = rows

        def all(self):
            return self._rows

    class InterleavingSession(Session):
        interleaved = False

        def execute(self, statement, *args, **kwargs):
            result = super().execute(statement, *args, **kwargs)
            rows = result.all()
            if not self.interleaved:
                self.interleaved = True
                writer.append(concurrent)
            return BufferedResult(rows)

    reader_factory = sessionmaker(bind=engine, class_=InterleavingSession, expire_on_commit=False)
    reader = SqlAlchemyCurrentEntitlementEvidenceRepository(reader_factory)
    assert reader.get_latest_population(2) == CompleteLatestEntitlementPopulation((original,), 2, ("a" * 64,))
    assert writer.get_latest_population(2) == CompleteLatestEntitlementPopulation(
        (original, concurrent),
        2,
        ("a" * 64, "c" * 64),
    )

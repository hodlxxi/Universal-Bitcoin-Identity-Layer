from dataclasses import replace
from datetime import datetime, timezone
import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.models import Base, CanonicalRootRegistrationBindingRow
from app.services.canonical_root_registration_binding import (
    BINDING_SCHEMA,
    BINDING_VERSION,
    CanonicalRootRegistrationBinding,
    RootRegistrationBindingLifecycle as Lifecycle,
)
from app.services.canonical_root_registration_binding_storage import (
    CanonicalRootRegistrationBindingStorageError,
    SqlAlchemyCanonicalRootRegistrationBindingRepository,
)
from app.services.trusted_covenant_registration import trusted_registration_sha256
from app.services.trusted_covenant_registration import TrustedCovenantRegistrationLifecycle


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


registration_fixtures = _module("registration_fixtures_for_root_binding_storage", "tests/unit/test_trusted_covenant_registration.py")
genesis_fixtures = _module("genesis_fixtures_for_root_binding_storage", "tests/unit/test_canonical_genesis_record.py")
NOW = datetime(2026, 8, 11, tzinfo=timezone.utc)


class GenesisRepository:
    def __init__(self, records):
        self.records = records

    def list_for_graph(self, _graph):
        return self.records


class RegistrationRepository:
    def __init__(self, values):
        self.values = {value.registration_id: value for value in values}

    def get(self, identifier):
        return self.values.get(identifier)


def binding(registration, record, *, identifier="20000000-0000-4000-8000-000000000001", state=Lifecycle.EFFECTIVE):
    return CanonicalRootRegistrationBinding(
        BINDING_SCHEMA,
        BINDING_VERSION,
        identifier,
        record.graph_or_protocol_id,
        record.identity_anchor.x_only_public_key,
        registration.registration_id,
        trusted_registration_sha256(registration),
        state,
        NOW,
        NOW,
        None if state is Lifecycle.PROPOSED else NOW,
        "20000000-0000-4000-8000-000000000099" if state is Lifecycle.SUPERSEDED else None,
    )


@pytest.fixture
def storage():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    record = genesis_fixtures.record()
    registration = registration_fixtures.registration()
    repository = SqlAlchemyCanonicalRootRegistrationBindingRepository(
        sessionmaker(bind=engine, expire_on_commit=False),
        genesis_repository=GenesisRepository((record,)),
        trusted_registration_repository=RegistrationRepository((registration,)),
    )
    return engine, repository, record, registration


def test_model_and_migration_have_partial_effective_uniqueness():
    indexes = {index.name: index for index in CanonicalRootRegistrationBindingRow.__table__.indexes}
    assert indexes["uq_root_registration_binding_effective_root"].unique
    sql = Path("migrations/2026-08-11_canonical_root_registration_binding_v1.sql").read_text()
    assert "WHERE lifecycle_state = 'effective'" in sql
    assert "effective_at >= created_at AND lifecycle_changed_at >= effective_at" in sql
    assert not any(word in sql.upper() for word in ("INSERT INTO", "DROP TABLE", "DELETE FROM"))


def test_append_get_resolve_round_trip(storage):
    _, repository, record, registration = storage
    value = binding(registration, record)
    repository.append(value, evaluated_at=NOW)
    assert repository.get(value.binding_id) == value
    assert repository.list_for_root(value.graph_or_protocol_id, value.root_x_only_public_key) == (value,)
    assert repository.resolve_effective(
        value.graph_or_protocol_id, value.root_x_only_public_key, evaluated_at=NOW
    ) == value


def test_zero_and_multiple_effective_results_fail_closed(storage, monkeypatch):
    _, repository, record, registration = storage
    value = binding(registration, record)
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.resolve_effective(value.graph_or_protocol_id, value.root_x_only_public_key, evaluated_at=NOW)
    monkeypatch.setattr(repository, "_rows", lambda _filters: (value, value))
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.resolve_effective(value.graph_or_protocol_id, value.root_x_only_public_key, evaluated_at=NOW)


def test_missing_and_changed_registration_fail_closed(storage):
    _, repository, record, registration = storage
    value = binding(registration, record)
    repository._trusted_registration_repository.values.clear()
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.append(value, evaluated_at=NOW)
    repository._trusted_registration_repository.values[registration.registration_id] = registration
    repository.append(value, evaluated_at=NOW)
    repository._trusted_registration_repository.values.clear()
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.resolve_effective(value.graph_or_protocol_id, value.root_x_only_public_key, evaluated_at=NOW)


def test_wrong_digest_and_root_cannot_be_appended(storage):
    _, repository, record, registration = storage
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.append(
            replace(binding(registration, record), trusted_registration_sha256="f" * 64), evaluated_at=NOW
        )
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.append(
            replace(binding(registration, record), root_x_only_public_key="f" * 64), evaluated_at=NOW
        )


def test_inactive_registration_cannot_be_appended(storage):
    _, repository, record, _ = storage
    inactive = registration_fixtures.registration(state=TrustedCovenantRegistrationLifecycle.REVOKED)
    repository._trusted_registration_repository.values = {inactive.registration_id: inactive}
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.append(binding(inactive, record), evaluated_at=NOW)


def test_proposed_binding_can_be_activated_transactionally(storage):
    _, repository, record, registration = storage
    proposed = binding(registration, record, state=Lifecycle.PROPOSED)
    repository.append(proposed, evaluated_at=NOW)
    effective = replace(
        proposed,
        lifecycle_state=Lifecycle.EFFECTIVE,
        lifecycle_changed_at=NOW,
        effective_at=NOW,
    )
    repository.transition(proposed.binding_id, effective, evaluated_at=NOW)
    assert repository.resolve_effective(
        effective.graph_or_protocol_id, effective.root_x_only_public_key, evaluated_at=NOW
    ) == effective


@pytest.mark.parametrize("state", (Lifecycle.DISPUTED, Lifecycle.REVOKED))
def test_effective_binding_can_be_deactivated_and_retained(storage, state):
    _, repository, record, registration = storage
    effective = binding(registration, record)
    repository.append(effective, evaluated_at=NOW)
    transitioned = replace(effective, lifecycle_state=state)
    repository.transition(effective.binding_id, transitioned, evaluated_at=NOW)
    assert repository.get(effective.binding_id) == transitioned
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.resolve_effective(
            effective.graph_or_protocol_id, effective.root_x_only_public_key, evaluated_at=NOW
        )


def test_binding_can_be_revoked_after_registration_becomes_inactive(storage):
    _, repository, record, registration = storage
    effective = binding(registration, record)
    repository.append(effective, evaluated_at=NOW)
    inactive = registration_fixtures.registration(
        state=TrustedCovenantRegistrationLifecycle.REVOKED
    )
    repository._trusted_registration_repository.values = {inactive.registration_id: inactive}
    revoked = replace(effective, lifecycle_state=Lifecycle.REVOKED)
    repository.transition(effective.binding_id, revoked, evaluated_at=NOW)
    assert repository.get(effective.binding_id) == revoked


def test_never_effective_proposal_can_be_disputed_without_activation_time(storage):
    _, repository, record, registration = storage
    proposed = binding(registration, record, state=Lifecycle.PROPOSED)
    repository.append(proposed, evaluated_at=NOW)
    disputed = replace(proposed, lifecycle_state=Lifecycle.DISPUTED)
    repository.transition(proposed.binding_id, disputed, evaluated_at=NOW)
    assert repository.get(proposed.binding_id).effective_at is None


def test_effective_binding_can_rotate_atomically_and_retain_history(storage):
    _, repository, record, registration = storage
    other = replace(registration, registration_id="30000000-0000-4000-8000-000000000003")
    repository._trusted_registration_repository.values[other.registration_id] = other
    current = binding(registration, record)
    repository.append(current, evaluated_at=NOW)
    replacement = binding(
        other, record, identifier="20000000-0000-4000-8000-000000000005"
    )
    superseded = replace(
        current,
        lifecycle_state=Lifecycle.SUPERSEDED,
        superseded_by_binding_id=replacement.binding_id,
    )
    repository.transition(
        current.binding_id,
        superseded,
        evaluated_at=NOW,
        replacement=replacement,
    )
    assert repository.get(current.binding_id) == superseded
    assert repository.resolve_effective(
        current.graph_or_protocol_id, current.root_x_only_public_key, evaluated_at=NOW
    ) == replacement


def test_failed_rotation_rolls_back_original_effective_binding(storage):
    _, repository, record, registration = storage
    current = binding(registration, record)
    repository.append(current, evaluated_at=NOW)
    reserved = binding(
        registration,
        record,
        identifier="20000000-0000-4000-8000-000000000006",
        state=Lifecycle.PROPOSED,
    )
    repository.append(reserved, evaluated_at=NOW)
    invalid_replacement = replace(
        reserved,
        lifecycle_state=Lifecycle.EFFECTIVE,
        effective_at=NOW,
    )
    superseded = replace(
        current,
        lifecycle_state=Lifecycle.SUPERSEDED,
        superseded_by_binding_id=invalid_replacement.binding_id,
    )
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.transition(
            current.binding_id,
            superseded,
            evaluated_at=NOW,
            replacement=invalid_replacement,
        )
    assert repository.get(current.binding_id) == current


def test_effective_uniqueness_and_historical_coexistence(storage):
    _, repository, record, registration = storage
    first = binding(registration, record)
    repository.append(first, evaluated_at=NOW)
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.append(
            binding(registration, record, identifier="20000000-0000-4000-8000-000000000002"),
            evaluated_at=NOW,
        )
    proposed = binding(
        registration,
        record,
        identifier="20000000-0000-4000-8000-000000000003",
        state=Lifecycle.PROPOSED,
    )
    repository.append(proposed, evaluated_at=NOW)
    assert set(repository.list_for_root(first.graph_or_protocol_id, first.root_x_only_public_key)) == {
        first, proposed
    }


def test_tampered_projection_fails_closed(storage):
    engine, repository, record, registration = storage
    value = binding(registration, record)
    repository.append(value, evaluated_at=NOW)
    with engine.begin() as connection:
        connection.execute(text("PRAGMA ignore_check_constraints = ON"))
        connection.execute(text("UPDATE canonical_root_registration_bindings SET trusted_registration_sha256=:v"), {"v": "f" * 64})
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.get(value.binding_id)


def test_tampered_canonical_json_and_invalidated_genesis_fail_closed(storage):
    engine, repository, record, registration = storage
    value = binding(registration, record)
    repository.append(value, evaluated_at=NOW)
    repository._genesis_repository.records = ()
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.resolve_effective(value.graph_or_protocol_id, value.root_x_only_public_key, evaluated_at=NOW)
    with engine.begin() as connection:
        connection.execute(text("UPDATE canonical_root_registration_bindings SET canonical_record_json='{}'"))
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.get(value.binding_id)


def test_semantically_equal_noncanonical_json_fails_closed(storage):
    engine, repository, record, registration = storage
    value = binding(registration, record)
    repository.append(value, evaluated_at=NOW)
    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE canonical_root_registration_bindings "
                "SET canonical_record_json = replace(canonical_record_json, ',', ', ')"
            )
        )
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        repository.get(value.binding_id)


def test_multiple_active_registrations_do_not_create_order_selection(storage):
    _, repository, record, registration = storage
    other = replace(registration, registration_id="30000000-0000-4000-8000-000000000002")
    repository._trusted_registration_repository.values[other.registration_id] = other
    chosen = binding(registration, record)
    repository.append(chosen, evaluated_at=NOW)
    assert repository.resolve_effective(
        chosen.graph_or_protocol_id, chosen.root_x_only_public_key, evaluated_at=NOW
    ).trusted_registration_id == registration.registration_id


def test_database_constraint_rejects_second_effective_row(storage):
    engine, repository, record, registration = storage
    value = binding(registration, record)
    repository.append(value, evaluated_at=NOW)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        row = session.query(CanonicalRootRegistrationBindingRow).one()
        values = {column.name: getattr(row, column.name) for column in row.__table__.columns}
        values.update(
            binding_id="20000000-0000-4000-8000-000000000004",
            canonical_binding_sha256="e" * 64,
        )
        session.add(CanonicalRootRegistrationBindingRow(**values))
        with pytest.raises(IntegrityError):
            session.commit()

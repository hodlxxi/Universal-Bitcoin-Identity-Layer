from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path

import pytest

from app.services.canonical_genesis_record import evaluate_canonical_genesis
from app.services.canonical_root_registration_binding import (
    BINDING_SCHEMA,
    BINDING_VERSION,
    CanonicalRootRegistrationBinding,
    InvalidCanonicalRootRegistrationBinding,
    RootRegistrationBindingLifecycle as Lifecycle,
    canonical_root_registration_binding_bytes,
    canonical_root_registration_binding_sha256,
    parse_canonical_root_registration_binding,
    validate_binding_sources,
    validate_root_registration_binding_transition,
)
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistrationLifecycle,
    trusted_registration_sha256,
)


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


registration_fixtures = _module("registration_fixtures_for_root_binding", "tests/unit/test_trusted_covenant_registration.py")
genesis_fixtures = _module("genesis_fixtures_for_root_binding", "tests/unit/test_canonical_genesis_record.py")
NOW = datetime(2026, 8, 11, tzinfo=timezone.utc)


def sources():
    record = genesis_fixtures.record()
    genesis = evaluate_canonical_genesis(
        (record,), graph_or_protocol_id=record.graph_or_protocol_id, evaluated_at=record.effective_at
    )
    registration = registration_fixtures.registration()
    return genesis, registration


def binding(*, state=Lifecycle.EFFECTIVE, identifier="10000000-0000-4000-8000-000000000001"):
    genesis, registration = sources()
    effective = None if state is Lifecycle.PROPOSED else NOW
    successor = "10000000-0000-4000-8000-000000000099" if state is Lifecycle.SUPERSEDED else None
    return CanonicalRootRegistrationBinding(
        BINDING_SCHEMA,
        BINDING_VERSION,
        identifier,
        genesis.graph_or_protocol_id,
        genesis.x_only_public_key,
        registration.registration_id,
        trusted_registration_sha256(registration),
        state,
        NOW,
        NOW,
        effective,
        successor,
    )


def test_exact_round_trip_digest_and_source_validation():
    value = binding()
    genesis, registration = sources()
    assert parse_canonical_root_registration_binding(canonical_root_registration_binding_bytes(value)) == value
    assert len(canonical_root_registration_binding_sha256(value)) == 64
    assert validate_binding_sources(
        value, genesis_evaluation=genesis, trusted_registration=registration
    ) == (value, registration)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("binding_id", "NOT-A-UUID"),
        ("root_x_only_public_key", "A" * 64),
        ("trusted_registration_sha256", "0" * 63),
        ("created_at", NOW.replace(tzinfo=None)),
        ("created_at", NOW.replace(microsecond=1)),
        ("lifecycle_state", "effective"),
    ),
)
def test_malformed_values_fail(field, value):
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        replace(binding(), **{field: value})


def test_parser_rejects_nonexact_duplicate_and_numeric_json():
    payload = json.loads(canonical_root_registration_binding_bytes(binding()))
    payload["extra"] = None
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        parse_canonical_root_registration_binding(payload)
    raw = canonical_root_registration_binding_bytes(binding()).decode()
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        parse_canonical_root_registration_binding(raw[:-1] + ',"binding_id":"duplicate"}')
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        parse_canonical_root_registration_binding(raw.replace('"effective"', "1.0"))


def test_parser_rejects_noncanonical_whitespace_and_key_order():
    raw = canonical_root_registration_binding_bytes(binding()).decode()
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        parse_canonical_root_registration_binding(raw.replace(",", ", ", 1))
    payload = json.loads(raw)
    reordered = json.dumps(dict(reversed(tuple(payload.items()))), separators=(",", ":"), ensure_ascii=True)
    assert reordered != raw
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        parse_canonical_root_registration_binding(reordered)


def test_fixed_string_fields_require_exact_str():
    class Text(str):
        pass

    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        replace(binding(), schema=Text(BINDING_SCHEMA))
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        replace(binding(), binding_version=Text(BINDING_VERSION))


def test_construction_rejects_binding_subclasses():
    class BindingSubclass(CanonicalRootRegistrationBinding):
        pass

    value = binding()
    with pytest.raises(InvalidCanonicalRootRegistrationBinding, match="binding type"):
        BindingSubclass(
            *(getattr(value, field) for field in CanonicalRootRegistrationBinding.__dataclass_fields__)
        )


@pytest.mark.parametrize("state", tuple(Lifecycle))
def test_each_minimal_lifecycle_shape_is_canonical(state):
    assert binding(state=state).lifecycle_state is state


def test_superseded_binding_enforces_effective_chronology():
    value = binding(state=Lifecycle.SUPERSEDED)
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        replace(value, effective_at=NOW - timedelta(seconds=1))
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        replace(value, effective_at=NOW + timedelta(seconds=1))


def test_lifecycle_transitions_enforce_identity_and_terminal_states():
    proposed = binding(state=Lifecycle.PROPOSED)
    effective = binding(state=Lifecycle.EFFECTIVE)
    validate_root_registration_binding_transition(proposed, effective)
    revoked = replace(effective, lifecycle_state=Lifecycle.REVOKED, lifecycle_changed_at=NOW + timedelta(seconds=1))
    validate_root_registration_binding_transition(effective, revoked)
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        validate_root_registration_binding_transition(revoked, effective)
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        validate_root_registration_binding_transition(
            proposed, replace(effective, root_x_only_public_key="f" * 64)
        )


def test_never_effective_proposal_keeps_effective_at_empty_when_deactivated():
    proposed = binding(state=Lifecycle.PROPOSED)
    disputed = replace(proposed, lifecycle_state=Lifecycle.DISPUTED)
    revoked = replace(proposed, lifecycle_state=Lifecycle.REVOKED)
    validate_root_registration_binding_transition(proposed, disputed)
    validate_root_registration_binding_transition(proposed, revoked)
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        validate_root_registration_binding_transition(
            proposed,
            replace(disputed, effective_at=NOW),
        )


def test_genesis_and_registration_disagreement_fail_closed():
    value = binding()
    genesis, registration = sources()
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        validate_binding_sources(
            replace(value, root_x_only_public_key="f" * 64),
            genesis_evaluation=genesis,
            trusted_registration=registration,
        )
    inactive = registration_fixtures.registration(
        state=TrustedCovenantRegistrationLifecycle.REVOKED
    )
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        validate_binding_sources(
            replace(
                value,
                trusted_registration_sha256=trusted_registration_sha256(inactive),
            ),
            genesis_evaluation=genesis,
            trusted_registration=inactive,
        )
    with pytest.raises(InvalidCanonicalRootRegistrationBinding):
        validate_binding_sources(
            replace(value, trusted_registration_sha256="f" * 64),
            genesis_evaluation=genesis,
            trusted_registration=registration,
        )


def test_contract_has_selection_fields_only():
    assert set(CanonicalRootRegistrationBinding.__dataclass_fields__) == {
        "schema", "binding_version", "binding_id", "graph_or_protocol_id",
        "root_x_only_public_key", "trusted_registration_id", "trusted_registration_sha256",
        "lifecycle_state", "created_at", "lifecycle_changed_at", "effective_at",
        "superseded_by_binding_id",
    }

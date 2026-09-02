from dataclasses import replace
from datetime import datetime, timezone
import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base
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
from app.services.legacy_covenant_canonical_migration_planner import (
    LegacyCovenantCanonicalMigrationPlanner,
    LegacyWalletObservation,
    LegacyWalletOutpoint,
    MigrationDecision,
    native_p2wsh_script_pubkey,
)
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistrationLifecycle,
    trusted_registration_sha256,
)
from scripts.legacy_covenant_canonical_migration_plan import _load_canonical_snapshot

NOW = datetime(2026, 8, 11, tzinfo=timezone.utc)


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


registration_fixtures = _module(
    "registration_fixtures_for_legacy_root_authority",
    "tests/unit/test_trusted_covenant_registration.py",
)
genesis_fixtures = _module(
    "genesis_fixtures_for_legacy_root_authority",
    "tests/unit/test_canonical_genesis_record.py",
)


class GenesisRepository:
    def __init__(self, records):
        self.records = records

    def list_for_graph(self, _graph):
        return self.records


class EdgeRepository:
    def list_for_graph(self, _graph):
        return ()


class RegistrationRepository:
    def __init__(self, registrations):
        self.values = {value.registration_id: value for value in registrations}

    def get(self, identifier):
        return self.values.get(identifier)


def _binding(registration, record, *, state=Lifecycle.EFFECTIVE, identifier=None):
    return CanonicalRootRegistrationBinding(
        BINDING_SCHEMA,
        BINDING_VERSION,
        identifier or "40000000-0000-4000-8000-000000000001",
        record.graph_or_protocol_id,
        record.identity_anchor.x_only_public_key,
        registration.registration_id,
        trusted_registration_sha256(registration),
        state,
        NOW,
        NOW,
        None if state is Lifecycle.PROPOSED else NOW,
        ("40000000-0000-4000-8000-000000000099" if state is Lifecycle.SUPERSEDED else None),
    )


@pytest.fixture
def authority():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    record = genesis_fixtures.record()
    registration = registration_fixtures.registration()
    genesis_repository = GenesisRepository((record,))
    registration_repository = RegistrationRepository((registration,))
    root_repository = SqlAlchemyCanonicalRootRegistrationBindingRepository(
        sessionmaker(bind=engine, expire_on_commit=False),
        genesis_repository=genesis_repository,
        trusted_registration_repository=registration_repository,
    )
    try:
        yield (
            root_repository,
            genesis_repository,
            EdgeRepository(),
            registration_repository,
            record,
            registration,
        )
    finally:
        engine.dispose()


def _snapshot(authority):
    root, genesis, edges, registrations, _, _ = authority
    return _load_canonical_snapshot(
        genesis_repository=genesis,
        edge_repository=edges,
        registration_repository=registrations,
        root_binding_repository=root,
        evaluated_at=NOW,
    )


def _observed_wallet(registration):
    scripts = (
        registration.mirrored_pair.earlier_leg.raw_script_hex,
        registration.mirrored_pair.later_leg.raw_script_hex,
    )
    amount = registration.outpoints[0].amount_sats
    return LegacyWalletObservation(
        "root-observation-wallet",
        tuple(f"wsh(raw({script}))#checksum" for script in scripts),
        (
            LegacyWalletOutpoint(
                "a" * 64,
                0,
                amount,
                6,
                native_p2wsh_script_pubkey(scripts[0]),
            ),
            LegacyWalletOutpoint(
                "b" * 64,
                1,
                amount,
                6,
                native_p2wsh_script_pubkey(scripts[1]),
            ),
        ),
    )


def test_effective_source_validated_root_registration_is_already_canonical(authority):
    root, _, _, _, record, registration = authority
    root.append(_binding(registration, record), evaluated_at=NOW)
    plan = LegacyCovenantCanonicalMigrationPlanner().plan(
        (_observed_wallet(registration),),
        _snapshot(authority),
    )
    assert len(plan.relationships) == 1
    assert plan.relationships[0].decision is MigrationDecision.ALREADY_CANONICAL


@pytest.mark.parametrize(
    "state",
    (
        Lifecycle.REVOKED,
        Lifecycle.SUPERSEDED,
        Lifecycle.DISPUTED,
        Lifecycle.PROPOSED,
    ),
)
def test_historical_binding_with_active_registration_is_not_current_root_authority(
    authority,
    state,
):
    root, _, _, _, record, registration = authority
    historical = _binding(registration, record, state=state)
    root.append(historical, evaluated_at=NOW)
    assert registration.lifecycle_state is TrustedCovenantRegistrationLifecycle.ACTIVE
    assert root.list_for_root(record.graph_or_protocol_id, record.identity_anchor.x_only_public_key) == (historical,)
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        _snapshot(authority)


def test_multiple_effective_root_bindings_fail_closed(authority, monkeypatch):
    root, _, _, _, record, registration = authority
    first = _binding(registration, record)
    second = _binding(
        registration,
        record,
        identifier="40000000-0000-4000-8000-000000000002",
    )
    monkeypatch.setattr(root, "_rows", lambda _filters: (first, second))
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        _snapshot(authority)


def test_effective_root_binding_digest_mismatch_fails_closed(authority, monkeypatch):
    root, _, _, _, record, registration = authority
    mismatched = replace(
        _binding(registration, record),
        trusted_registration_sha256="f" * 64,
    )
    monkeypatch.setattr(root, "_rows", lambda _filters: (mismatched,))
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        _snapshot(authority)


def test_effective_root_binding_with_inactive_registration_fails_closed(
    authority,
    monkeypatch,
):
    root, _, _, registrations, record, _ = authority
    inactive = registration_fixtures.registration(state=TrustedCovenantRegistrationLifecycle.REVOKED)
    effective = _binding(inactive, record)
    registrations.values = {inactive.registration_id: inactive}
    monkeypatch.setattr(root, "_rows", lambda _filters: (effective,))
    with pytest.raises(CanonicalRootRegistrationBindingStorageError):
        _snapshot(authority)


def test_collector_never_uses_historical_root_inventory_as_authority():
    source = Path("scripts/legacy_covenant_canonical_migration_plan.py").read_text()
    canonical_loader = source[source.index("def _load_canonical_snapshot") : source.index("def _collect_live")]
    assert ".resolve_effective(" in canonical_loader
    assert ".list_for_root(" not in canonical_loader
    assert canonical_loader.count("evaluated_at=evaluated_at") == 2
    assert "datetime.now" not in canonical_loader

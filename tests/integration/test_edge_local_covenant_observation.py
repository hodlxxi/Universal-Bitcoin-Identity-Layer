"""Boundary regression: authority reads finish before injected Bitcoin observation."""

from datetime import datetime, timezone
import importlib.util
from pathlib import Path

import app.services.edge_local_covenant_observation as service
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from app.models import Base, CanonicalCovenantFundingOutpointRow, CanonicalCovenantFundingSetRow
from app.services.canonical_controlling_registration import (
    ControllingRegistrationSelection,
    ControllingRegistrationSelectionSource,
)
from app.services.covenant_relation import (
    EVALUATION_SCHEMA,
    OBSERVATION_SCHEMA,
    CovenantRelationEvaluation,
    CovenantRelationObservation,
)
from app.services.canonical_covenant_funding_set_storage import (
    SqlAlchemyCanonicalCovenantFundingSetRepository,
)


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixtures = _module("funding_fixtures_for_edge_local_integration", "tests/unit/test_canonical_covenant_funding_set.py")
NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)


def test_repository_read_precedes_bitcoin_observation_and_no_write_api_is_used(monkeypatch):
    registration = fixtures.registration()
    events = []
    selection = ControllingRegistrationSelection(
        "graph",
        registration.subject_xonly_pubkey,
        ControllingRegistrationSelectionSource.CANONICAL_ADMISSION_EDGE,
        "00000000-0000-4000-8000-000000000020",
        "9" * 64,
        registration,
    )
    monkeypatch.setattr(service, "resolve_controlling_registration", lambda *a, **k: selection)

    class Repository:
        def resolve_effective(self, registration_id):
            events.append("repository_read_closed")
            return fixtures.funding()

    class Observer:
        def observe(self, outpoints):
            assert events == ["repository_read_closed"]
            events.append("bitcoin_observation")
            observations = tuple(
                CovenantRelationObservation(
                    OBSERVATION_SCHEMA,
                    x.subject_pubkey,
                    x.counterparty_pubkey,
                    x.direction,
                    x.txid,
                    x.vout,
                    x.amount_sats,
                    x.script_sha256,
                    x.descriptor_sha256,
                    1,
                    True,
                )
                for x in outpoints
            )
            return CovenantRelationEvaluation(
                EVALUATION_SCHEMA,
                "bitcoin",
                registration.subject_xonly_pubkey,
                registration.counterparty_xonly_pubkey,
                NOW,
                900000,
                observations,
            )

    result = service.observe_edge_local_covenant_relation(
        "graph",
        registration.subject_xonly_pubkey,
        evaluated_at=NOW,
        genesis_repository=object(),
        admission_edge_repository=object(),
        root_registration_binding_repository=object(),
        trusted_registration_repository=object(),
        funding_set_repository=Repository(),
        observer=Observer(),
    )
    assert events == ["repository_read_closed", "bitcoin_observation"]
    assert result.qualifying_observation_count == 5
    assert result.observed_at == NOW


def test_real_repository_session_closes_before_rpc_and_operation_does_not_write(monkeypatch, tmp_path):
    registration = fixtures.registration()
    selection = ControllingRegistrationSelection(
        "graph",
        registration.subject_xonly_pubkey,
        ControllingRegistrationSelectionSource.CANONICAL_ADMISSION_EDGE,
        "00000000-0000-4000-8000-000000000020",
        "9" * 64,
        registration,
    )
    monkeypatch.setattr(service, "resolve_controlling_registration", lambda *a, **k: selection)
    engine = create_engine(f"sqlite:///{tmp_path / 'edge-local.db'}")
    Base.metadata.create_all(engine)

    class TrackingSession(Session):
        open_count = 0

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            type(self).open_count += 1

        def close(self):
            try:
                super().close()
            finally:
                type(self).open_count -= 1

    factory = sessionmaker(bind=engine, class_=TrackingSession, expire_on_commit=False)

    class Registrations:
        def get(self, identifier):
            return registration if identifier == registration.registration_id else None

    repository = SqlAlchemyCanonicalCovenantFundingSetRepository(
        factory,
        trusted_registration_repository=Registrations(),
    )
    repository.append(fixtures.funding())

    def counts():
        with factory() as session:
            return (
                session.query(CanonicalCovenantFundingSetRow).count(),
                session.query(CanonicalCovenantFundingOutpointRow).count(),
            )

    before = counts()

    class Observer:
        def observe(self, outpoints):
            assert TrackingSession.open_count == 0
            observations = tuple(
                CovenantRelationObservation(
                    OBSERVATION_SCHEMA,
                    x.subject_pubkey,
                    x.counterparty_pubkey,
                    x.direction,
                    x.txid,
                    x.vout,
                    x.amount_sats,
                    x.script_sha256,
                    x.descriptor_sha256,
                    1,
                    True,
                )
                for x in outpoints
            )
            return CovenantRelationEvaluation(
                EVALUATION_SCHEMA,
                "bitcoin",
                registration.subject_xonly_pubkey,
                registration.counterparty_xonly_pubkey,
                NOW,
                900000,
                observations,
            )

    result = service.observe_edge_local_covenant_relation(
        "graph",
        registration.subject_xonly_pubkey,
        evaluated_at=NOW,
        genesis_repository=object(),
        admission_edge_repository=object(),
        root_registration_binding_repository=object(),
        trusted_registration_repository=object(),
        funding_set_repository=repository,
        observer=Observer(),
    )
    assert result.qualifying_observation_count == 5
    assert result.observed_at == NOW
    assert counts() == before
    assert TrackingSession.open_count == 0

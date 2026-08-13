from contextlib import contextmanager
from datetime import datetime, timezone
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.services.canonical_root_entitlement_refresh as service
from app.models import CurrentEntitlementEvidence
from app.services.canonical_controlling_registration import ControllingRegistrationSelectionSource
from app.services.canonical_root_entitlement_materializer import CanonicalRootEntitlementMaterializer
from app.services.covenant_relation import CovenantRelationReason
from app.services.current_entitlement_evidence_storage import SqlAlchemyCurrentEntitlementEvidenceRepository
from app.services.edge_local_covenant_observation import EdgeLocalCovenantRelationResult

GRAPH = "hodlxxi.crt_membership_graph.v1"
SUBJECT = "a" * 64
NOW = datetime(2026, 8, 13, 12, tzinfo=timezone.utc)


class Guard:
    exclusive = True

    def __init__(self):
        self.subjects = []

    @contextmanager
    def hold(self, subject):
        self.subjects.append(subject)
        yield


def test_temporary_sqlite_append_then_exact_replay_is_unchanged(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'refresh.db'}")
    CurrentEntitlementEvidence.__table__.create(engine)
    repository = SqlAlchemyCurrentEntitlementEvidenceRepository(
        sessionmaker(bind=engine, expire_on_commit=False)
    )
    relation = EdgeLocalCovenantRelationResult(
        GRAPH,
        SUBJECT,
        "b" * 64,
        ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING,
        "00000000-0000-4000-8000-000000000001",
        "1" * 64,
        "00000000-0000-4000-8000-000000000002",
        "2" * 64,
        "00000000-0000-4000-8000-000000000003",
        "3" * 64,
        5,
        5,
        NOW,
        900000,
        300000,
        300000,
        True,
        CovenantRelationReason.FULL_RELATION_SATISFIED,
        "4" * 64,
    )
    observations = []
    monkeypatch.setattr(
        service,
        "observe_edge_local_covenant_relation",
        lambda graph, subject, **kwargs: observations.append((graph, subject, kwargs)) or relation,
    )
    identifiers = iter(
        [uuid.UUID("00000000-0000-4000-8000-000000000010")]
    )
    monkeypatch.setattr(
        service,
        "CanonicalRootEntitlementMaterializer",
        lambda repo: CanonicalRootEntitlementMaterializer(
            repo, clock=lambda: NOW, uuid_factory=lambda: next(identifiers)
        ),
    )
    guard = Guard()
    common = dict(
        evaluated_at=NOW,
        mode=service.CanonicalRootEntitlementRefreshMode.COMMIT,
        genesis_repository=object(),
        admission_edge_repository=object(),
        root_registration_binding_repository=object(),
        trusted_registration_repository=object(),
        funding_set_repository=object(),
        evidence_repository=repository,
        execution_guard=guard,
    )
    appended = service.refresh_canonical_root_entitlement(GRAPH, SUBJECT, **common)
    unchanged = service.refresh_canonical_root_entitlement(GRAPH, SUBJECT, **common)

    assert appended.outcome is service.CanonicalRootEntitlementRefreshOutcome.APPENDED
    assert unchanged.outcome is service.CanonicalRootEntitlementRefreshOutcome.UNCHANGED
    assert appended.evidence == unchanged.evidence == repository.get_latest(SUBJECT)
    assert appended.append_performed is True and unchanged.append_performed is False
    assert guard.subjects == [SUBJECT, SUBJECT]
    assert len(observations) == 2
    assert set(CurrentEntitlementEvidence.metadata.tables) >= {"current_entitlement_evidence"}

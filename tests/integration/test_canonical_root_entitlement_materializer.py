from datetime import datetime, timedelta, timezone
from pathlib import Path
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import CurrentEntitlementEvidence
from app.services.action_authorization import IdentityClass
from app.services.canonical_controlling_registration import ControllingRegistrationSelectionSource
from app.services.canonical_root_entitlement_materializer import CanonicalRootEntitlementMaterializer
from app.services.covenant_relation import CovenantRelationReason
from app.services.current_entitlement import EntitlementDecision, EvidenceBackedCurrentEntitlementResolver
from app.services.current_entitlement_evidence_storage import SqlAlchemyCurrentEntitlementEvidenceRepository
from app.services.edge_local_covenant_observation import EdgeLocalCovenantRelationResult

GRAPH = "hodlxxi.crt_membership_graph.v1"
SUBJECT = "a" * 64
OTHER = "b" * 64
NOW = datetime(2026, 8, 13, 12, 0, 0, 123456, tzinfo=timezone.utc)


def relation(subject=SUBJECT, observed_at=None, *, full=True):
    return EdgeLocalCovenantRelationResult(
        GRAPH,
        subject,
        "c" * 64,
        ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING,
        str(uuid.uuid4()),
        "1" * 64,
        str(uuid.uuid4()),
        "2" * 64,
        str(uuid.uuid4()),
        "3" * 64,
        5,
        5 if full else 1,
        observed_at or NOW,
        900000,
        300000,
        300000 if full else 0,
        full,
        CovenantRelationReason.FULL_RELATION_SATISFIED if full else CovenantRelationReason.MISSING_OUTGOING,
        "4" * 64,
    )


def baseline(subject):
    return EntitlementDecision(subject, IdentityClass.LIMITED, False, "active_persisted_user")


def test_isolated_repository_resolver_expiry_newer_limited_and_subject_isolation(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'materializer.db'}")
    CurrentEntitlementEvidence.__table__.create(engine)
    repository = SqlAlchemyCurrentEntitlementEvidenceRepository(sessionmaker(bind=engine, expire_on_commit=False))

    full = CanonicalRootEntitlementMaterializer(
        repository, clock=lambda: NOW, uuid_factory=lambda: uuid.UUID(int=1)
    ).materialize(GRAPH, SUBJECT, relation())
    assert repository.get_latest(SUBJECT) == full
    assert repository.get_latest(OTHER) is None
    assert full.observed_at.microsecond == 123456
    assert (
        EvidenceBackedCurrentEntitlementResolver(
            repository, clock=lambda: NOW + timedelta(seconds=1), active_user_resolver=baseline
        )(SUBJECT).identity_class
        is IdentityClass.FULL
    )
    assert (
        EvidenceBackedCurrentEntitlementResolver(
            repository, clock=lambda: full.valid_until, active_user_resolver=baseline
        )(SUBJECT).identity_class
        is IdentityClass.LIMITED
    )

    newer_limited = CanonicalRootEntitlementMaterializer(
        repository,
        clock=lambda: NOW + timedelta(seconds=2),
        uuid_factory=lambda: uuid.UUID(int=2),
    ).materialize(GRAPH, SUBJECT, relation(observed_at=NOW + timedelta(seconds=2), full=False))
    other_full = CanonicalRootEntitlementMaterializer(
        repository,
        clock=lambda: NOW + timedelta(seconds=3),
        uuid_factory=lambda: uuid.UUID(int=3),
    ).materialize(GRAPH, OTHER, relation(OTHER, NOW + timedelta(seconds=3)))
    assert repository.get_latest(SUBJECT) == newer_limited
    assert repository.get_latest(OTHER) == other_full
    assert (
        EvidenceBackedCurrentEntitlementResolver(
            repository, clock=lambda: NOW + timedelta(seconds=4), active_user_resolver=baseline
        )(SUBJECT).identity_class
        is IdentityClass.LIMITED
    )


def test_materializer_has_no_active_or_publication_coupling():
    source = (Path(__file__).parents[2] / "app/services/canonical_root_entitlement_materializer.py").read_text()
    forbidden = (
        "get_rpc_connection",
        "listunspent",
        "scantxoutset",
        "descriptor",
        "wallet",
        "os.environ",
        "SPECIAL_USERS",
        "session_scope",
        "get_user_by_pubkey",
        "commit(",
        "flush(",
        "rollback(",
        "get_latest(",
        "blueprints",
        "scheduler",
    )
    assert not any(value in source for value in forbidden)

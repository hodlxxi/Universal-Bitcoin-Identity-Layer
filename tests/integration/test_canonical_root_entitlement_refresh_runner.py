from datetime import datetime, timezone
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import CurrentEntitlementEvidence
from app.services.canonical_admission_edge_storage import SqlAlchemyCanonicalAdmissionEdgeRepository
from app.services.canonical_controlling_registration import ControllingRegistrationSelectionSource
from app.services.canonical_covenant_funding_set_storage import SqlAlchemyCanonicalCovenantFundingSetRepository
from app.services.canonical_genesis_record_storage import SqlAlchemyCanonicalGenesisRecordRepository
from app.services.canonical_root_entitlement_materializer import CanonicalRootEntitlementMaterializer
from app.services.canonical_root_registration_binding_storage import (
    SqlAlchemyCanonicalRootRegistrationBindingRepository,
)
from app.services.current_entitlement_evidence_storage import SqlAlchemyCurrentEntitlementEvidenceRepository
from app.services.covenant_relation import CovenantRelationReason
from app.services.edge_local_covenant_observation import EdgeLocalCovenantRelationResult
from app.services.trusted_covenant_registration_storage import SqlAlchemyTrustedCovenantRegistrationRepository
import app.services.canonical_root_entitlement_refresh_runner as runner


def test_runtime_repository_adapter_is_usable_with_isolated_sqlite(tmp_path):
    """The runner's evidence adapter requires neither app factory nor live services."""
    engine = create_engine(f"sqlite:///{tmp_path / 'runner.db'}")
    CurrentEntitlementEvidence.__table__.create(engine)
    repository = SqlAlchemyCurrentEntitlementEvidenceRepository(sessionmaker(bind=engine, expire_on_commit=False))
    assert repository.get_latest("a" * 64) is None


def test_parser_and_guard_need_no_application_or_network(tmp_path):
    request = runner.parse_runner_argv(
        [
            "--graph",
            "hodlxxi.crt_membership_graph.v1",
            "--subject",
            "a" * 64,
            "--commit",
            "--lock-directory",
            str(tmp_path),
        ]
    )
    guard = runner.LinuxSubjectFileExecutionGuard(request.lock_directory)
    with guard.hold(request.subject_xonly_pubkey):
        assert guard.exclusive is True


@pytest.mark.parametrize("limited", [False, True])
def test_one_shot_runner_composes_real_adapters_append_then_unchanged(tmp_path, monkeypatch, limited):
    engine = create_engine(f"sqlite:///{tmp_path / 'composed.db'}")
    CurrentEntitlementEvidence.__table__.create(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    genesis = SqlAlchemyCanonicalGenesisRecordRepository(factory)
    admission = SqlAlchemyCanonicalAdmissionEdgeRepository(factory)
    trusted = SqlAlchemyTrustedCovenantRegistrationRepository(factory)
    binding = SqlAlchemyCanonicalRootRegistrationBindingRepository(
        factory, genesis_repository=genesis, trusted_registration_repository=trusted
    )
    funding = SqlAlchemyCanonicalCovenantFundingSetRepository(factory, trusted_registration_repository=trusted)
    evidence = SqlAlchemyCurrentEntitlementEvidenceRepository(factory)
    graph, subject, now = "hodlxxi.crt_membership_graph.v1", "a" * 64, datetime(2026, 8, 13, 12, tzinfo=timezone.utc)
    relation = EdgeLocalCovenantRelationResult(
        graph,
        subject,
        "b" * 64,
        ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING,
        "00000000-0000-4000-8000-000000000001",
        "1" * 64,
        "00000000-0000-4000-8000-000000000002",
        "2" * 64,
        "00000000-0000-4000-8000-000000000003",
        "3" * 64,
        5,
        1 if limited else 5,
        now,
        900000,
        300000,
        0 if limited else 300000,
        not limited,
        CovenantRelationReason.MISSING_OUTGOING if limited else CovenantRelationReason.FULL_RELATION_SATISFIED,
        "4" * 64,
    )
    monkeypatch.setattr(
        "app.services.canonical_root_entitlement_refresh.observe_edge_local_covenant_relation",
        lambda *_args, **_kwargs: relation,
    )
    monkeypatch.setattr(
        "app.services.canonical_root_entitlement_refresh.CanonicalRootEntitlementMaterializer",
        lambda repo: CanonicalRootEntitlementMaterializer(
            repo,
            clock=lambda: now,
            uuid_factory=lambda: uuid.UUID("00000000-0000-4000-8000-000000000010"),
        ),
    )

    def dependencies(_mode):
        return {
            "genesis_repository": genesis,
            "admission_edge_repository": admission,
            "root_registration_binding_repository": binding,
            "trusted_registration_repository": trusted,
            "funding_set_repository": funding,
            "evidence_repository": evidence,
            "rpc_factory": lambda: (_ for _ in ()).throw(AssertionError("offline")),
        }

    request = runner.parse_runner_argv(
        [
            "--graph",
            graph,
            "--subject",
            subject,
            "--commit",
            "--lock-directory",
            str(tmp_path),
        ]
    )
    appended = runner.execute_request(request, dependency_factory=dependencies, clock=lambda: now)
    unchanged = runner.execute_request(request, dependency_factory=dependencies, clock=lambda: now)
    assert appended["outcome"] == "appended" and unchanged["outcome"] == "unchanged"
    assert appended["evidence_id"] == unchanged["evidence_id"]
    with factory() as session:
        assert session.query(CurrentEntitlementEvidence).count() == 1

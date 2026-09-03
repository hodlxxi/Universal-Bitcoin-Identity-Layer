from datetime import datetime, timedelta, timezone
import uuid

import pytest

from app.services.action_authorization import IdentityClass
from app.services.canonical_controlling_registration import (
    ControllingRegistrationSelectionSource,
)
from app.services.canonical_root_reciprocal_entitlement_materializer import (
    CanonicalRootReciprocalEntitlementMaterializationUnavailable,
    CanonicalRootReciprocalEntitlementMaterializer,
)
from app.services.covenant_relation import CovenantRelationReason
from app.services.edge_local_covenant_observation import (
    EdgeLocalCovenantRelationResult,
)

GRAPH = "hodlxxi.crt_membership_graph.v1"
ROOT = "1" * 64
OTHER = "2" * 64

NOW = datetime(
    2026,
    8,
    13,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)


def relation(**changes):
    values = dict(
        graph_or_protocol_id=GRAPH,
        subject_xonly_pubkey=ROOT,
        counterparty_xonly_pubkey=OTHER,
        controlling_selection_source=(ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING),
        selector_record_id=("00000000-0000-4000-8000-000000000001"),
        selector_record_sha256="3" * 64,
        trusted_registration_id=("00000000-0000-4000-8000-000000000002"),
        trusted_registration_sha256="4" * 64,
        funding_set_id=("00000000-0000-4000-8000-000000000003"),
        funding_set_sha256="5" * 64,
        recognized_outpoint_count=5,
        qualifying_observation_count=5,
        observed_at=NOW,
        observed_block_height=900000,
        incoming_sats=300000,
        outgoing_sats=300000,
        current_full_relation_satisfied=True,
        relation_reason=(CovenantRelationReason.FULL_RELATION_SATISFIED),
        relation_source_evidence_sha256="6" * 64,
    )
    values.update(changes)
    return EdgeLocalCovenantRelationResult(**values)


class Repository:
    def __init__(self):
        self.pairs = []

    def append_pair(self, value):
        self.pairs.append(value)


def ids():
    values = iter(
        (
            uuid.UUID("00000000-0000-4000-8000-000000000010"),
            uuid.UUID("00000000-0000-4000-8000-000000000011"),
        )
    )
    return lambda: next(values)


def test_balanced_relation_atomically_materializes_two_full_subjects():
    repository = Repository()

    result = CanonicalRootReciprocalEntitlementMaterializer(
        repository,
        clock=lambda: NOW,
        uuid_factory=ids(),
    ).materialize(
        GRAPH,
        ROOT,
        relation(),
    )

    assert len(repository.pairs) == 1

    root, reciprocal = repository.pairs[0]

    assert result.root_evidence == root
    assert result.reciprocal_evidence == reciprocal

    assert root.subject_pubkey == ROOT
    assert reciprocal.subject_pubkey == OTHER

    assert root.identity_class is IdentityClass.FULL
    assert reciprocal.identity_class is IdentityClass.FULL

    assert root.current_full_relation_satisfied is True
    assert reciprocal.current_full_relation_satisfied is True

    assert root.evidence_source != reciprocal.evidence_source

    assert root.observed_at == reciprocal.observed_at == NOW
    assert root.valid_until == reciprocal.valid_until
    assert root.created_at == reciprocal.created_at


def test_subject_relative_asymmetry_is_evaluated_independently():
    repository = Repository()

    result = CanonicalRootReciprocalEntitlementMaterializer(
        repository,
        clock=lambda: NOW,
        uuid_factory=ids(),
    ).materialize(
        GRAPH,
        ROOT,
        relation(
            incoming_sats=200000,
            outgoing_sats=300000,
        ),
    )

    assert result.root_evidence.identity_class is IdentityClass.FULL
    assert result.reciprocal_evidence.identity_class is IdentityClass.LIMITED


def test_stale_observation_fails_before_append():
    repository = Repository()

    with pytest.raises(CanonicalRootReciprocalEntitlementMaterializationUnavailable):
        CanonicalRootReciprocalEntitlementMaterializer(
            repository,
            clock=lambda: NOW + timedelta(seconds=61),
            uuid_factory=ids(),
        ).materialize(
            GRAPH,
            ROOT,
            relation(),
        )

    assert repository.pairs == []


def test_repository_without_atomic_pair_contract_is_rejected():
    with pytest.raises(CanonicalRootReciprocalEntitlementMaterializationUnavailable):
        CanonicalRootReciprocalEntitlementMaterializer(object())

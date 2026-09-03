from contextlib import contextmanager
from datetime import datetime, timezone
from threading import Lock

import pytest

import app.services.canonical_root_entitlement_refresh as service
from app.services.action_authorization import IdentityClass
from app.services.canonical_controlling_registration import (
    ControllingRegistrationSelectionSource,
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


def relation():
    return EdgeLocalCovenantRelationResult(
        GRAPH,
        ROOT,
        OTHER,
        (ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING),
        "00000000-0000-4000-8000-000000000001",
        "3" * 64,
        "00000000-0000-4000-8000-000000000002",
        "4" * 64,
        "00000000-0000-4000-8000-000000000003",
        "5" * 64,
        5,
        5,
        NOW,
        900000,
        300000,
        300000,
        True,
        CovenantRelationReason.FULL_RELATION_SATISFIED,
        "6" * 64,
    )


class Repository:
    def __init__(self):
        self.latest = {}
        self.pairs = []

    def get_latest(self, subject):
        return self.latest.get(subject)

    def append(self, item):
        self.latest[item.subject_pubkey] = item

    def append_pair(self, pair):
        self.pairs.append(pair)
        for item in pair:
            self.latest[item.subject_pubkey] = item


class Guard:
    exclusive = True

    def __init__(self):
        self.lock = Lock()

    def hold(self, _subject):
        lock = self.lock

        @contextmanager
        def held():
            with lock:
                yield

        return held()


def invoke(repository=None, mode=None):
    return service.refresh_canonical_root_entitlement(
        GRAPH,
        ROOT,
        evaluated_at=NOW,
        mode=(service.CanonicalRootEntitlementRefreshMode.COMMIT if mode is None else mode),
        genesis_repository=object(),
        admission_edge_repository=object(),
        root_registration_binding_repository=object(),
        trusted_registration_repository=object(),
        funding_set_repository=object(),
        evidence_repository=repository,
        execution_guard=(None if mode is service.CanonicalRootEntitlementRefreshMode.DRY_RUN else Guard()),
        materialize_reciprocal_counterparty=True,
        materializer_clock=lambda: NOW,
    )


@pytest.fixture(autouse=True)
def canonical_observation(monkeypatch):
    source = relation()

    monkeypatch.setattr(
        service,
        "observe_edge_local_covenant_relation",
        lambda *_args, **_kwargs: source,
    )

    return source


def test_first_commit_appends_root_and_counterparty_together():
    repository = Repository()

    result = invoke(repository)

    assert result.outcome is service.CanonicalRootEntitlementRefreshOutcome.APPENDED

    assert len(repository.pairs) == 1
    assert set(repository.latest) == {ROOT, OTHER}

    assert repository.latest[ROOT].identity_class is IdentityClass.FULL
    assert repository.latest[OTHER].identity_class is IdentityClass.FULL

    assert result.evidence == repository.latest[ROOT]


def test_exact_pair_replay_is_unchanged():
    repository = Repository()

    first = invoke(repository)
    second = invoke(repository)

    assert first.outcome is service.CanonicalRootEntitlementRefreshOutcome.APPENDED

    assert second.outcome is service.CanonicalRootEntitlementRefreshOutcome.UNCHANGED

    assert len(repository.pairs) == 1


def test_missing_counterparty_evidence_repairs_pair():
    repository = Repository()

    invoke(repository)

    del repository.latest[OTHER]

    repaired = invoke(repository)

    assert repaired.outcome is service.CanonicalRootEntitlementRefreshOutcome.APPENDED

    assert len(repository.pairs) == 2
    assert set(repository.latest) == {ROOT, OTHER}


def test_pair_dry_run_never_persists():
    result = invoke(
        None,
        mode=service.CanonicalRootEntitlementRefreshMode.DRY_RUN,
    )

    assert result.outcome is service.CanonicalRootEntitlementRefreshOutcome.PREVIEW

    assert result.evidence is None
    assert result.append_performed is False


def test_pair_commit_requires_atomic_repository_contract():
    class OldRepository:
        def get_latest(self, _subject):
            return None

        def append(self, _item):
            pytest.fail("single append must not be used")

    with pytest.raises(service.CanonicalRootEntitlementRefreshUnavailable):
        invoke(OldRepository())

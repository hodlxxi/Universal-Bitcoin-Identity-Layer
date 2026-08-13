from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from threading import Barrier, Lock, Thread
import uuid

import pytest

import app.services.canonical_root_entitlement_refresh as service
from app.services.action_authorization import IdentityClass
from app.services.canonical_controlling_registration import ControllingRegistrationSelectionSource
from app.services.canonical_root_entitlement_policy import evaluate_canonical_root_entitlement
from app.services.covenant_relation import CovenantRelationReason
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.edge_local_covenant_observation import EdgeLocalCovenantRelationResult

GRAPH = "hodlxxi.crt_membership_graph.v1"
SUBJECT = "3" * 64
NOW = datetime(2026, 8, 13, 12, tzinfo=timezone.utc)


def relation(**changes):
    values = dict(
        graph_or_protocol_id=GRAPH,
        subject_xonly_pubkey=SUBJECT,
        counterparty_xonly_pubkey="2" * 64,
        controlling_selection_source=ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING,
        selector_record_id="00000000-0000-4000-8000-000000000001",
        selector_record_sha256="4" * 64,
        trusted_registration_id="00000000-0000-4000-8000-000000000002",
        trusted_registration_sha256="5" * 64,
        funding_set_id="00000000-0000-4000-8000-000000000003",
        funding_set_sha256="6" * 64,
        recognized_outpoint_count=5,
        qualifying_observation_count=5,
        observed_at=NOW,
        observed_block_height=900000,
        incoming_sats=300000,
        outgoing_sats=300000,
        current_full_relation_satisfied=True,
        relation_reason=CovenantRelationReason.FULL_RELATION_SATISFIED,
        relation_source_evidence_sha256="7" * 64,
    )
    values.update(changes)
    return EdgeLocalCovenantRelationResult(**values)


def evidence(decision, **changes):
    values = dict(
        evidence_id="00000000-0000-4000-8000-000000000010",
        contract_version=CONTRACT_VERSION,
        subject_pubkey=decision.subject_xonly_pubkey,
        identity_class=decision.identity_class,
        current_full_relation_satisfied=decision.current_full_relation_satisfied,
        evidence_source=decision.evidence_source,
        evidence_version=decision.policy_version,
        source_evidence_sha256=decision.source_evidence_sha256,
        observed_at=decision.observed_at,
        valid_until=decision.observed_at + timedelta(seconds=300),
        revoked_at=None,
        created_at=decision.observed_at,
    )
    values.update(changes)
    return CurrentEntitlementEvidenceRecord(**values)


class Repository:
    def __init__(self, latest=None, events=None):
        self.latest = latest
        self.appended = []
        self.events = events if events is not None else []

    def get_latest(self, subject):
        self.events.append(("latest", subject))
        return self.latest

    def append(self, item):
        self.events.append(("append", item.subject_pubkey))
        self.appended.append(item)
        self.latest = item


class Guard:
    exclusive = True

    def __init__(self, lock=None, events=None):
        self.lock = lock or Lock()
        self.events = events if events is not None else []
        self.holds = []

    def hold(self, subject):
        self.holds.append(subject)
        lock, events = self.lock, self.events

        @contextmanager
        def held():
            with lock:
                events.append(("enter", subject))
                yield
                events.append(("exit", subject))

        return held()


def invoke(mode, **changes):
    values = dict(
        evaluated_at=NOW,
        mode=mode,
        genesis_repository=object(),
        admission_edge_repository=object(),
        root_registration_binding_repository=object(),
        trusted_registration_repository=object(),
        funding_set_repository=object(),
    )
    values.update(changes)
    return service.refresh_canonical_root_entitlement(GRAPH, SUBJECT, **values)


@pytest.fixture
def canonical(monkeypatch):
    source = relation()
    calls = []
    monkeypatch.setattr(
        service,
        "observe_edge_local_covenant_relation",
        lambda graph, subject, **kwargs: calls.append(("observe", graph, subject, kwargs)) or source,
    )
    original = evaluate_canonical_root_entitlement
    monkeypatch.setattr(
        service,
        "evaluate_canonical_root_entitlement",
        lambda graph, subject, item: calls.append(("policy", graph, subject, item))
        or original(graph, subject, item),
    )
    return source, calls


def test_closed_contracts_and_dry_run_is_exactly_one_read_only_preview(canonical):
    source, calls = canonical
    result = invoke(service.CanonicalRootEntitlementRefreshMode.DRY_RUN)
    assert list(service.CanonicalRootEntitlementRefreshMode) == [
        service.CanonicalRootEntitlementRefreshMode.DRY_RUN,
        service.CanonicalRootEntitlementRefreshMode.COMMIT,
    ]
    assert len(service.CanonicalRootEntitlementRefreshOutcome) == 3
    assert [call[0] for call in calls] == ["observe", "policy"]
    assert result.outcome is service.CanonicalRootEntitlementRefreshOutcome.PREVIEW
    assert result.edge_local_result is source and result.evidence is None
    assert result.decision.identity_class is IdentityClass.FULL
    assert result.append_performed is False
    with pytest.raises(FrozenInstanceError):
        result.outcome = service.CanonicalRootEntitlementRefreshOutcome.APPENDED


def test_limited_preview_is_not_failure(monkeypatch, canonical):
    limited = relation(
        qualifying_observation_count=1,
        outgoing_sats=0,
        current_full_relation_satisfied=False,
        relation_reason=CovenantRelationReason.MISSING_OUTGOING,
    )
    monkeypatch.setattr(service, "observe_edge_local_covenant_relation", lambda *_a, **_k: limited)
    result = invoke(service.CanonicalRootEntitlementRefreshMode.DRY_RUN)
    assert result.decision.identity_class is IdentityClass.LIMITED


@pytest.mark.parametrize("guard", [None, object(), type("Shared", (), {"exclusive": False, "hold": lambda *_: None})()])
def test_commit_rejects_invalid_guard_before_observation(canonical, guard):
    _, calls = canonical
    with pytest.raises(service.CanonicalRootEntitlementRefreshUnavailable):
        invoke(service.CanonicalRootEntitlementRefreshMode.COMMIT, execution_guard=guard, evidence_repository=Repository())
    assert calls == []


def test_exact_replay_is_unchanged_inside_one_guard(canonical):
    source, calls = canonical
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, source)
    events = []
    repository = Repository(evidence(decision), events)
    guard = Guard(events=events)
    result = invoke(service.CanonicalRootEntitlementRefreshMode.COMMIT, execution_guard=guard, evidence_repository=repository)
    assert result.outcome is service.CanonicalRootEntitlementRefreshOutcome.UNCHANGED
    assert result.evidence == repository.latest and repository.appended == []
    assert guard.holds == [SUBJECT]
    assert events[0] == ("enter", SUBJECT) and events[-1] == ("exit", SUBJECT)
    assert [call[0] for call in calls] == ["observe", "policy"]


@pytest.mark.parametrize(
    "change",
    [
        {"source_evidence_sha256": "f" * 64},
        {"observed_at": NOW - timedelta(seconds=1), "valid_until": NOW + timedelta(seconds=1)},
    ],
)
def test_digest_or_time_difference_does_not_suppress_append(monkeypatch, canonical, change):
    source, _ = canonical
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, source)
    repository = Repository(evidence(decision, **change))
    materialized = evidence(decision, evidence_id="00000000-0000-4000-8000-000000000011")

    class Materializer:
        def __init__(self, repo): self.repo = repo
        def materialize(self, graph, subject, item):
            self.repo.append(materialized)
            return materialized

    monkeypatch.setattr(service, "CanonicalRootEntitlementMaterializer", Materializer)
    result = invoke(service.CanonicalRootEntitlementRefreshMode.COMMIT, execution_guard=Guard(), evidence_repository=repository)
    assert result.outcome is service.CanonicalRootEntitlementRefreshOutcome.APPENDED
    assert repository.appended == [materialized]


def test_post_append_mismatch_is_sanitized_without_second_append(monkeypatch, canonical):
    source, _ = canonical
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, source)
    made = evidence(decision)
    repository = Repository()

    class Materializer:
        def __init__(self, repo): self.repo = repo
        def materialize(self, *_args):
            self.repo.appended.append(made)
            return made

    monkeypatch.setattr(service, "CanonicalRootEntitlementMaterializer", Materializer)
    with pytest.raises(service.CanonicalRootEntitlementRefreshUnavailable, match="refresh unavailable"):
        invoke(service.CanonicalRootEntitlementRefreshMode.COMMIT, execution_guard=Guard(), evidence_repository=repository)
    assert repository.appended == [made]


@pytest.mark.parametrize("failure", [RuntimeError("secret path"), ValueError("rpc url")])
def test_dependency_failures_are_sanitized(monkeypatch, failure):
    monkeypatch.setattr(service, "observe_edge_local_covenant_relation", lambda *_a, **_k: (_ for _ in ()).throw(failure))
    with pytest.raises(service.CanonicalRootEntitlementRefreshUnavailable) as caught:
        invoke(service.CanonicalRootEntitlementRefreshMode.DRY_RUN)
    assert str(caught.value) == "canonical root entitlement refresh unavailable"


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt(), SystemExit()])
def test_interrupts_remain_visible(monkeypatch, interrupt):
    monkeypatch.setattr(service, "observe_edge_local_covenant_relation", lambda *_a, **_k: (_ for _ in ()).throw(interrupt))
    with pytest.raises(type(interrupt)):
        invoke(service.CanonicalRootEntitlementRefreshMode.DRY_RUN)


def test_two_competing_commits_are_serialized_by_injected_guard(monkeypatch, canonical):
    source, _ = canonical
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, source)
    repository = Repository()
    shared_lock = Lock()
    guard = Guard(lock=shared_lock)
    start = Barrier(3)
    made = evidence(decision)

    class Materializer:
        def __init__(self, repo): self.repo = repo
        def materialize(self, *_args):
            self.repo.append(made)
            return made

    monkeypatch.setattr(service, "CanonicalRootEntitlementMaterializer", Materializer)
    results = []

    def run():
        start.wait()
        results.append(invoke(service.CanonicalRootEntitlementRefreshMode.COMMIT, execution_guard=guard, evidence_repository=repository))

    threads = [Thread(target=run), Thread(target=run)]
    for thread in threads: thread.start()
    start.wait()
    for thread in threads: thread.join()
    assert {item.outcome for item in results} == {
        service.CanonicalRootEntitlementRefreshOutcome.APPENDED,
        service.CanonicalRootEntitlementRefreshOutcome.UNCHANGED,
    }
    assert repository.appended == [made]
    assert guard.holds == [SUBJECT, SUBJECT]


def test_admission_provenance_and_arbitrary_mode_fail_closed(monkeypatch, canonical):
    source, _ = canonical
    monkeypatch.setattr(service, "observe_edge_local_covenant_relation", lambda *_a, **_k: replace(source, controlling_selection_source=ControllingRegistrationSelectionSource.CANONICAL_ADMISSION_EDGE))
    for mode in ("dry_run", service.CanonicalRootEntitlementRefreshMode.DRY_RUN):
        with pytest.raises(service.CanonicalRootEntitlementRefreshUnavailable):
            invoke(mode)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("policy_version", "private-policy"),
        ("evidence_source", "private-source"),
        ("source_evidence_sha256", "f" * 64),
        ("identity_class", IdentityClass.LIMITED),
        ("current_full_relation_satisfied", False),
        ("observed_at", NOW + timedelta(microseconds=1)),
        ("selector_record_sha256", "e" * 64),
        ("recognized_outpoint_count", 6),
        ("incoming_sats", 299999),
        ("relation_source_evidence_sha256", "d" * 64),
    ],
)
def test_malformed_policy_decision_fields_fail_closed(monkeypatch, canonical, field, value):
    source, _ = canonical
    canonical_decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, source)
    monkeypatch.setattr(
        service,
        "evaluate_canonical_root_entitlement",
        lambda *_args: replace(canonical_decision, **{field: value}),
    )
    with pytest.raises(service.CanonicalRootEntitlementRefreshUnavailable):
        invoke(service.CanonicalRootEntitlementRefreshMode.DRY_RUN)


@pytest.mark.parametrize("stage", ["hold", "enter"])
def test_guard_boundary_failures_are_sanitized_before_append(canonical, stage):
    class FailingGuard:
        exclusive = True

        def hold(self, _subject):
            if stage == "hold":
                raise RuntimeError("private guard")

            class Held:
                def __enter__(self):
                    if stage == "enter":
                        raise RuntimeError("private enter")

                def __exit__(self, *_args):
                    if stage == "exit":
                        raise RuntimeError("private exit")

            return Held()

    repository = Repository()
    with pytest.raises(service.CanonicalRootEntitlementRefreshUnavailable) as caught:
        invoke(
            service.CanonicalRootEntitlementRefreshMode.COMMIT,
            execution_guard=FailingGuard(),
            evidence_repository=repository,
        )
    assert "private" not in str(caught.value)
    assert repository.appended == []


def test_fresh_limited_commit_has_complete_ordered_guard_lifecycle(monkeypatch):
    events = []
    limited = relation(
        qualifying_observation_count=1,
        outgoing_sats=0,
        current_full_relation_satisfied=False,
        relation_reason=CovenantRelationReason.MISSING_OUTGOING,
    )
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, limited)
    made = evidence(
        decision,
        evidence_id="00000000-0000-4000-8000-000000000020",
    )
    repository = Repository(events=events)

    monkeypatch.setattr(
        service,
        "observe_edge_local_covenant_relation",
        lambda *_a, **_k: events.append(("observation", SUBJECT)) or limited,
    )
    monkeypatch.setattr(
        service,
        "evaluate_canonical_root_entitlement",
        lambda *_a: events.append(("policy", SUBJECT)) or decision,
    )

    class Materializer:
        def __init__(self, repo):
            self.repo = repo

        def materialize(self, *_args):
            self.repo.append(made)
            return made

    monkeypatch.setattr(service, "CanonicalRootEntitlementMaterializer", Materializer)
    result = invoke(
        service.CanonicalRootEntitlementRefreshMode.COMMIT,
        execution_guard=Guard(events=events),
        evidence_repository=repository,
    )

    assert events == [
        ("enter", SUBJECT),
        ("latest", SUBJECT),
        ("observation", SUBJECT),
        ("policy", SUBJECT),
        ("append", SUBJECT),
        ("latest", SUBJECT),
        ("exit", SUBJECT),
    ]
    assert result.outcome is service.CanonicalRootEntitlementRefreshOutcome.APPENDED
    assert repository.appended == [made]
    assert made.identity_class is IdentityClass.LIMITED
    assert made.current_full_relation_satisfied is False
    assert made.source_evidence_sha256 == decision.source_evidence_sha256
    assert made.observed_at == decision.observed_at == NOW


def test_exact_replay_has_complete_ordered_guard_lifecycle(monkeypatch):
    events = []
    source = relation()
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, source)
    repository = Repository(evidence(decision), events)
    monkeypatch.setattr(
        service,
        "observe_edge_local_covenant_relation",
        lambda *_a, **_k: events.append(("observation", SUBJECT)) or source,
    )
    monkeypatch.setattr(
        service,
        "evaluate_canonical_root_entitlement",
        lambda *_a: events.append(("policy", SUBJECT)) or decision,
    )

    result = invoke(
        service.CanonicalRootEntitlementRefreshMode.COMMIT,
        execution_guard=Guard(events=events),
        evidence_repository=repository,
    )

    assert result.outcome is service.CanonicalRootEntitlementRefreshOutcome.UNCHANGED
    assert events == [
        ("enter", SUBJECT),
        ("latest", SUBJECT),
        ("observation", SUBJECT),
        ("policy", SUBJECT),
        ("exit", SUBJECT),
    ]
    assert repository.appended == []


def test_expired_historical_evidence_does_not_suppress_fresh_append(monkeypatch):
    historical_relation = relation(observed_at=NOW - timedelta(minutes=10))
    historical_decision = evaluate_canonical_root_entitlement(
        GRAPH, SUBJECT, historical_relation
    )
    historical = evidence(
        historical_decision,
        valid_until=NOW - timedelta(minutes=5),
        created_at=NOW - timedelta(minutes=10),
    )
    fresh = relation()
    fresh_decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, fresh)
    made = evidence(
        fresh_decision,
        evidence_id="00000000-0000-4000-8000-000000000021",
    )
    repository = Repository(historical)
    monkeypatch.setattr(
        service, "observe_edge_local_covenant_relation", lambda *_a, **_k: fresh
    )

    class Materializer:
        def __init__(self, repo):
            self.repo = repo

        def materialize(self, *_args):
            self.repo.append(made)
            return made

    monkeypatch.setattr(service, "CanonicalRootEntitlementMaterializer", Materializer)
    result = invoke(
        service.CanonicalRootEntitlementRefreshMode.COMMIT,
        execution_guard=Guard(),
        evidence_repository=repository,
    )
    assert historical.valid_until < NOW
    assert historical.source_evidence_sha256 != fresh_decision.source_evidence_sha256
    assert historical.observed_at != fresh_decision.observed_at
    assert result.outcome is service.CanonicalRootEntitlementRefreshOutcome.APPENDED
    assert repository.appended == [made]


def test_guard_exit_failure_after_verified_append_is_sanitized_without_retry(
    monkeypatch, canonical
):
    source, _ = canonical
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, source)
    made = evidence(
        decision,
        evidence_id="00000000-0000-4000-8000-000000000022",
    )
    repository = Repository()

    class Materializer:
        def __init__(self, repo):
            self.repo = repo

        def materialize(self, *_args):
            self.repo.append(made)
            return made

    class ExitFailingGuard:
        exclusive = True

        @contextmanager
        def hold(self, _subject):
            try:
                yield
            finally:
                raise RuntimeError("private exit")

    monkeypatch.setattr(service, "CanonicalRootEntitlementMaterializer", Materializer)
    with pytest.raises(service.CanonicalRootEntitlementRefreshUnavailable) as caught:
        invoke(
            service.CanonicalRootEntitlementRefreshMode.COMMIT,
            execution_guard=ExitFailingGuard(),
            evidence_repository=repository,
        )
    assert str(caught.value) == "canonical root entitlement refresh unavailable"
    assert repository.appended == [made]
    assert repository.latest == made


@pytest.mark.parametrize(
    "stage",
    ["observer", "policy", "initial_latest", "materializer", "verified_latest"],
)
def test_malformed_dependency_return_types_fail_closed(monkeypatch, canonical, stage):
    source, _ = canonical
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, source)
    made = evidence(decision)

    class SequencedRepository(Repository):
        def __init__(self):
            super().__init__()
            self.reads = 0

        def get_latest(self, subject):
            self.reads += 1
            if stage == "initial_latest" and self.reads == 1:
                return object()
            if stage == "verified_latest" and self.reads == 2:
                return object()
            return super().get_latest(subject)

    repository = SequencedRepository()
    if stage == "observer":
        monkeypatch.setattr(
            service, "observe_edge_local_covenant_relation", lambda *_a, **_k: object()
        )
    if stage == "policy":
        monkeypatch.setattr(
            service, "evaluate_canonical_root_entitlement", lambda *_a: object()
        )

    class Materializer:
        def __init__(self, repo):
            self.repo = repo

        def materialize(self, *_args):
            if stage == "materializer":
                return object()
            self.repo.append(made)
            return made

    monkeypatch.setattr(service, "CanonicalRootEntitlementMaterializer", Materializer)
    with pytest.raises(service.CanonicalRootEntitlementRefreshUnavailable) as caught:
        invoke(
            service.CanonicalRootEntitlementRefreshMode.COMMIT,
            execution_guard=Guard(),
            evidence_repository=repository,
        )
    assert str(caught.value) == "canonical root entitlement refresh unavailable"
    assert len(repository.appended) <= 1


def test_repository_and_policy_failures_are_sanitized(monkeypatch, canonical):
    class FailingRepository(Repository):
        def get_latest(self, _subject):
            raise RuntimeError("private database")

    with pytest.raises(service.CanonicalRootEntitlementRefreshUnavailable):
        invoke(
            service.CanonicalRootEntitlementRefreshMode.COMMIT,
            execution_guard=Guard(),
            evidence_repository=FailingRepository(),
        )

    monkeypatch.setattr(
        service,
        "evaluate_canonical_root_entitlement",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("private policy")),
    )
    with pytest.raises(service.CanonicalRootEntitlementRefreshUnavailable):
        invoke(service.CanonicalRootEntitlementRefreshMode.DRY_RUN)


def test_result_constructor_rejects_inconsistent_outcome(canonical):
    source, _ = canonical
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, source)
    with pytest.raises(ValueError):
        service.CanonicalRootEntitlementRefreshResult(
            service.REFRESH_CONTRACT_VERSION,
            service.CanonicalRootEntitlementRefreshMode.DRY_RUN,
            service.CanonicalRootEntitlementRefreshOutcome.APPENDED,
            GRAPH,
            SUBJECT,
            NOW,
            source,
            decision,
            evidence(decision),
            True,
        )

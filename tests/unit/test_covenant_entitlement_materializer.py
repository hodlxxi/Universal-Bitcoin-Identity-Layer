from datetime import datetime, timedelta, timezone
import uuid

import pytest

from app.services.action_authorization import IdentityClass
from app.services.covenant_entitlement_materializer import (
    EVIDENCE_SOURCE,
    EVIDENCE_VALIDITY_SECONDS,
    EVIDENCE_VERSION,
    MATERIALIZER_VERSION,
    CovenantEntitlementMaterializationUnavailable,
    CovenantEntitlementMaterializer,
)
from app.services.covenant_relation import (
    EVALUATION_SCHEMA,
    OBSERVATION_SCHEMA,
    CovenantDirection,
    CovenantRelationEvaluation,
    CovenantRelationObservation,
)
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.trusted_covenant_observation import (
    ADAPTER_VERSION,
    InvalidTrustedCovenantOutpoint,
    TrustedCovenantObservationUnavailable,
)

SUBJECT = "a" * 64
ALICE = "b" * 64
NOW = datetime(2026, 7, 23, 12, tzinfo=timezone.utc)
IDENTIFIER = uuid.UUID("12345678-1234-5678-9234-567812345678")


def observation(direction=CovenantDirection.INCOMING, amount=100, unspent=True, txid="1" * 64):
    return CovenantRelationObservation(
        schema=OBSERVATION_SCHEMA,
        subject_pubkey=SUBJECT,
        counterparty_pubkey=ALICE,
        direction=direction,
        txid=txid,
        vout=0,
        amount_sats=amount,
        script_sha256="d" * 64,
        descriptor_sha256=None,
        confirmations=1 if unspent else 0,
        unspent=unspent,
    )


def evaluation(items, observed_at=NOW - timedelta(seconds=1)):
    return CovenantRelationEvaluation(
        schema=EVALUATION_SCHEMA,
        network="bitcoin",
        subject_pubkey=SUBJECT,
        counterparty_pubkey=ALICE,
        observed_at=observed_at,
        observed_block_height=900_000,
        observations=items,
    )


class Adapter:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def observe(self, outpoints):
        self.calls.append(outpoints)
        if self.error:
            raise self.error
        return self.result


class Repository:
    def __init__(self, error=None):
        self.error = error
        self.appended = []
        self.get_latest_calls = 0

    def append(self, record):
        if self.error:
            raise self.error
        self.appended.append(record)

    def get_latest(self, _subject):
        self.get_latest_calls += 1
        raise AssertionError("must not inspect older evidence")


def materialize(items, *, now=NOW, repository=None, observed_at=None, uuid_factory=lambda: IDENTIFIER):
    repository = repository or Repository()
    request = evaluation(items, observed_at=observed_at or NOW - timedelta(seconds=1))
    result = CovenantEntitlementMaterializer(
        Adapter(request), repository, clock=lambda: now, uuid_factory=uuid_factory
    ).materialize(())
    return result, repository


@pytest.mark.parametrize(
    ("incoming", "outgoing"),
    [(100, 100), (100, 101)],
)
def test_positive_exact_and_greater_outgoing_create_full_evidence(incoming, outgoing):
    record, repository = materialize(
        (
            observation(amount=incoming),
            observation(CovenantDirection.OUTGOING, outgoing, txid="2" * 64),
        )
    )
    assert type(record) is CurrentEntitlementEvidenceRecord
    assert repository.appended == [record]
    assert record.identity_class is IdentityClass.FULL
    assert record.current_full_relation_satisfied is True
    assert record.evidence_id == str(IDENTIFIER)
    assert record.contract_version == CONTRACT_VERSION
    assert record.subject_pubkey == SUBJECT
    assert record.evidence_source == EVIDENCE_SOURCE
    assert record.evidence_version == EVIDENCE_VERSION == ADAPTER_VERSION
    assert record.observed_at == NOW - timedelta(seconds=1)
    assert record.valid_until - record.observed_at == timedelta(seconds=EVIDENCE_VALIDITY_SECONDS)
    assert record.created_at == NOW
    assert record.revoked_at is None
    assert len(record.source_evidence_sha256) == 64
    assert repository.get_latest_calls == 0
    assert MATERIALIZER_VERSION == "hodlxxi.covenant_entitlement_materializer.v1"


@pytest.mark.parametrize(
    "items",
    [
        (observation(),),
        (observation(), observation(CovenantDirection.OUTGOING, 99, txid="2" * 64)),
        (observation(unspent=False),),
    ],
)
def test_negative_and_missing_utxo_evidence_is_persisted_as_limited(items):
    record, repository = materialize(items)
    assert record.identity_class is IdentityClass.LIMITED
    assert record.current_full_relation_satisfied is False
    assert repository.appended == [record]


def test_source_hash_and_observed_time_are_copied_from_exact_decision():
    request = evaluation((observation(), observation(CovenantDirection.OUTGOING, txid="2" * 64)))
    from app.services.covenant_relation import evaluate_covenant_relation

    decision = evaluate_covenant_relation(request)
    repository = Repository()
    record = CovenantEntitlementMaterializer(
        Adapter(request), repository, clock=lambda: NOW, uuid_factory=lambda: IDENTIFIER
    ).materialize(())
    assert record.source_evidence_sha256 == decision.source_evidence_sha256
    assert record.observed_at == decision.observed_at


def test_non_utc_materializer_clock_is_normalized_and_called_once():
    calls = []

    def clock():
        calls.append(1)
        return NOW.astimezone(timezone(timedelta(hours=-4)))

    repository = Repository()
    record = CovenantEntitlementMaterializer(
        Adapter(evaluation((observation(),))), repository, clock=clock, uuid_factory=lambda: IDENTIFIER
    ).materialize(())
    assert calls == [1]
    assert record.created_at == NOW and record.created_at.tzinfo is timezone.utc


def test_observation_exactly_sixty_seconds_old_is_accepted_with_raw_clock_creation_time():
    record, repository = materialize((observation(),), observed_at=NOW - timedelta(seconds=60))
    assert repository.appended == [record]
    assert record.observed_at == NOW - timedelta(seconds=60)
    assert record.created_at == NOW


def test_observation_older_than_sixty_seconds_by_one_microsecond_is_rejected_without_append():
    repository = Repository()
    with pytest.raises(CovenantEntitlementMaterializationUnavailable):
        materialize(
            (observation(),),
            repository=repository,
            observed_at=NOW - timedelta(seconds=60, microseconds=1),
        )
    assert repository.appended == []


def test_observation_exactly_five_seconds_in_future_uses_causal_creation_floor():
    observed_at = NOW + timedelta(seconds=5)
    request = evaluation((observation(),), observed_at=observed_at)
    from app.services.covenant_relation import evaluate_covenant_relation

    decision = evaluate_covenant_relation(request)
    clock_calls = []

    def clock():
        clock_calls.append(1)
        return NOW

    repository = Repository()
    record = CovenantEntitlementMaterializer(
        Adapter(request), repository, clock=clock, uuid_factory=lambda: IDENTIFIER
    ).materialize(())

    assert clock_calls == [1]
    assert repository.appended == [record]
    assert record.observed_at == observed_at
    assert record.created_at == record.observed_at
    assert record.valid_until == observed_at + timedelta(seconds=300)
    assert record.source_evidence_sha256 == decision.source_evidence_sha256


def test_observation_over_five_seconds_in_future_by_one_microsecond_is_rejected_without_append():
    repository = Repository()
    with pytest.raises(CovenantEntitlementMaterializationUnavailable):
        materialize(
            (observation(),),
            repository=repository,
            observed_at=NOW + timedelta(seconds=5, microseconds=1),
        )
    assert repository.appended == []


def test_naive_clock_malformed_result_uuid_and_repository_failure_are_sanitized():
    secret = "postgresql://secret-password/private"
    cases = (
        (Adapter(object()), Repository(), lambda: NOW, lambda: IDENTIFIER),
        (Adapter(evaluation((observation(),))), Repository(), lambda: NOW.replace(tzinfo=None), lambda: IDENTIFIER),
        (Adapter(evaluation((observation(),))), Repository(), lambda: NOW, lambda: "not-a-uuid"),
        (
            Adapter(evaluation((observation(),))),
            Repository(RuntimeError(secret)),
            lambda: NOW,
            lambda: IDENTIFIER,
        ),
    )
    for source, repository, clock, uuid_factory in cases:
        with pytest.raises(CovenantEntitlementMaterializationUnavailable) as caught:
            CovenantEntitlementMaterializer(source, repository, clock=clock, uuid_factory=uuid_factory).materialize(())
        assert secret not in str(caught.value)
        assert repository.appended == []


def test_adapter_failure_means_no_append_and_typed_input_violation_can_remain_typed():
    for error, expected in (
        (TrustedCovenantObservationUnavailable(), CovenantEntitlementMaterializationUnavailable),
        (InvalidTrustedCovenantOutpoint("bad input"), InvalidTrustedCovenantOutpoint),
    ):
        repository = Repository()
        with pytest.raises(expected):
            CovenantEntitlementMaterializer(Adapter(error=error), repository).materialize(())
        assert repository.appended == []


def test_evaluator_failure_means_no_append(monkeypatch):
    repository = Repository()

    def fail(_evaluation):
        raise RuntimeError("sensitive evaluator failure")

    monkeypatch.setattr("app.services.covenant_entitlement_materializer.evaluate_covenant_relation", fail)
    with pytest.raises(CovenantEntitlementMaterializationUnavailable):
        CovenantEntitlementMaterializer(
            Adapter(evaluation((observation(),))), repository, clock=lambda: NOW
        ).materialize(())
    assert repository.appended == []

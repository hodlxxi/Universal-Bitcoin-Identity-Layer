from __future__ import annotations

import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from coincurve import PrivateKey, PublicKeyXOnly
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.models import ActionOperation, ActionStepUpChallenge
from app.services.action_idempotency import request_fingerprint_sha256, token_reference_sha256
from app.services.action_operation_storage import ActionOperationStorageError, InvalidReservationError, Reservation
from app.services.action_step_up import (
    CHALLENGE_SCHEMA,
    PROOF_SCHEMA,
    SIGNATURE_DOMAIN,
    SIGNATURE_FORMAT,
    ActionStepUpService,
    StepUpChallenge,
    StepUpProof,
    StepUpReason,
    canonical_signed_bytes,
    step_up_verification_sha256,
)
from app.services.action_step_up_operation_storage import (
    AtomicStepUpReserveStatus,
    SqlAlchemyAtomicStepUpOperationRepository,
)
from app.services.action_step_up_storage import SqlAlchemyActionStepUpRepository

NOW = datetime(2026, 7, 21, 12, tzinfo=timezone.utc)


def setup(tmp_path, name="atomic.db"):
    engine = create_engine(
        f"sqlite:///{tmp_path / name}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    ActionStepUpChallenge.__table__.create(engine)
    ActionOperation.__table__.create(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    return factory, SqlAlchemyAtomicStepUpOperationRepository(factory)


def actor(key):
    return PublicKeyXOnly.from_secret(key.secret).format().hex()


def create_challenge(factory, key, *, challenge_id=None, **changes):
    values = dict(
        schema=CHALLENGE_SCHEMA,
        challenge_id=challenge_id or uuid.uuid4().hex,
        actor_pubkey=actor(key),
        oauth_client_id="client",
        token_jti="jti",
        action="covenant_draft_create",
        resource_id=None,
        request_sha256="33" * 32,
        nonce=uuid.uuid4().hex + uuid.uuid4().hex,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        signature_domain=SIGNATURE_DOMAIN,
        consumed_at=None,
    )
    values.update(changes)
    challenge = StepUpChallenge(**values)
    SqlAlchemyActionStepUpRepository(factory).create(challenge)
    if challenge.consumed_at is not None:
        with factory() as session:
            session.get(ActionStepUpChallenge, challenge.challenge_id).consumed_at = challenge.consumed_at
            session.commit()
    return challenge


def signed_proof(challenge, key):
    digest = hashlib.sha256(canonical_signed_bytes(challenge)).digest()
    return StepUpProof(PROOF_SCHEMA, challenge.challenge_id, key.sign_schnorr(digest), SIGNATURE_FORMAT)


def reservation(challenge, **changes):
    values = dict(
        contract_version="hodlxxi.action-operation.v1",
        actor_pubkey=challenge.actor_pubkey,
        oauth_client_id=challenge.oauth_client_id,
        token_jti=challenge.token_jti,
        token_reference_sha256=token_reference_sha256(challenge.token_jti),
        action=challenge.action,
        resource_id=challenge.resource_id,
        request_sha256=challenge.request_sha256,
        idempotency_key_sha256="44" * 32,
        step_up_challenge_id=challenge.challenge_id,
        step_up_verification_sha256=None,
        policy_version="policy-v1",
        authorization_decision_sha256="66" * 32,
        reserved_at=NOW,
    )
    values.update(changes)
    values.setdefault(
        "request_fingerprint_sha256",
        request_fingerprint_sha256(
            contract_version=values["contract_version"],
            actor_pubkey=values["actor_pubkey"],
            oauth_client_id=values["oauth_client_id"],
            token_jti=values["token_jti"],
            action=values["action"],
            resource_id=values["resource_id"],
            request_sha256=values["request_sha256"],
            step_up_challenge_id=values["step_up_challenge_id"],
        ),
    )
    return Reservation(**values)


def rows(factory):
    with factory() as session:
        return session.query(ActionOperation).all(), session.query(ActionStepUpChallenge).all()


def test_atomic_success_persists_bound_evidence_without_secrets(tmp_path):
    factory, repository = setup(tmp_path)
    key = PrivateKey()
    challenge = create_challenge(factory, key)
    proof = signed_proof(challenge, key)
    result = repository.reserve_with_step_up(reservation(challenge), proof, NOW + timedelta(seconds=1))
    assert result.status is AtomicStepUpReserveStatus.NEW
    operations, challenges = rows(factory)
    assert len(operations) == 1
    assert challenges[0].consumed_at is not None
    assert result.operation.step_up_challenge_id == challenge.challenge_id
    assert result.operation.step_up_verification_sha256 == step_up_verification_sha256(result.verification)
    assert result.operation.request_fingerprint_sha256 == reservation(challenge).request_fingerprint_sha256
    stored = vars(result.operation)
    assert not ({"signature", "bearer_token", "client_secret", "private_key"} & set(stored))
    assert proof.signature not in stored.values()


def test_exact_replay_precedes_consumption_and_expiration(tmp_path, monkeypatch):
    factory, repository = setup(tmp_path)
    key = PrivateKey()
    challenge = create_challenge(factory, key)
    request = reservation(challenge)
    proof = signed_proof(challenge, key)
    first = repository.reserve_with_step_up(request, proof, NOW + timedelta(seconds=1))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("proof verification must not run")

    monkeypatch.setattr("app.services.action_step_up_operation_storage._verify_step_up_candidate", forbidden)
    replay = repository.reserve_with_step_up(request, proof, NOW + timedelta(hours=1))
    assert replay.status is AtomicStepUpReserveStatus.REPLAY
    assert replay.operation.operation_id == first.operation.operation_id
    assert len(rows(factory)[0]) == 1


def test_idempotency_conflict_does_not_consume_losing_challenge(tmp_path, monkeypatch):
    factory, repository = setup(tmp_path)
    first_key = losing_key = PrivateKey()
    first_challenge = create_challenge(factory, first_key)
    losing_challenge = create_challenge(factory, losing_key)
    repository.reserve_with_step_up(reservation(first_challenge), signed_proof(first_challenge, first_key), NOW)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("proof verification must not run")

    monkeypatch.setattr("app.services.action_step_up_operation_storage._verify_step_up_candidate", forbidden)
    result = repository.reserve_with_step_up(
        reservation(losing_challenge), signed_proof(losing_challenge, losing_key), NOW
    )
    assert result.status is AtomicStepUpReserveStatus.IDEMPOTENCY_CONFLICT
    with factory() as session:
        assert session.get(ActionStepUpChallenge, losing_challenge.challenge_id).consumed_at is None
        assert session.query(ActionOperation).count() == 1


def test_same_challenge_different_key_is_consumed_rejection(tmp_path):
    factory, repository = setup(tmp_path)
    key = PrivateKey()
    challenge = create_challenge(factory, key)
    proof = signed_proof(challenge, key)
    assert repository.reserve_with_step_up(reservation(challenge), proof, NOW).status is AtomicStepUpReserveStatus.NEW
    second = reservation(challenge, idempotency_key_sha256="55" * 32)
    result = repository.reserve_with_step_up(second, proof, NOW + timedelta(seconds=1))
    assert result.status is AtomicStepUpReserveStatus.STEP_UP_REJECTED
    assert result.verification.reason_code is StepUpReason.CHALLENGE_CONSUMED
    assert len(rows(factory)[0]) == 1


@pytest.mark.parametrize(
    "case,reason",
    [
        ("proof_type", StepUpReason.INVALID_REQUEST),
        ("signature", StepUpReason.INVALID_SIGNATURE),
        ("actor", StepUpReason.BINDING_MISMATCH),
        ("client", StepUpReason.BINDING_MISMATCH),
        ("token", StepUpReason.BINDING_MISMATCH),
        ("action", StepUpReason.BINDING_MISMATCH),
        ("resource", StepUpReason.BINDING_MISMATCH),
        ("request", StepUpReason.BINDING_MISMATCH),
        ("not_yet", StepUpReason.CHALLENGE_NOT_YET_VALID),
        ("expired", StepUpReason.CHALLENGE_EXPIRED),
        ("consumed", StepUpReason.CHALLENGE_CONSUMED),
        ("malformed", StepUpReason.INVALID_REQUEST),
    ],
)
def test_invalid_step_up_cases_never_mutate(tmp_path, case, reason):
    factory, repository = setup(tmp_path, f"{case}.db")
    key = PrivateKey()
    challenge_changes = {}
    timestamp = NOW + timedelta(seconds=1)
    if case == "not_yet":
        challenge_changes = {"issued_at": NOW + timedelta(seconds=2), "expires_at": NOW + timedelta(minutes=5)}
    elif case == "expired":
        challenge_changes = {"issued_at": NOW - timedelta(minutes=5), "expires_at": NOW}
    elif case == "consumed":
        challenge_changes = {"consumed_at": NOW}
    elif case == "malformed":
        challenge_changes = {"schema": "legacy"}
    challenge = create_challenge(factory, key, **challenge_changes)
    request = reservation(challenge)
    proof = signed_proof(challenge, key)
    if case == "proof_type":
        proof = object()
    elif case == "signature":
        proof = replace(proof, signature="00" * 64)
    elif case in {"actor", "client", "token", "action", "resource", "request"}:
        field, value = {
            "actor": ("actor_pubkey", actor(PrivateKey())),
            "client": ("oauth_client_id", "other"),
            "token": ("token_jti", "other"),
            "action": ("action", "covenant_draft_read_self"),
            "resource": ("resource_id", "other"),
            "request": ("request_sha256", "77" * 32),
        }[case]
        request = reservation(challenge, **{field: value})
        if field == "token_jti":
            request = replace(request, token_reference_sha256=token_reference_sha256(value))
    result = repository.reserve_with_step_up(request, proof, timestamp)
    assert result.status is AtomicStepUpReserveStatus.STEP_UP_REJECTED
    assert result.verification.reason_code is reason
    with factory() as session:
        assert session.query(ActionOperation).count() == 0
        stored = session.get(ActionStepUpChallenge, challenge.challenge_id)
        if case != "consumed":
            assert stored.consumed_at is None


def test_missing_challenge_and_invalid_input_contract(tmp_path):
    factory, repository = setup(tmp_path)
    key = PrivateKey()
    challenge = StepUpChallenge(
        CHALLENGE_SCHEMA,
        "0" * 32,
        actor(key),
        "client",
        "jti",
        "covenant_draft_create",
        None,
        "33" * 32,
        "11" * 32,
        NOW,
        NOW + timedelta(minutes=5),
        SIGNATURE_DOMAIN,
    )
    result = repository.reserve_with_step_up(reservation(challenge), signed_proof(challenge, key), NOW)
    assert result.verification.reason_code is StepUpReason.CHALLENGE_NOT_FOUND
    with pytest.raises(InvalidReservationError):
        repository.reserve_with_step_up(
            replace(reservation(challenge), step_up_verification_sha256="1" * 64),
            signed_proof(challenge, key),
            NOW,
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        repository.reserve_with_step_up(reservation(challenge), signed_proof(challenge, key), NOW.replace(tzinfo=None))


def test_flush_failure_rolls_back_challenge_consumption(tmp_path):
    factory, repository = setup(tmp_path)
    key = PrivateKey()
    challenge = create_challenge(factory, key)
    invalid_database_value = reservation(challenge, authorization_decision_sha256="x" * 63)
    with pytest.raises(ActionOperationStorageError, match="storage_unavailable"):
        repository.reserve_with_step_up(invalid_database_value, signed_proof(challenge, key), NOW)
    with factory() as session:
        assert session.query(ActionOperation).count() == 0
        assert session.get(ActionStepUpChallenge, challenge.challenge_id).consumed_at is None


def test_concurrent_identical_requests_resolve_new_and_replay(tmp_path):
    factory, repository = setup(tmp_path)
    key = PrivateKey()
    challenge = create_challenge(factory, key)
    request, proof = reservation(challenge), signed_proof(challenge, key)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: repository.reserve_with_step_up(request, proof, NOW), range(2)))
    assert sorted(result.status.value for result in results) == ["new", "replay"]
    assert len({result.operation.operation_id for result in results}) == 1
    assert len(rows(factory)[0]) == 1


def test_concurrent_different_keys_same_challenge(tmp_path):
    factory, repository = setup(tmp_path)
    key = PrivateKey()
    challenge = create_challenge(factory, key)
    proof = signed_proof(challenge, key)
    requests = [reservation(challenge), reservation(challenge, idempotency_key_sha256="55" * 32)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda request: repository.reserve_with_step_up(request, proof, NOW), requests))
    assert sorted(result.status.value for result in results) == ["new", "step_up_rejected"]
    rejected = next(
        result for result in results if result.verification is not None and not result.verification.verified
    )
    assert rejected.verification.reason_code is StepUpReason.CHALLENGE_CONSUMED
    assert len(rows(factory)[0]) == 1


def test_concurrent_same_namespace_different_challenges(tmp_path):
    factory, repository = setup(tmp_path)
    keys = [PrivateKey()] * 2
    challenges = [create_challenge(factory, key) for key in keys]
    requests = [reservation(challenge) for challenge in challenges]
    proofs = [signed_proof(challenge, key) for challenge, key in zip(challenges, keys)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda pair: repository.reserve_with_step_up(pair[0], pair[1], NOW),
                zip(requests, proofs),
            )
        )
    assert sorted(result.status.value for result in results) == ["idempotency_conflict", "new"]
    with factory() as session:
        stored = {row.challenge_id: row for row in session.query(ActionStepUpChallenge)}
        assert sum(row.consumed_at is not None for row in stored.values()) == 1
        winner = next(result.operation for result in results if result.status is AtomicStepUpReserveStatus.NEW)
        assert stored[winner.step_up_challenge_id].consumed_at is not None


def test_model_metadata_and_additive_migration_contract():
    constraints = {constraint.name for constraint in ActionOperation.__table__.constraints}
    assert "uq_action_operations_step_up_challenge" in constraints
    assert "fk_action_operations_step_up_challenge" in constraints
    sql = Path("migrations/2026-07-21_action_step_up_operation_binding.sql").read_text().lower()
    assert "uq_action_operations_step_up_challenge" in sql
    assert "fk_action_operations_step_up_challenge" in sql
    assert "pg_constraint" in sql and "begin;" in sql and "commit;" in sql
    assert not any(statement in sql for statement in ("drop ", "delete ", "update ", "truncate "))

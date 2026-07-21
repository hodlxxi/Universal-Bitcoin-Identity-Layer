import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import create_engine, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.models import ActionOperation, User
from app.services.action_idempotency import request_fingerprint_sha256, token_reference_sha256
from app.services.action_operation_storage import (
    InvalidReservationError,
    Reservation,
    SqlAlchemyActionOperationRepository,
    stored_receipt_bytes,
)
from app.services.action_receipt import canonical_json_bytes, create_action_receipt

NOW = datetime(2026, 7, 20, 12, tzinfo=timezone.utc)
ACTOR = (
    ec.derive_private_key(11, ec.SECP256K1())
    .public_key()
    .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)[1:]
    .hex()
)


def reservation(**changes):
    values = dict(
        contract_version="hodlxxi.action-operation.v1",
        actor_pubkey=ACTOR,
        oauth_client_id="client",
        token_jti="jti",
        token_reference_sha256=token_reference_sha256("jti"),
        action="draft_create",
        resource_id=None,
        request_sha256="33" * 32,
        idempotency_key_sha256="44" * 32,
        request_fingerprint_sha256=request_fingerprint_sha256(
            contract_version="hodlxxi.action-operation.v1",
            actor_pubkey=ACTOR,
            oauth_client_id="client",
            token_jti="jti",
            action="draft_create",
            resource_id=None,
            request_sha256="33" * 32,
            step_up_challenge_id=None,
        ),
        step_up_challenge_id=None,
        step_up_verification_sha256=None,
        policy_version="policy-v1",
        authorization_decision_sha256="66" * 32,
        reserved_at=NOW,
    )
    values.update(changes)
    return Reservation(**values)


def repository(tmp_path, name="operations.db"):
    engine = create_engine(f"sqlite:///{tmp_path / name}", connect_args={"check_same_thread": False})
    ActionOperation.__table__.create(engine)
    return SqlAlchemyActionOperationRepository(sessionmaker(bind=engine, expire_on_commit=False)), engine


def receipt(
    operation_id,
    state="completed",
    started_at="2026-07-20T12:00:01.000000Z",
    idempotency_key_sha256="44" * 32,
):
    key = ec.derive_private_key(9, ec.SECP256K1())
    pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint).hex()
    signer = lambda message: key.sign(message, ec.ECDSA(hashes.SHA256())).hex()
    return create_action_receipt(
        signer=signer,
        signer_public_key=pub,
        operation_id=operation_id,
        idempotency_key_sha256=idempotency_key_sha256,
        actor_pubkey=ACTOR,
        oauth_client_id="client",
        token_reference_sha256=token_reference_sha256("jti"),
        action="draft_create",
        resource_id=None,
        request_sha256="33" * 32,
        policy_version="policy-v1",
        authorization_decision_sha256="66" * 32,
        step_up_challenge_id=None,
        step_up_verification_sha256=None,
        state=state,
        started_at=started_at,
        completed_at="2026-07-20T12:00:02.000000Z",
        failure_code=None if state == "completed" else "dispatch_failed",
        result_sha256="77" * 32 if state == "completed" else None,
    )


def test_first_replay_conflict_and_namespace_isolation(tmp_path):
    repo, _ = repository(tmp_path)
    first = repo.reserve(reservation())
    replay = repo.reserve(reservation())
    conflicting = reservation(action="draft_delete")
    conflicting = reservation(
        action=conflicting.action,
        request_fingerprint_sha256=request_fingerprint_sha256(
            contract_version=conflicting.contract_version,
            actor_pubkey=conflicting.actor_pubkey,
            oauth_client_id=conflicting.oauth_client_id,
            token_jti=conflicting.token_jti,
            action=conflicting.action,
            resource_id=conflicting.resource_id,
            request_sha256=conflicting.request_sha256,
            step_up_challenge_id=conflicting.step_up_challenge_id,
        ),
    )
    conflict = repo.reserve(conflicting)
    assert first.is_new and replay.status == "replay" and conflict.status == "idempotency_conflict"
    assert first.operation.operation_id == replay.operation.operation_id == conflict.operation.operation_id
    other_actor = reservation(actor_pubkey="aa" * 32)
    assert repo.reserve(
        reservation(
            actor_pubkey=other_actor.actor_pubkey,
            request_fingerprint_sha256=request_fingerprint_sha256(
                contract_version=other_actor.contract_version,
                actor_pubkey=other_actor.actor_pubkey,
                oauth_client_id=other_actor.oauth_client_id,
                token_jti=other_actor.token_jti,
                action=other_actor.action,
                resource_id=other_actor.resource_id,
                request_sha256=other_actor.request_sha256,
                step_up_challenge_id=other_actor.step_up_challenge_id,
            ),
        )
    ).is_new
    other_client = reservation(oauth_client_id="other")
    assert repo.reserve(
        reservation(
            oauth_client_id=other_client.oauth_client_id,
            request_fingerprint_sha256=request_fingerprint_sha256(
                contract_version=other_client.contract_version,
                actor_pubkey=other_client.actor_pubkey,
                oauth_client_id=other_client.oauth_client_id,
                token_jti=other_client.token_jti,
                action=other_client.action,
                resource_id=other_client.resource_id,
                request_sha256=other_client.request_sha256,
                step_up_challenge_id=other_client.step_up_challenge_id,
            ),
        )
    ).is_new


def test_concurrent_identical_and_conflicting_reservations(tmp_path):
    repo, _ = repository(tmp_path)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: repo.reserve(reservation()), range(2)))
    assert sorted(x.status for x in results) == ["new", "replay"]
    assert len({x.operation.operation_id for x in results}) == 1
    repo2, _ = repository(tmp_path, "conflict.db")
    changed = reservation(action="draft_delete")
    changed = reservation(
        action=changed.action,
        request_fingerprint_sha256=request_fingerprint_sha256(
            contract_version=changed.contract_version,
            actor_pubkey=changed.actor_pubkey,
            oauth_client_id=changed.oauth_client_id,
            token_jti=changed.token_jti,
            action=changed.action,
            resource_id=changed.resource_id,
            request_sha256=changed.request_sha256,
            step_up_challenge_id=changed.step_up_challenge_id,
        ),
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(repo2.reserve, [reservation(), changed]))
    assert sorted(x.status for x in results) == ["idempotency_conflict", "new"]
    assert len({x.operation.operation_id for x in results}) == 1


def test_cas_transitions_terminal_immutability_and_exact_receipt_replay(tmp_path):
    repo, _ = repository(tmp_path)
    operation = repo.reserve(reservation()).operation
    assert repo.mark_executing(operation.operation_id, NOW + timedelta(seconds=1))
    assert not repo.mark_executing(operation.operation_id, NOW + timedelta(seconds=1))
    final = receipt(operation.operation_id)
    assert repo.finalize_completed(operation.operation_id, final)
    assert not repo.finalize_failed(operation.operation_id, receipt(operation.operation_id, "failed"))
    stored = repo.get_by_operation_id(operation.operation_id)
    assert stored_receipt_bytes(stored) == canonical_json_bytes(final)


def test_failed_from_reserved_and_indeterminate_from_executing(tmp_path):
    repo, _ = repository(tmp_path)
    failed = repo.reserve(reservation()).operation
    assert repo.finalize_failed(
        failed.operation_id, receipt(failed.operation_id, "failed", "2026-07-20T12:00:00.000000Z")
    )
    assert not repo.mark_executing(failed.operation_id, NOW)
    indeterminate = repo.reserve(reservation(idempotency_key_sha256="88" * 32)).operation
    assert repo.mark_executing(indeterminate.operation_id, NOW + timedelta(seconds=1))
    assert repo.mark_indeterminate(indeterminate.operation_id, NOW + timedelta(seconds=2))
    assert not repo.mark_indeterminate(indeterminate.operation_id, NOW + timedelta(seconds=3))


def test_migration_shape_model_agreement_and_unrelated_table_survives(tmp_path):
    sql = Path("migrations/2026-07-20_action_operations.sql").read_text()
    # SQLite exercises the direct shape after adapting PostgreSQL-only types/default.
    sqlite_sql = sql.replace("JSONB", "JSON").replace(" DEFAULT (gen_random_uuid())::text", "")
    connection = sqlite3.connect(tmp_path / "migration.db")
    connection.executescript(sqlite_sql)
    columns = {row[1] for row in connection.execute("PRAGMA table_info(action_operations)")}
    assert columns == set(ActionOperation.__table__.columns.keys())
    assert "uq_action_operations_idempotency_namespace" in sql
    assert "DEFAULT (gen_random_uuid())::text" in sql
    assert str(ActionOperation.__table__.c.operation_id.server_default.arg) == "(gen_random_uuid())::text"
    engine = create_engine(f"sqlite:///{tmp_path / 'tables.db'}")
    User.__table__.create(engine)
    ActionOperation.__table__.create(engine)
    assert User.__table__.exists if False else "users" in __import__("sqlalchemy").inspect(engine).get_table_names()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("token_jti", "other-jti"),
        ("actor_pubkey", "aa" * 32),
        ("oauth_client_id", "other-client"),
        ("action", "draft_delete"),
        ("resource_id", "resource-1"),
        ("request_sha256", "99" * 32),
        ("step_up_challenge_id", "ab" * 16),
        ("contract_version", "hodlxxi.action-operation.v2"),
    ),
)
def test_reservation_rejects_reused_fingerprint_for_changed_binding_without_mutation(tmp_path, field, value):
    repo, engine = repository(tmp_path)
    supplied = reservation()
    with pytest.raises(InvalidReservationError, match="^invalid_reservation$"):
        repo.reserve(reservation(**{field: value}, request_fingerprint_sha256=supplied.request_fingerprint_sha256))
    with sessionmaker(bind=engine)() as session:
        assert session.query(ActionOperation).count() == 0


def test_reservation_rejects_bad_token_reference_and_idempotency_hash_without_mutation(tmp_path):
    repo, engine = repository(tmp_path)
    for invalid in (
        reservation(token_reference_sha256="00" * 32),
        reservation(idempotency_key_sha256="A" * 64),
    ):
        with pytest.raises(InvalidReservationError, match="^invalid_reservation$"):
            repo.reserve(invalid)
    with sessionmaker(bind=engine)() as session:
        assert session.query(ActionOperation).count() == 0


def test_terminal_started_at_is_bound_to_persisted_execution_boundary(tmp_path):
    repo, _ = repository(tmp_path)
    completed = repo.reserve(reservation()).operation
    assert repo.mark_executing(completed.operation_id, NOW + timedelta(seconds=1))
    assert not repo.finalize_completed(
        completed.operation_id, receipt(completed.operation_id, started_at="2026-07-20T12:00:00.500000Z")
    )
    preserved = repo.get_by_operation_id(completed.operation_id)
    assert preserved.state == "executing" and _utc(preserved.started_at) == NOW + timedelta(seconds=1)
    assert repo.finalize_completed(completed.operation_id, receipt(completed.operation_id))

    executing_failed = repo.reserve(reservation(idempotency_key_sha256="88" * 32)).operation
    assert repo.mark_executing(executing_failed.operation_id, NOW + timedelta(seconds=1))
    assert not repo.finalize_failed(
        executing_failed.operation_id,
        receipt(
            executing_failed.operation_id,
            "failed",
            "2026-07-20T12:00:00.500000Z",
            idempotency_key_sha256="88" * 32,
        ),
    )
    assert repo.get_by_operation_id(executing_failed.operation_id).state == "executing"

    reserved_failed = repo.reserve(reservation(idempotency_key_sha256="99" * 32)).operation
    assert not repo.finalize_failed(
        reserved_failed.operation_id,
        receipt(reserved_failed.operation_id, "failed", idempotency_key_sha256="99" * 32),
    )
    assert repo.get_by_operation_id(reserved_failed.operation_id).state == "reserved"
    assert repo.finalize_failed(
        reserved_failed.operation_id,
        receipt(
            reserved_failed.operation_id,
            "failed",
            "2026-07-20T12:00:00.000000Z",
            idempotency_key_sha256="99" * 32,
        ),
    )
    assert not repo.finalize_failed(
        reserved_failed.operation_id,
        receipt(
            reserved_failed.operation_id,
            "failed",
            "2026-07-20T12:00:00.000000Z",
            idempotency_key_sha256="99" * 32,
        ),
    )


def _utc(value):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def test_database_failed_result_and_empty_code_invariants_and_completed_semantics(tmp_path):
    repo, engine = repository(tmp_path)
    failed = repo.reserve(reservation()).operation
    assert repo.finalize_failed(
        failed.operation_id, receipt(failed.operation_id, "failed", "2026-07-20T12:00:00.000000Z")
    )
    for values in ({"result_sha256": "77" * 32}, {"failure_code": ""}):
        with sessionmaker(bind=engine)() as session:
            with pytest.raises(IntegrityError):
                session.execute(
                    update(ActionOperation).where(ActionOperation.operation_id == failed.operation_id).values(**values)
                )
                session.commit()

    completed = repo.reserve(reservation(idempotency_key_sha256="aa" * 32)).operation
    assert repo.mark_executing(completed.operation_id, NOW + timedelta(seconds=1))
    assert repo.finalize_completed(
        completed.operation_id, receipt(completed.operation_id, idempotency_key_sha256="aa" * 32)
    )
    stored = repo.get_by_operation_id(completed.operation_id)
    assert stored.result_sha256 == "77" * 32 and stored.failure_code is None

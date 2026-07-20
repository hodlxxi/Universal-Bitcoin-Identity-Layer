from __future__ import annotations

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from coincurve import PrivateKey, PublicKeyXOnly
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import ActionStepUpChallenge
from app.services.action_step_up import (
    PROOF_SCHEMA,
    SIGNATURE_FORMAT,
    ActionStepUpService,
    StepUpProof,
    StepUpReason,
    canonical_signed_bytes,
)
from app.services.action_step_up_storage import SqlAlchemyActionStepUpRepository


def test_repository_native_sql_migration_matches_model(tmp_path):
    migration = Path("migrations/2026-07-20_action_step_up_challenges.sql")
    connection = sqlite3.connect(tmp_path / "migration.db")
    connection.executescript(migration.read_text(encoding="utf-8"))
    columns = {row[1] for row in connection.execute("PRAGMA table_info(action_step_up_challenges)")}
    assert columns == set(ActionStepUpChallenge.__table__.columns.keys())
    indexes = {row[1] for row in connection.execute("PRAGMA index_list(action_step_up_challenges)")}
    assert {index.name for index in ActionStepUpChallenge.__table__.indexes} <= indexes
    assert "migrations/action_step_up_challenges_v1.py" not in migration.read_text(encoding="utf-8")


def test_storage_consumes_concurrently_exactly_once_and_persists_no_signature_or_bearer(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'proof.db'}", connect_args={"check_same_thread": False})
    ActionStepUpChallenge.__table__.create(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    repository = SqlAlchemyActionStepUpRepository(factory)
    now = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
    service = ActionStepUpService(repository, clock=lambda: now)
    private_key = PrivateKey()
    actor = PublicKeyXOnly.from_secret(private_key.secret).format().hex()
    challenge = service.issue_challenge(
        actor_pubkey=actor,
        oauth_client_id="client",
        token_jti="jti",
        action="covenant_draft_create",
        resource_id=None,
        request_sha256=hashlib.sha256(b"request").hexdigest(),
    )
    signature = private_key.sign_schnorr(hashlib.sha256(canonical_signed_bytes(challenge)).digest())
    proof = StepUpProof(PROOF_SCHEMA, challenge.challenge_id, signature, SIGNATURE_FORMAT)

    def attempt():
        return service.verify_and_consume(
            proof=proof,
            actor_pubkey=actor,
            oauth_client_id="client",
            token_jti="jti",
            action="covenant_draft_create",
            resource_id=None,
            request_sha256=challenge.request_sha256,
        ).reason_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        reasons = list(pool.map(lambda _: attempt(), range(2)))
    assert sorted(reason.value for reason in reasons) == ["challenge_consumed", "verified"]
    with factory() as session:
        row = session.query(ActionStepUpChallenge).one()
        values = vars(row)
        assert "signature" not in values and "bearer_token" not in values
        assert "request_body" not in values and "access_token" not in values
        assert row.consumed_at is not None


def test_atomic_storage_expiration_predicate_is_exclusive():
    import inspect as python_inspect

    source = python_inspect.getsource(SqlAlchemyActionStepUpRepository.consume)
    assert "ActionStepUpChallenge.expires_at > consumed_at" in source
    assert "ActionStepUpChallenge.expires_at >= consumed_at" not in source

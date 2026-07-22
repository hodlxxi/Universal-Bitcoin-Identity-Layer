from concurrent.futures import ThreadPoolExecutor
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from threading import Lock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from coincurve import PrivateKey, PublicKeyXOnly
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import ActionOperation, ActionStepUpChallenge
from app.services.action_authorization import ActionName, IdentityClass
from app.services.action_operation_storage import SqlAlchemyActionOperationRepository
from app.services.action_step_up import (
    CHALLENGE_SCHEMA,
    PROOF_SCHEMA,
    SIGNATURE_DOMAIN,
    SIGNATURE_FORMAT,
    StepUpChallenge,
    StepUpProof,
    canonical_signed_bytes,
)
from app.services.action_step_up_operation_storage import SqlAlchemyAtomicStepUpOperationRepository
from app.services.action_step_up_storage import SqlAlchemyActionStepUpRepository
from app.services.action_receipt import parse_action_receipt
from app.services.current_entitlement import EntitlementDecision
from app.services.internal_action_gateway import (
    GatewayReason,
    HandlerResult,
    InternalActionGateway,
    InternalActionInvocation,
)
from app.services.oauth_bearer_validation import BearerPrincipal

NOW = datetime(2026, 7, 21, 12, tzinfo=timezone.utc)


def test_file_backed_sqlite_concurrent_exact_callers_dispatch_at_most_once(tmp_path):
    actor_key = ec.derive_private_key(11, ec.SECP256K1())
    actor = (
        actor_key.public_key()
        .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)[1:]
        .hex()
    )
    signer_key = ec.derive_private_key(23, ec.SECP256K1())
    signer_public = (
        signer_key.public_key()
        .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
        .hex()
    )
    engine = create_engine(
        f"sqlite:///{tmp_path / 'gateway.db'}", connect_args={"check_same_thread": False, "timeout": 30}
    )
    ActionOperation.__table__.create(engine)
    repository = SqlAlchemyActionOperationRepository(sessionmaker(bind=engine, expire_on_commit=False))
    counter = {"calls": 0}
    lock = Lock()

    def handler(payload):
        with lock:
            counter["calls"] += 1
        return HandlerResult.completed({"accepted": True})

    principal = BearerPrincipal(
        actor,
        "user",
        "client",
        frozenset({"self:read"}),
        "jti",
        NOW,
        NOW + timedelta(hours=1),
        "hodlxxi.oauth.access-token.v1",
    )
    gateway = InternalActionGateway(
        bearer_validator=lambda _: principal,
        entitlement_resolver=lambda _: EntitlementDecision(actor, IdentityClass.LIMITED, False, "test"),
        operation_repository=repository,
        handlers={ActionName.SELF_READ: handler},
        receipt_signer=lambda message: signer_key.sign(message, ec.ECDSA(hashes.SHA256())).hex(),
        signer_public_key=signer_public,
        clock=lambda: NOW + timedelta(seconds=1),
    )
    invocation = InternalActionInvocation(
        "encoded.jwt.token", "client", ActionName.SELF_READ, None, "concurrent-key", {"same": True}
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: gateway.invoke(invocation), range(2)))

    assert counter["calls"] == 1
    assert {result.reason for result in results} <= {
        GatewayReason.COMPLETED,
        GatewayReason.REPLAY,
        GatewayReason.OPERATION_IN_PROGRESS,
    }
    assert sum(result.reason is GatewayReason.COMPLETED for result in results) == 1
    rows = [repository.get_by_operation_id(result.operation_id) for result in results]
    assert len({row.operation_id for row in rows}) == 1
    assert rows[0].state == "completed"


def test_real_atomic_step_up_gateway_consumes_reserves_receipts_and_replays(tmp_path):
    actor_key = PrivateKey()
    actor = PublicKeyXOnly.from_secret(actor_key.secret).format().hex()
    signer_key = ec.derive_private_key(29, ec.SECP256K1())
    signer_public = signer_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    ).hex()
    engine = create_engine(
        f"sqlite:///{tmp_path / 'step-up-gateway.db'}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    ActionStepUpChallenge.__table__.create(engine)
    ActionOperation.__table__.create(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    operation_repository = SqlAlchemyActionOperationRepository(factory)
    atomic_repository = SqlAlchemyAtomicStepUpOperationRepository(factory)
    request_payload = {"draft": 1}
    request_sha256 = hashlib.sha256(b'{"draft":1}').hexdigest()
    challenge = StepUpChallenge(
        CHALLENGE_SCHEMA,
        uuid.uuid4().hex,
        actor,
        "client",
        "jti",
        ActionName.COVENANT_DRAFT_CREATE.value,
        None,
        request_sha256,
        uuid.uuid4().hex + uuid.uuid4().hex,
        NOW,
        NOW + timedelta(minutes=5),
        SIGNATURE_DOMAIN,
    )
    SqlAlchemyActionStepUpRepository(factory).create(challenge)
    proof = StepUpProof(
        PROOF_SCHEMA,
        challenge.challenge_id,
        actor_key.sign_schnorr(hashlib.sha256(canonical_signed_bytes(challenge)).digest()),
        SIGNATURE_FORMAT,
    )
    counter = {"calls": 0}

    def handler(_payload):
        counter["calls"] += 1
        return HandlerResult.completed({"draft_id": "d-1"})

    principal = BearerPrincipal(
        actor,
        "user",
        "client",
        frozenset({"covenant:draft:create"}),
        "jti",
        NOW,
        NOW + timedelta(hours=1),
        "hodlxxi.oauth.access-token.v1",
    )
    gateway = InternalActionGateway(
        bearer_validator=lambda _: principal,
        entitlement_resolver=lambda _: EntitlementDecision(actor, IdentityClass.FULL, True, "test"),
        operation_repository=operation_repository,
        atomic_step_up_repository=atomic_repository,
        handlers={ActionName.COVENANT_DRAFT_CREATE: handler},
        receipt_signer=lambda message: signer_key.sign(message, ec.ECDSA(hashes.SHA256())).hex(),
        signer_public_key=signer_public,
        clock=lambda: NOW + timedelta(seconds=1),
    )
    invocation = InternalActionInvocation(
        "encoded.jwt.token",
        "client",
        ActionName.COVENANT_DRAFT_CREATE,
        None,
        "atomic-key",
        request_payload,
        proof,
    )

    first = gateway.invoke(invocation)
    assert first.reason is GatewayReason.COMPLETED and counter["calls"] == 1
    operation = operation_repository.get_by_operation_id(first.operation_id)
    receipt = parse_action_receipt(first.receipt)
    assert operation.step_up_challenge_id == challenge.challenge_id
    assert len(operation.step_up_verification_sha256) == 64
    assert operation.step_up_verification_sha256 == operation.step_up_verification_sha256.lower()
    assert receipt["step_up_challenge_id"] == operation.step_up_challenge_id
    assert receipt["step_up_verification_sha256"] == operation.step_up_verification_sha256
    with factory() as session:
        assert session.get(ActionStepUpChallenge, challenge.challenge_id).consumed_at is not None

    replay = gateway.invoke(invocation)
    assert replay.reason is GatewayReason.REPLAY and replay.receipt == first.receipt
    assert counter["calls"] == 1
    conflict = gateway.invoke(
        InternalActionInvocation(
            "encoded.jwt.token",
            "client",
            ActionName.COVENANT_DRAFT_CREATE,
            None,
            "atomic-key",
            {"draft": 2},
            proof,
        )
    )
    assert conflict.reason is GatewayReason.IDEMPOTENCY_CONFLICT and counter["calls"] == 1

    rejected = gateway.invoke(
        InternalActionInvocation(
            "encoded.jwt.token",
            "client",
            ActionName.COVENANT_DRAFT_CREATE,
            None,
            "other-key",
            request_payload,
            proof,
        )
    )
    assert rejected.reason is GatewayReason.STEP_UP_REJECTED and counter["calls"] == 1

    racing_challenge = StepUpChallenge(
        CHALLENGE_SCHEMA,
        uuid.uuid4().hex,
        actor,
        "client",
        "jti",
        ActionName.COVENANT_DRAFT_CREATE.value,
        None,
        request_sha256,
        uuid.uuid4().hex + uuid.uuid4().hex,
        NOW,
        NOW + timedelta(minutes=5),
        SIGNATURE_DOMAIN,
    )
    SqlAlchemyActionStepUpRepository(factory).create(racing_challenge)
    racing_proof = StepUpProof(
        PROOF_SCHEMA,
        racing_challenge.challenge_id,
        actor_key.sign_schnorr(hashlib.sha256(canonical_signed_bytes(racing_challenge)).digest()),
        SIGNATURE_FORMAT,
    )
    racing_invocation = InternalActionInvocation(
        "encoded.jwt.token",
        "client",
        ActionName.COVENANT_DRAFT_CREATE,
        None,
        "racing-key",
        request_payload,
        racing_proof,
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        racing_results = list(pool.map(lambda _: gateway.invoke(racing_invocation), range(2)))
    assert counter["calls"] == 2
    assert {result.reason for result in racing_results} <= {
        GatewayReason.COMPLETED,
        GatewayReason.REPLAY,
        GatewayReason.OPERATION_IN_PROGRESS,
        GatewayReason.STEP_UP_REJECTED,
        GatewayReason.STORAGE_UNAVAILABLE,
    }
    assert sum(result.reason is GatewayReason.COMPLETED for result in racing_results) <= 1

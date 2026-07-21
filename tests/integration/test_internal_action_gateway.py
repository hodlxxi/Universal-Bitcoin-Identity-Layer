from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Lock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import ActionOperation
from app.services.action_authorization import ActionName, IdentityClass
from app.services.action_operation_storage import SqlAlchemyActionOperationRepository
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

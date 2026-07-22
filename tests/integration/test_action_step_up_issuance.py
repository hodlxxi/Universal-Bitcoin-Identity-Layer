import hashlib
from datetime import datetime, timedelta, timezone

from coincurve import PrivateKey, PublicKeyXOnly
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import ActionOperation, ActionStepUpChallenge
from app.services.action_authorization import ActionName, IdentityClass
from app.services.action_step_up import ActionStepUpService, canonical_signed_bytes
from app.services.action_step_up_issuance import (
    ActionStepUpIssuanceOrchestrator,
    StepUpIssuanceReason,
    StepUpIssuanceRequest,
)
from app.services.action_step_up_storage import SqlAlchemyActionStepUpRepository
from app.services.current_entitlement import EntitlementDecision
from app.services.oauth_bearer_validation import BearerPrincipal


def test_real_sqlalchemy_issuance_persists_only_unconsumed_challenges(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'issuance.db'}",
        connect_args={"check_same_thread": False},
    )
    ActionStepUpChallenge.__table__.create(engine)
    ActionOperation.__table__.create(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    repository = SqlAlchemyActionStepUpRepository(factory)
    now = datetime(2026, 7, 22, 12, tzinfo=timezone.utc)
    service = ActionStepUpService(repository, clock=lambda: now)
    private_key = PrivateKey(b"\x33" * 32)
    actor = PublicKeyXOnly.from_secret(private_key.secret).format().hex()
    bearer = "encoded.jwt.token.never.persisted"
    principal = BearerPrincipal(
        actor,
        "user",
        "trusted-client",
        frozenset({"covenant:draft:create"}),
        "trusted-jti",
        now - timedelta(minutes=1),
        now + timedelta(hours=1),
        "hodlxxi.oauth.access-token.v1",
    )
    entitlement = EntitlementDecision(actor, IdentityClass.FULL, True, "integration")
    orchestrator = ActionStepUpIssuanceOrchestrator(
        bearer_validator=lambda token: principal if token == bearer else None,
        entitlement_resolver=lambda subject: entitlement,
        challenge_issuer=service,
    )
    payload = {"unicode": "é", "draft": {"amount": 21}}
    expected_digest = hashlib.sha256(b'{"draft":{"amount":21},"unicode":"\\u00e9"}').hexdigest()

    first = orchestrator.issue(
        StepUpIssuanceRequest(
            bearer,
            "trusted-client",
            ActionName.COVENANT_DRAFT_CREATE,
            None,
            payload,
        )
    )
    second = orchestrator.issue(
        StepUpIssuanceRequest(
            bearer,
            "trusted-client",
            ActionName.COVENANT_DRAFT_CREATE,
            None,
            payload,
        )
    )

    assert first.reason is second.reason is StepUpIssuanceReason.ISSUED
    assert first.challenge.challenge_id != second.challenge.challenge_id
    assert first.challenge.nonce != second.challenge.nonce
    assert first.challenge.consumed_at is second.challenge.consumed_at is None
    assert first.challenge.request_sha256 == expected_digest
    assert canonical_signed_bytes(first.challenge).startswith(b'{"challenge":')

    with factory() as session:
        rows = session.query(ActionStepUpChallenge).order_by(ActionStepUpChallenge.challenge_id).all()
        assert len(rows) == 2
        assert session.query(ActionOperation).count() == 0
        for row in rows:
            assert row.actor_pubkey == actor
            assert row.oauth_client_id == "trusted-client"
            assert row.token_jti == "trusted-jti"
            assert row.action == ActionName.COVENANT_DRAFT_CREATE.value
            assert row.resource_id is None
            assert row.request_sha256 == expected_digest
            assert row.consumed_at is None
            persisted = vars(row)
            assert bearer not in repr(persisted)
            assert "signature" not in persisted
            assert "bearer_token" not in persisted


def test_repository_failure_maps_without_leaking_or_returning_challenge(tmp_path):
    class FailingRepository:
        def create(self, challenge):
            raise RuntimeError("sqlite path and secret")

    now = datetime(2026, 7, 22, 12, tzinfo=timezone.utc)
    actor = PublicKeyXOnly.from_secret(PrivateKey(b"\x44" * 32).secret).format().hex()
    principal = BearerPrincipal(
        actor,
        "user",
        "client",
        frozenset({"covenant:draft:create"}),
        "jti",
        now,
        now + timedelta(hours=1),
        "hodlxxi.oauth.access-token.v1",
    )
    orchestrator = ActionStepUpIssuanceOrchestrator(
        bearer_validator=lambda _: principal,
        entitlement_resolver=lambda _: EntitlementDecision(actor, IdentityClass.FULL, True, "test"),
        challenge_issuer=ActionStepUpService(FailingRepository(), clock=lambda: now),
    )
    result = orchestrator.issue(StepUpIssuanceRequest("token", "client", ActionName.COVENANT_DRAFT_CREATE, None, {}))
    assert result.reason is StepUpIssuanceReason.STORAGE_UNAVAILABLE
    assert result.challenge is None
    assert "sqlite path and secret" not in repr(result)

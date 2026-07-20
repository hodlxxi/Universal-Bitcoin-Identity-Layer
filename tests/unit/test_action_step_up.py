from __future__ import annotations

import hashlib
import inspect
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

from app.services.action_step_up import (
    CHALLENGE_SCHEMA,
    DEFAULT_CHALLENGE_LIFETIME_SECONDS,
    PROOF_SCHEMA,
    SIGNATURE_DOMAIN,
    SIGNATURE_FORMAT,
    VERIFICATION_SCHEMA,
    ActionStepUpService,
    StepUpChallenge,
    StepUpError,
    StepUpProof,
    StepUpReason,
    VerifiedStepUp,
    canonical_signed_bytes,
    parse_step_up_proof,
)

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
REQUEST_HASH = hashlib.sha256(b'{"amount":1}').hexdigest()


class MemoryRepository:
    def __init__(self):
        self.rows = {}
        self.fail_read = False
        self.fail_consume = False

    def create(self, challenge):
        self.rows[challenge.challenge_id] = challenge

    def get(self, challenge_id):
        if self.fail_read:
            raise RuntimeError("secret database detail")
        return self.rows.get(challenge_id)

    def consume(self, challenge, consumed_at):
        if self.fail_consume:
            raise RuntimeError("secret database detail")
        current = self.rows.get(challenge.challenge_id)
        if current is None or current.consumed_at is not None or current.expires_at <= consumed_at:
            return False
        self.rows[challenge.challenge_id] = replace(current, consumed_at=consumed_at)
        return True


def actor(private_key):
    return PublicKeyXOnly.from_secret(private_key.secret).format().hex()


def issue(service, private_key, **overrides):
    values = {
        "actor_pubkey": actor(private_key),
        "oauth_client_id": "client-1",
        "token_jti": "token-1",
        "action": "covenant_draft_create",
        "resource_id": None,
        "request_sha256": REQUEST_HASH,
    }
    values.update(overrides)
    return service.issue_challenge(**values)


def proof(challenge, private_key):
    digest = hashlib.sha256(canonical_signed_bytes(challenge)).digest()
    return StepUpProof(PROOF_SCHEMA, challenge.challenge_id, private_key.sign_schnorr(digest), SIGNATURE_FORMAT)


def verify(service, challenge, signed_proof, **overrides):
    values = {
        "proof": signed_proof,
        "actor_pubkey": challenge.actor_pubkey,
        "oauth_client_id": challenge.oauth_client_id,
        "token_jti": challenge.token_jti,
        "action": challenge.action,
        "resource_id": challenge.resource_id,
        "request_sha256": challenge.request_sha256,
    }
    values.update(overrides)
    return service.verify_and_consume(**values)


def test_imports_and_exact_contract_constants():
    assert CHALLENGE_SCHEMA == "hodlxxi.action-step-up.challenge.v1"
    assert PROOF_SCHEMA == "hodlxxi.action-step-up.proof.v1"
    assert VERIFICATION_SCHEMA == "hodlxxi.action-step-up.verification.v1"
    assert SIGNATURE_DOMAIN == "HODLXXI_ACTION_STEP_UP_V1"


def test_pure_module_has_no_forbidden_runtime_dependencies():
    import app.services.action_step_up as module

    source = inspect.getsource(module).lower()
    for forbidden in (
        "flask",
        "session[",
        "app.app",
        "mcp",
        "wallet",
        "lnd",
        "bitcoin rpc",
        "subprocess",
        "requests.",
        "redis",
    ):
        assert forbidden not in source


def test_issue_is_bounded_and_only_for_policy_step_up_action():
    service = ActionStepUpService(MemoryRepository(), clock=lambda: NOW)
    key = PrivateKey()
    challenge = issue(service, key)
    assert challenge.schema == CHALLENGE_SCHEMA
    assert challenge.signature_domain == SIGNATURE_DOMAIN
    assert challenge.expires_at - challenge.issued_at == timedelta(seconds=DEFAULT_CHALLENGE_LIFETIME_SECONDS)
    assert challenge.resource_id is None
    assert set(challenge.to_dict()) == {
        "schema",
        "challenge_id",
        "actor_pubkey",
        "oauth_client_id",
        "token_jti",
        "action",
        "resource_id",
        "request_sha256",
        "nonce",
        "issued_at",
        "expires_at",
        "signature_domain",
    }
    assert not ({"bearer_token", "client_secret", "private_key"} & set(challenge.to_dict()))
    with pytest.raises(StepUpError) as exc:
        issue(service, key, action="self_read")
    assert exc.value.reason is StepUpReason.STEP_UP_NOT_REQUIRED
    with pytest.raises(StepUpError) as exc:
        issue(service, key, action="covenant:create")
    assert exc.value.reason is StepUpReason.UNKNOWN_ACTION


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("actor_pubkey", "02" + "ab" * 32, StepUpReason.INVALID_ACTOR),
        ("actor_pubkey", "AB" * 32, StepUpReason.INVALID_ACTOR),
        ("request_sha256", "A" * 64, StepUpReason.INVALID_REQUEST),
        ("request_sha256", "0" * 63, StepUpReason.INVALID_REQUEST),
        ("oauth_client_id", " x", StepUpReason.INVALID_REQUEST),
        ("oauth_client_id", "x" * 257, StepUpReason.INVALID_REQUEST),
        ("token_jti", "", StepUpReason.INVALID_REQUEST),
        ("token_jti", "x\n", StepUpReason.INVALID_REQUEST),
        ("resource_id", "", StepUpReason.INVALID_REQUEST),
        ("resource_id", " x", StepUpReason.INVALID_REQUEST),
        ("resource_id", "x" * 257, StepUpReason.INVALID_REQUEST),
    ],
)
def test_issue_rejects_malformed_or_unbounded_bindings(field, value, reason):
    service = ActionStepUpService(MemoryRepository(), clock=lambda: NOW)
    with pytest.raises(StepUpError) as exc:
        issue(service, PrivateKey(), **{field: value})
    assert exc.value.reason is reason


def test_lifetime_is_bounded():
    service = ActionStepUpService(MemoryRepository(), clock=lambda: NOW)
    with pytest.raises(StepUpError) as exc:
        issue(service, PrivateKey(), lifetime_seconds=601)
    assert exc.value.reason is StepUpReason.INVALID_REQUEST


def test_canonical_signed_bytes_are_deterministic_and_bind_all_fields():
    challenge = issue(ActionStepUpService(MemoryRepository(), clock=lambda: NOW), PrivateKey())
    assert canonical_signed_bytes(challenge) == canonical_signed_bytes(challenge)
    for field, value in (
        ("oauth_client_id", "other"),
        ("token_jti", "other"),
        ("action", "self_read"),
        ("resource_id", "r"),
        ("request_sha256", "1" * 64),
        ("actor_pubkey", "2" * 64),
    ):
        assert canonical_signed_bytes(replace(challenge, **{field: value})) != canonical_signed_bytes(challenge)


def test_real_schnorr_proof_verifies_and_consumes_once():
    repository = MemoryRepository()
    service = ActionStepUpService(repository, clock=lambda: NOW)
    key = PrivateKey()
    challenge = issue(service, key)
    result = verify(service, challenge, proof(challenge, key))
    assert isinstance(result, VerifiedStepUp) and result.verified
    assert result.reason_code is StepUpReason.VERIFIED
    assert result.to_dict()["verification_schema"] == VERIFICATION_SCHEMA
    assert "signature" not in result.to_dict() and "nonce" not in result.to_dict()
    replay = verify(service, challenge, proof(challenge, key))
    assert replay.reason_code is StepUpReason.CHALLENGE_CONSUMED


def test_proof_parser_requires_exact_bounded_canonical_fields():
    key = PrivateKey()
    challenge = issue(ActionStepUpService(MemoryRepository(), clock=lambda: NOW), key)
    signed = proof(challenge, key)
    parsed = parse_step_up_proof(signed.to_dict())
    assert parsed.to_dict() == signed.to_dict()
    for malformed in (
        {**signed.to_dict(), "extra": True},
        {**signed.to_dict(), "schema": "legacy"},
        {**signed.to_dict(), "signature": "A" * 128},
        {**signed.to_dict(), "challenge_id": "x" * 65},
    ):
        with pytest.raises(StepUpError):
            parse_step_up_proof(malformed)


def test_wrong_key_and_binding_mismatch_do_not_consume():
    repository = MemoryRepository()
    service = ActionStepUpService(repository, clock=lambda: NOW)
    key = PrivateKey()
    challenge = issue(service, key)
    assert verify(service, challenge, proof(challenge, PrivateKey())).reason_code is StepUpReason.INVALID_SIGNATURE
    assert repository.rows[challenge.challenge_id].consumed_at is None
    mismatch_cases = {
        "actor_pubkey": actor(PrivateKey()),
        "oauth_client_id": "other",
        "token_jti": "other",
        "action": "self_read",
        "resource_id": "other",
        "request_sha256": "1" * 64,
    }
    for field, value in mismatch_cases.items():
        assert (
            verify(service, challenge, proof(challenge, key), **{field: value}).reason_code
            is StepUpReason.BINDING_MISMATCH
        )
        assert repository.rows[challenge.challenge_id].consumed_at is None


def test_expired_future_and_invalid_time_challenges_fail_closed():
    repository = MemoryRepository()
    key = PrivateKey()
    challenge = issue(ActionStepUpService(repository, clock=lambda: NOW), key)
    assert (
        verify(
            ActionStepUpService(repository, clock=lambda: NOW + timedelta(minutes=6)), challenge, proof(challenge, key)
        ).reason_code
        is StepUpReason.CHALLENGE_EXPIRED
    )
    for changed in (
        replace(challenge, issued_at=NOW + timedelta(seconds=61)),
        replace(challenge, expires_at=challenge.issued_at),
        replace(challenge, expires_at=challenge.issued_at + timedelta(seconds=601)),
    ):
        repository.rows[challenge.challenge_id] = changed
        assert (
            verify(ActionStepUpService(repository, clock=lambda: NOW), changed, proof(changed, key)).reason_code
            is StepUpReason.INVALID_REQUEST
        )


def test_exact_expiration_boundary_is_expired_and_not_consumed():
    repository = MemoryRepository()
    key = PrivateKey()
    challenge = issue(ActionStepUpService(repository, clock=lambda: NOW), key)
    result = verify(
        ActionStepUpService(repository, clock=lambda: challenge.expires_at), challenge, proof(challenge, key)
    )
    assert result.reason_code is StepUpReason.CHALLENGE_EXPIRED
    assert repository.rows[challenge.challenge_id].consumed_at is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("challenge_id", "not-a-canonical-uuid"),
        ("actor_pubkey", "0" * 64),
        ("request_sha256", "f" * 63),
        ("nonce", "f" * 63),
        ("schema", "legacy"),
        ("signature_domain", "legacy"),
        ("oauth_client_id", " client"),
        ("token_jti", ""),
        ("action", "unsupported_action"),
        ("resource_id", "x" * 257),
        ("issued_at", NOW.replace(tzinfo=None)),
        ("expires_at", NOW + timedelta(seconds=601)),
        ("consumed_at", NOW - timedelta(seconds=1)),
    ],
)
def test_malformed_persisted_challenge_state_fails_closed(field, value):
    repository = MemoryRepository()
    key = PrivateKey()
    challenge = issue(ActionStepUpService(repository, clock=lambda: NOW), key)
    malformed = replace(challenge, **{field: value})
    repository.rows[challenge.challenge_id] = malformed
    result = verify(ActionStepUpService(repository, clock=lambda: NOW), challenge, proof(challenge, key))
    assert result.reason_code is StepUpReason.INVALID_REQUEST
    assert repository.rows[challenge.challenge_id] == malformed


def test_malformed_proof_and_storage_failures_are_safe():
    repository = MemoryRepository()
    key = PrivateKey()
    service = ActionStepUpService(repository, clock=lambda: NOW)
    challenge = issue(service, key)
    malformed = StepUpProof(PROOF_SCHEMA, challenge.challenge_id, b"x", SIGNATURE_FORMAT)
    assert verify(service, challenge, malformed).reason_code is StepUpReason.INVALID_SIGNATURE
    repository.fail_read = True
    assert verify(service, challenge, proof(challenge, key)).reason_code is StepUpReason.STORAGE_UNAVAILABLE
    repository.fail_read = False
    repository.fail_consume = True
    assert verify(service, challenge, proof(challenge, key)).reason_code is StepUpReason.STORAGE_UNAVAILABLE


def test_no_forgeable_policy_boolean_bridge_exists():
    import app.services.action_step_up as module

    assert not hasattr(module, "policy_step_up_verified")
    source = inspect.getsource(module)
    assert "step_up_verified" not in source


def test_documentation_states_authorization_non_claims():
    text = open("docs/ACTION_STEP_UP_PROOF_V1.md", encoding="utf-8").read().lower()
    for statement in (
        "does not integrate step-up proof into action authorization",
        "audit and application data, not an unforgeable credential",
        "must call `verify_and_consume()` directly",
        "must not accept a client-supplied boolean or reconstructed result object",
    ):
        assert statement in text

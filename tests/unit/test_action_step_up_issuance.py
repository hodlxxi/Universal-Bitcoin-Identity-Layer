import hashlib
import inspect
import math
import uuid
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

from app.services.action_authorization import ActionName, IdentityClass
from app.services.action_request_canonicalization import MAX_REQUEST_BYTES, canonical_payload_bytes
from app.services.action_step_up import CHALLENGE_SCHEMA, SIGNATURE_DOMAIN, StepUpChallenge, StepUpError, StepUpReason
from app.services.action_step_up_issuance import (
    ActionStepUpIssuanceOrchestrator,
    StepUpIssuanceReason,
    StepUpIssuanceRequest,
    StepUpIssuanceResult,
)
from app.services.current_entitlement import EntitlementDecision, EntitlementDenied, EntitlementUnavailable
from app.services.internal_action_gateway import canonical_payload_bytes as gateway_canonical_payload_bytes
from app.services.oauth_bearer_validation import BearerPrincipal, BearerValidationError

NOW = datetime(2026, 7, 22, 12, tzinfo=timezone.utc)
ACTOR = PublicKeyXOnly.from_secret(PrivateKey(b"\x11" * 32).secret).format().hex()
OTHER = PublicKeyXOnly.from_secret(PrivateKey(b"\x22" * 32).secret).format().hex()


def principal(**changes):
    values = dict(
        subject=ACTOR,
        user_id="user",
        client_id="client",
        scopes=frozenset({"covenant:draft:create"}),
        jti="token-jti",
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        token_contract="hodlxxi.oauth.access-token.v1",
    )
    values.update(changes)
    return BearerPrincipal(**values)


def entitlement(**changes):
    values = dict(
        subject=ACTOR,
        identity_class=IdentityClass.FULL,
        current_full_relation_satisfied=True,
        evidence_source="test",
    )
    values.update(changes)
    return EntitlementDecision(**values)


def request(**changes):
    values = dict(
        encoded_bearer_token="encoded.jwt.token",
        expected_oauth_client_id="client",
        action=ActionName.COVENANT_DRAFT_CREATE,
        resource_id=None,
        request_payload={"b": 2, "a": ["é", True]},
    )
    values.update(changes)
    return StepUpIssuanceRequest(**values)


class FakeIssuer:
    def __init__(self):
        self.calls = []
        self.failure = None
        self.mutate = None

    def issue_challenge(self, **bindings):
        self.calls.append(bindings)
        if self.failure:
            raise self.failure
        challenge = StepUpChallenge(
            CHALLENGE_SCHEMA,
            uuid.uuid4().hex,
            bindings["actor_pubkey"],
            bindings["oauth_client_id"],
            bindings["token_jti"],
            ActionName(bindings["action"]).value,
            bindings["resource_id"],
            bindings["request_sha256"],
            "ab" * 32,
            NOW,
            NOW + timedelta(seconds=bindings["lifetime_seconds"]),
            SIGNATURE_DOMAIN,
        )
        return self.mutate(challenge) if self.mutate else challenge


def make_orchestrator(*, validator=None, resolver=None, issuer=None, lifetime=300):
    issuer = issuer or FakeIssuer()
    calls = {"validator": 0, "resolver": 0}

    def default_validator(token):
        calls["validator"] += 1
        return principal()

    def default_resolver(actor):
        calls["resolver"] += 1
        return entitlement(subject=actor)

    return (
        ActionStepUpIssuanceOrchestrator(
            bearer_validator=validator or default_validator,
            entitlement_resolver=resolver or default_resolver,
            challenge_issuer=issuer,
            lifetime_seconds=lifetime,
        ),
        issuer,
        calls,
    )


@pytest.mark.parametrize(
    "bad",
    [
        b"bytes",
        bytearray(b"bytes"),
        (1, 2),
        {1: "non-string key"},
        math.nan,
        math.inf,
        -math.inf,
    ],
)
def test_invalid_payloads_fail_before_dependencies(bad):
    orchestrator, issuer, calls = make_orchestrator()
    result = orchestrator.issue(request(request_payload=bad))
    assert result.reason is StepUpIssuanceReason.INVALID_REQUEST
    assert not issuer.calls and calls == {"validator": 0, "resolver": 0}


def test_wrong_request_type_cycle_and_oversize_are_invalid_without_challenge():
    orchestrator, issuer, calls = make_orchestrator()
    cyclic = []
    cyclic.append(cyclic)
    for value in [object(), request(request_payload=cyclic), request(request_payload="x" * MAX_REQUEST_BYTES)]:
        assert orchestrator.issue(value).reason is StepUpIssuanceReason.INVALID_REQUEST
    assert not issuer.calls and calls == {"validator": 0, "resolver": 0}


@pytest.mark.parametrize(
    "changes, reason",
    [
        ({"encoded_bearer_token": ""}, StepUpIssuanceReason.INVALID_REQUEST),
        ({"encoded_bearer_token": "x" * 16_385}, StepUpIssuanceReason.INVALID_REQUEST),
        ({"expected_oauth_client_id": " client"}, StepUpIssuanceReason.INVALID_REQUEST),
        ({"expected_oauth_client_id": "x" * 257}, StepUpIssuanceReason.INVALID_REQUEST),
        ({"resource_id": "bad\n"}, StepUpIssuanceReason.INVALID_REQUEST),
        ({"resource_id": "x" * 257}, StepUpIssuanceReason.INVALID_REQUEST),
        ({"action": "unknown"}, StepUpIssuanceReason.ACTION_UNAVAILABLE),
        ({"action": ActionName.SELF_READ}, StepUpIssuanceReason.ACTION_UNAVAILABLE),
        ({"action": ActionName.COVENANT_DRAFT_READ_SELF}, StepUpIssuanceReason.ACTION_UNAVAILABLE),
    ],
)
def test_envelope_and_action_availability(changes, reason):
    orchestrator, issuer, calls = make_orchestrator()
    assert orchestrator.issue(request(**changes)).reason is reason
    assert not issuer.calls and calls["resolver"] == 0


def test_canonical_bytes_are_gateway_identical_and_deterministic():
    left = {"z": [1, "é"], "a": {"y": False}}
    right = {"a": {"y": False}, "z": [1, "é"]}
    expected = b'{"a":{"y":false},"z":[1,"\\u00e9"]}'
    assert canonical_payload_bytes(left) == canonical_payload_bytes(right) == expected
    assert gateway_canonical_payload_bytes(left) == expected


@pytest.mark.parametrize(
    "validator",
    [
        lambda _: (_ for _ in ()).throw(BearerValidationError("secret")),
        lambda _: object(),
        lambda _: principal(subject="bad"),
        lambda _: principal(client_id="other"),
        lambda _: principal(jti=""),
        lambda _: principal(jti="x" * 129),
    ],
)
def test_authentication_failures_stop_entitlement_and_issuance(validator):
    issuer = FakeIssuer()
    resolver_calls = []
    orchestrator = ActionStepUpIssuanceOrchestrator(
        bearer_validator=validator,
        entitlement_resolver=lambda actor: resolver_calls.append(actor),
        challenge_issuer=issuer,
    )
    result = orchestrator.issue(request())
    assert result.reason is StepUpIssuanceReason.INVALID_TOKEN
    assert not resolver_calls and not issuer.calls and result.challenge is None


@pytest.mark.parametrize(
    "resolver, reason",
    [
        (lambda _: (_ for _ in ()).throw(EntitlementDenied("detail")), StepUpIssuanceReason.ENTITLEMENT_DENIED),
        (
            lambda _: (_ for _ in ()).throw(EntitlementUnavailable("detail")),
            StepUpIssuanceReason.ENTITLEMENT_UNAVAILABLE,
        ),
        (lambda _: (_ for _ in ()).throw(RuntimeError("detail")), StepUpIssuanceReason.ENTITLEMENT_UNAVAILABLE),
    ],
)
def test_entitlement_failures_are_bounded(resolver, reason):
    orchestrator, issuer, _ = make_orchestrator(resolver=resolver)
    result = orchestrator.issue(request())
    assert result.reason is reason and result.challenge is None and not issuer.calls
    assert "detail" not in repr(result)


@pytest.mark.parametrize(
    "principal_value, entitlement_value",
    [
        (principal(), entitlement(subject=OTHER)),
        (principal(), entitlement(identity_class=IdentityClass.GUEST)),
        (principal(), entitlement(identity_class=IdentityClass.LIMITED)),
        (principal(), entitlement(identity_class=IdentityClass.OPERATOR)),
        (principal(), entitlement(current_full_relation_satisfied=False)),
        (principal(scopes=frozenset()), entitlement()),
        (principal(scopes="covenant:draft:create"), entitlement()),
    ],
)
def test_policy_denials_precede_issuance(principal_value, entitlement_value):
    orchestrator, issuer, _ = make_orchestrator(
        validator=lambda _: principal_value,
        resolver=lambda _: entitlement_value,
    )
    assert orchestrator.issue(request()).reason is StepUpIssuanceReason.AUTHORIZATION_DENIED
    assert not issuer.calls


def test_success_uses_only_trusted_bindings_and_hashes_canonical_snapshot():
    payload = {"z": 2, "a": [1]}
    orchestrator, issuer, _ = make_orchestrator(lifetime=123)
    result = orchestrator.issue(request(resource_id="draft-slot", request_payload=payload))
    payload["a"].append(99)
    expected_hash = hashlib.sha256(b'{"a":[1],"z":2}').hexdigest()
    assert result.reason is StepUpIssuanceReason.ISSUED
    assert issuer.calls == [
        {
            "actor_pubkey": ACTOR,
            "oauth_client_id": "client",
            "token_jti": "token-jti",
            "action": ActionName.COVENANT_DRAFT_CREATE,
            "resource_id": "draft-slot",
            "request_sha256": expected_hash,
            "lifetime_seconds": 123,
        }
    ]
    assert result.challenge.request_sha256 == expected_hash
    assert "encoded.jwt.token" not in repr(issuer.calls)
    assert {field.name for field in fields(StepUpIssuanceRequest)} == {
        "encoded_bearer_token",
        "expected_oauth_client_id",
        "action",
        "resource_id",
        "request_payload",
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda challenge: object(),
        lambda challenge: replace(challenge, actor_pubkey=OTHER),
        lambda challenge: replace(challenge, oauth_client_id="other"),
        lambda challenge: replace(challenge, token_jti="other"),
        lambda challenge: replace(challenge, action=ActionName.SELF_READ.value),
        lambda challenge: replace(challenge, resource_id="other"),
        lambda challenge: replace(challenge, request_sha256="0" * 64),
        lambda challenge: replace(challenge, schema="wrong"),
        lambda challenge: replace(challenge, consumed_at=NOW),
    ],
)
def test_malformed_or_mismatched_issuer_result_fails_closed(mutate):
    issuer = FakeIssuer()
    issuer.mutate = mutate
    orchestrator, _, _ = make_orchestrator(issuer=issuer)
    result = orchestrator.issue(request())
    assert result.reason is StepUpIssuanceReason.INTERNAL_FAILURE and result.challenge is None


def test_issuer_failures_are_bounded_and_result_invariants_hold():
    issuer = FakeIssuer()
    issuer.failure = StepUpError(StepUpReason.STORAGE_UNAVAILABLE)
    orchestrator, _, _ = make_orchestrator(issuer=issuer)
    assert orchestrator.issue(request()).reason is StepUpIssuanceReason.STORAGE_UNAVAILABLE
    issuer.failure = RuntimeError("raw database secret")
    result = orchestrator.issue(request())
    assert result.reason is StepUpIssuanceReason.INTERNAL_FAILURE
    assert "raw database secret" not in repr(result)
    with pytest.raises(ValueError):
        StepUpIssuanceResult(StepUpIssuanceReason.ISSUED)
    with pytest.raises(ValueError):
        StepUpIssuanceResult("issued")
    with pytest.raises(ValueError):
        StepUpIssuanceResult(StepUpIssuanceReason.INVALID_TOKEN, FakeIssuer().issue_challenge(**issuer.calls[0]))


def test_constructor_lifetime_uses_service_bounds():
    for invalid in [True, 0, 601, 1.5]:
        with pytest.raises(ValueError):
            make_orchestrator(lifetime=invalid)


def test_module_has_dormant_structural_boundary():
    import app.services.action_step_up_issuance as module

    source = inspect.getsource(module).lower()
    forbidden = [
        "flask",
        "blueprint",
        "current_app",
        "mcp",
        "subprocess",
        "bitcoin",
        "lightning",
        "lnd",
        "nostr",
        "reserve_with_step_up",
        "verify_and_consume",
        "mark_executing",
        "receipt_signer",
        "handler",
    ]
    assert all(term not in source for term in forbidden)

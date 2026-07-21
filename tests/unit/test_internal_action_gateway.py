import hashlib
import inspect
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.services.action_authorization import (
    ActionName,
    EntitlementSnapshot,
    IdentityClass,
    authorize_action,
    ActionRequest,
)
from app.services.action_receipt import parse_action_receipt, verify_action_receipt
from app.services.current_entitlement import EntitlementDecision, EntitlementDenied, EntitlementUnavailable
from app.services.internal_action_gateway import (
    GatewayReason,
    HandlerResult,
    InternalActionGateway,
    InternalActionInvocation,
    ReceiptRetrievalRequest,
    authorization_decision_sha256,
)
from app.services.oauth_bearer_validation import BearerPrincipal, BearerValidationError
import app.services.internal_action_gateway as gateway_module

NOW = datetime(2026, 7, 21, 12, tzinfo=timezone.utc)
ACTOR_KEY = ec.derive_private_key(11, ec.SECP256K1())
OTHER_KEY = ec.derive_private_key(13, ec.SECP256K1())
SIGNER_KEY = ec.derive_private_key(19, ec.SECP256K1())


def xonly(key):
    return (
        key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)[1:].hex()
    )


ACTOR = xonly(ACTOR_KEY)
OTHER = xonly(OTHER_KEY)
SIGNER_PUBLIC = (
    SIGNER_KEY.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint).hex()
)


class FakeRepository:
    def __init__(self):
        self.operations = {}
        self.namespace = {}
        self.reservations = []
        self.mark_executing_result = True
        self.finalize_result = True
        self.raise_finalize = False
        self.mark_indeterminate_result = True

    def reserve(self, reservation):
        self.reservations.append(reservation)
        namespace = (reservation.actor_pubkey, reservation.oauth_client_id, reservation.idempotency_key_sha256)
        existing = self.namespace.get(namespace)
        if existing:
            status = (
                "replay"
                if existing.request_fingerprint_sha256 == reservation.request_fingerprint_sha256
                else "idempotency_conflict"
            )
            return SimpleNamespace(status=status, operation=deepcopy(existing), is_new=False)
        operation = SimpleNamespace(
            **vars(reservation),
            operation_id="11111111-1111-4111-8111-111111111111",
            state="reserved",
            started_at=None,
            receipt_json=None,
        )
        self.operations[operation.operation_id] = operation
        self.namespace[namespace] = operation
        return SimpleNamespace(status="new", operation=deepcopy(operation), is_new=True)

    def mark_executing(self, operation_id, started_at):
        if not self.mark_executing_result:
            return False
        row = self.operations[operation_id]
        if row.state != "reserved":
            return False
        row.state, row.started_at = "executing", started_at
        return True

    def finalize_completed(self, operation_id, receipt):
        return self._finalize(operation_id, receipt)

    def finalize_failed(self, operation_id, receipt):
        return self._finalize(operation_id, receipt)

    def _finalize(self, operation_id, receipt):
        if self.raise_finalize:
            raise RuntimeError("database detail")
        if not self.finalize_result:
            return False
        row = self.operations[operation_id]
        row.state, row.receipt_json = receipt["state"], deepcopy(receipt)
        return True

    def mark_indeterminate(self, operation_id, updated_at):
        if not self.mark_indeterminate_result:
            return False
        self.operations[operation_id].state = "indeterminate"
        return True

    def get_by_operation_id(self, operation_id):
        row = self.operations.get(operation_id)
        return deepcopy(row) if row else None


class Clock:
    def __init__(self):
        self.value = NOW

    def __call__(self):
        self.value += timedelta(microseconds=1)
        return self.value


def principal(actor=ACTOR, scopes=frozenset({"self:read", "job:create", "action:receipt:read:self"}), client="client"):
    return BearerPrincipal(
        actor, "user", client, scopes, "token-jti", NOW, NOW + timedelta(hours=1), "hodlxxi.oauth.access-token.v1"
    )


def entitlement(actor=ACTOR, identity=IdentityClass.LIMITED):
    return EntitlementDecision(actor, identity, False, "test")


def invocation(**changes):
    values = dict(
        encoded_bearer_token="encoded.jwt.token",
        expected_oauth_client_id="client",
        action=ActionName.SELF_READ,
        resource_id=None,
        idempotency_key="idempotency-1",
        request_payload={"b": 2, "a": 1},
    )
    values.update(changes)
    return InternalActionInvocation(**values)


def make_gateway(*, repo=None, validator=None, resolver=None, handler=None, signer=None, handlers=None, ownership=None):
    repo = repo or FakeRepository()
    calls = {"handler": 0, "signer": 0}

    def default_handler(payload):
        calls["handler"] += 1
        return HandlerResult.completed({"ok": True})

    def default_signer(message):
        calls["signer"] += 1
        return SIGNER_KEY.sign(message, ec.ECDSA(hashes.SHA256())).hex()

    selected_handler = handler or default_handler
    gateway = InternalActionGateway(
        bearer_validator=validator or (lambda _: principal()),
        entitlement_resolver=resolver or (lambda _: entitlement()),
        operation_repository=repo,
        handlers=handlers if handlers is not None else {ActionName.SELF_READ: selected_handler},
        receipt_signer=signer or default_signer,
        signer_public_key=SIGNER_PUBLIC,
        clock=Clock(),
        ownership_resolver=ownership,
    )
    return gateway, repo, calls


@pytest.mark.parametrize("case", ["invalid_bearer", "client_mismatch", "denied", "unavailable"])
def test_authentication_and_entitlement_fail_before_reservation(case):
    def validator(_):
        return principal()

    def resolver(_):
        return entitlement()

    if case == "invalid_bearer":

        def validator(_):
            raise BearerValidationError("secret")

    elif case == "client_mismatch":

        def validator(_):
            return principal(client="other")

    elif case == "denied":

        def resolver(_):
            raise EntitlementDenied("secret")

    elif case == "unavailable":

        def resolver(_):
            raise EntitlementUnavailable("database")

    gateway, repo, _ = make_gateway(validator=validator, resolver=resolver)
    result = gateway.invoke(invocation())
    expected = {
        "invalid_bearer": GatewayReason.INVALID_TOKEN,
        "client_mismatch": GatewayReason.INVALID_TOKEN,
        "denied": GatewayReason.ENTITLEMENT_DENIED,
        "unavailable": GatewayReason.ENTITLEMENT_UNAVAILABLE,
    }[case]
    assert result.reason is expected and repo.reservations == []


def test_malformed_unknown_unregistered_full_stepup_ownership_and_scope_fail_before_reservation():
    gateway, repo, _ = make_gateway()
    assert gateway.invoke(invocation(action="unknown")).reason is GatewayReason.INVALID_REQUEST
    no_handlers, _, _ = make_gateway(repo=repo, handlers={})
    assert no_handlers.invoke(invocation()).reason is GatewayReason.GATEWAY_ACTION_UNAVAILABLE
    full_gateway, _, _ = make_gateway(repo=repo, resolver=lambda _: entitlement(identity=IdentityClass.FULL))
    assert (
        full_gateway.invoke(invocation(action=ActionName.COVENANT_DRAFT_CREATE)).reason
        is GatewayReason.GATEWAY_ACTION_UNAVAILABLE
    )
    assert (
        gateway.invoke(invocation(action=ActionName.COVENANT_DRAFT_READ_SELF, resource_id="draft-1")).reason
        is GatewayReason.GATEWAY_ACTION_UNAVAILABLE
    )
    assert (
        gateway.invoke(invocation(action=ActionName.COVENANT_DRAFT_CREATE, step_up_proof={"verified": True})).reason
        is GatewayReason.GATEWAY_ACTION_UNAVAILABLE
    )
    assert (
        gateway.invoke(invocation(action=ActionName.JOB_READ_SELF, resource_id="job-1")).reason
        is GatewayReason.OWNERSHIP_UNAVAILABLE
    )
    scoped, _, _ = make_gateway(repo=repo, validator=lambda _: principal(scopes=frozenset()))
    assert scoped.invoke(invocation()).reason is GatewayReason.AUTHORIZATION_DENIED
    assert repo.reservations == []
    with pytest.raises(TypeError):
        InternalActionInvocation(**(vars(invocation()) | {"resource_owner_pubkey": ACTOR}))


@pytest.mark.parametrize(
    "payload",
    [
        {"not_json": object()},
        ("tuple",),
        b"bytes",
        bytearray(b"bytes"),
        {1: "non-string key"},
        {"nonfinite": float("nan")},
        {"nonfinite": float("inf")},
        {"nonfinite": float("-inf")},
        "x" * 65_537,
    ],
)
def test_noncanonical_or_oversized_payload_is_invalid_before_reservation(payload):
    gateway, repo, _ = make_gateway()
    assert gateway.invoke(invocation(request_payload=payload)).reason is GatewayReason.INVALID_REQUEST
    assert repo.reservations == []


def test_handler_receives_exact_canonical_request_bytes_used_for_hash():
    received = []
    payload = {"nested": [3, 2, 1], "a": True}
    gateway, repo, _ = make_gateway(
        handler=lambda request_bytes: received.append(request_bytes) or HandlerResult.completed({"ok": True})
    )

    result = gateway.invoke(invocation(request_payload=payload))

    assert result.reason is GatewayReason.COMPLETED
    assert received == [b'{"a":true,"nested":[3,2,1]}']
    assert received[0] is not payload
    assert hashlib.sha256(received[0]).hexdigest() == repo.reservations[0].request_sha256


@pytest.mark.parametrize(
    ("payload", "mutate"),
    [
        ({"value": "before"}, lambda value: value.__setitem__("value", "after")),
        ({"items": ["before"]}, lambda value: value["items"].append("after")),
    ],
)
def test_mutating_original_after_canonicalization_cannot_alter_handler_input(payload, mutate):
    class MutatingRepository(FakeRepository):
        def reserve(self, reservation):
            result = super().reserve(reservation)
            mutate(payload)
            return result

    received = []
    gateway, repo, _ = make_gateway(
        repo=MutatingRepository(),
        handler=lambda request_bytes: received.append(request_bytes) or HandlerResult.completed({"ok": True}),
    )

    result = gateway.invoke(invocation(request_payload=payload))

    assert result.reason is GatewayReason.COMPLETED
    assert received == [b'{"items":["before"]}'] if "items" in payload else [b'{"value":"before"}']
    assert hashlib.sha256(received[0]).hexdigest() == repo.reservations[0].request_sha256


def test_completed_result_is_canonicalized_once_and_hashes_those_exact_bytes(monkeypatch):
    result_payload = {"z": [2, 1], "a": "result"}
    canonical_calls = []
    original = gateway_module.canonical_payload_bytes

    def recording_canonical(value, *, maximum=gateway_module.MAX_REQUEST_BYTES):
        encoded = original(value, maximum=maximum)
        if value is result_payload:
            canonical_calls.append(encoded)
        return encoded

    monkeypatch.setattr(gateway_module, "canonical_payload_bytes", recording_canonical)
    gateway, _, _ = make_gateway(handler=lambda _: HandlerResult.completed(result_payload))

    completed = gateway.invoke(invocation())
    receipt = parse_action_receipt(completed.receipt)

    assert completed.reason is GatewayReason.COMPLETED
    assert canonical_calls == [b'{"a":"result","z":[2,1]}']
    assert receipt["result_sha256"] == hashlib.sha256(canonical_calls[0]).hexdigest()


def test_decision_hash_is_canonical_and_binds_full_decision():
    resolver = SimpleNamespace(resolve=lambda _: EntitlementSnapshot(ACTOR, IdentityClass.LIMITED, False, "test"))
    decision = authorize_action(ActionRequest(ACTOR, ActionName.SELF_READ, {"self:read"}), resolver)
    assert authorization_decision_sha256(decision) == "32e565866d4e3ac8dc58c3e4019f9b33dc4ea9362f4234351ef4849e8ee95371"
    assert authorization_decision_sha256(decision) == authorization_decision_sha256(decision)


def test_completed_once_persists_only_hashes_and_valid_receipt_then_exact_replays():
    gateway, repo, calls = make_gateway()
    supplied = invocation(step_up_proof={"signature": "proof-signature", "step_up_verified": True})
    first = gateway.invoke(supplied)
    assert first.reason is GatewayReason.COMPLETED and calls == {"handler": 1, "signer": 1}
    receipt = parse_action_receipt(first.receipt)
    assert verify_action_receipt(receipt) and receipt["state"] == "completed"
    reservation = repo.reservations[0]
    serialized = repr(vars(reservation)) + repr(vars(repo.operations[first.operation_id]))
    for secret in ("encoded.jwt.token", "idempotency-1", "{'b': 2, 'a': 1}", "{'ok': True}"):
        assert secret not in serialized
    assert "proof-signature" not in serialized
    replay = gateway.invoke(supplied)
    assert replay.reason is GatewayReason.REPLAY and replay.receipt == first.receipt
    assert calls == {"handler": 1, "signer": 1} and len(repo.reservations) == 2


def test_explicit_failure_is_signed_but_handler_signer_and_finalization_exceptions_are_indeterminate():
    failed, _, _ = make_gateway(handler=lambda _: HandlerResult.failed("stable_failure"))
    result = failed.invoke(invocation())
    assert (
        result.reason is GatewayReason.FAILED
        and parse_action_receipt(result.receipt)["failure_code"] == "stable_failure"
    )
    for options in (
        {"handler": lambda _: (_ for _ in ()).throw(RuntimeError("side effect unknown")), "failure": None},
        {
            "signer": lambda _: (_ for _ in ()).throw(RuntimeError("key path")),
            "failure": GatewayReason.SIGNING_FAILED,
        },
    ):
        expected_failure = options.pop("failure")
        gateway, repo, _ = make_gateway(**options)
        result = gateway.invoke(invocation())
        assert result.reason is GatewayReason.OPERATION_INDETERMINATE
        assert result.failure is expected_failure
        assert repo.get_by_operation_id(result.operation_id).state == "indeterminate"
    repo = FakeRepository()
    repo.raise_finalize = True
    gateway, _, _ = make_gateway(repo=repo)
    result = gateway.invoke(invocation())
    assert result.reason is GatewayReason.OPERATION_INDETERMINATE
    assert result.failure is GatewayReason.FINALIZATION_FAILED
    repo = FakeRepository()
    repo.mark_indeterminate_result = False
    gateway, _, _ = make_gateway(repo=repo, handler=lambda _: (_ for _ in ()).throw(RuntimeError("unknown")))
    assert gateway.invoke(invocation()).reason is GatewayReason.GATEWAY_INTERNAL_FAILURE


def test_dispatch_requires_cas_and_replay_states_never_dispatch():
    repo = FakeRepository()
    repo.mark_executing_result = False
    gateway, _, calls = make_gateway(repo=repo)
    assert gateway.invoke(invocation()).reason is GatewayReason.OPERATION_IN_PROGRESS
    assert calls["handler"] == 0
    for state, reason in (
        ("reserved", GatewayReason.OPERATION_IN_PROGRESS),
        ("executing", GatewayReason.OPERATION_IN_PROGRESS),
        ("indeterminate", GatewayReason.OPERATION_INDETERMINATE),
    ):
        repo = FakeRepository()
        gateway, _, calls = make_gateway(repo=repo)
        gateway.invoke(invocation())
        row = next(iter(repo.operations.values()))
        row.state = state
        row.receipt_json = None
        calls["handler"] = 0
        calls["signer"] = 0
        assert gateway.invoke(invocation()).reason is reason
        assert calls == {"handler": 0, "signer": 0}


def test_conflicting_payload_does_not_dispatch_again():
    gateway, _, calls = make_gateway()
    assert gateway.invoke(invocation()).reason is GatewayReason.COMPLETED
    result = gateway.invoke(invocation(request_payload={"different": True}))
    assert result.reason is GatewayReason.IDEMPOTENCY_CONFLICT and calls["handler"] == 1


def test_receipt_retrieval_authenticates_authorizes_persisted_owner_and_returns_exact_bytes():
    gateway, _, _ = make_gateway()
    created = gateway.invoke(invocation())
    request = ReceiptRetrievalRequest("encoded.jwt.token", "client", created.operation_id)
    retrieved = gateway.retrieve_receipt(request)
    assert retrieved.reason is GatewayReason.REPLAY and retrieved.receipt == created.receipt
    invalid, _, _ = make_gateway(validator=lambda _: (_ for _ in ()).throw(BearerValidationError("x")))
    assert invalid.retrieve_receipt(request).reason is GatewayReason.INVALID_TOKEN
    stale, _, _ = make_gateway(
        repo=gateway._repository,
        resolver=lambda _: (_ for _ in ()).throw(EntitlementDenied("stale")),
    )
    assert stale.retrieve_receipt(request).reason is GatewayReason.ENTITLEMENT_DENIED
    other, _, _ = make_gateway(
        repo=gateway._repository,
        validator=lambda _: principal(actor=OTHER),
        resolver=lambda _: entitlement(actor=OTHER),
    )
    assert other.retrieve_receipt(request).reason is GatewayReason.AUTHORIZATION_DENIED
    row = gateway._repository.operations[created.operation_id]
    row.state = "executing"
    row.receipt_json = None
    assert gateway.retrieve_receipt(request).reason is GatewayReason.OPERATION_IN_PROGRESS


def test_registry_is_immutable_and_module_has_no_runtime_or_transport_dependencies():
    gateway, _, _ = make_gateway()
    with pytest.raises(TypeError):
        gateway._handlers[ActionName.JOB_CREATE] = lambda _: HandlerResult.completed({})
    source = inspect.getsource(__import__("app.services.internal_action_gateway", fromlist=["x"]))
    forbidden = ("current_app", "Blueprint", "@app.route", "mcp", "Bitcoin", "LND", "getenv", "private_key")
    assert not any(value in source for value in forbidden)
    assert "handler(invocation.request_payload)" not in source

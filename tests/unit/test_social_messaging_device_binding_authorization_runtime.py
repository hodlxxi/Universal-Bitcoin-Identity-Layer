from __future__ import annotations

import json
import inspect
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

import app.services.social_messaging_device_binding_authorization_runtime as runtime_module
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    CredentialDenied,
    VerifiedServiceCredential,
)
from app.services.oauth_bearer_validation import BearerPrincipal
from app.services.social_messaging_device_binding_authorization import (
    AUTHORIZATION_SCHEMA,
    PROOF_ID_PREFIX,
    SIGNATURE_FORMAT,
    AdoptedDeviceBindingAuthorization,
    AuthorizedDeviceBinding,
    DeviceBindingAdoptionClaim,
    DeviceBindingAuthorizationClaim,
    DeviceBindingAuthorizationUnavailable,
    IdentitySignedDeviceBindingAdoption,
    IdentitySignedDeviceBindingAuthorization,
    adoption_digest,
    authorization_digest,
)
from app.services.social_messaging_device_binding_authorization_storage import (
    SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage,
)
from app.services.social_messaging_device_contract import (
    BINDING_RECORD_SCHEMA,
    BINDING_RECORD_VERSION,
    MessagingDeviceBinding,
)
from app.services.social_messaging_recipient_routing import VerifiedBindingAuthorization

NOW = datetime(2026, 9, 10, 18, 30, tzinfo=timezone.utc)
IDENTITY_KEY = PrivateKey(bytes.fromhex("00" * 31 + "03"))
SUBJECT = PublicKeyXOnly.from_secret(IDENTITY_KEY.secret).format().hex()
DEVICE_ID = "22" * 32
REQUEST_ID = "33" * 32
PUBLIC_KEY = "09" + "00" * 31


def service_config():
    return ConfidentialServiceConfig(
        enabled=True,
        client_id="social-binding-authorization-v1",
        service_principal="service:social-binding-authorization",
        issuer="https://identity.example",
        token_endpoint_audience="https://identity.example/internal/token",
        service_resource_audience="https://identity.example/internal/authorization",
        client_jwks=(),
        service_jwks=(),
        service_scope=runtime_module.MESSAGING_DEVICE_AUTHORIZATION_SCOPE,
        service_purpose=runtime_module.MESSAGING_DEVICE_AUTHORIZATION_PURPOSE,
    )


def service_credential(**changes):
    values = {
        "service_principal": "service:social-binding-authorization",
        "client_id": "social-binding-authorization-v1",
        "scope": runtime_module.MESSAGING_DEVICE_AUTHORIZATION_SCOPE,
        "purpose": runtime_module.MESSAGING_DEVICE_AUTHORIZATION_PURPOSE,
        "issued_at": 1,
        "expires_at": 2,
        "token_id": "service-token-id",
    }
    values.update(changes)
    return VerifiedServiceCredential(**values)


def viewer(**changes):
    values = {
        "subject": SUBJECT,
        "user_id": "user-a",
        "client_id": "social-browser",
        "scopes": frozenset({"openid"}),
        "jti": "viewer-jti",
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
        "token_contract": "hodlxxi.oauth.access-token.v1",
    }
    values.update(changes)
    return BearerPrincipal(**values)


def authorized_result():
    claim = DeviceBindingAuthorizationClaim(
        schema=AUTHORIZATION_SCHEMA,
        version=1,
        binding_record_schema=BINDING_RECORD_SCHEMA,
        binding_record_version=BINDING_RECORD_VERSION,
        operation="register",
        subject=SUBJECT,
        device_id=DEVICE_ID,
        algorithm="x25519-v1",
        public_key=PUBLIC_KEY,
        binding_version=1,
        binding_valid_from=NOW,
        binding_expires_at=NOW + timedelta(days=30),
        prior_binding_id=None,
        request_id=REQUEST_ID,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    digest = authorization_digest(claim)
    authorization = IdentitySignedDeviceBindingAuthorization(
        claim,
        digest,
        SIGNATURE_FORMAT,
        IDENTITY_KEY.sign_schnorr(bytes.fromhex(digest), b"\x00" * 32).hex(),
    )
    binding = MessagingDeviceBinding(
        subject=SUBJECT,
        device_id=DEVICE_ID,
        binding_id=authorization.binding_id,
        public_key=PUBLIC_KEY,
        binding_version=1,
        valid_from=NOW,
        expires_at=NOW + timedelta(days=30),
        operation="register",
        prior_binding_id=None,
        request_id=REQUEST_ID,
        active=True,
    )
    verification = VerifiedBindingAuthorization(
        proof_id=PROOF_ID_PREFIX + digest,
        subject=SUBJECT,
        device_id=DEVICE_ID,
        binding_id=binding.binding_id,
        binding_version=1,
        public_key=PUBLIC_KEY,
        valid_from=NOW,
        expires_at=NOW + timedelta(days=30),
        evidence_valid_from=NOW,
        evidence_expires_at=NOW + timedelta(days=30),
    )
    return AuthorizedDeviceBinding(authorization, binding, verification)


def adopted_result():
    lifecycle = authorized_result()
    claim = DeviceBindingAdoptionClaim(
        schema=runtime_module.ADOPTION_SCHEMA,
        version=1,
        action="adopt",
        request_id="aa" * 32,
        binding=lifecycle.binding,
        issued_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=5),
    )
    digest = adoption_digest(claim)
    adoption = IdentitySignedDeviceBindingAdoption(
        claim,
        digest,
        SIGNATURE_FORMAT,
        IDENTITY_KEY.sign_schnorr(bytes.fromhex(digest), b"\x00" * 32).hex(),
    )
    verification = VerifiedBindingAuthorization(
        proof_id=PROOF_ID_PREFIX + digest,
        subject=SUBJECT,
        device_id=DEVICE_ID,
        binding_id=lifecycle.binding.binding_id,
        binding_version=1,
        public_key=PUBLIC_KEY,
        valid_from=NOW,
        expires_at=NOW + timedelta(days=30),
        evidence_valid_from=NOW + timedelta(seconds=1),
        evidence_expires_at=NOW + timedelta(days=30),
    )
    return AdoptedDeviceBindingAuthorization(adoption, lifecycle.binding, verification)


class Session:
    def __init__(self, events):
        self.events = events

    def begin(self):
        self.events.append("begin")
        return object()

    def commit(self):
        self.events.append("commit")

    def rollback(self):
        self.events.append("rollback")

    def close(self):
        self.events.append("close")


def instance(monkeypatch, session_factory, *, principal=None):
    monkeypatch.setattr(runtime_module, "validate_confidential_service_config", lambda _config: None)
    return runtime_module.MessagingDeviceBindingAuthorizationRuntime(
        service_config=service_config(),
        replay_consumer=lambda _jti, _deadline: True,
        service_signing_key=object(),
        service_signing_kid="service-key",
        viewer_oauth_client_id="social-browser",
        viewer_token_validator=lambda _token: principal or viewer(),
        session_factory=session_factory,
    )


def dispatch_payload(action):
    if action == "adopt":
        value = {"action": "adopt", "schema": runtime_module.ADOPTION_SCHEMA}
    else:
        value = {"operation": action, "schema": AUTHORIZATION_SCHEMA}
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@pytest.mark.parametrize("action", ["register", "rotate", "revoke", "adopt"])
def test_runtime_uses_one_caller_owned_session_and_transaction(monkeypatch, action):
    events = []
    session = Session(events)
    calls = []

    class Storage:
        def __init__(self, supplied_session):
            assert supplied_session is session
            events.append("storage")

        def authorize_lifecycle(self, payload, *, authenticated_subject):
            calls.append(("lifecycle", payload, authenticated_subject))
            return object()

        def adopt_legacy(self, payload, *, authenticated_subject):
            calls.append(("adopt", payload, authenticated_subject))
            return object()

    monkeypatch.setattr(runtime_module, "SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage", Storage)
    monkeypatch.setattr(runtime_module, "canonical_authorization_result_bytes", lambda _result: b'{"ok":true}')
    value = instance(monkeypatch, lambda: session)
    payload = dispatch_payload(action)

    assert value.authorize_for_service(service_credential(), "viewer-token", payload) == b'{"ok":true}'
    assert calls == [("adopt" if action == "adopt" else "lifecycle", payload, SUBJECT)]
    assert events == ["begin", "storage", "commit", "close"]


def test_existing_storage_builds_current_full_from_its_exact_session():
    source = inspect.getsource(SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage)

    assert source.count("SqlAlchemyTransactionBoundCurrentFullVerifier(self._session)") == 2
    assert "self._session.begin(" not in source
    assert "self._session.commit(" not in source
    assert "self._session.rollback(" not in source
    assert "self._session.close(" not in source


def test_runtime_rolls_back_and_closes_on_storage_or_serialization_failure(monkeypatch):
    for failure_point in ("storage", "serializer"):
        events = []
        session = Session(events)

        class Storage:
            def __init__(self, supplied_session):
                assert supplied_session is session

            def authorize_lifecycle(self, _payload, *, authenticated_subject):
                assert authenticated_subject == SUBJECT
                if failure_point == "storage":
                    raise RuntimeError("sensitive database detail")
                return object()

        monkeypatch.setattr(runtime_module, "SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage", Storage)

        def serialize(_result):
            raise RuntimeError("sensitive serializer detail")

        monkeypatch.setattr(runtime_module, "canonical_authorization_result_bytes", serialize)
        value = instance(monkeypatch, lambda: session)

        with pytest.raises(DeviceBindingAuthorizationUnavailable) as caught:
            value.authorize_for_service(service_credential(), "viewer-token", dispatch_payload("register"))

        assert caught.value.__cause__ is None
        assert events == ["begin", "rollback", "close"]


def test_viewer_and_service_are_exact_before_any_transaction(monkeypatch):
    opened = []
    value = instance(monkeypatch, lambda: opened.append(True), principal=viewer(client_id="foreign"))
    with pytest.raises(runtime_module.MessagingDeviceBindingAuthorizationViewerDenied):
        value.authorize_for_service(service_credential(), "viewer-token", dispatch_payload("register"))
    assert opened == []

    value = instance(monkeypatch, lambda: opened.append(True))
    with pytest.raises(CredentialDenied):
        value.authorize_for_service(
            service_credential(scope="social:messaging-device:manage"),
            "viewer-token",
            dispatch_payload("register"),
        )
    assert opened == []


def test_dispatch_rejects_noncanonical_duplicate_and_unknown_schema():
    for payload in (
        '{"schema":"%s", "operation":"register"}' % AUTHORIZATION_SCHEMA,
        '{"operation":"register","operation":"rotate","schema":"%s"}' % AUTHORIZATION_SCHEMA,
        '{"operation":"register","schema":"unknown"}',
        "\ud800",
    ):
        with pytest.raises(DeviceBindingAuthorizationUnavailable):
            runtime_module._authorization_action(payload)


def test_result_serializer_is_canonical_private_and_fail_closed():
    result = authorized_result()
    encoded = runtime_module.canonical_authorization_result_bytes(result)
    decoded = json.loads(encoded)

    assert encoded == json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode("ascii")
    assert decoded["bindingId"] == result.binding.binding_id
    assert decoded["authorizationProofId"] == result.verification.proof_id
    assert decoded["action"] == "register"
    assert "subject" not in decoded
    assert "publicKey" not in decoded
    assert "signature" not in decoded

    malformed = AuthorizedDeviceBinding(
        result.authorization,
        result.binding,
        SimpleNamespace(**vars(result.verification)),
    )
    with pytest.raises(DeviceBindingAuthorizationUnavailable):
        runtime_module.canonical_authorization_result_bytes(malformed)


def test_adoption_result_serializes_the_distinct_action_without_mutating_binding():
    result = adopted_result()
    before = result.binding

    first = runtime_module.canonical_authorization_result_bytes(result)
    second = runtime_module.canonical_authorization_result_bytes(result)
    decoded = json.loads(first)

    assert first == second
    assert decoded["action"] == "adopt"
    assert decoded["requestId"] == "aa" * 32
    assert decoded["bindingOperation"] == "register"
    assert decoded["bindingId"] == before.binding_id
    assert result.binding is before

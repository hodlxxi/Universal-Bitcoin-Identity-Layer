from __future__ import annotations

from datetime import datetime, timezone

import pytest

import app.services.social_messaging_device_internal_delivery as delivery
from app.services.action_authorization import IdentityClass
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    CredentialDenied,
    VerifiedServiceCredential,
)
from app.services.current_entitlement import EntitlementDecision
from app.services.oauth_bearer_validation import BearerPrincipal

SUBJECT = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
NOW = datetime(2026, 9, 4, 23, 30, 0, tzinfo=timezone.utc)


def service_config(**changes):
    values = dict(
        enabled=True,
        client_id="social-messaging-v1",
        service_principal="social-messaging",
        issuer="https://hodlxxi.example",
        token_endpoint_audience="urn:hodlxxi:messaging-token",
        service_resource_audience="urn:hodlxxi:messaging-resource",
        client_jwks=(),
        service_jwks=(),
        service_scope=delivery.MESSAGING_DEVICE_SCOPE,
        service_purpose=delivery.MESSAGING_DEVICE_PURPOSE,
    )
    values.update(changes)
    return ConfidentialServiceConfig(**values)


def viewer(*, client_id="social-web", scopes=frozenset({"openid"})):
    return BearerPrincipal(
        subject=SUBJECT,
        user_id="user-a",
        client_id=client_id,
        scopes=scopes,
        jti="viewer-jti",
        issued_at=NOW,
        expires_at=NOW,
        token_contract="hodlxxi.oauth.access-token.v1",
    )


def entitlement(*, identity_class=IdentityClass.FULL, current_full=True):
    return EntitlementDecision(
        subject=SUBJECT,
        identity_class=identity_class,
        current_full_relation_satisfied=current_full,
        evidence_source="test",
    )


def verified_service(**changes):
    values = dict(
        service_principal="social-messaging",
        client_id="social-messaging-v1",
        scope=delivery.MESSAGING_DEVICE_SCOPE,
        purpose=delivery.MESSAGING_DEVICE_PURPOSE,
        issued_at=1,
        expires_at=2,
        token_id="service-jti",
    )
    values.update(changes)
    return VerifiedServiceCredential(**values)


class Authority:
    def __init__(self):
        self.calls = []

    def current(self, *, authenticated_subject):
        self.calls.append(("current", authenticated_subject))
        return {"kind": "snapshot"}

    def apply(self, payload, *, authenticated_subject):
        self.calls.append(("apply", authenticated_subject, payload))
        return {"kind": "result"}


def runtime(monkeypatch, *, principal=None, decision=None, authority=None, config=None):
    monkeypatch.setattr(delivery, "validate_confidential_service_config", lambda _: None)
    return delivery.MessagingDeviceInternalDeliveryRuntime(
        service_config=config or service_config(),
        replay_consumer=lambda _jti, _exp: True,
        service_signing_key=object(),
        service_signing_kid="kid-1",
        viewer_oauth_client_id="social-web",
        viewer_token_validator=lambda _token: principal or viewer(),
        current_entitlement_resolver=lambda _subject: decision or entitlement(),
        device_authority=authority or Authority(),
    )


def test_runtime_requires_exact_messaging_scope_and_purpose(monkeypatch):
    with pytest.raises(delivery.MessagingDeviceInternalConfigurationError):
        runtime(
            monkeypatch,
            config=service_config(service_scope="social:full-directory:read"),
        )

    with pytest.raises(delivery.MessagingDeviceInternalConfigurationError):
        runtime(
            monkeypatch,
            config=service_config(service_purpose="social_full_directory_read"),
        )


def test_current_uses_server_derived_viewer_subject_only(monkeypatch):
    authority = Authority()
    instance = runtime(monkeypatch, authority=authority)

    result = instance.current_for_service(
        verified_service(),
        "viewer-token",
    )

    assert result == {"kind": "snapshot"}
    assert authority.calls == [("current", SUBJECT)]


def test_apply_passes_payload_but_not_browser_chosen_subject(monkeypatch):
    authority = Authority()
    instance = runtime(monkeypatch, authority=authority)
    payload = '{"deviceId":"opaque"}'

    result = instance.apply_for_service(
        verified_service(),
        "viewer-token",
        payload,
    )

    assert result == {"kind": "result"}
    assert authority.calls == [("apply", SUBJECT, payload)]


def test_wrong_service_domain_is_rejected_before_viewer_or_authority(monkeypatch):
    authority = Authority()
    viewer_calls = []
    instance = runtime(monkeypatch, authority=authority)
    object.__setattr__(instance, "viewer_token_validator", lambda token: viewer_calls.append(token))

    with pytest.raises(CredentialDenied):
        instance.current_for_service(
            verified_service(scope="social:full-directory:read"),
            "viewer-token",
        )

    assert viewer_calls == []
    assert authority.calls == []


def test_viewer_client_and_openid_scope_are_independently_required(monkeypatch):
    authority = Authority()

    for principal in (
        viewer(client_id="foreign-client"),
        viewer(scopes=frozenset()),
    ):
        instance = runtime(
            monkeypatch,
            principal=principal,
            authority=authority,
        )
        with pytest.raises(delivery.MessagingViewerCredentialDenied):
            instance.current_for_service(verified_service(), "viewer-token")

    assert authority.calls == []


def test_current_full_is_required_independently_of_valid_oauth(monkeypatch):
    authority = Authority()

    for decision in (
        entitlement(identity_class=IdentityClass.LIMITED, current_full=False),
        entitlement(identity_class=IdentityClass.FULL, current_full=False),
    ):
        instance = runtime(
            monkeypatch,
            decision=decision,
            authority=authority,
        )
        with pytest.raises(delivery.MessagingViewerEntitlementDenied):
            instance.current_for_service(verified_service(), "viewer-token")

    assert authority.calls == []


def test_malformed_entitlement_evidence_fails_unavailable(monkeypatch):
    authority = Authority()
    instance = runtime(monkeypatch, authority=authority)
    object.__setattr__(
        instance,
        "current_entitlement_resolver",
        lambda _subject: object(),
    )

    with pytest.raises(delivery.MessagingViewerEntitlementUnavailable):
        instance.current_for_service(verified_service(), "viewer-token")

    assert authority.calls == []


def test_issue_and_verify_use_messaging_policy_config(monkeypatch):
    issued = []
    verified = []

    def fake_issue(assertion, *, config, replay_consumer, signing_key, signing_kid):
        issued.append((assertion, config.service_scope, config.service_purpose, signing_kid))
        return "service-token"

    def fake_verify(token, *, config):
        verified.append((token, config.service_scope, config.service_purpose))
        return verified_service()

    monkeypatch.setattr(delivery, "issue_service_access_token", fake_issue)
    monkeypatch.setattr(delivery, "verify_service_access_token", fake_verify)
    instance = runtime(monkeypatch)

    assert instance.issue_service_token("assertion") == "service-token"
    assert instance.verify_service_authority("token") == verified_service()
    assert issued == [
        (
            "assertion",
            delivery.MESSAGING_DEVICE_SCOPE,
            delivery.MESSAGING_DEVICE_PURPOSE,
            "kid-1",
        )
    ]
    assert verified == [
        (
            "token",
            delivery.MESSAGING_DEVICE_SCOPE,
            delivery.MESSAGING_DEVICE_PURPOSE,
        )
    ]

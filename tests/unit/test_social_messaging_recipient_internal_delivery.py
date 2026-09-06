from __future__ import annotations

from datetime import datetime, timezone

import pytest

import app.services.social_messaging_recipient_internal_delivery as delivery
from app.services.action_authorization import IdentityClass
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    CredentialDenied,
    VerifiedServiceCredential,
)
from app.services.current_entitlement import EntitlementDecision
from app.services.oauth_bearer_validation import BearerPrincipal
from app.services.recipient_device_resolver import (
    RecipientAliasInvalid,
    RecipientDeviceResolverUnavailable,
)

SUBJECT = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
ALIAS = "p_abcdefghijklmnopqrstuv"
NOW = datetime(2026, 9, 5, 23, 30, 0, tzinfo=timezone.utc)


def service_config(**changes):
    values = dict(
        enabled=True,
        client_id="social-messaging-recipient-v1",
        service_principal="social-messaging-recipient",
        issuer="https://hodlxxi.example",
        token_endpoint_audience="urn:hodlxxi:messaging-recipient-token",
        service_resource_audience="urn:hodlxxi:messaging-recipient-resource",
        client_jwks=(),
        service_jwks=(),
        service_scope=delivery.MESSAGING_RECIPIENT_SCOPE,
        service_purpose=delivery.MESSAGING_RECIPIENT_PURPOSE,
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
        service_principal="social-messaging-recipient",
        client_id="social-messaging-recipient-v1",
        scope=delivery.MESSAGING_RECIPIENT_SCOPE,
        purpose=delivery.MESSAGING_RECIPIENT_PURPOSE,
        issued_at=1,
        expires_at=2,
        token_id="service-jti",
    )
    values.update(changes)
    return VerifiedServiceCredential(**values)


class Resolver:
    def __init__(self, result=None, error=None):
        self.result = {"kind": "recipient-package"} if result is None else result
        self.error = error
        self.calls = []

    def resolve(self, *, viewer_subject, recipient_alias):
        self.calls.append((viewer_subject, recipient_alias))
        if self.error is not None:
            raise self.error
        return self.result


def runtime(monkeypatch, *, principal=None, decision=None, resolver=None, config=None):
    monkeypatch.setattr(delivery, "validate_confidential_service_config", lambda _: None)
    return delivery.MessagingRecipientInternalDeliveryRuntime(
        service_config=config or service_config(),
        replay_consumer=lambda _jti, _exp: True,
        service_signing_key=object(),
        service_signing_kid="kid-1",
        viewer_oauth_client_id="social-web",
        viewer_token_validator=lambda _token: principal or viewer(),
        current_entitlement_resolver=lambda _subject: decision or entitlement(),
        recipient_resolver=resolver or Resolver(),
    )


def test_runtime_requires_exact_recipient_scope_and_purpose(monkeypatch):
    for config in (
        service_config(service_scope="social:messaging-device:manage"),
        service_config(service_scope="social:full-directory:read"),
        service_config(service_purpose="social_messaging_device_manage"),
        service_config(service_purpose="social_full_directory_read"),
    ):
        with pytest.raises(delivery.MessagingRecipientInternalConfigurationError):
            runtime(monkeypatch, config=config)


def test_resolve_uses_server_derived_viewer_subject_only(monkeypatch):
    resolver = Resolver()
    instance = runtime(monkeypatch, resolver=resolver)

    result = instance.resolve_for_service(
        verified_service(),
        "viewer-token",
        ALIAS,
    )

    assert result == {"kind": "recipient-package"}
    assert resolver.calls == [(SUBJECT, ALIAS)]


def test_wrong_service_domain_is_rejected_before_viewer_or_resolver(monkeypatch):
    resolver = Resolver()
    viewer_calls = []
    instance = runtime(monkeypatch, resolver=resolver)
    object.__setattr__(
        instance,
        "viewer_token_validator",
        lambda token: viewer_calls.append(token),
    )

    with pytest.raises(CredentialDenied):
        instance.resolve_for_service(
            verified_service(scope="social:messaging-device:manage"),
            "viewer-token",
            ALIAS,
        )

    assert viewer_calls == []
    assert resolver.calls == []


def test_viewer_client_and_openid_scope_are_independently_required(monkeypatch):
    resolver = Resolver()

    for principal in (
        viewer(client_id="foreign-client"),
        viewer(scopes=frozenset()),
    ):
        instance = runtime(
            monkeypatch,
            principal=principal,
            resolver=resolver,
        )
        with pytest.raises(delivery.MessagingRecipientViewerCredentialDenied):
            instance.resolve_for_service(
                verified_service(),
                "viewer-token",
                ALIAS,
            )

    assert resolver.calls == []


def test_current_full_is_required_before_recipient_resolution(monkeypatch):
    resolver = Resolver()

    for decision in (
        entitlement(identity_class=IdentityClass.LIMITED, current_full=False),
        entitlement(identity_class=IdentityClass.FULL, current_full=False),
    ):
        instance = runtime(
            monkeypatch,
            decision=decision,
            resolver=resolver,
        )
        with pytest.raises(delivery.MessagingRecipientViewerEntitlementDenied):
            instance.resolve_for_service(
                verified_service(),
                "viewer-token",
                ALIAS,
            )

    assert resolver.calls == []


def test_malformed_entitlement_evidence_fails_unavailable(monkeypatch):
    resolver = Resolver()
    instance = runtime(monkeypatch, resolver=resolver)
    object.__setattr__(
        instance,
        "current_entitlement_resolver",
        lambda _subject: object(),
    )

    with pytest.raises(delivery.MessagingRecipientViewerEntitlementUnavailable):
        instance.resolve_for_service(
            verified_service(),
            "viewer-token",
            ALIAS,
        )

    assert resolver.calls == []


def test_recipient_resolver_taxonomy_is_preserved(monkeypatch):
    for error in (
        RecipientAliasInvalid(),
        RecipientDeviceResolverUnavailable(),
    ):
        resolver = Resolver(error=error)
        instance = runtime(monkeypatch, resolver=resolver)
        with pytest.raises(type(error)):
            instance.resolve_for_service(
                verified_service(),
                "viewer-token",
                ALIAS,
            )


def test_malformed_resolver_result_is_recipient_unavailable(monkeypatch):
    resolver = Resolver(result=object())
    instance = runtime(monkeypatch, resolver=resolver)

    with pytest.raises(RecipientDeviceResolverUnavailable):
        instance.resolve_for_service(
            verified_service(),
            "viewer-token",
            ALIAS,
        )


def test_issue_and_verify_use_recipient_policy_config(monkeypatch):
    issued = []
    verified = []

    def fake_issue(assertion, *, config, replay_consumer, signing_key, signing_kid):
        issued.append(
            (
                assertion,
                config.service_scope,
                config.service_purpose,
                signing_kid,
            )
        )
        return "service-token"

    def fake_verify(token, *, config):
        verified.append(
            (
                token,
                config.service_scope,
                config.service_purpose,
            )
        )
        return verified_service()

    monkeypatch.setattr(delivery, "issue_service_access_token", fake_issue)
    monkeypatch.setattr(delivery, "verify_service_access_token", fake_verify)

    instance = runtime(monkeypatch)

    assert instance.issue_service_token("assertion") == "service-token"
    assert instance.verify_service_authority("token") == verified_service()
    assert issued == [
        (
            "assertion",
            delivery.MESSAGING_RECIPIENT_SCOPE,
            delivery.MESSAGING_RECIPIENT_PURPOSE,
            "kid-1",
        )
    ]
    assert verified == [
        (
            "token",
            delivery.MESSAGING_RECIPIENT_SCOPE,
            delivery.MESSAGING_RECIPIENT_PURPOSE,
        )
    ]


def test_constructor_rejects_incomplete_dependencies(monkeypatch):
    monkeypatch.setattr(delivery, "validate_confidential_service_config", lambda _: None)

    values = dict(
        service_config=service_config(),
        replay_consumer=lambda _jti, _exp: True,
        service_signing_key=object(),
        service_signing_kid="kid-1",
        viewer_oauth_client_id="social-web",
        viewer_token_validator=lambda _token: viewer(),
        current_entitlement_resolver=lambda _subject: entitlement(),
        recipient_resolver=Resolver(),
    )

    for name, value in (
        ("replay_consumer", None),
        ("service_signing_kid", ""),
        ("viewer_oauth_client_id", ""),
        ("viewer_token_validator", None),
        ("current_entitlement_resolver", None),
        ("recipient_resolver", object()),
    ):
        with pytest.raises(delivery.MessagingRecipientInternalConfigurationError):
            delivery.MessagingRecipientInternalDeliveryRuntime(**{**values, name: value})

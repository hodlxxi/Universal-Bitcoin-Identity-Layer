from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest
from flask import Flask

import app.services.social_messaging_recipient_internal_delivery as delivery
from app.blueprints.internal_social_messaging_recipient import (
    CLIENT_ASSERTION_TYPE,
    MESSAGING_RECIPIENT_INTERNAL_EXTENSION,
    RECIPIENT_DEVICES_ROUTE,
    SERVICE_TOKEN_ROUTE,
    VIEWER_AUTHORIZATION_HEADER,
    internal_social_messaging_recipient_bp,
)
from app.services.action_authorization import IdentityClass
from app.services.confidential_service_credentials import (
    GRANT_TYPE,
    ConfidentialServiceConfig,
    CredentialDenied,
    VerifiedServiceCredential,
)
from app.services.current_entitlement import EntitlementDecision
from app.services.oauth_bearer_validation import BearerPrincipal
from app.services.recipient_device_resolver import (
    PACKAGE_SCHEMA,
    SOURCE,
    VERSION,
    RecipientAliasInvalid,
    RecipientDeviceResolverDenied,
    RecipientDeviceResolverUnavailable,
)
from app.services.social_messaging_device_contract import ALGORITHM

SUBJECT = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
ALIAS = "p_AAAAAAAAAAAAAAAAAAAAAA"
PUBLIC_KEY = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
NOW = datetime(2026, 9, 5, 23, 30, 0, tzinfo=timezone.utc)


def service_config():
    return ConfidentialServiceConfig(
        enabled=True,
        client_id="social-recipient-v1",
        service_principal="social-recipient",
        issuer="https://hodlxxi.example",
        token_endpoint_audience="urn:hodlxxi:recipient-token",
        service_resource_audience="urn:hodlxxi:recipient-resource",
        client_jwks=(),
        service_jwks=(),
        service_scope=delivery.MESSAGING_RECIPIENT_SCOPE,
        service_purpose=delivery.MESSAGING_RECIPIENT_PURPOSE,
    )


def verified_service():
    return VerifiedServiceCredential(
        service_principal="social-recipient",
        client_id="social-recipient-v1",
        scope=delivery.MESSAGING_RECIPIENT_SCOPE,
        purpose=delivery.MESSAGING_RECIPIENT_PURPOSE,
        issued_at=1,
        expires_at=2,
        token_id="service-jti",
    )


def viewer():
    return BearerPrincipal(
        subject=SUBJECT,
        user_id="user-a",
        client_id="social-web",
        scopes=frozenset({"openid"}),
        jti="viewer-jti",
        issued_at=NOW,
        expires_at=NOW,
        token_contract="hodlxxi.oauth.access-token.v1",
    )


def entitlement(*, full=True):
    return EntitlementDecision(
        subject=SUBJECT,
        identity_class=IdentityClass.FULL if full else IdentityClass.LIMITED,
        current_full_relation_satisfied=full,
        evidence_source="test",
    )


def package(alias=ALIAS):
    devices = [
        {
            "deviceHandle": "d_AAAAAAAAAAAAAAAAAAAAAA",
            "algorithm": ALGORITHM,
            "version": 1,
            "publicKey": PUBLIC_KEY,
            "validFrom": 900,
            "expiresAt": 3000,
        }
    ]
    evidence = {
        "schema": PACKAGE_SCHEMA,
        "version": VERSION,
        "source": SOURCE,
        "alias": alias,
        "complete": True,
        "issuedAt": 1000,
        "expiresAt": 2000,
        "devices": devices,
    }
    canonical = json.dumps(
        evidence,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return {
        "schema": PACKAGE_SCHEMA,
        "version": VERSION,
        "source": SOURCE,
        "snapshotId": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "complete": True,
        "alias": alias,
        "issuedAt": 1000,
        "expiresAt": 2000,
        "devices": devices,
    }


class Resolver:
    def __init__(self, *, result=None, exception=None):
        self.result = result
        self.exception = exception
        self.calls = []

    def resolve(self, *, viewer_subject, recipient_alias):
        self.calls.append((viewer_subject, recipient_alias))
        if self.exception is not None:
            raise self.exception
        return package(recipient_alias) if self.result is None else self.result


def runtime(monkeypatch, *, resolver=None, full=True):
    monkeypatch.setattr(
        delivery,
        "validate_confidential_service_config",
        lambda _config: None,
    )
    return delivery.MessagingRecipientInternalDeliveryRuntime(
        service_config=service_config(),
        replay_consumer=lambda _jti, _exp: True,
        service_signing_key=object(),
        service_signing_kid="kid-1",
        viewer_oauth_client_id="social-web",
        viewer_token_validator=lambda _token: viewer(),
        current_entitlement_resolver=lambda _subject: entitlement(full=full),
        recipient_resolver=resolver or Resolver(),
    )


def app_with_runtime(instance=None):
    app = Flask(__name__)
    app.register_blueprint(internal_social_messaging_recipient_bp)
    if instance is not None:
        app.extensions[MESSAGING_RECIPIENT_INTERNAL_EXTENSION] = instance
    return app


def auth_headers():
    return {
        "Authorization": "Bearer service-token",
        VIEWER_AUTHORIZATION_HEADER: "Bearer viewer-token",
    }


def enable_service_verification(monkeypatch):
    monkeypatch.setattr(
        delivery,
        "verify_service_access_token",
        lambda _token, *, config: verified_service(),
    )


def test_routes_are_inert_without_exact_runtime():
    client = app_with_runtime().test_client()

    response = client.post(
        RECIPIENT_DEVICES_ROUTE,
        json={"recipientAlias": ALIAS},
    )

    assert response.status_code == 404
    assert response.get_json() == {"error": "not_found"}
    assert response.headers["Cache-Control"] == "no-store"


def test_service_token_route_uses_exact_recipient_scope(monkeypatch):
    instance = runtime(monkeypatch)
    monkeypatch.setattr(
        delivery,
        "issue_service_access_token",
        lambda assertion, **_kwargs: "service-token",
    )
    client = app_with_runtime(instance).test_client()

    response = client.post(
        SERVICE_TOKEN_ROUTE,
        data={
            "grant_type": GRANT_TYPE,
            "client_id": instance.service_config.client_id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": "assertion",
            "scope": delivery.MESSAGING_RECIPIENT_SCOPE,
        },
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["access_token"] == "service-token"
    assert body["scope"] == delivery.MESSAGING_RECIPIENT_SCOPE
    assert response.headers["Cache-Control"] == "no-store"


def test_service_token_route_rejects_other_scope(monkeypatch):
    instance = runtime(monkeypatch)
    client = app_with_runtime(instance).test_client()

    response = client.post(
        SERVICE_TOKEN_ROUTE,
        data={
            "grant_type": GRANT_TYPE,
            "client_id": instance.service_config.client_id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": "assertion",
            "scope": "social:messaging-device:manage",
        },
    )

    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_client"}


@pytest.mark.parametrize(
    "body",
    [
        b'{"recipientAlias":"not-a-p-alias"}',
        b'{"recipientAlias":"p_AAAAAAAAAAAAAAAAAAAAAA","extra":1}',
        b'{"recipientAlias":"p_AAAAAAAAAAAAAAAAAAAAAA","recipientAlias":"p_BBBBBBBBBBBBBBBBBBBBBB"}',
    ],
)
def test_recipient_request_is_closed_and_strict(monkeypatch, body):
    resolver = Resolver()
    instance = runtime(monkeypatch, resolver=resolver)
    client = app_with_runtime(instance).test_client()

    response = client.post(
        RECIPIENT_DEVICES_ROUTE,
        data=body,
        headers={
            **auth_headers(),
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid_request"}
    assert resolver.calls == []


def test_service_is_rejected_before_viewer_or_resolver(monkeypatch):
    resolver = Resolver()
    instance = runtime(monkeypatch, resolver=resolver)
    viewer_calls = []
    object.__setattr__(
        instance,
        "viewer_token_validator",
        lambda token: viewer_calls.append(token),
    )
    monkeypatch.setattr(
        delivery,
        "verify_service_access_token",
        lambda _token, *, config: (_ for _ in ()).throw(CredentialDenied("credential denied")),
    )
    client = app_with_runtime(instance).test_client()

    response = client.post(
        RECIPIENT_DEVICES_ROUTE,
        json={"recipientAlias": ALIAS},
        headers=auth_headers(),
    )

    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_token"}
    assert viewer_calls == []
    assert resolver.calls == []


def test_valid_request_uses_server_derived_viewer_and_projects_only_package(monkeypatch):
    resolver = Resolver()
    instance = runtime(monkeypatch, resolver=resolver)
    enable_service_verification(monkeypatch)
    client = app_with_runtime(instance).test_client()

    response = client.post(
        RECIPIENT_DEVICES_ROUTE,
        json={"recipientAlias": ALIAS},
        headers=auth_headers(),
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body == package()
    serialized = json.dumps(body, sort_keys=True)
    assert "deviceId" not in serialized
    assert "bindingId" not in serialized
    assert SUBJECT not in serialized
    assert resolver.calls == [(SUBJECT, ALIAS)]
    assert response.headers["Cache-Control"] == "no-store"


def test_invalid_viewer_credential_is_401_before_resolver(monkeypatch):
    resolver = Resolver()
    instance = runtime(monkeypatch, resolver=resolver)
    object.__setattr__(
        instance,
        "viewer_token_validator",
        lambda _token: (_ for _ in ()).throw(ValueError("bad viewer")),
    )
    enable_service_verification(monkeypatch)
    client = app_with_runtime(instance).test_client()

    response = client.post(
        RECIPIENT_DEVICES_ROUTE,
        json={"recipientAlias": ALIAS},
        headers=auth_headers(),
    )

    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_viewer_credential"}
    assert resolver.calls == []


def test_non_full_viewer_is_403_before_resolver(monkeypatch):
    resolver = Resolver()
    instance = runtime(monkeypatch, resolver=resolver, full=False)
    enable_service_verification(monkeypatch)
    client = app_with_runtime(instance).test_client()

    response = client.post(
        RECIPIENT_DEVICES_ROUTE,
        json={"recipientAlias": ALIAS},
        headers=auth_headers(),
    )

    assert response.status_code == 403
    assert response.get_json() == {"error": "insufficient_entitlement"}
    assert resolver.calls == []


@pytest.mark.parametrize(
    "exception",
    [
        RecipientAliasInvalid(),
        RecipientDeviceResolverDenied(),
        RecipientDeviceResolverUnavailable(),
    ],
)
def test_target_state_failures_collapse_to_one_generic_503(monkeypatch, exception):
    resolver = Resolver(exception=exception)
    instance = runtime(monkeypatch, resolver=resolver)
    enable_service_verification(monkeypatch)
    client = app_with_runtime(instance).test_client()

    response = client.post(
        RECIPIENT_DEVICES_ROUTE,
        json={"recipientAlias": ALIAS},
        headers=auth_headers(),
    )

    assert response.status_code == 503
    assert response.get_json() == {"error": "recipient_authority_unavailable"}


@pytest.mark.parametrize(
    "mutation",
    ["target", "rawDevice", "snapshot", "alias"],
)
def test_malformed_or_leaky_resolver_package_is_never_serialized(
    monkeypatch,
    mutation,
):
    value = package()
    if mutation == "target":
        value["targetSubject"] = SUBJECT
    elif mutation == "rawDevice":
        value["devices"][0]["deviceId"] = "0" * 64
    elif mutation == "snapshot":
        value["snapshotId"] = "sha256:" + "0" * 64
    elif mutation == "alias":
        value["alias"] = "p_BBBBBBBBBBBBBBBBBBBBBB"

    resolver = Resolver(result=value)
    instance = runtime(monkeypatch, resolver=resolver)
    enable_service_verification(monkeypatch)
    client = app_with_runtime(instance).test_client()

    response = client.post(
        RECIPIENT_DEVICES_ROUTE,
        json={"recipientAlias": ALIAS},
        headers=auth_headers(),
    )

    assert response.status_code == 503
    assert response.get_json() == {"error": "recipient_authority_unavailable"}
    assert SUBJECT not in response.get_data(as_text=True)


def test_missing_viewer_header_is_401_without_resolver_call(monkeypatch):
    resolver = Resolver()
    instance = runtime(monkeypatch, resolver=resolver)
    enable_service_verification(monkeypatch)
    client = app_with_runtime(instance).test_client()

    response = client.post(
        RECIPIENT_DEVICES_ROUTE,
        json={"recipientAlias": ALIAS},
        headers={"Authorization": "Bearer service-token"},
    )

    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_viewer_credential"}
    assert resolver.calls == []

from datetime import (
    datetime,
    timedelta,
    timezone,
)
import json
from pathlib import Path

from coincurve import (
    PrivateKey,
    PublicKeyXOnly,
)
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
)
import jwt
from jwt.algorithms import RSAAlgorithm
from flask import Flask
import pytest

import app.services.social_messaging_device_binding_registry as device_contract

from app.blueprints.internal_social_messaging import (
    CLIENT_ASSERTION_TYPE,
    DEVICE_BINDINGS_ROUTE,
    SERVICE_TOKEN_ROUTE,
    VIEWER_AUTHORIZATION_HEADER,
    internal_social_messaging_bp,
)
from app.services.action_authorization import (
    IdentityClass,
)
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    verify_service_access_token,
)
from app.services.current_entitlement import (
    EntitlementDecision,
)
from app.services.oauth_bearer_validation import (
    BearerPrincipal,
)
from app.services.social_messaging_device_binding_registry import (
    SocialMessagingDeviceBindingRegistry,
    statement_digest,
)
from app.services.social_messaging_internal_delivery import (
    INTERNAL_MESSAGING_EXTENSION,
    MESSAGING_SERVICE_PURPOSE,
    MESSAGING_SERVICE_SCOPE,
    SocialMessagingInternalDeliveryRuntime,
)


NOW = 2_000_000_000
NOW_DT = datetime.fromtimestamp(
    NOW,
    timezone.utc,
)

CLIENT = "social-messaging-backend"
PRINCIPAL = "service:social-messaging"

ISSUER = "https://identity.example"

TOKEN_AUDIENCE = (
    "https://identity.example"
    "/internal/v1/social/messaging/service-token"
)

RESOURCE_AUDIENCE = (
    "https://identity.example"
    "/internal/v1/social/messaging"
)

VIEWER_CLIENT = "social-browser-client"

DEVICE_ID = "11" * 32
X25519_KEY = "09" + "00" * 31


def _public_jwk(key, kid):
    value = json.loads(
        RSAAlgorithm.to_jwk(
            key.public_key()
        )
    )

    value.update(
        {
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
        }
    )

    return value


@pytest.fixture(scope="module")
def material():
    client_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    service_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    return (
        client_key,
        service_key,
        _public_jwk(
            client_key,
            "client-key",
        ),
        _public_jwk(
            service_key,
            "service-key",
        ),
    )


def _service_config(material):
    return ConfidentialServiceConfig(
        enabled=True,
        client_id=CLIENT,
        service_principal=PRINCIPAL,
        issuer=ISSUER,
        token_endpoint_audience=TOKEN_AUDIENCE,
        service_resource_audience=RESOURCE_AUDIENCE,
        client_jwks=(material[2],),
        service_jwks=(material[3],),
        service_scope=MESSAGING_SERVICE_SCOPE,
        service_purpose=MESSAGING_SERVICE_PURPOSE,
    )


def _assertion(material):
    payload = {
        "iss": CLIENT,
        "sub": CLIENT,
        "aud": TOKEN_AUDIENCE,
        "iat": NOW,
        "exp": NOW + 60,
        "jti": "messaging-assertion-1",
        "token_use": "client_assertion",
        "grant_type": "client_credentials",
        "purpose": "service_client_authentication",
    }

    return jwt.encode(
        payload,
        material[0],
        algorithm="RS256",
        headers={"kid": "client-key"},
    )


def _service_token(
    material,
    *,
    scope=MESSAGING_SERVICE_SCOPE,
    purpose=MESSAGING_SERVICE_PURPOSE,
):
    payload = {
        "iss": ISSUER,
        "aud": RESOURCE_AUDIENCE,
        "sub": PRINCIPAL,
        "azp": CLIENT,
        "scope": scope,
        "grant_type": "client_credentials",
        "token_use": "service_access",
        "purpose": purpose,
        "iat": NOW,
        "exp": NOW + 60,
        "jti": "messaging-service-token-1",
    }

    return jwt.encode(
        payload,
        material[1],
        algorithm="RS256",
        headers={"kid": "service-key"},
    )


class MemoryRepository:
    def __init__(self):
        self.records = []

    def apply(
        self,
        statement,
        _now,
    ):
        self.records = [
            record
            for record in self.records
            if not (
                record.subject
                == statement.subject
                and record.device_id
                == statement.device_id
            )
        ]

        if statement.operation != "revoke":
            self.records.append(
                statement
            )

        return statement

    def current_for_subject(
        self,
        subject,
        _now,
        maximum,
    ):
        return sorted(
            [
                record
                for record in self.records
                if record.subject == subject
            ],
            key=lambda record: (
                record.device_id
            ),
        )[:maximum]


def _subject(private_key):
    return (
        PublicKeyXOnly.from_secret(
            private_key.secret
        )
        .format()
        .hex()
    )


def _viewer_principal(subject):
    return BearerPrincipal(
        subject=subject,
        user_id="viewer-user",
        client_id=VIEWER_CLIENT,
        scopes=frozenset(
            {"openid", "profile"}
        ),
        jti="viewer-jti",
        issued_at=NOW_DT,
        expires_at=(
            NOW_DT
            + timedelta(hours=1)
        ).replace(tzinfo=None),
        token_contract=(
            "hodlxxi.oauth.access-token.v1"
        ),
    )


def _decision(
    subject,
    *,
    identity=IdentityClass.FULL,
    relation=True,
):
    return EntitlementDecision(
        subject=subject,
        identity_class=identity,
        current_full_relation_satisfied=relation,
        evidence_source=(
            "canonical_current_entitlement"
        ),
        observed_at=NOW_DT.isoformat(),
    )


def _runtime(
    material,
    *,
    subject,
    repository=None,
    identity=IdentityClass.FULL,
    relation=True,
):
    repository = repository or MemoryRepository()

    registry = (
        SocialMessagingDeviceBindingRegistry(
            repository,
            clock=lambda: NOW_DT,
        )
    )

    return SocialMessagingInternalDeliveryRuntime(
        service_config=_service_config(
            material
        ),
        replay_consumer=(
            lambda _jti, _deadline: True
        ),
        service_signing_key=material[1],
        service_signing_kid="service-key",
        viewer_oauth_client_id=(
            VIEWER_CLIENT
        ),
        viewer_token_validator=(
            lambda _token: (
                _viewer_principal(subject)
            )
        ),
        current_entitlement_resolver=(
            lambda value: _decision(
                value,
                identity=identity,
                relation=relation,
            )
        ),
        device_registry=registry,
    )


def _route_client(runtime=None):
    app = Flask(__name__)
    app.config.update(TESTING=True)

    if runtime is not None:
        app.extensions[
            INTERNAL_MESSAGING_EXTENSION
        ] = runtime

    app.register_blueprint(
        internal_social_messaging_bp
    )

    return app.test_client()


def _statement(
    identity_key,
):
    subject = _subject(identity_key)

    valid_from = (
        NOW_DT
        - timedelta(minutes=1)
    ).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")

    expires_at = (
        NOW_DT
        + timedelta(hours=1)
    ).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")

    core = {
        "schema": (
            device_contract.STATEMENT_SCHEMA
        ),
        "version": 1,
        "subject": subject,
        "deviceId": DEVICE_ID,
        "algorithm": (
            device_contract.ALGORITHM
        ),
        "publicKey": X25519_KEY,
        "bindingVersion": 1,
        "validFrom": valid_from,
        "expiresAt": expires_at,
        "operation": "register",
        "priorBindingId": None,
        "nonce": "22" * 32,
    }

    digest = statement_digest(core)

    payload = {
        **core,
        "digest": digest,
        "signatureFormat": (
            device_contract.SIGNATURE_FORMAT
        ),
        "signature": (
            identity_key.sign_schnorr(
                bytes.fromhex(digest),
                b"\x00" * 32,
            ).hex()
        ),
    }

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _headers(material):
    return {
        "Authorization": (
            f"Bearer {_service_token(material)}"
        ),
        VIEWER_AUTHORIZATION_HEADER: (
            "Bearer viewer-token"
        ),
    }


def test_messaging_service_token_has_separate_scope_and_purpose(
    material,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.services.confidential_service_credentials.time.time",
        lambda: NOW,
    )

    identity_key = PrivateKey(
        b"\x01" * 32
    )

    runtime = _runtime(
        material,
        subject=_subject(identity_key),
    )

    client = _route_client(runtime)

    response = client.post(
        SERVICE_TOKEN_ROUTE,
        data={
            "grant_type": (
                "client_credentials"
            ),
            "client_id": CLIENT,
            "client_assertion_type": (
                CLIENT_ASSERTION_TYPE
            ),
            "client_assertion": (
                _assertion(material)
            ),
            "scope": (
                MESSAGING_SERVICE_SCOPE
            ),
        },
    )

    assert response.status_code == 200

    assert response.json["scope"] == (
        MESSAGING_SERVICE_SCOPE
    )

    evidence = verify_service_access_token(
        response.json["access_token"],
        config=_service_config(material),
        now=NOW,
    )

    assert evidence.scope == (
        MESSAGING_SERVICE_SCOPE
    )

    claims = jwt.decode(
        response.json["access_token"],
        options={
            "verify_signature": False
        },
    )

    assert claims["purpose"] == (
        MESSAGING_SERVICE_PURPOSE
    )


def test_disabled_private_routes_are_404(
    material,
):
    client = _route_client()

    assert (
        client.post(
            SERVICE_TOKEN_ROUTE
        ).status_code
        == 404
    )

    assert (
        client.get(
            DEVICE_BINDINGS_ROUTE
        ).status_code
        == 404
    )


def test_full_viewer_registers_and_reads_own_device_without_subject_leak(
    material,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.services.confidential_service_credentials.time.time",
        lambda: NOW,
    )

    identity_key = PrivateKey(
        b"\x01" * 32
    )

    subject = _subject(
        identity_key
    )

    repository = MemoryRepository()

    client = _route_client(
        _runtime(
            material,
            subject=subject,
            repository=repository,
        )
    )

    response = client.post(
        DEVICE_BINDINGS_ROUTE,
        data=_statement(
            identity_key
        ),
        content_type="application/json",
        headers=_headers(material),
    )

    assert response.status_code == 200

    serialized = response.get_data(
        as_text=True
    )

    assert subject not in serialized
    assert '"signature"' not in serialized
    assert '"nonce"' not in serialized

    assert response.json[
        "device"
    ]["deviceId"] == DEVICE_ID

    assert response.json[
        "device"
    ]["publicKey"] == X25519_KEY

    response = client.get(
        DEVICE_BINDINGS_ROUTE,
        headers=_headers(material),
    )

    assert response.status_code == 200
    assert len(
        response.json["activeDevices"]
    ) == 1

    serialized = response.get_data(
        as_text=True
    )

    assert subject not in serialized


def test_limited_viewer_cannot_write_device_binding(
    material,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.services.confidential_service_credentials.time.time",
        lambda: NOW,
    )

    identity_key = PrivateKey(
        b"\x01" * 32
    )

    repository = MemoryRepository()

    client = _route_client(
        _runtime(
            material,
            subject=_subject(
                identity_key
            ),
            repository=repository,
            identity=IdentityClass.LIMITED,
            relation=False,
        )
    )

    response = client.post(
        DEVICE_BINDINGS_ROUTE,
        data=_statement(
            identity_key
        ),
        content_type="application/json",
        headers=_headers(material),
    )

    assert response.status_code == 403
    assert response.json == {
        "error": "insufficient_entitlement"
    }

    assert repository.records == []


def test_full_directory_scope_cannot_manage_messaging_devices(
    material,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.services.confidential_service_credentials.time.time",
        lambda: NOW,
    )

    identity_key = PrivateKey(
        b"\x01" * 32
    )

    runtime = _runtime(
        material,
        subject=_subject(identity_key),
    )

    client = _route_client(runtime)

    headers = {
        "Authorization": (
            "Bearer "
            + _service_token(
                material,
                scope=(
                    "social:full-directory:read"
                ),
                purpose=(
                    "social_full_directory_read"
                ),
            )
        ),
        VIEWER_AUTHORIZATION_HEADER: (
            "Bearer viewer-token"
        ),
    }

    response = client.get(
        DEVICE_BINDINGS_ROUTE,
        headers=headers,
    )

    assert response.status_code == 401
    assert response.json == {
        "error": "invalid_token"
    }


def test_noncanonical_statement_json_fails_closed(
    material,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.services.confidential_service_credentials.time.time",
        lambda: NOW,
    )

    identity_key = PrivateKey(
        b"\x01" * 32
    )

    client = _route_client(
        _runtime(
            material,
            subject=_subject(
                identity_key
            ),
        )
    )

    payload = (
        _statement(identity_key)
        + " "
    )

    response = client.post(
        DEVICE_BINDINGS_ROUTE,
        data=payload,
        content_type="application/json",
        headers=_headers(material),
    )

    assert response.status_code == 503
    assert response.json == {
        "error": "device_binding_unavailable"
    }


def test_messaging_private_routes_are_not_publicly_advertised():
    routes = (
        SERVICE_TOKEN_ROUTE,
        DEVICE_BINDINGS_ROUTE,
    )

    sources = (
        Path("app/blueprints/agent.py"),
        Path("app/blueprints/ui.py"),
        Path(
            "app/services/mcp_discovery.py"
        ),
        Path(
            "app/services/agent_readiness_report.py"
        ),
    )

    for source in sources:
        content = source.read_text(
            encoding="utf-8"
        )

        for route in routes:
            assert route not in content


def test_factory_config_defaults_messaging_boundary_off(
    monkeypatch,
):
    monkeypatch.delenv(
        "SOCIAL_MESSAGING_INTERNAL_ENABLED",
        raising=False,
    )

    from app.config import get_config

    assert (
        get_config()[
            "SOCIAL_MESSAGING_INTERNAL_ENABLED"
        ]
        is False
    )

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask
from jwt.algorithms import RSAAlgorithm

from app.blueprints.internal_privacy_full_directory import (
    CLIENT_ASSERTION_TYPE,
    PRIVATE_DIRECTORY_ROUTE,
    SERVICE_TOKEN_ROUTE,
    VIEWER_AUTHORIZATION_HEADER,
    internal_privacy_full_directory_bp,
)
from app.config import get_config
from app.services.action_authorization import IdentityClass
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    CredentialDenied,
    CredentialUnavailable,
)
from app.services.current_entitlement import EntitlementDecision
from app.services.oauth_bearer_validation import BearerPrincipal
from app.services.privacy_full_directory_internal_delivery import (
    INTERNAL_DELIVERY_EXTENSION,
    InternalDeliveryConfigurationError,
    PrivacyFullDirectoryInternalDeliveryRuntime,
    ViewerCredentialDenied,
    build_internal_delivery_runtime,
    configure_internal_delivery,
)
from app.services.privacy_safe_full_directory import (
    PrivacySafeFullDirectoryDenied,
    PrivacySafeFullDirectoryUnavailable,
)

NOW = 2_000_000_000
NOW_DT = datetime.fromtimestamp(NOW, timezone.utc)
CLIENT = "social-confidential-backend"
VIEWER_CLIENT = "social-browser-client"
PRINCIPAL = "service:social-full-directory"
ISSUER = "https://identity.example"
TOKEN_AUDIENCE = "https://identity.example/internal/v1/social/service-token"
RESOURCE_AUDIENCE = "https://identity.example/internal/v1/social/full-directory"
VIEWER = "01" * 32
OTHER_VIEWER = "02" * 32
TARGET = "03" * 32
ALIAS_SECRET = bytes(range(32))


def _public_jwk(key, kid):
    value = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    value.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return value


@pytest.fixture(scope="module")
def material():
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        client_key,
        service_key,
        _public_jwk(client_key, "client-key"),
        _public_jwk(service_key, "service-key"),
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
    )


def _assertion(material, *, jti="assertion-1", claims=None, headers=None, key=None, algorithm="RS256"):
    payload = {
        "iss": CLIENT,
        "sub": CLIENT,
        "aud": TOKEN_AUDIENCE,
        "iat": NOW,
        "exp": NOW + 60,
        "jti": jti,
        "token_use": "client_assertion",
        "grant_type": "client_credentials",
        "purpose": "service_client_authentication",
    }
    payload.update(claims or {})
    token_headers = {"kid": "client-key"}
    token_headers.update(headers or {})
    return jwt.encode(payload, key or material[0], algorithm=algorithm, headers=token_headers)


def _service_token(material, *, claims=None):
    payload = {
        "iss": ISSUER,
        "aud": RESOURCE_AUDIENCE,
        "sub": PRINCIPAL,
        "azp": CLIENT,
        "scope": "social:full-directory:read",
        "grant_type": "client_credentials",
        "token_use": "service_access",
        "purpose": "social_full_directory_read",
        "iat": NOW,
        "exp": NOW + 60,
        "jti": "service-token-1",
    }
    payload.update(claims or {})
    return jwt.encode(payload, material[1], algorithm="RS256", headers={"kid": "service-key"})


def _viewer_principal(subject=VIEWER, *, client_id=VIEWER_CLIENT, scopes=frozenset({"openid", "profile"})):
    return BearerPrincipal(
        subject=subject,
        user_id="viewer-user-id",
        client_id=client_id,
        scopes=scopes,
        jti="viewer-token-jti",
        issued_at=NOW_DT,
        expires_at=(NOW_DT + timedelta(hours=1)).replace(tzinfo=None),
        token_contract="hodlxxi.oauth.access-token.v1",
    )


def _decision(subject=VIEWER, identity=IdentityClass.FULL, *, relation=True, observed_at=None):
    return EntitlementDecision(
        subject=subject,
        identity_class=identity,
        current_full_relation_satisfied=relation,
        evidence_source="canonical_current_entitlement",
        observed_at=observed_at or NOW_DT.isoformat(),
    )


def _snapshot(subjects=(VIEWER, TARGET), *, complete=True, expires_at=None):
    issued_at = NOW * 1000
    expires_at = expires_at if expires_at is not None else issued_at + 300_000
    entitlements = [
        {
            "subject": subject,
            "status": "full",
            "validFrom": issued_at - 1_000,
            "expiresAt": expires_at,
            "revoked": False,
        }
        for subject in sorted(subjects)
    ]
    evidence = {
        "complete": complete,
        "entitlements": entitlements,
        "expiresAt": expires_at,
        "issuedAt": issued_at,
    }
    canonical = json.dumps(evidence, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    snapshot_id = "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest()
    return {
        "schema": "hodlxxi.full_entitlement_snapshot.v1",
        "version": 1,
        "source": "hodlxxi-crt",
        "snapshotId": snapshot_id,
        "complete": complete,
        "issuedAt": issued_at,
        "expiresAt": expires_at,
        "entitlements": [{"snapshotId": snapshot_id, **value} for value in entitlements],
    }


def _runtime(
    material,
    *,
    replay=None,
    viewer=None,
    resolver=None,
    provider=None,
    secret=ALIAS_SECRET,
    service_config=None,
):
    return PrivacyFullDirectoryInternalDeliveryRuntime(
        service_config=service_config or _service_config(material),
        replay_consumer=replay or (lambda _jti, _deadline: True),
        service_signing_key=material[1],
        service_signing_kid="service-key",
        viewer_oauth_client_id=VIEWER_CLIENT,
        viewer_token_validator=viewer or (lambda _token: _viewer_principal()),
        current_entitlement_resolver=resolver or (lambda subject: _decision(subject)),
        full_population_provider=provider or (lambda: _snapshot()),
        alias_secret=secret,
    )


def _route_client(runtime=None):
    app = Flask(__name__)
    app.config.update(TESTING=True)
    if runtime is not None:
        app.extensions[INTERNAL_DELIVERY_EXTENSION] = runtime
    app.register_blueprint(internal_privacy_full_directory_bp)
    return app.test_client()


def _token_form(assertion):
    return {
        "grant_type": "client_credentials",
        "client_id": CLIENT,
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": assertion,
        "scope": "social:full-directory:read",
    }


def test_valid_assertion_uses_replay_consumer_and_issues_exact_service_token(material, monkeypatch):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)
    calls = []
    runtime = _runtime(material, replay=lambda jti, deadline: calls.append((jti, deadline)) is None)

    token = runtime.issue_service_token(_assertion(material))
    evidence = runtime.verify_service_authority(token)

    assert calls == [("assertion-1", NOW + 66)]
    assert evidence.service_principal == PRINCIPAL
    assert evidence.client_id == CLIENT
    assert evidence.scope == "social:full-directory:read"
    assert evidence.expires_at - evidence.issued_at == 60


def test_duplicate_assertion_jti_fails_closed(material, monkeypatch):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)
    seen = set()

    def consume(jti, _deadline):
        if jti in seen:
            return False
        seen.add(jti)
        return True

    runtime = _runtime(material, replay=consume)
    runtime.issue_service_token(_assertion(material))
    with pytest.raises(CredentialUnavailable, match="^credential service unavailable$"):
        runtime.issue_service_token(_assertion(material))


def test_disabled_route_runtime_is_not_available(material):
    client = _route_client()
    assert client.post(SERVICE_TOKEN_ROUTE, data=_token_form(_assertion(material))).status_code == 404
    assert client.get(PRIVATE_DIRECTORY_ROUTE).status_code == 404


def test_token_route_accepts_only_exact_flow_and_does_not_cache(material, monkeypatch):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)
    client = _route_client(_runtime(material))

    response = client.post(SERVICE_TOKEN_ROUTE, data=_token_form(_assertion(material)))
    assert response.status_code == 200
    assert set(response.json) == {"access_token", "expires_in", "scope", "token_type"}
    assert response.json["scope"] == "social:full-directory:read"
    assert response.headers["Cache-Control"] == "no-store"

    wrong = _token_form(_assertion(material, jti="wrong-flow"))
    wrong["scope"] = "social:full-directory:write"
    assert client.post(SERVICE_TOKEN_ROUTE, data=wrong).status_code == 401
    assert client.post(SERVICE_TOKEN_ROUTE, json=wrong).status_code == 400


def test_token_route_replay_and_malformed_assertion_fail_closed(material, monkeypatch):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)
    seen = set()

    def consume(jti, _deadline):
        if jti in seen:
            return False
        seen.add(jti)
        return True

    client = _route_client(_runtime(material, replay=consume))
    form = _token_form(_assertion(material))
    assert client.post(SERVICE_TOKEN_ROUTE, data=form).status_code == 200
    assert client.post(SERVICE_TOKEN_ROUTE, data=form).status_code == 503
    form["client_assertion"] = "not-a-jwt"
    assert client.post(SERVICE_TOKEN_ROUTE, data=form).status_code == 401


def test_directory_route_requires_service_then_independent_viewer(material, monkeypatch):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)
    viewer_calls = []
    runtime = _runtime(
        material,
        viewer=lambda token: viewer_calls.append(token) or _viewer_principal(),
    )
    client = _route_client(runtime)

    assert client.get(PRIVATE_DIRECTORY_ROUTE).status_code == 401
    assert viewer_calls == []
    wrong_scope = _service_token(material, claims={"scope": "wrong"})
    response = client.get(
        PRIVATE_DIRECTORY_ROUTE,
        headers={
            "Authorization": f"Bearer {wrong_scope}",
            VIEWER_AUTHORIZATION_HEADER: "Bearer viewer-token",
        },
    )
    assert response.status_code == 401
    assert viewer_calls == []

    response = client.get(
        PRIVATE_DIRECTORY_ROUTE,
        headers={"Authorization": f"Bearer {_service_token(material)}"},
    )
    assert response.status_code == 401


def test_directory_route_rejects_cryptographically_invalid_viewer(material, monkeypatch):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)

    def reject_viewer(_token):
        raise ValueError("signature invalid")

    client = _route_client(_runtime(material, viewer=reject_viewer))
    response = client.get(
        PRIVATE_DIRECTORY_ROUTE,
        headers={
            "Authorization": f"Bearer {_service_token(material)}",
            VIEWER_AUTHORIZATION_HEADER: "Bearer forged-viewer-token",
        },
    )
    assert response.status_code == 401
    assert response.json == {"error": "invalid_viewer_credential"}


def test_directory_route_returns_only_privacy_projection(material, monkeypatch):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)
    monkeypatch.setattr("app.services.privacy_safe_full_directory.datetime", _FixedDateTime)
    client = _route_client(_runtime(material))
    response = client.get(
        PRIVATE_DIRECTORY_ROUTE,
        headers={
            "Authorization": f"Bearer {_service_token(material)}",
            VIEWER_AUTHORIZATION_HEADER: "Bearer independently-verified-viewer-token",
        },
    )

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert set(response.json) == {"participants", "schema", "version"}
    assert len(response.json["participants"]) == 1
    serialized = response.get_data(as_text=True)
    for forbidden in (VIEWER, TARGET, "xpub", "descriptor", "utxo", "nostr", "x25519"):
        assert forbidden not in serialized.lower()


def test_directory_route_denials_do_not_reveal_population(material, monkeypatch):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)
    monkeypatch.setattr("app.services.privacy_safe_full_directory.datetime", _FixedDateTime)
    client = _route_client(
        _runtime(
            material,
            resolver=lambda subject: _decision(subject, IdentityClass.LIMITED, relation=False),
        )
    )
    response = client.get(
        PRIVATE_DIRECTORY_ROUTE,
        headers={
            "Authorization": f"Bearer {_service_token(material)}",
            VIEWER_AUTHORIZATION_HEADER: "Bearer viewer-token",
        },
    )
    assert response.status_code == 403
    assert response.json == {"error": "insufficient_entitlement"}


def test_credentials_are_not_logged_by_internal_routes(material, monkeypatch, caplog):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)
    assertion = _assertion(material, jti="private-log-test-jti")
    service_token = _service_token(material)
    viewer_token = "private-viewer-bearer"
    client = _route_client(_runtime(material))
    client.post(SERVICE_TOKEN_ROUTE, data=_token_form(assertion))
    client.get(
        PRIVATE_DIRECTORY_ROUTE,
        headers={
            "Authorization": f"Bearer {service_token}",
            VIEWER_AUTHORIZATION_HEADER: f"Bearer {viewer_token}",
        },
    )
    logs = caplog.text
    assert assertion not in logs
    assert service_token not in logs
    assert viewer_token not in logs
    assert "private-log-test-jti" not in logs


def test_internal_routes_are_absent_from_public_discovery_and_catalog_sources():
    public_sources = (
        Path("app/blueprints/agent.py"),
        Path("app/blueprints/ui.py"),
        Path("app/services/mcp_discovery.py"),
        Path("app/services/agent_readiness_report.py"),
    )
    for source in public_sources:
        content = source.read_text(encoding="utf-8")
        assert SERVICE_TOKEN_ROUTE not in content
        assert PRIVATE_DIRECTORY_ROUTE not in content


def test_service_authority_is_verified_before_viewer_authentication(material, monkeypatch):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)
    viewer_calls = []
    runtime = _runtime(material, viewer=lambda token: viewer_calls.append(token) or _viewer_principal())

    with pytest.raises(CredentialDenied):
        runtime.current_directory("not-a-token", "viewer-token")
    assert viewer_calls == []


def test_human_viewer_is_a_separate_audience_bound_openid_principal(material, monkeypatch):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)
    service_token = _service_token(material)

    for principal in (
        _viewer_principal(client_id="other-client"),
        _viewer_principal(scopes=frozenset({"profile"})),
    ):
        runtime = _runtime(material, viewer=lambda _token, value=principal: value)
        with pytest.raises(ViewerCredentialDenied):
            runtime.current_directory(service_token, "viewer-token")


def test_valid_current_full_viewer_receives_only_opaque_self_excluding_directory(material, monkeypatch):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)
    monkeypatch.setattr("app.services.privacy_safe_full_directory.datetime", _FixedDateTime)
    result = _runtime(material).current_directory(_service_token(material), "viewer-token")

    assert set(result) == {"schema", "version", "participants"}
    assert len(result["participants"]) == 1
    serialized = json.dumps(result, sort_keys=True)
    assert VIEWER not in serialized
    assert TARGET not in serialized
    assert "xpub" not in serialized.lower()
    assert "descriptor" not in serialized.lower()
    assert "utxo" not in serialized.lower()
    assert "nostr" not in serialized.lower()
    assert "x25519" not in serialized.lower()


class _FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls.fromtimestamp(NOW, tz) if tz is not None else cls.fromtimestamp(NOW)


@pytest.mark.parametrize(
    "resolver",
    (
        lambda subject: _decision(subject, IdentityClass.LIMITED, relation=False),
        lambda subject: _decision(subject, IdentityClass.FULL, relation=False),
    ),
)
def test_limited_revoked_or_noncurrent_viewer_is_denied(material, monkeypatch, resolver):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)
    monkeypatch.setattr("app.services.privacy_safe_full_directory.datetime", _FixedDateTime)
    with pytest.raises(PrivacySafeFullDirectoryDenied):
        _runtime(material, resolver=resolver).current_directory(_service_token(material), "viewer-token")


@pytest.mark.parametrize(
    "provider",
    (
        lambda: _snapshot(complete=False),
        lambda: _snapshot(expires_at=NOW * 1000),
        lambda: (_ for _ in ()).throw(RuntimeError("storage unavailable")),
    ),
)
def test_incomplete_stale_or_unavailable_population_fails_closed(material, monkeypatch, provider):
    monkeypatch.setattr("app.services.confidential_service_credentials.time.time", lambda: NOW)
    monkeypatch.setattr("app.services.privacy_safe_full_directory.datetime", _FixedDateTime)
    with pytest.raises(PrivacySafeFullDirectoryUnavailable):
        _runtime(material, provider=provider).current_directory(_service_token(material), "viewer-token")


def _write_runtime_material(tmp_path, material, *, shared_keys=False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    client_dir = tmp_path / "client"
    service_dir = tmp_path / "service"
    client_dir.mkdir()
    service_dir.mkdir()
    client_jwk = material[3] if shared_keys else material[2]
    (client_dir / "jwks.json").write_text(json.dumps({"keys": [client_jwk]}), encoding="utf-8")
    (service_dir / "jwks.json").write_text(json.dumps({"keys": [material[3]]}), encoding="utf-8")
    private_path = service_dir / "private_key_service-key.pem"
    private_path.write_bytes(
        material[1].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    secret_path = tmp_path / "alias-secret"
    secret_path.write_bytes(ALIAS_SECRET)
    secret_path.chmod(0o600)
    return client_dir, service_dir, secret_path


def _runtime_config(tmp_path, material, *, shared_keys=False):
    client_dir, service_dir, secret_path = _write_runtime_material(tmp_path, material, shared_keys=shared_keys)
    return {
        "PRIVACY_FULL_DIRECTORY_INTERNAL_ENABLED": True,
        "CONFIDENTIAL_SERVICE_CLIENT_ID": CLIENT,
        "CONFIDENTIAL_SERVICE_PRINCIPAL": PRINCIPAL,
        "CONFIDENTIAL_SERVICE_ISSUER": ISSUER,
        "CONFIDENTIAL_SERVICE_TOKEN_ENDPOINT_AUDIENCE": TOKEN_AUDIENCE,
        "CONFIDENTIAL_SERVICE_RESOURCE_AUDIENCE": RESOURCE_AUDIENCE,
        "PRIVACY_FULL_DIRECTORY_VIEWER_OAUTH_CLIENT_ID": VIEWER_CLIENT,
        "CONFIDENTIAL_SERVICE_CLIENT_JWKS_DIR": str(client_dir),
        "CONFIDENTIAL_SERVICE_SIGNING_JWKS_DIR": str(service_dir),
        "PRIVACY_FULL_DIRECTORY_ALIAS_SECRET_FILE": str(secret_path),
    }


def test_runtime_is_disabled_by_default_and_partial_enablement_fails_closed(material, monkeypatch):
    monkeypatch.delenv("PRIVACY_FULL_DIRECTORY_INTERNAL_ENABLED", raising=False)
    assert get_config()["PRIVACY_FULL_DIRECTORY_INTERNAL_ENABLED"] is False
    assert build_internal_delivery_runtime({}) is None
    app = Flask(__name__)
    assert configure_internal_delivery(app, {}) is False
    assert INTERNAL_DELIVERY_EXTENSION not in app.extensions
    with pytest.raises(InternalDeliveryConfigurationError):
        build_internal_delivery_runtime({"PRIVACY_FULL_DIRECTORY_INTERNAL_ENABLED": True})


def test_complete_config_loads_existing_material_without_generating_secrets(tmp_path, material):
    config = _runtime_config(tmp_path, material)
    before = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    runtime = build_internal_delivery_runtime(
        config,
        session_factory=lambda: None,
        viewer_token_validator=lambda _token: _viewer_principal(),
    )
    after = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    assert type(runtime) is PrivacyFullDirectoryInternalDeliveryRuntime
    assert before == after


def test_unsafe_key_or_alias_secret_configuration_is_rejected(tmp_path, material):
    shared = _runtime_config(tmp_path / "shared", material, shared_keys=True)
    with pytest.raises(InternalDeliveryConfigurationError):
        build_internal_delivery_runtime(shared, session_factory=lambda: None)

    config = _runtime_config(tmp_path / "weak", material)
    secret_path = config["PRIVACY_FULL_DIRECTORY_ALIAS_SECRET_FILE"]
    os.chmod(secret_path, 0o644)
    with pytest.raises(InternalDeliveryConfigurationError):
        build_internal_delivery_runtime(config, session_factory=lambda: None)


def test_default_viewer_validator_uses_canonical_oauth_with_exact_social_client(tmp_path, material, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.services.oauth_bearer_validation.validate_canonical_access_token",
        lambda token, *, expected_client_id=None: calls.append((token, expected_client_id)) or _viewer_principal(),
    )
    runtime = build_internal_delivery_runtime(_runtime_config(tmp_path, material), session_factory=lambda: None)
    assert runtime.viewer_token_validator("viewer-bearer") == _viewer_principal()
    assert calls == [("viewer-bearer", VIEWER_CLIENT)]


def test_full_directory_runtime_rejects_non_directory_service_policy(material):
    base = _service_config(material)

    foreign_policies = (
        replace(
            base,
            service_scope="social:messaging-device:manage",
        ),
        replace(
            base,
            service_purpose="social_messaging_device_manage",
        ),
    )

    for service_config in foreign_policies:
        with pytest.raises(
            InternalDeliveryConfigurationError,
            match="^privacy Full-directory internal delivery configuration invalid$",
        ):
            _runtime(
                material,
                service_config=service_config,
            )

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask
from jwt.algorithms import RSAAlgorithm

from app.blueprints.internal_social_messaging_device_binding_authorization import (
    AUTHORIZATIONS_ROUTE,
    SERVICE_TOKEN_ROUTE,
)
from app.config import get_config
from app.factory import register_messaging_device_binding_authorization_blueprint
from app.services.social_messaging_device_binding_authorization_runtime import (
    MESSAGING_DEVICE_AUTHORIZATION_EXTENSION,
    MESSAGING_DEVICE_AUTHORIZATION_PURPOSE,
    MESSAGING_DEVICE_AUTHORIZATION_SCOPE,
    MessagingDeviceBindingAuthorizationConfigurationError,
    MessagingDeviceBindingAuthorizationRuntime,
    build_messaging_device_binding_authorization_runtime,
    configure_messaging_device_binding_authorization,
    configured_messaging_device_binding_authorization_runtime,
)

CLIENT = "social-binding-authorization"
PRINCIPAL = "service:social-binding-authorization"
ISSUER = "https://identity.example"
TOKEN_AUDIENCE = "https://identity.example/internal/device-binding-authorization-token"
RESOURCE_AUDIENCE = "https://identity.example/internal/device-binding-authorizations"
VIEWER_CLIENT = "social-browser"


def _public_jwk(key, kid):
    value = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    value.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return value


@pytest.fixture(scope="module")
def material():
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return client_key, service_key, _public_jwk(client_key, "client-key"), _public_jwk(service_key, "service-key")


def _config(tmp_path: Path, material):
    client_dir = tmp_path / "client"
    service_dir = tmp_path / "service"
    client_dir.mkdir()
    service_dir.mkdir()
    (client_dir / "jwks.json").write_text(json.dumps({"keys": [material[2]]}), encoding="utf-8")
    (service_dir / "jwks.json").write_text(json.dumps({"keys": [material[3]]}), encoding="utf-8")
    (service_dir / "private_key_service-key.pem").write_bytes(
        material[1].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return {
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_INTERNAL_ENABLED": True,
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_CLIENT_ID": CLIENT,
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_PRINCIPAL": PRINCIPAL,
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_ISSUER": ISSUER,
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_TOKEN_ENDPOINT_AUDIENCE": TOKEN_AUDIENCE,
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_RESOURCE_AUDIENCE": RESOURCE_AUDIENCE,
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID": VIEWER_CLIENT,
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_CLIENT_JWKS_DIR": str(client_dir),
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SIGNING_JWKS_DIR": str(service_dir),
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_CLOCK_SKEW_SECONDS": 5,
    }


def test_dedicated_gate_is_disabled_and_does_not_inherit_legacy_device_gate():
    assert build_messaging_device_binding_authorization_runtime({}) is None
    assert (
        build_messaging_device_binding_authorization_runtime({"SOCIAL_MESSAGING_DEVICE_INTERNAL_ENABLED": True}) is None
    )


def test_explicit_enable_with_incomplete_configuration_fails_closed():
    incomplete = {"SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_INTERNAL_ENABLED": True}
    with pytest.raises(
        MessagingDeviceBindingAuthorizationConfigurationError,
        match="^messaging device binding authorization configuration invalid$",
    ):
        build_messaging_device_binding_authorization_runtime(incomplete)

    app = Flask("incomplete")
    with pytest.raises(MessagingDeviceBindingAuthorizationConfigurationError):
        configure_messaging_device_binding_authorization(app, incomplete)
    assert MESSAGING_DEVICE_AUTHORIZATION_EXTENSION not in app.extensions


def test_complete_configuration_loads_only_existing_key_material(tmp_path, material):
    config = _config(tmp_path, material)
    before = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    runtime = build_messaging_device_binding_authorization_runtime(
        config,
        session_factory=lambda: None,
        viewer_token_validator=lambda _token: None,
    )
    after = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))

    assert type(runtime) is MessagingDeviceBindingAuthorizationRuntime
    assert runtime.service_config.service_scope == MESSAGING_DEVICE_AUTHORIZATION_SCOPE
    assert runtime.service_config.service_purpose == MESSAGING_DEVICE_AUTHORIZATION_PURPOSE
    assert runtime.viewer_oauth_client_id == VIEWER_CLIENT
    assert before == after


def test_configure_installs_once_and_disabled_preserves_route_absence(tmp_path, material):
    disabled = Flask("disabled")
    assert configure_messaging_device_binding_authorization(disabled, {}) is False
    assert MESSAGING_DEVICE_AUTHORIZATION_EXTENSION not in disabled.extensions
    assert configured_messaging_device_binding_authorization_runtime(disabled) is None

    enabled = Flask("enabled")
    config = _config(tmp_path, material)
    assert configure_messaging_device_binding_authorization(enabled, config) is True
    assert (
        type(configured_messaging_device_binding_authorization_runtime(enabled))
        is MessagingDeviceBindingAuthorizationRuntime
    )
    with pytest.raises(MessagingDeviceBindingAuthorizationConfigurationError):
        configure_messaging_device_binding_authorization(enabled, config)


def test_application_config_defaults_are_separate_and_disabled(monkeypatch):
    names = (
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_INTERNAL_ENABLED",
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_CLIENT_ID",
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_PRINCIPAL",
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_ISSUER",
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_TOKEN_ENDPOINT_AUDIENCE",
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_RESOURCE_AUDIENCE",
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID",
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_CLIENT_JWKS_DIR",
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SIGNING_JWKS_DIR",
        "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_CLOCK_SKEW_SECONDS",
    )
    for name in names:
        monkeypatch.delenv(name, raising=False)

    config = get_config()
    assert config["SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_INTERNAL_ENABLED"] is False
    assert config["SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_CLIENT_ID"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_PRINCIPAL"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_ISSUER"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_TOKEN_ENDPOINT_AUDIENCE"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_RESOURCE_AUDIENCE"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_CLIENT_JWKS_DIR"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SIGNING_JWKS_DIR"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_CLOCK_SKEW_SECONDS"] == 5


def test_factory_route_registration_is_absent_when_disabled_and_present_when_enabled():
    disabled = Flask("factory-disabled")
    assert register_messaging_device_binding_authorization_blueprint(disabled) is False
    assert AUTHORIZATIONS_ROUTE not in {rule.rule for rule in disabled.url_map.iter_rules()}
    assert SERVICE_TOKEN_ROUTE not in {rule.rule for rule in disabled.url_map.iter_rules()}

    enabled = Flask("factory-enabled")
    enabled.extensions[MESSAGING_DEVICE_AUTHORIZATION_EXTENSION] = object.__new__(
        MessagingDeviceBindingAuthorizationRuntime
    )
    assert register_messaging_device_binding_authorization_blueprint(enabled) is True
    rules = {rule.rule for rule in enabled.url_map.iter_rules()}
    assert AUTHORIZATIONS_ROUTE in rules
    assert SERVICE_TOKEN_ROUTE in rules

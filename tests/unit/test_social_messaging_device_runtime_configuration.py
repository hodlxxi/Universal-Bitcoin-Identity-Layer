from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask
from jwt.algorithms import RSAAlgorithm

from app.config import get_config
from app.services.social_messaging_device_internal_delivery import (
    MESSAGING_DEVICE_INTERNAL_EXTENSION,
    MESSAGING_DEVICE_PURPOSE,
    MESSAGING_DEVICE_SCOPE,
    MessagingDeviceInternalConfigurationError,
    MessagingDeviceInternalDeliveryRuntime,
    build_messaging_device_internal_runtime,
    configure_messaging_device_internal_delivery,
    configured_messaging_device_internal_runtime,
)

CLIENT = "social-messaging-backend"
PRINCIPAL = "service:social-messaging-device"
ISSUER = "https://identity.example"
TOKEN_AUDIENCE = "https://identity.example/internal/v1/social/messaging/service-token"
RESOURCE_AUDIENCE = "https://identity.example/internal/v1/social/messaging/device-bindings"
VIEWER_CLIENT = "social-browser-client"
TEST_BINDING_LIFETIME_SECONDS = 3600


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


def _write_material(tmp_path: Path, material, *, shared_keys=False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    client_dir = tmp_path / "client"
    service_dir = tmp_path / "service"
    client_dir.mkdir()
    service_dir.mkdir()

    client_jwk = material[3] if shared_keys else material[2]
    (client_dir / "jwks.json").write_text(
        json.dumps({"keys": [client_jwk]}),
        encoding="utf-8",
    )
    (service_dir / "jwks.json").write_text(
        json.dumps({"keys": [material[3]]}),
        encoding="utf-8",
    )
    (service_dir / "private_key_service-key.pem").write_bytes(
        material[1].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return client_dir, service_dir


def _config(tmp_path: Path, material, *, shared_keys=False):
    client_dir, service_dir = _write_material(
        tmp_path,
        material,
        shared_keys=shared_keys,
    )
    return {
        "SOCIAL_MESSAGING_DEVICE_INTERNAL_ENABLED": True,
        "SOCIAL_MESSAGING_DEVICE_SERVICE_CLIENT_ID": CLIENT,
        "SOCIAL_MESSAGING_DEVICE_SERVICE_PRINCIPAL": PRINCIPAL,
        "SOCIAL_MESSAGING_DEVICE_SERVICE_ISSUER": ISSUER,
        "SOCIAL_MESSAGING_DEVICE_SERVICE_TOKEN_ENDPOINT_AUDIENCE": TOKEN_AUDIENCE,
        "SOCIAL_MESSAGING_DEVICE_SERVICE_RESOURCE_AUDIENCE": RESOURCE_AUDIENCE,
        "SOCIAL_MESSAGING_DEVICE_VIEWER_OAUTH_CLIENT_ID": VIEWER_CLIENT,
        "SOCIAL_MESSAGING_DEVICE_CLIENT_JWKS_DIR": str(client_dir),
        "SOCIAL_MESSAGING_DEVICE_SIGNING_JWKS_DIR": str(service_dir),
        "SOCIAL_MESSAGING_DEVICE_CLOCK_SKEW_SECONDS": 5,
        "SOCIAL_MESSAGING_DEVICE_BINDING_LIFETIME_SECONDS": TEST_BINDING_LIFETIME_SECONDS,
    }


def test_builder_is_disabled_by_default_and_partial_enablement_fails_closed():
    assert build_messaging_device_internal_runtime({}) is None
    assert build_messaging_device_internal_runtime({"SOCIAL_MESSAGING_DEVICE_INTERNAL_ENABLED": False}) is None
    with pytest.raises(
        MessagingDeviceInternalConfigurationError,
        match="^messaging device internal delivery configuration invalid$",
    ):
        build_messaging_device_internal_runtime({"SOCIAL_MESSAGING_DEVICE_INTERNAL_ENABLED": True})


def test_complete_config_loads_existing_material_without_generating_files(
    tmp_path,
    material,
):
    config = _config(tmp_path, material)
    before = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))

    runtime = build_messaging_device_internal_runtime(
        config,
        session_factory=lambda: None,
        viewer_token_validator=lambda _token: None,
    )

    after = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    assert type(runtime) is MessagingDeviceInternalDeliveryRuntime
    assert runtime.service_config.service_scope == MESSAGING_DEVICE_SCOPE
    assert runtime.service_config.service_purpose == MESSAGING_DEVICE_PURPOSE
    assert runtime.service_config.client_id == CLIENT
    assert runtime.viewer_oauth_client_id == VIEWER_CLIENT
    assert before == after


def test_builder_rejects_shared_service_and_client_rsa_authority(tmp_path, material):
    config = _config(tmp_path, material, shared_keys=True)
    with pytest.raises(MessagingDeviceInternalConfigurationError):
        build_messaging_device_internal_runtime(
            config,
            session_factory=lambda: None,
            viewer_token_validator=lambda _token: None,
        )


def test_builder_rejects_client_private_key_material(tmp_path, material):
    config = _config(tmp_path, material)
    client_dir = Path(config["SOCIAL_MESSAGING_DEVICE_CLIENT_JWKS_DIR"])
    (client_dir / "private_key_forbidden.pem").write_text(
        "not-a-key",
        encoding="utf-8",
    )
    with pytest.raises(MessagingDeviceInternalConfigurationError):
        build_messaging_device_internal_runtime(
            config,
            session_factory=lambda: None,
            viewer_token_validator=lambda _token: None,
        )


def test_invalid_binding_lifetime_fails_closed(tmp_path, material):
    config = _config(tmp_path, material)
    config["SOCIAL_MESSAGING_DEVICE_BINDING_LIFETIME_SECONDS"] = 1
    with pytest.raises(MessagingDeviceInternalConfigurationError):
        build_messaging_device_internal_runtime(
            config,
            session_factory=lambda: None,
            viewer_token_validator=lambda _token: None,
        )


def test_missing_binding_lifetime_fails_closed(tmp_path, material):
    config = _config(tmp_path, material)
    config.pop("SOCIAL_MESSAGING_DEVICE_BINDING_LIFETIME_SECONDS")

    with pytest.raises(MessagingDeviceInternalConfigurationError):
        build_messaging_device_internal_runtime(
            config,
            session_factory=lambda: None,
            viewer_token_validator=lambda _token: None,
        )


def test_default_viewer_validator_binds_exact_social_oauth_client(
    tmp_path,
    material,
    monkeypatch,
):
    calls = []
    expected = object()
    monkeypatch.setattr(
        "app.services.oauth_bearer_validation.validate_canonical_access_token",
        lambda token, *, expected_client_id=None: calls.append((token, expected_client_id)) or expected,
    )
    runtime = build_messaging_device_internal_runtime(
        _config(tmp_path, material),
        session_factory=lambda: None,
    )

    assert runtime.viewer_token_validator("viewer-token") is expected
    assert calls == [("viewer-token", VIEWER_CLIENT)]


def test_configure_installs_exact_runtime_once_and_disabled_installs_nothing(
    tmp_path,
    material,
):
    disabled = Flask("disabled")
    assert configure_messaging_device_internal_delivery(disabled, {}) is False
    assert MESSAGING_DEVICE_INTERNAL_EXTENSION not in disabled.extensions
    assert configured_messaging_device_internal_runtime(disabled) is None

    app = Flask("enabled")
    config = _config(tmp_path, material)
    assert configure_messaging_device_internal_delivery(app, config) is True
    runtime = configured_messaging_device_internal_runtime(app)
    assert type(runtime) is MessagingDeviceInternalDeliveryRuntime
    assert app.extensions[MESSAGING_DEVICE_INTERNAL_EXTENSION] is runtime

    with pytest.raises(MessagingDeviceInternalConfigurationError):
        configure_messaging_device_internal_delivery(app, config)


def test_application_config_exposes_messaging_device_runtime_disabled_by_default(monkeypatch):
    names = (
        "SOCIAL_MESSAGING_DEVICE_INTERNAL_ENABLED",
        "SOCIAL_MESSAGING_DEVICE_SERVICE_CLIENT_ID",
        "SOCIAL_MESSAGING_DEVICE_SERVICE_PRINCIPAL",
        "SOCIAL_MESSAGING_DEVICE_SERVICE_ISSUER",
        "SOCIAL_MESSAGING_DEVICE_SERVICE_TOKEN_ENDPOINT_AUDIENCE",
        "SOCIAL_MESSAGING_DEVICE_SERVICE_RESOURCE_AUDIENCE",
        "SOCIAL_MESSAGING_DEVICE_VIEWER_OAUTH_CLIENT_ID",
        "SOCIAL_MESSAGING_DEVICE_CLIENT_JWKS_DIR",
        "SOCIAL_MESSAGING_DEVICE_SIGNING_JWKS_DIR",
        "SOCIAL_MESSAGING_DEVICE_CLOCK_SKEW_SECONDS",
        "SOCIAL_MESSAGING_DEVICE_BINDING_LIFETIME_SECONDS",
    )
    for name in names:
        monkeypatch.delenv(name, raising=False)

    config = get_config()

    assert config["SOCIAL_MESSAGING_DEVICE_INTERNAL_ENABLED"] is False
    assert config["SOCIAL_MESSAGING_DEVICE_SERVICE_CLIENT_ID"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_SERVICE_PRINCIPAL"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_SERVICE_ISSUER"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_SERVICE_TOKEN_ENDPOINT_AUDIENCE"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_SERVICE_RESOURCE_AUDIENCE"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_VIEWER_OAUTH_CLIENT_ID"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_CLIENT_JWKS_DIR"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_SIGNING_JWKS_DIR"] == ""
    assert config["SOCIAL_MESSAGING_DEVICE_CLOCK_SKEW_SECONDS"] == 5
    assert config["SOCIAL_MESSAGING_DEVICE_BINDING_LIFETIME_SECONDS"] is None


def test_factory_wires_messaging_runtime_only_through_conditional_runtime():
    source = Path("app/factory.py").read_text(encoding="utf-8")

    assert source.count("configure_messaging_device_internal_delivery(app, cfg)") == 1
    assert source.count("configured_messaging_device_internal_runtime(app) is not None") == 1
    assert source.count("app.register_blueprint(internal_social_messaging_device_bp)") == 1

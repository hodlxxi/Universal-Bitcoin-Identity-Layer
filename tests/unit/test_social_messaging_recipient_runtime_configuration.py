from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.services.privacy_full_directory_internal_delivery import (
    PrivacyFullDirectoryInternalDeliveryRuntime,
)
from app.services.social_messaging_recipient_internal_delivery import (
    MESSAGING_RECIPIENT_PURPOSE,
    MESSAGING_RECIPIENT_SCOPE,
    MessagingRecipientInternalConfigurationError,
    MessagingRecipientInternalDeliveryRuntime,
)
from app.services.social_messaging_recipient_runtime_configuration import (
    build_messaging_recipient_internal_runtime,
)

CLIENT = "social-recipient-backend"
PRINCIPAL = "service:social-messaging-recipient"
ISSUER = "https://identity.example"
TOKEN_AUDIENCE = "https://identity.example/internal/v1/social/messaging/recipient-service-token"
RESOURCE_AUDIENCE = "https://identity.example/internal/v1/social/messaging/recipient-devices"
VIEWER_CLIENT = "social-browser-client"
TEST_BINDING_LIFETIME_SECONDS = 3600
ALIAS_SECRET = b"a" * 32
ALIAS_VERSION = 7


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
        "SOCIAL_MESSAGING_RECIPIENT_INTERNAL_ENABLED": True,
        "SOCIAL_MESSAGING_RECIPIENT_SERVICE_CLIENT_ID": CLIENT,
        "SOCIAL_MESSAGING_RECIPIENT_SERVICE_PRINCIPAL": PRINCIPAL,
        "SOCIAL_MESSAGING_RECIPIENT_SERVICE_ISSUER": ISSUER,
        "SOCIAL_MESSAGING_RECIPIENT_SERVICE_TOKEN_ENDPOINT_AUDIENCE": (TOKEN_AUDIENCE),
        "SOCIAL_MESSAGING_RECIPIENT_SERVICE_RESOURCE_AUDIENCE": (RESOURCE_AUDIENCE),
        "SOCIAL_MESSAGING_RECIPIENT_CLIENT_JWKS_DIR": str(client_dir),
        "SOCIAL_MESSAGING_RECIPIENT_SIGNING_JWKS_DIR": str(service_dir),
        "SOCIAL_MESSAGING_RECIPIENT_CLOCK_SKEW_SECONDS": 5,
        "SOCIAL_MESSAGING_DEVICE_BINDING_LIFETIME_SECONDS": (TEST_BINDING_LIFETIME_SECONDS),
    }


def _privacy_runtime():
    def current_entitlement_resolver(_subject):
        return None

    def full_population_provider():
        return None

    def viewer_token_validator(_token):
        return None

    runtime = object.__new__(PrivacyFullDirectoryInternalDeliveryRuntime)
    object.__setattr__(runtime, "viewer_oauth_client_id", VIEWER_CLIENT)
    object.__setattr__(runtime, "viewer_token_validator", viewer_token_validator)
    object.__setattr__(
        runtime,
        "current_entitlement_resolver",
        current_entitlement_resolver,
    )
    object.__setattr__(
        runtime,
        "full_population_provider",
        full_population_provider,
    )
    object.__setattr__(runtime, "alias_secret", ALIAS_SECRET)
    object.__setattr__(runtime, "alias_version", ALIAS_VERSION)
    return runtime


def test_builder_is_disabled_by_default_before_privacy_dependency_access():
    assert (
        build_messaging_recipient_internal_runtime(
            {},
            privacy_directory_runtime=None,
        )
        is None
    )
    assert (
        build_messaging_recipient_internal_runtime(
            {"SOCIAL_MESSAGING_RECIPIENT_INTERNAL_ENABLED": False},
            privacy_directory_runtime=object(),
        )
        is None
    )


def test_enabled_builder_requires_exact_privacy_runtime():
    with pytest.raises(MessagingRecipientInternalConfigurationError):
        build_messaging_recipient_internal_runtime(
            {"SOCIAL_MESSAGING_RECIPIENT_INTERNAL_ENABLED": True},
            privacy_directory_runtime=object(),
        )


def test_complete_config_reuses_privacy_alias_and_authority_dependencies(
    tmp_path,
    material,
):
    privacy_runtime = _privacy_runtime()
    config = _config(tmp_path, material)
    before = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))

    runtime = build_messaging_recipient_internal_runtime(
        config,
        privacy_directory_runtime=privacy_runtime,
        session_factory=lambda: None,
    )

    after = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))

    assert type(runtime) is MessagingRecipientInternalDeliveryRuntime
    assert runtime.service_config.service_scope == MESSAGING_RECIPIENT_SCOPE
    assert runtime.service_config.service_purpose == MESSAGING_RECIPIENT_PURPOSE
    assert runtime.service_config.client_id == CLIENT
    assert runtime.viewer_oauth_client_id == VIEWER_CLIENT
    assert runtime.viewer_token_validator is privacy_runtime.viewer_token_validator
    assert runtime.current_entitlement_resolver is privacy_runtime.current_entitlement_resolver
    assert runtime.recipient_resolver._current_entitlement_resolver is privacy_runtime.current_entitlement_resolver
    assert runtime.recipient_resolver._full_population_provider is privacy_runtime.full_population_provider
    assert runtime.recipient_resolver._alias_secret is privacy_runtime.alias_secret
    assert runtime.recipient_resolver._alias_version == ALIAS_VERSION
    assert before == after


def test_builder_rejects_shared_service_and_client_rsa_authority(
    tmp_path,
    material,
):
    with pytest.raises(MessagingRecipientInternalConfigurationError):
        build_messaging_recipient_internal_runtime(
            _config(tmp_path, material, shared_keys=True),
            privacy_directory_runtime=_privacy_runtime(),
            session_factory=lambda: None,
        )


def test_builder_rejects_client_private_key_material(tmp_path, material):
    config = _config(tmp_path, material)
    client_dir = Path(config["SOCIAL_MESSAGING_RECIPIENT_CLIENT_JWKS_DIR"])
    (client_dir / "private_key_forbidden.pem").write_text(
        "not-a-key",
        encoding="utf-8",
    )

    with pytest.raises(MessagingRecipientInternalConfigurationError):
        build_messaging_recipient_internal_runtime(
            config,
            privacy_directory_runtime=_privacy_runtime(),
            session_factory=lambda: None,
        )


@pytest.mark.parametrize("lifetime", [None, 1, True])
def test_binding_lifetime_is_explicit_and_fail_closed(
    tmp_path,
    material,
    lifetime,
):
    config = _config(tmp_path, material)
    if lifetime is None:
        config.pop("SOCIAL_MESSAGING_DEVICE_BINDING_LIFETIME_SECONDS")
    else:
        config["SOCIAL_MESSAGING_DEVICE_BINDING_LIFETIME_SECONDS"] = lifetime

    with pytest.raises(MessagingRecipientInternalConfigurationError):
        build_messaging_recipient_internal_runtime(
            config,
            privacy_directory_runtime=_privacy_runtime(),
            session_factory=lambda: None,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("alias_secret", b"short"),
        ("alias_version", 0),
        ("viewer_oauth_client_id", ""),
        ("viewer_token_validator", None),
        ("current_entitlement_resolver", None),
        ("full_population_provider", None),
    ],
)
def test_tampered_privacy_runtime_is_rejected_before_service_material(
    field,
    value,
):
    runtime = _privacy_runtime()
    object.__setattr__(runtime, field, value)

    with pytest.raises(MessagingRecipientInternalConfigurationError):
        build_messaging_recipient_internal_runtime(
            {"SOCIAL_MESSAGING_RECIPIENT_INTERNAL_ENABLED": True},
            privacy_directory_runtime=runtime,
        )


def test_partial_service_configuration_fails_closed(tmp_path, material):
    config = _config(tmp_path, material)
    config["SOCIAL_MESSAGING_RECIPIENT_SERVICE_CLIENT_ID"] = ""

    with pytest.raises(
        MessagingRecipientInternalConfigurationError,
        match="^messaging recipient internal delivery configuration invalid$",
    ):
        build_messaging_recipient_internal_runtime(
            config,
            privacy_directory_runtime=_privacy_runtime(),
            session_factory=lambda: None,
        )

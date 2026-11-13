from pathlib import Path

import pytest
from flask import Flask

import app.services.social_messaging_recipient_runtime_configuration as configuration
from app.config import get_config
from app.services.social_messaging_recipient_internal_delivery import (
    MESSAGING_RECIPIENT_INTERNAL_EXTENSION,
    MessagingRecipientInternalConfigurationError,
    MessagingRecipientInternalDeliveryRuntime,
)


def _runtime_instance():
    return object.__new__(MessagingRecipientInternalDeliveryRuntime)


def test_configure_installs_exact_runtime_once_and_disabled_installs_nothing(
    monkeypatch,
):
    disabled = Flask("disabled")
    monkeypatch.setattr(
        configuration,
        "build_messaging_recipient_internal_runtime",
        lambda config, *, privacy_directory_runtime, session_factory=None: None,
    )
    assert (
        configuration.configure_messaging_recipient_internal_delivery(
            disabled,
            {},
            privacy_directory_runtime=object(),
        )
        is False
    )
    assert MESSAGING_RECIPIENT_INTERNAL_EXTENSION not in disabled.extensions
    assert configuration.configured_messaging_recipient_internal_runtime(disabled) is None

    enabled = Flask("enabled")
    runtime = _runtime_instance()
    monkeypatch.setattr(
        configuration,
        "build_messaging_recipient_internal_runtime",
        lambda config, *, privacy_directory_runtime, session_factory=None: runtime,
    )
    assert (
        configuration.configure_messaging_recipient_internal_delivery(
            enabled,
            {"SOCIAL_MESSAGING_RECIPIENT_INTERNAL_ENABLED": True},
            privacy_directory_runtime=object(),
        )
        is True
    )
    assert enabled.extensions[MESSAGING_RECIPIENT_INTERNAL_EXTENSION] is runtime
    assert configuration.configured_messaging_recipient_internal_runtime(enabled) is runtime

    with pytest.raises(MessagingRecipientInternalConfigurationError):
        configuration.configure_messaging_recipient_internal_delivery(
            enabled,
            {"SOCIAL_MESSAGING_RECIPIENT_INTERNAL_ENABLED": True},
            privacy_directory_runtime=object(),
        )


def test_configured_runtime_rejects_wrong_extension_type():
    app = Flask("wrong")
    app.extensions[MESSAGING_RECIPIENT_INTERNAL_EXTENSION] = object()

    assert configuration.configured_messaging_recipient_internal_runtime(app) is None


def test_application_config_exposes_recipient_runtime_disabled_by_default(
    monkeypatch,
):
    names = (
        "SOCIAL_MESSAGING_RECIPIENT_INTERNAL_ENABLED",
        "SOCIAL_MESSAGING_RECIPIENT_SERVICE_CLIENT_ID",
        "SOCIAL_MESSAGING_RECIPIENT_SERVICE_PRINCIPAL",
        "SOCIAL_MESSAGING_RECIPIENT_SERVICE_ISSUER",
        "SOCIAL_MESSAGING_RECIPIENT_SERVICE_TOKEN_ENDPOINT_AUDIENCE",
        "SOCIAL_MESSAGING_RECIPIENT_SERVICE_RESOURCE_AUDIENCE",
        "SOCIAL_MESSAGING_RECIPIENT_CLIENT_JWKS_DIR",
        "SOCIAL_MESSAGING_RECIPIENT_SIGNING_JWKS_DIR",
        "SOCIAL_MESSAGING_RECIPIENT_CLOCK_SKEW_SECONDS",
    )
    for name in names:
        monkeypatch.delenv(name, raising=False)

    config = get_config()

    assert config["SOCIAL_MESSAGING_RECIPIENT_INTERNAL_ENABLED"] is False
    assert config["SOCIAL_MESSAGING_RECIPIENT_SERVICE_CLIENT_ID"] == ""
    assert config["SOCIAL_MESSAGING_RECIPIENT_SERVICE_PRINCIPAL"] == ""
    assert config["SOCIAL_MESSAGING_RECIPIENT_SERVICE_ISSUER"] == ""
    assert config["SOCIAL_MESSAGING_RECIPIENT_SERVICE_TOKEN_ENDPOINT_AUDIENCE"] == ""
    assert config["SOCIAL_MESSAGING_RECIPIENT_SERVICE_RESOURCE_AUDIENCE"] == ""
    assert config["SOCIAL_MESSAGING_RECIPIENT_CLIENT_JWKS_DIR"] == ""
    assert config["SOCIAL_MESSAGING_RECIPIENT_SIGNING_JWKS_DIR"] == ""
    assert config["SOCIAL_MESSAGING_RECIPIENT_CLOCK_SKEW_SECONDS"] == 5


def test_factory_wires_recipient_runtime_after_privacy_and_registers_conditionally():
    source = Path("app/factory.py").read_text(encoding="utf-8")

    privacy_configure = source.index("configure_internal_delivery(app, cfg)")
    recipient_configure = source.index("configure_messaging_recipient_internal_delivery(")

    assert privacy_configure < recipient_configure
    assert source.count("configure_messaging_recipient_internal_delivery(") == 1
    assert source.count("configured_messaging_recipient_internal_runtime(app) is not None") == 1
    assert source.count("app.register_blueprint(internal_social_messaging_recipient_bp)") == 1

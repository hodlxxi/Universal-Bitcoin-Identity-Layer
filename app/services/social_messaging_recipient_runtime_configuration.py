"""Configuration builder for private Social recipient-device delivery.

This slice creates the recipient read runtime only from explicit service
configuration and an already-validated privacy Full-directory runtime. Reusing
that runtime is the alias-boundary guarantee: recipient resolution receives the
same viewer OAuth validator, canonical Full population provider, alias secret,
and alias version as the privacy-safe Full directory.
"""

from __future__ import annotations

import glob
import os
import stat
from typing import Mapping

from app.services.confidential_service_assertion_replay_storage import (
    PostgresConfidentialServiceAssertionReplayStore,
)
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    validate_confidential_service_config,
)
from app.services.privacy_full_directory_internal_delivery import (
    PrivacyFullDirectoryInternalDeliveryRuntime,
)
from app.services.privacy_safe_full_directory import (
    MAX_ALIAS_SECRET_BYTES,
    MAX_ALIAS_VERSION,
    MIN_ALIAS_SECRET_BYTES,
)
from app.services.recipient_device_resolver import RecipientDeviceResolverV1
from app.services.social_messaging_device_storage import (
    MAX_BINDING_LIFETIME_SECONDS,
    MIN_BINDING_LIFETIME_SECONDS,
    SqlAlchemySocialMessagingDeviceRepository,
)
from app.services.social_messaging_recipient_internal_delivery import (
    MESSAGING_RECIPIENT_INTERNAL_EXTENSION,
    MESSAGING_RECIPIENT_PURPOSE,
    MESSAGING_RECIPIENT_SCOPE,
    MessagingRecipientInternalConfigurationError,
    MessagingRecipientInternalDeliveryRuntime,
)


def _required_string(config: Mapping[str, object], name: str) -> str:
    value = config.get(name)
    if type(value) is not str or not value or value.strip() != value:
        raise MessagingRecipientInternalConfigurationError()
    return value


def _absolute_directory(config: Mapping[str, object], name: str) -> str:
    value = _required_string(config, name)
    try:
        info = os.lstat(value)
        if not os.path.isabs(value) or not stat.S_ISDIR(info.st_mode) or os.path.islink(value):
            raise ValueError
    except Exception:
        raise MessagingRecipientInternalConfigurationError() from None
    return value


def _required_binding_lifetime_seconds(config: Mapping[str, object]) -> int:
    value = config.get("SOCIAL_MESSAGING_DEVICE_BINDING_LIFETIME_SECONDS")
    if type(value) is not int or not MIN_BINDING_LIFETIME_SECONDS <= value <= MAX_BINDING_LIFETIME_SECONDS:
        raise MessagingRecipientInternalConfigurationError()
    return value


def _require_privacy_runtime(
    runtime: object,
) -> PrivacyFullDirectoryInternalDeliveryRuntime:
    if type(runtime) is not PrivacyFullDirectoryInternalDeliveryRuntime:
        raise MessagingRecipientInternalConfigurationError()

    try:
        if (
            type(runtime.viewer_oauth_client_id) is not str
            or not runtime.viewer_oauth_client_id
            or runtime.viewer_oauth_client_id.strip() != runtime.viewer_oauth_client_id
            or not callable(runtime.viewer_token_validator)
            or not callable(runtime.current_entitlement_resolver)
            or not callable(runtime.full_population_provider)
            or type(runtime.alias_secret) is not bytes
            or not MIN_ALIAS_SECRET_BYTES <= len(runtime.alias_secret) <= MAX_ALIAS_SECRET_BYTES
            or type(runtime.alias_version) is not int
            or not 1 <= runtime.alias_version <= MAX_ALIAS_VERSION
        ):
            raise ValueError
    except Exception:
        raise MessagingRecipientInternalConfigurationError() from None

    return runtime


def build_messaging_recipient_internal_runtime(
    config: Mapping[str, object],
    *,
    privacy_directory_runtime: object,
    session_factory=None,
) -> MessagingRecipientInternalDeliveryRuntime | None:
    """Build the read-only recipient runtime from complete explicit config."""

    if config.get("SOCIAL_MESSAGING_RECIPIENT_INTERNAL_ENABLED") is not True:
        return None

    privacy_runtime = _require_privacy_runtime(privacy_directory_runtime)
    binding_lifetime_seconds = _required_binding_lifetime_seconds(config)

    try:
        client_jwks_dir = _absolute_directory(
            config,
            "SOCIAL_MESSAGING_RECIPIENT_CLIENT_JWKS_DIR",
        )
        service_jwks_dir = _absolute_directory(
            config,
            "SOCIAL_MESSAGING_RECIPIENT_SIGNING_JWKS_DIR",
        )
        if glob.glob(os.path.join(client_jwks_dir, "private_key*.pem")):
            raise ValueError

        from app.jwks import load_jwks_document, load_signing_material

        client_document = load_jwks_document(client_jwks_dir)
        service_document, signing_kid, signing_key = load_signing_material(service_jwks_dir)
        service_config = ConfidentialServiceConfig(
            enabled=True,
            client_id=_required_string(
                config,
                "SOCIAL_MESSAGING_RECIPIENT_SERVICE_CLIENT_ID",
            ),
            service_principal=_required_string(
                config,
                "SOCIAL_MESSAGING_RECIPIENT_SERVICE_PRINCIPAL",
            ),
            issuer=_required_string(
                config,
                "SOCIAL_MESSAGING_RECIPIENT_SERVICE_ISSUER",
            ),
            token_endpoint_audience=_required_string(
                config,
                "SOCIAL_MESSAGING_RECIPIENT_SERVICE_TOKEN_ENDPOINT_AUDIENCE",
            ),
            service_resource_audience=_required_string(
                config,
                "SOCIAL_MESSAGING_RECIPIENT_SERVICE_RESOURCE_AUDIENCE",
            ),
            client_jwks=tuple(client_document["keys"]),
            service_jwks=tuple(service_document["keys"]),
            service_scope=MESSAGING_RECIPIENT_SCOPE,
            service_purpose=MESSAGING_RECIPIENT_PURPOSE,
            clock_skew_seconds=config.get(
                "SOCIAL_MESSAGING_RECIPIENT_CLOCK_SKEW_SECONDS",
                5,
            ),
        )
        validate_confidential_service_config(service_config)

        if session_factory is None:
            from app.database import get_session

            session_factory = get_session

        replay_consumer = PostgresConfidentialServiceAssertionReplayStore(session_factory)
        device_repository = SqlAlchemySocialMessagingDeviceRepository(
            session_factory,
            binding_lifetime_seconds=binding_lifetime_seconds,
        )
        recipient_resolver = RecipientDeviceResolverV1(
            current_entitlement_resolver=privacy_runtime.current_entitlement_resolver,
            full_population_provider=privacy_runtime.full_population_provider,
            device_repository=device_repository,
            alias_secret=privacy_runtime.alias_secret,
            alias_version=privacy_runtime.alias_version,
        )

        return MessagingRecipientInternalDeliveryRuntime(
            service_config=service_config,
            replay_consumer=replay_consumer,
            service_signing_key=signing_key,
            service_signing_kid=signing_kid,
            viewer_oauth_client_id=privacy_runtime.viewer_oauth_client_id,
            viewer_token_validator=privacy_runtime.viewer_token_validator,
            current_entitlement_resolver=privacy_runtime.current_entitlement_resolver,
            recipient_resolver=recipient_resolver,
        )
    except MessagingRecipientInternalConfigurationError:
        raise
    except Exception:
        raise MessagingRecipientInternalConfigurationError() from None


def configure_messaging_recipient_internal_delivery(
    app,
    config: Mapping[str, object],
    *,
    privacy_directory_runtime: object,
) -> bool:
    """Install the exact recipient runtime only when explicitly enabled."""

    runtime = build_messaging_recipient_internal_runtime(
        config,
        privacy_directory_runtime=privacy_directory_runtime,
    )
    if runtime is None:
        return False
    if MESSAGING_RECIPIENT_INTERNAL_EXTENSION in app.extensions:
        raise MessagingRecipientInternalConfigurationError()
    app.extensions[MESSAGING_RECIPIENT_INTERNAL_EXTENSION] = runtime
    return True


def configured_messaging_recipient_internal_runtime(
    app,
) -> MessagingRecipientInternalDeliveryRuntime | None:
    runtime = app.extensions.get(MESSAGING_RECIPIENT_INTERNAL_EXTENSION)
    return runtime if type(runtime) is MessagingRecipientInternalDeliveryRuntime else None


__all__ = [
    "build_messaging_recipient_internal_runtime",
    "configure_messaging_recipient_internal_delivery",
    "configured_messaging_recipient_internal_runtime",
]

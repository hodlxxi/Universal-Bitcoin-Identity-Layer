"""Disabled-by-default private Social messaging device-key delivery boundary."""

from __future__ import annotations

import glob
import os
import stat
from dataclasses import dataclass
from typing import Mapping

from app.services.action_authorization import IdentityClass
from app.services.confidential_service_assertion_replay_storage import (
    PostgresConfidentialServiceAssertionReplayStore,
)
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    CredentialDenied,
    VerifiedServiceCredential,
    issue_service_access_token,
    validate_confidential_service_config,
    verify_service_access_token,
)
from app.services.current_entitlement import (
    EntitlementDecision,
    EntitlementDenied,
    EntitlementUnavailable,
)
from app.services.oauth_bearer_validation import BearerPrincipal
from app.services.social_messaging_device_binding_registry import (
    SocialMessagingDeviceBindingRegistry,
)
from app.services.social_messaging_device_binding_registry_storage import (
    SqlAlchemySocialMessagingDeviceBindingRepository,
)


INTERNAL_MESSAGING_EXTENSION = (
    "social_messaging_internal_delivery_v1"
)

VIEWER_REQUIRED_SCOPE = "openid"

MESSAGING_SERVICE_SCOPE = (
    "social:messaging-device:manage"
)

MESSAGING_SERVICE_PURPOSE = (
    "social_messaging_device_manage"
)

RESULT_SCHEMA = (
    "hodlxxi.social_messaging_device_binding_result.v1"
)


class SocialMessagingConfigurationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__(
            "Social messaging internal delivery configuration invalid"
        )


class MessagingViewerCredentialDenied(ValueError):
    pass


class MessagingEntitlementDenied(ValueError):
    pass


class MessagingEntitlementUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class SocialMessagingInternalDeliveryRuntime:
    service_config: ConfidentialServiceConfig
    replay_consumer: object
    service_signing_key: object
    service_signing_kid: str

    viewer_oauth_client_id: str
    viewer_token_validator: object
    current_entitlement_resolver: object

    device_registry: SocialMessagingDeviceBindingRegistry

    def __post_init__(self) -> None:
        try:
            validate_confidential_service_config(
                self.service_config
            )

            if (
                self.service_config.service_scope
                != MESSAGING_SERVICE_SCOPE
                or self.service_config.service_purpose
                != MESSAGING_SERVICE_PURPOSE
                or not callable(self.replay_consumer)
                or not isinstance(
                    self.service_signing_kid,
                    str,
                )
                or not self.service_signing_kid
                or self.service_signing_kid.strip()
                != self.service_signing_kid
                or not isinstance(
                    self.viewer_oauth_client_id,
                    str,
                )
                or not self.viewer_oauth_client_id
                or self.viewer_oauth_client_id.strip()
                != self.viewer_oauth_client_id
                or not callable(
                    self.viewer_token_validator
                )
                or not callable(
                    self.current_entitlement_resolver
                )
                or type(self.device_registry)
                is not SocialMessagingDeviceBindingRegistry
            ):
                raise ValueError

        except Exception:
            raise SocialMessagingConfigurationError() from None

    def issue_service_token(
        self,
        client_assertion: str,
    ) -> str:
        return issue_service_access_token(
            client_assertion,
            config=self.service_config,
            replay_consumer=self.replay_consumer,
            signing_key=self.service_signing_key,
            signing_kid=self.service_signing_kid,
        )

    def verify_service_authority(
        self,
        service_token: str,
    ) -> VerifiedServiceCredential:
        service = verify_service_access_token(
            service_token,
            config=self.service_config,
        )

        if (
            type(service)
            is not VerifiedServiceCredential
            or service.service_principal
            != self.service_config.service_principal
            or service.client_id
            != self.service_config.client_id
            or service.scope
            != self.service_config.service_scope
        ):
            raise CredentialDenied(
                "credential denied"
            )

        return service

    def _require_service(
        self,
        service: VerifiedServiceCredential,
    ) -> None:
        if (
            type(service)
            is not VerifiedServiceCredential
            or service.service_principal
            != self.service_config.service_principal
            or service.client_id
            != self.service_config.client_id
            or service.scope
            != MESSAGING_SERVICE_SCOPE
        ):
            raise CredentialDenied(
                "credential denied"
            )

    def _viewer(
        self,
        viewer_token: str,
    ) -> BearerPrincipal:
        try:
            viewer = self.viewer_token_validator(
                viewer_token
            )

            if (
                type(viewer)
                is not BearerPrincipal
                or viewer.client_id
                != self.viewer_oauth_client_id
                or VIEWER_REQUIRED_SCOPE
                not in viewer.scopes
            ):
                raise ValueError

            return viewer

        except Exception:
            raise MessagingViewerCredentialDenied() from None

    def _require_full(
        self,
        viewer: BearerPrincipal,
    ) -> str:
        try:
            decision = (
                self.current_entitlement_resolver(
                    viewer.subject
                )
            )

        except EntitlementDenied:
            raise MessagingEntitlementDenied() from None

        except EntitlementUnavailable:
            raise MessagingEntitlementUnavailable() from None

        except Exception:
            raise MessagingEntitlementUnavailable() from None

        if (
            type(decision)
            is not EntitlementDecision
            or decision.subject
            != viewer.subject
        ):
            raise MessagingEntitlementUnavailable()

        if (
            decision.identity_class
            is not IdentityClass.FULL
            or decision.current_full_relation_satisfied
            is not True
        ):
            raise MessagingEntitlementDenied()

        return viewer.subject

    def apply_device_statement_for_service(
        self,
        service: VerifiedServiceCredential,
        viewer_token: str,
        payload: str,
    ) -> dict[str, object]:
        self._require_service(service)

        viewer = self._viewer(viewer_token)
        subject = self._require_full(viewer)

        result = self.device_registry.apply(
            payload,
            authenticated_subject=subject,
        )

        # Deliberately do not return canonical subject,
        # identity signature, statement nonce or Full evidence.
        return {
            "schema": RESULT_SCHEMA,
            "version": 1,
            "operation": result["operation"],
            "device": {
                "deviceId": result["deviceId"],
                "bindingId": result["digest"],
                "algorithm": result["algorithm"],
                "version": result[
                    "bindingVersion"
                ],
                "publicKey": result["publicKey"],
                "validFrom": result["validFrom"],
                "expiresAt": result["expiresAt"],
            },
        }

    def current_devices_for_service(
        self,
        service: VerifiedServiceCredential,
        viewer_token: str,
    ) -> dict[str, object]:
        self._require_service(service)

        viewer = self._viewer(viewer_token)
        subject = self._require_full(viewer)

        # Registry snapshot intentionally omits subject.
        return self.device_registry.current_for_subject(
            subject
        )


def _required_string(
    config: Mapping[str, object],
    name: str,
) -> str:
    value = config.get(name)

    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
    ):
        raise SocialMessagingConfigurationError()

    return value


def _absolute_directory(
    config: Mapping[str, object],
    name: str,
) -> str:
    value = _required_string(
        config,
        name,
    )

    try:
        info = os.lstat(value)

        if (
            not os.path.isabs(value)
            or not stat.S_ISDIR(info.st_mode)
            or os.path.islink(value)
        ):
            raise ValueError

    except Exception:
        raise SocialMessagingConfigurationError() from None

    return value


def build_social_messaging_internal_delivery_runtime(
    config: Mapping[str, object],
    *,
    session_factory=None,
    viewer_token_validator=None,
) -> SocialMessagingInternalDeliveryRuntime | None:
    if (
        config.get(
            "SOCIAL_MESSAGING_INTERNAL_ENABLED"
        )
        is not True
    ):
        return None

    try:
        client_jwks_dir = _absolute_directory(
            config,
            "SOCIAL_MESSAGING_SERVICE_CLIENT_JWKS_DIR",
        )

        service_jwks_dir = _absolute_directory(
            config,
            "SOCIAL_MESSAGING_SERVICE_SIGNING_JWKS_DIR",
        )

        # The Social client directory is verification-only.
        if glob.glob(
            os.path.join(
                client_jwks_dir,
                "private_key*.pem",
            )
        ):
            raise ValueError

        from app.jwks import (
            load_jwks_document,
            load_signing_material,
        )

        client_document = load_jwks_document(
            client_jwks_dir
        )

        (
            service_document,
            signing_kid,
            signing_key,
        ) = load_signing_material(
            service_jwks_dir
        )

        service_config = ConfidentialServiceConfig(
            enabled=True,
            client_id=_required_string(
                config,
                "SOCIAL_MESSAGING_SERVICE_CLIENT_ID",
            ),
            service_principal=_required_string(
                config,
                "SOCIAL_MESSAGING_SERVICE_PRINCIPAL",
            ),
            issuer=_required_string(
                config,
                "SOCIAL_MESSAGING_SERVICE_ISSUER",
            ),
            token_endpoint_audience=_required_string(
                config,
                "SOCIAL_MESSAGING_SERVICE_TOKEN_ENDPOINT_AUDIENCE",
            ),
            service_resource_audience=_required_string(
                config,
                "SOCIAL_MESSAGING_SERVICE_RESOURCE_AUDIENCE",
            ),
            client_jwks=tuple(
                client_document["keys"]
            ),
            service_jwks=tuple(
                service_document["keys"]
            ),
            clock_skew_seconds=config.get(
                "SOCIAL_MESSAGING_SERVICE_CLOCK_SKEW_SECONDS",
                5,
            ),
            service_scope=MESSAGING_SERVICE_SCOPE,
            service_purpose=MESSAGING_SERVICE_PURPOSE,
        )

        validate_confidential_service_config(
            service_config
        )

        viewer_oauth_client_id = _required_string(
            config,
            "SOCIAL_MESSAGING_VIEWER_OAUTH_CLIENT_ID",
        )

        if session_factory is None:
            from app.database import get_session

            session_factory = get_session

        replay_consumer = (
            PostgresConfidentialServiceAssertionReplayStore(
                session_factory
            )
        )

        device_repository = (
            SqlAlchemySocialMessagingDeviceBindingRepository(
                session_factory
            )
        )

        device_registry = (
            SocialMessagingDeviceBindingRegistry(
                device_repository
            )
        )

        from app.services.current_entitlement import (
            resolve_runtime_current_entitlement,
        )

        from app.services.current_entitlement_evidence_storage import (
            SqlAlchemyCurrentEntitlementEvidenceRepository,
        )

        entitlement_repository = (
            SqlAlchemyCurrentEntitlementEvidenceRepository(
                session_factory
            )
        )

        def current_entitlement_resolver(
            subject,
        ):
            return resolve_runtime_current_entitlement(
                subject,
                repository=entitlement_repository,
            )

        if viewer_token_validator is None:
            from app.services.oauth_bearer_validation import (
                validate_canonical_access_token,
            )

            def viewer_token_validator(token):
                return validate_canonical_access_token(
                    token,
                    expected_client_id=(
                        viewer_oauth_client_id
                    ),
                )

        return SocialMessagingInternalDeliveryRuntime(
            service_config=service_config,
            replay_consumer=replay_consumer,
            service_signing_key=signing_key,
            service_signing_kid=signing_kid,
            viewer_oauth_client_id=(
                viewer_oauth_client_id
            ),
            viewer_token_validator=(
                viewer_token_validator
            ),
            current_entitlement_resolver=(
                current_entitlement_resolver
            ),
            device_registry=device_registry,
        )

    except SocialMessagingConfigurationError:
        raise

    except Exception:
        raise SocialMessagingConfigurationError() from None


def configure_social_messaging_internal_delivery(
    app,
    config: Mapping[str, object],
) -> bool:
    runtime = (
        build_social_messaging_internal_delivery_runtime(
            config
        )
    )

    if runtime is None:
        return False

    if INTERNAL_MESSAGING_EXTENSION in app.extensions:
        raise SocialMessagingConfigurationError()

    app.extensions[
        INTERNAL_MESSAGING_EXTENSION
    ] = runtime

    return True


def configured_social_messaging_internal_delivery_runtime(
    app,
) -> SocialMessagingInternalDeliveryRuntime | None:
    runtime = app.extensions.get(
        INTERNAL_MESSAGING_EXTENSION
    )

    return (
        runtime
        if type(runtime)
        is SocialMessagingInternalDeliveryRuntime
        else None
    )


__all__ = [
    "INTERNAL_MESSAGING_EXTENSION",
    "MESSAGING_SERVICE_PURPOSE",
    "MESSAGING_SERVICE_SCOPE",
    "MessagingEntitlementDenied",
    "MessagingEntitlementUnavailable",
    "MessagingViewerCredentialDenied",
    "SocialMessagingConfigurationError",
    "SocialMessagingInternalDeliveryRuntime",
    "build_social_messaging_internal_delivery_runtime",
    "configure_social_messaging_internal_delivery",
    "configured_social_messaging_internal_delivery_runtime",
]

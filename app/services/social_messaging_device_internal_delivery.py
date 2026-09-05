"""Private runtime boundary for Social messaging-device authority.

This layer joins an exact confidential service policy, an independently
validated human OAuth bearer, current canonical Full entitlement, and the
multi-device X25519 authority. It deliberately does not register HTTP routes
or enable any production configuration.
"""

from __future__ import annotations

import glob
import os
import stat
from dataclasses import dataclass
from typing import Callable, Mapping

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
)
from app.services.oauth_bearer_validation import BearerPrincipal
from app.services.social_messaging_device_contract import (
    MessagingDeviceAuthorityUnavailable,
)

MESSAGING_DEVICE_SCOPE = "social:messaging-device:manage"
MESSAGING_DEVICE_PURPOSE = "social_messaging_device_manage"
MESSAGING_DEVICE_INTERNAL_EXTENSION = "social_messaging_device_internal_delivery_v1"
VIEWER_REQUIRED_SCOPE = "openid"


class MessagingDeviceInternalConfigurationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("messaging device internal delivery configuration invalid")


class MessagingViewerCredentialDenied(ValueError):
    def __init__(self) -> None:
        super().__init__("messaging viewer credential denied")


class MessagingViewerEntitlementDenied(ValueError):
    def __init__(self) -> None:
        super().__init__("messaging viewer entitlement denied")


class MessagingViewerEntitlementUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__("messaging viewer entitlement unavailable")


@dataclass(frozen=True)
class MessagingDeviceInternalDeliveryRuntime:
    """Authorize Social's own-device messaging key operations."""

    service_config: ConfidentialServiceConfig
    replay_consumer: Callable[[str, int], bool]
    service_signing_key: object
    service_signing_kid: str
    viewer_oauth_client_id: str
    viewer_token_validator: Callable[[str], BearerPrincipal]
    current_entitlement_resolver: Callable[[str], EntitlementDecision]
    device_authority: object

    def __post_init__(self) -> None:
        try:
            validate_confidential_service_config(self.service_config)
            if (
                self.service_config.service_scope != MESSAGING_DEVICE_SCOPE
                or self.service_config.service_purpose != MESSAGING_DEVICE_PURPOSE
                or not callable(self.replay_consumer)
                or type(self.service_signing_kid) is not str
                or not self.service_signing_kid
                or self.service_signing_kid.strip() != self.service_signing_kid
                or type(self.viewer_oauth_client_id) is not str
                or not self.viewer_oauth_client_id
                or self.viewer_oauth_client_id.strip() != self.viewer_oauth_client_id
                or not callable(self.viewer_token_validator)
                or not callable(self.current_entitlement_resolver)
                or not callable(getattr(self.device_authority, "current", None))
                or not callable(getattr(self.device_authority, "apply", None))
            ):
                raise ValueError
        except Exception:
            raise MessagingDeviceInternalConfigurationError() from None

    def issue_service_token(self, client_assertion: str) -> str:
        return issue_service_access_token(
            client_assertion,
            config=self.service_config,
            replay_consumer=self.replay_consumer,
            signing_key=self.service_signing_key,
            signing_kid=self.service_signing_kid,
        )

    def verify_service_authority(self, service_token: str) -> VerifiedServiceCredential:
        service = verify_service_access_token(
            service_token,
            config=self.service_config,
        )
        if (
            type(service) is not VerifiedServiceCredential
            or service.service_principal != self.service_config.service_principal
            or service.client_id != self.service_config.client_id
            or service.scope != MESSAGING_DEVICE_SCOPE
            or service.purpose != MESSAGING_DEVICE_PURPOSE
        ):
            raise CredentialDenied("credential denied")
        return service

    def _require_viewer_full(self, viewer_token: str) -> BearerPrincipal:
        try:
            viewer = self.viewer_token_validator(viewer_token)
            if (
                type(viewer) is not BearerPrincipal
                or viewer.client_id != self.viewer_oauth_client_id
                or VIEWER_REQUIRED_SCOPE not in viewer.scopes
            ):
                raise ValueError
        except Exception:
            raise MessagingViewerCredentialDenied() from None

        try:
            decision = self.current_entitlement_resolver(viewer.subject)
        except EntitlementDenied:
            raise MessagingViewerEntitlementDenied() from None
        except Exception:
            raise MessagingViewerEntitlementUnavailable() from None

        if type(decision) is not EntitlementDecision or decision.subject != viewer.subject:
            raise MessagingViewerEntitlementUnavailable()
        if decision.identity_class is not IdentityClass.FULL or decision.current_full_relation_satisfied is not True:
            raise MessagingViewerEntitlementDenied()
        return viewer

    @staticmethod
    def _require_service(
        service: VerifiedServiceCredential,
        config: ConfidentialServiceConfig,
    ) -> None:
        if (
            type(service) is not VerifiedServiceCredential
            or service.service_principal != config.service_principal
            or service.client_id != config.client_id
            or service.scope != MESSAGING_DEVICE_SCOPE
            or service.purpose != MESSAGING_DEVICE_PURPOSE
        ):
            raise CredentialDenied("credential denied")

    def current_for_service(
        self,
        service: VerifiedServiceCredential,
        viewer_token: str,
    ) -> dict[str, object]:
        self._require_service(service, self.service_config)
        viewer = self._require_viewer_full(viewer_token)
        result = self.device_authority.current(
            authenticated_subject=viewer.subject,
        )
        if type(result) is not dict:
            raise MessagingDeviceAuthorityUnavailable()
        return result

    def apply_for_service(
        self,
        service: VerifiedServiceCredential,
        viewer_token: str,
        payload: object,
    ) -> dict[str, object]:
        self._require_service(service, self.service_config)
        viewer = self._require_viewer_full(viewer_token)
        result = self.device_authority.apply(
            payload,
            authenticated_subject=viewer.subject,
        )
        if type(result) is not dict:
            raise MessagingDeviceAuthorityUnavailable()
        return result

    def current(self, service_token: str, viewer_token: str) -> dict[str, object]:
        service = self.verify_service_authority(service_token)
        return self.current_for_service(service, viewer_token)

    def apply(
        self,
        service_token: str,
        viewer_token: str,
        payload: object,
    ) -> dict[str, object]:
        service = self.verify_service_authority(service_token)
        return self.apply_for_service(service, viewer_token, payload)


def _required_string(config: Mapping[str, object], name: str) -> str:
    value = config.get(name)
    if type(value) is not str or not value or value.strip() != value:
        raise MessagingDeviceInternalConfigurationError()
    return value


def _absolute_directory(config: Mapping[str, object], name: str) -> str:
    value = _required_string(config, name)
    try:
        info = os.lstat(value)
        if not os.path.isabs(value) or not stat.S_ISDIR(info.st_mode) or os.path.islink(value):
            raise ValueError
    except Exception:
        raise MessagingDeviceInternalConfigurationError() from None
    return value


def _required_binding_lifetime_seconds(config: Mapping[str, object]) -> int:
    from app.services.social_messaging_device_storage import (
        MAX_BINDING_LIFETIME_SECONDS,
        MIN_BINDING_LIFETIME_SECONDS,
    )

    value = config.get("SOCIAL_MESSAGING_DEVICE_BINDING_LIFETIME_SECONDS")
    if type(value) is not int or not MIN_BINDING_LIFETIME_SECONDS <= value <= MAX_BINDING_LIFETIME_SECONDS:
        raise MessagingDeviceInternalConfigurationError()
    return value


def build_messaging_device_internal_runtime(
    config: Mapping[str, object],
    *,
    session_factory=None,
    viewer_token_validator=None,
) -> MessagingDeviceInternalDeliveryRuntime | None:
    """Build the private messaging runtime only from complete explicit config."""

    if config.get("SOCIAL_MESSAGING_DEVICE_INTERNAL_ENABLED") is not True:
        return None

    binding_lifetime_seconds = _required_binding_lifetime_seconds(config)

    try:
        client_jwks_dir = _absolute_directory(
            config,
            "SOCIAL_MESSAGING_DEVICE_CLIENT_JWKS_DIR",
        )
        service_jwks_dir = _absolute_directory(
            config,
            "SOCIAL_MESSAGING_DEVICE_SIGNING_JWKS_DIR",
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
                "SOCIAL_MESSAGING_DEVICE_SERVICE_CLIENT_ID",
            ),
            service_principal=_required_string(
                config,
                "SOCIAL_MESSAGING_DEVICE_SERVICE_PRINCIPAL",
            ),
            issuer=_required_string(
                config,
                "SOCIAL_MESSAGING_DEVICE_SERVICE_ISSUER",
            ),
            token_endpoint_audience=_required_string(
                config,
                "SOCIAL_MESSAGING_DEVICE_SERVICE_TOKEN_ENDPOINT_AUDIENCE",
            ),
            service_resource_audience=_required_string(
                config,
                "SOCIAL_MESSAGING_DEVICE_SERVICE_RESOURCE_AUDIENCE",
            ),
            client_jwks=tuple(client_document["keys"]),
            service_jwks=tuple(service_document["keys"]),
            service_scope=MESSAGING_DEVICE_SCOPE,
            service_purpose=MESSAGING_DEVICE_PURPOSE,
            clock_skew_seconds=config.get(
                "SOCIAL_MESSAGING_DEVICE_CLOCK_SKEW_SECONDS",
                5,
            ),
        )
        validate_confidential_service_config(service_config)

        viewer_oauth_client_id = _required_string(
            config,
            "SOCIAL_MESSAGING_DEVICE_VIEWER_OAUTH_CLIENT_ID",
        )
        if session_factory is None:
            from app.database import get_session

            session_factory = get_session

        replay_consumer = PostgresConfidentialServiceAssertionReplayStore(session_factory)

        from app.services.current_entitlement import (
            resolve_runtime_current_entitlement,
        )
        from app.services.current_entitlement_evidence_storage import (
            SqlAlchemyCurrentEntitlementEvidenceRepository,
        )
        from app.services.social_messaging_device_contract import (
            SocialMessagingDeviceAuthority,
        )
        from app.services.social_messaging_device_storage import (
            SqlAlchemySocialMessagingDeviceRepository,
        )

        entitlement_repository = SqlAlchemyCurrentEntitlementEvidenceRepository(session_factory)

        def current_entitlement_resolver(subject):
            return resolve_runtime_current_entitlement(
                subject,
                repository=entitlement_repository,
            )

        device_repository = SqlAlchemySocialMessagingDeviceRepository(
            session_factory,
            binding_lifetime_seconds=binding_lifetime_seconds,
        )
        device_authority = SocialMessagingDeviceAuthority(device_repository)

        if viewer_token_validator is None:
            from app.services.oauth_bearer_validation import (
                validate_canonical_access_token,
            )

            def viewer_token_validator(token):
                return validate_canonical_access_token(
                    token,
                    expected_client_id=viewer_oauth_client_id,
                )

        return MessagingDeviceInternalDeliveryRuntime(
            service_config=service_config,
            replay_consumer=replay_consumer,
            service_signing_key=signing_key,
            service_signing_kid=signing_kid,
            viewer_oauth_client_id=viewer_oauth_client_id,
            viewer_token_validator=viewer_token_validator,
            current_entitlement_resolver=current_entitlement_resolver,
            device_authority=device_authority,
        )
    except MessagingDeviceInternalConfigurationError:
        raise
    except Exception:
        raise MessagingDeviceInternalConfigurationError() from None


def configure_messaging_device_internal_delivery(
    app,
    config: Mapping[str, object],
) -> bool:
    runtime = build_messaging_device_internal_runtime(config)
    if runtime is None:
        return False
    if MESSAGING_DEVICE_INTERNAL_EXTENSION in app.extensions:
        raise MessagingDeviceInternalConfigurationError()
    app.extensions[MESSAGING_DEVICE_INTERNAL_EXTENSION] = runtime
    return True


def configured_messaging_device_internal_runtime(
    app,
) -> MessagingDeviceInternalDeliveryRuntime | None:
    runtime = app.extensions.get(MESSAGING_DEVICE_INTERNAL_EXTENSION)
    return runtime if type(runtime) is MessagingDeviceInternalDeliveryRuntime else None


__all__ = [
    "MESSAGING_DEVICE_INTERNAL_EXTENSION",
    "MESSAGING_DEVICE_PURPOSE",
    "MESSAGING_DEVICE_SCOPE",
    "MessagingDeviceInternalConfigurationError",
    "MessagingDeviceInternalDeliveryRuntime",
    "MessagingViewerCredentialDenied",
    "MessagingViewerEntitlementDenied",
    "MessagingViewerEntitlementUnavailable",
    "VIEWER_REQUIRED_SCOPE",
    "build_messaging_device_internal_runtime",
    "configure_messaging_device_internal_delivery",
    "configured_messaging_device_internal_runtime",
]

"""Private runtime boundary for Social messaging-device authority.

This layer joins an exact confidential service policy, an independently
validated human OAuth bearer, current canonical Full entitlement, and the
multi-device X25519 authority. It deliberately does not register HTTP routes
or enable any production configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from app.services.action_authorization import IdentityClass
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

MESSAGING_DEVICE_SCOPE = "social:messaging-device:manage"
MESSAGING_DEVICE_PURPOSE = "social_messaging_device_manage"
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
        if (
            decision.identity_class is not IdentityClass.FULL
            or decision.current_full_relation_satisfied is not True
        ):
            raise MessagingViewerEntitlementDenied()
        return viewer

    @staticmethod
    def _require_service(service: VerifiedServiceCredential, config: ConfidentialServiceConfig) -> None:
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
            raise MessagingViewerEntitlementUnavailable()
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
            raise MessagingViewerEntitlementUnavailable()
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


__all__ = [
    "MESSAGING_DEVICE_PURPOSE",
    "MESSAGING_DEVICE_SCOPE",
    "MessagingDeviceInternalConfigurationError",
    "MessagingDeviceInternalDeliveryRuntime",
    "MessagingViewerCredentialDenied",
    "MessagingViewerEntitlementDenied",
    "MessagingViewerEntitlementUnavailable",
    "VIEWER_REQUIRED_SCOPE",
]

"""Private service boundary for Social recipient-device resolution.

This slice authenticates Social independently from the human viewer, rechecks
the viewer's current canonical Full entitlement, and then delegates one
viewer-private recipient alias to the pure recipient-device resolver. It does
not register HTTP routes, read environment configuration, or enable runtime
behavior.
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
from app.services.recipient_device_resolver import (
    RecipientDeviceResolverUnavailable,
)

MESSAGING_RECIPIENT_SCOPE = "social:messaging-recipient:read"
MESSAGING_RECIPIENT_PURPOSE = "social_messaging_recipient_read"
MESSAGING_RECIPIENT_INTERNAL_EXTENSION = "social_messaging_recipient_internal_delivery_v1"
VIEWER_REQUIRED_SCOPE = "openid"


class MessagingRecipientInternalConfigurationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("messaging recipient internal delivery configuration invalid")


class MessagingRecipientViewerCredentialDenied(ValueError):
    def __init__(self) -> None:
        super().__init__("messaging recipient viewer credential denied")


class MessagingRecipientViewerEntitlementDenied(ValueError):
    def __init__(self) -> None:
        super().__init__("messaging recipient viewer entitlement denied")


class MessagingRecipientViewerEntitlementUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__("messaging recipient viewer entitlement unavailable")


@dataclass(frozen=True)
class MessagingRecipientInternalDeliveryRuntime:
    """Authorize one Social request before recipient-device resolution."""

    service_config: ConfidentialServiceConfig
    replay_consumer: Callable[[str, int], bool]
    service_signing_key: object
    service_signing_kid: str
    viewer_oauth_client_id: str
    viewer_token_validator: Callable[[str], BearerPrincipal]
    current_entitlement_resolver: Callable[[str], EntitlementDecision]
    recipient_resolver: object

    def __post_init__(self) -> None:
        try:
            validate_confidential_service_config(self.service_config)
            if (
                self.service_config.service_scope != MESSAGING_RECIPIENT_SCOPE
                or self.service_config.service_purpose != MESSAGING_RECIPIENT_PURPOSE
                or not callable(self.replay_consumer)
                or type(self.service_signing_kid) is not str
                or not self.service_signing_kid
                or self.service_signing_kid.strip() != self.service_signing_kid
                or type(self.viewer_oauth_client_id) is not str
                or not self.viewer_oauth_client_id
                or self.viewer_oauth_client_id.strip() != self.viewer_oauth_client_id
                or not callable(self.viewer_token_validator)
                or not callable(self.current_entitlement_resolver)
                or not callable(getattr(self.recipient_resolver, "resolve", None))
            ):
                raise ValueError
        except Exception:
            raise MessagingRecipientInternalConfigurationError() from None

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
        self._require_service(service, self.service_config)
        return service

    @staticmethod
    def _require_service(
        service: VerifiedServiceCredential,
        config: ConfidentialServiceConfig,
    ) -> None:
        if (
            type(service) is not VerifiedServiceCredential
            or service.service_principal != config.service_principal
            or service.client_id != config.client_id
            or service.scope != MESSAGING_RECIPIENT_SCOPE
            or service.purpose != MESSAGING_RECIPIENT_PURPOSE
        ):
            raise CredentialDenied("credential denied")

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
            raise MessagingRecipientViewerCredentialDenied() from None

        try:
            decision = self.current_entitlement_resolver(viewer.subject)
        except EntitlementDenied:
            raise MessagingRecipientViewerEntitlementDenied() from None
        except Exception:
            raise MessagingRecipientViewerEntitlementUnavailable() from None

        if (
            type(decision) is not EntitlementDecision
            or decision.subject != viewer.subject
            or type(decision.identity_class) is not IdentityClass
            or type(decision.current_full_relation_satisfied) is not bool
        ):
            raise MessagingRecipientViewerEntitlementUnavailable()

        if decision.identity_class is not IdentityClass.FULL or decision.current_full_relation_satisfied is not True:
            raise MessagingRecipientViewerEntitlementDenied()

        return viewer

    def resolve_for_service(
        self,
        service: VerifiedServiceCredential,
        viewer_token: str,
        recipient_alias: object,
    ) -> dict[str, object]:
        self._require_service(service, self.service_config)
        viewer = self._require_viewer_full(viewer_token)
        result = self.recipient_resolver.resolve(
            viewer_subject=viewer.subject,
            recipient_alias=recipient_alias,
        )
        if type(result) is not dict:
            raise RecipientDeviceResolverUnavailable()
        return result

    def resolve(
        self,
        service_token: str,
        viewer_token: str,
        recipient_alias: object,
    ) -> dict[str, object]:
        service = self.verify_service_authority(service_token)
        return self.resolve_for_service(
            service,
            viewer_token,
            recipient_alias,
        )


__all__ = [
    "MESSAGING_RECIPIENT_INTERNAL_EXTENSION",
    "MESSAGING_RECIPIENT_PURPOSE",
    "MESSAGING_RECIPIENT_SCOPE",
    "MessagingRecipientInternalConfigurationError",
    "MessagingRecipientInternalDeliveryRuntime",
    "MessagingRecipientViewerCredentialDenied",
    "MessagingRecipientViewerEntitlementDenied",
    "MessagingRecipientViewerEntitlementUnavailable",
    "VIEWER_REQUIRED_SCOPE",
]

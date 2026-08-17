"""Dormant trusted orchestration for issuing action step-up challenges."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from app.auth_api_core import canonical_xonly_pubkey
from app.services.action_authorization import ACTION_REQUIREMENTS, ActionName, ActionRequest, authorize_action
from app.services.action_request_canonicalization import canonical_payload_bytes
from app.services.action_step_up import (
    DEFAULT_CHALLENGE_LIFETIME_SECONDS,
    MAX_CHALLENGE_LIFETIME_SECONDS,
    MAX_CLIENT_ID_LENGTH,
    MAX_RESOURCE_ID_LENGTH,
    MAX_TOKEN_JTI_LENGTH,
    ActionStepUpService,
    StepUpChallenge,
    StepUpError,
    StepUpReason,
)
from app.services.current_entitlement import (
    CurrentEntitlementResolver,
    EntitlementDecision,
    EntitlementDenied,
    EntitlementUnavailable,
)
from app.services.oauth_bearer_validation import BearerPrincipal, BearerValidationError

MAX_BEARER_BYTES = 16_384
_SAFE_IDENTIFIER = re.compile(r"^[\x21-\x7e]+$")
_ELIGIBLE_ACTIONS = frozenset({ActionName.COVENANT_DRAFT_CREATE})


class StepUpIssuanceReason(str, Enum):
    ISSUED = "issued"
    INVALID_REQUEST = "invalid_request"
    INVALID_TOKEN = "invalid_token"
    ENTITLEMENT_DENIED = "entitlement_denied"
    ENTITLEMENT_UNAVAILABLE = "entitlement_unavailable"
    AUTHORIZATION_DENIED = "authorization_denied"
    ACTION_UNAVAILABLE = "action_unavailable"
    OWNERSHIP_UNAVAILABLE = "ownership_unavailable"
    STORAGE_UNAVAILABLE = "storage_unavailable"
    INTERNAL_FAILURE = "internal_failure"


@dataclass(frozen=True)
class StepUpIssuanceRequest:
    encoded_bearer_token: str
    expected_oauth_client_id: str
    action: ActionName | str
    resource_id: str | None
    request_payload: object


@dataclass(frozen=True)
class StepUpIssuanceResult:
    reason: StepUpIssuanceReason
    challenge: StepUpChallenge | None = None

    def __post_init__(self) -> None:
        if type(self.reason) is not StepUpIssuanceReason:
            raise ValueError("invalid issuance result")
        issued = self.reason is StepUpIssuanceReason.ISSUED
        if issued != (type(self.challenge) is StepUpChallenge):
            raise ValueError("invalid issuance result")


class ChallengeIssuer(Protocol):
    def issue_challenge(
        self,
        *,
        actor_pubkey: str,
        oauth_client_id: str,
        token_jti: str,
        action: ActionName | str,
        resource_id: str | None,
        request_sha256: str,
        lifetime_seconds: int,
    ) -> StepUpChallenge: ...


BearerValidator = Callable[[str], BearerPrincipal]
EntitlementResolverCallback = Callable[[str], EntitlementDecision]
OwnershipResolver = Callable[[ActionName, str, str], str | None]


def _identifier(value: object, maximum: int, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value.strip() != value
        or _SAFE_IDENTIFIER.fullmatch(value) is None
    ):
        raise ValueError("invalid request")
    return value


def _valid_principal(value: object) -> BearerPrincipal | None:
    if type(value) is not BearerPrincipal:
        return None
    try:
        subject = canonical_xonly_pubkey(value.subject)
        client = _identifier(value.client_id, MAX_CLIENT_ID_LENGTH)
        jti = _identifier(value.jti, MAX_TOKEN_JTI_LENGTH)
        if subject != value.subject or client != value.client_id or jti != value.jti:
            return None
    except Exception:
        return None
    return value


class ActionStepUpIssuanceOrchestrator:
    """Authenticate, authorize, bind, and issue without consuming or executing."""

    def __init__(
        self,
        *,
        bearer_validator: BearerValidator,
        entitlement_resolver: EntitlementResolverCallback,
        challenge_issuer: ChallengeIssuer,
        ownership_resolver: OwnershipResolver | None = None,
        lifetime_seconds: int = DEFAULT_CHALLENGE_LIFETIME_SECONDS,
    ):
        if not callable(bearer_validator) or not callable(entitlement_resolver):
            raise ValueError("invalid dependency")
        if not isinstance(challenge_issuer, ActionStepUpService) and not callable(
            getattr(challenge_issuer, "issue_challenge", None)
        ):
            raise ValueError("invalid dependency")
        if ownership_resolver is not None and not callable(ownership_resolver):
            raise ValueError("invalid dependency")
        if (
            isinstance(lifetime_seconds, bool)
            or not isinstance(lifetime_seconds, int)
            or not 1 <= lifetime_seconds <= MAX_CHALLENGE_LIFETIME_SECONDS
        ):
            raise ValueError("invalid lifetime")
        self._bearer_validator = bearer_validator
        self._entitlement_resolver = entitlement_resolver
        self._challenge_issuer = challenge_issuer
        self._ownership_resolver = ownership_resolver
        self._lifetime_seconds = lifetime_seconds

    def issue(self, request: StepUpIssuanceRequest) -> StepUpIssuanceResult:
        try:
            if type(request) is not StepUpIssuanceRequest:
                raise ValueError
            token = _identifier(request.encoded_bearer_token, MAX_BEARER_BYTES)
            expected_client = _identifier(request.expected_oauth_client_id, MAX_CLIENT_ID_LENGTH)
            resource_id = _identifier(request.resource_id, MAX_RESOURCE_ID_LENGTH, optional=True)
            request_bytes = canonical_payload_bytes(request.request_payload)
        except Exception:
            return StepUpIssuanceResult(StepUpIssuanceReason.INVALID_REQUEST)

        try:
            action = ActionName(request.action)
        except (TypeError, ValueError):
            return StepUpIssuanceResult(StepUpIssuanceReason.ACTION_UNAVAILABLE)

        requirement = ACTION_REQUIREMENTS[action]
        if action not in _ELIGIBLE_ACTIONS or requirement.step_up_required is not True:
            return StepUpIssuanceResult(StepUpIssuanceReason.ACTION_UNAVAILABLE)

        try:
            principal = _valid_principal(self._bearer_validator(token))
        except BearerValidationError:
            principal = None
        except Exception:
            principal = None
        if principal is None or principal.client_id != expected_client:
            return StepUpIssuanceResult(StepUpIssuanceReason.INVALID_TOKEN)

        try:
            entitlement = self._entitlement_resolver(principal.subject)
        except EntitlementDenied:
            return StepUpIssuanceResult(StepUpIssuanceReason.ENTITLEMENT_DENIED)
        except EntitlementUnavailable:
            return StepUpIssuanceResult(StepUpIssuanceReason.ENTITLEMENT_UNAVAILABLE)
        except Exception:
            return StepUpIssuanceResult(StepUpIssuanceReason.ENTITLEMENT_UNAVAILABLE)

        owner = None
        if requirement.ownership_required:
            if resource_id is None or self._ownership_resolver is None:
                return StepUpIssuanceResult(StepUpIssuanceReason.OWNERSHIP_UNAVAILABLE)
            try:
                owner = self._ownership_resolver(action, resource_id, principal.subject)
            except Exception:
                return StepUpIssuanceResult(StepUpIssuanceReason.OWNERSHIP_UNAVAILABLE)
            if owner is None:
                return StepUpIssuanceResult(StepUpIssuanceReason.OWNERSHIP_UNAVAILABLE)

        decision = authorize_action(
            ActionRequest(principal.subject, action, principal.scopes, owner, step_up_verified=True),
            CurrentEntitlementResolver(entitlement),
        )
        if not decision.allowed:
            return StepUpIssuanceResult(StepUpIssuanceReason.AUTHORIZATION_DENIED)

        request_sha256 = hashlib.sha256(request_bytes).hexdigest()
        try:
            challenge = self._challenge_issuer.issue_challenge(
                actor_pubkey=principal.subject,
                oauth_client_id=principal.client_id,
                token_jti=principal.jti,
                action=action,
                resource_id=resource_id,
                request_sha256=request_sha256,
                lifetime_seconds=self._lifetime_seconds,
            )
        except StepUpError as exc:
            reason = (
                StepUpIssuanceReason.STORAGE_UNAVAILABLE
                if exc.reason is StepUpReason.STORAGE_UNAVAILABLE
                else StepUpIssuanceReason.INTERNAL_FAILURE
            )
            return StepUpIssuanceResult(reason)
        except Exception:
            return StepUpIssuanceResult(StepUpIssuanceReason.INTERNAL_FAILURE)
        if (
            type(challenge) is not StepUpChallenge
            or ActionStepUpService._validate_persisted(challenge, challenge.issued_at) is not None
            or challenge.consumed_at is not None
            or (
                challenge.actor_pubkey,
                challenge.oauth_client_id,
                challenge.token_jti,
                challenge.action,
                challenge.resource_id,
                challenge.request_sha256,
            )
            != (
                principal.subject,
                principal.client_id,
                principal.jti,
                action.value,
                resource_id,
                request_sha256,
            )
        ):
            return StepUpIssuanceResult(StepUpIssuanceReason.INTERNAL_FAILURE)
        return StepUpIssuanceResult(StepUpIssuanceReason.ISSUED, challenge)

"""Disabled-by-default internal runtime for identity-authorized device bindings."""

from __future__ import annotations

import glob
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Mapping, Protocol

from app.services.confidential_service_assertion_replay_storage import PostgresConfidentialServiceAssertionReplayStore
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    CredentialDenied,
    VerifiedServiceCredential,
    issue_service_access_token,
    validate_confidential_service_config,
    verify_service_access_token,
)
from app.services.oauth_bearer_validation import BearerPrincipal
from app.services.social_messaging_device_binding_authorization import (
    ADOPTION_SCHEMA,
    AUTHORIZATION_SCHEMA,
    MAX_AUTHORIZATION_BYTES,
    PROOF_ID_PREFIX,
    AdoptedDeviceBindingAuthorization,
    AuthorizedDeviceBinding,
    Bip340IdentitySignatureVerifier,
    DeviceBindingAuthorizationUnavailable,
    canonical_adoption_json,
    canonical_authorization_json,
)
from app.services.social_messaging_device_binding_authorization_intent import (
    canonical_authorization_intent_bytes,
    seal_authorization_intent,
    verify_authorization_intent_submission,
)
from app.services.social_messaging_device_binding_authorization_storage import (
    SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage,
)
from app.services.social_messaging_device_contract import MessagingDeviceBinding
from app.services.social_messaging_device_storage import MAX_BINDING_LIFETIME_SECONDS, MIN_BINDING_LIFETIME_SECONDS
from app.services.social_messaging_recipient_routing import VerifiedBindingAuthorization

MESSAGING_DEVICE_AUTHORIZATION_SCOPE = "social:messaging-device-binding-authorization:manage"
MESSAGING_DEVICE_AUTHORIZATION_PURPOSE = "social_messaging_device_binding_authorization_manage"
MESSAGING_DEVICE_AUTHORIZATION_EXTENSION = "social_messaging_device_binding_authorization_runtime_v1"
RESULT_SCHEMA = "hodlxxi.social_messaging_device_binding_authorization_result.v1"
RESULT_VERSION = 1
VIEWER_REQUIRED_SCOPE = "openid"
DEFAULT_BINDING_LIFETIME_SECONDS = 30 * 24 * 60 * 60


class MessagingDeviceBindingAuthorizationConfigurationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("messaging device binding authorization configuration invalid")


class MessagingDeviceBindingAuthorizationViewerDenied(ValueError):
    def __init__(self) -> None:
        super().__init__("messaging device binding authorization viewer denied")


class _AuthorizationSession(Protocol):
    def begin(self) -> object: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...


def _timestamp(value: object) -> str:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        raise ValueError
    return normalized.isoformat(timespec="seconds").replace("+00:00", "Z")


def _verified_result_values(
    value: object,
) -> tuple[str, str, MessagingDeviceBinding, VerifiedBindingAuthorization, datetime]:
    if type(value) is AuthorizedDeviceBinding:
        authorization = value.authorization
        canonical_authorization_json(authorization)
        claim = authorization.claim
        action = claim.operation
        request_id = claim.request_id
        binding_id = authorization.binding_id
        evidence_valid_from = claim.issued_at
        digest = authorization.digest
        binding = value.binding
        verification = value.verification
        if (
            type(binding) is not MessagingDeviceBinding
            or type(verification) is not VerifiedBindingAuthorization
            or binding.subject != claim.subject
            or binding.device_id != claim.device_id
            or binding.public_key != claim.public_key
            or binding.binding_version != claim.binding_version
            or binding.valid_from != claim.binding_valid_from
            or binding.expires_at != claim.binding_expires_at
            or binding.operation != claim.operation
            or binding.prior_binding_id != claim.prior_binding_id
            or binding.request_id != claim.request_id
            or binding.active is not (claim.operation != "revoke")
        ):
            raise ValueError
    elif type(value) is AdoptedDeviceBindingAuthorization:
        adoption = value.adoption
        canonical_adoption_json(adoption)
        adoption_claim = adoption.claim
        action = adoption_claim.action
        request_id = adoption_claim.request_id
        binding_id = adoption.binding_id
        evidence_valid_from = adoption_claim.issued_at
        digest = adoption.digest
        binding = value.binding
        verification = value.verification
        if (
            type(binding) is not MessagingDeviceBinding
            or type(verification) is not VerifiedBindingAuthorization
            or binding != adoption_claim.binding
        ):
            raise ValueError
    else:
        raise ValueError

    if (
        binding.binding_id != binding_id
        or verification.proof_id != PROOF_ID_PREFIX + digest
        or verification.subject != binding.subject
        or verification.device_id != binding.device_id
        or verification.binding_id != binding.binding_id
        or verification.binding_version != binding.binding_version
        or verification.public_key != binding.public_key
        or verification.valid_from != binding.valid_from
        or verification.expires_at != binding.expires_at
        or verification.evidence_valid_from != evidence_valid_from
        or verification.evidence_expires_at != binding.expires_at
    ):
        raise ValueError
    return action, request_id, binding, verification, evidence_valid_from


def canonical_authorization_result_bytes(value: object) -> bytes:
    """Serialize one exact verified storage result without exposing key material."""

    try:
        action, request_id, binding, verification, evidence_valid_from = _verified_result_values(value)
        payload = {
            "action": action,
            "active": binding.active,
            "authorizationExpiresAt": _timestamp(verification.evidence_expires_at),
            "authorizationProofId": verification.proof_id,
            "authorizationValidFrom": _timestamp(evidence_valid_from),
            "bindingId": binding.binding_id,
            "bindingOperation": binding.operation,
            "bindingVersion": binding.binding_version,
            "deviceId": binding.device_id,
            "expiresAt": _timestamp(binding.expires_at),
            "requestId": request_id,
            "schema": RESULT_SCHEMA,
            "validFrom": _timestamp(binding.valid_from),
            "version": RESULT_VERSION,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(encoded) > MAX_AUTHORIZATION_BYTES:
            raise ValueError
        return encoded
    except DeviceBindingAuthorizationUnavailable:
        raise
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def _authorization_action(payload: object) -> str:
    def pairs(values):
        result = {}
        for key, item in values:
            if type(key) is not str or key in result:
                raise ValueError
            result[key] = item
        return result

    try:
        if type(payload) is not str or not payload or len(payload.encode("utf-8")) > MAX_AUTHORIZATION_BYTES:
            raise ValueError
        if any(ord(character) > 0x7F for character in payload):
            raise ValueError
        decoded = json.loads(payload, object_pairs_hook=pairs)
        if type(decoded) is not dict:
            raise ValueError
        canonical = json.dumps(decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if canonical != payload:
            raise ValueError
        if decoded.get("schema") == AUTHORIZATION_SCHEMA:
            action = decoded.get("operation")
            if type(action) is not str or action not in {"register", "rotate", "revoke"}:
                raise ValueError
            return action
        if decoded.get("schema") == ADOPTION_SCHEMA and decoded.get("action") == "adopt":
            return "adopt"
        raise ValueError
    except DeviceBindingAuthorizationUnavailable:
        raise
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


@dataclass(frozen=True)
class MessagingDeviceBindingAuthorizationRuntime:
    service_config: ConfidentialServiceConfig
    replay_consumer: Callable[[str, int], bool]
    service_signing_key: object
    service_signing_kid: str
    viewer_oauth_client_id: str
    viewer_token_validator: Callable[[str], BearerPrincipal]
    session_factory: Callable[[], _AuthorizationSession]
    binding_lifetime_seconds: int
    clock: Callable[[], datetime]

    def __post_init__(self) -> None:
        try:
            validate_confidential_service_config(self.service_config)
            if (
                self.service_config.service_scope != MESSAGING_DEVICE_AUTHORIZATION_SCOPE
                or self.service_config.service_purpose != MESSAGING_DEVICE_AUTHORIZATION_PURPOSE
                or not callable(self.replay_consumer)
                or type(self.service_signing_kid) is not str
                or not self.service_signing_kid
                or self.service_signing_kid.strip() != self.service_signing_kid
                or type(self.viewer_oauth_client_id) is not str
                or not self.viewer_oauth_client_id
                or self.viewer_oauth_client_id.strip() != self.viewer_oauth_client_id
                or not callable(self.viewer_token_validator)
                or not callable(self.session_factory)
                or type(self.binding_lifetime_seconds) is not int
                or not MIN_BINDING_LIFETIME_SECONDS <= self.binding_lifetime_seconds <= MAX_BINDING_LIFETIME_SECONDS
                or not callable(self.clock)
            ):
                raise ValueError
        except Exception:
            raise MessagingDeviceBindingAuthorizationConfigurationError() from None

    def issue_service_token(self, client_assertion: str) -> str:
        return issue_service_access_token(
            client_assertion,
            config=self.service_config,
            replay_consumer=self.replay_consumer,
            signing_key=self.service_signing_key,
            signing_kid=self.service_signing_kid,
        )

    def verify_service_authority(self, service_token: str) -> VerifiedServiceCredential:
        service = verify_service_access_token(service_token, config=self.service_config)
        self._require_service(service)
        return service

    def _require_service(self, service: object) -> None:
        if (
            type(service) is not VerifiedServiceCredential
            or service.service_principal != self.service_config.service_principal
            or service.client_id != self.service_config.client_id
            or service.scope != MESSAGING_DEVICE_AUTHORIZATION_SCOPE
            or service.purpose != MESSAGING_DEVICE_AUTHORIZATION_PURPOSE
        ):
            raise CredentialDenied("credential denied")

    def _viewer_subject(self, viewer_token: str) -> str:
        try:
            viewer = self.viewer_token_validator(viewer_token)
            if (
                type(viewer) is not BearerPrincipal
                or viewer.client_id != self.viewer_oauth_client_id
                or type(viewer.scopes) is not frozenset
                or any(type(scope) is not str for scope in viewer.scopes)
                or VIEWER_REQUIRED_SCOPE not in viewer.scopes
            ):
                raise ValueError
            return viewer.subject
        except Exception:
            raise MessagingDeviceBindingAuthorizationViewerDenied() from None

    def authorize_for_service(
        self,
        service: VerifiedServiceCredential,
        viewer_token: str,
        payload: object,
        intent_token: object,
    ) -> bytes:
        """Own one transaction from begin through serialized result and commit."""

        self._require_service(service)
        subject = self._viewer_subject(viewer_token)
        action = _authorization_action(payload)
        signature_verifier = Bip340IdentitySignatureVerifier()
        verify_authorization_intent_submission(
            intent_token,
            payload,
            authenticated_subject=subject,
            issuer=self.service_config.issuer,
            expected_kid=self.service_signing_kid,
            verification_keys=self.service_config.service_jwks,
            signature_verifier=signature_verifier,
            now=self.clock(),
        )
        session: _AuthorizationSession | None = None
        try:
            session = self.session_factory()
            if (
                not callable(getattr(session, "begin", None))
                or not callable(getattr(session, "commit", None))
                or not callable(getattr(session, "rollback", None))
                or not callable(getattr(session, "close", None))
            ):
                raise ValueError
            session.begin()
            storage = SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(
                session,
                signature_verifier=signature_verifier,
                clock=self.clock,
            )

            def validate_admission(now: datetime) -> None:
                verify_authorization_intent_submission(
                    intent_token,
                    payload,
                    authenticated_subject=subject,
                    issuer=self.service_config.issuer,
                    expected_kid=self.service_signing_kid,
                    verification_keys=self.service_config.service_jwks,
                    signature_verifier=signature_verifier,
                    now=now,
                )

            result: AuthorizedDeviceBinding | AdoptedDeviceBindingAuthorization
            if action == "adopt":
                result = storage.adopt_legacy(
                    payload,
                    authenticated_subject=subject,
                    admission_validator=validate_admission,
                )
            else:
                result = storage.authorize_lifecycle(
                    payload,
                    authenticated_subject=subject,
                    admission_validator=validate_admission,
                )
            response = canonical_authorization_result_bytes(result)
            session.commit()
            return response
        except DeviceBindingAuthorizationUnavailable:
            if session is not None:
                try:
                    session.rollback()
                except Exception:
                    pass
            raise
        except Exception:
            if session is not None:
                try:
                    session.rollback()
                except Exception:
                    pass
            raise DeviceBindingAuthorizationUnavailable() from None
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass

    def create_intent_for_service(
        self,
        service: VerifiedServiceCredential,
        viewer_token: str,
        payload: object,
    ) -> bytes:
        """Derive and seal one intent; always roll back the read transaction."""

        self._require_service(service)
        subject = self._viewer_subject(viewer_token)
        session: _AuthorizationSession | None = None
        try:
            session = self.session_factory()
            if (
                not callable(getattr(session, "begin", None))
                or not callable(getattr(session, "rollback", None))
                or not callable(getattr(session, "close", None))
            ):
                raise ValueError
            session.begin()
            storage = SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(
                session,
                clock=self.clock,
            )
            intent = storage.create_intent(
                payload,
                authenticated_subject=subject,
                binding_lifetime_seconds=self.binding_lifetime_seconds,
            )
            token = seal_authorization_intent(
                intent,
                issuer=self.service_config.issuer,
                signing_key=self.service_signing_key,
                signing_kid=self.service_signing_kid,
                verification_keys=self.service_config.service_jwks,
            )
            response = canonical_authorization_intent_bytes(intent, intent_token=token)
            session.rollback()
            return response
        except DeviceBindingAuthorizationUnavailable:
            if session is not None:
                try:
                    session.rollback()
                except Exception:
                    pass
            raise
        except Exception:
            if session is not None:
                try:
                    session.rollback()
                except Exception:
                    pass
            raise DeviceBindingAuthorizationUnavailable() from None
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass


def _required_string(config: Mapping[str, object], name: str) -> str:
    value = config.get(name)
    if type(value) is not str or not value or value.strip() != value:
        raise MessagingDeviceBindingAuthorizationConfigurationError()
    return value


def _absolute_directory(config: Mapping[str, object], name: str) -> str:
    value = _required_string(config, name)
    try:
        info = os.lstat(value)
        if not os.path.isabs(value) or not stat.S_ISDIR(info.st_mode) or os.path.islink(value):
            raise ValueError
    except Exception:
        raise MessagingDeviceBindingAuthorizationConfigurationError() from None
    return value


def build_messaging_device_binding_authorization_runtime(
    config: Mapping[str, object],
    *,
    session_factory=None,
    viewer_token_validator=None,
    clock=None,
) -> MessagingDeviceBindingAuthorizationRuntime | None:
    if config.get("SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_INTERNAL_ENABLED") is not True:
        return None

    try:
        client_jwks_dir = _absolute_directory(
            config,
            "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_CLIENT_JWKS_DIR",
        )
        signing_jwks_dir = _absolute_directory(
            config,
            "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SIGNING_JWKS_DIR",
        )
        if glob.glob(os.path.join(client_jwks_dir, "private_key*.pem")):
            raise ValueError

        from app.jwks import load_jwks_document, load_signing_material

        client_document = load_jwks_document(client_jwks_dir)
        service_document, signing_kid, signing_key = load_signing_material(signing_jwks_dir)
        service_config = ConfidentialServiceConfig(
            enabled=True,
            client_id=_required_string(
                config,
                "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_CLIENT_ID",
            ),
            service_principal=_required_string(
                config,
                "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_PRINCIPAL",
            ),
            issuer=_required_string(
                config,
                "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_ISSUER",
            ),
            token_endpoint_audience=_required_string(
                config,
                "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_TOKEN_ENDPOINT_AUDIENCE",
            ),
            service_resource_audience=_required_string(
                config,
                "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_RESOURCE_AUDIENCE",
            ),
            client_jwks=tuple(client_document["keys"]),
            service_jwks=tuple(service_document["keys"]),
            service_scope=MESSAGING_DEVICE_AUTHORIZATION_SCOPE,
            service_purpose=MESSAGING_DEVICE_AUTHORIZATION_PURPOSE,
            clock_skew_seconds=config.get(
                "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_CLOCK_SKEW_SECONDS",
                5,
            ),
        )
        validate_confidential_service_config(service_config)
        viewer_oauth_client_id = _required_string(
            config,
            "SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID",
        )
        binding_lifetime_seconds = config.get(
            "SOCIAL_MESSAGING_DEVICE_BINDING_LIFETIME_SECONDS",
            DEFAULT_BINDING_LIFETIME_SECONDS,
        )
        if (
            type(binding_lifetime_seconds) is not int
            or not MIN_BINDING_LIFETIME_SECONDS <= binding_lifetime_seconds <= MAX_BINDING_LIFETIME_SECONDS
        ):
            raise ValueError
        if session_factory is None:
            from app.database import get_session

            session_factory = get_session
        replay_consumer = PostgresConfidentialServiceAssertionReplayStore(session_factory)

        if viewer_token_validator is None:
            from app.services.oauth_bearer_validation import validate_canonical_access_token

            def viewer_token_validator(token):
                return validate_canonical_access_token(
                    token,
                    expected_client_id=viewer_oauth_client_id,
                )

        if clock is None:

            def clock():
                return datetime.now(timezone.utc).replace(microsecond=0)

        if not callable(clock):
            raise ValueError

        return MessagingDeviceBindingAuthorizationRuntime(
            service_config=service_config,
            replay_consumer=replay_consumer,
            service_signing_key=signing_key,
            service_signing_kid=signing_kid,
            viewer_oauth_client_id=viewer_oauth_client_id,
            viewer_token_validator=viewer_token_validator,
            session_factory=session_factory,
            binding_lifetime_seconds=binding_lifetime_seconds,
            clock=clock,
        )
    except MessagingDeviceBindingAuthorizationConfigurationError:
        raise
    except Exception:
        raise MessagingDeviceBindingAuthorizationConfigurationError() from None


def configure_messaging_device_binding_authorization(app, config: Mapping[str, object]) -> bool:
    runtime = build_messaging_device_binding_authorization_runtime(config)
    if runtime is None:
        return False
    if MESSAGING_DEVICE_AUTHORIZATION_EXTENSION in app.extensions:
        raise MessagingDeviceBindingAuthorizationConfigurationError()
    app.extensions[MESSAGING_DEVICE_AUTHORIZATION_EXTENSION] = runtime
    return True


def configured_messaging_device_binding_authorization_runtime(
    app,
) -> MessagingDeviceBindingAuthorizationRuntime | None:
    runtime = app.extensions.get(MESSAGING_DEVICE_AUTHORIZATION_EXTENSION)
    return runtime if type(runtime) is MessagingDeviceBindingAuthorizationRuntime else None


__all__ = [
    "MESSAGING_DEVICE_AUTHORIZATION_EXTENSION",
    "MESSAGING_DEVICE_AUTHORIZATION_PURPOSE",
    "MESSAGING_DEVICE_AUTHORIZATION_SCOPE",
    "RESULT_SCHEMA",
    "RESULT_VERSION",
    "MessagingDeviceBindingAuthorizationConfigurationError",
    "MessagingDeviceBindingAuthorizationRuntime",
    "MessagingDeviceBindingAuthorizationViewerDenied",
    "build_messaging_device_binding_authorization_runtime",
    "canonical_authorization_result_bytes",
    "configure_messaging_device_binding_authorization",
    "configured_messaging_device_binding_authorization_runtime",
]

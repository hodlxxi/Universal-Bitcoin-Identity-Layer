"""Disabled-by-default orchestration for private Social directory delivery."""

from __future__ import annotations

import glob
import os
import stat
from dataclasses import dataclass
from typing import Callable, Mapping

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
from app.services.oauth_bearer_validation import BearerPrincipal
from app.services.privacy_safe_full_directory import (
    MAX_ALIAS_VERSION,
    MAX_ALIAS_SECRET_BYTES,
    MIN_ALIAS_SECRET_BYTES,
    PrivacySafeFullDirectoryV1,
)

INTERNAL_DELIVERY_EXTENSION = "privacy_full_directory_internal_delivery_v1"
VIEWER_REQUIRED_SCOPE = "openid"


class InternalDeliveryConfigurationError(RuntimeError):
    """The explicitly enabled runtime has incomplete or unsafe configuration."""

    def __init__(self) -> None:
        super().__init__("privacy Full-directory internal delivery configuration invalid")


class ViewerCredentialDenied(ValueError):
    """The independently supplied human OAuth credential was denied."""

    def __init__(self) -> None:
        super().__init__("viewer credential denied")


@dataclass(frozen=True)
class PrivacyFullDirectoryInternalDeliveryRuntime:
    """Join service auth, human auth, canonical Full state, and private output."""

    service_config: ConfidentialServiceConfig
    replay_consumer: Callable[[str, int], bool]
    service_signing_key: object
    service_signing_kid: str
    viewer_oauth_client_id: str
    viewer_token_validator: Callable[[str], BearerPrincipal]
    current_entitlement_resolver: Callable[[str], object]
    full_population_provider: Callable[[], object]
    alias_secret: bytes
    alias_version: int = 1

    def __post_init__(self) -> None:
        try:
            validate_confidential_service_config(self.service_config)
            if (
                not callable(self.replay_consumer)
                or not isinstance(self.service_signing_kid, str)
                or not self.service_signing_kid
                or self.service_signing_kid.strip() != self.service_signing_kid
                or not isinstance(self.viewer_oauth_client_id, str)
                or not self.viewer_oauth_client_id
                or self.viewer_oauth_client_id.strip() != self.viewer_oauth_client_id
                or not callable(self.viewer_token_validator)
                or not callable(self.current_entitlement_resolver)
                or not callable(self.full_population_provider)
                or type(self.alias_secret) is not bytes
                or not MIN_ALIAS_SECRET_BYTES <= len(self.alias_secret) <= MAX_ALIAS_SECRET_BYTES
                or type(self.alias_version) is not int
                or not 1 <= self.alias_version <= MAX_ALIAS_VERSION
            ):
                raise ValueError
        except Exception:
            raise InternalDeliveryConfigurationError() from None

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
        if (
            type(service) is not VerifiedServiceCredential
            or service.service_principal != self.service_config.service_principal
            or service.client_id != self.service_config.client_id
            or service.scope != self.service_config.service_scope
        ):
            raise CredentialDenied("credential denied")
        return service

    def current_directory_for_service(
        self,
        service: VerifiedServiceCredential,
        viewer_token: str,
    ) -> dict[str, object]:
        if (
            type(service) is not VerifiedServiceCredential
            or service.service_principal != self.service_config.service_principal
            or service.client_id != self.service_config.client_id
            or service.scope != self.service_config.service_scope
        ):
            raise CredentialDenied("credential denied")

        try:
            viewer = self.viewer_token_validator(viewer_token)
            if (
                type(viewer) is not BearerPrincipal
                or viewer.client_id != self.viewer_oauth_client_id
                or VIEWER_REQUIRED_SCOPE not in viewer.scopes
            ):
                raise ValueError
        except Exception:
            raise ViewerCredentialDenied() from None

        return PrivacySafeFullDirectoryV1(
            viewer_subject=viewer.subject,
            current_entitlement_resolver=self.current_entitlement_resolver,
            full_population_provider=self.full_population_provider,
            alias_secret=self.alias_secret,
            alias_version=self.alias_version,
        ).current_directory()

    def current_directory(self, service_token: str, viewer_token: str) -> dict[str, object]:
        service = self.verify_service_authority(service_token)
        return self.current_directory_for_service(service, viewer_token)


def _required_string(config: Mapping[str, object], name: str) -> str:
    value = config.get(name)
    if not isinstance(value, str) or not value or value.strip() != value:
        raise InternalDeliveryConfigurationError()
    return value


def _absolute_directory(config: Mapping[str, object], name: str) -> str:
    value = _required_string(config, name)
    try:
        info = os.lstat(value)
        if not os.path.isabs(value) or not stat.S_ISDIR(info.st_mode) or os.path.islink(value):
            raise ValueError
    except Exception:
        raise InternalDeliveryConfigurationError() from None
    return value


def _read_alias_secret(path: str) -> bytes:
    descriptor = None
    try:
        if not os.path.isabs(path):
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError
        value = os.read(descriptor, MAX_ALIAS_SECRET_BYTES + 1)
        if not MIN_ALIAS_SECRET_BYTES <= len(value) <= MAX_ALIAS_SECRET_BYTES:
            raise ValueError
        return value
    except Exception:
        raise InternalDeliveryConfigurationError() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def build_internal_delivery_runtime(
    config: Mapping[str, object],
    *,
    session_factory=None,
    viewer_token_validator=None,
) -> PrivacyFullDirectoryInternalDeliveryRuntime | None:
    """Build only from complete explicit configuration; disabled returns no runtime."""

    if config.get("PRIVACY_FULL_DIRECTORY_INTERNAL_ENABLED") is not True:
        return None

    try:
        client_id = _required_string(config, "CONFIDENTIAL_SERVICE_CLIENT_ID")
        viewer_oauth_client_id = _required_string(
            config,
            "PRIVACY_FULL_DIRECTORY_VIEWER_OAUTH_CLIENT_ID",
        )
        client_jwks_dir = _absolute_directory(config, "CONFIDENTIAL_SERVICE_CLIENT_JWKS_DIR")
        service_jwks_dir = _absolute_directory(config, "CONFIDENTIAL_SERVICE_SIGNING_JWKS_DIR")
        alias_secret_path = _required_string(config, "PRIVACY_FULL_DIRECTORY_ALIAS_SECRET_FILE")
        if glob.glob(os.path.join(client_jwks_dir, "private_key*.pem")):
            raise ValueError

        from app.jwks import load_jwks_document, load_signing_material

        client_document = load_jwks_document(client_jwks_dir)
        service_document, signing_kid, signing_key = load_signing_material(service_jwks_dir)
        service_config = ConfidentialServiceConfig(
            enabled=True,
            client_id=client_id,
            service_principal=_required_string(config, "CONFIDENTIAL_SERVICE_PRINCIPAL"),
            issuer=_required_string(config, "CONFIDENTIAL_SERVICE_ISSUER"),
            token_endpoint_audience=_required_string(config, "CONFIDENTIAL_SERVICE_TOKEN_ENDPOINT_AUDIENCE"),
            service_resource_audience=_required_string(config, "CONFIDENTIAL_SERVICE_RESOURCE_AUDIENCE"),
            client_jwks=tuple(client_document["keys"]),
            service_jwks=tuple(service_document["keys"]),
            clock_skew_seconds=config.get("CONFIDENTIAL_SERVICE_CLOCK_SKEW_SECONDS", 5),
        )
        validate_confidential_service_config(service_config)
        alias_secret = _read_alias_secret(alias_secret_path)
        alias_version = config.get("PRIVACY_FULL_DIRECTORY_ALIAS_VERSION", 1)
        if type(alias_version) is not int or not 1 <= alias_version <= MAX_ALIAS_VERSION:
            raise ValueError

        if session_factory is None:
            from app.database import get_session

            session_factory = get_session
        replay_consumer = PostgresConfidentialServiceAssertionReplayStore(session_factory)

        from app.services.current_entitlement import resolve_runtime_current_entitlement
        from app.services.current_entitlement_evidence_storage import (
            SqlAlchemyCurrentEntitlementEvidenceRepository,
        )
        from app.services.full_entitlement_snapshot import FullEntitlementSnapshotReader

        repository = SqlAlchemyCurrentEntitlementEvidenceRepository(session_factory)

        def current_entitlement_resolver(subject):
            return resolve_runtime_current_entitlement(
                subject,
                repository=repository,
            )

        full_population_provider = FullEntitlementSnapshotReader(repository).current_snapshot

        if viewer_token_validator is None:
            from app.services.oauth_bearer_validation import validate_canonical_access_token

            def viewer_token_validator(token):
                return validate_canonical_access_token(
                    token,
                    expected_client_id=viewer_oauth_client_id,
                )

        return PrivacyFullDirectoryInternalDeliveryRuntime(
            service_config=service_config,
            replay_consumer=replay_consumer,
            service_signing_key=signing_key,
            service_signing_kid=signing_kid,
            viewer_oauth_client_id=viewer_oauth_client_id,
            viewer_token_validator=viewer_token_validator,
            current_entitlement_resolver=current_entitlement_resolver,
            full_population_provider=full_population_provider,
            alias_secret=alias_secret,
            alias_version=alias_version,
        )
    except InternalDeliveryConfigurationError:
        raise
    except Exception:
        raise InternalDeliveryConfigurationError() from None


def configure_internal_delivery(app, config: Mapping[str, object]) -> bool:
    runtime = build_internal_delivery_runtime(config)
    if runtime is None:
        return False
    if INTERNAL_DELIVERY_EXTENSION in app.extensions:
        raise InternalDeliveryConfigurationError()
    app.extensions[INTERNAL_DELIVERY_EXTENSION] = runtime
    return True


def configured_internal_delivery_runtime(app) -> PrivacyFullDirectoryInternalDeliveryRuntime | None:
    runtime = app.extensions.get(INTERNAL_DELIVERY_EXTENSION)
    return runtime if type(runtime) is PrivacyFullDirectoryInternalDeliveryRuntime else None


__all__ = [
    "INTERNAL_DELIVERY_EXTENSION",
    "InternalDeliveryConfigurationError",
    "PrivacyFullDirectoryInternalDeliveryRuntime",
    "VIEWER_REQUIRED_SCOPE",
    "ViewerCredentialDenied",
    "build_internal_delivery_runtime",
    "configure_internal_delivery",
    "configured_internal_delivery_runtime",
]

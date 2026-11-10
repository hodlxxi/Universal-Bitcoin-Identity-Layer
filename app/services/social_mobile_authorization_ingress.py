"""Explicit injectable mobile ingress; no environment or factory activation."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from types import MappingProxyType
from urllib.parse import urlsplit

from app.services import social_messaging_mobile_authorization as protocol
from app.services.confidential_service_assertion_replay_storage import PostgresConfidentialServiceAssertionReplayStore
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    CredentialDenied,
    issue_service_access_token,
    validate_confidential_service_config,
    verify_service_access_token,
)
from app.services.oauth_session_lifecycle import SqlAlchemyOAuthSessionLifecycle
from app.services.social_messaging_mobile_authorization_storage import SqlAlchemyMobileAuthorizationService
from app.services.social_mobile_authorization_ingress_schema import (
    COMMANDS,
    GROUPS,
    PREFIX,
    PURPOSES,
    SCOPES,
    TOKEN_PATH,
)

EXTENSION = "social_mobile_authorization_ingress_v1"


class MobileIngressConfigurationError(ValueError):
    def __init__(self):
        super().__init__("mobile ingress configuration unavailable")


def public_snapshot(value):
    if type(value) is protocol.PairingOffer:
        return dict(
            schema="hodlxxi.social_mobile_pairing_offer.v1",
            version=1,
            pairingId=value.pairing_id,
            secretCommitment=value.secret_commitment,
            desktopContext=value.desktop_context,
            subject=value.subject,
            createdAt=value.created_at,
            expiresAt=value.expires_at,
            revision=value.revision,
            status=value.status,
        )
    if type(value) is protocol.PairingState:
        accepted = value.acceptance
        return dict(
            schema="hodlxxi.social_mobile_pairing_snapshot.v1",
            version=1,
            source=value.source,
            revision=value.revision,
            status=value.status,
            acceptance=(
                None
                if accepted is None
                else dict(
                    schema="hodlxxi.social_mobile_authorization_acceptance.v1",
                    version=1,
                    authorizationDigest=accepted.authorization_digest,
                    bindingId=accepted.binding_id,
                    subject=accepted.subject,
                    requestId=accepted.request_id,
                )
            ),
        )
    raise protocol.MobileAuthorizationUnavailable()


@dataclass(frozen=True, repr=False)
class MobileAuthorizationIngress:
    """Trust configuration is construction input; all state owners are explicit.

    Each configured backend capability is bound to the one lifecycle client.
    The shared factory identity prevents split-database continuity/replay owners.
    """

    service_configs: tuple[ConfidentialServiceConfig, ...]
    service_signing_key: object
    service_signing_kid: str
    viewer_client_id: str
    lifecycle: SqlAlchemyOAuthSessionLifecycle
    mobile: SqlAlchemyMobileAuthorizationService
    replay: PostgresConfidentialServiceAssertionReplayStore

    def __post_init__(self):
        try:
            if (
                type(self.service_configs) is not tuple
                or len(self.service_configs) != len(GROUPS)
                or type(self.lifecycle) is not SqlAlchemyOAuthSessionLifecycle
                or type(self.mobile) is not SqlAlchemyMobileAuthorizationService
                or type(self.replay) is not PostgresConfidentialServiceAssertionReplayStore
                or self.lifecycle.client_id != self.viewer_client_id
                or self.mobile._factory is not self.lifecycle._factory
                or self.replay._session_factory is not self.lifecycle._factory
                or type(self.service_signing_kid) is not str
                or not self.service_signing_kid
            ):
                raise ValueError
            configs = {}
            first = self.service_configs[0]
            for config in self.service_configs:
                validate_confidential_service_config(config)
                group = next(g for g in GROUPS if SCOPES[g] == config.service_scope)
                origin = urlsplit(config.issuer)
                if (
                    group in configs
                    or origin.scheme != "https"
                    or not origin.hostname
                    or origin.username
                    or origin.password
                    or origin.path
                    or origin.query
                    or origin.fragment
                    or origin.netloc != origin.netloc.lower()
                    or config.token_endpoint_audience != config.issuer + TOKEN_PATH
                    or config.service_resource_audience != config.issuer + PREFIX + "/" + group
                    or config.service_purpose != PURPOSES[group]
                    or config.client_id != first.client_id
                    or config.service_principal != first.service_principal
                    or config.issuer != first.issuer
                ):
                    raise ValueError
                configs[group] = config
            object.__setattr__(self, "_configs", MappingProxyType(configs))
        except Exception:
            raise MobileIngressConfigurationError() from None

    def issue(self, assertion, scope):
        group = next((g for g in GROUPS if SCOPES[g] == scope), None)
        if group is None:
            raise CredentialDenied("credential denied")
        return issue_service_access_token(
            assertion,
            config=self._configs[group],
            replay_consumer=self.replay,
            signing_key=self.service_signing_key,
            signing_kid=self.service_signing_kid,
        )

    def authenticate(self, command, service_token):
        """Verify before any authority-dependent database operation."""
        group = COMMANDS[command][0]
        return verify_service_access_token(service_token, config=self._configs[group])

    def execute(self, command, data, *, service_token, viewer_token=None):
        self.authenticate(command, service_token)
        group = COMMANDS[command][0]
        if group == "invalidate":
            self.lifecycle.invalidate_original(viewer_token)
            return dict(schema="hodlxxi.social_mobile_generation_invalidation.v1", version=1, status="invalidated")
        if group in {"phone", "exchange"}:
            return self._phone(command, data)
        authority = self.lifecycle.resolve(viewer_token)
        owner = dict(session_id=authority.session_id, subject=authority.subject)
        if command == "legacy/reserve":
            context = secrets.token_hex(32)
            result = protocol.parse_json(self.mobile.reserve_legacy(data["content"], login_context=context, **owner))
            return dict(schema="hodlxxi.social_mobile_legacy_reservation.v1", version=1, loginContext=context, **result)
        if command == "qr/create":
            offer, qr = self.mobile.create_pairing(
                desktop_context=secrets.token_hex(32), revision=secrets.token_hex(32), **owner
            )
            return dict(
                schema="hodlxxi.social_mobile_pairing_creation.v1", version=1, offer=public_snapshot(offer), qr=qr
            )
        method = protocol.LEGACY if command.startswith("legacy/") else protocol.QR
        operation_id = data["operationId"] if method == protocol.LEGACY else data["pairingId"]
        context = self.mobile.original_context(operation_id, method=method, **owner)
        if command in {"legacy/accept", "qr/accept"}:
            return protocol.parse_json(
                self.mobile.accept(
                    operation_id,
                    data["proof"],
                    method=method,
                    context_id=context,
                    authorization_digest=data["authorizationDigest"],
                    revision=data.get("revision"),
                    **owner,
                )
            )
        if command in {"legacy/status", "qr/status"}:
            return protocol.parse_json(self.mobile.status(operation_id, method=method, context_id=context, **owner))
        if command in {"legacy/close", "qr/close"}:
            return dict(
                status=self.mobile.close(
                    operation_id,
                    method=method,
                    context_id=context,
                    status=data["status"],
                    **owner,
                )
            )
        if command == "qr/snapshot":
            return public_snapshot(
                self.mobile.pairing_snapshot(
                    operation_id,
                    desktop_context=context,
                    revision=data["revision"],
                    **owner,
                )
            )
        if command == "qr/claim":
            return dict(
                status=self.mobile.claim_approval(
                    operation_id,
                    desktop_context=context,
                    revision=data["revision"],
                    authorization_digest=data["authorizationDigest"],
                    human_code=data["humanCode"],
                    **owner,
                )
            )
        raise protocol.MobileAuthorizationUnavailable()

    def _phone(self, command, data):
        if command == "qr/offer":
            return public_snapshot(self.mobile.pairing_offer_for_scan(qr=data["qr"]))
        if command == "qr/scan":
            return public_snapshot(
                self.mobile.scan_pairing(
                    data["source"],
                    qr=data["qr"],
                    possession_proof=data["possessionProof"],
                )
            )
        if command == "phone/recover":
            return protocol.parse_json(
                self.mobile.recover_pairing_proposal(
                    data["source"],
                    qr=data["qr"],
                    possession_proof=data["possessionProof"],
                    verifier=data["verifier"],
                    revision=data["revision"],
                )
            )
        options = dict(
            verifier=data["verifier"], revision=data["revision"], authorization_digest=data["authorizationDigest"]
        )
        if command == "phone/status":
            return protocol.parse_json(self.mobile.phone_status(data["pairingId"], **options))
        if command == "phone/exchange":
            return protocol.parse_json(self.mobile.exchange_delivery(data["pairingId"], **options))
        raise protocol.MobileAuthorizationUnavailable()


def install_mobile_ingress(app, runtime, *, enabled=False):
    """Explicit composition only. Disabled performs no import/registration."""
    if enabled is False:
        return False
    if enabled is not True or type(runtime) is not MobileAuthorizationIngress or EXTENSION in app.extensions:
        raise MobileIngressConfigurationError()
    from app.blueprints.internal_social_mobile_authorization import internal_social_mobile_authorization_bp

    app.register_blueprint(internal_social_mobile_authorization_bp)
    app.extensions[EXTENSION] = runtime
    return True

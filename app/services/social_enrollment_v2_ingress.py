"""Explicit confidential V2 ingress. Nothing is installed by the app factory."""

import time
from dataclasses import dataclass
from types import MappingProxyType

from app.services.confidential_service_assertion_replay_storage import PostgresConfidentialServiceAssertionReplayStore
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    CredentialDenied,
    issue_service_access_token,
    validate_confidential_service_config,
    verify_service_access_token,
)
from app.services.social_enrollment_v2_authenticated_composition import AuthenticatedEnrollmentV2Composition
from app.services.social_enrollment_v2_challenge import CommittedEnrollmentChallenge, EnrollmentV2ChallengeComposition
from app.services.social_enrollment_v2_ingress_schema import COMMANDS, PREFIX, PURPOSES, SCOPES, TOKEN_PATH
from app.services.social_enrollment_v2_runtime_composition import CommittedFinalization, CommittedReservation

EXTENSION = "social_enrollment_v2_ingress_v1"
RUNTIME_ENABLED = False
DM_TRANSPORT_ENABLED = False


class EnrollmentIngressUnavailable(ValueError):
    def __init__(self):
        super().__init__("social enrollment v2 unavailable")


@dataclass(frozen=True, repr=False)
class EnrollmentV2Ingress:
    service_configs: tuple[ConfidentialServiceConfig, ...]
    service_signing_key: object
    service_signing_kid: str
    challenge: EnrollmentV2ChallengeComposition
    operations: AuthenticatedEnrollmentV2Composition
    replay: PostgresConfidentialServiceAssertionReplayStore

    def __post_init__(self):
        try:
            if (
                type(self.service_configs) is not tuple
                or len(self.service_configs) != len(COMMANDS)
                or type(self.challenge) is not EnrollmentV2ChallengeComposition
                or type(self.operations) is not AuthenticatedEnrollmentV2Composition
                or type(self.replay) is not PostgresConfidentialServiceAssertionReplayStore
                or self.replay._session_factory is not self.challenge._factory
                or type(self.service_signing_kid) is not str
                or not self.service_signing_kid
            ):
                raise ValueError
            rc = self.operations.composition._config.reservation_config
            ec, cc = rc.evidence_config, self.challenge.config
            if (cc.client_id, cc.backend_id, cc.service_principal, cc.issuer, cc.audience) != (
                ec.client_id,
                rc.backend_id,
                ec.service_principal,
                ec.issuer,
                rc.verification_audience,
            ) or cc.enabled is not True:
                raise ValueError
            configs = {}
            for supplied in self.service_configs:
                if type(supplied) is not ConfidentialServiceConfig:
                    raise ValueError
                cfg = ConfidentialServiceConfig(
                    **{name: getattr(supplied, name) for name in supplied.__dataclass_fields__}
                )
                validate_confidential_service_config(cfg)
                command = next(name for name in COMMANDS if cfg.service_scope == SCOPES[name])
                if (
                    command in configs
                    or cfg.clock_skew_seconds != 0
                    or (cfg.client_id, cfg.service_principal, cfg.issuer)
                    != (rc.backend_id, ec.service_principal, ec.issuer)
                    or cfg.token_endpoint_audience != ec.issuer + TOKEN_PATH
                    or cfg.service_resource_audience != ec.issuer + PREFIX + "/" + command
                    or cfg.service_purpose != PURPOSES[command]
                ):
                    raise ValueError
                configs[command] = cfg
            object.__setattr__(self, "_configs", MappingProxyType(configs))
            return
        except Exception:
            pass
        raise EnrollmentIngressUnavailable() from None

    def issue(self, assertion, scope):
        command = next((name for name in COMMANDS if SCOPES[name] == scope), None)
        if command is None:
            raise CredentialDenied("credential denied")
        return issue_service_access_token(
            assertion,
            config=self._configs[command],
            replay_consumer=self.replay,
            signing_key=self.service_signing_key,
            signing_kid=self.service_signing_kid,
        )

    def authenticate(self, command, service_token):
        if type(command) is not str or command not in COMMANDS:
            raise CredentialDenied("credential denied")
        at = int(time.time())
        verified = verify_service_access_token(service_token, config=self._configs[command], now=at)
        if not verified.issued_at <= at < verified.expires_at:
            raise CredentialDenied("credential denied")

    def execute(self, command, data, *, service_token, viewer_token):
        self.authenticate(command, service_token)  # No participant database before service authentication.
        if command == "challenge":
            value = self.challenge.challenge(data["issuanceId"], viewer_bearer=viewer_token)
        elif command == "reserve":
            value = self.operations.reserve(
                data["verificationInputWire"], issuance_id=data["issuanceId"], viewer_bearer=viewer_token
            )
        else:
            value = self.operations.finalize(
                viewer_bearer=viewer_token,
                issuance_id=data["issuanceId"],
                reservation_id=data["reservationId"],
                reservation_revision=1,
                verification_input_wire=data["verificationInputWire"],
                evidence_compact_jws=data["evidenceCompactJws"],
                statement_compact_jws=data["statementCompactJws"],
            )
        self.authenticate(command, service_token)  # Expired delivery publishes no result, even after commit.
        return public_result(command, value)


def public_result(command, value):
    expected = {
        "challenge": CommittedEnrollmentChallenge,
        "reserve": CommittedReservation,
        "finalize": CommittedFinalization,
    }.get(command)
    if (
        expected is None
        or type(value) is not expected
        or value.publication_status != "committed"
        or value.final_admission != "denied"
        or value.bearer_authority != "none"
    ):
        raise EnrollmentIngressUnavailable()
    common = dict(
        schema="hodlxxi.social_enrollment_v2_" + command + "_publication.v1",
        version=1,
        publicationStatus="committed",
        finalAdmission="denied",
        bearerAuthority="none",
    )
    if command == "challenge":
        common.update(
            contextWire=value.context_wire,
            enrollmentWire=value.enrollment_wire,
            approvalEventWire=value.approval_event_wire,
            challengeRevision=value.challenge_revision,
            issuedAt=value.issued_at,
            expiresAt=value.expires_at,
        )
    elif command == "reserve":
        common.update(
            evidenceCompactJws=value.evidence_compact_jws,
            reservationId=value.reservation_id,
            observedAt=value.observed_at,
            expiresAt=value.expires_at,
        )
    else:
        if type(value.historical_recovery) is not bool:
            raise EnrollmentIngressUnavailable()
        common.update(receiptWire=value.receipt_wire, historicalRecovery=value.historical_recovery)
    return common


def install_enrollment_v2_ingress(app, runtime, *, enabled=False):
    if enabled is False:
        return False
    if enabled is not True or type(runtime) is not EnrollmentV2Ingress or EXTENSION in app.extensions:
        raise EnrollmentIngressUnavailable()
    from app.blueprints.internal_social_enrollment_v2 import internal_social_enrollment_v2_bp

    app.register_blueprint(internal_social_enrollment_v2_bp)
    app.extensions[EXTENSION] = runtime
    return True

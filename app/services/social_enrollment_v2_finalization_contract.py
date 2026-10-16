"""Dormant V2 finalization configuration; no detached acceptance authority."""

from dataclasses import dataclass, field
from functools import wraps

from app.services import social_preaccepted_enrollment_verification_statement_v2 as statement
from app.services.social_enrollment_v2_reservation_contract import ReservationConfig, _freeze_config

RUNTIME_ENABLED = False
FINAL_ADMISSION = "denied"
DENIED_MESSAGE = "social enrollment v2 finalization denied"


class FinalizationDenied(ValueError):
    def __init__(self):
        super().__init__(DENIED_MESSAGE)


def _deny():
    raise FinalizationDenied()


def _sanitized(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            if args and hasattr(args[0], "_poison"):
                try:
                    args[0]._poison()
                except Exception:
                    pass
        _deny()

    return call


@dataclass(frozen=True, slots=True, repr=False)
class StatementTrustPin:
    """Server-owned immutable registration, retained for historical recovery."""

    key_id: str
    fingerprint: str
    revision: int
    not_before: int
    not_after: int
    revoked_at: int | None = None

    @_sanitized
    def __post_init__(self):
        statement._configured_identifier(self.key_id)
        if type(self.fingerprint) is not str or not self.fingerprint.startswith("sha256:"):
            _deny()
        statement._hex64(self.fingerprint[7:])
        statement._integer(self.revision, positive=True)
        statement._integer(self.not_before)
        statement._integer(self.not_after, positive=True)
        if self.not_before >= self.not_after:
            _deny()
        if self.revoked_at is not None:
            statement._integer(self.revoked_at)


@dataclass(frozen=True, slots=True, repr=False)
class FinalizationConfig:
    enabled: bool = False
    reservation_config: ReservationConfig = field(default_factory=ReservationConfig)
    statement_config: statement.SocialPreacceptedEnrollmentVerificationStatementV2Config = field(
        default_factory=statement.SocialPreacceptedEnrollmentVerificationStatementV2Config
    )
    statement_pins: tuple[StatementTrustPin, ...] = ()

    @_sanitized
    def __post_init__(self):
        if type(self.enabled) is not bool:
            _deny()
        rc = _freeze_config(self.reservation_config)
        sc = self.statement_config
        if type(sc) is not statement.SocialPreacceptedEnrollmentVerificationStatementV2Config:
            _deny()
        sc = statement.SocialPreacceptedEnrollmentVerificationStatementV2Config(
            enabled=sc.enabled,
            issuer=sc.issuer,
            audience=sc.audience,
            client_id=sc.client_id,
            service_principal=sc.service_principal,
            purpose=sc.purpose,
            trusted_jwks=tuple(dict(jwk) for jwk in sc.trusted_jwks),
            freshness_profile=sc.freshness_profile,
        )
        if type(self.statement_pins) is not tuple or any(type(p) is not StatementTrustPin for p in self.statement_pins):
            _deny()
        pins = tuple(
            StatementTrustPin(p.key_id, p.fingerprint, p.revision, p.not_before, p.not_after, p.revoked_at)
            for p in self.statement_pins
        )
        object.__setattr__(self, "reservation_config", rc)
        object.__setattr__(self, "statement_config", sc)
        object.__setattr__(self, "statement_pins", pins)
        if not self.enabled and not rc.enabled and not sc.enabled and not pins:
            return
        if (
            not rc.enabled
            or not sc.enabled
            or sc.freshness_profile != rc.evidence_config.freshness_profile
            or sc.issuer != rc.verification_audience
            or sc.client_id != rc.evidence_config.client_id
            or sc.service_principal != rc.evidence_config.service_principal
            or sc.audience != rc.evidence_config.issuer + statement.STATEMENT_CONSUME_PATH
            or len(pins) != len(sc.trusted_jwks)
            or len({p.key_id for p in pins}) != len(pins)
        ):
            _deny()
        actual = {(key.kid, key.fingerprint) for key in sc._keys}
        if {(p.key_id, p.fingerprint) for p in pins} != actual:
            _deny()


@_sanitized
def freeze_config(config):
    if type(config) is not FinalizationConfig:
        _deny()
    return FinalizationConfig(config.enabled, config.reservation_config, config.statement_config, config.statement_pins)


@dataclass(frozen=True, slots=True, repr=False)
class FinalizationResult:
    receipt_wire: str
    historical_recovery: bool
    publication_status: str = field(default="provisional_until_caller_commit", init=False)
    final_admission: str = field(default=FINAL_ADMISSION, init=False)
    runtime_enabled: bool = field(default=RUNTIME_ENABLED, init=False)
    bearer_authority: str = field(default="none", init=False)

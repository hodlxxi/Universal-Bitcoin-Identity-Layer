"""Dormant reservation configuration and non-sensitive public result contract.

Configuration is server-owned. Pure validation creates no signing authority.
"""

from dataclasses import dataclass, field
from functools import wraps

from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence

RUNTIME_ENABLED = False
FINAL_ADMISSION = "denied"
DENIED_MESSAGE = "social enrollment v2 reservation denied"


class ReservationDenied(ValueError):
    def __init__(self):
        super().__init__(DENIED_MESSAGE)


def _deny():
    raise ReservationDenied()


def _sanitized(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            if args and hasattr(args[0], "_poison"):
                args[0]._poison()
        # Raise outside the handler: sensitive exception context is not retained.
        _deny()

    return call


@_sanitized
def dedicated_reservation_key_id(*, key_fingerprint, trust_revision, not_before, not_after):
    """Operational kid policy, using the existing SPKI fingerprint (no new hash).

    The canonical protected header signs this identifier. Encoding immutable
    registration fields prevents same-key revision/lifetime relabeling even if
    an administrator replaces an independent pin. Revocation is always denial.
    This pure configuration helper supplies no signing/current authority.
    """
    if type(key_fingerprint) is not str or not key_fingerprint.startswith("sha256:"):
        _deny()
    fingerprint = evidence._hex64(key_fingerprint[7:])
    revision = evidence._integer(trust_revision, positive=True)
    before, after = evidence._integer(not_before), evidence._integer(not_after, positive=True)
    if before >= after:
        _deny()
    return evidence._configured_identifier(f"ubid-v2-reservation-r{revision}-{fingerprint}-{before}-{after}")


@dataclass(frozen=True, slots=True, repr=False)
class ReservationConfig:
    enabled: bool = False
    backend_id: str = ""
    verification_audience: str = ""
    selected_kid: str = ""
    selected_revision: int = 0
    evidence_config: evidence.MessagingDeviceVerificationDeadlineEvidenceV1Config = field(
        default_factory=evidence.MessagingDeviceVerificationDeadlineEvidenceV1Config
    )
    # Durable operational registry identity: a kid has ONE immutable registration.
    # Pins must be retained independently of current issuance selection.
    trust_pins: tuple[tuple[str, int, str], ...] = ()

    @_sanitized
    def __post_init__(self):
        if (
            type(self.enabled) is not bool
            or type(self.evidence_config) is not evidence.MessagingDeviceVerificationDeadlineEvidenceV1Config
        ):
            _deny()
        if (
            not self.enabled
            and (
                self.backend_id,
                self.verification_audience,
                self.selected_kid,
                self.selected_revision,
                self.trust_pins,
            )
            == ("", "", "", 0, ())
            and not self.evidence_config.enabled
        ):
            return
        evidence._configured_identifier(self.backend_id)
        evidence._https_origin(self.verification_audience)
        evidence._configured_identifier(self.selected_kid)
        evidence._integer(self.selected_revision, positive=True)
        if type(self.trust_pins) is not tuple or not self.evidence_config.enabled:
            _deny()
        expected = tuple(
            sorted((r.key_id, r.trust_revision, r.trust_record_id) for r in self.evidence_config.trust_records)
        )
        if self.trust_pins != expected:
            _deny()
        for record in self.evidence_config.trust_records:
            if record.key_id != dedicated_reservation_key_id(
                key_fingerprint=record.key_fingerprint,
                trust_revision=record.trust_revision,
                not_before=record.not_before,
                not_after=record.not_after,
            ):
                _deny()
        self.selected_trust()

    @_sanitized
    def selected_trust(self):
        if not self.enabled:
            _deny()
        records = [
            r
            for r in self.evidence_config.trust_records
            if (r.key_id, r.trust_revision) == (self.selected_kid, self.selected_revision)
        ]
        if len(records) != 1 or records[0].revoked_at is not None:
            _deny()
        return records[0]


@_sanitized
def _freeze_config(value):
    """Reparse public trust; caller-mutated cached RSA objects are not config."""
    if type(value) is not ReservationConfig:
        _deny()
    ec = value.evidence_config
    if (
        type(ec) is not evidence.MessagingDeviceVerificationDeadlineEvidenceV1Config
        or type(ec.trust_records) is not tuple
    ):
        _deny()
    records = []
    for record in ec.trust_records:
        if type(record) is not evidence.DeadlineEvidenceTrustRecordV1:
            _deny()
        records.append(
            evidence.DeadlineEvidenceTrustRecordV1(
                dict(record.public_jwk),
                record.trust_revision,
                record.not_before,
                record.not_after,
                record.revoked_at,
            )
        )
    frozen_evidence = evidence.MessagingDeviceVerificationDeadlineEvidenceV1Config(
        enabled=ec.enabled,
        issuer=ec.issuer,
        audience=ec.audience,
        client_id=ec.client_id,
        service_principal=ec.service_principal,
        purpose=ec.purpose,
        trust_records=tuple(records),
        freshness_profile=ec.freshness_profile,
    )
    return ReservationConfig(
        enabled=value.enabled,
        backend_id=value.backend_id,
        verification_audience=value.verification_audience,
        selected_kid=value.selected_kid,
        selected_revision=value.selected_revision,
        evidence_config=frozen_evidence,
        trust_pins=value.trust_pins,
    )


@dataclass(frozen=True, slots=True, repr=False)
class ProvisionalReservation:
    evidence_compact_jws: str = field(repr=False)
    reservation_id: str = field(repr=False)
    observed_at: int
    expires_at: int
    provisional_until_caller_commit: bool = field(default=True, init=False)
    final_admission: str = field(default=FINAL_ADMISSION, init=False)

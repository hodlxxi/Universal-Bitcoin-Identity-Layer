"""Explicit purpose-specific RS256 port; no provider/key discovery or fallback."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence
from app.services.social_enrollment_v2_reservation_authority import NativeReservationAuthority
from app.services.social_enrollment_v2_reservation_contract import ReservationConfig, _deny, _freeze_config, _sanitized

RUNTIME_ENABLED = False
SIGNER_PROVISIONED = False


class DedicatedRS256EvidenceSigner:
    """Receives an already-held RSA private object and exact dedicated trust.

    The injected server registry, not this port, owns custody/rotation policy.
    No raw bytes/dictionaries, generic OAuth provider, filename or env selector.
    """

    @_sanitized
    def __init__(self, *, private_key, config):
        config = _freeze_config(config)
        if (
            type(config) is not ReservationConfig
            or not config.enabled
            or not isinstance(private_key, rsa.RSAPrivateKey)
        ):
            _deny()
        trust = config.selected_trust()
        if private_key.public_key().public_numbers() != trust._key.public_key.public_numbers():
            _deny()
        self._key = private_key
        self._trust = trust
        self._config = config

    @_sanitized
    def sign(self, candidate, *, owner):
        # Invalid input never invokes the private-key operation. Valid authority
        # is one-use even when signing/persistence later fails.
        try:
            if type(owner) is not NativeReservationAuthority or owner.config != self._config:
                _deny()
            record = owner._claim_signing(candidate)
            if (
                record.trust != self._trust
                or self._key.public_key().public_numbers() != self._trust._key.public_key.public_numbers()
            ):
                _deny()
            header = evidence.canonical_messaging_device_verification_deadline_evidence_protected_header_v1_bytes(
                kid=self._trust.key_id
            ).decode("ascii")
            signing_input = evidence.messaging_device_verification_deadline_evidence_signing_input_v1(
                protected_header_wire=header, payload_wire=record.payload_wire
            )
            signature = self._key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            compact = evidence.compact_messaging_device_verification_deadline_evidence_v1(
                protected_header_wire=header, payload_wire=record.payload_wire, signature=signature
            )
            owner._signed(candidate)
            evidence.verify_messaging_device_verification_deadline_evidence_v1(
                compact, config=self._config.evidence_config, expected_input_wire=record.input_wire, now=owner.now()
            )
            owner._candidate(candidate, "signed")
            return compact
        except Exception:
            if type(owner) is NativeReservationAuthority:
                owner._poison()
        _deny()

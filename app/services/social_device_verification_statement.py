"""Dormant, explicitly injected authentication of Social's exact V1 statement.

This authenticates a purpose-bound attestation, not current authority or final
admission. There is no I/O, ambient clock, key provisioning or replay state.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, NoReturn, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from jwt.algorithms import RSAAlgorithm

from app.services import social_messaging_device_admission_contract as contract

RUNTIME_ENABLED = False
CURRENT_AUTHORITY = "not_evaluated"
CHALLENGE_CONSUMPTION = "not_implemented"
FINAL_ADMISSION = "denied"
DENIED_MESSAGE = "social device verification statement denied"
_PUBLIC_JWK_FIELDS = frozenset(("kty", "use", "alg", "kid", "n", "e"))


class SocialDeviceVerificationStatementDenied(ValueError):
    """One non-sensitive failure for disabled, malformed and untrusted inputs."""

    def __init__(self) -> None:
        super().__init__(DENIED_MESSAGE)


def _deny() -> NoReturn:
    raise SocialDeviceVerificationStatementDenied()


@dataclass(frozen=True, slots=True, repr=False)
class _TrustedRSAKey:
    kid: str
    public_key: rsa.RSAPublicKey
    fingerprint: str


def _public_key(value: Mapping[str, object]) -> _TrustedRSAKey:
    # A closed vocabulary rejects ALL private parameters (including oth and k),
    # embedded keys, certificates, remote locators and alternate key formats.
    if set(value) != _PUBLIC_JWK_FIELDS or any(type(item) is not str for item in value.values()):
        _deny()
    if value["kty"] != "RSA" or value["use"] != "sig" or value["alg"] != contract.STATEMENT_ALGORITHM:
        _deny()
    kid = contract._configured_identifier(value["kid"])
    for name, maximum in (("n", 1366), ("e", 16)):
        encoded = value[name]
        if not isinstance(encoded, str) or not 1 <= len(encoded) <= maximum:
            _deny()
        raw = contract._base64url_decode(encoded)
        if raw[0] == 0:  # JWK Base64urlUInt must use its minimal unsigned form.
            _deny()
    key = RSAAlgorithm.from_jwk(json.dumps(dict(value)))
    if not isinstance(key, rsa.RSAPublicKey) or not 2048 <= key.key_size <= 8192:
        _deny()
    numbers = key.public_numbers()
    if numbers.n % 2 != 1 or numbers.e % 2 != 1 or not 3 <= numbers.e < numbers.n:
        _deny()
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return _TrustedRSAKey(kid, key, "sha256:" + hashlib.sha256(spki).hexdigest())


@dataclass(frozen=True, slots=True, repr=False)
class SocialDeviceVerificationStatementConfig:
    """Dedicated public trust registration; no generic service-token authority.

    The empty default is disabled. Supplied registrations are validated eagerly,
    even when disabled, and copied before retention. Only public RSA JWKs with
    the six exact fields kty/use/alg/kid/n/e are accepted.
    """

    enabled: bool = False
    issuer: str = ""
    audience: str = ""
    client_id: str = ""
    service_principal: str = ""
    purpose: str = contract.STATEMENT_PURPOSE
    trusted_jwks: tuple[Mapping[str, object], ...] = field(default=(), repr=False)
    _keys: tuple[_TrustedRSAKey, ...] = field(default=(), init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            if type(self.enabled) is not bool or type(self.trusted_jwks) is not tuple:
                _deny()
            if type(self.purpose) is not str or self.purpose != contract.STATEMENT_PURPOSE:
                _deny()
            identities = (self.issuer, self.audience, self.client_id, self.service_principal)
            if any(type(value) is not str for value in identities):
                _deny()
            if not self.enabled and identities == ("", "", "", "") and not self.trusted_jwks:
                return
            contract._audience(self.issuer)
            contract._statement_audience(self.audience)
            contract._configured_identifier(self.client_id)
            contract._configured_identifier(self.service_principal)
            if not self.trusted_jwks:
                _deny()
            copies = []
            keys = []
            kids = set()
            for supplied in self.trusted_jwks:
                if type(supplied) not in (dict, MappingProxyType):
                    _deny()
                copied = dict(supplied)
                key = _public_key(copied)
                if key.kid in kids:
                    _deny()
                kids.add(key.kid)
                copies.append(MappingProxyType(copied))
                keys.append(key)
            object.__setattr__(self, "trusted_jwks", tuple(copies))
            object.__setattr__(self, "_keys", tuple(keys))
            return
        except Exception:
            pass
        # Raise outside the handler: no internal exception chain is exposed.
        _deny()


@dataclass(frozen=True, slots=True, init=False, repr=False)
class AuthenticatedSocialDeviceVerificationStatementV1:
    """Narrow authenticated facts, constructible only by the verifier API.

    No bearer, Current-Full, session, binding, consumption, operation or receipt
    capability is conveyed. Python reflection is not a process trust boundary.
    """

    issuer: str
    audience: str
    client_id: str
    service_principal: str
    purpose: str
    result: str
    challenge_kind: str
    challenge_id: str
    attempt_id: str
    context_digest: str
    input_digest: str
    issued_at: int
    expires_at: int
    token_id: str
    key_id: str
    key_fingerprint: str

    def __new__(cls, *args: object, **kwargs: object) -> AuthenticatedSocialDeviceVerificationStatementV1:
        _deny()

    def __init_subclass__(cls, **kwargs: object) -> None:
        _deny()


def verify_social_device_verification_statement_v1(
    statement: object,
    *,
    config: SocialDeviceVerificationStatementConfig = SocialDeviceVerificationStatementConfig(),
    expected_context_wire: object,
    expected_input_wire: object,
    now: object,
    challenge_expires_at: object,
    session_expires_at: object,
    approver_session_expires_at: object = None,
) -> AuthenticatedSocialDeviceVerificationStatementV1:
    """Authenticate exact bytes against explicit trust, bindings and deadlines.

    The future atomic caller must obtain wires/deadlines from authoritative
    state and recheck current authority after waits. Repeated verification is
    intentionally stateless and does not consume a challenge or authorize use.
    """
    try:
        if type(config) is not SocialDeviceVerificationStatementConfig or config.enabled is not True:
            _deny()
        if type(statement) is not str or not 1 <= len(statement) <= contract.MAX_STATEMENT_BYTES:
            _deny()
        if not statement.isascii() or statement.count(".") != 2:
            _deny()
        # Reuse PR 1's closed canonical parser for selection, then invoke its
        # complete inspection with the selected trusted kid. Never use jwt.decode.
        protected = contract._base64url_decode(statement.split(".")[0]).decode("ascii")
        header = contract._closed_json(protected, {"alg", "kid", "typ"}, 1024)
        matches = [key for key in config._keys if key.kid == header["kid"]]
        if len(matches) != 1:
            _deny()
        key = matches[0]
        inspected = contract.inspect_verification_statement_shape_v1(
            statement,
            expected_kid=key.kid,
            expected_issuer=config.issuer,
            expected_audience=config.audience,
            expected_client_id=config.client_id,
            expected_service_principal=config.service_principal,
            expected_context_wire=expected_context_wire,
            expected_input_wire=expected_input_wire,
            now=now,
            challenge_expires_at=challenge_expires_at,
            session_expires_at=session_expires_at,
            approver_session_expires_at=approver_session_expires_at,
        )
        claims = inspected.claims
        # PR 1 checks injected deadlines. Also bound the statement to the exact
        # already-canonical embedded challenge, even if a caller supplies a later
        # deadline. These reads never rebuild the signed header or payload.
        challenge = json.loads(json.loads(cast(str, expected_input_wire))["challenge"])
        if claims.issued_at < challenge["issuedAt"] or claims.expires_at > challenge["expiresAt"]:
            _deny()
        if len(inspected.signature) != (key.public_key.key_size + 7) // 8:
            _deny()
        key.public_key.verify(inspected.signature, inspected.signing_input, padding.PKCS1v15(), hashes.SHA256())

        # There is deliberately no public constructor or shape-to-result helper.
        # This allocation is reachable only after both inspection and RSA verify.
        result = object.__new__(AuthenticatedSocialDeviceVerificationStatementV1)
        for name in contract.VerificationStatementClaimsV1.__dataclass_fields__:
            object.__setattr__(result, name, getattr(claims, name))
        object.__setattr__(result, "purpose", config.purpose)
        object.__setattr__(result, "key_id", key.kid)
        object.__setattr__(result, "key_fingerprint", key.fingerprint)
        return result
    except Exception:
        pass
    _deny()


__all__ = [
    "AuthenticatedSocialDeviceVerificationStatementV1",
    "SocialDeviceVerificationStatementConfig",
    "SocialDeviceVerificationStatementDenied",
    "verify_social_device_verification_statement_v1",
]

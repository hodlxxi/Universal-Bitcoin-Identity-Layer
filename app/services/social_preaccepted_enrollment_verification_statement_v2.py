"""Dormant authenticated consumer for Social's exact V2 statement.

This module freezes canonical statement bytes and authenticates one exact
preaccepted-enrollment V2 input.  It performs no I/O, discovers no keys or
clock, consumes no challenge, persists no acceptance, and grants no authority.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import weakref
from dataclasses import FrozenInstanceError, dataclass, field
from types import MappingProxyType
from typing import Mapping, NamedTuple, NoReturn, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.services import social_messaging_mobile_pre_enrollment_v2 as preacceptance

VERSION = 2
STATEMENT_SCHEMA = "hodlxxi.social_preaccepted_enrollment_verification_statement.v2"
STATEMENT_ALGORITHM = "RS256"
STATEMENT_TYPE = "hodlxxi-social-preaccepted-enrollment-verification-v2+jws"
STATEMENT_PURPOSE = "social_preaccepted_enrollment_cryptographic_verification_v2"
STATEMENT_RESULT = "preaccepted-enrollment-v2-bip340-and-ed25519-valid"
STATEMENT_JTI_DOMAIN = "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_JTI_V2"
STATEMENT_CONSUME_PATH = "/internal/v2/social/device-admission/consume"

MAX_STATEMENT_BYTES = 4_096
MAX_PROTECTED_HEADER_BYTES = 1_024
MAX_PAYLOAD_BYTES = 3_072
MAX_STATEMENT_LIFETIME_MS = 10_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991

RUNTIME_ENABLED = False
DURABLE_ACCEPTANCE = "not_established"
CURRENT_AUTHORITY = "not_evaluated"
CHALLENGE_CONSUMPTION = "not_implemented"
ASSOCIATION_COMMITMENT = "not_implemented"
FINAL_ADMISSION = "denied"
RECEIPT = "not_issued"
DENIED_MESSAGE = "social preaccepted enrollment verification statement denied"

_PUBLIC_JWK_FIELDS = frozenset(("kty", "use", "alg", "kid", "n", "e"))
_HEADER_FIELDS = {"alg", "kid", "typ"}
_PAYLOAD_WITHOUT_JTI_FIELDS = {
    "acceptanceId",
    "associationId",
    "aud",
    "attemptId",
    "clientId",
    "enrollmentChallengeId",
    "expiresAt",
    "inputDigest",
    "iss",
    "issuedAt",
    "purpose",
    "result",
    "schema",
    "servicePrincipal",
    "version",
}
_PAYLOAD_FIELDS = _PAYLOAD_WITHOUT_JTI_FIELDS | {"jti"}
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z").fullmatch
_HEX64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_INPUT_DIGEST = re.compile(
    r"hodlxxi-social-preaccepted-enrollment-verification-input-v2-sha256:[0-9a-f]{64}\Z"
).fullmatch
_CONFIGURED_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}\Z").fullmatch


class SocialPreacceptedEnrollmentVerificationStatementV2Denied(ValueError):
    """The one bounded, non-sensitive public failure."""

    def __init__(self) -> None:
        super().__init__(DENIED_MESSAGE)


def _deny() -> NoReturn:
    raise SocialPreacceptedEnrollmentVerificationStatementV2Denied() from None


def _canonical(value: Mapping[str, object]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _closed_json(source: object, fields: set[str], maximum: int) -> dict[str, object]:
    try:
        if type(source) is not str:
            raise ValueError
        encoded = source.encode("ascii")
        if not 1 <= len(encoded) <= maximum or any(byte < 0x20 or byte > 0x7E for byte in encoded):
            raise ValueError

        def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in items:
                if type(key) is not str or key in result:
                    raise ValueError
                result[key] = value
            return result

        def invalid_constant(_value: str) -> NoReturn:
            raise ValueError

        value = json.loads(source, object_pairs_hook=pairs, parse_constant=invalid_constant)
        if type(value) is not dict or set(value) != fields or _canonical(value) != source:
            raise ValueError
        return cast(dict[str, object], value)
    except Exception:
        pass
    _deny()


def _integer(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER or positive and value == 0:
        _deny()
    return cast(int, value)


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX64(value) is None:
        _deny()
    return cast(str, value)


def _configured_identifier(value: object) -> str:
    if type(value) is not str or _CONFIGURED_IDENTIFIER(value) is None:
        _deny()
    return cast(str, value)


def _canonical_ipv6_hex(address: ipaddress.IPv6Address) -> str:
    raw = int(address)
    groups = [(raw >> shift) & 0xFFFF for shift in range(112, -1, -16)]
    best_start = best_length = run_start = run_length = 0
    for index, group in enumerate(groups):
        if group == 0:
            if run_length == 0:
                run_start = index
            run_length += 1
            if run_length > best_length:
                best_start, best_length = run_start, run_length
        else:
            run_length = 0
    encoded = [format(group, "x") for group in groups]
    if best_length < 2:
        return ":".join(encoded)
    return ":".join(encoded[:best_start]) + "::" + ":".join(encoded[best_start + best_length :])


def _https_origin(value: object) -> str:
    try:
        if type(value) is not str or not value.isascii() or not 1 <= len(value) <= 255:
            raise ValueError
        match = re.fullmatch(r"https://(\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::([0-9]+))?", value)
        if match is None:
            raise ValueError
        host, port = match.groups()
        if port is not None and (re.fullmatch(r"[1-9][0-9]{0,4}", port) is None or int(port) > 65535 or port == "443"):
            raise ValueError
        if host.startswith("["):
            if _canonical_ipv6_hex(ipaddress.IPv6Address(host[1:-1])) != host[1:-1]:
                raise ValueError
        else:
            labels = host.split(".")
            if len(labels) == 4 and all(re.fullmatch(r"[0-9]+", label) for label in labels):
                if str(ipaddress.IPv4Address(host)) != host:
                    raise ValueError
            elif re.fullmatch(r"[0-9]+|0x[0-9a-f]*", labels[-1]) or any(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None or label.startswith("xn--")
                for label in labels
            ):
                raise ValueError
        return cast(str, value)
    except Exception:
        pass
    _deny()


def _statement_audience(value: object) -> str:
    if type(value) is not str or not value.endswith(STATEMENT_CONSUME_PATH):
        _deny()
    _https_origin(value[: -len(STATEMENT_CONSUME_PATH)])
    return cast(str, value)


def _base64url_encode(source: bytes) -> str:
    return base64.urlsafe_b64encode(source).decode("ascii").rstrip("=")


def _base64url_decode(source: object) -> bytes:
    try:
        if type(source) is not str or _BASE64URL(source) is None or "=" in source:
            raise ValueError
        decoded = base64.urlsafe_b64decode(source + "=" * ((4 - len(source) % 4) % 4))
        if not decoded or _base64url_encode(decoded) != source:
            raise ValueError
        return decoded
    except Exception:
        pass
    _deny()


@dataclass(frozen=True, slots=True, repr=False)
class _TrustedRSAKeyV2:
    kid: str
    public_key: rsa.RSAPublicKey
    fingerprint: str


def _public_key(value: Mapping[str, object]) -> _TrustedRSAKeyV2:
    try:
        if set(value) != _PUBLIC_JWK_FIELDS or any(type(item) is not str for item in value.values()):
            raise ValueError
        if value["kty"] != "RSA" or value["use"] != "sig" or value["alg"] != STATEMENT_ALGORITHM:
            raise ValueError
        kid = _configured_identifier(value["kid"])
        integers: dict[str, int] = {}
        for name, maximum in (("n", 1_366), ("e", 16)):
            encoded = cast(str, value[name])
            if not 1 <= len(encoded) <= maximum:
                raise ValueError
            raw = _base64url_decode(encoded)
            if raw[0] == 0:
                raise ValueError
            integers[name] = int.from_bytes(raw, "big")
        modulus = integers["n"]
        exponent = integers["e"]
        if (
            not 2_048 <= modulus.bit_length() <= 8_192
            or modulus % 2 != 1
            or exponent < 65_537
            or exponent % 2 != 1
            or exponent >= modulus
        ):
            raise ValueError
        key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size != modulus.bit_length():
            raise ValueError
        spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return _TrustedRSAKeyV2(kid, key, "sha256:" + hashlib.sha256(spki).hexdigest())
    except Exception:
        pass
    _deny()


@dataclass(frozen=True, slots=True, repr=False)
class SocialPreacceptedEnrollmentVerificationStatementV2Config:
    """Dedicated V2 public RSA trust; the empty default is disabled."""

    enabled: bool = False
    issuer: str = ""
    audience: str = ""
    client_id: str = ""
    service_principal: str = ""
    purpose: str = STATEMENT_PURPOSE
    trusted_jwks: tuple[Mapping[str, object], ...] = field(default=(), repr=False)
    _keys: tuple[_TrustedRSAKeyV2, ...] = field(default=(), init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            if type(self.enabled) is not bool or type(self.trusted_jwks) is not tuple:
                raise ValueError
            if type(self.purpose) is not str or self.purpose != STATEMENT_PURPOSE:
                raise ValueError
            identities = (self.issuer, self.audience, self.client_id, self.service_principal)
            if any(type(value) is not str for value in identities):
                raise ValueError
            if not self.enabled and identities == ("", "", "", "") and not self.trusted_jwks:
                return
            _https_origin(self.issuer)
            _statement_audience(self.audience)
            _configured_identifier(self.client_id)
            _configured_identifier(self.service_principal)
            if not self.trusted_jwks:
                raise ValueError
            copies: list[Mapping[str, object]] = []
            keys: list[_TrustedRSAKeyV2] = []
            kids: set[str] = set()
            for supplied in self.trusted_jwks:
                if type(supplied) not in (dict, MappingProxyType):
                    raise ValueError
                copied = dict(supplied)
                key = _public_key(copied)
                if key.kid in kids:
                    raise ValueError
                kids.add(key.kid)
                copies.append(MappingProxyType(copied))
                keys.append(key)
            object.__setattr__(self, "trusted_jwks", tuple(copies))
            object.__setattr__(self, "_keys", tuple(keys))
            return
        except Exception:
            pass
        _deny()


@dataclass(frozen=True, slots=True, repr=False)
class _ExpectedBindingsV2:
    input_wire: str
    context_wire: str
    input_digest: str
    acceptance_id: str
    association_id: str
    enrollment_challenge_id: str
    attempt_id: str
    issuer: str
    enrollment_issued_at: int
    enrollment_expires_at: int
    pre_enrollment_expires_at: int
    x25519_binding_expires_at: int


def _expected_bindings(expected_context_wire: object, expected_input_wire: object) -> _ExpectedBindingsV2:
    if type(expected_context_wire) is not str or type(expected_input_wire) is not str:
        _deny()
    parsed = preacceptance.parse_preaccepted_enrollment_verification_input_v2(expected_input_wire)
    if parsed.context.wire != expected_context_wire:
        _deny()
    envelope = parsed.approval.envelope
    return _ExpectedBindingsV2(
        input_wire=cast(str, expected_input_wire),
        context_wire=cast(str, expected_context_wire),
        input_digest=preacceptance.preaccepted_enrollment_verification_input_v2_digest(expected_input_wire),
        acceptance_id=parsed.acceptance_id,
        association_id=parsed.association_id,
        enrollment_challenge_id=parsed.enrollment.enrollment_challenge_id,
        attempt_id=parsed.context.attempt_id,
        issuer=parsed.context.audience,
        enrollment_issued_at=parsed.enrollment.issued_at,
        enrollment_expires_at=parsed.enrollment.expires_at,
        pre_enrollment_expires_at=envelope.pre_enrollment.expires_at,
        x25519_binding_expires_at=envelope.x25519_binding_expires_at_ms,
    )


def _payload_without_jti_values(
    *,
    issuer: object,
    audience: object,
    client_id: object,
    service_principal: object,
    expected_context_wire: object,
    expected_input_wire: object,
    issued_at: object,
    expires_at: object,
) -> dict[str, object]:
    bindings = _expected_bindings(expected_context_wire, expected_input_wire)
    normalized_issuer = _https_origin(issuer)
    issued = _integer(issued_at)
    expires = _integer(expires_at)
    if (
        normalized_issuer != bindings.issuer
        or expires <= issued
        or expires - issued > MAX_STATEMENT_LIFETIME_MS
        or issued < bindings.enrollment_issued_at
        or expires
        > min(
            bindings.enrollment_expires_at,
            bindings.pre_enrollment_expires_at,
            bindings.x25519_binding_expires_at,
        )
    ):
        _deny()
    return {
        "acceptanceId": bindings.acceptance_id,
        "associationId": bindings.association_id,
        "aud": _statement_audience(audience),
        "attemptId": bindings.attempt_id,
        "clientId": _configured_identifier(client_id),
        "enrollmentChallengeId": bindings.enrollment_challenge_id,
        "expiresAt": expires,
        "inputDigest": bindings.input_digest,
        "iss": normalized_issuer,
        "issuedAt": issued,
        "purpose": STATEMENT_PURPOSE,
        "result": STATEMENT_RESULT,
        "schema": STATEMENT_SCHEMA,
        "servicePrincipal": _configured_identifier(service_principal),
        "version": VERSION,
    }


def _jti_from_values(value: Mapping[str, object]) -> str:
    return hashlib.sha256(STATEMENT_JTI_DOMAIN.encode("ascii") + b"\0" + _canonical(value).encode("ascii")).hexdigest()


def canonical_preaccepted_enrollment_verification_statement_protected_header_v2_bytes(*, kid: object) -> bytes:
    try:
        source = _canonical({"alg": STATEMENT_ALGORITHM, "kid": _configured_identifier(kid), "typ": STATEMENT_TYPE})
        _parse_protected_header(source)
        return source.encode("ascii")
    except Exception:
        pass
    _deny()


def canonical_preaccepted_enrollment_verification_statement_payload_without_jti_v2_bytes(
    *,
    issuer: object,
    audience: object,
    client_id: object,
    service_principal: object,
    expected_context_wire: object,
    expected_input_wire: object,
    issued_at: object,
    expires_at: object,
) -> bytes:
    try:
        values = _payload_without_jti_values(
            issuer=issuer,
            audience=audience,
            client_id=client_id,
            service_principal=service_principal,
            expected_context_wire=expected_context_wire,
            expected_input_wire=expected_input_wire,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        source = _canonical(values)
        _closed_json(source, _PAYLOAD_WITHOUT_JTI_FIELDS, MAX_PAYLOAD_BYTES)
        return source.encode("ascii")
    except Exception:
        pass
    _deny()


def preaccepted_enrollment_verification_statement_jti_v2(payload_without_jti_wire: object) -> str:
    try:
        value = _closed_json(payload_without_jti_wire, _PAYLOAD_WITHOUT_JTI_FIELDS, MAX_PAYLOAD_BYTES)
        _parse_payload_without_jti(value)
        return _jti_from_values(value)
    except Exception:
        pass
    _deny()


def canonical_preaccepted_enrollment_verification_statement_payload_v2_bytes(
    *,
    issuer: object,
    audience: object,
    client_id: object,
    service_principal: object,
    expected_context_wire: object,
    expected_input_wire: object,
    issued_at: object,
    expires_at: object,
) -> bytes:
    try:
        without_jti = canonical_preaccepted_enrollment_verification_statement_payload_without_jti_v2_bytes(
            issuer=issuer,
            audience=audience,
            client_id=client_id,
            service_principal=service_principal,
            expected_context_wire=expected_context_wire,
            expected_input_wire=expected_input_wire,
            issued_at=issued_at,
            expires_at=expires_at,
        ).decode("ascii")
        values = _closed_json(without_jti, _PAYLOAD_WITHOUT_JTI_FIELDS, MAX_PAYLOAD_BYTES)
        source = _canonical({**values, "jti": _jti_from_values(values)})
        _parse_payload(_closed_json(source, _PAYLOAD_FIELDS, MAX_PAYLOAD_BYTES))
        return source.encode("ascii")
    except Exception:
        pass
    _deny()


def compact_preaccepted_enrollment_verification_statement_v2(
    *, protected_header_wire: object, payload_wire: object, signature: object
) -> str:
    try:
        if type(protected_header_wire) is not str or type(payload_wire) is not str or type(signature) is not bytes:
            raise ValueError
        if not signature:
            raise ValueError
        _parse_protected_header(protected_header_wire)
        _parse_payload(_closed_json(payload_wire, _PAYLOAD_FIELDS, MAX_PAYLOAD_BYTES))
        statement = ".".join(
            (
                _base64url_encode(protected_header_wire.encode("ascii")),
                _base64url_encode(payload_wire.encode("ascii")),
                _base64url_encode(signature),
            )
        )
        if len(statement.encode("ascii")) > MAX_STATEMENT_BYTES:
            raise ValueError
        return statement
    except Exception:
        pass
    _deny()


def _parse_protected_header(source: object) -> dict[str, object]:
    value = _closed_json(source, _HEADER_FIELDS, MAX_PROTECTED_HEADER_BYTES)
    if (
        value["alg"] != STATEMENT_ALGORITHM
        or value["typ"] != STATEMENT_TYPE
        or _configured_identifier(value["kid"]) != value["kid"]
    ):
        _deny()
    return value


def _parse_payload_without_jti(value: Mapping[str, object]) -> None:
    if (
        value["schema"] != STATEMENT_SCHEMA
        or type(value["version"]) is not int
        or value["version"] != VERSION
        or value["purpose"] != STATEMENT_PURPOSE
        or value["result"] != STATEMENT_RESULT
        or type(value["inputDigest"]) is not str
        or _INPUT_DIGEST(cast(str, value["inputDigest"])) is None
    ):
        _deny()
    _https_origin(value["iss"])
    _statement_audience(value["aud"])
    _configured_identifier(value["clientId"])
    _configured_identifier(value["servicePrincipal"])
    _hex64(value["acceptanceId"])
    _hex64(value["associationId"])
    _hex64(value["enrollmentChallengeId"])
    _hex64(value["attemptId"])
    issued = _integer(value["issuedAt"])
    expires = _integer(value["expiresAt"])
    if expires <= issued or expires - issued > MAX_STATEMENT_LIFETIME_MS:
        _deny()


def _parse_payload(value: Mapping[str, object]) -> None:
    without_jti = {name: value[name] for name in _PAYLOAD_WITHOUT_JTI_FIELDS}
    _parse_payload_without_jti(without_jti)
    if _hex64(value["jti"]) != _jti_from_values(without_jti):
        _deny()


class _AuthenticatedSnapshotV2(NamedTuple):
    issuer: str
    audience: str
    client_id: str
    service_principal: str
    purpose: str
    result: str
    acceptance_id: str
    association_id: str
    enrollment_challenge_id: str
    attempt_id: str
    input_digest: str
    issued_at: int
    expires_at: int
    token_id: str
    key_id: str
    key_fingerprint: str


class AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2:
    """Read-only view of exact internally registered authenticated facts."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls, *args: object, **kwargs: object
    ) -> AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2:
        _deny()

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise FrozenInstanceError(f"cannot assign to field {name!r}")

    def __eq__(self, other: object) -> bool:
        if type(other) is not AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2:
            return False
        try:
            return _authenticated_snapshot(self) == _authenticated_snapshot(other)
        except SocialPreacceptedEnrollmentVerificationStatementV2Denied:
            return self is other

    def __init_subclass__(cls, **kwargs: object) -> None:
        _deny()

    def __copy__(self) -> NoReturn:
        _deny()

    def __deepcopy__(self, memo: object) -> NoReturn:
        _deny()

    def __reduce__(self) -> NoReturn:
        _deny()

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        _deny()

    @property
    def issuer(self) -> str:
        return _authenticated_snapshot(self).issuer

    @property
    def audience(self) -> str:
        return _authenticated_snapshot(self).audience

    @property
    def client_id(self) -> str:
        return _authenticated_snapshot(self).client_id

    @property
    def service_principal(self) -> str:
        return _authenticated_snapshot(self).service_principal

    @property
    def purpose(self) -> str:
        return _authenticated_snapshot(self).purpose

    @property
    def result(self) -> str:
        return _authenticated_snapshot(self).result

    @property
    def acceptance_id(self) -> str:
        return _authenticated_snapshot(self).acceptance_id

    @property
    def association_id(self) -> str:
        return _authenticated_snapshot(self).association_id

    @property
    def enrollment_challenge_id(self) -> str:
        return _authenticated_snapshot(self).enrollment_challenge_id

    @property
    def attempt_id(self) -> str:
        return _authenticated_snapshot(self).attempt_id

    @property
    def input_digest(self) -> str:
        return _authenticated_snapshot(self).input_digest

    @property
    def issued_at(self) -> int:
        return _authenticated_snapshot(self).issued_at

    @property
    def expires_at(self) -> int:
        return _authenticated_snapshot(self).expires_at

    @property
    def token_id(self) -> str:
        return _authenticated_snapshot(self).token_id

    @property
    def key_id(self) -> str:
        return _authenticated_snapshot(self).key_id

    @property
    def key_fingerprint(self) -> str:
        return _authenticated_snapshot(self).key_fingerprint


_AUTHENTIC_RESULTS: dict[
    int,
    tuple[
        weakref.ReferenceType[AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2],
        _AuthenticatedSnapshotV2,
    ],
] = {}


def _register_authenticated(
    value: AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2,
    snapshot: _AuthenticatedSnapshotV2,
) -> None:
    identity = id(value)

    def remove(
        reference: weakref.ReferenceType[AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2],
    ) -> None:
        registered = _AUTHENTIC_RESULTS.get(identity)
        if registered is not None and registered[0] is reference:
            _AUTHENTIC_RESULTS.pop(identity, None)

    _AUTHENTIC_RESULTS[identity] = (weakref.ref(value, remove), snapshot)


def _authenticated_snapshot(value: object) -> _AuthenticatedSnapshotV2:
    if type(value) is not AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2:
        _deny()
    registered = _AUTHENTIC_RESULTS.get(id(value))
    if registered is None or registered[0]() is not value:
        _deny()
    return registered[1]


def project_authenticated_social_preaccepted_enrollment_verification_statement_v2(
    value: object,
) -> Mapping[str, object]:
    """Project facts only from the exact internally registered result object."""

    try:
        authenticated = _authenticated_snapshot(value)
        return MappingProxyType(
            {
                "acceptanceId": authenticated.acceptance_id,
                "associationCommitment": "not_implemented",
                "associationId": authenticated.association_id,
                "attemptId": authenticated.attempt_id,
                "audience": authenticated.audience,
                "authority": "not-granted",
                "challengeConsumption": "not_implemented",
                "clientId": authenticated.client_id,
                "currentAuthority": "not_evaluated",
                "durableAcceptance": "not_established",
                "enrollmentChallengeId": authenticated.enrollment_challenge_id,
                "expiresAt": authenticated.expires_at,
                "finalAdmission": "denied",
                "inputDigest": authenticated.input_digest,
                "issuedAt": authenticated.issued_at,
                "issuer": authenticated.issuer,
                "keyFingerprint": authenticated.key_fingerprint,
                "keyId": authenticated.key_id,
                "purpose": authenticated.purpose,
                "receipt": "not_issued",
                "result": authenticated.result,
                "runtimeEnabled": False,
                "servicePrincipal": authenticated.service_principal,
                "tokenId": authenticated.token_id,
            }
        )
    except Exception:
        pass
    _deny()


def verify_social_preaccepted_enrollment_verification_statement_v2(
    statement: object,
    *,
    config: SocialPreacceptedEnrollmentVerificationStatementV2Config = (
        SocialPreacceptedEnrollmentVerificationStatementV2Config()
    ),
    expected_context_wire: object,
    expected_input_wire: object,
    now: object,
    phone_session_expires_at_ms: object,
    approver_session_expires_at_ms: object,
    full_expires_at_ms: object,
    x25519_binding_expires_at_ms: object,
) -> AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2:
    """Authenticate one exact V2 input without consuming or persisting it."""

    try:
        if type(config) is not SocialPreacceptedEnrollmentVerificationStatementV2Config or config.enabled is not True:
            raise ValueError
        if type(statement) is not str:
            raise ValueError
        encoded = statement.encode("ascii")
        if (
            not 1 <= len(encoded) <= MAX_STATEMENT_BYTES
            or any(byte < 0x20 or byte > 0x7E for byte in encoded)
            or statement.count(".") != 2
        ):
            raise ValueError
        protected_segment, payload_segment, signature_segment = statement.split(".")
        protected_wire = _base64url_decode(protected_segment).decode("ascii")
        header = _parse_protected_header(protected_wire)
        matches = [key for key in config._keys if key.kid == header["kid"]]
        if len(matches) != 1:
            raise ValueError
        key = matches[0]

        payload_wire = _base64url_decode(payload_segment).decode("ascii")
        payload = _closed_json(payload_wire, _PAYLOAD_FIELDS, MAX_PAYLOAD_BYTES)
        _parse_payload(payload)
        bindings = _expected_bindings(expected_context_wire, expected_input_wire)
        expected_payload = canonical_preaccepted_enrollment_verification_statement_payload_v2_bytes(
            issuer=config.issuer,
            audience=config.audience,
            client_id=config.client_id,
            service_principal=config.service_principal,
            expected_context_wire=bindings.context_wire,
            expected_input_wire=bindings.input_wire,
            issued_at=payload["issuedAt"],
            expires_at=payload["expiresAt"],
        ).decode("ascii")
        if payload_wire != expected_payload:
            raise ValueError

        current = _integer(now)
        phone_deadline = _integer(phone_session_expires_at_ms, positive=True)
        approver_deadline = _integer(approver_session_expires_at_ms, positive=True)
        full_deadline = _integer(full_expires_at_ms, positive=True)
        binding_deadline = _integer(x25519_binding_expires_at_ms, positive=True)
        preacceptance.validate_preaccepted_enrollment_time_v2(
            bindings.input_wire,
            now_ms=current,
            phone_session_expires_at_ms=phone_deadline,
            approver_session_expires_at_ms=approver_deadline,
            full_expires_at_ms=full_deadline,
            x25519_binding_expires_at_ms=binding_deadline,
        )
        issued_at = cast(int, payload["issuedAt"])
        expires_at = cast(int, payload["expiresAt"])
        if (
            not issued_at <= current < expires_at
            or binding_deadline != bindings.x25519_binding_expires_at
            or expires_at
            > min(
                bindings.enrollment_expires_at,
                bindings.pre_enrollment_expires_at,
                phone_deadline,
                approver_deadline,
                full_deadline,
                binding_deadline,
            )
        ):
            raise ValueError

        signature = _base64url_decode(signature_segment)
        if len(signature) != (key.public_key.key_size + 7) // 8:
            raise ValueError
        signing_input = (protected_segment + "." + payload_segment).encode("ascii")
        key.public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())

        snapshot = _AuthenticatedSnapshotV2(
            issuer=cast(str, payload["iss"]),
            audience=cast(str, payload["aud"]),
            client_id=cast(str, payload["clientId"]),
            service_principal=cast(str, payload["servicePrincipal"]),
            purpose=cast(str, payload["purpose"]),
            result=cast(str, payload["result"]),
            acceptance_id=cast(str, payload["acceptanceId"]),
            association_id=cast(str, payload["associationId"]),
            enrollment_challenge_id=cast(str, payload["enrollmentChallengeId"]),
            attempt_id=cast(str, payload["attemptId"]),
            input_digest=cast(str, payload["inputDigest"]),
            issued_at=issued_at,
            expires_at=expires_at,
            token_id=cast(str, payload["jti"]),
            key_id=key.kid,
            key_fingerprint=key.fingerprint,
        )
        result = object.__new__(AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2)
        _register_authenticated(result, snapshot)
        return result
    except Exception:
        pass
    _deny()


__all__ = [
    "ASSOCIATION_COMMITMENT",
    "AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2",
    "CHALLENGE_CONSUMPTION",
    "CURRENT_AUTHORITY",
    "DURABLE_ACCEPTANCE",
    "FINAL_ADMISSION",
    "MAX_STATEMENT_BYTES",
    "MAX_STATEMENT_LIFETIME_MS",
    "RECEIPT",
    "RUNTIME_ENABLED",
    "STATEMENT_ALGORITHM",
    "STATEMENT_CONSUME_PATH",
    "STATEMENT_JTI_DOMAIN",
    "STATEMENT_PURPOSE",
    "STATEMENT_RESULT",
    "STATEMENT_SCHEMA",
    "STATEMENT_TYPE",
    "SocialPreacceptedEnrollmentVerificationStatementV2Config",
    "SocialPreacceptedEnrollmentVerificationStatementV2Denied",
    "canonical_preaccepted_enrollment_verification_statement_payload_v2_bytes",
    "canonical_preaccepted_enrollment_verification_statement_payload_without_jti_v2_bytes",
    "canonical_preaccepted_enrollment_verification_statement_protected_header_v2_bytes",
    "compact_preaccepted_enrollment_verification_statement_v2",
    "preaccepted_enrollment_verification_statement_jti_v2",
    "project_authenticated_social_preaccepted_enrollment_verification_statement_v2",
    "verify_social_preaccepted_enrollment_verification_statement_v2",
]

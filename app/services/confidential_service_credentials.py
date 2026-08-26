"""Pure, disabled-by-default confidential service credential boundary.

This module deliberately provides no HTTP route, application wiring, key loading,
or replay-store implementation.  All trust inputs are explicit dependencies.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping, Sequence

import jwt
from jwt.algorithms import RSAAlgorithm

from app.services.bearer_credentials import DEFAULT_MAX_BEARER_LENGTH, has_compact_jwt_shape

ALGORITHM = "RS256"
SERVICE_SCOPE = "social:full-directory:read"
ASSERTION_TOKEN_USE = "client_assertion"
ASSERTION_PURPOSE = "service_client_authentication"
SERVICE_TOKEN_USE = "service_access"
GRANT_TYPE = "client_credentials"
SERVICE_PURPOSE = "social_full_directory_read"
MAX_LIFETIME_SECONDS = 60
MAX_CLOCK_SKEW_SECONDS = 5
MAX_JTI_LENGTH = 128
MAX_KID_LENGTH = 255
RSA_PRIVATE_PARAMETERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")


class CredentialDenied(ValueError):
    """A credential was denied without exposing the reason."""


class CredentialUnavailable(RuntimeError):
    """A required trusted dependency was unavailable."""


@dataclass(frozen=True)
class ConfidentialServiceConfig:
    enabled: bool = False
    client_id: str = ""
    service_principal: str = ""
    issuer: str = ""
    token_endpoint_audience: str = ""
    service_resource_audience: str = ""
    client_jwks: tuple[Mapping[str, object], ...] = ()
    service_jwks: tuple[Mapping[str, object], ...] = ()
    clock_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS
    max_credential_length: int = DEFAULT_MAX_BEARER_LENGTH

    def __post_init__(self) -> None:
        # Copy the public key records so later caller mutation cannot change the
        # trusted configuration. MappingProxyType also prevents mutation through
        # the configuration object itself.
        for name in ("client_jwks", "service_jwks"):
            keys = getattr(self, name)
            if not isinstance(keys, tuple) or any(not isinstance(key, Mapping) for key in keys):
                object.__setattr__(self, name, ())
                continue
            object.__setattr__(self, name, tuple(MappingProxyType(dict(key)) for key in keys))


@dataclass(frozen=True)
class VerifiedServiceCredential:
    service_principal: str
    client_id: str
    scope: str
    issued_at: int
    expires_at: int
    token_id: str


ReplayConsumer = Callable[[str, int], bool]


def _deny() -> None:
    raise CredentialDenied("credential denied")


def _configuration(config: ConfidentialServiceConfig) -> None:
    if type(config) is not ConfidentialServiceConfig or config.enabled is not True:
        _deny()
    values = (
        config.client_id,
        config.service_principal,
        config.issuer,
        config.token_endpoint_audience,
        config.service_resource_audience,
    )
    if any(not isinstance(value, str) or not value or value.strip() != value for value in values):
        _deny()
    if (
        isinstance(config.clock_skew_seconds, bool)
        or not isinstance(config.clock_skew_seconds, int)
        or not 0 <= config.clock_skew_seconds <= MAX_CLOCK_SKEW_SECONDS
        or isinstance(config.max_credential_length, bool)
        or not isinstance(config.max_credential_length, int)
        or config.max_credential_length <= 0
        or config.max_credential_length > DEFAULT_MAX_BEARER_LENGTH
    ):
        _deny()
    _ensure_separate_rsa_public_keys(config.client_jwks, config.service_jwks)


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _deny()
    return value


def _identifier(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or value.strip() != value:
        _deny()
    return value


def _rsa_public_parameters(key: Mapping[str, object]) -> tuple[int, int]:
    if key.get("kty") != "RSA" or key.get("use") != "sig" or key.get("alg") != ALGORITHM:
        _deny()
    if any(name in key for name in RSA_PRIVATE_PARAMETERS):
        _deny()
    public_key = RSAAlgorithm.from_jwk(json.dumps(dict(key)))
    numbers = public_key.public_numbers()
    return numbers.n, numbers.e


def _ensure_separate_rsa_public_keys(
    client_jwks: Sequence[Mapping[str, object]], service_jwks: Sequence[Mapping[str, object]]
) -> None:
    client_parameters = {_rsa_public_parameters(key) for key in client_jwks}
    for service_key in service_jwks:
        if _rsa_public_parameters(service_key) in client_parameters:
            _deny()


def _select_rsa_key(encoded: str, keys: Sequence[Mapping[str, object]], maximum: int):
    if not isinstance(encoded, str) or not encoded or len(encoded) > maximum or not has_compact_jwt_shape(encoded):
        _deny()
    header = jwt.get_unverified_header(encoded)
    if not isinstance(header, dict) or header.get("alg") != ALGORITHM:
        _deny()
    kid = _identifier(header.get("kid"), MAX_KID_LENGTH)
    matches = [key for key in keys if isinstance(key, Mapping) and key.get("kid") == kid]
    if len(matches) != 1:
        _deny()
    key = matches[0]
    if key.get("kty") != "RSA" or key.get("use") != "sig" or key.get("alg") != ALGORITHM:
        _deny()
    if any(name in key for name in RSA_PRIVATE_PARAMETERS):
        _deny()
    return RSAAlgorithm.from_jwk(json.dumps(dict(key)))


def _decode(encoded: str, keys: Sequence[Mapping[str, object]], config: ConfidentialServiceConfig) -> dict:
    key = _select_rsa_key(encoded, keys, config.max_credential_length)
    claims = jwt.decode(
        encoded,
        key,
        algorithms=[ALGORITHM],
        options={
            "verify_signature": True,
            "verify_aud": False,
            "verify_iss": False,
            "verify_exp": False,
            "verify_iat": False,
            "verify_nbf": False,
        },
    )
    if not isinstance(claims, dict):
        _deny()
    return claims


def _times(claims: Mapping[str, object], now: int, skew: int) -> tuple[int, int]:
    iat = _integer(claims.get("iat"))
    exp = _integer(claims.get("exp"))
    if exp <= iat or exp - iat > MAX_LIFETIME_SECONDS:
        _deny()
    if iat > now + skew or exp < now - skew or iat < now - MAX_LIFETIME_SECONDS - skew:
        _deny()
    if "nbf" in claims and _integer(claims["nbf"]) > now + skew:
        _deny()
    return iat, exp


def validate_client_assertion(
    encoded_assertion: str, *, config: ConfidentialServiceConfig, now: int | None = None
) -> tuple[str, int]:
    """Cryptographically verify one private_key_jwt client assertion."""
    try:
        _configuration(config)
        current = int(time.time()) if now is None else _integer(now)
        claims = _decode(encoded_assertion, config.client_jwks, config)
        _, exp = _times(claims, current, config.clock_skew_seconds)
        if not all(
            (
                claims.get("iss") == config.client_id,
                claims.get("sub") == config.client_id,
                claims.get("aud") == config.token_endpoint_audience,
                isinstance(claims.get("aud"), str),
                claims.get("token_use") == ASSERTION_TOKEN_USE,
                claims.get("grant_type") == GRANT_TYPE,
                claims.get("purpose") == ASSERTION_PURPOSE,
            )
        ):
            _deny()
        return _identifier(claims.get("jti"), MAX_JTI_LENGTH), exp
    except CredentialDenied:
        raise
    except Exception:
        pass
    _deny()


def issue_service_access_token(
    encoded_assertion: str,
    *,
    config: ConfidentialServiceConfig,
    replay_consumer: ReplayConsumer | None,
    signing_key: object,
    signing_kid: str,
    now: int | None = None,
    token_jti: str | None = None,
) -> str:
    """Consume a verified assertion once and issue a domain-separated token."""
    current = int(time.time()) if now is None else _integer(now)
    assertion_jti, assertion_exp = validate_client_assertion(encoded_assertion, config=config, now=current)
    if not callable(replay_consumer):
        raise CredentialUnavailable("credential service unavailable")
    replay_retention_deadline = assertion_exp + MAX_CLOCK_SKEW_SECONDS + 1
    try:
        consumed = replay_consumer(assertion_jti, replay_retention_deadline)
    except Exception:
        consumed = False
    if consumed is not True:
        raise CredentialUnavailable("credential service unavailable")
    jti = _identifier(token_jti if token_jti is not None else uuid.uuid4().hex, MAX_JTI_LENGTH)
    kid = _identifier(signing_kid, MAX_KID_LENGTH)
    payload = {
        "iss": config.issuer,
        "aud": config.service_resource_audience,
        "sub": config.service_principal,
        "azp": config.client_id,
        "scope": SERVICE_SCOPE,
        "grant_type": GRANT_TYPE,
        "token_use": SERVICE_TOKEN_USE,
        "purpose": SERVICE_PURPOSE,
        "iat": current,
        "exp": current + MAX_LIFETIME_SECONDS,
        "jti": jti,
    }
    try:
        return jwt.encode(payload, signing_key, algorithm=ALGORITHM, headers={"kid": kid})
    except Exception:
        pass
    raise CredentialUnavailable("credential service unavailable")


def verify_service_access_token(
    encoded_token: str, *, config: ConfidentialServiceConfig, now: int | None = None
) -> VerifiedServiceCredential:
    """Verify a service token and return minimal immutable authentication evidence."""
    try:
        _configuration(config)
        current = int(time.time()) if now is None else _integer(now)
        claims = _decode(encoded_token, config.service_jwks, config)
        iat, exp = _times(claims, current, config.clock_skew_seconds)
        exact = (
            ("iss", config.issuer),
            ("aud", config.service_resource_audience),
            ("sub", config.service_principal),
            ("azp", config.client_id),
            ("scope", SERVICE_SCOPE),
            ("grant_type", GRANT_TYPE),
            ("token_use", SERVICE_TOKEN_USE),
            ("purpose", SERVICE_PURPOSE),
        )
        if any(not isinstance(claims.get(name), str) or claims.get(name) != value for name, value in exact):
            _deny()
        return VerifiedServiceCredential(
            config.service_principal,
            config.client_id,
            SERVICE_SCOPE,
            iat,
            exp,
            _identifier(claims.get("jti"), MAX_JTI_LENGTH),
        )
    except CredentialDenied:
        raise
    except Exception:
        pass
    _deny()


__all__ = [
    "ConfidentialServiceConfig",
    "CredentialDenied",
    "CredentialUnavailable",
    "VerifiedServiceCredential",
    "issue_service_access_token",
    "validate_client_assertion",
    "verify_service_access_token",
]

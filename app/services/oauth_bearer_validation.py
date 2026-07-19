"""Fail-closed validation for canonical OAuth access tokens."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from flask import current_app

from app.auth_api_core import canonical_xonly_pubkey
from app.db_storage import get_canonical_jwt_record_by_jti
from app.jwks import get_key_by_kid
from app.services.oauth_scope_policy import RESERVED_SCOPES, SCOPE_POLICY_VERSION, parse_scopes, serialize_scopes

TOKEN_CONTRACT = "hodlxxi.oauth.access-token.v1"
MAX_BEARER_LENGTH = 16 * 1024
MAX_JTI_LENGTH = 128
MAX_KID_LENGTH = 255
_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
_REQUIRED = ("iss", "aud", "sub", "iat", "exp", "jti", "scope", "token_use", "token_contract")


class BearerValidationError(ValueError):
    """A canonical credential is not valid for authorization."""


@dataclass(frozen=True)
class BearerPrincipal:
    subject: str
    user_id: str
    client_id: str
    scopes: frozenset[str]
    jti: str
    issued_at: datetime
    expires_at: datetime
    token_contract: str


def _reject() -> None:
    raise BearerValidationError("invalid canonical access token")


def _integer_date(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _reject()
    return value


def validate_canonical_access_token(
    encoded_token: str, *, expected_client_id: str | None = None
) -> BearerPrincipal:
    """Validate one locally issued canonical JWT without writing state."""
    try:
        if not isinstance(encoded_token, str) or not encoded_token or len(encoded_token) > MAX_BEARER_LENGTH:
            _reject()
        segments = encoded_token.split(".")
        if len(segments) != 3 or not all(segments) or not all(_SEGMENT.fullmatch(part) for part in segments):
            _reject()

        header = jwt.get_unverified_header(encoded_token)
        if not isinstance(header, dict) or header.get("alg") != "RS256":
            _reject()
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > MAX_KID_LENGTH:
            _reject()

        unverified = jwt.decode(encoded_token, options={"verify_signature": False})
        if not isinstance(unverified, dict):
            _reject()
        jti = unverified.get("jti")
        audience = unverified.get("aud")
        if not isinstance(jti, str) or not jti or len(jti) > MAX_JTI_LENGTH:
            _reject()
        if not isinstance(audience, str) or not audience:
            _reject()

        record = get_canonical_jwt_record_by_jti(jti)
        if not isinstance(record, dict):
            _reject()
        record_client = record.get("client_id")
        if not isinstance(record_client, str) or not record_client or audience != record_client:
            _reject()
        if expected_client_id is not None and expected_client_id != record_client:
            _reject()

        cfg = current_app.config.get("APP_CONFIG")
        if not isinstance(cfg, dict):
            _reject()
        issuer = str(cfg.get("JWT_ISSUER") or "").rstrip("/")
        jwks_dir = cfg.get("JWKS_DIR")
        if not issuer or not isinstance(jwks_dir, (str, bytes)):
            _reject()
        key = get_key_by_kid(str(jwks_dir), kid)
        if key is None:
            _reject()
        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        claims = jwt.decode(
            encoded_token,
            public_key,
            algorithms=["RS256"],
            audience=record_client,
            issuer=issuer,
            leeway=30,
            options={"require": list(_REQUIRED), "verify_iat": True},
        )
        if not isinstance(claims.get("aud"), str) or claims["aud"] != record_client:
            _reject()
        if claims.get("jti") != jti or claims.get("token_use") != "access":
            _reject()
        if claims.get("token_contract") != TOKEN_CONTRACT:
            _reject()
        subject = claims.get("sub")
        if not isinstance(subject, str) or subject != canonical_xonly_pubkey(subject):
            _reject()
        scopes = parse_scopes(claims.get("scope"))
        if scopes & RESERVED_SCOPES:
            _reject()
        canonical_scope = serialize_scopes(scopes)
        if claims.get("scope") != canonical_scope:
            _reject()
        exp = _integer_date(claims.get("exp"))
        iat = _integer_date(claims.get("iat"))
        issued_at = datetime.fromtimestamp(iat, timezone.utc)
        expires_at = datetime.fromtimestamp(exp, timezone.utc).replace(tzinfo=None)

        user = record.get("user")
        metadata = record.get("metadata")
        expected_metadata = {
            "token_contract": TOKEN_CONTRACT,
            "token_use": "access",
            "issuer": issuer,
            "audience": record_client,
            "kid": kid,
            "digest_algorithm": "sha256",
            "scope_policy_version": SCOPE_POLICY_VERSION,
        }
        digest = hashlib.sha256(encoded_token.encode("ascii")).hexdigest()
        stored_digest = record.get("digest")
        if not isinstance(stored_digest, str) or not hmac.compare_digest(stored_digest, digest):
            _reject()
        if not isinstance(user, dict) or user.get("is_active") is not True:
            _reject()
        user_id = user.get("id")
        if not isinstance(user_id, str) or user_id != record.get("user_id"):
            _reject()
        user_subject = user.get("pubkey")
        if not isinstance(user_subject, str) or user_subject != subject:
            _reject()
        if not all(
            (
                record.get("jti") == jti,
                record.get("scope") == canonical_scope,
                record.get("expires_at") == expires_at,
                record.get("is_revoked") is False,
                metadata == expected_metadata,
            )
        ):
            _reject()
        return BearerPrincipal(subject, user_id, record_client, scopes, jti, issued_at, expires_at, TOKEN_CONTRACT)
    except BearerValidationError:
        raise
    except Exception as exc:
        raise BearerValidationError("invalid canonical access token") from exc

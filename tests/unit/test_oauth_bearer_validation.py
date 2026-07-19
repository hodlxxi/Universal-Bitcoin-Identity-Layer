from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.db_storage import create_user, store_canonical_jwt_record
from app.config import get_config
from app.jwks import get_signing_key
from app.services.bearer_credentials import (
    BearerHeaderError,
    DEFAULT_MAX_BEARER_LENGTH,
    has_compact_jwt_shape,
    parse_bearer_authorization_header,
)
from app.services.oauth_bearer_validation import (
    MAX_JTI_LENGTH,
    MAX_KID_LENGTH,
    BearerValidationConfig,
    BearerValidationError,
    validate_canonical_access_token_with_config,
)
from app.services.oauth_scope_policy import SCOPE_POLICY_VERSION

SUBJECT = "a" * 64
CONTRACT = "hodlxxi.oauth.access-token.v1"


@pytest.fixture
def canonical_token_factory(monkeypatch):
    cfg = get_config()
    issuer = str(cfg["JWT_ISSUER"]).rstrip("/")
    jwks_dir = str(cfg["JWKS_DIR"])
    kid, key = get_signing_key(jwks_dir)
    validation_config = BearerValidationConfig(issuer=issuer, jwks_dir=jwks_dir)

    def make(*, claims=None, headers=None, signing_key=key, algorithm="RS256", persist=True, record=None):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        client_id = f"canonical-client-{uuid.uuid4().hex}"
        jti = uuid.uuid4().hex
        payload = {
            "iss": issuer,
            "aud": client_id,
            "sub": SUBJECT,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "jti": jti,
            "scope": "self:read",
            "token_use": "access",
            "token_contract": CONTRACT,
        }
        if claims:
            for name, value in claims.items():
                if value is _MISSING:
                    payload.pop(name, None)
                else:
                    payload[name] = value
        token_headers = {"kid": kid}
        if headers:
            for name, value in headers.items():
                if value is _MISSING:
                    token_headers.pop(name, None)
                else:
                    token_headers[name] = value
        token = jwt.encode(payload, signing_key, algorithm=algorithm, headers=token_headers)
        user_id = create_user(SUBJECT)
        default_record = {
            "jti": payload.get("jti"),
            "digest": hashlib.sha256(token.encode("ascii")).hexdigest(),
            "client_id": client_id,
            "user_id": user_id,
            "scope": payload.get("scope"),
            "expires_at": datetime.fromtimestamp(payload.get("exp", 0), timezone.utc).replace(tzinfo=None),
            "is_revoked": False,
            "metadata": {
                "token_contract": CONTRACT,
                "token_use": "access",
                "issuer": issuer,
                "audience": client_id,
                "kid": token_headers.get("kid"),
                "digest_algorithm": "sha256",
                "scope_policy_version": SCOPE_POLICY_VERSION,
            },
            "user": {"id": user_id, "pubkey": SUBJECT, "is_active": True},
        }
        if record:
            record(default_record)
        if persist:
            store_canonical_jwt_record(
                jti=default_record["jti"], digest=default_record["digest"], client_id=default_record["client_id"],
                user_id=default_record["user_id"], scope=default_record["scope"],
                expires_at=default_record["expires_at"], metadata=default_record["metadata"],
            )
        else:
            monkeypatch.setattr(
                "app.services.oauth_bearer_validation.get_canonical_jwt_record_by_jti", lambda _jti: default_record
            )
        return token, payload, default_record, validation_config

    return make


_MISSING = object()


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER", "BeArEr"])
def test_shared_header_parser_accepts_case_insensitive_scheme(scheme):
    assert parse_bearer_authorization_header(f"{scheme} credential") == "credential"


@pytest.mark.parametrize(
    "header",
    [None, "", "Basic value", "Bearer", "Bearer ", " Bearer value", "Bearer  value", "Bearer\tvalue",
     "Bearer value ", "Bearer val ue", "Bearer value,other", "Bearer value,Bearer other"],
)
def test_shared_header_parser_rejects_ambiguous_credentials(header):
    with pytest.raises(BearerHeaderError):
        parse_bearer_authorization_header(header)


def test_shared_header_parser_enforces_size_bound():
    assert parse_bearer_authorization_header("Bearer " + "x" * DEFAULT_MAX_BEARER_LENGTH)
    with pytest.raises(BearerHeaderError):
        parse_bearer_authorization_header("Bearer " + "x" * (DEFAULT_MAX_BEARER_LENGTH + 1))


@pytest.mark.parametrize(
    ("credential", "expected"),
    [("a.b.c", True), ("A_-0.b.c", True), ("a.b", False), ("a.b.c.d", False), ("a..c", False),
     (".b.c", False), ("a.b.", False), ("a.b.c=", False), ("a+b.c.d", False), ("a/b.c.d", False),
     ("a.b.c d", False), ("opaque", False), (None, False)],
)
def test_compact_jwt_classifier_exact_boundary(credential, expected):
    assert has_compact_jwt_shape(credential) is expected


def test_valid_real_canonical_jwt_and_exact_principal(app, canonical_token_factory):
    token, claims, record, config = canonical_token_factory()
    principal = validate_canonical_access_token_with_config(
        token, config=config, expected_client_id=record["client_id"]
    )
    assert principal.subject == SUBJECT
    assert principal.user_id == record["user_id"]
    assert principal.client_id == record["client_id"]
    assert principal.scopes == frozenset({"self:read"})
    assert principal.jti == claims["jti"]
    assert principal.issued_at == datetime.fromtimestamp(claims["iat"], timezone.utc)
    assert principal.expires_at == datetime.fromtimestamp(claims["exp"], timezone.utc).replace(tzinfo=None)
    assert principal.token_contract == CONTRACT


@pytest.mark.parametrize(
    "token",
    [None, "", "x" * (DEFAULT_MAX_BEARER_LENGTH + 1), "opaque", "a..c", "a.b", "a.b.c.d", "a.b.c=", "***.b.c"],
)
def test_rejects_malformed_compact_credentials(token):
    config = BearerValidationConfig("https://issuer.test", "/unneeded")
    with pytest.raises(BearerValidationError):
        validate_canonical_access_token_with_config(token, config=config)


@pytest.mark.parametrize("alg", ["none", "HS256", "ES256", "PS256"])
def test_rejects_every_non_rs256_algorithm(canonical_token_factory, alg):
    token, _, _, config = canonical_token_factory()
    header, payload, signature = token.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(header + "=="))
    decoded["alg"] = alg
    altered = base64.urlsafe_b64encode(json.dumps(decoded).encode()).decode().rstrip("=") + "." + payload + "." + signature
    with pytest.raises(BearerValidationError):
        validate_canonical_access_token_with_config(altered, config=config)


@pytest.mark.parametrize("kid", [_MISSING, "", "x" * (MAX_KID_LENGTH + 1), "unknown-key"])
def test_rejects_missing_empty_oversized_and_unknown_kid(canonical_token_factory, kid):
    token, _, _, config = canonical_token_factory(headers={"kid": kid}, persist=False)
    with pytest.raises(BearerValidationError):
        validate_canonical_access_token_with_config(token, config=config)


def test_rejects_invalid_signature(canonical_token_factory):
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token, _, _, config = canonical_token_factory(signing_key=wrong_key, persist=False)
    with pytest.raises(BearerValidationError):
        validate_canonical_access_token_with_config(token, config=config)


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://wrong.test"}, {"aud": "wrong-client"}, {"aud": ["client"]},
        {"exp": 1}, {"iat": int((datetime.now(timezone.utc) + timedelta(minutes=2)).timestamp())},
        *[{name: _MISSING} for name in ("iss", "aud", "sub", "iat", "exp", "jti", "scope", "token_use", "token_contract")],
        {"jti": ""}, {"jti": "x" * (MAX_JTI_LENGTH + 1)}, {"token_use": "refresh"},
        {"token_contract": "other"}, {"sub": "02" + SUBJECT}, {"sub": SUBJECT.upper()}, {"sub": "bad"},
        {"scope": " self:read"}, {"scope": "unknown"}, {"scope": "read"}, {"scope": "write"},
        {"scope": "admin"}, {"scope": "operator"}, {"scope": "*"}, {"scope": "self:read self:read"},
        {"scope": "self:read profile"}, {"scope": "covenant:draft:create"},
    ],
)
def test_rejects_invalid_claim_contract(canonical_token_factory, claims):
    token, _, _, config = canonical_token_factory(claims=claims, persist=False)
    with pytest.raises(BearerValidationError):
        validate_canonical_access_token_with_config(token, config=config)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r.update(digest="0" * 64), lambda r: r.update(client_id="other"),
        lambda r: r.update(user_id="other"), lambda r: r["user"].update(id="other"),
        lambda r: r["user"].update(pubkey="b" * 64), lambda r: r["user"].update(is_active=False),
        lambda r: r.update(expires_at=r["expires_at"] + timedelta(seconds=1)), lambda r: r.update(is_revoked=True),
        lambda r: r.update(metadata=None), lambda r: r["metadata"].update(token_contract="other"),
        lambda r: r["metadata"].update(issuer="other"), lambda r: r["metadata"].update(audience="other"),
        lambda r: r["metadata"].update(kid="other"), lambda r: r["metadata"].update(digest_algorithm="md5"),
        lambda r: r["metadata"].update(scope_policy_version="other"), lambda r: r.update(scope="profile"),
    ],
)
def test_rejects_issuance_record_disagreement(canonical_token_factory, mutation):
    token, _, _, config = canonical_token_factory(record=mutation, persist=False)
    with pytest.raises(BearerValidationError):
        validate_canonical_access_token_with_config(token, config=config)


def test_missing_record_and_service_failures_fail_closed(canonical_token_factory, monkeypatch, caplog):
    token, claims, _, config = canonical_token_factory(persist=False)
    for outcome in (None, RuntimeError("database unavailable")):
        def load(_jti, value=outcome):
            if isinstance(value, Exception):
                raise value
            return value
        monkeypatch.setattr("app.services.oauth_bearer_validation.get_canonical_jwt_record_by_jti", load)
        with pytest.raises(BearerValidationError):
            validate_canonical_access_token_with_config(token, config=config)
    assert token not in caplog.text
    assert hashlib.sha256(token.encode()).hexdigest() not in caplog.text
    assert claims["jti"] not in caplog.text


def test_expected_client_and_key_loader_failures_fail_closed(canonical_token_factory, monkeypatch):
    token, _, _, config = canonical_token_factory(persist=False)
    with pytest.raises(BearerValidationError):
        validate_canonical_access_token_with_config(token, config=config, expected_client_id="other")
    monkeypatch.setattr("app.services.oauth_bearer_validation.get_key_by_kid", lambda *_: (_ for _ in ()).throw(OSError()))
    with pytest.raises(BearerValidationError):
        validate_canonical_access_token_with_config(token, config=config)

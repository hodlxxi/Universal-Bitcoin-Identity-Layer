"""
OAuth2/OIDC Blueprint - Token Issuance, Authorization, Introspection

Implements OAuth 2.0 and OpenID Connect flows with PKCE.
"""

import logging
import hmac
import base64
import hashlib
import re
import secrets
import time
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from flask import Blueprint, current_app, jsonify, redirect, request, session

from app.audit_logger import get_audit_logger
from app.auth_api_core import canonical_xonly_pubkey
from app.db_storage import (
    consume_oauth_code,
    get_canonical_jwt_record_by_jti,
    get_oauth_client,
    get_oauth_code,
    get_user_by_id,
    store_canonical_jwt_record,
    store_oauth_client,
    store_oauth_code,
    update_oauth_client_secret,
)
from app.services.oauth_scope_policy import (
    PUBLIC_DYNAMIC_SCOPES,
    SCOPE_POLICY_VERSION,
    ScopePolicyError,
    client_allowed_scopes,
    parse_scopes,
    serialize_scopes,
    validate_client_scopes,
)
from app.security import limiter as _limiter
from werkzeug.security import check_password_hash, generate_password_hash


class _NoopLimiter:
    """Fallback when the rate limiter isn't initialized (e.g., unit tests)."""

    def limit(self, *_args, **_kwargs):
        def _decorator(fn):
            return fn

        return _decorator


limiter = _limiter or _NoopLimiter()

from app.tokens import issue_rs256_jwt as _issue_rs256_jwt


def issue_jwt_compat(
    *,
    subject=None,
    sub=None,
    claims=None,
    cfg=None,
    **kwargs,
):
    """
    Compatibility wrapper around RS256 JWT issuer.

    Real function signature:
      _issue_rs256_jwt(sub: str, claims: Optional[dict] = None) -> str

    This wrapper accepts either `subject=` or `sub=` and merges any extra kwargs into claims.
    """
    if sub is None and subject is not None:
        sub = subject
    if sub is None:
        raise TypeError("missing required sub/subject")

    # Merge extra kwargs into claims (safe default)
    merged_claims = {}
    if isinstance(claims, dict):
        merged_claims.update(claims)
    merged_claims.update(kwargs)

    # Map OAuth-style `audience` to JWT `aud` (tests expect aud == client_id)
    if "aud" not in merged_claims and "audience" in merged_claims:
        merged_claims["aud"] = merged_claims.pop("audience")
    # Don't leak compatibility flags into JWT claims.
    merged_claims.pop("id_token", None)

    return _issue_rs256_jwt(
        sub=sub,
        claims=merged_claims or None,
        cfg=cfg,
    )


logger = logging.getLogger(__name__)
audit_logger = get_audit_logger()

oauth_bp = Blueprint("oauth", __name__)

OAUTH_RATE_LIMIT = "30 per minute"
TOKEN_CONTRACT = "hodlxxi.oauth.access-token.v1"
_PKCE_VERIFIER = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_PKCE_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def _verify_client_secret(client: dict, supplied: object) -> bool:
    stored = client.get("client_secret")
    if not isinstance(stored, str) or not isinstance(supplied, str):
        return False
    if stored.startswith(("scrypt:", "pbkdf2:")):
        try:
            return check_password_hash(stored, supplied)
        except (ValueError, TypeError):
            return False
    if not hmac.compare_digest(stored, supplied):
        return False
    update_oauth_client_secret(client["client_id"], stored, generate_password_hash(supplied))
    return True


def _valid_pkce_challenge(value: object) -> bool:
    if not isinstance(value, str) or not _PKCE_CHALLENGE.fullmatch(value):
        return False
    try:
        return len(base64.urlsafe_b64decode(value + "=")) == 32
    except Exception:
        return False


def _verify_pkce(challenge: object, verifier: object) -> bool:
    if not isinstance(verifier, str) or not _PKCE_VERIFIER.fullmatch(verifier):
        return False
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    return isinstance(challenge, str) and hmac.compare_digest(challenge, expected)


def _safe_local_redirect_target(target: str, fallback: str = "/login") -> str:
    """Allow only local relative-path redirects."""
    target = (target or "").strip()
    if not target:
        return fallback
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return fallback
    if not target.startswith("/") or target.startswith("//"):
        return fallback
    return target


# Register endpoint rate limit:
# - production: keep strict
# - TESTING/CI: allow many registrations (tests register clients repeatedly)
OAUTH_REGISTER_RATE_LIMIT = "10 per minute"
try:
    import os

    if os.environ.get("TESTING") == "1" or "PYTEST_CURRENT_TEST" in os.environ:
        OAUTH_REGISTER_RATE_LIMIT = "1000 per minute"
except Exception:
    pass


def _is_loopback_host(hostname: str | None) -> bool:
    return hostname in {"localhost", "127.0.0.1", "::1"}


def _validate_redirect_uris(redirect_uris):
    if not redirect_uris or not isinstance(redirect_uris, list):
        return None, "redirect_uris must be a non-empty array"

    cleaned = []
    for uri in redirect_uris:
        if not isinstance(uri, str):
            return None, "redirect_uris must contain only strings"

        uri = uri.strip()
        if not uri:
            return None, "redirect_uris must not contain empty values"

        if "*" in uri:
            return None, "redirect_uris must not contain wildcards"

        parsed = urlparse(uri)
        if parsed.scheme not in {"https", "http"}:
            return None, "redirect_uris must use https, except localhost http for development"

        if not parsed.hostname:
            return None, "redirect_uris must include a valid host"

        if parsed.username or parsed.password:
            return None, "redirect_uris must not include userinfo"

        if parsed.fragment:
            return None, "redirect_uris must not include fragments"

        if parsed.scheme == "http" and not _is_loopback_host(parsed.hostname):
            return None, "http redirect_uris are only allowed for localhost"

        cleaned.append(uri)

    return cleaned, None


@oauth_bp.route("/register", methods=["POST"])
@limiter.limit(OAUTH_REGISTER_RATE_LIMIT)
def register_client():
    """
    Dynamic OAuth2 client registration (RFC 7591).

    Expected JSON body:
        - client_name: Human-readable client name
        - redirect_uris: Array of redirect URIs
        - grant_types: Array of grant types (default: ["authorization_code"])
        - response_types: Array of response types (default: ["code"])

    Returns:
        JSON with client credentials
    """
    data = request.get_json(silent=True)

    if not data or not data.get("client_name"):
        return jsonify({"error": "client_name is required"}), 400

    redirect_uris, redirect_error = _validate_redirect_uris(data.get("redirect_uris", []))
    if redirect_error:
        return jsonify({"error": redirect_error}), 400

    exact_metadata = {
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
    }
    for field, expected in exact_metadata.items():
        if field in data and data[field] != expected:
            return jsonify({"error": "invalid_client_metadata", "error_description": f"invalid {field}"}), 400
    if "trust_class" in data or (isinstance(data.get("metadata"), dict) and "trust_class" in data["metadata"]):
        return jsonify({"error": "invalid_client_metadata", "error_description": "trust_class is managed"}), 400
    try:
        requested = PUBLIC_DYNAMIC_SCOPES if "scope" not in data else parse_scopes(data["scope"])
        validate_client_scopes(requested, PUBLIC_DYNAMIC_SCOPES)
        # Generate client credentials
        client_id = f"client_{secrets.token_urlsafe(32)}"
        client_secret = secrets.token_urlsafe(48)

        # Store client
        client_data = {
            "client_id": client_id,
            "client_secret": generate_password_hash(client_secret),
            "client_name": data.get("client_name"),
            "redirect_uris": redirect_uris,
            "grant_types": exact_metadata["grant_types"],
            "response_types": exact_metadata["response_types"],
            "scope": serialize_scopes(requested),
            "token_endpoint_auth_method": exact_metadata["token_endpoint_auth_method"],
            "metadata": {"trust_class": "public_dynamic", "scope_policy_version": SCOPE_POLICY_VERSION},
            "client_type": "free",  # Default tier
            "is_active": True,
            "created_at": datetime.now(timezone.utc).replace(tzinfo=None),
        }

        store_oauth_client(client_id, client_data)

        audit_logger.log_event(
            "oauth.client_registered",
            client_id=client_id,
            client_name=client_data["client_name"],
            ip=request.remote_addr,
        )

        # Return client credentials (RFC 7591 response)
        return (
            jsonify(
                {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "client_name": client_data["client_name"],
                    "redirect_uris": redirect_uris,
                    "grant_types": client_data["grant_types"],
                    "response_types": client_data["response_types"],
                    "scope": client_data["scope"],
                    "token_endpoint_auth_method": client_data["token_endpoint_auth_method"],
                    "client_id_issued_at": int(time.time()),
                }
            ),
            201,
        )

    except ScopePolicyError as e:
        return jsonify({"error": "invalid_client_metadata", "error_description": str(e)}), 400
    except Exception as e:
        logger.error(f"Client registration failed: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@oauth_bp.route("/authorize", methods=["GET"])
@limiter.limit(OAUTH_RATE_LIMIT)
def authorize():
    """
    OAuth2 authorization endpoint (RFC 6749).

    Query parameters:
        - response_type: "code" for authorization code flow
        - client_id: Client identifier
        - redirect_uri: Redirect URI
        - scope: Requested scopes
        - state: CSRF protection token
        - code_challenge: PKCE challenge (S256)
        - code_challenge_method: "S256"

    Returns:
        Redirect to client redirect_uri with authorization code or error
    """
    response_type = request.args.get("response_type")
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope", "openid profile")
    state = request.args.get("state")
    code_challenge = request.args.get("code_challenge")
    code_challenge_method = (request.args.get("code_challenge_method") or "").upper()

    # Validate required parameters
    if not all([response_type, client_id, redirect_uri]):
        return jsonify({"error": "invalid_request", "error_description": "Missing required parameters"}), 400

    if response_type != "code":
        return (
            jsonify(
                {"error": "unsupported_response_type", "error_description": "Only 'code' response_type is supported"}
            ),
            400,
        )

    if not _valid_pkce_challenge(code_challenge):
        return jsonify({"error": "invalid_request", "error_description": "invalid code_challenge"}), 400
    if code_challenge_method != "S256":
        return jsonify({"error": "invalid_request", "error_description": "code_challenge_method must be S256"}), 400

    try:
        # Validate client
        client = get_oauth_client(client_id)
        # Test compatibility: integration tests register clients via app.storage.store_oauth_client()
        # If the primary client store doesn't contain it, fall back to app.storage.get_oauth_client().
        if not client:
            try:
                from app.storage import get_oauth_client as _get_oauth_client

                client = _get_oauth_client(client_id)
            except Exception:
                pass
        if not client:
            audit_logger.log_event(
                "oauth.authorize_failed", reason="invalid_client", client_id=client_id, ip=request.remote_addr
            )
            return jsonify({"error": "invalid_client", "error_description": "Client not found"}), 401

        # Validate redirect_uri
        if redirect_uri not in client.get("redirect_uris", []):
            audit_logger.log_event(
                "oauth.authorize_failed",
                reason="invalid_redirect_uri",
                client_id=client_id,
                redirect_uri=redirect_uri,
                ip=request.remote_addr,
            )
            return jsonify({"error": "invalid_request", "error_description": "Invalid redirect_uri"}), 400

        try:
            requested_scopes = parse_scopes(scope)
            validate_client_scopes(requested_scopes, client_allowed_scopes(client))
            scope = serialize_scopes(requested_scopes)
        except ScopePolicyError:
            return jsonify({"error": "invalid_scope", "error_description": "Requested scope is not allowed"}), 400

        # Check if user is authenticated
        raw_subject = session.get("logged_in_pubkey")
        if not raw_subject:
            # Redirect to login with return URL
            login_return = _safe_local_redirect_target(request.full_path, fallback="/oauth/authorize")
            return redirect(f"/login?return_to={login_return}")
        try:
            user_pubkey = canonical_xonly_pubkey(raw_subject)
        except (TypeError, ValueError):
            return jsonify({"error": "access_denied", "error_description": "Invalid authenticated subject"}), 403

        # Generate authorization code
        auth_code = secrets.token_urlsafe(32)

        # Store authorization code with PKCE challenge
        code_data = {
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
            "code": auth_code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "user_pubkey": user_pubkey,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "created_at": datetime.now(timezone.utc).replace(tzinfo=None),
        }

        store_oauth_code(auth_code, code_data, ttl=600)  # 10 minute expiry

        audit_logger.log_event(
            "oauth.authorize_success", client_id=client_id, user_pubkey=user_pubkey, scope=scope, ip=request.remote_addr
        )

        # Redirect back to client with authorization code
        redirect_url = f"{redirect_uri}?code={auth_code}"
        if state:
            redirect_url += f"&state={state}"

        return redirect(redirect_url)

    except Exception as e:
        logger.error(f"Authorization failed: {e}", exc_info=True)
        return jsonify({"error": "server_error", "error_description": "Internal server error"}), 500


@oauth_bp.route("/token", methods=["POST"])
@limiter.limit(OAUTH_RATE_LIMIT)
def token():
    """
    OAuth2 token endpoint (RFC 6749).

    Expected form data:
        - grant_type: "authorization_code"
        - code: Authorization code
        - redirect_uri: Redirect URI (must match authorization)
        - client_id: Client identifier
        - client_secret: Client secret
        - code_verifier: PKCE verifier

    Returns:
        JSON with access_token, id_token, and token metadata
    """
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    code_verifier = request.form.get("code_verifier")

    if grant_type != "authorization_code":
        return (
            jsonify(
                {
                    "error": "unsupported_grant_type",
                    "error_description": "Only authorization_code grant type is supported",
                }
            ),
            400,
        )

    if not all([code, redirect_uri, client_id, client_secret]):
        return jsonify({"error": "invalid_request", "error_description": "Missing required parameters"}), 400

    try:
        # Validate client credentials
        client = get_oauth_client(client_id)
        # Test compatibility: integration tests register clients via app.storage.store_oauth_client()
        # If the primary client store doesn't contain it, fall back to app.storage.get_oauth_client().
        if not client:
            try:
                from app.storage import get_oauth_client as _get_oauth_client

                client = _get_oauth_client(client_id)
            except Exception:
                pass
        if not client or not _verify_client_secret(client, client_secret):
            audit_logger.log_event(
                "oauth.token_failed", reason="invalid_client", client_id=client_id, ip=request.remote_addr
            )
            return jsonify({"error": "invalid_client", "error_description": "Invalid client credentials"}), 401

        # Retrieve and validate authorization code
        code_data = get_oauth_code(code)
        if not code_data:
            audit_logger.log_event(
                "oauth.token_failed", reason="invalid_code", client_id=client_id, ip=request.remote_addr
            )
            return (
                jsonify({"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}),
                400,
            )

        # Validate code belongs to this client
        if code_data["client_id"] != client_id:
            return (
                jsonify(
                    {"error": "invalid_grant", "error_description": "Authorization code was issued to different client"}
                ),
                400,
            )

        # Validate redirect_uri matches
        if code_data["redirect_uri"] != redirect_uri:
            return jsonify({"error": "invalid_grant", "error_description": "Redirect URI mismatch"}), 400

        if not code_verifier:
            return jsonify({"error": "invalid_request", "error_description": "code_verifier required"}), 400
        if code_data.get("code_challenge_method") != "S256" or not _verify_pkce(
            code_data["code_challenge"], code_verifier
        ):
            audit_logger.log_event(
                "oauth.token_failed", reason="pkce_validation_failed", client_id=client_id, ip=request.remote_addr
            )
            return jsonify({"error": "invalid_grant", "error_description": "PKCE validation failed"}), 400

        # Back-compat: DB layer stores user_id; older code expects user_pubkey
        user = get_user_by_id(code_data.get("user_id"))
        if not user:
            audit_logger.log_event(
                "oauth.token_failed", reason="missing_user", client_id=client_id, ip=request.remote_addr
            )
            return jsonify({"error": "invalid_grant", "error_description": "Missing user for authorization code"}), 400
        try:
            user_pubkey = canonical_xonly_pubkey(user["pubkey"])
            scope = serialize_scopes(parse_scopes(code_data["scope"]))
        except (ValueError, TypeError, ScopePolicyError):
            return jsonify({"error": "invalid_grant", "error_description": "Invalid authorization code"}), 400

        # Every binding is valid; only now attempt the one-time atomic transition.
        if not consume_oauth_code(code):
            return jsonify({"error": "invalid_grant", "error_description": "Invalid authorization code"}), 400

        # Issue tokens
        cfg = current_app.config.get("APP_CONFIG", {})

        # Issue RS256 JWT access token
        jti = secrets.token_hex(16)
        access_token = issue_jwt_compat(
            subject=user_pubkey,
            audience=client_id,
            jti=jti,
            scope=scope,
            token_use="access",
            token_contract=TOKEN_CONTRACT,
            cfg=cfg,
        )

        import jwt

        unverified = jwt.decode(access_token, options={"verify_signature": False})
        header = jwt.get_unverified_header(access_token)
        digest = hashlib.sha256(access_token.encode("ascii")).hexdigest()
        issuer = str(unverified["iss"])
        store_canonical_jwt_record(
            jti=jti,
            digest=digest,
            client_id=client_id,
            user_id=code_data["user_id"],
            scope=scope,
            expires_at=datetime.fromtimestamp(unverified["exp"], timezone.utc).replace(tzinfo=None),
            metadata={
                "token_contract": TOKEN_CONTRACT,
                "token_use": "access",
                "issuer": issuer,
                "audience": client_id,
                "kid": header["kid"],
                "digest_algorithm": "sha256",
                "scope_policy_version": SCOPE_POLICY_VERSION,
            },
        )

        # Issue ID token (OpenID Connect)
        id_token = issue_jwt_compat(subject=user_pubkey, audience=client_id, scope=scope, cfg=cfg, id_token=True)

        audit_logger.log_event(
            "oauth.token_issued", client_id=client_id, user_pubkey=user_pubkey, scope=scope, ip=request.remote_addr
        )

        return jsonify(
            {
                "access_token": access_token,
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": cfg.get("JWT_EXPIRATION_HOURS", 24) * 3600,
                "scope": scope,
            }
        )

    except Exception as e:
        logger.error(f"Token issuance failed: {e}", exc_info=True)
        return jsonify({"error": "server_error", "error_description": "Token issuance failed"}), 500


@oauth_bp.route("/introspect", methods=["POST"])
@limiter.limit(OAUTH_RATE_LIMIT)
def introspect():
    """
    OAuth2 Token Introspection (RFC 7662).

    Requires valid client authentication and verifies JWT signatures.
    """
    data = request.form or request.get_json(silent=True) or {}
    token = data.get("token")
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")

    if not token or not client_id or not client_secret:
        return jsonify({"active": False}), 200

    # Validate client
    try:
        client = get_oauth_client(client_id)
        if not client or not _verify_client_secret(client, client_secret):
            return jsonify({"active": False}), 200
    except Exception:
        return jsonify({"active": False}), 200

    # Decode token with signature verification and strict algorithm pinning.
    try:
        import jwt

        from app.jwks import get_key_by_kid

        cfg = current_app.config.get("APP_CONFIG")
        if not cfg:
            return jsonify({"active": False}), 200

        allowed_algs = ["RS256"]

        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            return jsonify({"active": False}), 200

        jwks_dir = cfg.get("JWKS_DIR")
        if not jwks_dir:
            return jsonify({"active": False}), 200

        key = get_key_by_kid(str(jwks_dir), str(kid))
        if key is None:
            return jsonify({"active": False}), 200

        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        issuer = str(cfg.get("JWT_ISSUER") or "").rstrip("/")
        if not issuer:
            return jsonify({"active": False}), 200

        try:
            claims = jwt.decode(
                token,
                public_key,
                algorithms=allowed_algs,
                audience=client_id,
                issuer=issuer,
                options={"require": ["exp", "iat", "sub", "iss", "aud", "jti", "scope", "token_use", "token_contract"]},
            )
        except jwt.InvalidIssuerError:
            return jsonify({"active": False}), 200

        scope = serialize_scopes(parse_scopes(claims["scope"]))
        if claims.get("token_use") != "access" or claims.get("token_contract") != TOKEN_CONTRACT:
            return jsonify({"active": False}), 200
        record = get_canonical_jwt_record_by_jti(claims["jti"])
        user = get_user_by_id(record["user_id"]) if record else None
        metadata = record.get("metadata") if record else None
        expected_metadata = {
            "token_contract": TOKEN_CONTRACT,
            "token_use": "access",
            "issuer": issuer,
            "audience": client_id,
            "kid": str(kid),
            "digest_algorithm": "sha256",
            "scope_policy_version": SCOPE_POLICY_VERSION,
        }
        expiry = datetime.fromtimestamp(claims["exp"], timezone.utc).replace(tzinfo=None)
        subject = canonical_xonly_pubkey(user["pubkey"]) if user else None
        if not record or not all(
            [
                hmac.compare_digest(record["digest"], hashlib.sha256(token.encode("ascii")).hexdigest()),
                record["client_id"] == client_id,
                subject == claims["sub"],
                record["scope"] == scope,
                record["expires_at"] == expiry,
                record["is_revoked"] is False,
                metadata == expected_metadata,
            ]
        ):
            return jsonify({"active": False}), 200
        return (
            jsonify(
                {
                    "active": True,
                    "client_id": client_id,
                    "sub": claims.get("sub"),
                    "exp": claims.get("exp"),
                    "iat": claims.get("iat"),
                    "jti": claims.get("jti"),
                    "scope": scope,
                    "token_type": "Bearer",
                    "token_contract": TOKEN_CONTRACT,
                }
            ),
            200,
        )

    except Exception:
        logger.warning("Token introspection failed closed")
        return jsonify({"active": False}), 200

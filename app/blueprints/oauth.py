"""
OAuth2/OIDC Blueprint - Token Issuance, Authorization, Introspection

Implements OAuth 2.0 and OpenID Connect flows with PKCE.
"""

import logging
import secrets
import time
from typing import Optional

from flask import Blueprint, current_app, jsonify, redirect, request, session

from app.audit_logger import get_audit_logger
from app.db_storage import (
    delete_oauth_code,
    get_oauth_client,
    get_oauth_code,
    store_oauth_client,
    store_oauth_code,
)
from app.oidc import validate_pkce
from app.security import limiter
from app.tokens import issue_rs256_jwt

logger = logging.getLogger(__name__)
audit_logger = get_audit_logger()

oauth_bp = Blueprint("oauth", __name__)

OAUTH_RATE_LIMIT = "30 per minute"


@oauth_bp.route("/register", methods=["POST"])
@limiter.limit("10 per minute")
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
    data = request.get_json()

    if not data or not data.get("client_name"):
        return jsonify({"error": "client_name is required"}), 400

    redirect_uris = data.get("redirect_uris", [])
    if not redirect_uris or not isinstance(redirect_uris, list):
        return jsonify({"error": "redirect_uris must be a non-empty array"}), 400

    try:
        # Generate client credentials
        client_id = f"client_{secrets.token_urlsafe(32)}"
        client_secret = secrets.token_urlsafe(48)

        # Store client
        client_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": data.get("client_name"),
            "redirect_uris": redirect_uris,
            "grant_types": data.get("grant_types", ["authorization_code"]),
            "response_types": data.get("response_types", ["code"]),
            "client_type": "free",  # Default tier
            "is_active": True,
            "created_at": time.time()
        }

        store_oauth_client(client_id, client_data)

        audit_logger.log_event(
            "oauth.client_registered",
            client_id=client_id,
            client_name=client_data["client_name"],
            ip=request.remote_addr
        )

        # Return client credentials (RFC 7591 response)
        return jsonify({
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": client_data["client_name"],
            "redirect_uris": redirect_uris,
            "grant_types": client_data["grant_types"],
            "response_types": client_data["response_types"],
            "client_id_issued_at": int(time.time())
        }), 201

    except Exception as e:
        logger.error(f"Client registration failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


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
        - code_challenge: PKCE challenge (S256 or plain)
        - code_challenge_method: "S256" or "plain"

    Returns:
        Redirect to client redirect_uri with authorization code or error
    """
    response_type = request.args.get("response_type")
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope", "openid profile")
    state = request.args.get("state")
    code_challenge = request.args.get("code_challenge")
    code_challenge_method = request.args.get("code_challenge_method", "S256")

    # Validate required parameters
    if not all([response_type, client_id, redirect_uri]):
        return jsonify({
            "error": "invalid_request",
            "error_description": "Missing required parameters"
        }), 400

    if response_type != "code":
        return jsonify({
            "error": "unsupported_response_type",
            "error_description": "Only 'code' response_type is supported"
        }), 400

    try:
        # Validate client
        client = get_oauth_client(client_id)
        if not client:
            audit_logger.log_event(
                "oauth.authorize_failed",
                reason="invalid_client",
                client_id=client_id,
                ip=request.remote_addr
            )
            return jsonify({
                "error": "invalid_client",
                "error_description": "Client not found"
            }), 401

        # Validate redirect_uri
        if redirect_uri not in client.get("redirect_uris", []):
            audit_logger.log_event(
                "oauth.authorize_failed",
                reason="invalid_redirect_uri",
                client_id=client_id,
                redirect_uri=redirect_uri,
                ip=request.remote_addr
            )
            return jsonify({
                "error": "invalid_request",
                "error_description": "Invalid redirect_uri"
            }), 400

        # Check if user is authenticated
        user_pubkey = session.get("logged_in_pubkey")
        if not user_pubkey:
            # Redirect to login with return URL
            return redirect(f"/login?return_to={request.url}")

        # Generate authorization code
        auth_code = secrets.token_urlsafe(32)

        # Store authorization code with PKCE challenge
        code_data = {
            "code": auth_code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "user_pubkey": user_pubkey,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "created_at": time.time()
        }

        store_oauth_code(auth_code, code_data, ttl=600)  # 10 minute expiry

        audit_logger.log_event(
            "oauth.authorize_success",
            client_id=client_id,
            user_pubkey=user_pubkey,
            scope=scope,
            ip=request.remote_addr
        )

        # Redirect back to client with authorization code
        redirect_url = f"{redirect_uri}?code={auth_code}"
        if state:
            redirect_url += f"&state={state}"

        return redirect(redirect_url)

    except Exception as e:
        logger.error(f"Authorization failed: {e}", exc_info=True)
        return jsonify({
            "error": "server_error",
            "error_description": str(e)
        }), 500


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
        - code_verifier: PKCE verifier (if PKCE was used)

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
        return jsonify({
            "error": "unsupported_grant_type",
            "error_description": "Only authorization_code grant type is supported"
        }), 400

    if not all([code, redirect_uri, client_id, client_secret]):
        return jsonify({
            "error": "invalid_request",
            "error_description": "Missing required parameters"
        }), 400

    try:
        # Validate client credentials
        client = get_oauth_client(client_id)
        if not client or client.get("client_secret") != client_secret:
            audit_logger.log_event(
                "oauth.token_failed",
                reason="invalid_client",
                client_id=client_id,
                ip=request.remote_addr
            )
            return jsonify({
                "error": "invalid_client",
                "error_description": "Invalid client credentials"
            }), 401

        # Retrieve and validate authorization code
        code_data = get_oauth_code(code)
        if not code_data:
            audit_logger.log_event(
                "oauth.token_failed",
                reason="invalid_code",
                client_id=client_id,
                ip=request.remote_addr
            )
            return jsonify({
                "error": "invalid_grant",
                "error_description": "Invalid or expired authorization code"
            }), 400

        # Validate code belongs to this client
        if code_data["client_id"] != client_id:
            delete_oauth_code(code)
            return jsonify({
                "error": "invalid_grant",
                "error_description": "Authorization code was issued to different client"
            }), 400

        # Validate redirect_uri matches
        if code_data["redirect_uri"] != redirect_uri:
            delete_oauth_code(code)
            return jsonify({
                "error": "invalid_grant",
                "error_description": "Redirect URI mismatch"
            }), 400

        # Validate PKCE if used
        if code_data.get("code_challenge"):
            if not code_verifier:
                delete_oauth_code(code)
                return jsonify({
                    "error": "invalid_request",
                    "error_description": "code_verifier required for PKCE"
                }), 400

            if not validate_pkce(
                code_verifier,
                code_data["code_challenge"],
                code_data.get("code_challenge_method", "S256")
            ):
                delete_oauth_code(code)
                audit_logger.log_event(
                    "oauth.token_failed",
                    reason="pkce_validation_failed",
                    client_id=client_id,
                    ip=request.remote_addr
                )
                return jsonify({
                    "error": "invalid_grant",
                    "error_description": "PKCE validation failed"
                }), 400

        # Code is valid - delete it (one-time use)
        delete_oauth_code(code)

        # Issue tokens
        cfg = current_app.config.get("APP_CONFIG", {})
        user_pubkey = code_data["user_pubkey"]
        scope = code_data["scope"]

        # Issue RS256 JWT access token
        access_token = issue_rs256_jwt(
            subject=user_pubkey,
            audience=client_id,
            scope=scope,
            cfg=cfg
        )

        # Issue ID token (OpenID Connect)
        id_token = issue_rs256_jwt(
            subject=user_pubkey,
            audience=client_id,
            scope=scope,
            cfg=cfg,
            id_token=True
        )

        audit_logger.log_event(
            "oauth.token_issued",
            client_id=client_id,
            user_pubkey=user_pubkey,
            scope=scope,
            ip=request.remote_addr
        )

        return jsonify({
            "access_token": access_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": cfg.get("JWT_EXPIRATION_HOURS", 24) * 3600,
            "scope": scope
        })

    except Exception as e:
        logger.error(f"Token issuance failed: {e}", exc_info=True)
        return jsonify({
            "error": "server_error",
            "error_description": str(e)
        }), 500


@oauth_bp.route("/introspect", methods=["POST"])
@limiter.limit(OAUTH_RATE_LIMIT)
def introspect():
    """
    OAuth2 token introspection (RFC 7662).

    Expected form data:
        - token: Token to introspect
        - client_id: Client identifier
        - client_secret: Client secret

    Returns:
        JSON with token metadata
    """
    token_string = request.form.get("token")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    if not all([token_string, client_id, client_secret]):
        return jsonify({
            "active": False
        }), 200

    try:
        # Validate client
        client = get_oauth_client(client_id)
        if not client or client.get("client_secret") != client_secret:
            return jsonify({"active": False}), 200

        # Validate JWT token
        import jwt
        cfg = current_app.config.get("APP_CONFIG", {})
        jwks_doc = current_app.config.get("JWKS_DOCUMENT", {})

        # Extract public key from JWKS
        keys = jwks_doc.get("keys", [])
        if not keys:
            return jsonify({"active": False}), 200

        public_key_pem = keys[0].get("x5c", [""])[0]  # Simplified

        # Verify token
        payload = jwt.decode(
            token_string,
            public_key_pem,
            algorithms=["RS256"],
            audience=client_id
        )

        return jsonify({
            "active": True,
            "sub": payload.get("sub"),
            "aud": payload.get("aud"),
            "scope": payload.get("scope"),
            "exp": payload.get("exp"),
            "iat": payload.get("iat")
        })

    except jwt.ExpiredSignatureError:
        return jsonify({"active": False}), 200
    except Exception as e:
        logger.warning(f"Token introspection failed: {e}")
        return jsonify({"active": False}), 200

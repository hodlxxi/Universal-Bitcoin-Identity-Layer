"""
Shared OAuth token validation helpers for monolith and blueprint routes.
"""

from functools import wraps

from flask import jsonify, request

from app.db_storage import get_oauth_token, get_user_by_id


def require_oauth_token(required_scope: str | None = None):
    """
    Decorator to require a valid OAuth bearer token and (optionally) scope.
    """

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "unauthorized", "detail": "Missing Bearer token"}), 401

            token_str = auth_header.split(" ", 1)[1]
            token_data = get_oauth_token(token_str)
            if not token_data:
                return jsonify({"error": "invalid_token"}), 401

            token_scopes = set((token_data.get("scope") or "").split())
            if required_scope and required_scope not in token_scopes:
                return (
                    jsonify(
                        {"error": "insufficient_scope", "required": required_scope, "provided": list(token_scopes)}
                    ),
                    403,
                )

            user = get_user_by_id(token_data.get("user_id")) if token_data.get("user_id") else None
            request.oauth_payload = token_data
            request.oauth_client_id = token_data.get("client_id")
            request.oauth_scope = token_data.get("scope")
            request.oauth_sub = user.get("pubkey") if user else None
            request.oauth_pubkey = user.get("pubkey") if user else None

            return f(*args, **kwargs)

        return wrapper

    return decorator

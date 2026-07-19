"""
Shared OAuth token validation helpers for monolith and blueprint routes.
"""

from functools import wraps

from flask import g, jsonify, request

from app.db_storage import get_oauth_token, get_user_by_id


def require_oauth_token(required_scope: str | None = None):
    """
    Decorator to require a valid OAuth bearer token and (optionally) scope.
    """

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            parts = auth_header.split(" ")
            if len(parts) != 2 or parts[0] != "Bearer" or not parts[1]:
                return jsonify({"error": "unauthorized", "detail": "Missing Bearer token"}), 401

            token_str = parts[1]
            try:
                token_data = get_oauth_token(token_str)
            except Exception:
                token_data = None
            if not token_data:
                return jsonify({"error": "invalid_token"}), 401

            token_scopes = set((token_data.get("scope") or "").split())
            if required_scope and required_scope not in token_scopes:
                return (
                    jsonify({"error": "insufficient_scope", "required": required_scope}),
                    403,
                )

            user = get_user_by_id(token_data.get("user_id")) if token_data.get("user_id") else None
            if not user or user.get("is_active") is not True:
                return jsonify({"error": "invalid_token"}), 401
            request.oauth_payload = token_data
            request.oauth_client_id = token_data.get("client_id")
            request.oauth_scope = token_data.get("scope")
            request.oauth_sub = user.get("pubkey") if user else None
            request.oauth_pubkey = user.get("pubkey") if user else None

            return f(*args, **kwargs)

        return wrapper

    return decorator


def _bearer_error(code: str, status: int, *, scope: str | None = None):
    challenge = f'Bearer realm="hodlxxi", error="{code}"'
    if scope is not None:
        challenge += f', scope="{scope}"'
    response = jsonify({"error": code})
    response.status_code = status
    response.headers["WWW-Authenticate"] = challenge
    return response


def require_canonical_bearer(*, required_scope: str, required_action=None):
    """Require a canonical JWT, exact scope, and current entitlement."""

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            from app.services.action_authorization import ActionRequest, authorize_action
            from app.services.current_entitlement import (
                CurrentEntitlementResolver,
                EntitlementDenied,
                EntitlementUnavailable,
                resolve_current_entitlement,
            )
            from app.services.oauth_bearer_validation import (
                BearerValidationError,
                validate_canonical_access_token,
            )

            header = request.headers.get("Authorization", "")
            parts = header.split(" ")
            if len(parts) != 2 or parts[0] != "Bearer" or not parts[1]:
                return _bearer_error("invalid_token", 401)
            try:
                principal = validate_canonical_access_token(parts[1])
            except BearerValidationError:
                return _bearer_error("invalid_token", 401)
            if required_scope not in principal.scopes:
                return _bearer_error("insufficient_scope", 403, scope=required_scope)
            try:
                entitlement = resolve_current_entitlement(principal.subject)
            except EntitlementDenied:
                return jsonify({"error": "insufficient_entitlement"}), 403
            except EntitlementUnavailable:
                return jsonify({"error": "authorization_unavailable"}), 503
            if required_action is not None:
                policy = authorize_action(
                    ActionRequest(
                        actor_pubkey=principal.subject,
                        action=required_action,
                        granted_scopes=principal.scopes,
                    ),
                    CurrentEntitlementResolver(entitlement),
                )
                if not policy.allowed:
                    return jsonify({"error": "insufficient_entitlement"}), 403
            g.oauth_principal = principal
            g.entitlement_decision = entitlement
            return f(*args, **kwargs)

        return wrapper

    return decorator

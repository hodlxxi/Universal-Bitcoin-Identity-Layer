"""Dormant verified-browser admission and explicit, generation-scoped logout."""

from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timedelta, timezone

from flask import Response, current_app, g, jsonify, make_response, render_template_string, request, session

from app.auth_api_core import canonical_xonly_pubkey
from app.services.canonical_oauth_browser_subject import persist_verified_browser_subject
from app.services.oauth_session_lifecycle import OAuthSessionUnavailable, configured_lifecycle

BROWSER_GENERATION_KEY = "oauth_browser_generation_v1"


def lifecycle_enabled() -> bool:
    return configured_lifecycle(current_app) is not None


def browser_reference() -> str:
    """Read only authenticated Flask session state; no request-parameter fallback."""
    value = session.get(BROWSER_GENERATION_KEY)
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise OAuthSessionUnavailable()
    return value


def complete_verified_browser_login(
    verified_pubkey: str, *, challenge: str, created_at: datetime, expires_at: datetime
) -> None:
    """Call immediately after successful signature verification of this challenge.

    This is not a subject-only login helper. Actual verification branches supply
    the server-issued challenge and its original validity, never request times.
    """
    lifecycle = configured_lifecycle(current_app)
    if lifecycle is None:
        return
    canonical = persist_verified_browser_subject(verified_pubkey)
    previous = browser_reference() if BROWSER_GENERATION_KEY in session else None
    reference = lifecycle.complete_verified_login(
        subject=canonical,
        challenge=challenge,
        challenge_created=created_at,
        challenge_expires=expires_at,
        previous_generation=previous,
    )
    # The database transaction has committed before the cookie can refer to it.
    session[BROWSER_GENERATION_KEY] = reference
    g.oauth_verified_browser_subject = canonical
    session.pop("challenge", None)
    session.pop("challenge_timestamp", None)


def complete_verified_legacy_browser_login(verified_pubkey: str) -> None:
    """The Legacy verifier has just matched the signed-cookie challenge."""
    if not lifecycle_enabled():
        return
    timestamp = session.get("challenge_timestamp")
    challenge = session.get("challenge")
    if type(timestamp) not in (int, float) or type(challenge) is not str:
        raise OAuthSessionUnavailable()
    created = datetime.fromtimestamp(timestamp, timezone.utc)
    complete_verified_browser_login(
        verified_pubkey,
        challenge=challenge,
        created_at=created,
        expires_at=created + timedelta(seconds=600),
    )


def require_verified_browser_completion(pubkey: str) -> None:
    """Compatibility membership helpers cannot establish browser authority."""
    lifecycle = configured_lifecycle(current_app)
    if lifecycle is None:
        return
    subject = canonical_xonly_pubkey(pubkey)
    if getattr(g, "oauth_verified_browser_subject", None) != subject:
        raise OAuthSessionUnavailable()
    if lifecycle.browser_subject(browser_reference()) != subject:
        raise OAuthSessionUnavailable()


def _csrf(reference: str) -> str:
    secret = current_app.secret_key
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if not isinstance(secret, bytes) or not secret:
        raise OAuthSessionUnavailable()
    return hmac.new(secret, b"HODLXXI_BROWSER_LOGOUT_CSRF_V1\0" + reference.encode("ascii"), hashlib.sha256).hexdigest()


def protected_browser_logout() -> Response | tuple[Response, int] | None:
    """Return a non-mutating response, or None only after explicit POST commits."""
    lifecycle = configured_lifecycle(current_app)
    if lifecycle is None:
        return None
    try:
        reference = browser_reference()
        if request.method in {"GET", "HEAD"}:
            response = make_response(
                render_template_string(
                    "<!doctype html><title>Log out</title><h1>Log out of UBID?</h1>"
                    '<form method="post" action="/logout">'
                    '<input type="hidden" name="csrf_token" value="{{ csrf }}">'
                    '<button type="submit">Log out</button></form>',
                    csrf=_csrf(reference),
                )
            )
            response.headers["Cache-Control"] = "no-store"
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
            )
            response.headers["Referrer-Policy"] = "no-referrer"
            return response
        if request.method != "POST":
            return jsonify(error="method_not_allowed"), 405
        # Missing and literal null Origin are rejected. No Host/forwarded-header,
        # Referer or SameSite fallback confers origin authority.
        if (
            request.headers.get("Origin") != lifecycle.browser_origin
            or request.query_string
            or request.mimetype != "application/x-www-form-urlencoded"
            or request.content_length is None
            or request.content_length > 1024
        ):
            return jsonify(error="logout_denied"), 403
        if len(request.get_data(cache=True)) > 1024 or set(request.form) != {"csrf_token"}:
            return jsonify(error="logout_denied"), 403
        values = request.form.getlist("csrf_token")
        if (
            len(values) != 1
            or re.fullmatch(r"[0-9a-f]{64}", values[0]) is None
            or not hmac.compare_digest(values[0], _csrf(reference))
        ):
            return jsonify(error="logout_denied"), 403
        lifecycle.invalidate_browser(reference)
        return None
    except OAuthSessionUnavailable:
        return jsonify(error="authentication_unavailable"), 503

"""Project verified browser identities through the same current authority as Social."""

from flask import current_app, request, session

from app.auth_api_core import canonical_xonly_pubkey
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement import resolve_runtime_current_entitlement

_VERIFIED_SUBJECT = "canonical_verified_login_subject_v1"


def canonical_browser_access(subject):
    try:
        decision = resolve_runtime_current_entitlement(subject)
        if (
            decision.subject == subject
            and decision.identity_class is IdentityClass.FULL
            and decision.current_full_relation_satisfied is True
        ):
            return "full"
    except Exception:
        current_app.logger.warning("Canonical browser entitlement unavailable")
    return "limited"


def verified_browser_access(pubkey, *, persist_subject=False):
    """Called only after the login handler has verified proof of key control."""
    try:
        subject = canonical_xonly_pubkey(pubkey)
    except (TypeError, ValueError):
        session.pop(_VERIFIED_SUBJECT, None)
        return "limited"
    if persist_subject:
        from app.services.canonical_oauth_browser_subject import persist_verified_browser_subject

        try:
            persist_verified_browser_subject(subject)
        except Exception:
            current_app.logger.warning("Verified browser subject unavailable for canonical entitlement")
            session.pop(_VERIFIED_SUBJECT, None)
            return "limited"
    session[_VERIFIED_SUBJECT] = subject
    return canonical_browser_access(subject)


def refresh_canonical_browser_access():
    """A cached role is never evidence. A configured lifecycle must still be live."""
    # Confirmation and rejected logout requests must preserve the cookie and
    # must work independently of the current-generation/evidence reads.
    # Keep operational health probes independent of browser authority too.
    if request.path in {"/logout", "/health", "/health/live", "/health/ready"}:
        return
    from app.services.oauth_browser_authentication import browser_reference
    from app.services.oauth_session_lifecycle import configured_lifecycle

    # Leave inadmissible session roles intact for consumers that explicitly
    # deny them. Refresh applies only to an established member session.
    previous_level = session.get("access_level")
    if previous_level not in ("limited", "full"):
        return
    level = "limited"
    try:
        subject = canonical_xonly_pubkey(session.get("logged_in_pubkey"))
        lifecycle = configured_lifecycle(current_app)
        verified = (
            lifecycle.browser_subject(browser_reference()) if lifecycle is not None else session.get(_VERIFIED_SUBJECT)
        )
        if verified == subject:
            level = canonical_browser_access(subject)
    except (TypeError, ValueError):
        pass
    except Exception:
        current_app.logger.warning("Browser generation unavailable for canonical entitlement")
    if previous_level != level:
        session["access_level"] = level

"""Browser Full follows current canonical authority, including after login."""

from pathlib import Path

import pytest
from flask import session

from app.services import automatic_browser_access as access
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement import EntitlementDecision

HOME = Path("app/browser_shell_routes.py")
SUBJECT = "a" * 64


@pytest.mark.parametrize("prefix", ["", "02", "03"])
def test_verified_login_uses_canonical_subject_independent_of_writer_flags(app, monkeypatch, prefix):
    monkeypatch.delenv("AUTO_SPONSORED_IMPORT_ENABLED", raising=False)
    current = IdentityClass.FULL

    def resolve(subject):
        assert subject == SUBJECT
        return EntitlementDecision(subject, current, current is IdentityClass.FULL, "test")

    monkeypatch.setattr(access, "resolve_runtime_current_entitlement", resolve)
    with app.test_request_context():
        key = prefix + SUBJECT
        session["logged_in_pubkey"] = key
        session["access_level"] = access.verified_browser_access(key)
        assert session["access_level"] == "full"
        access.refresh_canonical_browser_access()
        assert session["access_level"] == "full"
        current = IdentityClass.LIMITED
        access.refresh_canonical_browser_access()
        assert session["access_level"] == "limited"


def test_unbound_browser_role_cannot_grant_full(app, monkeypatch):
    monkeypatch.setattr(access, "resolve_runtime_current_entitlement", lambda *args: pytest.fail("unverified subject"))
    with app.test_request_context():
        session.update(logged_in_pubkey=SUBJECT, access_level="full")
        access.refresh_canonical_browser_access()
        assert session["access_level"] == "limited"


def test_unsupported_subject_cannot_retain_a_verified_binding(app, monkeypatch):
    monkeypatch.setattr(access, "resolve_runtime_current_entitlement", lambda _: pytest.fail("unsupported subject"))
    with app.test_request_context():
        session["canonical_verified_login_subject_v1"] = SUBJECT
        assert access.verified_browser_access("unsupported") == "limited"
        assert "canonical_verified_login_subject_v1" not in session


@pytest.mark.parametrize("state", ["revoked", "different_subject"])
def test_bound_session_requires_the_same_live_generation(app, monkeypatch, state):
    from app.services import oauth_session_lifecycle as lifecycle
    from app.services.oauth_browser_authentication import BROWSER_GENERATION_KEY

    class Generation:
        def browser_subject(self, reference):
            if state == "revoked":
                raise lifecycle.OAuthSessionUnavailable()
            return "b" * 64

    monkeypatch.setattr(lifecycle, "configured_lifecycle", lambda _: Generation())
    monkeypatch.setattr(access, "resolve_runtime_current_entitlement", lambda _: pytest.fail("invalid generation"))
    with app.test_request_context():
        session.update(logged_in_pubkey=SUBJECT, access_level="full", canonical_verified_login_subject_v1=SUBJECT)
        session[BROWSER_GENERATION_KEY] = "c" * 64
        access.refresh_canonical_browser_access()
        assert session["access_level"] == "limited"


def test_home_rpc_descriptor_panel_remains_full_only():
    text = HOME.read_text(encoding="utf-8")

    assert "{% if access_level == 'full' %}" in text
    assert "RPC Full Node Section" in text
    assert "Import Covenant Descriptor" in text
    assert "Set Checking Labels" in text
    assert "Descriptors" in text

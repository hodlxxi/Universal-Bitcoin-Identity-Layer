"""Browser principal isolation for Canon V2 enrollment; no real user grants."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from flask import Flask, session

import app.services.canonical_v2_browser_admission as service
from tests.unit.test_canonical_admission_proposal_v2 import ALICE, BOB


@pytest.fixture
def app():
    app = Flask(__name__)
    app.secret_key = "disposable-unit-test-only"
    return app


@contextmanager
def _request(app, *, key=ALICE, reference="a" * 64, login="legacy", origin="https://ubid.test"):
    with app.test_request_context(
        "/canon/v2/issue",
        method="POST",
        headers={"Origin": origin, "Content-Type": "application/json"},
    ):
        session["logged_in_pubkey"] = key
        session["oauth_browser_generation_v1"] = reference
        session["login_method"] = login
        yield


def test_sponsor_and_child_resolve_separate_verified_generations(app, monkeypatch):
    seen = []
    expected = {"a" * 64: ALICE[2:], "b" * 64: BOB[2:]}

    def browser_subject(reference):
        seen.append(reference)
        return expected[reference]

    monkeypatch.setattr(
        service,
        "configured_lifecycle",
        lambda _: SimpleNamespace(browser_origin="https://ubid.test", browser_subject=browser_subject),
    )
    with _request(app):
        assert service._verified_browser_subject(expected_compressed=ALICE) == ALICE[2:]
    with _request(app, key=BOB, reference="b" * 64):
        assert service._verified_browser_subject(expected_compressed=BOB) == BOB[2:]
    assert seen == ["a" * 64, "b" * 64]


@pytest.mark.parametrize(
    "cookie_key,origin,login,reference,verified",
    [
        (BOB, "https://ubid.test", "legacy", "a" * 64, ALICE[2:]),
        (ALICE, "https://evil.test", "legacy", "a" * 64, ALICE[2:]),
        (ALICE, "https://ubid.test", "guest", "a" * 64, ALICE[2:]),
        (ALICE, "https://ubid.test", "legacy", "a" * 64, BOB[2:]),
        (ALICE, "https://ubid.test", "legacy", "x" * 64, ALICE[2:]),
    ],
)
def test_cannot_spoof_issuer_via_cookie_claim_or_http_origin(
    app, monkeypatch, cookie_key, origin, login, reference, verified
):
    monkeypatch.setattr(
        service,
        "configured_lifecycle",
        lambda _: SimpleNamespace(browser_origin="https://ubid.test", browser_subject=lambda _: verified),
    )
    with _request(app, key=cookie_key, origin=origin, login=login, reference=reference):
        with pytest.raises(service.CanonicalV2BrowserAdmissionUnavailable):
            service._verified_browser_subject(expected_compressed=ALICE)


def test_missing_or_revoked_browser_generation_denied(app, monkeypatch):
    def denied(_):
        raise RuntimeError("revoked")

    monkeypatch.setattr(
        service,
        "configured_lifecycle",
        lambda _: SimpleNamespace(browser_origin="https://ubid.test", browser_subject=denied),
    )
    with _request(app):
        with pytest.raises(service.CanonicalV2BrowserAdmissionUnavailable):
            service._verified_browser_subject(expected_compressed=ALICE)


def test_unconfigured_lifecycle_denied_even_for_full_cookie(app, monkeypatch):
    monkeypatch.setattr(service, "configured_lifecycle", lambda _: None)
    with _request(app):
        session["access_level"] = "full"
        with pytest.raises(service.CanonicalV2BrowserAdmissionUnavailable):
            service._verified_browser_subject(expected_compressed=ALICE)


def test_non_post_and_missing_request_context_rejected(app, monkeypatch):
    monkeypatch.setattr(
        service,
        "configured_lifecycle",
        lambda _: SimpleNamespace(browser_origin="https://ubid.test", browser_subject=lambda _: ALICE[2:]),
    )
    with pytest.raises(service.CanonicalV2BrowserAdmissionUnavailable):
        service._verified_browser_subject(expected_compressed=ALICE)
    with app.test_request_context("/canon/v2/issue", method="GET"):
        with pytest.raises(service.CanonicalV2BrowserAdmissionUnavailable):
            service._verified_browser_subject(expected_compressed=ALICE)


def test_no_runtime_or_full_promotion():
    assert service.RUNTIME_ENABLED is False

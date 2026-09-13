"""Offline boundary tests; PostgreSQL behavior lives in the real DB harness."""

import hashlib
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.services import social_messaging_mobile_authorization as protocol
from app.services.social_messaging_mobile_authorization_storage import SqlAlchemyMobileAuthorizationService


def test_phase_one_vectors_are_unchanged():
    fixture = Path(__file__).parents[1] / "fixtures/social_mobile_device_authorization_v1.json"
    assert (
        hashlib.sha256(fixture.read_bytes()).hexdigest()
        == "26f335b718a771d08aacc7ebbe63895d395e2e2376d12484fb19ab30c0db7356"
    )


def test_no_implicit_or_sqlite_production_fallback():
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        SqlAlchemyMobileAuthorizationService(None)
    engine = create_engine("sqlite:///:memory:")
    service = SqlAlchemyMobileAuthorizationService(sessionmaker(bind=engine))
    with pytest.raises(protocol.MobileAuthorizationUnavailable, match="^mobile device authorization unavailable$"):
        service.status("a" * 64, method=protocol.QR, session_id="synthetic", subject="b" * 64, context_id="c" * 64)
    engine.dispose()


@pytest.mark.parametrize("clock", [lambda: True, lambda: 1.5, lambda: -1])
def test_clock_is_strict(clock):
    service = SqlAlchemyMobileAuthorizationService(lambda: None, clock=clock)
    with pytest.raises(ValueError):
        service._now()

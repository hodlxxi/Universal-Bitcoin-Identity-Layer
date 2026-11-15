"""Issuer-generation provenance must reject caller-supplied or non-PG state."""

from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.services.canonical_v2_issuer_generation_binding import (
    CanonicalV2IssuerGenerationUnavailable,
    RUNTIME_ENABLED,
    bind_issuer_generation_in_transaction,
    require_current_issuer_generation_in_transaction,
)
from tests.unit.test_canonical_admission_proposal_v2 import ALICE, NOW


def test_issuer_binding_does_not_enable_runtime_or_grant_membership():
    assert RUNTIME_ENABLED is False


@pytest.mark.parametrize("bad", ("A" * 64, "x" * 64, "", "00"))
def test_nonce_binding_rejects_noncanonical_digest(bad):
    engine = create_engine("sqlite:///:memory:")
    try:
        with Session(engine) as session:
            with session.begin():
                with pytest.raises(CanonicalV2IssuerGenerationUnavailable):
                    bind_issuer_generation_in_transaction(
                        session,
                        challenge_sha256=bad,
                        sponsor_generation_id="a" * 64,
                        sponsor_subject=ALICE[2:],
                        client_id="ubid",
                        issued_at=NOW,
                    )
    finally:
        engine.dispose()


def test_browser_issuer_binding_never_accepts_sqlite_transaction():
    engine = create_engine("sqlite:///:memory:")
    try:
        with Session(engine) as session:
            with session.begin():
                with pytest.raises(CanonicalV2IssuerGenerationUnavailable):
                    require_current_issuer_generation_in_transaction(
                        session,
                        challenge_sha256="b" * 64,
                        sponsor_subject=ALICE[2:],
                        client_id="ubid",
                        proposal_sha256="c" * 64,
                        now=NOW,
                    )
    finally:
        engine.dispose()


def test_invalid_or_naive_clock_refused():
    with pytest.raises(CanonicalV2IssuerGenerationUnavailable):
        require_current_issuer_generation_in_transaction(
            None,
            challenge_sha256="b" * 64,
            sponsor_subject=ALICE[2:],
            client_id="ubid",
            proposal_sha256="c" * 64,
            now=datetime(2026, 11, 13),
        )

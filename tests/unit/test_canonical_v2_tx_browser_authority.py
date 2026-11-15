"""Fail-closed input tests for same-transaction OAuth generation lock (Issue #588)."""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.services.canonical_v2_tx_browser_authority import (
    CanonicalV2TransactionBrowserUnavailable,
    LockedCanonicalV2BrowserSubject,
    locked_browser_subject_in_transaction,
)
from tests.unit.test_canonical_admission_proposal_v2 import ALICE, NOW


def test_browser_subject_never_grants_full():
    locked = LockedCanonicalV2BrowserSubject(ALICE[2:], "a" * 64, "00000000-0000-4000-8000-000000000001", "ubid")
    assert locked.subject == ALICE[2:]
    assert locked.grants_full is False


@pytest.mark.parametrize(
    "changes",
    [
        {"generation_id": "not-a-valid-generation"},
        {"generation_id": "A" * 64},
        {"expected_subject": ALICE},
        {"expected_subject": "zz" * 32},
        {"client_id": ""},
        {"client_id": " user "},
        {"now": datetime(2026, 11, 14)},
    ],
)
def test_refuses_invalid_identity_and_clock_on_sqlite(changes):
    values = {
        "generation_id": "a" * 64,
        "expected_subject": ALICE[2:],
        "client_id": "ubid",
        "now": NOW,
    }
    values.update(changes)
    engine = create_engine("sqlite:///:memory:")
    try:
        with Session(engine) as session:
            with session.begin():
                with pytest.raises(CanonicalV2TransactionBrowserUnavailable):
                    locked_browser_subject_in_transaction(session, **values)
    finally:
        engine.dispose()


def test_no_transaction_or_null_session_is_not_trusted():
    with pytest.raises(CanonicalV2TransactionBrowserUnavailable):
        locked_browser_subject_in_transaction(
            None, generation_id="a" * 64, expected_subject=ALICE[2:], client_id="ubid", now=NOW
        )


def test_non_timezone_clock_cannot_establish_browser_identity():
    with pytest.raises(CanonicalV2TransactionBrowserUnavailable):
        locked_browser_subject_in_transaction(
            None, generation_id="a" * 64, expected_subject=ALICE[2:], client_id="ubid", now=datetime.now(timezone.utc)
        )

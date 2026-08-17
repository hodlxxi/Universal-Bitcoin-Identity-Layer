from datetime import datetime, timezone

import pytest

from app.services.action_step_up import StepUpReason, VerifiedStepUp
from app.services.action_step_up_operation_storage import (
    AtomicStepUpReserveResult,
    AtomicStepUpReserveStatus,
)


def test_atomic_result_contract_rejects_inconsistent_shapes():
    failure = VerifiedStepUp(False, StepUpReason.INVALID_SIGNATURE)
    with pytest.raises(ValueError):
        AtomicStepUpReserveResult(AtomicStepUpReserveStatus.NEW, None, failure)
    with pytest.raises(ValueError):
        AtomicStepUpReserveResult(AtomicStepUpReserveStatus.REPLAY, None, None)
    assert (
        AtomicStepUpReserveResult(AtomicStepUpReserveStatus.STEP_UP_REJECTED, None, failure).status.value
        == "step_up_rejected"
    )


def test_result_status_is_bounded_and_timestamp_fixture_is_aware():
    assert {status.value for status in AtomicStepUpReserveStatus} == {
        "new",
        "replay",
        "idempotency_conflict",
        "step_up_rejected",
    }
    assert datetime(2026, 7, 21, tzinfo=timezone.utc).utcoffset() is not None

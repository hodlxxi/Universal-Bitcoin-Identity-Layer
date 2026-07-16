from datetime import datetime, timezone

import pytest

from app.services.trust_surface import daily_report_period, parse_daily_report_id

REPORT_ID = "hodlxxi-herald-01-daily-20260716"
VALIDATION_TIME = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def test_daily_report_id_defines_fixed_exclusive_utc_cutoff():
    parsed = parse_daily_report_id(
        REPORT_ID,
        expected_agent_id="hodlxxi-herald-01",
        now=VALIDATION_TIME,
    )

    assert parsed is not None
    agent_id, period_end = parsed
    period_from, period_to = daily_report_period(period_end)

    assert agent_id == "hodlxxi-herald-01"
    assert period_from == datetime(2026, 7, 15, 0, 0, tzinfo=timezone.utc)
    assert period_to == datetime(2026, 7, 16, 0, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "report_id",
    [
        "arbitrary-report",
        "hodlxxi-herald-01-daily-test",
        "hodlxxi-herald-01-daily-20260230",
        "other-agent-daily-20260716",
        "hodlxxi-herald-01-daily-20260717",
    ],
)
def test_daily_report_id_rejects_unsupported_ids(report_id):
    assert (
        parse_daily_report_id(
            report_id,
            expected_agent_id="hodlxxi-herald-01",
            now=VALIDATION_TIME,
        )
        is None
    )


def test_daily_report_period_requires_utc_midnight():
    with pytest.raises(ValueError, match="UTC midnight"):
        daily_report_period(datetime(2026, 7, 16, 0, 0, 1, tzinfo=timezone.utc))

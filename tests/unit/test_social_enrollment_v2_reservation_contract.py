"""Configuration validation creates no authority or alternate wire."""

from dataclasses import replace
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.services.social_enrollment_v2_reservation_authority import LockedReservationCandidate
from app.services.social_enrollment_v2_reservation_contract import RUNTIME_ENABLED, ReservationConfig, ReservationDenied
from app.services.social_session_issuance_v2_contract import milliseconds, trusted_now
from tests.unit.test_social_enrollment_v2_reservation import configuration


def test_default_is_disabled_and_runtime_stays_dormant():
    config = ReservationConfig()
    assert config.enabled is False and config.evidence_config.enabled is False
    assert RUNTIME_ENABLED is False
    with pytest.raises(ReservationDenied):
        config.selected_trust()
    with pytest.raises(ReservationDenied):
        LockedReservationCandidate()


@pytest.mark.parametrize(
    "change",
    [
        dict(enabled=1),
        dict(backend_id="bad backend"),
        dict(selected_kid="missing"),
        dict(selected_revision=True),
        dict(selected_revision=2),
        dict(trust_pins=()),
        dict(evidence_config={"verified": True}),
        dict(verification_audience="http://social.example"),
    ],
)
def test_invalid_configuration_has_sanitized_failure(change):
    config = configuration(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    with pytest.raises(ReservationDenied) as error:
        replace(config, **change)
    assert error.value.__context__ is None and error.value.__cause__ is None
    assert str(error.value) == "social enrollment v2 reservation denied"


def test_server_clock_requires_aware_datetime_and_floors_fractional_milliseconds():
    now = datetime(2026, 9, 8, tzinfo=timezone.utc).replace(microsecond=999999)
    assert milliseconds(trusted_now(lambda: now)) % 1000 == 999
    for value in (now.replace(tzinfo=None), {}, True, 123):
        with pytest.raises(ValueError):
            trusted_now(lambda: value)


@pytest.mark.parametrize("field,change", [("trust_revision", 2), ("not_before", 0), ("not_after", 1)])
def test_original_kid_cannot_relabel_revision_or_bounds_even_with_replaced_pin(field, change):
    config = configuration(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    original = config.selected_trust()
    value = original.not_after + change if field == "not_after" else change
    record = replace(original, **{field: value})
    ec = replace(config.evidence_config, trust_records=(record,))
    with pytest.raises(ReservationDenied):
        replace(
            config,
            evidence_config=ec,
            selected_revision=record.trust_revision,
            trust_pins=((record.key_id, record.trust_revision, record.trust_record_id),),
        )

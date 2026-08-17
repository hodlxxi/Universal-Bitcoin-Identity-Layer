from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

import pytest

from app.services.canonical_covenant_funding_set import (
    CanonicalCovenantFundingSet,
    CovenantFundingSetLifecycle,
    InvalidCanonicalCovenantFundingSet,
    RecognizedCovenantFundingOutpoint,
    canonical_covenant_funding_set_bytes,
    canonical_covenant_funding_set_sha256,
    create_canonical_covenant_funding_set,
    parse_canonical_covenant_funding_set,
    validate_funding_set_registration,
)
from app.services.covenant_relation import CovenantDirection
from app.services.mirrored_covenant_pair import CovenantDeltaProfile, validate_mirrored_covenant_pair
from app.services.trusted_covenant_registration import (
    RegisteredCovenantOutpoint,
    TrustedCovenantRegistrationLifecycle,
    create_trusted_covenant_registration,
)

SUBJECT = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
LEG1 = "6303681d1bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac670371201bb17521032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8cac68"
LEG2 = "630371201bb17521032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8cac67037a231bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac68"
NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)


def registration(state=TrustedCovenantRegistrationLifecycle.ACTIVE):
    pair = validate_mirrored_covenant_pair(
        LEG1, LEG2, subject_pubkey=SUBJECT, allowed_delta_profiles=(CovenantDeltaProfile.LEGACY_777,)
    )
    return create_trusted_covenant_registration(
        pair,
        (
            RegisteredCovenantOutpoint(
                CovenantDirection.INCOMING, "a" * 64, 0, 133129, pair.incoming_leg_script_sha256, "c" * 64
            ),
            RegisteredCovenantOutpoint(
                CovenantDirection.OUTGOING, "d" * 64, 1, 122223, pair.outgoing_leg_script_sha256
            ),
        ),
        registration_id="00000000-0000-4000-8000-000000000001",
        lifecycle_state=state,
        registered_at=NOW,
        lifecycle_changed_at=NOW,
    )


def funding(reg=None, reverse=False):
    reg = reg or registration()
    pair = reg.mirrored_pair
    values = (
        RecognizedCovenantFundingOutpoint(
            CovenantDirection.INCOMING, "a" * 64, 0, 133129, pair.incoming_leg_script_sha256, "c" * 64
        ),
        RecognizedCovenantFundingOutpoint(
            CovenantDirection.INCOMING, "b" * 64, 2, 44648, pair.incoming_leg_script_sha256
        ),
        RecognizedCovenantFundingOutpoint(
            CovenantDirection.INCOMING, "c" * 64, 3, 122223, pair.incoming_leg_script_sha256
        ),
        RecognizedCovenantFundingOutpoint(
            CovenantDirection.OUTGOING, "d" * 64, 1, 122223, pair.outgoing_leg_script_sha256
        ),
        RecognizedCovenantFundingOutpoint(
            CovenantDirection.OUTGOING, "e" * 64, 4, 177777, pair.outgoing_leg_script_sha256
        ),
    )
    return create_canonical_covenant_funding_set(
        funding_set_id="00000000-0000-4000-8000-000000000010",
        trusted_registration=reg,
        lifecycle_state=CovenantFundingSetLifecycle.EFFECTIVE,
        created_at=NOW,
        lifecycle_changed_at=NOW,
        effective_at=NOW,
        recognized_outpoints=tuple(reversed(values)) if reverse else values,
    )


def test_multi_utxo_vector_canonical_roundtrip_digest_and_immutability():
    value = funding(reverse=True)
    assert [x.amount_sats for x in value.recognized_outpoints if x.direction is CovenantDirection.INCOMING] == [
        133129,
        44648,
        122223,
    ]
    assert [x.amount_sats for x in value.recognized_outpoints if x.direction is CovenantDirection.OUTGOING] == [
        122223,
        177777,
    ]
    assert canonical_covenant_funding_set_bytes(value) == canonical_covenant_funding_set_bytes(funding())
    assert parse_canonical_covenant_funding_set(canonical_covenant_funding_set_bytes(value)) == value
    assert canonical_covenant_funding_set_sha256(value) == canonical_covenant_funding_set_sha256(funding())
    with pytest.raises(FrozenInstanceError):
        value.funding_set_id = "x"


@pytest.mark.parametrize("amount", [True, 1.0, "1", 0, -1])
def test_amount_is_positive_exact_int(amount):
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        RecognizedCovenantFundingOutpoint(CovenantDirection.INCOMING, "a" * 64, 0, amount, "b" * 64)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("txid", "g" * 64),
        ("txid", "A" * 64),
        ("vout", True),
        ("vout", 1.0),
        ("vout", -1),
        ("vout", 4294967296),
        ("witness_script_sha256", "g" * 64),
        ("descriptor_sha256", "G" * 64),
    ),
)
def test_outpoint_fields_reject_malformed_values_and_coercion(field, value):
    values = {
        "direction": CovenantDirection.INCOMING,
        "txid": "a" * 64,
        "vout": 0,
        "amount_sats": 1,
        "witness_script_sha256": "b" * 64,
        "descriptor_sha256": None,
    }
    values[field] = value
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        RecognizedCovenantFundingOutpoint(**values)


@pytest.mark.parametrize(
    ("state", "effective", "successor"),
    (
        (CovenantFundingSetLifecycle.PROPOSED, NOW, None),
        (CovenantFundingSetLifecycle.EFFECTIVE, None, None),
        (CovenantFundingSetLifecycle.EFFECTIVE, NOW, "00000000-0000-4000-8000-000000000099"),
        (CovenantFundingSetLifecycle.SUPERSEDED, NOW, None),
        (CovenantFundingSetLifecycle.REVOKED, None, "00000000-0000-4000-8000-000000000099"),
    ),
)
def test_lifecycle_consistency_fails_closed(state, effective, successor):
    value = funding()
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        replace(value, lifecycle_state=state, effective_at=effective, superseded_by_funding_set_id=successor)


@pytest.mark.parametrize(
    "state",
    (
        CovenantFundingSetLifecycle.DISPUTED,
        CovenantFundingSetLifecycle.REVOKED,
    ),
)
@pytest.mark.parametrize("effective", (NOW - timedelta(seconds=1), NOW + timedelta(seconds=1)))
def test_disputed_and_revoked_effective_time_must_stay_within_lifecycle_bounds(state, effective):
    value = funding()
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        replace(value, lifecycle_state=state, effective_at=effective)


@pytest.mark.parametrize(
    "field",
    (
        "trusted_registration_id",
        "trusted_registration_sha256",
        "pair_sha256",
        "subject_xonly_pubkey",
        "counterparty_xonly_pubkey",
    ),
)
def test_effective_registration_projection_mismatches_fail_closed(field):
    value = funding()
    replacement = "00000000-0000-4000-8000-000000000099" if field.endswith("_id") else "f" * 64
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        validate_funding_set_registration(replace(value, **{field: replacement}), registration())


def test_noncanonical_and_tampered_json_fail_closed():
    canonical = canonical_covenant_funding_set_bytes(funding())
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        parse_canonical_covenant_funding_set(canonical.decode("ascii") + " ")
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        parse_canonical_covenant_funding_set(canonical.replace(b'"pair_sha256":"', b'"pair_sha256":"g'))


def test_duplicate_wrong_script_missing_direction_and_anchor_fail_closed():
    value = funding()
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        replace(value, recognized_outpoints=value.recognized_outpoints + (value.recognized_outpoints[0],))
    wrong = replace(value.recognized_outpoints[1], witness_script_sha256="f" * 64)
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        validate_funding_set_registration(
            replace(
                value, recognized_outpoints=(value.recognized_outpoints[0], wrong) + value.recognized_outpoints[2:]
            ),
            registration(),
        )
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        validate_funding_set_registration(
            replace(value, recognized_outpoints=value.recognized_outpoints[1:]), registration()
        )
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        CanonicalCovenantFundingSet(
            *(getattr(value, f) for f in list(CanonicalCovenantFundingSet.__dataclass_fields__)[:-1]),
            tuple(x for x in value.recognized_outpoints if x.direction is CovenantDirection.INCOMING),
        )


def test_inactive_and_registration_projection_mismatch_fail_closed():
    value = funding()
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        validate_funding_set_registration(value, registration(TrustedCovenantRegistrationLifecycle.REVOKED))
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        validate_funding_set_registration(replace(value, pair_sha256="f" * 64), registration())


def test_one_incoming_two_outgoing_is_structurally_valid_when_anchor_exact():
    reg = registration()
    p = reg.mirrored_pair
    value = create_canonical_covenant_funding_set(
        funding_set_id="00000000-0000-4000-8000-000000000011",
        trusted_registration=reg,
        lifecycle_state=CovenantFundingSetLifecycle.EFFECTIVE,
        created_at=NOW,
        lifecycle_changed_at=NOW,
        effective_at=NOW,
        recognized_outpoints=(
            RecognizedCovenantFundingOutpoint(
                CovenantDirection.INCOMING, "a" * 64, 0, 133129, p.incoming_leg_script_sha256, "c" * 64
            ),
            RecognizedCovenantFundingOutpoint(
                CovenantDirection.OUTGOING, "d" * 64, 1, 122223, p.outgoing_leg_script_sha256
            ),
            RecognizedCovenantFundingOutpoint(
                CovenantDirection.OUTGOING, "e" * 64, 2, 50000, p.outgoing_leg_script_sha256
            ),
        ),
    )
    assert len(value.recognized_outpoints) == 3

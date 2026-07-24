from dataclasses import FrozenInstanceError
from dataclasses import replace

import pytest

from app.services.mirrored_covenant_pair import (
    LEG_SCHEMA,
    NETWORK,
    PAIR_SCHEMA,
    VALIDATOR_VERSION,
    CovenantDeltaProfile,
    CovenantTemplateFamily,
    InvalidMirroredCovenantPair,
    MirroredCovenantErrorCode,
    ParsedCovenantLeg,
    ValidatedMirroredCovenantPair,
    canonical_mirrored_pair_bytes,
    mirrored_covenant_pair_sha256,
    parse_covenant_leg,
    validate_mirrored_covenant_pair,
)

OPERATOR = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
AGENT = "02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92"
LEGACY = "032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8c"


def num(value):
    if value == -1:
        return b"\x4f"
    if value == 0:
        return b"\x00"
    if 1 <= value <= 16:
        return bytes((0x50 + value,))
    data = bytearray()
    while value:
        data.append(value & 255)
        value >>= 8
    if data[-1] & 128:
        data.append(0)
    return bytes((len(data),)) + bytes(data)


def direct_num(hex_value):
    data = bytes.fromhex(hex_value)
    return bytes((len(data),)) + data


def push(hex_value):
    data = bytes.fromhex(hex_value)
    return bytes((len(data),)) + data


def cltv(receiver, sender, rh, sh):
    return (
        b"\x63"
        + num(rh)
        + b"\xb1\x75"
        + push(receiver)
        + b"\xac\x67"
        + num(sh)
        + b"\xb1\x75"
        + push(sender)
        + b"\xac\x68"
    ).hex()


def coop(receiver, sender, rh, sh, keys=None):
    one, two = keys or (receiver, sender)
    return (
        b"\x63\x52"
        + push(one)
        + push(two)
        + b"\x52\xae\x67\x63"
        + num(rh)
        + b"\xb1\x75"
        + push(receiver)
        + b"\xac\x67"
        + num(sh)
        + b"\xb1\x75"
        + push(sender)
        + b"\xac\x68\x68"
    ).hex()


def cltv_with_operands(receiver, sender, receiver_operand, sender_operand):
    return (
        b"\x63"
        + receiver_operand
        + b"\xb1\x75"
        + push(receiver)
        + b"\xac\x67"
        + sender_operand
        + b"\xb1\x75"
        + push(sender)
        + b"\xac\x68"
    ).hex()


LEGACY_1 = cltv(OPERATOR, LEGACY, 1777000, 1777777)
LEGACY_2 = cltv(LEGACY, OPERATOR, 1777777, 1778554)
CURRENT_1 = coop(AGENT, OPERATOR, 1777777, 1777921)
CURRENT_2 = coop(OPERATOR, AGENT, 1777921, 1778065)

# Literal assertions prevent helpers from silently redefining the supplied vectors.
assert (
    LEGACY_1
    == "6303681d1bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac670371201bb17521032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8cac68"
)
assert (
    LEGACY_2
    == "630371201bb17521032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8cac67037a231bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac68"
)
assert (
    CURRENT_1
    == "63522102019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f9221023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e92352ae67630371201bb1752102019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92ac670301211bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac6868"
)


def test_parse_and_validate_legacy():
    assert parse_covenant_leg(LEGACY_1).delta_blocks == 777
    assert parse_covenant_leg(LEGACY_2).receiver_pubkey == LEGACY
    pair = validate_mirrored_covenant_pair(
        LEGACY_1, LEGACY_2, subject_pubkey=OPERATOR, allowed_delta_profiles=(CovenantDeltaProfile.LEGACY_777,)
    )
    assert pair.delta_profile is CovenantDeltaProfile.LEGACY_777
    with pytest.raises(InvalidMirroredCovenantPair) as error:
        validate_mirrored_covenant_pair(
            LEGACY_1, LEGACY_2, subject_pubkey=OPERATOR, allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,)
        )
    assert error.value.code is MirroredCovenantErrorCode.DISALLOWED_DELTA_PROFILE


def test_current_pair_both_subjects_order_and_digest():
    operator = validate_mirrored_covenant_pair(
        CURRENT_1, CURRENT_2, subject_pubkey=OPERATOR, allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,)
    )
    reverse = validate_mirrored_covenant_pair(
        CURRENT_2, CURRENT_1, subject_pubkey=OPERATOR, allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,)
    )
    agent = validate_mirrored_covenant_pair(
        CURRENT_1, CURRENT_2, subject_pubkey=AGENT, allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,)
    )
    assert operator == reverse
    assert canonical_mirrored_pair_bytes(operator) == canonical_mirrored_pair_bytes(reverse)
    assert mirrored_covenant_pair_sha256(operator) == mirrored_covenant_pair_sha256(reverse)
    assert operator.counterparty_pubkey == AGENT
    assert agent.counterparty_pubkey == OPERATOR
    assert parse_covenant_leg(CURRENT_1).template_family is CovenantTemplateFamily.COOPERATIVE_2_OF_2_CLTV
    with pytest.raises(FrozenInstanceError):
        operator.delta_blocks = 777


def test_op_1_is_a_canonical_cltv_height():
    assert parse_covenant_leg(cltv(OPERATOR, AGENT, 1, 17)).receiver_height == 1


def test_op_16_is_a_canonical_cltv_height():
    assert parse_covenant_leg(cltv(OPERATOR, AGENT, 16, 17)).receiver_height == 16


def test_op_2_is_both_cooperative_structure_and_cltv_height():
    leg = parse_covenant_leg(coop(AGENT, OPERATOR, 2, 146))
    assert leg.receiver_height == 2
    assert leg.template_family is CovenantTemplateFamily.COOPERATIVE_2_OF_2_CLTV
    assert leg.cooperative_pubkeys == tuple(sorted((AGENT, OPERATOR)))


@pytest.mark.parametrize("operand", (b"\x00", b"\x4f"))
def test_non_positive_small_integer_reaches_lock_height_validation(operand):
    with pytest.raises(InvalidMirroredCovenantPair) as error:
        parse_covenant_leg(cltv_with_operands(OPERATOR, AGENT, operand, num(17)))
    assert error.value.code is MirroredCovenantErrorCode.INVALID_LOCK_HEIGHT


def test_negative_zero_is_an_invalid_lock_height():
    with pytest.raises(InvalidMirroredCovenantPair) as error:
        parse_covenant_leg(cltv_with_operands(OPERATOR, AGENT, direct_num("80"), num(17)))
    assert error.value.code is MirroredCovenantErrorCode.INVALID_LOCK_HEIGHT


@pytest.mark.parametrize("encoded", ("01", "10", "81"))
def test_direct_pushed_small_integer_is_non_canonical(encoded):
    with pytest.raises(InvalidMirroredCovenantPair) as error:
        parse_covenant_leg(cltv_with_operands(OPERATOR, AGENT, direct_num(encoded), num(17)))
    assert error.value.code is MirroredCovenantErrorCode.NON_CANONICAL_SCRIPT


@pytest.mark.parametrize("bad", ["", "AA", "0x12", "12 ", "1", "zz"])
def test_bad_hex(bad):
    with pytest.raises(InvalidMirroredCovenantPair):
        parse_covenant_leg(bad)


def test_pair_rejections():
    cases = [
        (LEGACY_1, LEGACY_1, MirroredCovenantErrorCode.DUPLICATE_SCRIPT),
        (LEGACY_1, CURRENT_2, MirroredCovenantErrorCode.MIXED_TEMPLATE_FAMILY),
        (cltv(OPERATOR, AGENT, 17, 161), cltv(AGENT, OPERATOR, 161, 938), MirroredCovenantErrorCode.INVALID_DELTA),
        (
            cltv(OPERATOR, AGENT, 17, 161),
            cltv(AGENT, OPERATOR, 162, 306),
            MirroredCovenantErrorCode.MIDDLE_HEIGHT_MISMATCH,
        ),
        (LEGACY_1, cltv(AGENT, OPERATOR, 1777777, 1778554), MirroredCovenantErrorCode.PARTICIPANT_MISMATCH),
    ]
    for first, second, code in cases:
        with pytest.raises(InvalidMirroredCovenantPair) as error:
            validate_mirrored_covenant_pair(
                first,
                second,
                subject_pubkey=OPERATOR,
                allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144, CovenantDeltaProfile.LEGACY_777),
            )
        assert error.value.code is code


def test_cooperative_and_subject_rejections():
    with pytest.raises(InvalidMirroredCovenantPair) as error:
        parse_covenant_leg(coop(AGENT, OPERATOR, 17, 161, (AGENT, AGENT)))
    assert error.value.code is MirroredCovenantErrorCode.COOPERATIVE_PARTICIPANT_MISMATCH
    with pytest.raises(InvalidMirroredCovenantPair) as error:
        validate_mirrored_covenant_pair(
            CURRENT_1, CURRENT_2, subject_pubkey=LEGACY, allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,)
        )
    assert error.value.code is MirroredCovenantErrorCode.SUBJECT_NOT_PARTICIPANT


def test_exact_types_and_trailing_opcode():
    for value in (None, b"00", True):
        with pytest.raises(InvalidMirroredCovenantPair):
            parse_covenant_leg(value)
    with pytest.raises(InvalidMirroredCovenantPair):
        validate_mirrored_covenant_pair(
            CURRENT_1, CURRENT_2, subject_pubkey=OPERATOR, allowed_delta_profiles=[CovenantDeltaProfile.CURRENT_144]
        )
    with pytest.raises(InvalidMirroredCovenantPair):
        parse_covenant_leg(LEGACY_1 + "61")


def test_direct_leg_constructor_cannot_forge_raw_script_semantics():
    real = parse_covenant_leg(CURRENT_1)
    with pytest.raises(InvalidMirroredCovenantPair) as error:
        replace(
            real,
            receiver_pubkey=real.sender_pubkey,
            receiver_xonly_pubkey=real.sender_xonly_pubkey,
            sender_pubkey=real.receiver_pubkey,
            sender_xonly_pubkey=real.receiver_xonly_pubkey,
            receiver_height=real.sender_height,
            sender_height=real.sender_height + real.delta_blocks,
        )
    assert error.value.code is MirroredCovenantErrorCode.NON_CANONICAL_SCRIPT


def test_same_raw_script_cannot_supply_two_claimed_roles_to_direct_pair():
    leg = parse_covenant_leg(CURRENT_1)
    with pytest.raises(InvalidMirroredCovenantPair):
        forged = replace(
            leg,
            receiver_pubkey=leg.sender_pubkey,
            receiver_xonly_pubkey=leg.sender_xonly_pubkey,
            sender_pubkey=leg.receiver_pubkey,
            sender_xonly_pubkey=leg.receiver_xonly_pubkey,
            receiver_height=leg.sender_height,
            sender_height=leg.sender_height + leg.delta_blocks,
        )
        ValidatedMirroredCovenantPair(
            PAIR_SCHEMA,
            VALIDATOR_VERSION,
            NETWORK,
            OPERATOR,
            OPERATOR[2:],
            AGENT,
            AGENT[2:],
            leg.template_family,
            CovenantDeltaProfile.CURRENT_144,
            144,
            leg,
            forged,
            leg.script_sha256,
            forged.script_sha256,
        )


def test_direct_pair_rejects_duplicate_authoritative_leg():
    valid = validate_mirrored_covenant_pair(
        CURRENT_1,
        CURRENT_2,
        subject_pubkey=OPERATOR,
        allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,),
    )
    with pytest.raises(InvalidMirroredCovenantPair) as error:
        replace(valid, later_leg=valid.earlier_leg)
    assert error.value.code is MirroredCovenantErrorCode.DUPLICATE_SCRIPT


def test_canonicalization_revalidates_mutated_frozen_pair():
    pair = validate_mirrored_covenant_pair(
        CURRENT_1,
        CURRENT_2,
        subject_pubkey=OPERATOR,
        allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,),
    )
    object.__setattr__(pair, "incoming_leg_script_sha256", "00" * 32)
    with pytest.raises(InvalidMirroredCovenantPair):
        canonical_mirrored_pair_bytes(pair)


def test_canonicalization_rejects_nested_bool_equal_to_integer_mutation():
    pair = validate_mirrored_covenant_pair(
        cltv(OPERATOR, AGENT, 1, 145),
        cltv(AGENT, OPERATOR, 145, 289),
        subject_pubkey=OPERATOR,
        allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,),
    )
    assert pair.earlier_leg.receiver_height == 1
    object.__setattr__(pair.earlier_leg, "receiver_height", True)
    with pytest.raises(InvalidMirroredCovenantPair):
        canonical_mirrored_pair_bytes(pair)


def test_canonicalization_rejects_nested_float_equal_to_integer_mutation():
    pair = validate_mirrored_covenant_pair(
        CURRENT_1,
        CURRENT_2,
        subject_pubkey=OPERATOR,
        allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,),
    )
    object.__setattr__(pair.earlier_leg, "delta_blocks", 144.0)
    with pytest.raises(InvalidMirroredCovenantPair):
        canonical_mirrored_pair_bytes(pair)


def test_exact_same_participants_with_roles_not_mirrored():
    first = cltv(OPERATOR, AGENT, 17, 161)
    second = cltv(OPERATOR, AGENT, 161, 305)
    with pytest.raises(InvalidMirroredCovenantPair) as error:
        validate_mirrored_covenant_pair(
            first,
            second,
            subject_pubkey=OPERATOR,
            allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,),
        )
    assert error.value.code is MirroredCovenantErrorCode.ROLES_NOT_MIRRORED


@pytest.mark.parametrize(
    "script",
    (
        coop(AGENT, OPERATOR, 17, 161).replace("6352", "6351", 1),
        (b"\x63\x52" + push(AGENT) + push(OPERATOR) + push(LEGACY) + b"\x53\xae\x68").hex(),
        coop(AGENT, OPERATOR, 17, 161, (AGENT, AGENT)),
        coop(AGENT, OPERATOR, 17, 161, (AGENT, LEGACY)),
    ),
)
def test_invalid_cooperative_thresholds_and_participants(script):
    with pytest.raises(InvalidMirroredCovenantPair):
        parse_covenant_leg(script)


def test_pushdata1_and_scriptnum_canonicality_vectors():
    minimally_encoded_but_wrong_template = (b"\x4c\x4c" + b"\x01" * 76).hex()
    nonminimal_short_push = (
        b"\x63\x4c\x01\x11\xb1\x75" + push(OPERATOR) + b"\xac\x67" + num(161) + b"\xb1\x75" + push(AGENT) + b"\xac\x68"
    ).hex()
    redundant_sign = cltv_with_operands(OPERATOR, AGENT, direct_num("1100"), num(161))
    for script in (minimally_encoded_but_wrong_template, nonminimal_short_push, redundant_sign):
        with pytest.raises(InvalidMirroredCovenantPair):
            parse_covenant_leg(script)


@pytest.mark.parametrize(
    ("receiver_height", "sender_height"),
    ((500_000_000, 500_000_144), (17, 17), (161, 17)),
)
def test_invalid_locktime_relationship_vectors(receiver_height, sender_height):
    with pytest.raises(InvalidMirroredCovenantPair):
        parse_covenant_leg(cltv(OPERATOR, AGENT, receiver_height, sender_height))


@pytest.mark.parametrize(
    "bad_key",
    (
        "04" + "01" * 32,
        "02" + "ff" * 32,
        "02" + "00" * 32,
    ),
)
def test_invalid_compressed_pubkey_vectors(bad_key):
    with pytest.raises(InvalidMirroredCovenantPair) as error:
        parse_covenant_leg(cltv(bad_key, AGENT, 17, 161))
    assert error.value.code is MirroredCovenantErrorCode.INVALID_PUBKEY


def test_opposite_compressed_prefixes_same_xonly_identity():
    opposite_agent = ("03" if AGENT.startswith("02") else "02") + AGENT[2:]
    with pytest.raises(InvalidMirroredCovenantPair) as error:
        parse_covenant_leg(cltv(AGENT, opposite_agent, 17, 161))
    assert error.value.code is MirroredCovenantErrorCode.XONLY_IDENTITY_COLLISION


def test_delta_allow_list_and_arbitrary_delta_vectors():
    for profiles in ((), (CovenantDeltaProfile.CURRENT_144, CovenantDeltaProfile.CURRENT_144)):
        with pytest.raises(InvalidMirroredCovenantPair):
            validate_mirrored_covenant_pair(
                CURRENT_1, CURRENT_2, subject_pubkey=OPERATOR, allowed_delta_profiles=profiles
            )
    with pytest.raises(InvalidMirroredCovenantPair) as error:
        validate_mirrored_covenant_pair(
            cltv(OPERATOR, AGENT, 17, 162),
            cltv(AGENT, OPERATOR, 162, 307),
            subject_pubkey=OPERATOR,
            allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,),
        )
    assert error.value.code is MirroredCovenantErrorCode.UNSUPPORTED_DELTA_PROFILE


def test_bool_integer_fields_fail_closed_in_direct_construction():
    leg = parse_covenant_leg(cltv(OPERATOR, AGENT, 1, 145))
    with pytest.raises(InvalidMirroredCovenantPair):
        replace(leg, receiver_height=True)
    pair = validate_mirrored_covenant_pair(
        CURRENT_1,
        CURRENT_2,
        subject_pubkey=OPERATOR,
        allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,),
    )
    with pytest.raises(InvalidMirroredCovenantPair):
        replace(pair, delta_blocks=True)


def test_public_models_are_frozen():
    leg = parse_covenant_leg(CURRENT_1)
    pair = validate_mirrored_covenant_pair(
        CURRENT_1,
        CURRENT_2,
        subject_pubkey=OPERATOR,
        allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,),
    )
    with pytest.raises(FrozenInstanceError):
        leg.delta_blocks = 777
    with pytest.raises(FrozenInstanceError):
        pair.delta_blocks = 777

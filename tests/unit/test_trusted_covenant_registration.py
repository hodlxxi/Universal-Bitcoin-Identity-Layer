from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from app.services.covenant_relation import CovenantDirection
from app.services.mirrored_covenant_pair import CovenantDeltaProfile, validate_mirrored_covenant_pair
from app.services.trusted_covenant_registration import (
    REGISTRATION_SCHEMA,
    REGISTRATION_VERSION,
    NETWORK,
    InvalidTrustedCovenantRegistration,
    RegisteredCovenantOutpoint,
    TrustedCovenantRegistrationLifecycle,
    canonical_trusted_registration_bytes,
    create_trusted_covenant_registration,
    p2wsh_script_pubkey_sha256,
    trusted_outpoints_from_registration,
    trusted_registration_sha256,
)
from app.services.trusted_covenant_observation import TrustedBitcoinCovenantObservationAdapter

OPERATOR = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
LEGACY = "032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8c"
AGENT = "02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92"
LEGACY_1 = "6303681d1bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac670371201bb17521032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8cac68"
LEGACY_2 = "630371201bb17521032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8cac67037a231bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac68"
NOW = datetime(2026, 7, 25, 12, tzinfo=timezone.utc)


def _num(value):
    data = bytearray()
    while value:
        data.append(value & 255)
        value >>= 8
    if data[-1] & 128:
        data.append(0)
    return bytes((len(data),)) + bytes(data)


def _push(pubkey):
    raw = bytes.fromhex(pubkey)
    return bytes((len(raw),)) + raw


def _cooperative(receiver, sender, receiver_height, sender_height):
    first, second = sorted((receiver, sender))
    return (
        b"\x63\x52"
        + _push(first)
        + _push(second)
        + b"\x52\xae\x67\x63"
        + _num(receiver_height)
        + b"\xb1\x75"
        + _push(receiver)
        + b"\xac\x67"
        + _num(sender_height)
        + b"\xb1\x75"
        + _push(sender)
        + b"\xac\x68\x68"
    ).hex()


def pair():
    return validate_mirrored_covenant_pair(
        LEGACY_1,
        LEGACY_2,
        subject_pubkey=OPERATOR,
        allowed_delta_profiles=(CovenantDeltaProfile.LEGACY_777,),
    )


def registration(*, state=TrustedCovenantRegistrationLifecycle.ACTIVE, reverse=False, superseded=None):
    validated = pair()
    bindings = (
        RegisteredCovenantOutpoint(
            CovenantDirection.INCOMING, "a" * 64, 0, 123, validated.incoming_leg_script_sha256, "c" * 64
        ),
        RegisteredCovenantOutpoint(CovenantDirection.OUTGOING, "b" * 64, 7, 456, validated.outgoing_leg_script_sha256),
    )
    return create_trusted_covenant_registration(
        validated,
        tuple(reversed(bindings)) if reverse else bindings,
        registration_id="00000000-0000-4000-8000-000000000001",
        lifecycle_state=state,
        registered_at=NOW,
        lifecycle_changed_at=NOW,
        superseded_by_registration_id=superseded,
    )


def test_valid_exact_registration_is_canonical_ordered_and_preserves_unequal_amounts():
    value = registration(reverse=True)
    assert (REGISTRATION_SCHEMA, REGISTRATION_VERSION, NETWORK) == (
        value.schema,
        value.registration_version,
        value.network,
    )
    assert tuple(item.direction for item in value.outpoints) == (
        CovenantDirection.INCOMING,
        CovenantDirection.OUTGOING,
    )
    assert tuple(item.amount_sats for item in trusted_outpoints_from_registration(value)) == (123, 456)
    assert value.subject_xonly_pubkey == value.subject_pubkey[2:]
    assert value.counterparty_xonly_pubkey == value.counterparty_pubkey[2:]
    assert canonical_trusted_registration_bytes(value) == canonical_trusted_registration_bytes(registration())
    assert trusted_registration_sha256(value) == trusted_registration_sha256(registration())
    assert b'"witness_script_sha256":' in canonical_trusted_registration_bytes(value)
    assert b'"script_sha256":' not in canonical_trusted_registration_bytes(value)


@pytest.mark.parametrize(
    ("witness_digest", "expected"),
    (
        ("0" * 64, "cb87c4abf1ab1968f184f55a0ddbbb54a4da8123c05437a4fcc71c5bc2cab8c9"),
        ("f" * 64, "e4f65c3e30d4881df084723dc542e785160158eb9b0099521db5ebf0ca355c15"),
    ),
)
def test_p2wsh_script_pubkey_hash_vectors_and_strict_input(witness_digest, expected):
    assert p2wsh_script_pubkey_sha256(witness_digest) == expected
    with pytest.raises(InvalidTrustedCovenantRegistration):
        p2wsh_script_pubkey_sha256("A" * 64)


def test_materialized_native_p2wsh_definitions_observe_real_core_style_outputs():
    value = registration()
    value = replace(
        value,
        outpoints=tuple(replace(item, descriptor_sha256=None) for item in value.outpoints),
    )
    definitions = trusted_outpoints_from_registration(value)
    best_block = "9" * 64
    responses = {
        (definition.txid, definition.vout): {
            "bestblock": best_block,
            "confirmations": 6,
            "value": Decimal(definition.amount_sats) / Decimal(100_000_000),
            "scriptPubKey": {
                "hex": "0020" + binding.witness_script_sha256,
            },
        }
        for definition, binding in zip(definitions, value.outpoints)
    }

    class Rpc:
        def getblockcount(self):
            return 900_000

        def getbestblockhash(self):
            return best_block

        def gettxout(self, txid, vout, include_mempool):
            assert include_mempool is False
            return responses[(txid, vout)]

    for definition, binding in zip(definitions, value.outpoints):
        assert definition.script_sha256 == p2wsh_script_pubkey_sha256(binding.witness_script_sha256)
        assert definition.script_sha256 != binding.witness_script_sha256
    evaluation = TrustedBitcoinCovenantObservationAdapter(Rpc(), clock=lambda: NOW).observe(definitions)
    assert len(evaluation.observations) == 2
    assert all(observation.unspent for observation in evaluation.observations)


def test_explicit_current_144_cooperative_pair_can_be_registered_separately():
    validated = validate_mirrored_covenant_pair(
        _cooperative(AGENT, OPERATOR, 1777777, 1777921),
        _cooperative(OPERATOR, AGENT, 1777921, 1778065),
        subject_pubkey=OPERATOR,
        allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144,),
    )
    value = create_trusted_covenant_registration(
        validated,
        (
            RegisteredCovenantOutpoint(
                CovenantDirection.INCOMING, "d" * 64, 3, 9, validated.incoming_leg_script_sha256
            ),
            RegisteredCovenantOutpoint(
                CovenantDirection.OUTGOING, "e" * 64, 4, 11, validated.outgoing_leg_script_sha256
            ),
        ),
        registration_id="00000000-0000-4000-8000-000000000003",
        lifecycle_state=TrustedCovenantRegistrationLifecycle.ACTIVE,
        registered_at=NOW,
        lifecycle_changed_at=NOW,
    )
    assert value.delta_profile is CovenantDeltaProfile.CURRENT_144
    assert value.delta_blocks == 144


def test_frozen_slotted_and_mutation_is_detected():
    value = registration()
    with pytest.raises(FrozenInstanceError):
        value.network = "testnet"
    assert not hasattr(value, "__dict__")
    object.__setattr__(value, "pair_sha256", "f" * 64)
    with pytest.raises(InvalidTrustedCovenantRegistration):
        canonical_trusted_registration_bytes(value)
    with pytest.raises(InvalidTrustedCovenantRegistration):
        trusted_outpoints_from_registration(value)


@pytest.mark.parametrize("field", ("vout", "amount_sats"))
def test_bool_integer_binding_fields_are_rejected(field):
    validated = pair()
    values = dict(
        direction=CovenantDirection.INCOMING,
        txid="a" * 64,
        vout=0,
        amount_sats=1,
        witness_script_sha256=validated.incoming_leg_script_sha256,
    )
    values[field] = True
    with pytest.raises(InvalidTrustedCovenantRegistration):
        RegisteredCovenantOutpoint(**values)


def test_duplicate_outpoint_direction_script_and_noncanonical_inputs_fail():
    validated = pair()
    incoming = RegisteredCovenantOutpoint(
        CovenantDirection.INCOMING, "a" * 64, 1, 1, validated.incoming_leg_script_sha256
    )
    outgoing_same = RegisteredCovenantOutpoint(
        CovenantDirection.OUTGOING, "a" * 64, 1, 1, validated.outgoing_leg_script_sha256
    )
    with pytest.raises(InvalidTrustedCovenantRegistration):
        create_trusted_covenant_registration(
            validated,
            (incoming, outgoing_same),
            registration_id="00000000-0000-4000-8000-000000000001",
            lifecycle_state=TrustedCovenantRegistrationLifecycle.ACTIVE,
            registered_at=NOW,
            lifecycle_changed_at=NOW,
        )
    with pytest.raises(InvalidTrustedCovenantRegistration):
        replace(registration(), registration_id="00000000-0000-4000-8000-00000000000A")
    with pytest.raises(InvalidTrustedCovenantRegistration):
        replace(registration(), outpoints=(incoming, incoming))
    with pytest.raises(InvalidTrustedCovenantRegistration):
        replace(
            registration(),
            outpoints=(
                replace(registration().outpoints[0], witness_script_sha256="f" * 64),
                registration().outpoints[1],
            ),
        )


@pytest.mark.parametrize(
    "state",
    (
        TrustedCovenantRegistrationLifecycle.REVOKED,
        TrustedCovenantRegistrationLifecycle.SUPERSEDED,
        TrustedCovenantRegistrationLifecycle.DISPUTED,
    ),
)
def test_only_active_materializes(state):
    superseded = (
        "00000000-0000-4000-8000-000000000002" if state is TrustedCovenantRegistrationLifecycle.SUPERSEDED else None
    )
    with pytest.raises(InvalidTrustedCovenantRegistration):
        trusted_outpoints_from_registration(registration(state=state, superseded=superseded))


def test_superseded_id_and_timestamp_consistency():
    with pytest.raises(InvalidTrustedCovenantRegistration):
        registration(state=TrustedCovenantRegistrationLifecycle.SUPERSEDED)
    with pytest.raises(InvalidTrustedCovenantRegistration):
        replace(
            registration(),
            lifecycle_changed_at=NOW - timedelta(seconds=1),
        )
    with pytest.raises(InvalidTrustedCovenantRegistration):
        replace(registration(), superseded_by_registration_id="00000000-0000-4000-8000-000000000002")

"""Cross-language shape and exact signing-domain regression."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.services import social_registered_device_session_contract_v1 as contract

VECTOR = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures/social_registered_device_session_v1.json").read_text()
)
WIRE = VECTOR["challengeWire"]
PROOF = VECTOR["proofWire"]
CHALLENGE = json.loads(WIRE)
PINS = dict(
    issuer=CHALLENGE["issuer"],
    audience=CHALLENGE["audience"],
    client_id=CHALLENGE["clientId"],
    context_commitment=CHALLENGE["contextCommitment"],
)


def test_cross_language_bytes_and_time_pins():
    assert contract.require_current_challenge_v1(WIRE, now=CHALLENGE["issuedAt"], **PINS) == CHALLENGE
    proof = contract.parse_proof_v1(PROOF, challenge_wire=WIRE)
    # Test-only independent signature check; runtime UBID still owns no
    # Ed25519 admission verifier. Social supplies strict crypto.
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(CHALLENGE["ed25519PublicKey"])).verify(
        bytes.fromhex(proof["signature"]), contract.signing_preimage_v1(WIRE)
    )
    assert contract.RUNTIME_ENABLED is False


@pytest.mark.parametrize("now", [CHALLENGE["issuedAt"] - 1, CHALLENGE["expiresAt"], True, 1.0])
def test_exclusive_time_denial(now):
    with pytest.raises(contract.RegisteredDeviceSessionContractError):
        contract.require_current_challenge_v1(WIRE, now=now, **PINS)


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", True),
        ("authorityEpoch", 0),
        ("bindingVersion", 0),
        ("associationVersion", 2),
        ("domain", "HODLXXI_SOCIAL_MESSAGING_DEVICE_PROOF_ED25519_WEBCRYPTO_V1"),
        ("issuer", "https://ubid-preview.hodlxxi.test:443"),
        ("audience", "https://social-preview.hodlxxi.test:9544/path"),
        ("ed25519PublicKey", CHALLENGE["subject"]),
        ("expiresAt", CHALLENGE["expiresAt"] + 1),
    ],
)
def test_bad_challenge_shape(field, value):
    with pytest.raises(contract.RegisteredDeviceSessionContractError):
        contract.parse_challenge_v1(contract.canonical(dict(CHALLENGE, **{field: value})))


def test_context_and_exact_wire_denial():
    with pytest.raises(contract.RegisteredDeviceSessionContractError):
        contract.require_current_challenge_v1(
            WIRE, now=CHALLENGE["issuedAt"], **dict(PINS, context_commitment="99" * 32)
        )
    for invalid in (WIRE + " ", WIRE.replace('"version":1', '"version":1,"version":1')):
        with pytest.raises(contract.RegisteredDeviceSessionContractError):
            contract.parse_challenge_v1(invalid)
    with pytest.raises(contract.RegisteredDeviceSessionContractError):
        contract.parse_proof_v1(contract.canonical(dict(json.loads(PROOF), challengeId="99" * 32)), challenge_wire=WIRE)

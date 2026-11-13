"""Canon V2 dual signature proof: Bitcoin Core message contract, never admission."""

import base64
from dataclasses import replace
from datetime import timedelta

import pytest

from app.services.canonical_admission_consent_v2 import (
    CHALLENGE_SCHEMA,
    DOMAIN,
    NETWORK,
    CanonicalAdmissionConsentChallengeV2,
    CanonicalAdmissionConsentVerificationV2,
    CanonicalAdmissionConsentVerifierUnavailable,
    InvalidCanonicalAdmissionConsentV2,
    canonical_admission_consent_challenge_v2_bytes,
    canonical_admission_consent_message_v2,
    issue_canonical_admission_consent_challenge_v2,
    verify_canonical_admission_consent_signatures_v2,
)
from app.utils import derive_legacy_address_from_pubkey
from tests.unit.test_canonical_admission_proposal_v2 import ALICE, BOB, NOW, _make

# These 65-byte compact-signature-shaped values are TEST DUMMIES.
# StrictRPC simulates authoritative Bitcoin Core results. It does not
# cryptographically validate these synthetic bytes.
SPONSOR_SIG = base64.b64encode(bytes([31]) + b"\x11" * 64).decode("ascii")
CHILD_SIG = base64.b64encode(bytes([31]) + b"\x22" * 64).decode("ascii")


class StrictRpc:
    def __init__(self, accepted):
        self.accepted = set(accepted)
        self.calls = []

    def verifymessage(self, address, signature, message):
        self.calls.append((address, signature, message))
        return (address, signature, message) in self.accepted


def _setup():
    proposal, _, _ = _make()
    challenge = issue_canonical_admission_consent_challenge_v2(proposal, now=NOW)
    sponsor_message = canonical_admission_consent_message_v2(challenge, role="sponsor")
    child_message = canonical_admission_consent_message_v2(challenge, role="child")
    sponsor_call = (
        derive_legacy_address_from_pubkey(ALICE), SPONSOR_SIG, sponsor_message
    )
    child_call = (
        derive_legacy_address_from_pubkey(BOB), CHILD_SIG, child_message
    )
    return proposal, challenge, sponsor_call, child_call, StrictRpc((sponsor_call, child_call))


def _verify(proposal, challenge, rpc, sponsor_signature=SPONSOR_SIG, child_signature=CHILD_SIG, now=NOW):
    return verify_canonical_admission_consent_signatures_v2(
        proposal, challenge, sponsor_signature=sponsor_signature,
        child_signature=child_signature, rpc=rpc, now=now
    )


def test_exact_sponsor_and_child_messages_bind_roles_proposal_and_fresh_nonce():
    proposal, challenge, sponsor, child, rpc = _setup()
    assert challenge.schema == CHALLENGE_SCHEMA
    assert challenge.domain == DOMAIN
    assert challenge.network == NETWORK
    assert len(challenge.nonce_hex) == 64
    assert challenge.expires_at == NOW + timedelta(seconds=300)
    assert challenge.is_trusted_issuance is False
    assert challenge.sponsor_compressed_pubkey == ALICE
    assert challenge.child_compressed_pubkey == BOB
    assert sponsor[2] != child[2]
    assert "role=sponsor" in sponsor[2]
    assert "role=child" in child[2]
    assert f"proposal_sha256={challenge.proposal_sha256}" in sponsor[2]
    assert f"nonce={challenge.nonce_hex}" in child[2]
    receipt = _verify(proposal, challenge, rpc)
    assert type(receipt) is CanonicalAdmissionConsentVerificationV2
    assert rpc.calls == [sponsor, child]
    assert receipt.proposal_sha256 == challenge.proposal_sha256
    assert not receipt.grants_full and not receipt.replay_protected
    assert receipt.sponsor_message_sha256 != receipt.child_message_sha256
    assert receipt.sponsor_signature_sha256 != receipt.child_signature_sha256
    assert b'"domain":"HODLXXI/SponsoredAdmissionConsent/V2"' in (
        canonical_admission_consent_challenge_v2_bytes(challenge)
    )


def test_two_challenges_for_same_proposal_have_distinct_nonces_and_texts():
    proposal, original, _, _, _ = _setup()
    next_challenge = issue_canonical_admission_consent_challenge_v2(proposal, now=NOW)
    assert original.nonce_hex != next_challenge.nonce_hex
    assert canonical_admission_consent_message_v2(original, role="child") != (
        canonical_admission_consent_message_v2(next_challenge, role="child")
    )


def test_swapping_roles_or_signatures_fails_even_for_same_valid_pair():
    proposal, challenge, sponsor, child, rpc = _setup()
    with pytest.raises(InvalidCanonicalAdmissionConsentV2, match="sponsor_signature_invalid"):
        _verify(proposal, challenge, rpc, sponsor_signature=CHILD_SIG, child_signature=SPONSOR_SIG)
    with pytest.raises(InvalidCanonicalAdmissionConsentV2, match="indistinguishable_signatures"):
        _verify(proposal, challenge, rpc, sponsor_signature=SPONSOR_SIG, child_signature=SPONSOR_SIG)


def test_absent_or_invalid_child_signature_fails_closed():
    proposal, challenge, _, _, rpc = _setup()
    for child in ("", "A" * 88, base64.b64encode(b"\x00" * 65).decode("ascii")):
        with pytest.raises(InvalidCanonicalAdmissionConsentV2):
            _verify(proposal, challenge, rpc, child_signature=child)
    rpc.calls.clear()
    wrong = base64.b64encode(bytes([31]) + b"\x33" * 64).decode("ascii")
    with pytest.raises(InvalidCanonicalAdmissionConsentV2, match="child_signature_invalid"):
        _verify(proposal, challenge, rpc, child_signature=wrong)
    assert len(rpc.calls) == 2


def test_expired_or_future_challenge_never_calls_rpc():
    proposal, challenge, _, _, rpc = _setup()
    for moment in (NOW - timedelta(seconds=1), NOW + timedelta(seconds=300)):
        with pytest.raises(InvalidCanonicalAdmissionConsentV2, match="challenge_expired_or_not_issued"):
            _verify(proposal, challenge, rpc, now=moment)
    assert rpc.calls == []


def test_replacing_proposal_breaks_exact_challenge_digest():
    proposal, challenge, _, _, rpc = _setup()
    different = replace(proposal, sponsor_import_event_sha256="4" * 64)
    with pytest.raises(InvalidCanonicalAdmissionConsentV2, match="challenge_proposal_or_identity_binding"):
        _verify(different, challenge, rpc)
    assert not rpc.calls


def test_replacing_nonce_with_valid_hex_breaks_both_signed_messages():
    proposal, challenge, _, _, rpc = _setup()
    alternate = replace(challenge, nonce_hex="0" * 64)
    with pytest.raises(InvalidCanonicalAdmissionConsentV2, match="sponsor_signature_invalid"):
        _verify(proposal, alternate, rpc)


def test_bad_challenge_fields_and_timestamp_window_rejected():
    _, challenge, _, _, _ = _setup()
    with pytest.raises(InvalidCanonicalAdmissionConsentV2):
        replace(challenge, domain="HODLXXI/login")
    with pytest.raises(InvalidCanonicalAdmissionConsentV2):
        replace(challenge, network="testnet")
    with pytest.raises(InvalidCanonicalAdmissionConsentV2):
        replace(challenge, expires_at=NOW + timedelta(seconds=301))
    with pytest.raises(InvalidCanonicalAdmissionConsentV2):
        replace(challenge, child_compressed_pubkey=ALICE)
    with pytest.raises(InvalidCanonicalAdmissionConsentV2):
        replace(challenge, nonce_hex="G" * 64)
    with pytest.raises(InvalidCanonicalAdmissionConsentV2):
        replace(challenge, schema="legacy")


def test_wrong_or_unknown_message_role_rejected():
    _, challenge, _, _, _ = _setup()
    for role in ("full", "alice", None, 1, "Sponsor"):
        with pytest.raises(InvalidCanonicalAdmissionConsentV2, match="role"):
            canonical_admission_consent_message_v2(challenge, role=role)


def test_missing_or_broken_verifier_is_unavailable_not_false_evidence():
    proposal, challenge, sponsor, child, _ = _setup()
    with pytest.raises(CanonicalAdmissionConsentVerifierUnavailable):
        _verify(proposal, challenge, object())

    class Boom:
        def verifymessage(self, *_):
            raise RuntimeError("rpc outage")

    with pytest.raises(CanonicalAdmissionConsentVerifierUnavailable):
        _verify(proposal, challenge, Boom())

    class NonBoolean:
        def verifymessage(self, *_):
            return 1

    with pytest.raises(CanonicalAdmissionConsentVerifierUnavailable):
        _verify(proposal, challenge, NonBoolean())

    bad = StrictRpc([sponsor])
    with pytest.raises(InvalidCanonicalAdmissionConsentV2, match="child_signature_invalid"):
        _verify(proposal, challenge, bad)
    assert bad.calls == [sponsor, child]


def test_valid_message_signatures_are_not_replay_protection_or_full_authority():
    proposal, challenge, _, _, rpc = _setup()
    first = _verify(proposal, challenge, rpc)
    second = _verify(proposal, challenge, rpc)
    assert first == second
    assert not first.replay_protected and not second.replay_protected
    assert not first.grants_full and not second.grants_full
    # The missing durable nonce issuance and atomic one-time use are
    # deliberate hard blockers for a future actual admission transition.


def test_untrusted_proposal_or_challenge_object_rejected():
    proposal, challenge, _, _, rpc = _setup()
    with pytest.raises(InvalidCanonicalAdmissionConsentV2):
        _verify({"proposal": "forged"}, challenge, rpc)
    with pytest.raises(InvalidCanonicalAdmissionConsentV2):
        _verify(proposal, {"nonce": "forged"}, rpc)
    with pytest.raises(InvalidCanonicalAdmissionConsentV2):
        canonical_admission_consent_challenge_v2_bytes({"nonce": "forged"})


def test_verification_receipt_tamper_and_type_rejection():
    proposal, challenge, _, _, rpc = _setup()
    value = _verify(proposal, challenge, rpc)
    with pytest.raises(InvalidCanonicalAdmissionConsentV2):
        replace(value, sponsor_message_sha256="GG" * 32)
    with pytest.raises(InvalidCanonicalAdmissionConsentV2):
        replace(value, schema="hodlxxi.current_entitlement_evidence.v1")

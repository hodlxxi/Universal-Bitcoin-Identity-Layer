"""Offline protocol tests: no database, socket, wallet RPC, or signer transport."""

import json
import socket
from dataclasses import replace
from pathlib import Path

import pytest

from app.services import social_messaging_mobile_authorization as contract
from app.services.full_recipient_directory_provider import (
    _PROHIBITED_X25519,
    X25519_FIELD_PRIME,
    validate_x25519_public_key,
)
from tests.unit.test_social_messaging_device_binding_authorization_intent import Full

VECTORS = json.loads((Path(__file__).parents[1] / "fixtures/social_mobile_device_authorization_v1.json").read_text())
SUBJECT = VECTORS["subject"]
FIRST = VECTORS["entries"][0]
REVISION = "cc" * 32


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("offline contract attempted a network operation")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)


def source_for(entry=FIRST, method=contract.QR):
    context = (
        None
        if method == contract.NOSTR
        else VECTORS["legacyContext"] if method == contract.LEGACY else VECTORS["pairingContext"]
    )
    content = entry[method]["content"] if method == contract.QR else entry["content"]
    return contract.create_authorization(
        content, contract.canonical(context), method, subject=SUBJECT, now=entry["now"]
    )


def event_for(entry=FIRST, method=contract.QR):
    source = source_for(entry, method)
    event = contract.unsigned_event(source, subject=SUBJECT, expected_method=method, now=entry["now"])["unsignedEvent"]
    return contract.canonical(dict(event, pubkey=SUBJECT, id=entry[method]["eventId"], sig=entry[method]["signature"]))


def submission_for(entry=FIRST, **changes):
    result = dict(
        method=contract.LEGACY,
        **VECTORS["legacyContext"],
        authorizationDigest=entry[contract.LEGACY]["digest"],
        compressedPublicKey=VECTORS["compressedPublicKey"],
        signature=entry[contract.LEGACY]["signature"],
    )
    result.update(changes)
    return contract.canonical(result)


def verified_legacy(source=None, submission=None, now=None):
    return contract.verify_legacy_submission(
        source or source_for(FIRST, contract.LEGACY),
        submission or submission_for(),
        subject=SUBJECT,
        login_context=VECTORS["legacyContext"]["loginContext"],
        now=FIRST["now"] if now is None else now,
    )


@pytest.mark.parametrize("entry", VECTORS["entries"], ids=lambda e: e["operation"])
@pytest.mark.parametrize("method", sorted(contract.METHODS))
def test_independent_canonical_and_real_signature_fixed_vectors(entry, method):
    source = source_for(entry, method)
    candidate = contract.parse_authorization(source, subject=SUBJECT, expected_method=method, now=entry["now"])
    assert candidate.digest == entry[method]["digest"]
    assert candidate.semantic.binding_id == entry["bindingId"]
    assert candidate.semantic.operation == entry["operation"]
    assert contract.digest(entry["content"]) == entry["semanticDigest"]
    assert candidate.replay_ids[0] == "request:" + entry["proposal"]["requestId"]
    if method == contract.LEGACY:
        assert contract.legacy_signing_digest(VECTORS["legacyContext"]["challenge"]) == entry[method]["signingDigest"]
        verified = contract.verify_legacy_submission(
            source,
            submission_for(entry),
            subject=SUBJECT,
            login_context=VECTORS["legacyContext"]["loginContext"],
            now=entry["now"],
        )
    else:
        verified = contract.verify_event(
            source, event_for(entry, method), subject=SUBJECT, expected_method=method, now=entry["now"]
        )
        assert (
            contract.unsigned_event(source, subject=SUBJECT, expected_method=method, now=entry["now"])["eventId"]
            == entry[method]["eventId"]
        )
        if method == contract.QR:
            assert contract.comparison_code(candidate.digest) == entry[method]["comparisonCode"]
            assert (
                contract.pairing_possession_proof(VECTORS["pairingSecret"], candidate.digest)
                == entry[method]["possessionProof"]
            )
    assert verified.candidate == candidate


class AtomicBoundary:
    """Exact synthetic substitute for mandatory immutable/CAS/replay ports."""

    def __init__(self):
        self.issued = {}
        self.accepted = {}
        self.offer = None
        self.pending = None
        self.exchanged = False
        self.accept_calls = 0

    def reserve_legacy(self, ids, source):
        if any(identity in self.issued for identity in ids):
            return False
        self.issued.update({identity: source for identity in ids})
        return True

    def reserve_offer(self, offer):
        if self.offer is not None:
            return False
        self.offer = offer
        return True

    def claim(self, offer, candidate):
        if self.offer != offer or offer.status != "created" or self.pending is not None:
            return False
        self.pending = candidate
        return True

    def accept(self, verified, proof):
        assert type(verified) is contract.VerifiedMethodAuthorization
        candidate = verified.candidate
        self.accept_calls += 1
        assert proof.subject == candidate.semantic.subject
        if any(identity in self.accepted for identity in candidate.replay_ids):
            return None
        if candidate.method == contract.LEGACY:
            if any(self.issued.get(identity) != candidate.source for identity in candidate.replay_ids):
                return None
        elif candidate.method == contract.QR:
            if self.offer.status != "created" or self.offer.revision != REVISION or self.pending != candidate:
                return None
        self.accepted.update({identity: candidate.digest for identity in candidate.replay_ids})
        return contract.CanonicalAcceptance(
            candidate.digest, candidate.semantic.binding_id, candidate.semantic.subject, candidate.semantic.request_id
        )

    def exchange(self, pairing_id, revision, digest):
        if (
            self.exchanged
            or self.offer.status != "created"
            or self.offer.pairing_id != pairing_id
            or self.offer.revision != revision
            or self.accepted.get("pairing:" + pairing_id) != digest
        ):
            return False
        self.exchanged = True
        return True


def full():
    from datetime import datetime, timezone

    return Full(now=datetime.fromtimestamp(FIRST["now"], timezone.utc))


def pairing():
    boundary = AtomicBoundary()
    randomness = iter([bytes.fromhex(VECTORS["pairingContext"]["pairingId"]), bytes.fromhex(VECTORS["pairingSecret"])])
    offer, qr = contract.create_pairing_offer(
        subject=SUBJECT,
        desktop_context=VECTORS["pairingContext"]["desktopContext"],
        revision=REVISION,
        now=FIRST["now"],
        enabled=True,
        random_bytes=lambda count: next(randomness),
        reserve_once=boundary.reserve_offer,
    )
    return boundary, offer, qr


def scan(boundary, offer, qr):
    return contract.submit_pairing_scan(
        offer,
        source_for(),
        qr=qr,
        possession_proof=FIRST[contract.QR]["possessionProof"],
        claim_once=boundary.claim,
        now=FIRST["now"],
    )


def approve(boundary, state, **changes):
    args = dict(
        subject=SUBJECT,
        desktop_context=VECTORS["pairingContext"]["desktopContext"],
        expected_revision=REVISION,
        human_code=FIRST[contract.QR]["comparisonCode"],
        current_full=full(),
        atomic_accept=boundary.accept,
        now=FIRST["now"],
    )
    args.update(changes)
    return contract.approve_pairing(state, event_for(), **args)


def exchange(boundary, state, **changes):
    args = dict(
        verifier=VECTORS["exchangeVerifier"],
        subject=SUBJECT,
        expected_revision=REVISION,
        consume_once=boundary.exchange,
        now=FIRST["now"],
    )
    args.update(changes)
    return contract.consume_phone_exchange(state, **args)


def test_bound_legacy_phone_acceptance_needs_no_nostr_signer_and_replay_is_rejected(monkeypatch):
    monkeypatch.setattr(
        contract.Bip340IdentitySignatureVerifier, "verify", lambda *args, **kwargs: pytest.fail("LEGACY touched Nostr")
    )
    boundary = AtomicBoundary()
    source = source_for(FIRST, contract.LEGACY)
    released = contract.issue_legacy_challenge(
        source, subject=SUBJECT, reserve_once=boundary.reserve_legacy, now=FIRST["now"], enabled=True
    )
    assert json.loads(released)["challenge"] == VECTORS["legacyContext"]["challenge"]
    # The immutable record is selected by the original challenge, not submitted
    # by the phone. Changing the entire proposal cannot rebind that message.
    original = boundary.issued["legacy-challenge:" + VECTORS["legacyContext"]["challenge"]]
    verified = verified_legacy(original)
    accepted = contract.accept_verified_candidate(
        verified, current_full=full(), atomic_accept=boundary.accept, now=FIRST["now"]
    )
    assert accepted.binding_id == FIRST["bindingId"]
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        contract.accept_verified_candidate(
            verified, current_full=full(), atomic_accept=boundary.accept, now=FIRST["now"]
        )
    for entry in VECTORS["entries"]:
        with pytest.raises(contract.MobileAuthorizationUnavailable):
            contract.issue_legacy_challenge(
                source_for(entry, contract.LEGACY),
                subject=SUBJECT,
                reserve_once=boundary.reserve_legacy,
                now=entry["now"],
                enabled=True,
            )
    for entry in VECTORS["entries"][1:]:
        with pytest.raises(contract.MobileAuthorizationUnavailable):
            verified_legacy(original, submission_for(entry))


@pytest.mark.parametrize(
    "field,value",
    [
        ("subject", "ab" * 32),
        ("deviceId", "ab" * 32),
        ("publicKey", "0b" + "00" * 31),
        ("requestId", "ab" * 32),
        ("operation", "rotate"),
        ("version", 2),
        ("bindingVersion", 2),
        ("priorBindingId", "ab" * 32),
        ("expiresAt", "2026-09-08T22:34:58Z"),
    ],
)
def test_original_challenge_cannot_be_substituted_with_another_proposal(field, value):
    original = source_for(FIRST, contract.LEGACY)
    mutated = json.loads(original)
    claim = json.loads(mutated["content"])
    claim["authorization"][field] = value
    mutated["content"] = contract.canonical(claim)
    substituted = contract.canonical(mutated)
    # Client rehashing cannot change the originally reserved server record.
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        verified_legacy(original, submission_for(authorizationDigest=contract.digest(substituted)))


@pytest.mark.parametrize(
    "changes",
    [
        dict(challenge="12345678-1234-4234-8234-123456789abd"),
        dict(loginContext="ff" * 32),
        dict(authorizationDigest="ff" * 32),
        dict(method=contract.QR),
        dict(compressedPublicKey="03" + SUBJECT),
        dict(signature="A" * 87 + "="),
    ],
)
def test_wrong_legacy_challenge_digest_subject_method_or_signature_fails(changes):
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        verified_legacy(submission=submission_for(**changes))


def test_qr_scan_is_pending_explicit_signature_and_canonical_acceptance_precede_one_time_exchange():
    boundary, offer, qr = pairing()
    assert contract.parse_pairing_qr(qr) == (offer.pairing_id, VECTORS["pairingSecret"])
    assert SUBJECT not in qr
    state = scan(boundary, offer, qr)
    assert state.status == "awaiting-approval" and state.acceptance is None
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        exchange(boundary, state)
    accepted = approve(boundary, state)
    result = json.loads(exchange(boundary, accepted))
    assert result["bindingId"] == FIRST["bindingId"]
    assert result["authorizationDigest"] == FIRST[contract.QR]["digest"]
    assert result["deviceId"] == FIRST["proposal"]["deviceId"]
    assert result["exchangeCommitment"] == VECTORS["pairingContext"]["exchangeCommitment"]
    assert contract.canonical(result) == FIRST[contract.QR]["exchangeIdentity"]
    assert contract.digest(contract.canonical(result)) == FIRST[contract.QR]["exchangeIdentityDigest"]
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        exchange(boundary, accepted)
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        approve(boundary, state)
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        scan(boundary, offer, qr)


@pytest.mark.parametrize("condition", ["stolen", "expired", "cancelled", "replaced", "code", "subject", "desktop"])
def test_pairing_secret_never_bypasses_approval_and_context_guards(condition):
    boundary, offer, qr = pairing()
    if condition in {"expired", "cancelled"}:
        invalid = replace(offer, status="cancelled") if condition == "cancelled" else offer
        with pytest.raises(contract.MobileAuthorizationUnavailable):
            contract.submit_pairing_scan(
                invalid,
                source_for(),
                qr=qr,
                possession_proof=FIRST[contract.QR]["possessionProof"],
                claim_once=boundary.claim,
                now=FIRST["now"] + (300 if condition == "expired" else 0),
            )
        return
    state = scan(boundary, offer, qr)
    if condition == "stolen":
        # Even knowing the correct QR secret gives no post-approval exchange
        # verifier. It is not the participant signer or the phone verifier.
        with pytest.raises(contract.MobileAuthorizationUnavailable):
            exchange(boundary, state, verifier=VECTORS["pairingSecret"])
        accepted = approve(boundary, state)
        with pytest.raises(contract.MobileAuthorizationUnavailable):
            exchange(boundary, accepted, verifier=VECTORS["pairingSecret"])
    else:
        changes = {"human_code": "0000-0000-0000"} if condition == "code" else {}
        if condition == "subject":
            changes["subject"] = "ab" * 32
        if condition == "desktop":
            changes["desktop_context"] = "ff" * 32
        if condition == "replaced":
            boundary.offer = replace(offer, revision="ff" * 32)
        with pytest.raises(contract.MobileAuthorizationUnavailable):
            approve(boundary, state, **changes)
        assert boundary.accepted == {}


def test_wrong_secret_possession_or_transcript_and_cancelled_exchange_fail():
    boundary, offer, qr = pairing()
    for locator, proof in [
        (contract.create_pairing_qr(offer.pairing_id, "ff" * 32), FIRST[contract.QR]["possessionProof"]),
        (qr, "ff" * 32),
        (qr, VECTORS["entries"][1][contract.QR]["possessionProof"]),
    ]:
        with pytest.raises(contract.MobileAuthorizationUnavailable):
            contract.submit_pairing_scan(
                offer, source_for(), qr=locator, possession_proof=proof, claim_once=boundary.claim, now=FIRST["now"]
            )
    accepted = approve(boundary, scan(boundary, offer, qr))
    boundary.offer = replace(offer, status="cancelled")
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        exchange(boundary, accepted)
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        exchange(boundary, accepted, now=FIRST["now"] + 300)


def test_no_oauth_only_candidate_or_unverified_acceptance_or_missing_full_is_authority():
    parsed = contract.parse_authorization(source_for(), subject=SUBJECT, expected_method=contract.QR, now=FIRST["now"])
    for unverified in (parsed, {"authenticated": True, "subject": SUBJECT}, None):
        with pytest.raises(contract.MobileAuthorizationUnavailable):
            contract.accept_verified_candidate(
                unverified,
                current_full=full(),
                atomic_accept=lambda *args: pytest.fail("unverified accept"),
                now=FIRST["now"],
            )
    boundary, offer, qr = pairing()
    state = scan(boundary, offer, qr)
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        approve(boundary, state, current_full=object())
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        approve(boundary, state, atomic_accept=lambda *args: {"accepted": True})
    assert boundary.accepted == {}


def test_cross_method_and_operation_reuse_and_event_field_substitution_fail():
    for entry in VECTORS["entries"]:
        for method in contract.METHODS:
            source = source_for(entry, method)
            for other in contract.METHODS - {method}:
                with pytest.raises(contract.MobileAuthorizationUnavailable):
                    contract.parse_authorization(source, subject=SUBJECT, expected_method=other, now=entry["now"])
            if method != contract.LEGACY:
                for other in VECTORS["entries"]:
                    if other is not entry:
                        with pytest.raises(contract.MobileAuthorizationUnavailable):
                            contract.verify_event(
                                source,
                                event_for(other, method),
                                subject=SUBJECT,
                                expected_method=method,
                                now=entry["now"],
                            )
                for field, replacement in (
                    ("id", "ff" * 32),
                    ("kind", 1),
                    ("created_at", entry["now"] + 1),
                    ("tags", []),
                    ("pubkey", "ab" * 32),
                    ("sig", "ff" * 64),
                    ("content", "{}"),
                ):
                    event = json.loads(event_for(entry, method))
                    event[field] = replacement
                    with pytest.raises(contract.MobileAuthorizationUnavailable):
                        contract.verify_event(
                            source, contract.canonical(event), subject=SUBJECT, expected_method=method, now=entry["now"]
                        )
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        contract.verify_event(
            source_for(FIRST, contract.QR),
            event_for(FIRST, contract.NOSTR),
            subject=SUBJECT,
            expected_method=contract.QR,
            now=FIRST["now"],
        )


def test_closed_contracts_reject_private_fields_noncanonical_json_and_disabled_issuance():
    for name in ("privateKey", "participantPrivateKey", "K_message", "access_token", "password", "seed"):
        value = json.loads(source_for())
        value["context"][name] = "prohibited"
        with pytest.raises(contract.MobileAuthorizationUnavailable):
            contract.parse_authorization(
                contract.canonical(value), subject=SUBJECT, expected_method=contract.QR, now=FIRST["now"]
            )
    for invalid in (
        " " + source_for(),
        source_for() + "\n",
        source_for().replace('"version":1', '"version":1,"version":1'),
    ):
        with pytest.raises(contract.MobileAuthorizationUnavailable):
            contract.parse_json(invalid)
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        contract.issue_legacy_challenge(
            source_for(FIRST, contract.LEGACY),
            subject=SUBJECT,
            reserve_once=lambda *args: pytest.fail("disabled reserve"),
            now=FIRST["now"],
        )
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        contract.create_pairing_offer(subject=SUBJECT, desktop_context="aa" * 32, revision=REVISION, now=FIRST["now"])


def test_shared_request_namespace_rejects_valid_cross_method_reuse():
    boundary = AtomicBoundary()
    contract.issue_legacy_challenge(
        source_for(FIRST, contract.LEGACY),
        subject=SUBJECT,
        reserve_once=boundary.reserve_legacy,
        now=FIRST["now"],
        enabled=True,
    )
    contract.accept_verified_candidate(
        verified_legacy(), current_full=full(), atomic_accept=boundary.accept, now=FIRST["now"]
    )
    ordinary = contract.verify_event(
        source_for(FIRST, contract.NOSTR),
        event_for(FIRST, contract.NOSTR),
        subject=SUBJECT,
        expected_method=contract.NOSTR,
        now=FIRST["now"],
    )
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        contract.accept_verified_candidate(
            ordinary, current_full=full(), atomic_accept=boundary.accept, now=FIRST["now"]
        )


@pytest.mark.parametrize("entry", VECTORS["entries"], ids=lambda e: e["operation"])
def test_exchange_identity_cross_repository_vectors_and_revoke_denial(entry):
    source = source_for(entry)
    candidate = contract.parse_authorization(source, subject=SUBJECT, expected_method=contract.QR, now=entry["now"])
    acceptance = contract.CanonicalAcceptance(
        candidate.digest, candidate.semantic.binding_id, SUBJECT, candidate.semantic.request_id
    )
    state = contract.PairingState(source, REVISION, "accepted", acceptance)
    args = dict(
        verifier=VECTORS["exchangeVerifier"],
        subject=SUBJECT,
        expected_revision=REVISION,
        consume_once=lambda *args: True,
        now=entry["now"],
    )
    if entry["operation"] == "revoke":
        assert entry[contract.QR]["exchangeDenied"] is True
        args["consume_once"] = lambda *args: pytest.fail("revoked exchange consumed")
        with pytest.raises(contract.MobileAuthorizationUnavailable):
            contract.consume_phone_exchange(state, **args)
    else:
        result = contract.consume_phone_exchange(state, **args)
        assert result == entry[contract.QR]["exchangeIdentity"]
        assert contract.digest(result) == entry[contract.QR]["exchangeIdentityDigest"]


def test_legacy_expiry_and_unverified_evidence_never_reach_acceptance():
    for now in (FIRST["now"] - 1, FIRST["now"] + 300):
        with pytest.raises(contract.MobileAuthorizationUnavailable):
            verified_legacy(now=now)
    verified = verified_legacy()
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        contract.accept_verified_candidate(
            replace(verified, proof_source="{}"),
            current_full=full(),
            atomic_accept=lambda *args: pytest.fail("forged proof reached acceptance"),
            now=FIRST["now"],
        )


def test_shared_x25519_negative_vectors_cover_the_canonical_authority():
    negative = VECTORS["x25519NegativeVectors"]
    assert set(negative) == {"prohibitedEncodings", "nonCanonicalFieldEncodings", "highBitAliases"}
    assert negative["prohibitedEncodings"] == sorted(_PROHIBITED_X25519)
    noncanonical = [value.to_bytes(32, "little").hex() for value in range(X25519_FIELD_PRIME, 2**255)]
    assert negative["nonCanonicalFieldEncodings"] == noncanonical
    # Include aliases of every prohibited/boundary encoding and a valid key.
    bases = _PROHIBITED_X25519 | set(noncanonical) | {FIRST["proposal"]["publicKey"]}
    aliases = sorted(
        (int.from_bytes(bytes.fromhex(key), "little") | (1 << 255)).to_bytes(32, "little").hex() for key in bases
    )
    assert negative["highBitAliases"] == aliases
    assert validate_x25519_public_key(FIRST["proposal"]["publicKey"]) == FIRST["proposal"]["publicKey"]


@pytest.mark.parametrize("method", sorted(contract.METHODS))
@pytest.mark.parametrize("key", sorted({key for group in VECTORS["x25519NegativeVectors"].values() for key in group}))
def test_shared_complete_x25519_prohibited_set_rejected_at_both_boundaries(key, method):
    with pytest.raises(ValueError, match="invalid X25519 public key"):
        validate_x25519_public_key(key)
    value = json.loads(source_for(FIRST, method))
    semantic = json.loads(value["content"])
    semantic["authorization"]["publicKey"] = key
    value["content"] = contract.canonical(semantic)
    with pytest.raises(contract.MobileAuthorizationUnavailable):
        contract.parse_authorization(
            contract.canonical(value), subject=SUBJECT, expected_method=method, now=FIRST["now"]
        )

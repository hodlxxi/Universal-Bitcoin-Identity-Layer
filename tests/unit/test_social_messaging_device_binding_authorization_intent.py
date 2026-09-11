from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from coincurve import PrivateKey, PublicKeyXOnly
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from jwt.algorithms import RSAAlgorithm

from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.current_full_entitlement_proof import (
    CurrentFullEntitlementProofState,
    produce_verified_current_full_entitlement,
)
from app.services.social_messaging_device_binding_authorization import (
    ADOPTION_SCHEMA,
    AUTHORIZATION_SCHEMA,
    PROOF_ID_PREFIX,
    SIGNATURE_FORMAT,
    STATE_SCHEMA,
    AdoptedDeviceBindingAuthorization,
    AuthorizedDeviceBinding,
    BindingAuthorizationEvidenceState,
    CurrentDeviceBindingState,
    CurrentPublicKeyBindingState,
    CurrentSubjectBindingState,
    DeviceBindingAdoptionClaim,
    DeviceBindingAuthorizationClaim,
    DeviceBindingAuthorizationUnavailable,
    IdentitySignedDeviceBindingAdoption,
    IdentitySignedDeviceBindingAuthorization,
    MAX_AUTHORIZATION_WINDOW_SECONDS,
    SocialMessagingDeviceBindingAuthorizationV1,
    _adopted_from,
    _authorized_from,
    adoption_digest,
    adoption_event_id,
    authorization_digest,
    authorization_event_id,
    canonical_authorization_json,
)
from app.services.social_messaging_device_binding_authorization_intent import (
    INTENT_SCHEMA,
    INTENT_TOKEN_AUDIENCE,
    INTENT_TOKEN_PURPOSE,
    INTENT_TOKEN_TYPE,
    INTENT_TOKEN_USE,
    TrustedAuthorizationIntent,
    canonical_authorization_intent_bytes,
    derive_trusted_authorization_intent,
    parse_authorization_intent_proposal,
    seal_authorization_intent,
    verify_authorization_intent_submission,
)
from app.services.social_messaging_device_contract import (
    BINDING_RECORD_SCHEMA,
    BINDING_RECORD_VERSION,
    MessagingDeviceBinding,
    messaging_device_binding_id,
)

NOW = datetime(2026, 9, 8, 22, 29, 59, tzinfo=timezone.utc)
IDENTITY_KEY = PrivateKey(bytes.fromhex("00" * 31 + "03"))
SUBJECT = PublicKeyXOnly.from_secret(IDENTITY_KEY.secret).format().hex()
DEVICE_ID = "22" * 32
REGISTER_REQUEST = "33" * 32
ROTATE_REQUEST = "44" * 32
REVOKE_REQUEST = "55" * 32
ADOPTION_REQUEST = "aa" * 32
KEY_A = "09" + "00" * 31
KEY_B = "0a" + "00" * 31
ISSUER = "https://identity.example"
KID = "service-key"


@pytest.fixture(scope="module")
def signing_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    public.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return private, public


class SignatureVerifier:
    def verify(self, *, subject, signature, digest):
        try:
            return PublicKeyXOnly(bytes.fromhex(subject)).verify(signature, digest) is True
        except Exception:
            return False


def current_full(subject=SUBJECT, *, now=NOW):
    evidence = CurrentEntitlementEvidenceRecord(
        evidence_id="00000000-0000-4000-8000-000000000101",
        contract_version=CONTRACT_VERSION,
        subject_pubkey=subject,
        identity_class=IdentityClass.FULL,
        current_full_relation_satisfied=True,
        evidence_source="offline_verifier",
        evidence_version="v1",
        source_evidence_sha256="ab" * 32,
        observed_at=now - timedelta(seconds=1),
        valid_until=now + timedelta(minutes=10),
        revoked_at=None,
        created_at=now,
    )
    return produce_verified_current_full_entitlement(
        CurrentFullEntitlementProofState(
            user_id="00000000-0000-4000-8000-000000000102",
            user_subject=subject,
            user_is_active=True,
            evidence=evidence,
        ),
        now=now,
    )


class Full:
    def __init__(self, *, now=NOW):
        self.value = current_full(now=now)
        self.calls = []

    def verify_in_transaction(self, subject, *, now):
        self.calls.append((subject, now))
        return self.value


class State:
    def __init__(self, current=None):
        self.current = current
        self.replay = None
        self.evidence = ()

    def get(self, _request_id):
        return self.replay

    def current_for_subject(self, subject, *, now, maximum):
        records = () if self.current is None else (self.current,)
        return CurrentSubjectBindingState(STATE_SCHEMA, 1, subject, True, False, records)

    def current_for_device(self, subject, device_id, *, now, maximum):
        records = ()
        if self.current is not None and self.current.binding.device_id == device_id:
            records = (self.current,)
        return CurrentDeviceBindingState(STATE_SCHEMA, 1, subject, device_id, True, False, records)

    def current_for_public_key(self, public_key, *, now, maximum):
        records = ()
        if self.current is not None and self.current.binding.public_key == public_key:
            records = (self.current,)
        return CurrentPublicKeyBindingState(STATE_SCHEMA, 1, public_key, True, False, records)

    def authorization_for_binding(self, binding_id, *, now, maximum):
        return BindingAuthorizationEvidenceState(STATE_SCHEMA, 1, binding_id, True, False, self.evidence)


class Bindings:
    def __init__(self, selected=None):
        self.selected = selected
        self.device_history = False
        self.used_keys = set()

    def binding_for_id(self, binding_id, *, lock=True):
        if self.selected is not None and self.selected.binding_id == binding_id:
            return self.selected
        return None

    def has_device_history(self, _subject, _device_id):
        return self.device_history

    def public_key_was_used(self, public_key):
        return public_key in self.used_keys


class Replay:
    def __init__(self):
        self.records = {}

    def get(self, request_id):
        return self.records.get(request_id)

    def record(self, record):
        retained = self.records.setdefault(record.request_id, record)
        if retained != record:
            raise RuntimeError
        return retained


def proposal(**changes):
    values = {
        "deviceId": DEVICE_ID,
        "expectedBindingId": None,
        "operation": "register",
        "publicKey": KEY_A,
        "requestId": REGISTER_REQUEST,
    }
    values.update(changes)
    return json.dumps(values, sort_keys=True, separators=(",", ":"))


def derive(payload=None, *, state=None, bindings=None, now=NOW):
    return derive_trusted_authorization_intent(
        parse_authorization_intent_proposal(payload or proposal()),
        authenticated_subject=SUBJECT,
        state_provider=state or State(),
        binding_state=bindings or Bindings(),
        current_full=Full(now=now),
        now=now,
        binding_lifetime_seconds=30 * 24 * 60 * 60,
        signature_verifier=SignatureVerifier(),
    )


def signed_payload(intent, *, direct_digest=False):
    assert intent.claim_type == "lifecycle"
    target = intent.digest if direct_digest else authorization_event_id(intent.claim)
    signature = IDENTITY_KEY.sign_schnorr(bytes.fromhex(target), b"\x00" * 32).hex()
    signed = IdentitySignedDeviceBindingAuthorization(
        intent.claim,
        intent.digest,
        SIGNATURE_FORMAT,
        signature,
    )
    if direct_digest:
        claim = json.loads(
            json.dumps(
                {
                    **json.loads(
                        canonical_authorization_json(
                            replace(
                                signed,
                                signature=IDENTITY_KEY.sign_schnorr(
                                    bytes.fromhex(authorization_event_id(intent.claim)), b"\x00" * 32
                                ).hex(),
                            )
                        )
                    ),
                    "signature": signature,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return json.dumps(claim, sort_keys=True, separators=(",", ":"))
    return canonical_authorization_json(signed)


def token(intent, signing_material):
    return seal_authorization_intent(
        intent,
        issuer=ISSUER,
        signing_key=signing_material[0],
        signing_kid=KID,
        verification_keys=(signing_material[1],),
    )


def test_register_intent_freezes_carrier_and_separate_token_domain(signing_material):
    intent = derive()
    encoded_token = token(intent, signing_material)
    response = canonical_authorization_intent_bytes(intent, intent_token=encoded_token)
    decoded = json.loads(response)
    header = jwt.get_unverified_header(encoded_token)
    claims = jwt.decode(encoded_token, options={"verify_signature": False})

    assert intent.digest == "70aa19a24077c3365a836f0476660f0132ab7959615d2c8c67ba75afd9071d9c"
    assert authorization_event_id(intent.claim) == ("4fb89f90de1379e47893ad335c4839805be4265767d1972b7281aea2ef2e0ad0")
    assert header == {"alg": "RS256", "kid": KID, "typ": INTENT_TOKEN_TYPE}
    assert claims == {
        "iss": ISSUER,
        "sub": SUBJECT,
        "iat": 1788906599,
        "exp": 1788906599 + MAX_AUTHORIZATION_WINDOW_SECONDS,
        "jti": REGISTER_REQUEST,
        "aud": INTENT_TOKEN_AUDIENCE,
        "tokenUse": INTENT_TOKEN_USE,
        "purpose": INTENT_TOKEN_PURPOSE,
        "claimType": "lifecycle",
        "action": "register",
        "digest": intent.digest,
        "eventId": authorization_event_id(intent.claim),
        "signatureFormat": SIGNATURE_FORMAT,
    }
    assert decoded["schema"] == INTENT_SCHEMA
    assert decoded["claimType"] == "lifecycle"
    assert decoded["expectedPubkey"] == SUBJECT
    assert decoded["signatureFormat"] == SIGNATURE_FORMAT
    assert decoded["unsignedEvent"] == {
        "content": intent.unsigned_event["content"],
        "created_at": 1788906599,
        "kind": 27236,
        "tags": [
            ["purpose", "hodlxxi-social-messaging-device-binding-authorization-v1"],
            ["semantic-digest", intent.digest],
            ["request-id", REGISTER_REQUEST],
            ["action", "register"],
        ],
    }
    assert "id" not in decoded["unsignedEvent"]
    assert "sig" not in decoded["unsignedEvent"]
    assert "pubkey" not in decoded["unsignedEvent"]

    signed = signed_payload(intent)
    verified = verify_authorization_intent_submission(
        encoded_token,
        signed,
        authenticated_subject=SUBJECT,
        issuer=ISSUER,
        expected_kid=KID,
        verification_keys=(signing_material[1],),
        signature_verifier=SignatureVerifier(),
        now=NOW,
    )
    assert type(verified) is IdentitySignedDeviceBindingAuthorization
    assert verified.claim == intent.claim


def test_register_token_and_exact_retained_retry_follow_semantic_deadline(signing_material):
    state = State()
    intent = derive(state=state)
    encoded_token = token(intent, signing_material)
    signed = signed_payload(intent)
    clock = [NOW]
    authority = SocialMessagingDeviceBindingAuthorizationV1(
        state_provider=state,
        replay_ledger=Replay(),
        signature_verifier=SignatureVerifier(),
        clock=lambda: clock[0],
    )
    first = authority.authorize(signed, authenticated_subject=SUBJECT)

    def unavailable(*_args, **_kwargs):
        raise RuntimeError

    state.authorization_for_binding = unavailable
    state.current_for_device = unavailable
    state.current_for_subject = unavailable
    state.current_for_public_key = unavailable

    clock[0] = NOW + timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS - 1)
    verified = verify_authorization_intent_submission(
        encoded_token,
        signed,
        authenticated_subject=SUBJECT,
        issuer=ISSUER,
        expected_kid=KID,
        verification_keys=(signing_material[1],),
        signature_verifier=SignatureVerifier(),
        now=clock[0],
    )
    assert verified.claim == intent.claim
    assert authority.authorize(signed, authenticated_subject=SUBJECT) == first

    clock[0] = NOW + timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS)
    with pytest.raises(DeviceBindingAuthorizationUnavailable):
        verify_authorization_intent_submission(
            encoded_token,
            signed,
            authenticated_subject=SUBJECT,
            issuer=ISSUER,
            expected_kid=KID,
            verification_keys=(signing_material[1],),
            signature_verifier=SignatureVerifier(),
            now=clock[0],
        )
    with pytest.raises(DeviceBindingAuthorizationUnavailable):
        authority.authorize(signed, authenticated_subject=SUBJECT)


def test_earlier_binding_expiry_caps_claim_and_token_deadline(signing_material):
    registered_intent = derive()
    registered = _authorized_from(
        IdentitySignedDeviceBindingAuthorization(
            registered_intent.claim,
            registered_intent.digest,
            SIGNATURE_FORMAT,
            IDENTITY_KEY.sign_schnorr(
                bytes.fromhex(authorization_event_id(registered_intent.claim)),
                b"\x00" * 32,
            ).hex(),
        )
    )
    binding_values = {
        "subject": registered.binding.subject,
        "device_id": registered.binding.device_id,
        "public_key": registered.binding.public_key,
        "binding_version": registered.binding.binding_version,
        "valid_from": registered.binding.valid_from,
        "expires_at": NOW + timedelta(seconds=90),
        "operation": registered.binding.operation,
        "prior_binding_id": registered.binding.prior_binding_id,
        "request_id": registered.binding.request_id,
    }
    binding = replace(
        registered.binding,
        binding_id=messaging_device_binding_id(**binding_values),
        expires_at=binding_values["expires_at"],
    )
    intent = derive_trusted_authorization_intent(
        parse_authorization_intent_proposal(
            json.dumps(
                {
                    "bindingId": binding.binding_id,
                    "operation": "adopt",
                    "requestId": ADOPTION_REQUEST,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        ),
        authenticated_subject=SUBJECT,
        state_provider=State(),
        binding_state=Bindings(binding),
        current_full=Full(),
        now=NOW,
        binding_lifetime_seconds=30 * 24 * 60 * 60,
        signature_verifier=SignatureVerifier(),
    )
    claims = jwt.decode(token(intent, signing_material), options={"verify_signature": False})

    assert intent.claim.expires_at == binding.expires_at
    assert claims["exp"] == int(binding.expires_at.timestamp())


def test_direct_semantic_digest_signature_is_rejected(signing_material):
    intent = derive()
    with pytest.raises(DeviceBindingAuthorizationUnavailable):
        verify_authorization_intent_submission(
            token(intent, signing_material),
            signed_payload(intent, direct_digest=True),
            authenticated_subject=SUBJECT,
            issuer=ISSUER,
            expected_kid=KID,
            verification_keys=(signing_material[1],),
            signature_verifier=SignatureVerifier(),
            now=NOW,
        )


def test_browser_proposal_is_closed_canonical_and_cannot_select_authority():
    for invalid in (
        proposal(subject=SUBJECT),
        proposal(issuedAt="2026-09-08T22:29:59Z"),
        proposal(bindingVersion=1),
        proposal(priorBindingId=None),
        proposal(bindingExpiresAt="2026-10-08T22:29:59Z"),
        proposal(bindingId="66" * 32),
        proposal(now="2026-09-08T22:29:59Z"),
        proposal(state={}),
        proposal(currentFullProof={}),
        proposal().replace(",", ", ", 1),
        '{"deviceId":"%s","deviceId":"%s","expectedBindingId":null,"operation":"register","publicKey":"%s","requestId":"%s"}'
        % (DEVICE_ID, DEVICE_ID, KEY_A, REGISTER_REQUEST),
    ):
        with pytest.raises(DeviceBindingAuthorizationUnavailable):
            parse_authorization_intent_proposal(invalid)


def test_intent_derives_rotate_revoke_and_adoption_fixed_vectors():
    registered_intent = derive()
    registered = _authorized_from(
        IdentitySignedDeviceBindingAuthorization(
            registered_intent.claim,
            registered_intent.digest,
            SIGNATURE_FORMAT,
            IDENTITY_KEY.sign_schnorr(
                bytes.fromhex(authorization_event_id(registered_intent.claim)),
                b"\x00" * 32,
            ).hex(),
        )
    )
    rotate_time = NOW + timedelta(seconds=1)
    rotate_intent = derive(
        proposal(
            operation="rotate",
            publicKey=KEY_B,
            expectedBindingId=registered.binding.binding_id,
            requestId=ROTATE_REQUEST,
        ),
        state=State(registered),
        now=rotate_time,
    )
    assert rotate_intent.claim.prior_binding_id == registered.binding.binding_id
    assert rotate_intent.claim.binding_version == 2
    assert rotate_intent.digest == "16c47dd55844cf3086124b87249ec395b7d42759215f14ccfa99259fa51dd80c"
    assert authorization_event_id(rotate_intent.claim) == (
        "a429b02a9223fcb463d64da2483fc8ec644d2002889cdc9fa29ba1ec72732f28"
    )
    rotated = _authorized_from(
        IdentitySignedDeviceBindingAuthorization(
            rotate_intent.claim,
            rotate_intent.digest,
            SIGNATURE_FORMAT,
            IDENTITY_KEY.sign_schnorr(
                bytes.fromhex(authorization_event_id(rotate_intent.claim)),
                b"\x00" * 32,
            ).hex(),
        )
    )
    revoke_intent = derive(
        proposal(
            operation="revoke",
            publicKey=None,
            expectedBindingId=rotated.binding.binding_id,
            requestId=REVOKE_REQUEST,
        ),
        state=State(rotated),
        now=rotate_time,
    )
    assert revoke_intent.claim.public_key == rotated.binding.public_key
    assert revoke_intent.digest == "a7db4b3f77f902abfffe99ea33739b2c65f7a1ce2f0f313065e9f7bbdcdba8bb"
    assert authorization_event_id(revoke_intent.claim) == (
        "1da8e3972f9d82a15103a86de94ff06321e110065716baf5d3129a435063b2f6"
    )

    adoption_intent = derive_trusted_authorization_intent(
        parse_authorization_intent_proposal(
            json.dumps(
                {
                    "bindingId": registered.binding.binding_id,
                    "operation": "adopt",
                    "requestId": ADOPTION_REQUEST,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        ),
        authenticated_subject=SUBJECT,
        state_provider=State(),
        binding_state=Bindings(registered.binding),
        current_full=Full(now=rotate_time),
        now=rotate_time,
        binding_lifetime_seconds=30 * 24 * 60 * 60,
        signature_verifier=SignatureVerifier(),
    )
    assert adoption_intent.claim_type == "adoption"
    assert adoption_intent.digest == "c96902ddb67f6d63c1579e81100f267be27f5f0cd12727b521c76c66d8f25c36"
    assert adoption_event_id(adoption_intent.claim) == (
        "68bb9d6a6dc3a13630a47e27350be22859be407a0c2ff903a6820ab214d50955"
    )


def test_state_clock_and_predecessor_are_authoritative():
    bindings = Bindings()
    bindings.device_history = True
    with pytest.raises(DeviceBindingAuthorizationUnavailable):
        derive(bindings=bindings)

    registered_intent = derive()
    registered = _authorized_from(
        IdentitySignedDeviceBindingAuthorization(
            registered_intent.claim,
            registered_intent.digest,
            SIGNATURE_FORMAT,
            IDENTITY_KEY.sign_schnorr(
                bytes.fromhex(authorization_event_id(registered_intent.claim)), b"\x00" * 32
            ).hex(),
        )
    )
    with pytest.raises(DeviceBindingAuthorizationUnavailable):
        derive(
            proposal(
                operation="rotate",
                publicKey=KEY_B,
                expectedBindingId="66" * 32,
                requestId=ROTATE_REQUEST,
            ),
            state=State(registered),
            now=NOW + timedelta(seconds=1),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("iss", "https://wrong.example"),
        ("sub", "01" * 32),
        ("aud", "wrong"),
        ("jti", "66" * 32),
        ("tokenUse", "service_access"),
        ("purpose", "wrong"),
        ("claimType", "adoption"),
        ("action", "rotate"),
        ("digest", "00" * 32),
        ("eventId", "00" * 32),
        ("exp", int(NOW.timestamp()) + MAX_AUTHORIZATION_WINDOW_SECONDS - 1),
        ("exp", int(NOW.timestamp()) + MAX_AUTHORIZATION_WINDOW_SECONDS + 1),
        ("signatureFormat", "bip340_schnorr_sha256"),
    ),
)
def test_token_claim_substitution_fails(signing_material, field, value):
    intent = derive()
    encoded = token(intent, signing_material)
    claims = jwt.decode(encoded, options={"verify_signature": False})
    claims[field] = value
    altered = jwt.encode(
        claims,
        signing_material[0],
        algorithm="RS256",
        headers={"kid": KID, "typ": INTENT_TOKEN_TYPE},
    )
    with pytest.raises(DeviceBindingAuthorizationUnavailable):
        verify_authorization_intent_submission(
            altered,
            signed_payload(intent),
            authenticated_subject=SUBJECT,
            issuer=ISSUER,
            expected_kid=KID,
            verification_keys=(signing_material[1],),
            signature_verifier=SignatureVerifier(),
            now=NOW,
        )


def test_expired_future_stale_unknown_and_wrong_header_intents_fail(signing_material):
    intent = derive()
    encoded = token(intent, signing_material)
    claims = jwt.decode(encoded, options={"verify_signature": False})
    cases = []
    for changes in (
        {
            "iat": int(NOW.timestamp()) + 1,
            "exp": int(NOW.timestamp()) + MAX_AUTHORIZATION_WINDOW_SECONDS,
        },
        {
            "iat": int(NOW.timestamp()) - MAX_AUTHORIZATION_WINDOW_SECONDS - 1,
            "exp": int(NOW.timestamp()) - 1,
        },
        {"unexpected": "value"},
    ):
        altered = {**claims, **changes}
        cases.append(
            jwt.encode(
                altered,
                signing_material[0],
                algorithm="RS256",
                headers={"kid": KID, "typ": INTENT_TOKEN_TYPE},
            )
        )
    cases.append(
        jwt.encode(
            claims,
            signing_material[0],
            algorithm="RS256",
            headers={"kid": "wrong", "typ": INTENT_TOKEN_TYPE},
        )
    )
    cases.append(
        jwt.encode(
            claims,
            signing_material[0],
            algorithm="RS256",
            headers={"kid": KID, "typ": "JWT"},
        )
    )
    for altered in cases:
        with pytest.raises(DeviceBindingAuthorizationUnavailable):
            verify_authorization_intent_submission(
                altered,
                signed_payload(intent),
                authenticated_subject=SUBJECT,
                issuer=ISSUER,
                expected_kid=KID,
                verification_keys=(signing_material[1],),
                signature_verifier=SignatureVerifier(),
                now=NOW,
            )


def test_duplicate_token_claim_name_is_rejected_before_normalization(signing_material):
    intent = derive()
    encoded = token(intent, signing_material)
    header_segment, claims_segment, _signature_segment = encoded.split(".")
    raw_claims = base64.urlsafe_b64decode(claims_segment + "=" * (-len(claims_segment) % 4)).decode("ascii")
    duplicate_claims = raw_claims.replace(
        '"sub":',
        '"sub":"' + "01" * 32 + '","sub":',
        1,
    ).encode("ascii")
    duplicate_segment = base64.urlsafe_b64encode(duplicate_claims).rstrip(b"=").decode("ascii")
    signing_input = (header_segment + "." + duplicate_segment).encode("ascii")
    signature = signing_material[0].sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    duplicate_token = (
        header_segment
        + "."
        + duplicate_segment
        + "."
        + base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    )

    with pytest.raises(DeviceBindingAuthorizationUnavailable):
        verify_authorization_intent_submission(
            duplicate_token,
            signed_payload(intent),
            authenticated_subject=SUBJECT,
            issuer=ISSUER,
            expected_kid=KID,
            verification_keys=(signing_material[1],),
            signature_verifier=SignatureVerifier(),
            now=NOW,
        )


def test_valid_signature_for_different_payload_does_not_match_intent(signing_material):
    intent = derive()
    other = derive(proposal(requestId="77" * 32))
    with pytest.raises(DeviceBindingAuthorizationUnavailable):
        verify_authorization_intent_submission(
            token(intent, signing_material),
            signed_payload(other),
            authenticated_subject=SUBJECT,
            issuer=ISSUER,
            expected_kid=KID,
            verification_keys=(signing_material[1],),
            signature_verifier=SignatureVerifier(),
            now=NOW,
        )


def test_altered_payload_signature_and_token_fail(signing_material):
    intent = derive()
    encoded_token = token(intent, signing_material)
    signed = signed_payload(intent)
    decoded = json.loads(signed)
    altered_signature = json.dumps(
        {**decoded, "signature": "00" * 64},
        sort_keys=True,
        separators=(",", ":"),
    )
    header, claims, signature = encoded_token.split(".")
    altered_token = ".".join(
        (
            header,
            claims,
            ("A" if signature[0] != "A" else "B") + signature[1:],
        )
    )

    for candidate_token, candidate_payload in (
        (encoded_token, signed + " "),
        (encoded_token, altered_signature),
        (altered_token, signed),
    ):
        with pytest.raises(DeviceBindingAuthorizationUnavailable):
            verify_authorization_intent_submission(
                candidate_token,
                candidate_payload,
                authenticated_subject=SUBJECT,
                issuer=ISSUER,
                expected_kid=KID,
                verification_keys=(signing_material[1],),
                signature_verifier=SignatureVerifier(),
                now=NOW,
            )


def test_intent_objects_are_frozen_and_do_not_contain_authorization_evidence():
    intent = derive()
    assert type(intent) is TrustedAuthorizationIntent
    assert not hasattr(intent, "verification")
    assert not hasattr(intent, "proof_id")
    assert not hasattr(intent, "signature")
    with pytest.raises(Exception):
        intent.digest = "00" * 32

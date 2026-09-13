"""Dormant mobile messaging authorization contracts; no routes or runtime wiring.

Cryptographic inspection returns a candidate, never a session or binding grant.
Trusted challenge records and atomic acceptance are separately required ports.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from coincurve import PublicKey

from app.services.current_full_entitlement_proof import validate_verified_current_full_entitlement
from app.services.social_messaging_device_binding_authorization import (
    NOSTR_EVENT_KIND,
    NOSTR_EVENT_PURPOSE,
    SIGNATURE_FORMAT,
    Bip340IdentitySignatureVerifier,
    DeviceBindingAdoptionClaim,
    DeviceBindingAuthorizationClaim,
    _binding_from_record,
    _binding_id_from_claim,
    _parse_timestamp,
    canonical_adoption_signed_bytes,
    canonical_authorization_signed_bytes,
)
from app.services.social_messaging_device_contract import canonical_messaging_device_binding_record_bytes

SCHEMA = "hodlxxi.social_messaging_device_authorization_method.v1"
DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_METHOD_V1"
QR_APPROVAL_PURPOSE = "hodlxxi-social-messaging-device-qr-approval-v1"
NOSTR = "nostr_event_v1"
LEGACY = "legacy_challenge_v1"
QR = "qr_desktop_v1"
METHODS = frozenset((NOSTR, LEGACY, QR))
QR_PREFIX = "hodlxxi-social-pair:v1:"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")


class MobileAuthorizationUnavailable(ValueError):
    def __init__(self):
        super().__init__("mobile device authorization unavailable")


def _hex(value):
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise MobileAuthorizationUnavailable()
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def parse_json(source):
    try:
        if type(source) is not str or not 0 < len(source) <= 16384 or any(not 32 <= ord(c) <= 126 for c in source):
            raise ValueError

        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        def invalid_constant(_value):
            raise ValueError

        value = json.loads(source, object_pairs_hook=pairs, parse_constant=invalid_constant)
        if canonical(value) != source:
            raise ValueError
        return value
    except Exception:
        raise MobileAuthorizationUnavailable() from None


def _exact(value, fields):
    if type(value) is not dict or set(value) != set(fields.split()):
        raise MobileAuthorizationUnavailable()
    return value


def _second(value):
    return int(_parse_timestamp(value).timestamp())


@dataclass(frozen=True)
class SemanticProposal:
    content: str
    subject: str
    request_id: str
    operation: str
    binding_id: str
    binding_record: str
    issued_at: int
    expires_at: int


def inspect_claim(content, subject):
    """Reuse the established canonical claim and binding-record validators."""
    try:
        _hex(subject)
        root = parse_json(content)
        if "authorization" in root:
            _exact(root, "authorization domain")
            v = root["authorization"]
            claim = DeviceBindingAuthorizationClaim(
                schema=v["schema"],
                version=v["version"],
                binding_record_schema=v["bindingRecordSchema"],
                binding_record_version=v["bindingRecordVersion"],
                operation=v["operation"],
                subject=v["subject"],
                device_id=v["deviceId"],
                algorithm=v["algorithm"],
                public_key=v["publicKey"],
                binding_version=v["bindingVersion"],
                binding_valid_from=_parse_timestamp(v["bindingValidFrom"]),
                binding_expires_at=_parse_timestamp(v["bindingExpiresAt"]),
                prior_binding_id=v["priorBindingId"],
                request_id=v["requestId"],
                issued_at=_parse_timestamp(v["issuedAt"]),
                expires_at=_parse_timestamp(v["expiresAt"]),
            )
            expected = canonical_authorization_signed_bytes(claim).decode("ascii")
            binding_id = _binding_id_from_claim(claim)
            binding_record = canonical_messaging_device_binding_record_bytes(
                subject=claim.subject,
                device_id=claim.device_id,
                public_key=claim.public_key,
                binding_version=claim.binding_version,
                valid_from=claim.binding_valid_from,
                expires_at=claim.binding_expires_at,
                operation=claim.operation,
                prior_binding_id=claim.prior_binding_id,
                request_id=claim.request_id,
            ).decode("ascii")
            operation = claim.operation
            actual_subject = claim.subject
        else:
            _exact(root, "adoption domain")
            v = root["adoption"]
            binding = _binding_from_record(v["bindingRecord"], v["bindingId"])
            claim = DeviceBindingAdoptionClaim(
                v["schema"],
                v["version"],
                v["action"],
                v["requestId"],
                binding,
                _parse_timestamp(v["issuedAt"]),
                _parse_timestamp(v["expiresAt"]),
            )
            expected = canonical_adoption_signed_bytes(claim).decode("ascii")
            binding_id = binding.binding_id
            binding_record = canonical(v["bindingRecord"])
            operation = "adopt"
            actual_subject = binding.subject
        if expected != content or actual_subject != subject:
            raise ValueError
        return SemanticProposal(
            content,
            subject,
            claim.request_id,
            operation,
            binding_id,
            binding_record,
            int(claim.issued_at.timestamp()),
            int(claim.expires_at.timestamp()),
        )
    except Exception:
        raise MobileAuthorizationUnavailable() from None


@dataclass(frozen=True)
class AuthorizationCandidate:
    """Validated public transcript; not an accepted authorization or bearer."""

    source: str
    method: str
    digest: str
    semantic: SemanticProposal
    replay_ids: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedMethodAuthorization:
    candidate: AuthorizationCandidate
    proof_source: str
    login_context: str | None = None


def parse_authorization(source, *, subject, expected_method, now):
    try:
        if type(now) is not int or type(expected_method) is not str or expected_method not in METHODS:
            raise ValueError
        v = _exact(parse_json(source), "content context domain method schema version")
        if v["schema"] != SCHEMA or type(v["version"]) is not int or v["version"] != 1:
            raise ValueError
        if v["domain"] != DOMAIN or v["method"] != expected_method:
            raise ValueError
        semantic = inspect_claim(v["content"], subject)
        if semantic.issued_at < 0 or not semantic.issued_at <= now < semantic.expires_at:
            raise ValueError
        context = v["context"]
        replay_ids = ["request:" + semantic.request_id, "authorization:" + digest(source)]
        if expected_method == NOSTR:
            if context is not None:
                raise ValueError
        elif expected_method == LEGACY:
            _exact(context, "challenge loginContext")
            if type(context["challenge"]) is not str or _UUID.fullmatch(context["challenge"]) is None:
                raise ValueError
            _hex(context["loginContext"])
            replay_ids.append("legacy-challenge:" + context["challenge"])
        else:
            _exact(context, "createdAt desktopContext exchangeCommitment expiresAt pairingId secretCommitment")
            for field in ("desktopContext", "exchangeCommitment", "pairingId", "secretCommitment"):
                _hex(context[field])
            start, end = _second(context["createdAt"]), _second(context["expiresAt"])
            if not start < end <= start + 300 or start > semantic.issued_at or semantic.expires_at > end or now >= end:
                raise ValueError
            replay_ids.append("pairing:" + context["pairingId"])
        return AuthorizationCandidate(source, expected_method, digest(source), semantic, tuple(replay_ids))
    except Exception:
        raise MobileAuthorizationUnavailable() from None


def create_authorization(content, context, method, *, subject, now):
    source = canonical(
        dict(content=content, context=parse_json(context), domain=DOMAIN, method=method, schema=SCHEMA, version=1)
    )
    parse_authorization(source, subject=subject, expected_method=method, now=now)
    return source


def create_pairing_qr(pairing_id, secret):
    return QR_PREFIX + _hex(pairing_id) + ":" + _hex(secret)


def parse_pairing_qr(value):
    if type(value) is not str or not value.startswith(QR_PREFIX):
        raise MobileAuthorizationUnavailable()
    parts = value[len(QR_PREFIX) :].split(":")
    if len(parts) != 2:
        raise MobileAuthorizationUnavailable()
    return _hex(parts[0]), _hex(parts[1])


def pairing_secret_commitment(secret):
    return digest("HODLXXI_SOCIAL_PAIRING_SECRET_V1\x00" + _hex(secret))


def phone_exchange_commitment(verifier):
    return digest("HODLXXI_SOCIAL_PHONE_EXCHANGE_V1\x00" + _hex(verifier))


def comparison_code(transcript_digest):
    value = _hex(transcript_digest)[:12].upper()
    return "-".join(value[i : i + 4] for i in (0, 4, 8))


def pairing_possession_proof(secret, transcript_digest):
    return hmac.new(
        bytes.fromhex(_hex(secret)),
        ("HODLXXI_SOCIAL_PAIRING_POSSESSION_V1\x00" + _hex(transcript_digest)).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def verify_pairing_scan(source, *, qr, possession_proof, subject, now):
    candidate = parse_authorization(source, subject=subject, expected_method=QR, now=now)
    context = parse_json(source)["context"]
    pairing_id, secret = parse_pairing_qr(qr)
    if (
        pairing_id != context["pairingId"]
        or not hmac.compare_digest(pairing_secret_commitment(secret), context["secretCommitment"])
        or not hmac.compare_digest(pairing_possession_proof(secret, candidate.digest), _hex(possession_proof))
    ):
        raise MobileAuthorizationUnavailable()
    return candidate


def unsigned_event(source, *, subject, expected_method, now):
    candidate = parse_authorization(source, subject=subject, expected_method=expected_method, now=now)
    if expected_method == LEGACY:
        raise MobileAuthorizationUnavailable()
    qr = expected_method == QR
    content = source if qr else candidate.semantic.content
    tags = [
        ["purpose", QR_APPROVAL_PURPOSE if qr else NOSTR_EVENT_PURPOSE],
        ["semantic-digest", digest(content)],
        ["request-id", candidate.semantic.request_id],
        ["action", candidate.semantic.operation],
    ]
    if qr:
        context = parse_json(source)["context"]
        tags.extend([["pairing-id", context["pairingId"]], ["transcript", candidate.digest]])
    event = dict(content=content, created_at=candidate.semantic.issued_at, kind=NOSTR_EVENT_KIND, tags=tags)
    preimage = json.dumps(
        [0, subject, event["created_at"], event["kind"], tags, content], separators=(",", ":"), ensure_ascii=True
    )
    return dict(unsignedEvent=event, eventId=digest(preimage), signatureFormat=SIGNATURE_FORMAT)


def verify_event(source, event_source, *, subject, expected_method, now):
    try:
        expected = unsigned_event(source, subject=subject, expected_method=expected_method, now=now)
        event = _exact(parse_json(event_source), "content created_at id kind pubkey sig tags")
        if (
            event["pubkey"] != subject
            or event["id"] != expected["eventId"]
            or canonical({k: event[k] for k in ("content", "created_at", "kind", "tags")})
            != canonical(expected["unsignedEvent"])
            or type(event["sig"]) is not str
            or re.fullmatch(r"[0-9a-f]{128}", event["sig"]) is None
        ):
            raise ValueError
        if not Bip340IdentitySignatureVerifier().verify(
            subject=subject, signature=bytes.fromhex(event["sig"]), digest=bytes.fromhex(event["id"])
        ):
            raise ValueError
        return VerifiedMethodAuthorization(
            parse_authorization(source, subject=subject, expected_method=expected_method, now=now), event_source
        )
    except Exception:
        raise MobileAuthorizationUnavailable() from None


def legacy_signing_digest(challenge):
    if type(challenge) is not str or _UUID.fullmatch(challenge) is None:
        raise MobileAuthorizationUnavailable()
    magic = b"Bitcoin Signed Message:\n"
    message = challenge.encode("ascii")
    preimage = bytes([len(magic)]) + magic + bytes([len(message)]) + message
    return hashlib.sha256(hashlib.sha256(preimage).digest()).hexdigest()


def verify_legacy_submission(trusted_record, submission_source, *, subject, login_context, now):
    """Verify the existing compressed-P2PKH Bitcoin message signature locally.

    trusted_record MUST be fetched from immutable pre-sign challenge storage,
    never taken from the submission or an OAuth/session claim. This function
    does not consume it. Atomic reservation/consumption is a separate port.
    """
    try:
        candidate = parse_authorization(trusted_record, subject=subject, expected_method=LEGACY, now=now)
        context = parse_json(trusted_record)["context"]
        v = _exact(
            parse_json(submission_source),
            "authorizationDigest challenge compressedPublicKey loginContext method signature",
        )
        if (
            v["method"] != LEGACY
            or v["authorizationDigest"] != candidate.digest
            or v["challenge"] != context["challenge"]
            or v["loginContext"] != context["loginContext"]
            or v["loginContext"] != _hex(login_context)
            or type(v["compressedPublicKey"]) is not str
            or re.fullmatch(r"0[23][0-9a-f]{64}", v["compressedPublicKey"]) is None
            or v["compressedPublicKey"][2:] != subject
            or type(v["signature"]) is not str
        ):
            raise ValueError
        signature = base64.b64decode(v["signature"], validate=True)
        if (
            len(signature) != 65
            or not 31 <= signature[0] <= 34
            or base64.b64encode(signature).decode("ascii") != v["signature"]
        ):
            raise ValueError
        recovered = PublicKey.from_signature_and_message(
            signature[1:] + bytes([signature[0] - 31]),
            bytes.fromhex(legacy_signing_digest(v["challenge"])),
            hasher=None,
        )
        if recovered.format(compressed=True).hex() != v["compressedPublicKey"]:
            raise ValueError
        return VerifiedMethodAuthorization(candidate, submission_source, login_context)
    except Exception:
        raise MobileAuthorizationUnavailable() from None


@dataclass(frozen=True)
class CanonicalAcceptance:
    """Trusted acceptance-port output, never parsed from browser JSON."""

    authorization_digest: str
    binding_id: str
    subject: str
    request_id: str


def accept_verified_candidate(verified, *, current_full, atomic_accept, now):
    """Runtime-neutral final acceptance seam; caller owns one transaction.

    Only call with the output of a method verifier in this transaction.
    atomic_accept MUST recheck exact lifecycle state, immutable issued challenge
    or approved pairing revision, and ALL replay IDs atomically with acceptance.
    It must return None on conflict. No default ledger/authority is provided.
    """
    try:
        if type(verified) is not VerifiedMethodAuthorization or not callable(atomic_accept):
            raise ValueError
        candidate = verified.candidate
        if type(candidate) is not AuthorizationCandidate:
            raise ValueError
        if candidate.method == LEGACY:
            reverified = verify_legacy_submission(
                candidate.source,
                verified.proof_source,
                subject=candidate.semantic.subject,
                login_context=verified.login_context,
                now=now,
            )
        else:
            reverified = verify_event(
                candidate.source,
                verified.proof_source,
                subject=candidate.semantic.subject,
                expected_method=candidate.method,
                now=now,
            )
        if reverified != verified:
            raise ValueError
        checked = parse_authorization(
            candidate.source, subject=candidate.semantic.subject, expected_method=candidate.method, now=now
        )
        if candidate != checked or not callable(getattr(current_full, "verify_in_transaction", None)):
            raise ValueError
        timestamp = datetime.fromtimestamp(now, timezone.utc)
        proof = current_full.verify_in_transaction(candidate.semantic.subject, now=timestamp)
        validate_verified_current_full_entitlement(proof, subject=candidate.semantic.subject, now=timestamp)
        # Retain the exact method proof as well as the canonical proposal. A
        # digest alone cannot support exact retry or later evidence verification.
        accepted = atomic_accept(verified, proof)
        expected = CanonicalAcceptance(
            candidate.digest, candidate.semantic.binding_id, candidate.semantic.subject, candidate.semantic.request_id
        )
        if type(accepted) is not CanonicalAcceptance or accepted != expected:
            raise ValueError
        return accepted
    except Exception:
        raise MobileAuthorizationUnavailable() from None


@dataclass(frozen=True)
class PairingState:
    """Pure state snapshot. Its owner must CAS each transition durably."""

    source: str
    revision: str
    status: str = "awaiting-approval"
    acceptance: CanonicalAcceptance | None = None


def approve_pairing(
    state, event_source, *, subject, desktop_context, expected_revision, human_code, current_full, atomic_accept, now
):
    if (
        type(state) is not PairingState
        or state.status != "awaiting-approval"
        or state.acceptance is not None
        or state.revision != _hex(expected_revision)
    ):
        raise MobileAuthorizationUnavailable()
    verified = verify_event(state.source, event_source, subject=subject, expected_method=QR, now=now)
    candidate = verified.candidate
    context = parse_json(state.source)["context"]
    if context["desktopContext"] != _hex(desktop_context) or human_code != comparison_code(candidate.digest):
        raise MobileAuthorizationUnavailable()
    acceptance = accept_verified_candidate(verified, current_full=current_full, atomic_accept=atomic_accept, now=now)
    return PairingState(state.source, state.revision, "accepted", acceptance)


def consume_phone_exchange(state, *, verifier, subject, expected_revision, consume_once, now):
    """Return only a device-bound exchange identity after canonical acceptance.

    verifier is a separate, ephemeral phone PKCE-style value, NOT an X25519
    secret. The messaging CryptoKey is never used to authenticate a session.
    consume_once atomically consumes the accepted pairing revision; a future
    session issuer must own that transaction. This seam issues no session.
    """
    if (
        type(state) is not PairingState
        or state.status != "accepted"
        or state.revision != _hex(expected_revision)
        or type(state.acceptance) is not CanonicalAcceptance
        or not callable(consume_once)
    ):
        raise MobileAuthorizationUnavailable()
    candidate = parse_authorization(state.source, subject=subject, expected_method=QR, now=now)
    if candidate.semantic.operation == "revoke":
        raise MobileAuthorizationUnavailable()
    context = parse_json(state.source)["context"]
    expected = CanonicalAcceptance(
        candidate.digest, candidate.semantic.binding_id, subject, candidate.semantic.request_id
    )
    if state.acceptance != expected or not hmac.compare_digest(
        phone_exchange_commitment(verifier), context["exchangeCommitment"]
    ):
        raise MobileAuthorizationUnavailable()
    if consume_once(context["pairingId"], state.revision, candidate.digest) is not True:
        raise MobileAuthorizationUnavailable()
    return canonical(
        dict(
            schema="hodlxxi.social_phone_session_exchange_identity.v1",
            version=1,
            pairingId=context["pairingId"],
            authorizationDigest=candidate.digest,
            bindingId=candidate.semantic.binding_id,
            deviceId=parse_json(candidate.semantic.binding_record)["deviceId"],
            subject=subject,
            requestId=candidate.semantic.request_id,
            exchangeCommitment=context["exchangeCommitment"],
            expiresAt=datetime.fromtimestamp(candidate.semantic.expires_at, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        )
    )


def issue_legacy_challenge(source, *, subject, reserve_once, now, enabled=False):
    """Reserve the immutable proposal BEFORE exposing the wallet's UUID message.

    reserve_once must atomically reserve both the global challenge and request
    identity with these exact bytes. Issuance does not authorize anything.
    """
    if enabled is not True or not callable(reserve_once):
        raise MobileAuthorizationUnavailable()
    candidate = parse_authorization(source, subject=subject, expected_method=LEGACY, now=now)
    challenge = parse_json(source)["context"]["challenge"]
    if reserve_once(candidate.replay_ids, source) is not True:
        raise MobileAuthorizationUnavailable()
    return canonical(
        dict(
            challenge=challenge,
            authorizationDigest=candidate.digest,
            expiresAt=datetime.fromtimestamp(candidate.semantic.expires_at, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        )
    )


@dataclass(frozen=True)
class PairingOffer:
    pairing_id: str
    secret_commitment: str
    desktop_context: str
    subject: str
    created_at: str
    expires_at: str
    revision: str
    status: str = "created"


def create_pairing_offer(
    *,
    subject,
    desktop_context,
    revision,
    now,
    ttl=300,
    enabled=False,
    random_bytes=secrets.token_bytes,
    reserve_once=None,
):
    if (
        enabled is not True
        or type(now) is not int
        or now < 0
        or type(ttl) is not int
        or not 1 <= ttl <= 300
        or not callable(reserve_once)
    ):
        raise MobileAuthorizationUnavailable()
    _hex(subject)
    _hex(desktop_context)
    _hex(revision)
    identifier, secret = random_bytes(32), random_bytes(32)
    if (
        type(identifier) is not bytes
        or type(secret) is not bytes
        or len(identifier) != 32
        or len(secret) != 32
        or identifier == secret
    ):
        raise MobileAuthorizationUnavailable()

    def stamp(t):
        return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    offer = PairingOffer(
        identifier.hex(),
        pairing_secret_commitment(secret.hex()),
        desktop_context,
        subject,
        stamp(now),
        stamp(now + ttl),
        revision,
    )
    if reserve_once(offer) is not True:
        raise MobileAuthorizationUnavailable()
    return offer, create_pairing_qr(identifier.hex(), secret.hex())


def submit_pairing_scan(offer, source, *, qr, possession_proof, claim_once, now):
    if type(offer) is not PairingOffer or offer.status != "created" or not callable(claim_once):
        raise MobileAuthorizationUnavailable()
    candidate = verify_pairing_scan(source, qr=qr, possession_proof=possession_proof, subject=offer.subject, now=now)
    context = parse_json(source)["context"]
    if any(
        context[k] != v
        for k, v in dict(
            pairingId=offer.pairing_id,
            secretCommitment=offer.secret_commitment,
            desktopContext=offer.desktop_context,
            createdAt=offer.created_at,
            expiresAt=offer.expires_at,
        ).items()
    ):
        raise MobileAuthorizationUnavailable()
    if claim_once(offer, candidate) is not True:
        raise MobileAuthorizationUnavailable()
    return PairingState(source, offer.revision)

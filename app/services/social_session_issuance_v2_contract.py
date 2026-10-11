"""Dormant native V2 issuance identities; parsing is never authority."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone

from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
from app.services.oauth_bearer_validation import TOKEN_CONTRACT
from app.services.social_messaging_device_contract import MessagingDeviceBinding
from app.services.social_messaging_mobile_authorization import parse_json

RUNTIME_ENABLED = False
SCOPE = "openid profile"
REVISION_DOMAIN = "HODLXXI_SOCIAL_SESSION_ISSUANCE_REVISION_V2"
DELIVERY_DOMAIN = "HODLXXI_SOCIAL_SESSION_DELIVERY_V2"
CONTINUITY_DOMAIN = "HODLXXI_SOCIAL_SESSION_DESKTOP_CONTINUITY_V2"
MAX_SAFE_INTEGER = 9_007_199_254_740_991


class V2IssuanceUnavailable(ValueError):
    def __init__(self):
        super().__init__("social session issuance v2 unavailable")


def hex64(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise V2IssuanceUnavailable()
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(domain, value):
    return hashlib.sha256(domain.encode("ascii") + b"\0" + canonical(value).encode("ascii")).hexdigest()


def utc(value):
    if type(value) is not datetime:
        raise V2IssuanceUnavailable()
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def milliseconds(value):
    """Floor database microseconds using integer arithmetic, never float rounding."""
    delta = utc(value) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    result = delta.days * 86_400_000 + delta.seconds * 1000 + delta.microseconds // 1000
    if not 0 <= result <= MAX_SAFE_INTEGER:
        raise V2IssuanceUnavailable()
    return result


def trusted_now(clock):
    value = clock()
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise V2IssuanceUnavailable()
    milliseconds(value)
    return value.astimezone(timezone.utc)


def binding_from_wire(source):
    envelope = v2.parse_authorization_envelope_v2(source)
    record = parse_json(envelope.semantic.binding_record)
    return MessagingDeviceBinding(
        subject=record["subject"],
        device_id=record["deviceId"],
        binding_id=envelope.semantic.binding_id,
        public_key=record["publicKey"],
        binding_version=record["bindingVersion"],
        valid_from=utc(datetime.fromisoformat(record["validFrom"].replace("Z", "+00:00"))),
        expires_at=utc(datetime.fromisoformat(record["expiresAt"].replace("Z", "+00:00"))),
        operation="register",
        prior_binding_id=None,
        request_id=record["requestId"],
        active=True,
    )


def continuity(generation, auth, context):
    # The generation is native; context cannot manufacture one.
    return digest(
        CONTINUITY_DOMAIN,
        [
            generation.token_id,
            generation.session_id,
            generation.browser_generation_id,
            generation.user_id,
            generation.client_id,
            generation.subject,
            auth.created_at.isoformat(),
            auth.session_type,
            hex64(context),
        ],
    )


def delivery_commitment(*, issuer, client_id, backend_id, principal, operation_id, verifier, delivery_key):
    return digest(
        DELIVERY_DOMAIN,
        [issuer, client_id, backend_id, principal, hex64(operation_id), hex64(verifier), hex64(delivery_key)],
    )


def verify_phone(source, *, secret, possession_proof, verifier, now_ms=None):
    """History verifies original possession too; recovery never synthesizes proofs."""
    envelope = v2.parse_authorization_envelope_v2(source)
    if now_ms is not None:
        v2.verify_pairing_possession_v2(source, secret=secret, possession_proof=possession_proof, now_ms=now_ms)
    elif not (
        hmac.compare_digest(v2.pairing_secret_commitment_v2(secret), envelope.context.secret_commitment)
        and hmac.compare_digest(
            v2.pairing_possession_proof_v2(secret, v2.authorization_v2_digest(source)), hex64(possession_proof)
        )
    ):
        raise V2IssuanceUnavailable()
    if not hmac.compare_digest(v2.phone_exchange_commitment_v2(verifier), envelope.context.exchange_commitment):
        raise V2IssuanceUnavailable()
    return envelope


def revision_preimage(
    *,
    operation_id,
    acceptance_wire,
    approval_wire,
    issuance_id,
    token_id,
    parent_token_id,
    parent_session_id,
    parent_browser_id,
    client_id,
    backend_id,
    principal,
    issuer,
    delivery,
    issued_at,
    expires_at,
    signing_kid,
):
    accepted = v2.parse_acceptance_v2(acceptance_wire, approval_event_wire=approval_wire)
    if operation_id != accepted.approval.envelope.context.pairing_id:
        raise V2IssuanceUnavailable()
    for value in (operation_id, issuance_id, delivery, parent_browser_id, parent_session_id):
        hex64(value)
    if any(
        type(value) is not str or re.fullmatch(r"[0-9a-f]{32}", value) is None for value in (token_id, parent_token_id)
    ):
        raise V2IssuanceUnavailable()
    if (
        type(issued_at) is not int
        or type(expires_at) is not int
        or not 0 <= issued_at < expires_at <= min(issued_at + 300, MAX_SAFE_INTEGER // 1000)
    ):
        raise V2IssuanceUnavailable()
    if type(signing_kid) is not str or not 1 <= len(signing_kid) <= 255 or not signing_kid.isascii():
        raise V2IssuanceUnavailable()
    return canonical(
        dict(
            schema="hodlxxi.social_session_issuance_revision_preimage.v2",
            version=2,
            operationId=operation_id,
            acceptance=acceptance_wire,
            approvalEvent=approval_wire,
            issuanceId=issuance_id,
            tokenId=token_id,
            parentOAuthTokenId=parent_token_id,
            parentOAuthSessionId=parent_session_id,
            parentOAuthBrowserGenerationId=parent_browser_id,
            approverOAuthTokenId=parent_token_id,
            approverOAuthSessionId=parent_session_id,
            approverOAuthBrowserGenerationId=parent_browser_id,
            clientId=client_id,
            backendId=backend_id,
            servicePrincipal=principal,
            issuer=issuer,
            deliveryCommitment=delivery,
            signingKeyId=signing_kid,
            issuedAt=issued_at,
            expiresAt=expires_at,
        )
    ).encode("ascii")


def issuance_revision(**values):
    return hashlib.sha256(REVISION_DOMAIN.encode("ascii") + b"\0" + revision_preimage(**values)).hexdigest()


def claims(row):
    # Same insertion order as app.tokens.issue_rs256_jwt, including original JTI.
    return dict(
        iss=row.issuer,
        aud=row.client_id,
        sub=row.subject,
        iat=row.issued_at,
        exp=row.expires_at,
        jti=row.token_id,
        scope=SCOPE,
        token_use="access",
        token_contract=TOKEN_CONTRACT,
    )


def receipt(row):
    return dict(
        schema="hodlxxi.social_session_issuance.v2",
        version=2,
        issuanceId=row.issuance_id,
        socialSessionIssuanceRevision=row.revision,
        acceptanceId=row.acceptance_id,
        issuedAt=row.issued_at * 1000,
        expiresAt=row.expires_at * 1000,
    )

"""Dormant accepted-mobile evidence adapter for the existing recipient gate.

An injected authoritative reader supplies committed evidence, never request JSON.
Signature verification alone is insufficient. This module grants no session,
Full entitlement, sender-device admission, or private-key possession claim.
"""

from dataclasses import dataclass
from datetime import datetime, timezone

from app.services import social_messaging_mobile_authorization as mobile
from app.services.social_messaging_device_binding_authorization import (
    _binding_from_record,
    _utc_second,
    _validated_legacy_binding,
)
from app.services.social_messaging_device_contract import MessagingDeviceBinding
from app.services.social_messaging_recipient_routing import (
    RecipientMessagingRoutingUnavailable,
    VerifiedBindingAuthorization,
)

EVIDENCE_SCHEMA = "hodlxxi.social_mobile_binding_evidence.v1"
PROOF_ID_PREFIX = "hodlxxi-mobile-binding-authorization-v1-sha256:"


@dataclass(frozen=True)
class AcceptedMobileBindingEvidence:
    operation_id: str
    method: str
    subject: str
    context_id: str
    created_at: int
    expires_at: int
    revision: str | None
    secret_commitment: str | None
    source: str
    proof_source: str
    result_source: str
    request_id: str
    authorization_digest: str
    binding_id: str
    accepted_at: int


@dataclass(frozen=True)
class MobileBindingEvidenceState:
    schema: str
    version: int
    binding_id: str
    complete: bool
    truncated: bool
    records: tuple[AcceptedMobileBindingEvidence, ...]


class AcceptedMobileBindingAuthorizationVerifier:
    """Reverify one committed LEGACY/QR authorization for one exact binding.

    The reader must enforce the original accepted operation, immutable receipt,
    global request owner and exclusive binding owner. It exposes ambiguity rather
    than selecting a winner. No fallback to a Nostr or OAuth-shaped record exists.
    """

    def __init__(self, evidence_provider, *, enabled=False):
        if type(enabled) is not bool or not callable(getattr(evidence_provider, "accepted_for_binding", None)):
            raise ValueError("invalid mobile routing dependency")
        self._provider = evidence_provider
        self._enabled = enabled

    def verify(self, binding: MessagingDeviceBinding, *, now: datetime) -> VerifiedBindingAuthorization:
        try:
            if not self._enabled or type(binding) is not MessagingDeviceBinding:
                raise ValueError
            now = _utc_second(now)
            _validated_legacy_binding(binding)
            binding_id = mobile._hex(binding.binding_id)
            state = self._provider.accepted_for_binding(binding_id, maximum=2)
            if (
                type(state) is not MobileBindingEvidenceState
                or type(state.schema) is not str
                or state.schema != EVIDENCE_SCHEMA
                or type(state.version) is not int
                or state.version != 1
                or state.binding_id != binding_id
                or state.complete is not True
                or state.truncated is not False
                or type(state.records) is not tuple
                or len(state.records) != 1
            ):
                raise ValueError
            record = state.records[0]
            if type(record) is not AcceptedMobileBindingEvidence:
                raise ValueError
            if (
                type(record.created_at) is not int
                or type(record.expires_at) is not int
                or type(record.accepted_at) is not int
                or not 0 <= record.created_at <= record.accepted_at < record.expires_at <= record.created_at + 300
                or record.accepted_at > int(now.timestamp())
                or record.subject != binding.subject
                or record.binding_id != binding_id
            ):
                raise ValueError
            mobile._hex(record.context_id)
            if record.method == mobile.LEGACY:
                if record.revision is not None or record.secret_commitment is not None:
                    raise ValueError
                verified = mobile.verify_legacy_submission(
                    record.source,
                    record.proof_source,
                    subject=record.subject,
                    login_context=record.context_id,
                    now=record.accepted_at,
                )
            elif record.method == mobile.QR:
                mobile._hex(record.revision)
                mobile._hex(record.secret_commitment)
                verified = mobile.verify_event(
                    record.source,
                    record.proof_source,
                    subject=record.subject,
                    expected_method=mobile.QR,
                    now=record.accepted_at,
                )
            else:
                raise ValueError
            candidate = verified.candidate
            context = mobile.parse_json(candidate.source)["context"]
            if record.method == mobile.LEGACY:
                if context["challenge"] != record.operation_id:
                    raise ValueError
            elif (
                context["pairingId"] != record.operation_id
                or context["desktopContext"] != record.context_id
                or context["secretCommitment"] != record.secret_commitment
                or mobile._second(context["createdAt"]) != record.created_at
                or mobile._second(context["expiresAt"]) != record.expires_at
            ):
                raise ValueError
            expected_result = mobile.canonical(
                dict(
                    schema="hodlxxi.social_mobile_authorization_acceptance.v1",
                    version=1,
                    authorizationDigest=candidate.digest,
                    bindingId=candidate.semantic.binding_id,
                    subject=candidate.semantic.subject,
                    requestId=candidate.semantic.request_id,
                )
            )
            accepted_binding = _binding_from_record(
                mobile.parse_json(candidate.semantic.binding_record), candidate.semantic.binding_id
            )
            accepted_at = datetime.fromtimestamp(record.accepted_at, timezone.utc)
            if (
                candidate.digest != record.authorization_digest
                or candidate.semantic.request_id != record.request_id
                or candidate.semantic.binding_id != binding_id
                or record.result_source != expected_result
                or candidate.semantic.operation not in {"register", "rotate", "adopt"}
                or accepted_binding != binding
                or binding.active is not True
                or binding.operation not in {"register", "rotate"}
                or not binding.valid_from <= accepted_at <= now < binding.expires_at
            ):
                raise ValueError
            return VerifiedBindingAuthorization(
                proof_id=PROOF_ID_PREFIX + candidate.digest,
                subject=binding.subject,
                device_id=binding.device_id,
                binding_id=binding_id,
                binding_version=binding.binding_version,
                public_key=binding.public_key,
                valid_from=binding.valid_from,
                expires_at=binding.expires_at,
                evidence_valid_from=accepted_at,
                evidence_expires_at=binding.expires_at,
            )
        except Exception:
            raise RecipientMessagingRoutingUnavailable() from None

"""Dormant, endpoint-independent orchestration for authenticated internal actions."""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Protocol

from app.services.action_authorization import (
    ACTION_REQUIREMENTS,
    ActionDecision,
    ActionName,
    ActionRequest,
    IdentityClass,
    authorize_action,
)
from app.services.action_idempotency import (
    OPERATION_CONTRACT_VERSION,
    idempotency_key_sha256,
    request_fingerprint_sha256,
    token_reference_sha256,
)
from app.services.action_operation_storage import Reservation, stored_receipt_bytes
from app.services.action_receipt import ActionReceiptError, canonical_timestamp, create_action_receipt
from app.services.action_step_up import StepUpProof
from app.services.action_step_up_operation_storage import (
    AtomicStepUpReserveResult,
    AtomicStepUpReserveStatus,
)
from app.services.current_entitlement import (
    CurrentEntitlementResolver,
    EntitlementDecision,
    EntitlementDenied,
    EntitlementUnavailable,
)
from app.services.oauth_bearer_validation import BearerPrincipal, BearerValidationError

MAX_REQUEST_BYTES = 65_536
MAX_BEARER_BYTES = 16_384
MAX_CLIENT_ID_LENGTH = 256
MAX_RESOURCE_ID_LENGTH = 256
MAX_FAILURE_CODE_LENGTH = 64
_SAFE_IDENTIFIER = re.compile(r"^[\x21-\x7e]+$")
_SAFE_FAILURE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_ELIGIBLE_ACTIONS = frozenset(
    {ActionName.SELF_READ, ActionName.JOB_CREATE, ActionName.COVENANT_DRAFT_CREATE}
)


class GatewayReason(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    REPLAY = "replay"
    INVALID_REQUEST = "invalid_request"
    INVALID_TOKEN = "invalid_token"
    ENTITLEMENT_DENIED = "entitlement_denied"
    ENTITLEMENT_UNAVAILABLE = "entitlement_unavailable"
    AUTHORIZATION_DENIED = "authorization_denied"
    GATEWAY_ACTION_UNAVAILABLE = "gateway_action_unavailable"
    OWNERSHIP_UNAVAILABLE = "ownership_unavailable"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    STEP_UP_REJECTED = "step_up_rejected"
    OPERATION_IN_PROGRESS = "operation_in_progress"
    OPERATION_INDETERMINATE = "operation_indeterminate"
    STORAGE_UNAVAILABLE = "storage_unavailable"
    SIGNING_FAILED = "signing_failed"
    FINALIZATION_FAILED = "finalization_failed"
    GATEWAY_INTERNAL_FAILURE = "gateway_internal_failure"


@dataclass(frozen=True)
class InternalActionInvocation:
    encoded_bearer_token: str
    expected_oauth_client_id: str
    action: ActionName | str
    resource_id: str | None
    idempotency_key: str
    request_payload: object
    step_up_proof: object | None = None


@dataclass(frozen=True)
class ReceiptRetrievalRequest:
    encoded_bearer_token: str
    expected_oauth_client_id: str
    operation_id: str


@dataclass(frozen=True)
class HandlerResult:
    state: str
    result_payload: object | None = None
    failure_code: str | None = None

    @classmethod
    def completed(cls, payload: object) -> HandlerResult:
        return cls("completed", result_payload=payload)

    @classmethod
    def failed(cls, failure_code: str) -> HandlerResult:
        return cls("failed", failure_code=failure_code)


@dataclass(frozen=True)
class GatewayResult:
    reason: GatewayReason
    operation_id: str | None = None
    receipt: bytes | None = None
    failure: GatewayReason | None = None


class OperationRepository(Protocol):
    def reserve(self, reservation: Reservation): ...
    def mark_executing(self, operation_id: str, started_at: datetime) -> bool: ...
    def finalize_completed(self, operation_id: str, receipt: dict) -> bool: ...
    def finalize_failed(self, operation_id: str, receipt: dict) -> bool: ...
    def mark_indeterminate(self, operation_id: str, updated_at: datetime) -> bool: ...
    def get_by_operation_id(self, operation_id: str): ...


class AtomicStepUpOperationRepository(Protocol):
    def reserve_with_step_up(
        self,
        reservation: Reservation,
        proof: StepUpProof,
        consumed_at: datetime,
    ) -> AtomicStepUpReserveResult: ...


BearerValidator = Callable[[str], BearerPrincipal]
EntitlementResolverCallback = Callable[[str], EntitlementDecision]
ActionHandler = Callable[[bytes], HandlerResult]
OwnershipResolver = Callable[[ActionName, str, str], str | None]


def _validate_json_value(value: object, active_containers: set[int]) -> None:
    value_type = type(value)
    if value is None or value_type in {bool, int, str}:
        return
    if value_type is float:
        if not math.isfinite(value):
            raise ValueError("invalid_request")
        return
    if value_type not in {list, dict}:
        raise ValueError("invalid_request")

    identity = id(value)
    if identity in active_containers:
        raise ValueError("invalid_request")
    active_containers.add(identity)
    try:
        if value_type is list:
            for item in value:
                _validate_json_value(item, active_containers)
        else:
            for key, item in value.items():
                if type(key) is not str:
                    raise ValueError("invalid_request")
                _validate_json_value(item, active_containers)
    finally:
        active_containers.remove(identity)


def canonical_payload_bytes(value: object, *, maximum: int = MAX_REQUEST_BYTES) -> bytes:
    _validate_json_value(value, set())
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("invalid_request") from exc
    if len(encoded) > maximum:
        raise ValueError("invalid_request")
    return encoded


def authorization_decision_sha256(decision: ActionDecision) -> str:
    return hashlib.sha256(canonical_payload_bytes(decision.to_dict())).hexdigest()


def _identifier(value: object, maximum: int, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value.strip() != value
        or _SAFE_IDENTIFIER.fullmatch(value) is None
    ):
        raise ValueError("invalid_request")
    return value


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("invalid clock")
    return value.astimezone(timezone.utc)


class InternalActionGateway:
    """Compose trusted action contracts without exposing a transport or handler."""

    def __init__(
        self,
        *,
        bearer_validator: BearerValidator,
        entitlement_resolver: EntitlementResolverCallback,
        operation_repository: OperationRepository,
        handlers: Mapping[ActionName, ActionHandler],
        receipt_signer: Callable[[bytes], str],
        signer_public_key: str,
        clock: Callable[[], datetime],
        ownership_resolver: OwnershipResolver | None = None,
        atomic_step_up_repository: AtomicStepUpOperationRepository | None = None,
    ):
        normalized: dict[ActionName, ActionHandler] = {}
        for key, handler in handlers.items():
            if type(key) is not ActionName or not callable(handler) or key not in _ELIGIBLE_ACTIONS:
                raise ValueError("invalid handler registry")
            normalized[key] = handler
        self._handlers = MappingProxyType(normalized)
        self._bearer_validator = bearer_validator
        self._entitlement_resolver = entitlement_resolver
        self._repository = operation_repository
        self._receipt_signer = receipt_signer
        self._signer_public_key = signer_public_key
        self._clock = clock
        self._ownership_resolver = ownership_resolver
        self._atomic_step_up_repository = atomic_step_up_repository

    def invoke(self, invocation: InternalActionInvocation) -> GatewayResult:
        try:
            if type(invocation) is not InternalActionInvocation:
                raise ValueError
            token = _identifier(invocation.encoded_bearer_token, MAX_BEARER_BYTES)
            expected_client = _identifier(invocation.expected_oauth_client_id, MAX_CLIENT_ID_LENGTH)
            resource_id = _identifier(invocation.resource_id, MAX_RESOURCE_ID_LENGTH, optional=True)
            action = ActionName(invocation.action)
            request_bytes = canonical_payload_bytes(invocation.request_payload)
            key_hash = idempotency_key_sha256(invocation.idempotency_key)
        except Exception:
            return GatewayResult(GatewayReason.INVALID_REQUEST)

        principal_result = self._principal(token, expected_client)
        if isinstance(principal_result, GatewayResult):
            return principal_result
        principal = principal_result
        entitlement_result = self._entitlement(principal)
        if isinstance(entitlement_result, GatewayResult):
            return entitlement_result
        entitlement = entitlement_result

        requirement = ACTION_REQUIREMENTS[action]
        handler = self._handlers.get(action)
        if requirement.step_up_required:
            if action not in _ELIGIBLE_ACTIONS or handler is None or self._atomic_step_up_repository is None:
                return GatewayResult(GatewayReason.GATEWAY_ACTION_UNAVAILABLE)
            if type(invocation.step_up_proof) is not StepUpProof:
                return GatewayResult(GatewayReason.STEP_UP_REJECTED)
        elif IdentityClass.LIMITED not in requirement.allowed_identities or requirement.current_full_relation_required:
            return GatewayResult(GatewayReason.GATEWAY_ACTION_UNAVAILABLE)
        owner = None
        if requirement.ownership_required:
            if resource_id is None or self._ownership_resolver is None:
                return GatewayResult(GatewayReason.OWNERSHIP_UNAVAILABLE)
            try:
                owner = self._ownership_resolver(action, resource_id, principal.subject)
            except Exception:
                return GatewayResult(GatewayReason.OWNERSHIP_UNAVAILABLE)
            if owner is None:
                return GatewayResult(GatewayReason.OWNERSHIP_UNAVAILABLE)
        if action not in _ELIGIBLE_ACTIONS or handler is None:
            return GatewayResult(GatewayReason.GATEWAY_ACTION_UNAVAILABLE)
        decision = authorize_action(
            ActionRequest(
                principal.subject,
                action,
                principal.scopes,
                owner,
                step_up_verified=requirement.step_up_required,
            ),
            CurrentEntitlementResolver(entitlement),
        )
        if not decision.allowed:
            return GatewayResult(GatewayReason.AUTHORIZATION_DENIED)

        request_hash = hashlib.sha256(request_bytes).hexdigest()
        decision_hash = authorization_decision_sha256(decision)
        try:
            reserved_at = _utc(self._clock())
            step_up_challenge_id = (
                invocation.step_up_proof.challenge_id if requirement.step_up_required else None
            )
            reservation = Reservation(
                contract_version=OPERATION_CONTRACT_VERSION,
                actor_pubkey=principal.subject,
                oauth_client_id=principal.client_id,
                token_jti=principal.jti,
                token_reference_sha256=token_reference_sha256(principal.jti),
                action=action.value,
                resource_id=resource_id,
                request_sha256=request_hash,
                idempotency_key_sha256=key_hash,
                request_fingerprint_sha256=request_fingerprint_sha256(
                    contract_version=OPERATION_CONTRACT_VERSION,
                    actor_pubkey=principal.subject,
                    oauth_client_id=principal.client_id,
                    token_jti=principal.jti,
                    action=action.value,
                    resource_id=resource_id,
                    request_sha256=request_hash,
                    step_up_challenge_id=step_up_challenge_id,
                ),
                step_up_challenge_id=step_up_challenge_id,
                step_up_verification_sha256=None,
                policy_version=decision.policy_version,
                authorization_decision_sha256=decision_hash,
                reserved_at=reserved_at,
            )
            if requirement.step_up_required:
                reserve_result = self._atomic_step_up_repository.reserve_with_step_up(
                    reservation,
                    invocation.step_up_proof,
                    reserved_at,
                )
            else:
                reserve_result = self._repository.reserve(reservation)
        except Exception:
            return GatewayResult(GatewayReason.STORAGE_UNAVAILABLE)

        if requirement.step_up_required:
            if type(reserve_result) is not AtomicStepUpReserveResult:
                return GatewayResult(GatewayReason.STORAGE_UNAVAILABLE)
            if reserve_result.status is AtomicStepUpReserveStatus.STEP_UP_REJECTED:
                return GatewayResult(GatewayReason.STEP_UP_REJECTED)
            if reserve_result.status is AtomicStepUpReserveStatus.IDEMPOTENCY_CONFLICT:
                return GatewayResult(GatewayReason.IDEMPOTENCY_CONFLICT)
            if reserve_result.status is AtomicStepUpReserveStatus.REPLAY:
                return self._replay(reserve_result.operation)
            if reserve_result.status is not AtomicStepUpReserveStatus.NEW:
                return GatewayResult(GatewayReason.STORAGE_UNAVAILABLE)
        else:
            if reserve_result.status == "idempotency_conflict":
                return GatewayResult(GatewayReason.IDEMPOTENCY_CONFLICT)
            if reserve_result.status != "new":
                if reserve_result.operation is None:
                    return GatewayResult(GatewayReason.STORAGE_UNAVAILABLE)
                return self._replay(reserve_result.operation)
        operation = reserve_result.operation
        if operation is None:
            return GatewayResult(GatewayReason.STORAGE_UNAVAILABLE)

        try:
            started_at = _utc(self._clock())
            if not self._repository.mark_executing(operation.operation_id, started_at):
                current = self._repository.get_by_operation_id(operation.operation_id)
                return (
                    self._replay(current) if current is not None else GatewayResult(GatewayReason.STORAGE_UNAVAILABLE)
                )
        except Exception:
            return GatewayResult(GatewayReason.STORAGE_UNAVAILABLE, operation.operation_id)

        try:
            handler_result = handler(request_bytes)
            result_bytes = self._validate_and_canonicalize_handler_result(handler_result)
        except Exception:
            return self._indeterminate(operation.operation_id)

        try:
            completed_at = _utc(self._clock())
            result_hash = hashlib.sha256(result_bytes).hexdigest() if result_bytes is not None else None
            receipt = create_action_receipt(
                signer=self._receipt_signer,
                signer_public_key=self._signer_public_key,
                operation_id=operation.operation_id,
                idempotency_key_sha256=reservation.idempotency_key_sha256,
                actor_pubkey=principal.subject,
                oauth_client_id=principal.client_id,
                token_reference_sha256=reservation.token_reference_sha256,
                action=action.value,
                resource_id=resource_id,
                request_sha256=request_hash,
                policy_version=decision.policy_version,
                authorization_decision_sha256=decision_hash,
                step_up_challenge_id=operation.step_up_challenge_id,
                step_up_verification_sha256=operation.step_up_verification_sha256,
                state=handler_result.state,
                started_at=canonical_timestamp(started_at),
                completed_at=canonical_timestamp(completed_at),
                failure_code=handler_result.failure_code,
                result_sha256=result_hash,
            )
        except ActionReceiptError:
            result = self._indeterminate(operation.operation_id)
            return GatewayResult(result.reason, result.operation_id, failure=GatewayReason.SIGNING_FAILED)
        except Exception:
            return self._indeterminate(operation.operation_id)

        try:
            finalized = (
                self._repository.finalize_completed(operation.operation_id, receipt)
                if handler_result.state == "completed"
                else self._repository.finalize_failed(operation.operation_id, receipt)
            )
            if not finalized:
                result = self._indeterminate(operation.operation_id)
                return GatewayResult(result.reason, result.operation_id, failure=GatewayReason.FINALIZATION_FAILED)
        except Exception:
            result = self._indeterminate(operation.operation_id)
            return GatewayResult(result.reason, result.operation_id, failure=GatewayReason.FINALIZATION_FAILED)
        return GatewayResult(
            GatewayReason.COMPLETED if handler_result.state == "completed" else GatewayReason.FAILED,
            operation.operation_id,
            canonical_payload_bytes(receipt),
        )

    def retrieve_receipt(self, request: ReceiptRetrievalRequest) -> GatewayResult:
        try:
            if type(request) is not ReceiptRetrievalRequest:
                raise ValueError
            token = _identifier(request.encoded_bearer_token, MAX_BEARER_BYTES)
            expected_client = _identifier(request.expected_oauth_client_id, MAX_CLIENT_ID_LENGTH)
            operation_id = _identifier(request.operation_id, 36)
            if str(uuid.UUID(operation_id)) != operation_id:
                raise ValueError
        except Exception:
            return GatewayResult(GatewayReason.INVALID_REQUEST)
        principal_result = self._principal(token, expected_client)
        if isinstance(principal_result, GatewayResult):
            return principal_result
        principal = principal_result
        entitlement_result = self._entitlement(principal)
        if isinstance(entitlement_result, GatewayResult):
            return entitlement_result
        try:
            operation = self._repository.get_by_operation_id(operation_id)
        except Exception:
            return GatewayResult(GatewayReason.STORAGE_UNAVAILABLE)
        if operation is None:
            return GatewayResult(GatewayReason.AUTHORIZATION_DENIED)
        decision = authorize_action(
            ActionRequest(
                principal.subject,
                ActionName.ACTION_RECEIPT_READ_SELF,
                principal.scopes,
                resource_owner_pubkey=operation.actor_pubkey,
                step_up_verified=False,
            ),
            CurrentEntitlementResolver(entitlement_result),
        )
        if not decision.allowed:
            return GatewayResult(GatewayReason.AUTHORIZATION_DENIED)
        receipt = stored_receipt_bytes(operation)
        if receipt is None:
            return self._replay(operation)
        return GatewayResult(GatewayReason.REPLAY, operation.operation_id, receipt)

    def _principal(self, token: str, expected_client: str) -> BearerPrincipal | GatewayResult:
        try:
            principal = self._bearer_validator(token)
            if type(principal) is not BearerPrincipal or principal.client_id != expected_client:
                raise BearerValidationError("invalid")
            return principal
        except Exception:
            return GatewayResult(GatewayReason.INVALID_TOKEN)

    def _entitlement(self, principal: BearerPrincipal) -> EntitlementDecision | GatewayResult:
        try:
            decision = self._entitlement_resolver(principal.subject)
            if type(decision) is not EntitlementDecision or decision.subject != principal.subject:
                raise EntitlementUnavailable("mismatch")
            return decision
        except EntitlementDenied:
            return GatewayResult(GatewayReason.ENTITLEMENT_DENIED)
        except Exception:
            return GatewayResult(GatewayReason.ENTITLEMENT_UNAVAILABLE)

    @staticmethod
    def _validate_and_canonicalize_handler_result(result: HandlerResult) -> bytes | None:
        if type(result) is not HandlerResult:
            raise ValueError
        if result.state == "completed":
            if result.failure_code is not None:
                raise ValueError
            return canonical_payload_bytes(result.result_payload)
        if (
            result.state != "failed"
            or result.result_payload is not None
            or not isinstance(result.failure_code, str)
            or not 1 <= len(result.failure_code) <= MAX_FAILURE_CODE_LENGTH
            or _SAFE_FAILURE.fullmatch(result.failure_code) is None
        ):
            raise ValueError
        return None

    def _replay(self, operation) -> GatewayResult:
        if operation.state in {"completed", "failed"}:
            receipt = stored_receipt_bytes(operation)
            if receipt is None:
                return GatewayResult(GatewayReason.STORAGE_UNAVAILABLE, operation.operation_id)
            return GatewayResult(GatewayReason.REPLAY, operation.operation_id, receipt)
        if operation.state == "indeterminate":
            return GatewayResult(GatewayReason.OPERATION_INDETERMINATE, operation.operation_id)
        return GatewayResult(GatewayReason.OPERATION_IN_PROGRESS, operation.operation_id)

    def _indeterminate(self, operation_id: str) -> GatewayResult:
        try:
            confirmed = self._repository.mark_indeterminate(operation_id, _utc(self._clock()))
        except Exception:
            confirmed = False
        return GatewayResult(
            GatewayReason.OPERATION_INDETERMINATE if confirmed else GatewayReason.GATEWAY_INTERNAL_FAILURE,
            operation_id,
        )

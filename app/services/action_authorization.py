"""Pure, fail-closed authorization policy for future authenticated actions."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Protocol

from app.auth_api_core import canonical_xonly_pubkey

POLICY_VERSION = "hodlxxi.action-policy.v1"
UNKNOWN_ACTION_AUDIT_VALUE = "unknown"
MAX_GRANTED_SCOPES = 1024


class ActionName(str, Enum):
    SELF_READ = "self_read"
    JOB_CREATE = "job_create"
    JOB_READ_SELF = "job_read_self"
    JOB_RECEIPT_READ_SELF = "job_receipt_read_self"
    ACTION_RECEIPT_READ_SELF = "action_receipt_read_self"
    COVENANT_DRAFT_CREATE = "covenant_draft_create"
    COVENANT_DRAFT_READ_SELF = "covenant_draft_read_self"


class IdentityClass(str, Enum):
    ANONYMOUS = "anonymous"
    GUEST = "guest"
    LIMITED = "limited"
    FULL = "full"
    OPERATOR = "operator"


class ReasonCode(str, Enum):
    ALLOWED = "allowed"
    MISSING_ACTOR = "missing_actor"
    INVALID_ACTOR = "invalid_actor"
    UNKNOWN_ACTION = "unknown_action"
    ENTITLEMENT_UNAVAILABLE = "entitlement_unavailable"
    ENTITLEMENT_ACTOR_MISMATCH = "entitlement_actor_mismatch"
    ANONYMOUS_DENIED = "anonymous_denied"
    GUEST_DENIED = "guest_denied"
    OPERATOR_CONTROL_PLANE_REQUIRED = "operator_control_plane_required"
    INVALID_SCOPE_SET = "invalid_scope_set"
    MISSING_SCOPE = "missing_scope"
    INSUFFICIENT_IDENTITY = "insufficient_identity"
    CURRENT_FULL_RELATION_REQUIRED = "current_full_relation_required"
    OWNERSHIP_REQUIRED = "ownership_required"
    OWNERSHIP_MISMATCH = "ownership_mismatch"
    STEP_UP_REQUIRED = "step_up_required"


@dataclass(frozen=True)
class EntitlementSnapshot:
    actor_pubkey: str
    identity_class: IdentityClass
    current_full_relation_satisfied: bool
    evidence_source: str
    observed_at: str | None = None


@dataclass(frozen=True)
class ActionRequest:
    actor_pubkey: str | None
    action: ActionName | str
    granted_scopes: object | None
    resource_owner_pubkey: str | None = None
    step_up_verified: bool = False


@dataclass(frozen=True)
class ActionRequirement:
    required_scope: str
    allowed_identities: frozenset[IdentityClass]
    ownership_required: bool = False
    current_full_relation_required: bool = False
    step_up_required: bool = False


@dataclass(frozen=True)
class ActionDecision:
    allowed: bool
    reason_code: ReasonCode
    actor_pubkey: str | None
    identity_class: IdentityClass | None
    action: str
    required_scope: str | None
    current_access_level: str | None
    resource_owner_pubkey: str | None
    ownership_required: bool
    step_up_required: bool
    policy_version: str = POLICY_VERSION

    def to_dict(self) -> dict[str, object]:
        """Return the stable, audit-safe decision representation."""
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code.value,
            "actor_pubkey": self.actor_pubkey,
            "identity_class": self.identity_class.value if self.identity_class else None,
            "action": self.action,
            "required_scope": self.required_scope,
            "current_access_level": self.current_access_level,
            "resource_owner_pubkey": self.resource_owner_pubkey,
            "ownership_required": self.ownership_required,
            "step_up_required": self.step_up_required,
            "policy_version": self.policy_version,
        }


class EntitlementResolver(Protocol):
    def resolve(self, actor_pubkey: str) -> EntitlementSnapshot:
        """Resolve current authorization evidence for a canonical actor key."""


_LIMITED_AND_FULL = frozenset({IdentityClass.LIMITED, IdentityClass.FULL})
_FULL_ONLY = frozenset({IdentityClass.FULL})

ACTION_REQUIREMENTS: Mapping[ActionName, ActionRequirement] = MappingProxyType(
    {
        ActionName.SELF_READ: ActionRequirement("self:read", _LIMITED_AND_FULL),
        ActionName.JOB_CREATE: ActionRequirement("job:create", _LIMITED_AND_FULL),
        ActionName.JOB_READ_SELF: ActionRequirement("job:read:self", _LIMITED_AND_FULL, ownership_required=True),
        ActionName.JOB_RECEIPT_READ_SELF: ActionRequirement(
            "job:receipt:read:self", _LIMITED_AND_FULL, ownership_required=True
        ),
        ActionName.ACTION_RECEIPT_READ_SELF: ActionRequirement(
            "action:receipt:read:self", _LIMITED_AND_FULL, ownership_required=True
        ),
        ActionName.COVENANT_DRAFT_CREATE: ActionRequirement(
            "covenant:draft:create",
            _FULL_ONLY,
            current_full_relation_required=True,
            step_up_required=True,
        ),
        ActionName.COVENANT_DRAFT_READ_SELF: ActionRequirement(
            "covenant:draft:read:self",
            _FULL_ONLY,
            ownership_required=True,
            current_full_relation_required=True,
        ),
    }
)


def _known_action(action: object) -> ActionName | None:
    try:
        return ActionName(action)
    except (TypeError, ValueError):
        return None


def _normalize_granted_scopes(scopes: object | None) -> frozenset[str] | None:
    """Return validated scopes, or None for a malformed collection."""
    if scopes is None:
        return frozenset()
    if isinstance(scopes, (str, bytes, bytearray, Mapping)):
        return None
    if not isinstance(scopes, Iterable):
        return None

    normalized: set[str] = set()
    try:
        for index, scope in enumerate(scopes):
            if index >= MAX_GRANTED_SCOPES:
                return None
            if not isinstance(scope, str) or not scope or scope.strip() != scope:
                return None
            normalized.add(scope)
    except Exception:
        return None
    return frozenset(normalized)


def _decision(
    *,
    reason: ReasonCode,
    action: str,
    requirement: ActionRequirement | None,
    actor: str | None = None,
    identity: IdentityClass | None = None,
    owner: str | None = None,
) -> ActionDecision:
    return ActionDecision(
        allowed=reason is ReasonCode.ALLOWED,
        reason_code=reason,
        actor_pubkey=actor,
        identity_class=identity,
        action=action,
        required_scope=requirement.required_scope if requirement else None,
        current_access_level=identity.value if identity else None,
        resource_owner_pubkey=owner,
        ownership_required=requirement.ownership_required if requirement else False,
        step_up_required=requirement.step_up_required if requirement else False,
    )


def _canonical_pubkey(value: object) -> str | None:
    try:
        return canonical_xonly_pubkey(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def authorize_action(
    request: ActionRequest,
    resolver: EntitlementResolver | None,
) -> ActionDecision:
    """Evaluate one action from current resolver evidence, failing closed."""
    action = _known_action(request.action)
    action_value = action.value if action is not None else UNKNOWN_ACTION_AUDIT_VALUE
    raw_actor = request.actor_pubkey
    if raw_actor is None or (isinstance(raw_actor, str) and not raw_actor.strip()):
        return _decision(reason=ReasonCode.MISSING_ACTOR, action=action_value, requirement=None)

    actor = _canonical_pubkey(raw_actor)
    if actor is None:
        return _decision(reason=ReasonCode.INVALID_ACTOR, action=action_value, requirement=None)

    if action is None:
        return _decision(reason=ReasonCode.UNKNOWN_ACTION, action=action_value, requirement=None, actor=actor)
    requirement = ACTION_REQUIREMENTS[action]

    if resolver is None:
        return _decision(
            reason=ReasonCode.ENTITLEMENT_UNAVAILABLE,
            action=action_value,
            requirement=requirement,
            actor=actor,
        )
    try:
        snapshot = resolver.resolve(actor)
        snapshot_actor = _canonical_pubkey(snapshot.actor_pubkey)
        identity = IdentityClass(snapshot.identity_class)
    except Exception:
        return _decision(
            reason=ReasonCode.ENTITLEMENT_UNAVAILABLE,
            action=action_value,
            requirement=requirement,
            actor=actor,
        )

    if snapshot_actor != actor:
        return _decision(
            reason=ReasonCode.ENTITLEMENT_ACTOR_MISMATCH,
            action=action_value,
            requirement=requirement,
            actor=actor,
            identity=identity,
        )
    if identity is IdentityClass.ANONYMOUS:
        return _decision(
            reason=ReasonCode.ANONYMOUS_DENIED,
            action=action_value,
            requirement=requirement,
            actor=actor,
            identity=identity,
        )
    if identity is IdentityClass.GUEST:
        return _decision(
            reason=ReasonCode.GUEST_DENIED,
            action=action_value,
            requirement=requirement,
            actor=actor,
            identity=identity,
        )
    if identity is IdentityClass.OPERATOR:
        return _decision(
            reason=ReasonCode.OPERATOR_CONTROL_PLANE_REQUIRED,
            action=action_value,
            requirement=requirement,
            actor=actor,
            identity=identity,
        )

    scopes = _normalize_granted_scopes(request.granted_scopes)
    if scopes is None:
        return _decision(
            reason=ReasonCode.INVALID_SCOPE_SET,
            action=action_value,
            requirement=requirement,
            actor=actor,
            identity=identity,
        )
    if requirement.required_scope not in scopes:
        return _decision(
            reason=ReasonCode.MISSING_SCOPE,
            action=action_value,
            requirement=requirement,
            actor=actor,
            identity=identity,
        )
    if identity not in requirement.allowed_identities:
        return _decision(
            reason=ReasonCode.INSUFFICIENT_IDENTITY,
            action=action_value,
            requirement=requirement,
            actor=actor,
            identity=identity,
        )
    if requirement.current_full_relation_required and snapshot.current_full_relation_satisfied is not True:
        return _decision(
            reason=ReasonCode.CURRENT_FULL_RELATION_REQUIRED,
            action=action_value,
            requirement=requirement,
            actor=actor,
            identity=identity,
        )

    owner = None
    if requirement.ownership_required:
        owner = _canonical_pubkey(request.resource_owner_pubkey)
        if owner is None:
            return _decision(
                reason=ReasonCode.OWNERSHIP_REQUIRED,
                action=action_value,
                requirement=requirement,
                actor=actor,
                identity=identity,
            )
        if owner != actor:
            return _decision(
                reason=ReasonCode.OWNERSHIP_MISMATCH,
                action=action_value,
                requirement=requirement,
                actor=actor,
                identity=identity,
                owner=owner,
            )
    if requirement.step_up_required and request.step_up_verified is not True:
        return _decision(
            reason=ReasonCode.STEP_UP_REQUIRED,
            action=action_value,
            requirement=requirement,
            actor=actor,
            identity=identity,
            owner=owner,
        )
    return _decision(
        reason=ReasonCode.ALLOWED,
        action=action_value,
        requirement=requirement,
        actor=actor,
        identity=identity,
        owner=owner,
    )

"""Current OAuth entitlement from persisted local user state only."""

from __future__ import annotations

from dataclasses import dataclass

from app.auth_api_core import canonical_xonly_pubkey
from app.db_storage import get_user_by_pubkey
from app.services.action_authorization import EntitlementSnapshot, IdentityClass


class EntitlementDenied(ValueError):
    """The subject has no current OAuth entitlement."""


class EntitlementUnavailable(RuntimeError):
    """Persisted entitlement state could not be evaluated."""


@dataclass(frozen=True)
class EntitlementDecision:
    subject: str
    identity_class: IdentityClass
    current_full_relation_satisfied: bool
    evidence_source: str


def resolve_current_entitlement(subject_pubkey: str) -> EntitlementDecision:
    try:
        subject = canonical_xonly_pubkey(subject_pubkey)
        if subject_pubkey != subject:
            raise EntitlementDenied("noncanonical subject")
    except (TypeError, ValueError) as exc:
        raise EntitlementDenied("invalid subject") from exc
    try:
        user = get_user_by_pubkey(subject)
    except Exception as exc:
        raise EntitlementUnavailable("persisted user state unavailable") from exc
    if not isinstance(user, dict) or user.get("pubkey") != subject or user.get("is_active") is not True:
        raise EntitlementDenied("no current entitlement")
    return EntitlementDecision(subject, IdentityClass.LIMITED, False, "active_persisted_user")


class CurrentEntitlementResolver:
    """Adapter for the existing PR 1 action policy resolver protocol."""

    def __init__(self, decision: EntitlementDecision):
        self._decision = decision

    def resolve(self, actor_pubkey: str) -> EntitlementSnapshot:
        if actor_pubkey != self._decision.subject:
            raise EntitlementUnavailable("entitlement actor mismatch")
        return EntitlementSnapshot(
            actor_pubkey=self._decision.subject,
            identity_class=self._decision.identity_class,
            current_full_relation_satisfied=self._decision.current_full_relation_satisfied,
            evidence_source=self._decision.evidence_source,
        )

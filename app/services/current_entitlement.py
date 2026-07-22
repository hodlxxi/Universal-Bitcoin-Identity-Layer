"""Current OAuth entitlement from persisted local user state only."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

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
    observed_at: str | None = None


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
            observed_at=self._decision.observed_at,
        )


class EvidenceBackedCurrentEntitlementResolver:
    """Dormant resolver that augments the active-user baseline with evidence."""

    def __init__(self, repository, *, clock=None, active_user_resolver=resolve_current_entitlement):
        if not callable(getattr(repository, "get_latest", None)) or not callable(active_user_resolver):
            raise ValueError("invalid dependency")
        self._repository = repository
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._active_user_resolver = active_user_resolver

    def __call__(self, subject_pubkey: str) -> EntitlementDecision:
        baseline = self._active_user_resolver(subject_pubkey)
        try:
            evidence = self._repository.get_latest(baseline.subject)
        except Exception as exc:
            raise EntitlementUnavailable("entitlement evidence unavailable") from exc
        if evidence is None:
            return baseline
        try:
            from app.services.current_entitlement_evidence import CurrentEntitlementEvidenceRecord

            evidence = CurrentEntitlementEvidenceRecord(**vars(evidence))
            now = self._clock()
            if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
                raise ValueError("invalid clock")
            now = now.astimezone(timezone.utc)
            if evidence.subject_pubkey != baseline.subject:
                raise ValueError("evidence subject mismatch")
            if evidence.observed_at > now + timedelta(seconds=60):
                raise ValueError("evidence exceeds future skew")
        except Exception as exc:
            raise EntitlementUnavailable("malformed entitlement evidence") from exc

        observed_at = evidence.observed_at.isoformat()
        if (
            evidence.revoked_at is not None
            or now < evidence.observed_at
            or now >= evidence.valid_until
            or evidence.identity_class is IdentityClass.LIMITED
        ):
            return EntitlementDecision(
                baseline.subject,
                IdentityClass.LIMITED,
                False,
                evidence.evidence_source,
                observed_at,
            )
        return EntitlementDecision(
            baseline.subject,
            IdentityClass.FULL,
            True,
            evidence.evidence_source,
            observed_at,
        )

    def resolve(self, actor_pubkey: str) -> EntitlementSnapshot:
        return CurrentEntitlementResolver(self(actor_pubkey)).resolve(actor_pubkey)

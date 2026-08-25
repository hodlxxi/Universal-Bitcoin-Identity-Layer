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


def require_active_persisted_user(subject_pubkey: str, user) -> str:
    """Return the canonical subject only when the persisted user is active."""

    try:
        subject = canonical_xonly_pubkey(subject_pubkey)
    except (TypeError, ValueError) as exc:
        raise EntitlementDenied("invalid subject") from exc
    if subject_pubkey != subject:
        raise EntitlementDenied("noncanonical subject")
    if not isinstance(user, dict) or user.get("pubkey") != subject or user.get("is_active") is not True:
        raise EntitlementDenied("no current entitlement")
    return subject


def evaluate_current_entitlement_evidence(evidence, *, subject: str, now: datetime):
    """Validate one latest record and return it with its canonical Full state."""

    from app.services.current_entitlement_evidence import CurrentEntitlementEvidenceRecord

    evidence = CurrentEntitlementEvidenceRecord(**vars(evidence))
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("invalid clock")
    now = now.astimezone(timezone.utc)
    if evidence.subject_pubkey != subject:
        raise ValueError("evidence subject mismatch")
    if evidence.observed_at > now + timedelta(seconds=60):
        raise ValueError("evidence exceeds future skew")
    current_full = (
        evidence.revoked_at is None
        and evidence.observed_at <= now < evidence.valid_until
        and evidence.identity_class is IdentityClass.FULL
    )
    return evidence, current_full


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
    require_active_persisted_user(subject, user)
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
            now = self._clock()
            evidence, current_full = evaluate_current_entitlement_evidence(evidence, subject=baseline.subject, now=now)
        except Exception as exc:
            raise EntitlementUnavailable("malformed entitlement evidence") from exc

        observed_at = evidence.observed_at.isoformat()
        if not current_full:
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


def resolve_runtime_current_entitlement(
    subject_pubkey: str,
    *,
    repository=None,
    session_factory=None,
    clock=None,
    active_user_resolver=resolve_current_entitlement,
) -> EntitlementDecision:
    """Resolve current entitlement through the canonical runtime database seam."""

    if repository is not None and session_factory is not None:
        raise ValueError("provide repository or session factory, not both")
    if repository is None:
        if session_factory is None:
            from app.database import get_session

            session_factory = get_session
        from app.services.current_entitlement_evidence_storage import (
            SqlAlchemyCurrentEntitlementEvidenceRepository,
        )

        repository = SqlAlchemyCurrentEntitlementEvidenceRepository(session_factory)
    return EvidenceBackedCurrentEntitlementResolver(
        repository,
        clock=clock,
        active_user_resolver=active_user_resolver,
    )(subject_pubkey)

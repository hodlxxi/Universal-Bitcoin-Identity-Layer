"""Authoritative, complete current-Full population snapshot boundary."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from app.services.current_entitlement import evaluate_current_entitlement_evidence
from app.services.current_entitlement_evidence_storage import CompleteLatestEntitlementPopulation

SCHEMA = "hodlxxi.full_entitlement_snapshot.v1"
SOURCE = "hodlxxi-crt"
VERSION = 1
MAX_SUBJECTS = 4096
SNAPSHOT_LIFETIME = timedelta(seconds=300)
UNAVAILABLE_MESSAGE = "full entitlement snapshot unavailable"


class FullEntitlementSnapshotUnavailable(RuntimeError):
    def __init__(self):
        super().__init__(UNAVAILABLE_MESSAGE)


class FullEntitlementSnapshotReader:
    """Build snapshots only from a complete authoritative repository read."""

    def __init__(self, repository, *, clock=None):
        if not callable(getattr(repository, "get_latest_population", None)):
            raise FullEntitlementSnapshotUnavailable() from None
        self._repository = repository
        self._clock = (lambda: datetime.now(timezone.utc)) if clock is None else clock

    def current_snapshot(self, *, maximum=MAX_SUBJECTS):
        try:
            if type(maximum) is not int or not 0 <= maximum <= MAX_SUBJECTS:
                raise ValueError
            now = self._clock()
            if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
                raise ValueError
            now = now.astimezone(timezone.utc)
            population = self._repository.get_latest_population(maximum)
            if (
                type(population) is not CompleteLatestEntitlementPopulation
                or population.complete is not True
                or population.maximum != maximum
            ):
                raise ValueError
            records = population.records

            entitlements = []
            deadlines = []
            previous = None
            evidence_ids = set()
            record_subjects = set()
            for candidate in records:
                subject = getattr(candidate, "subject_pubkey", None)
                if (
                    type(subject) is not str
                    or previous is not None
                    and subject <= previous
                    or getattr(candidate, "evidence_id", None) in evidence_ids
                ):
                    raise ValueError
                evidence, current_full = evaluate_current_entitlement_evidence(candidate, subject=subject, now=now)
                if evidence.observed_at > now:
                    raise ValueError
                previous = subject
                evidence_ids.add(evidence.evidence_id)
                record_subjects.add(subject)
                if current_full:
                    deadlines.append(evidence.valid_until)
                    entitlements.append(
                        {
                            "subject": subject,
                            "status": "full",
                            "validFrom": int(evidence.observed_at.timestamp() * 1000),
                            "expiresAt": int(evidence.valid_until.timestamp() * 1000),
                            "revoked": False,
                        }
                    )
            expires = min(now + SNAPSHOT_LIFETIME, *deadlines) if deadlines else now + SNAPSHOT_LIFETIME
            if expires <= now:
                raise ValueError
            issued_at = int(now.timestamp() * 1000)
            expires_at = int(expires.timestamp() * 1000)
            if expires_at <= issued_at:
                raise ValueError
            evidence = {
                "complete": True,
                "entitlements": entitlements,
                "expiresAt": expires_at,
                "issuedAt": issued_at,
            }
            canonical = json.dumps(evidence, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            snapshot_id = "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest()
            return {
                "schema": SCHEMA,
                "version": VERSION,
                "source": SOURCE,
                "snapshotId": snapshot_id,
                "complete": True,
                "issuedAt": issued_at,
                "expiresAt": expires_at,
                "entitlements": [{"snapshotId": snapshot_id, **entitlement} for entitlement in entitlements],
            }
        except Exception:
            raise FullEntitlementSnapshotUnavailable() from None

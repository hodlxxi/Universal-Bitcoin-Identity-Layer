"""Task2B test-only helper from verified Task2 sources."""

from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.models import User, CurrentEntitlementEvidence
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CONTRACT_VERSION
from tests.unit.test_automatic_sponsored_import_v1 import ALICE

NOW = datetime(2026, 11, 13, 19, 10, 0, tzinfo=timezone.utc)


def _seed_full(engine, key, *, full=True):
    xonly = key[2:]
    with Session(engine) as session:
        with session.begin():
            session.add(User(pubkey=xonly, is_active=True, metadata_json={}))
            session.add(
                CurrentEntitlementEvidence(
                    evidence_id=(
                        "00000000-0000-4000-8000-000000000071"
                        if key == ALICE
                        else "00000000-0000-4000-8000-000000000072"
                    ),
                    contract_version=CONTRACT_VERSION,
                    subject_pubkey=xonly,
                    identity_class=IdentityClass.FULL.value if full else IdentityClass.LIMITED.value,
                    current_full_relation_satisfied=full,
                    evidence_source="disposable_integration_fixture",
                    evidence_version="v1",
                    source_evidence_sha256="f" * 64,
                    observed_at=NOW - timedelta(seconds=20),
                    valid_until=NOW + timedelta(seconds=300),
                    created_at=NOW - timedelta(seconds=1),
                    revoked_at=None,
                )
            )

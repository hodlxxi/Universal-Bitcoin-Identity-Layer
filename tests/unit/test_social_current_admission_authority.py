from __future__ import annotations

import ast
import inspect
from dataclasses import fields
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base
from app.services import social_current_admission_authority as authority
from app.services import social_messaging_device_admission_contract as admission

ROOT = Path(__file__).parents[2]
SOURCE = ROOT / "app/services/social_current_admission_authority.py"
ERROR = "^social messaging device admission unavailable$"


def test_sqlite_and_inactive_or_replaced_transactions_are_never_authority():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    with factory() as session:
        with pytest.raises(admission.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            authority.SqlAlchemyTransactionBoundAdmissionAuthority(
                session,
                device_issuance_id="11" * 32,
                device_client_id="social-viewer-v1",
                oauth_issuer="https://identity.example",
            )
        transaction = session.begin()
        with pytest.raises(admission.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            authority.SqlAlchemyTransactionBoundAdmissionAuthority(
                session,
                device_issuance_id="11" * 32,
                device_client_id="social-viewer-v1",
                oauth_issuer="https://identity.example",
            )
        transaction.rollback()
    Base.metadata.drop_all(engine)


@pytest.mark.parametrize(
    "kwargs",
    (
        {"device_issuance_id": "x" * 64},
        {"device_client_id": "not allowed space"},
        {"oauth_issuer": "http://identity.example"},
        {"approver_oauth_session_id": "22" * 32},
        {"approver_client_id": "social-viewer-v1"},
    ),
)
def test_trusted_selector_configuration_fails_closed_before_storage(kwargs):
    engine = create_engine("sqlite:///:memory:")
    factory = sessionmaker(engine)
    values = {
        "device_issuance_id": "11" * 32,
        "device_client_id": "social-viewer-v1",
        "oauth_issuer": "https://identity.example",
    }
    values.update(kwargs)
    with (
        factory.begin() as session,
        pytest.raises(admission.SocialMessagingDeviceAdmissionUnavailable, match=ERROR),
    ):
        authority.SqlAlchemyTransactionBoundAdmissionAuthority(session, **values)


def test_adapter_implements_only_the_frozen_current_authority_port():
    signature = inspect.signature(authority.SqlAlchemyTransactionBoundAdmissionAuthority.lock_current_authority)
    assert tuple(signature.parameters) == ("self", "context", "observed_at")
    assert signature.return_annotation in (
        "admission.CurrentAdmissionAuthorityV1",
        admission.CurrentAdmissionAuthorityV1,
    )
    assert [item.name for item in fields(admission.CurrentAdmissionAuthorityV1)] == [
        "context_digest",
        "authority_epoch",
        "locked_deadline_ms",
        "full_proof_id",
        "approver_full_proof_id",
    ]


def test_source_has_explicit_time_and_no_transaction_or_effect_ownership():
    source = SOURCE.read_text(encoding="utf-8")
    ast.parse(source)
    for forbidden in (
        "datetime.now(",
        "time.time(",
        "NOW()",
        ".commit(",
        ".rollback(",
        ".close(",
        "sessionmaker(",
        "create_engine(",
        "redis",
        "challenge_store",
        "AdmissionReceiptV1(",
        "PreparedAdmissionEffectV1(",
        "authorized=True",
        "admitted=True",
        "operationExecuted=True",
    ):
        assert forbidden not in source


def test_global_lock_order_is_explicit_and_parent_precedes_child_token():
    source = SOURCE.read_text(encoding="utf-8")
    assert "Global lock order:" in source
    assert source.index("Current-Full subject advisory lock") < source.index("OAuth clients")
    assert source.index("OAuth clients") < source.index("Exact current X25519")
    assert source.index("Exact current X25519") < source.index("Ed25519 pair advisory lock")
    method = inspect.getsource(authority.SqlAlchemyTransactionBoundAdmissionAuthority._lock_non_ed25519_authority)
    assert method.index("for token_id in sorted(generation_probes)") < method.index(
        "for token_id in sorted(generations)"
    )
    assert method.index("for token_id in sorted(generations)") < method.index("social_token = self._lock_token")
    assert method.index("social_token = self._lock_token") < method.index("issuance = self._lock_issuance")


@pytest.mark.parametrize("value", (True, -1, 9_007_199_254_740_992, "1000"))
def test_explicit_epoch_millisecond_input_is_closed(value):
    with pytest.raises(admission.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        authority._observed(value)


def test_exact_epoch_millisecond_input_is_not_rounded():
    raw, exact, whole = authority._observed(1_234)
    assert raw == 1_234
    assert authority._epoch_milliseconds(exact) == 1_234
    assert authority._epoch_milliseconds(whole) == 1_000

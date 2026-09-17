"""Read-only transaction/owner rejection tests; durable rehearsal is separate."""

from dataclasses import fields, replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.services.social_messaging_mobile_authorization_storage import (
    _REQUIRED_TRIGGERS,
    MobileOperationRow,
    MobileRequestRow,
)
from app.services.social_messaging_mobile_routing import AcceptedMobileBindingAuthorizationVerifier
from app.services.social_messaging_mobile_routing_storage import SqlAlchemyAcceptedMobileBindingEvidenceReader
from app.services.social_messaging_recipient_routing import RecipientMessagingRoutingUnavailable
from tests.unit.test_social_messaging_mobile_routing import ERROR, NOW, binding_for, record_for


def session_for(record=None):
    record = record or record_for()
    operation = SimpleNamespace(**{f.name: getattr(record, f.name) for f in fields(record)}, status="accepted")
    request = SimpleNamespace(request_id=record.request_id, owner="mobile", digest=record.authorization_digest)
    session = Mock(is_active=True, new=(), dirty=(), deleted=())
    session.in_transaction.return_value = True
    session.get_bind.return_value.dialect.name = "postgresql"
    session.get.side_effect = lambda model, _id, **kw: operation if model is MobileOperationRow else request
    results = [Mock(), Mock(), Mock(), Mock(), Mock()]
    results[0].scalar_one.return_value = "read committed"
    results[1].scalar_one.return_value = len(_REQUIRED_TRIGGERS)
    results[2].scalars.return_value.all.return_value = [record]
    results[3].all.return_value = []
    results[4].all.return_value = [(record.request_id,)]
    session.execute.side_effect = results
    return session, operation, request, results


def test_reader_and_verifier_connect_without_transaction_completion_or_writes():
    record = record_for()
    session, _, _, _ = session_for(record)
    reader = SqlAlchemyAcceptedMobileBindingEvidenceReader(session, enabled=True)
    proof = AcceptedMobileBindingAuthorizationVerifier(reader, enabled=True).verify(binding_for(record), now=NOW)
    assert proof.binding_id == record.binding_id
    for method in (session.flush, session.commit, session.rollback, session.close, session.add, session.begin):
        method.assert_not_called()
    assert session.get.call_args_list[1].args[0] is MobileRequestRow
    for call in session.execute.call_args_list[2:4]:
        assert call.args[0]._limit_clause.value == 2
        assert call.args[0].get_execution_options()["autoflush"] is False
    for call in session.get.call_args_list:
        assert call.kwargs["execution_options"]["autoflush"] is False


def test_default_disabled_reader_never_uses_session():
    session = Mock()
    with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
        SqlAlchemyAcceptedMobileBindingEvidenceReader(session).accepted_for_binding(record_for().binding_id, maximum=2)
    assert session.mock_calls == []


@pytest.mark.parametrize(
    "failure",
    [
        "inactive",
        "no-transaction",
        "dialect",
        "isolation",
        "guards",
        "new",
        "dirty",
        "deleted",
        "missing-operation",
        "pending",
        "wrong-operation",
        "operation-request",
        "operation-digest",
        "missing-request",
        "nostr-request",
        "request-digest",
        "missing-owner",
        "duplicate-owner",
        "wrong-owner",
        "nostr-evidence",
        "duplicate-receipt",
        "receipt-binding",
    ],
)
def test_incomplete_or_conflicting_persistent_ownership_fails_closed(failure):
    record = record_for()
    session, operation, request, results = session_for(record)
    if failure == "inactive":
        session.is_active = False
    elif failure == "no-transaction":
        session.in_transaction.return_value = False
    elif failure == "dialect":
        session.get_bind.return_value.dialect.name = "sqlite"
    elif failure == "isolation":
        results[0].scalar_one.return_value = "repeatable read"
    elif failure == "guards":
        results[1].scalar_one.return_value = 0
    elif failure in ("new", "dirty", "deleted"):
        setattr(session, failure, (object(),))
    elif failure == "missing-operation":
        session.get.side_effect = lambda *a, **kw: None
    elif failure == "pending":
        operation.status = "approval-claimed"
    elif failure == "wrong-operation":
        operation.operation_id = "aa" * 32
    elif failure == "operation-request":
        operation.request_id = "aa" * 32
    elif failure == "operation-digest":
        operation.authorization_digest = "aa" * 32
    elif failure == "missing-request":
        session.get.side_effect = lambda model, *a, **kw: operation if model is MobileOperationRow else None
    elif failure == "nostr-request":
        request.owner = "nostr"
    elif failure == "request-digest":
        request.digest = "aa" * 32
    elif failure == "missing-owner":
        results[4].all.return_value = []
    elif failure == "duplicate-owner":
        results[4].all.return_value *= 2
    elif failure == "wrong-owner":
        results[4].all.return_value = [("aa" * 32,)]
    elif failure == "nostr-evidence":
        results[3].all.return_value = [(record.binding_id,)]
    elif failure == "duplicate-receipt":
        results[2].scalars.return_value.all.return_value *= 2
    elif failure == "receipt-binding":
        results[2].scalars.return_value.all.return_value = [replace(record, binding_id="aa" * 32)]
    with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
        SqlAlchemyAcceptedMobileBindingEvidenceReader(session, enabled=True).accepted_for_binding(
            record.binding_id, maximum=2
        )
    session.commit.assert_not_called()
    session.flush.assert_not_called()


@pytest.mark.parametrize("maximum", [True, 1, 3, None])
def test_query_bound_is_exact(maximum):
    with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
        SqlAlchemyAcceptedMobileBindingEvidenceReader(Mock(), enabled=True).accepted_for_binding(
            record_for().binding_id, maximum=maximum
        )

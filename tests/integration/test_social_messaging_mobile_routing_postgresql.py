"""Existing guarded disposable PostgreSQL owner -> mobile routing verifier."""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.services.social_messaging_device_storage import (
    SocialMessagingDeviceBindingRow,
    SqlAlchemyTransactionBoundSocialMessagingDeviceStorage,
)
from app.services.social_messaging_mobile_routing import AcceptedMobileBindingAuthorizationVerifier
from app.services.social_messaging_mobile_routing_storage import SqlAlchemyAcceptedMobileBindingEvidenceReader
from app.services.social_messaging_recipient_routing import RecipientMessagingRoutingUnavailable
from tests.integration.test_social_messaging_mobile_authorization_storage_postgresql import NOW, accept
from tests.integration.test_social_messaging_mobile_authorization_storage_postgresql import (
    mobile_factory as mobile_factory,
)
from tests.integration.test_social_messaging_mobile_authorization_storage_postgresql import (
    postgres_factory as postgres_factory,
)
from tests.integration.test_social_messaging_mobile_authorization_storage_postgresql import prepare, protocol
from tests.integration.test_social_messaging_mobile_authorization_storage_postgresql import seed as seed
from tests.unit.test_social_messaging_mobile_routing import ERROR


def current_binding(factory):
    with factory[1].begin() as session:
        binding_id = session.execute(select(SocialMessagingDeviceBindingRow.binding_id)).scalar_one()
        return SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(session).binding_for_id(binding_id)


def verify(factory, binding):
    with factory[1].begin() as session:
        reader = SqlAlchemyAcceptedMobileBindingEvidenceReader(session, enabled=True)
        return AcceptedMobileBindingAuthorizationVerifier(reader, enabled=True).verify(
            binding, now=datetime.fromtimestamp(NOW + 301, timezone.utc)
        )


@pytest.mark.parametrize("method", [protocol.LEGACY, protocol.QR])
def test_real_committed_acceptance_survives_reader_recreation(method, mobile_factory):
    prepare(mobile_factory, method)
    result = accept(mobile_factory, method)
    binding = current_binding(mobile_factory)
    proof = verify(mobile_factory, binding)
    mobile_factory[0].dispose()
    assert verify(mobile_factory, binding) == proof
    assert proof.binding_id == protocol.parse_json(result)["bindingId"]
    assert proof.proof_id.startswith("hodlxxi-mobile-binding-authorization-v1-sha256:")
    # No second signature, command mutation, or expiry renewal.
    assert accept(mobile_factory, method, now=NOW + 301) == result


@pytest.mark.parametrize("method", [protocol.LEGACY, protocol.QR])
def test_pending_operation_has_no_routing_evidence(method, mobile_factory):
    from tests.unit.test_social_messaging_mobile_routing import binding_for, record_for

    prepare(mobile_factory, method)
    with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
        verify(mobile_factory, binding_for(record_for(method=method)))


def test_reader_never_flushes_the_callers_session(mobile_factory):
    prepare(mobile_factory, protocol.LEGACY)
    accept(mobile_factory, protocol.LEGACY)
    binding = current_binding(mobile_factory)
    with mobile_factory[1].begin() as session:
        with patch.object(session, "flush", side_effect=AssertionError("reader must not flush")):
            state = SqlAlchemyAcceptedMobileBindingEvidenceReader(session, enabled=True).accepted_for_binding(
                binding.binding_id, maximum=2
            )
        assert len(state.records) == 1

"""Dormant read-only adapter over the existing mobile acceptance owner.

Caller owns the active PostgreSQL READ COMMITTED transaction. No session factory,
environment fallback, transaction completion, migration or runtime wiring.
"""

from sqlalchemy import select, text

from app.services.social_messaging_device_binding_authorization_storage import (
    SocialMessagingDeviceBindingAuthorizationEvidenceRow,
)
from app.services.social_messaging_mobile_authorization import _hex
from app.services.social_messaging_mobile_authorization_storage import (
    _REQUIRED_TRIGGERS,
    MobileAcceptanceRow,
    MobileOperationRow,
    MobileRequestRow,
)
from app.services.social_messaging_mobile_routing import (
    EVIDENCE_SCHEMA,
    AcceptedMobileBindingEvidence,
    MobileBindingEvidenceState,
)
from app.services.social_messaging_recipient_routing import RecipientMessagingRoutingUnavailable


class SqlAlchemyAcceptedMobileBindingEvidenceReader:
    def __init__(self, session, *, enabled=False):
        if type(enabled) is not bool:
            raise ValueError("invalid mobile routing dependency")
        self._session = session
        self._enabled = enabled

    def accepted_for_binding(self, binding_id, *, maximum):
        try:
            if not self._enabled or type(maximum) is not int or maximum != 2:
                raise ValueError
            _hex(binding_id)
            session = self._session
            if not session.is_active or not session.in_transaction() or session.get_bind().dialect.name != "postgresql":
                raise ValueError
            if session.new or session.dirty or session.deleted:
                raise ValueError
            if session.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed":
                raise ValueError
            pairs = ",".join(f"(to_regclass('{table}'), '{trigger}')" for table, trigger in _REQUIRED_TRIGGERS)
            installed = session.execute(
                text(
                    "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal "
                    "AND tgenabled = 'O' AND (tgrelid, tgname) IN (" + pairs + ")"
                )
            ).scalar_one()
            if installed != len(_REQUIRED_TRIGGERS):
                raise ValueError
            # No locks or writes: these rows are immutable. The routing owner
            # must separately lock/recheck mutable Full and current binding state.
            receipts = (
                session.execute(
                    select(MobileAcceptanceRow)
                    .where(MobileAcceptanceRow.binding_id == binding_id)
                    .limit(maximum)
                    .execution_options(populate_existing=True, autoflush=False)
                )
                .scalars()
                .all()
            )
            nostr = session.execute(
                select(SocialMessagingDeviceBindingAuthorizationEvidenceRow.binding_id)
                .where(SocialMessagingDeviceBindingAuthorizationEvidenceRow.binding_id == binding_id)
                .limit(maximum)
                .execution_options(autoflush=False)
            ).all()
            if nostr or len(receipts) > 1:
                raise ValueError
            records = []
            for receipt in receipts:
                operation = session.get(
                    MobileOperationRow,
                    receipt.operation_id,
                    populate_existing=True,
                    execution_options={"autoflush": False},
                )
                request = session.get(
                    MobileRequestRow, receipt.request_id, populate_existing=True, execution_options={"autoflush": False}
                )
                owner = session.execute(
                    text(
                        "SELECT request_id FROM social_messaging_device_authorization_binding_owners "
                        "WHERE binding_id = :binding_id LIMIT 2"
                    ),
                    {"binding_id": binding_id},
                ).all()
                if (
                    operation is None
                    or operation.status != "accepted"
                    or operation.operation_id != receipt.operation_id
                    or operation.request_id != receipt.request_id
                    or operation.authorization_digest != receipt.authorization_digest
                    or receipt.binding_id != binding_id
                    or request is None
                    or request.owner != "mobile"
                    or request.request_id != receipt.request_id
                    or request.digest != receipt.authorization_digest
                    or len(owner) != 1
                    or owner[0][0] != receipt.request_id
                ):
                    raise ValueError
                records.append(
                    AcceptedMobileBindingEvidence(
                        operation.operation_id,
                        operation.method,
                        operation.subject,
                        operation.context_id,
                        operation.created_at,
                        operation.expires_at,
                        operation.revision,
                        operation.secret_commitment,
                        operation.source,
                        receipt.proof_source,
                        receipt.result_source,
                        receipt.request_id,
                        receipt.authorization_digest,
                        receipt.binding_id,
                        receipt.accepted_at,
                    )
                )
            return MobileBindingEvidenceState(EVIDENCE_SCHEMA, 1, binding_id, True, False, tuple(records))
        except Exception:
            raise RecipientMessagingRoutingUnavailable() from None

"""Dormant current-handle candidate comparison for recipient self-read.

This internal adapter accepts one exact canonical verification-input wire and
one already-active caller-owned PostgreSQL READ COMMITTED transaction.  It
establishes current admission authority itself, then locks the configured
ACTIVE alias namespace and one immutable historical handle-owner row in the
existing admission-to-routing lock order.  After every possible wait it
rechecks namespace and current binding/admission authority before comparing
the historical owner with the exact current binding.

The returned value is deliberately non-authorizing.  It grants no self-read,
does not select messages, and never returns ciphertext.  There is no handle
derivation here: in particular, the adapter never substitutes the recipient
as a viewer to derive a handle.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import NoReturn, cast

from sqlalchemy import text
from sqlalchemy.engine import Connection, NestedTransaction, RootTransaction
from sqlalchemy.orm import Session

from app.services import social_current_admission_authority as current_authority
from app.services import social_messaging_active_alias_namespace_storage as active_namespace
from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_recipient_routing_storage as routing_storage
from app.services.social_messaging_device_contract import MessagingDeviceBinding
from app.services.social_messaging_device_storage import SqlAlchemyTransactionBoundSocialMessagingDeviceStorage

RUNTIME_ENABLED = False
CANDIDATE_COMPARISON = "exact_current_candidate_match"
AUTHORIZATION = "not_granted"
RECIPIENT_SELF_READ = "not_granted"
CIPHERTEXT = "not_returned"


class SocialMessagingCurrentHandleCandidateUnavailable(RuntimeError):
    """The current-handle candidate comparison could not be established."""

    def __init__(self) -> None:
        super().__init__("social messaging current handle candidate unavailable")


def _deny() -> NoReturn:
    raise SocialMessagingCurrentHandleCandidateUnavailable()


@dataclass(frozen=True, slots=True)
class RecipientSelfReadCurrentHandleCandidateV1:
    """Internal comparison result with no authorization or read capability."""

    requested_handle: str
    alias_version: int
    context_digest: str
    comparison: str = field(default=CANDIDATE_COMPARISON, init=False)
    authorization: str = field(default=AUTHORIZATION, init=False)
    recipient_self_read: str = field(default=RECIPIENT_SELF_READ, init=False)
    ciphertext: str = field(default=CIPHERTEXT, init=False)


class SqlAlchemyTransactionBoundCurrentHandleCandidate:
    """Compare one requested self-read handle with locked current authority."""

    def __init__(
        self,
        session: Session,
        *,
        device_issuance_id: object,
        device_client_id: object,
        oauth_issuer: object,
        configured_alias_secret: bytes,
        configured_alias_version: int,
    ) -> None:
        self._session = session
        self._failed = False
        self._connection: Connection | None = None
        self._database_transaction: RootTransaction | None = None
        self._database_nested_transaction: NestedTransaction | None = None
        try:
            self._transaction = session.get_transaction()
            self._nested_transaction = session.get_nested_transaction()
            self._check_transaction()
            self._authority = current_authority.SqlAlchemyTransactionBoundAdmissionAuthority(
                session,
                device_issuance_id=device_issuance_id,
                device_client_id=device_client_id,
                oauth_issuer=oauth_issuer,
            )
            self._namespace = active_namespace.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
                session,
                configured_alias_secret=configured_alias_secret,
                configured_alias_version=configured_alias_version,
            )
            self._history = routing_storage.SqlAlchemyRecipientRoutingRepository(session)
            self._bindings = SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(session)
            return
        except Exception:
            self._failed = True
        _deny()

    def _check_transaction(self) -> Connection:
        try:
            session = self._session
            if (
                self._failed
                or self._transaction is None
                or not self._transaction.is_active
                or session.get_transaction() is not self._transaction
                or session.get_nested_transaction() is not self._nested_transaction
                or session.in_transaction() is not True
                or not session.is_active
                or session.new
                or session.dirty
                or session.deleted
                or session.get_bind().dialect.name != "postgresql"
            ):
                _deny()
            connection = session.connection()
            if (
                connection.closed
                or connection.invalidated
                or not connection.in_transaction()
                or getattr(connection.connection.dbapi_connection, "autocommit", None) is not False
            ):
                _deny()
            if self._connection is None:
                self._connection = connection
                self._database_transaction = connection.get_transaction()
                self._database_nested_transaction = connection.get_nested_transaction()
            if (
                connection is not self._connection
                or self._database_transaction is None
                or connection.get_transaction() is not self._database_transaction
                or connection.get_nested_transaction() is not self._database_nested_transaction
                or not self._database_transaction.is_active
            ):
                _deny()
            if connection.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed":
                _deny()
            return connection
        except SocialMessagingCurrentHandleCandidateUnavailable:
            raise
        except Exception:
            pass
        _deny()

    @staticmethod
    def _validate_authority(
        value: object,
        context: admission.VerificationContextV1,
        *,
        observed_at: int,
    ) -> admission.CurrentAdmissionAuthorityV1:
        if type(value) is not admission.CurrentAdmissionAuthorityV1:
            _deny()
        authority = cast(admission.CurrentAdmissionAuthorityV1, value)
        if (
            not hmac.compare_digest(
                authority.context_digest,
                admission.verification_context_digest_v1(context.wire),
            )
            or authority.authority_epoch != context.authority_epoch
            or type(authority.locked_deadline_ms) is not int
            or authority.locked_deadline_ms <= observed_at
            or not hmac.compare_digest(authority.full_proof_id, context.full_proof_id)
            or authority.approver_full_proof_id is not None
        ):
            _deny()
        return authority

    def check_recipient_self_read_candidate(
        self,
        verification_input_wire: object,
        *,
        observed_at: object,
    ) -> RecipientSelfReadCurrentHandleCandidateV1:
        """Return only a non-authorizing exact-match candidate record."""

        try:
            self._check_transaction()
            input_value = admission.parse_verification_input_v1(verification_input_wire)
            if input_value.operation != "recipient-self-read" or input_value.actual_request_wire is None:
                _deny()
            request = admission._parse_request(input_value.actual_request_wire)
            if request["operation"] != "recipient-self-read":
                _deny()
            requested_handle = cast(str, request["recipientHandle"])
            observed_ms, observed, _observed_second = current_authority._observed(observed_at)
            context = input_value.context

            before = self._validate_authority(
                self._authority.lock_current_authority(context, observed_at=observed_ms),
                context,
                observed_at=observed_ms,
            )
            namespace = self._namespace.lock_configured_active_namespace()
            owner = self._history.lock_historical_handle_owner(requested_handle)
            if owner is None or type(owner) is not routing_storage._RecipientHandleOwnerV1:
                _deny()

            after_owner_namespace = self._namespace.lock_configured_active_namespace()
            if after_owner_namespace != namespace:
                _deny()

            binding = self._bindings.binding_for_id(context.binding_id)
            if type(binding) is not MessagingDeviceBinding:
                _deny()
            current_binding = cast(MessagingDeviceBinding, binding)
            if (
                current_binding.subject != context.subject
                or current_binding.device_id != context.device_id
                or current_binding.binding_id != context.binding_id
                or current_binding.binding_version != context.binding_version
                or current_binding.active is not True
                or current_binding.operation not in {"register", "rotate"}
                or not current_binding.valid_from <= observed < current_binding.expires_at
                or owner.device_handle != requested_handle
                or owner.alias_version != namespace.alias_version
                or owner.recipient_subject != current_binding.subject
                or owner.device_id != current_binding.device_id
                or owner.binding_id != current_binding.binding_id
                or owner.binding_version != current_binding.binding_version
            ):
                _deny()

            after = self._validate_authority(
                self._authority.lock_current_authority(context, observed_at=observed_ms),
                context,
                observed_at=observed_ms,
            )
            final_namespace = self._namespace.lock_configured_active_namespace()
            if after != before or final_namespace != namespace:
                _deny()
            self._check_transaction()
            return RecipientSelfReadCurrentHandleCandidateV1(
                requested_handle=requested_handle,
                alias_version=namespace.alias_version,
                context_digest=after.context_digest,
            )
        except SocialMessagingCurrentHandleCandidateUnavailable:
            self._failed = True
            raise
        except Exception:
            self._failed = True
        _deny()


__all__ = [
    "AUTHORIZATION",
    "CANDIDATE_COMPARISON",
    "CIPHERTEXT",
    "RECIPIENT_SELF_READ",
    "RUNTIME_ENABLED",
    "RecipientSelfReadCurrentHandleCandidateV1",
    "SocialMessagingCurrentHandleCandidateUnavailable",
    "SqlAlchemyTransactionBoundCurrentHandleCandidate",
]

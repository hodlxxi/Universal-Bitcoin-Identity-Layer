"""Transaction-bound current authority for dormant Social device admission.

The caller supplies one already-active PostgreSQL transaction plus selectors
obtained from authenticated server-side presentations.  This adapter only
locks and compares current authority.  It never owns transaction lifecycle,
challenge state, admission effects, receipts, or final admission.

Global lock order:

1. Current-Full subject advisory lock, User row, entitlement evidence.
2. OAuth clients, Social issuer, exact OAuth generations, browser generations,
   parent/approver OAuth tokens and Sessions, then the child Social token and
   immutable issuance.
3. Exact current X25519 binding row.
4. Ed25519 pair advisory lock, chain row, then immutable event history.

The Full/User boundary precedes every potentially competing X25519 or OAuth
writer.  Parent OAuth tokens precede the child Social token to match the
durable invalidation-trigger direction.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import NoReturn
from urllib.parse import urlsplit

from sqlalchemy import select, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from app.models import OAuthBrowserGeneration, OAuthClient, OAuthSessionGeneration, OAuthToken
from app.models import Session as DurableSession
from app.models import User
from app.services import social_admission_session_binding as session_binding
from app.services import social_messaging_device_admission_contract as admission
from app.services.current_entitlement_evidence_storage import SqlAlchemyTransactionBoundCurrentFullVerifier
from app.services.oauth_bearer_validation import TOKEN_CONTRACT
from app.services.oauth_scope_policy import (
    SCOPE_POLICY_VERSION,
    client_allowed_scopes,
    parse_scopes,
    validate_client_scopes,
)
from app.services.oauth_session_lifecycle import _TRIGGERS as OAUTH_SESSION_GUARDS
from app.services.social_device_ed25519_association_storage import SqlAlchemyEd25519AssociationStore
from app.services.social_messaging_device_proof_profile import MAX_SAFE_INTEGER, x25519_public_key_commitment_v1
from app.services.social_messaging_device_storage import SqlAlchemyTransactionBoundSocialMessagingDeviceStorage
from app.services.social_session_issuance import _GUARDS as SOCIAL_SESSION_GUARDS
from app.services.social_session_issuance import SCOPE as SOCIAL_SESSION_SCOPE
from app.services.social_session_issuance import SocialSessionIssuance, SocialSessionIssuer

_HEX32 = re.compile(r"[0-9a-f]{32}\Z").fullmatch
_HEX64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_CONFIGURED_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}\Z").fullmatch
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _deny() -> NoReturn:
    raise admission.SocialMessagingDeviceAdmissionUnavailable()


def _hex32(value: object) -> str:
    if type(value) is not str or _HEX32(value) is None:
        _deny()
    return value


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX64(value) is None:
        _deny()
    return value


def _configured_id(value: object) -> str:
    if type(value) is not str or _CONFIGURED_ID(value) is None:
        _deny()
    return value


def _issuer(value: object) -> str:
    try:
        if type(value) is not str or not value.isascii() or not 1 <= len(value) <= 2048:
            raise ValueError
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.netloc != parsed.netloc.lower()
        ):
            raise ValueError
        return value
    except Exception:
        _deny()


def _db_utc(value: object) -> datetime:
    if type(value) is not datetime:
        _deny()
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _epoch_milliseconds(value: object) -> int:
    instant = _db_utc(value)
    if instant < _EPOCH:
        _deny()
    delta = instant - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1000 + delta.microseconds // 1000


def _observed(value: object) -> tuple[int, datetime, datetime]:
    try:
        if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
            raise ValueError
        seconds, milliseconds = divmod(value, 1000)
        whole_second = _EPOCH + timedelta(seconds=seconds)
        exact = whole_second + timedelta(milliseconds=milliseconds)
        return value, exact, whole_second
    except Exception:
        _deny()


def _one_locked(session: Session, statement):
    rows = (
        session.execute(statement.limit(2).with_for_update().execution_options(populate_existing=True)).scalars().all()
    )
    if len(rows) != 1:
        _deny()
    return rows[0]


@dataclass(frozen=True, slots=True)
class _LockedNonEd25519AuthorityV1:
    """Internal continuation after the shared Full/session/X25519 locks."""

    context: admission.VerificationContextV1
    observed_ms: int
    observed_second: datetime
    deadlines: tuple[int, ...]
    full_verifier: SqlAlchemyTransactionBoundCurrentFullVerifier


@dataclass(frozen=True, slots=True)
class _ValidatedNonEd25519AuthorityV1:
    """The reusable #551 dimensions, excluding current Ed25519 authority."""

    context_digest: str
    locked_deadline_ms: int
    full_proof_id: str
    approver_full_proof_id: str | None


class SqlAlchemyTransactionBoundAdmissionAuthority:
    """Compose existing durable owners without taking transaction ownership.

    ``device_issuance_id`` and ``approver_oauth_session_id`` are trusted
    server-side presentation resolutions.  They are never read from
    ``VerificationContextV1`` and are not bearer credentials by themselves.
    The approver selector is required only for ``enrollment-v2``.
    """

    def __init__(
        self,
        session: Session,
        *,
        device_issuance_id: object,
        device_client_id: object,
        oauth_issuer: object,
        approver_oauth_session_id: object = None,
        approver_client_id: object = None,
    ) -> None:
        self._session = session
        self._device_issuance_id = _hex64(device_issuance_id)
        self._device_client_id = _configured_id(device_client_id)
        self._oauth_issuer = _issuer(oauth_issuer)
        if (approver_oauth_session_id is None) != (approver_client_id is None):
            _deny()
        self._approver_oauth_session_id = (
            None if approver_oauth_session_id is None else _hex64(approver_oauth_session_id)
        )
        self._approver_client_id = None if approver_client_id is None else _configured_id(approver_client_id)
        try:
            self._transaction = session.get_transaction()
            self._nested_transaction = session.get_nested_transaction()
        except Exception:
            _deny()
        self._connection: Connection | None = None
        self._failed = False
        self._check_transaction(check_guards=True)

    def _check_transaction(self, *, check_guards: bool = False) -> Connection:
        try:
            current = self._session
            if (
                self._failed
                or self._transaction is None
                or not self._transaction.is_active
                or current.get_transaction() is not self._transaction
                or current.get_nested_transaction() is not self._nested_transaction
                or current.in_transaction() is not True
                or not current.is_active
                or current.new
                or current.dirty
                or current.deleted
                or current.get_bind().dialect.name != "postgresql"
            ):
                _deny()
            connection = current.connection()
            if connection.closed or connection.invalidated or not connection.in_transaction():
                _deny()
            dbapi = connection.connection.dbapi_connection
            if getattr(dbapi, "autocommit", None) is not False:
                _deny()
            if self._connection is None:
                self._connection = connection
            elif connection is not self._connection:
                _deny()
            if connection.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed":
                _deny()
            if check_guards:
                self._require_owner_guards(connection)
            return connection
        except admission.SocialMessagingDeviceAdmissionUnavailable:
            raise
        except Exception:
            _deny()

    @staticmethod
    def _require_owner_guards(connection: Connection) -> None:
        guards = tuple(dict.fromkeys(OAUTH_SESSION_GUARDS + SOCIAL_SESSION_GUARDS))
        clauses = []
        parameters: dict[str, str] = {}
        for position, (table_name, trigger_name) in enumerate(guards):
            clauses.append(f"(tgrelid=to_regclass(:table_{position}) AND tgname=:trigger_{position})")
            parameters[f"table_{position}"] = table_name
            parameters[f"trigger_{position}"] = trigger_name
        installed = connection.execute(
            text(
                "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal "
                "AND tgenabled='O' AND (" + " OR ".join(clauses) + ")"
            ),
            parameters,
        ).scalar_one()
        if installed != len(guards):
            _deny()

    def _lock_issuance(self) -> SocialSessionIssuance:
        return _one_locked(
            self._session,
            select(SocialSessionIssuance).where(SocialSessionIssuance.issuance_id == self._device_issuance_id),
        )

    def _issuance_for_discovery(self) -> SocialSessionIssuance:
        rows = (
            self._session.execute(
                select(SocialSessionIssuance)
                .where(SocialSessionIssuance.issuance_id == self._device_issuance_id)
                .limit(2)
                .execution_options(populate_existing=True)
            )
            .scalars()
            .all()
        )
        if len(rows) != 1:
            _deny()
        return rows[0]

    def _generation_for_session(self, session_id: str) -> OAuthSessionGeneration:
        rows = (
            self._session.execute(
                select(OAuthSessionGeneration).where(OAuthSessionGeneration.session_id == session_id).limit(2)
            )
            .scalars()
            .all()
        )
        if len(rows) != 1:
            _deny()
        return rows[0]

    def _lock_generation(self, token_id: str) -> OAuthSessionGeneration:
        return _one_locked(
            self._session,
            select(OAuthSessionGeneration).where(OAuthSessionGeneration.token_id == token_id),
        )

    def _lock_client(self, client_id: str) -> OAuthClient:
        client = self._session.get(
            OAuthClient,
            client_id,
            with_for_update=True,
            populate_existing=True,
        )
        if client is None or client.client_id != client_id or client.is_active is not True:
            _deny()
        return client

    def _lock_browser(self, generation: OAuthSessionGeneration) -> OAuthBrowserGeneration:
        browser = self._session.get(
            OAuthBrowserGeneration,
            generation.browser_generation_id,
            with_for_update=True,
            populate_existing=True,
        )
        if browser is None:
            _deny()
        return browser

    def _lock_token(self, token_id: str) -> OAuthToken:
        token = self._session.get(
            OAuthToken,
            token_id,
            with_for_update=True,
            populate_existing=True,
        )
        if token is None:
            _deny()
        return token

    def _lock_session(self, session_id: str) -> DurableSession:
        durable = self._session.get(
            DurableSession,
            session_id,
            with_for_update=True,
            populate_existing=True,
        )
        if durable is None:
            _deny()
        return durable

    def _validate_token(
        self,
        token: OAuthToken,
        *,
        user: User,
        client: OAuthClient,
        observed: datetime,
        exact_scope: str | None = None,
    ) -> int:
        try:
            scopes = parse_scopes(token.scope)
            validate_client_scopes(
                scopes,
                client_allowed_scopes(
                    {
                        "scope": client.scope,
                        "metadata": client.metadata_json,
                    }
                ),
            )
            metadata = token.metadata_json
            if type(metadata) is not dict:
                raise ValueError
            kid = metadata.get("kid")
            expected_metadata = {
                "token_contract": TOKEN_CONTRACT,
                "token_use": "access",
                "issuer": self._oauth_issuer,
                "audience": client.client_id,
                "kid": kid,
                "digest_algorithm": "sha256",
                "scope_policy_version": SCOPE_POLICY_VERSION,
            }
            created = _db_utc(token.created_at)
            expires = _db_utc(token.access_token_expires_at)
            if (
                type(token.id) is not str
                or _HEX32(token.id) is None
                or type(token.access_token) is not str
                or _HEX_DIGEST(token.access_token) is None
                or token.client_id != client.client_id
                or token.user_id != user.id
                or token.token_type != "Bearer"
                or token.refresh_token is not None
                or token.refresh_token_expires_at is not None
                or token.is_revoked is not False
                or type(kid) is not str
                or _CONFIGURED_ID(kid) is None
                or metadata != expected_metadata
                or "openid" not in scopes
                or exact_scope is not None
                and token.scope != exact_scope
                or not created <= observed < expires
            ):
                raise ValueError
            return _epoch_milliseconds(expires)
        except Exception:
            _deny()

    def _validate_oauth_generation(
        self,
        generation: OAuthSessionGeneration,
        *,
        expected_session_id: str,
        expected_client_id: str,
        user: User,
        client: OAuthClient,
        browser: OAuthBrowserGeneration,
        token: OAuthToken,
        durable: DurableSession,
        observed: datetime,
    ) -> int:
        token_deadline = self._validate_token(
            token,
            user=user,
            client=client,
            observed=observed,
        )
        created = _db_utc(durable.created_at)
        expires = _db_utc(durable.expires_at)
        browser_created = _db_utc(browser.created_at)
        browser_expires = _db_utc(browser.expires_at)
        if (
            generation.token_id != token.id
            or generation.session_id != expected_session_id
            or generation.user_id != user.id
            or generation.client_id != expected_client_id
            or generation.subject != user.pubkey
            or generation.browser_generation_id != browser.generation_id
            or browser.user_id != user.id
            or browser.client_id != expected_client_id
            or browser.subject != user.pubkey
            or browser.is_active is not True
            or not browser_created <= observed < browser_expires
            or durable.session_id != expected_session_id
            or durable.user_id != user.id
            or durable.session_type != "web"
            or durable.is_active is not True
            or durable.metadata_json is not None
            or created != _db_utc(token.created_at)
            or expires != _db_utc(token.access_token_expires_at)
            or browser_created > created
            or expires > browser_expires
            or not created <= observed < expires
        ):
            _deny()
        return min(
            token_deadline,
            _epoch_milliseconds(expires),
            _epoch_milliseconds(browser_expires),
        )

    def _validate_social_issuance(
        self,
        issuance: SocialSessionIssuance,
        *,
        context: admission.VerificationContextV1,
        user: User,
        client: OAuthClient,
        issuer: SocialSessionIssuer,
        parent: OAuthSessionGeneration,
        social_token: OAuthToken,
        observed_ms: int,
        observed: datetime,
    ) -> int:
        try:
            social_deadline = self._validate_token(
                social_token,
                user=user,
                client=client,
                observed=observed,
                exact_scope=SOCIAL_SESSION_SCOPE,
            )
            if (
                issuance.issuance_id != self._device_issuance_id
                or issuance.token_id != social_token.id
                or issuance.token_id == issuance.parent_token_id
                or issuance.parent_token_id != parent.token_id
                or issuance.client_id != self._device_client_id
                or issuance.user_id != user.id
                or issuance.subject != context.subject
                or issuance.binding_id != context.binding_id
                or issuance.device_id != context.device_id
                or issuance.method != "qr_desktop_v1"
                or issuance.operation not in {"register", "rotate", "adopt"}
                or issuer.client_id != issuance.client_id
                or issuer.backend_id != issuance.backend_id
                or issuer.service_principal != issuance.service_principal
                or issuer.is_active is not True
                or type(issuance.issued_at) is not int
                or type(issuance.expires_at) is not int
                or not issuance.issued_at * 1000 <= observed_ms < issuance.expires_at * 1000
                or _HEX64(issuance.operation_id) is None
                or _HEX64(issuance.request_id) is None
                or _HEX64(issuance.authorization_digest) is None
                or _HEX64(issuance.revision) is None
                or _HEX64(issuance.delivery_commitment) is None
                or _db_utc(social_token.created_at) != _EPOCH + timedelta(seconds=issuance.issued_at)
                or _db_utc(social_token.access_token_expires_at) != _EPOCH + timedelta(seconds=issuance.expires_at)
            ):
                raise ValueError
            return min(social_deadline, issuance.expires_at * 1000)
        except admission.SocialMessagingDeviceAdmissionUnavailable:
            raise
        except Exception:
            _deny()

    def _lock_non_ed25519_authority(
        self,
        context: admission.VerificationContextV1,
        *,
        observed_at: int,
    ) -> _LockedNonEd25519AuthorityV1:
        self._check_transaction()
        if (
            type(context) is not admission.VerificationContextV1
            or admission.parse_verification_context_v1(context.wire) != context
        ):
            _deny()
        observed_ms, observed, observed_second = _observed(observed_at)
        enrollment = context.challenge_kind == "enrollment-v2"
        if enrollment != (self._approver_oauth_session_id is not None):
            _deny()

        full_verifier = SqlAlchemyTransactionBoundCurrentFullVerifier(self._session)
        # This first call establishes the global subject/User/evidence
        # boundary before any OAuth, X25519, or Ed25519 authority lock.
        full_verifier.verify_in_transaction(context.subject, now=observed_second)
        user = _one_locked(
            self._session,
            select(User).where(User.pubkey == context.subject),
        )
        if user.pubkey != context.subject or user.is_active is not True:
            _deny()

        issuance_probe = self._issuance_for_discovery()
        if (
            issuance_probe is None
            or issuance_probe.subject != context.subject
            or issuance_probe.client_id != self._device_client_id
        ):
            _deny()
        parent_probe = self._session.get(
            OAuthSessionGeneration,
            issuance_probe.parent_token_id,
            populate_existing=True,
        )
        if parent_probe is None:
            _deny()

        approver_probe = None
        if enrollment:
            approver_probe = self._generation_for_session(self._approver_oauth_session_id)

        expected_clients = {self._device_client_id}
        if self._approver_client_id is not None:
            expected_clients.add(self._approver_client_id)
        clients = {client_id: self._lock_client(client_id) for client_id in sorted(expected_clients)}

        issuer = self._session.get(
            SocialSessionIssuer,
            self._device_client_id,
            with_for_update=True,
            populate_existing=True,
        )
        if issuer is None:
            _deny()

        generation_probes = {parent_probe.token_id: parent_probe}
        if approver_probe is not None:
            generation_probes[approver_probe.token_id] = approver_probe
        generations = {token_id: self._lock_generation(token_id) for token_id in sorted(generation_probes)}
        parent = generations[parent_probe.token_id]
        approver = None if approver_probe is None else generations[approver_probe.token_id]
        browsers = {
            generation.browser_generation_id: self._lock_browser(generation)
            for generation in sorted(
                generations.values(),
                key=lambda item: item.browser_generation_id,
            )
        }
        oauth_rows = {}
        for token_id in sorted(generations):
            generation = generations[token_id]
            oauth_rows[token_id] = (
                self._lock_token(token_id),
                self._lock_session(generation.session_id),
            )
        social_token = self._lock_token(issuance_probe.token_id)
        issuance = self._lock_issuance()

        parent_deadline = self._validate_oauth_generation(
            parent,
            expected_session_id=parent.session_id,
            expected_client_id=self._device_client_id,
            user=user,
            client=clients[self._device_client_id],
            browser=browsers[parent.browser_generation_id],
            token=oauth_rows[parent.token_id][0],
            durable=oauth_rows[parent.token_id][1],
            observed=observed,
        )
        social_deadline = self._validate_social_issuance(
            issuance,
            context=context,
            user=user,
            client=clients[self._device_client_id],
            issuer=issuer,
            parent=parent,
            social_token=social_token,
            observed_ms=observed_ms,
            observed=observed,
        )

        device_preimage = session_binding.canonical_session_binding_preimage_v1_bytes(
            subject=context.subject,
            device_id=context.device_id,
            x25519_binding_id=context.binding_id,
            social_session_issuance_id=issuance.issuance_id,
            social_session_token_id=issuance.token_id,
            parent_oauth_token_id=parent.token_id,
            parent_oauth_session_id=parent.session_id,
            parent_oauth_browser_generation_id=parent.browser_generation_id,
            client_id=issuance.client_id,
        ).decode("ascii")
        session_binding.require_session_binding_match_v1(
            device_preimage,
            context.session_binding,
        )

        deadlines = [parent_deadline, social_deadline]
        if enrollment:
            if approver is None or self._approver_client_id is None:
                _deny()
            if approver.subject != context.subject:
                _deny()
            approver_deadline = self._validate_oauth_generation(
                approver,
                expected_session_id=self._approver_oauth_session_id,
                expected_client_id=self._approver_client_id,
                user=user,
                client=clients[self._approver_client_id],
                browser=browsers[approver.browser_generation_id],
                token=oauth_rows[approver.token_id][0],
                durable=oauth_rows[approver.token_id][1],
                observed=observed,
            )
            approver_preimage = session_binding.canonical_approver_session_binding_preimage_v1_bytes(
                subject=approver.subject,
                oauth_token_id=approver.token_id,
                oauth_session_id=approver.session_id,
                oauth_browser_generation_id=approver.browser_generation_id,
                client_id=approver.client_id,
            ).decode("ascii")
            session_binding.require_approver_session_binding_match_v1(
                approver_preimage,
                context.approver_session_binding,
            )
            deadlines.append(approver_deadline)

        binding = SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(self._session).binding_for_id(
            context.binding_id
        )
        if (
            binding is None
            or binding.subject != context.subject
            or binding.device_id != context.device_id
            or binding.binding_id != context.binding_id
            or binding.binding_version != context.binding_version
            or binding.active is not True
            or binding.operation not in {"register", "rotate"}
            or not binding.valid_from <= observed < binding.expires_at
            or not hmac.compare_digest(
                x25519_public_key_commitment_v1(binding.public_key),
                context.x25519_public_key_commitment,
            )
        ):
            _deny()
        deadlines.append(_epoch_milliseconds(binding.expires_at))
        return _LockedNonEd25519AuthorityV1(
            context=context,
            observed_ms=observed_ms,
            observed_second=observed_second,
            deadlines=tuple(deadlines),
            full_verifier=full_verifier,
        )

    def _finalize_non_ed25519_authority(
        self,
        locked: _LockedNonEd25519AuthorityV1,
    ) -> _ValidatedNonEd25519AuthorityV1:
        if type(locked) is not _LockedNonEd25519AuthorityV1:
            _deny()
        context = locked.context
        deadlines = list(locked.deadlines)
        full = locked.full_verifier.verify_in_transaction(
            context.subject,
            now=locked.observed_second,
        )
        if not hmac.compare_digest(full.proof_id, context.full_proof_id):
            _deny()
        deadlines.append(_epoch_milliseconds(full.expires_at))
        approver_full_proof_id = None
        if context.challenge_kind == "enrollment-v2":
            approver_full = locked.full_verifier.verify_in_transaction(
                context.subject,
                now=locked.observed_second,
            )
            if not hmac.compare_digest(
                approver_full.proof_id,
                context.approver_full_proof_id,
            ):
                _deny()
            deadlines.append(_epoch_milliseconds(approver_full.expires_at))
            approver_full_proof_id = approver_full.proof_id

        locked_deadline = min(deadlines)
        if locked.observed_ms >= locked_deadline:
            _deny()
        self._check_transaction(check_guards=True)
        return _ValidatedNonEd25519AuthorityV1(
            context_digest=admission.verification_context_digest_v1(context.wire),
            locked_deadline_ms=locked_deadline,
            full_proof_id=full.proof_id,
            approver_full_proof_id=approver_full_proof_id,
        )

    def lock_current_authority(
        self,
        context: admission.VerificationContextV1,
        *,
        observed_at: int,
    ) -> admission.CurrentAdmissionAuthorityV1:
        try:
            locked = self._lock_non_ed25519_authority(
                context,
                observed_at=observed_at,
            )
            association = SqlAlchemyEd25519AssociationStore(self._session).lock_current_association(
                context.subject, context.device_id
            )
            if (
                association is None
                or association.state != "active"
                or association.subject != context.subject
                or association.device_id != context.device_id
                or association.ed25519_public_key != context.ed25519_public_key
                or association.association_id != context.association_id
                or association.association_version != context.association_version
                or association.authority_epoch != context.authority_epoch
                or context.challenge_kind == "enrollment-v2"
                and association.predecessor_association_id != context.predecessor_association_id
            ):
                _deny()

            # Re-enter the already-held Full locks after every other wait and
            # compare both independent roles against current durable evidence.
            non_ed25519 = self._finalize_non_ed25519_authority(locked)
            return admission.CurrentAdmissionAuthorityV1(
                context_digest=non_ed25519.context_digest,
                authority_epoch=association.authority_epoch,
                locked_deadline_ms=non_ed25519.locked_deadline_ms,
                full_proof_id=non_ed25519.full_proof_id,
                approver_full_proof_id=non_ed25519.approver_full_proof_id,
            )
        except admission.SocialMessagingDeviceAdmissionUnavailable:
            self._failed = True
            raise
        except Exception:
            self._failed = True
            _deny()


__all__ = ["SqlAlchemyTransactionBoundAdmissionAuthority"]

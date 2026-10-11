"""Dormant transaction-bound native V2 provenance and present-authority reader."""

from __future__ import annotations

import hmac
import re
import weakref
from collections import namedtuple
from copy import deepcopy
from typing import Any, NamedTuple
from urllib.parse import urlsplit

from sqlalchemy import inspect, select
from sqlalchemy.sql.functions import Function

from app.models import OAuthBrowserGeneration, OAuthClient, OAuthSessionGeneration, OAuthToken, Session, User
from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
from app.services.current_entitlement_evidence_storage import SqlAlchemyTransactionBoundCurrentFullVerifier
from app.services.oauth_bearer_validation import TOKEN_CONTRACT
from app.services.oauth_scope_policy import SCOPE_POLICY_VERSION, client_allowed_scopes, validate_client_scopes
from app.services.social_messaging_device_binding_authorization_storage import (
    SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage,
)
from app.services.social_messaging_device_storage import SqlAlchemyTransactionBoundSocialMessagingDeviceStorage
from app.services.social_session_issuance import SocialSessionIssuer
from app.services.social_session_issuance_v2_contract import (
    SCOPE,
    V2IssuanceUnavailable,
    binding_from_wire,
    continuity,
    hex64,
    issuance_revision,
    milliseconds,
    trusted_now,
    utc,
)
from app.services.social_session_issuance_v2_storage import (
    TransactionGuard,
    V2Acceptance,
    V2BindingBirth,
    V2Invalidation,
    V2Issuance,
    V2Offer,
    V2Parent,
    V2TokenBirth,
    attest,
)

_ROW_TYPES = {}


def _snapshot(row):
    """Freeze native values BEFORE parsing/validation; never reread ORM facts later."""
    if row is None:
        return None
    model = type(row)
    attributes = tuple(inspect(row).mapper.column_attrs)
    if model not in _ROW_TYPES:
        record = namedtuple("_NativeV2Row", [p.key for p in attributes])
        record.__repr__ = lambda self: "<private native V2 row snapshot>"
        _ROW_TYPES[model] = record
    return _ROW_TYPES[model](*(deepcopy(getattr(row, p.key)) for p in attributes))


class BoundSession:
    """Existing mutation/evidence primitives route ALL SQL through the guard.

    add stages a Core INSERT on the guarded Connection, avoiding mapper-specific
    flush binds. This port supports only the existing binding primitive's API.
    """

    def __init__(self, guard):
        self.guard = guard

    def __getattr__(self, name):
        return getattr(self.guard.session, name)

    def connection(self):
        self.guard.check()
        return self.guard.connection

    def get_bind(self, *args, **kwargs):
        return self.guard.connection

    def execute(self, statement, *args, **kwargs):
        if args:
            raise V2IssuanceUnavailable()
        columns = list(getattr(statement, "selected_columns", ()))
        if len(columns) == 1 and isinstance(columns[0], Function) and columns[0].name == "pg_advisory_xact_lock":
            self.guard.check()
            result = self.guard.connection.execute(statement)
            self.guard.check()
            return result
        return self.guard.execute(statement)

    def get(self, model, key, **kwargs):
        column = next(iter(model.__table__.primary_key.columns))
        return self.guard.row(model, column, key, lock=bool(kwargs.get("with_for_update")), optional=True)

    def add(self, row):
        values = {
            c.name: getattr(row, inspect(row).mapper.get_property_by_column(c).key) for c in row.__table__.columns
        }
        self.guard.execute(row.__table__.insert().values(**values))

    def flush(self):
        self.guard.check()


class _Facts(NamedTuple):
    issuance_id: str
    revision: str
    token_id: str
    operation_id: str
    acceptance_id: str
    approval_id: str
    authorization_digest: str
    pre_enrollment_digest: str
    approval_wire: str
    acceptance_wire: str
    subject: str
    device_id: str
    request_id: str
    client_id: str
    backend_id: str
    issuer: str
    service_principal: str
    parent_token_id: str
    parent_session_id: str
    parent_browser_id: str
    approver_token_id: str
    approver_session_id: str
    approver_browser_id: str
    binding_id: str
    binding_version: int
    public_key_commitment: str
    phone_expires_at_ms: int
    approver_expires_at_ms: int
    binding_expires_at_ms: int
    full_expires_at_ms: int
    full_evidence_id: str
    full_evidence_version: str
    full_source_evidence_sha256: str
    full_proof_id: str
    observed_at_ms: int
    input_digest: str | None = None

    def __repr__(self):
        return "<locked V2 authority provenance>"


_RECORDS: weakref.WeakKeyDictionary[Any, tuple[Any, _Facts]] = weakref.WeakKeyDictionary()


class LockedV2Authority:
    """Internally registered frozen observation, provisional until caller commit."""

    __slots__ = ("__weakref__",)

    def __new__(cls):
        raise V2IssuanceUnavailable()

    @property
    def facts(self):
        try:
            reader, facts = _RECORDS[self]
            reader._check()
            if milliseconds(trusted_now(reader.clock)) >= min(
                facts.phone_expires_at_ms,
                facts.approver_expires_at_ms,
                facts.binding_expires_at_ms,
                facts.full_expires_at_ms,
            ):
                raise V2IssuanceUnavailable()
            return facts
        except Exception:
            raise V2IssuanceUnavailable() from None

    @property
    def provisional_until_caller_commit(self):
        return True


def validated_facts(value, reader):
    if type(value) is not LockedV2Authority or value not in _RECORDS or _RECORDS[value][0] is not reader:
        raise V2IssuanceUnavailable()
    return value.facts


class NativeV2AuthorityReader:
    def __init__(self, session, *, client_id, backend_id, principal, issuer, clock):
        try:
            if not callable(clock) or any(
                type(v) is not str or not 1 <= len(v) <= 255 for v in (client_id, backend_id, principal, issuer)
            ):
                raise ValueError
            if any(
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}", v) is None
                for v in (client_id, backend_id, principal)
            ):
                raise ValueError
            origin = urlsplit(issuer)
            if (
                origin.scheme != "https"
                or not origin.hostname
                or origin.username
                or origin.password
                or origin.path
                or origin.query
                or origin.fragment
                or origin.netloc != origin.netloc.lower()
            ):
                raise ValueError
            self.guard = TransactionGuard(session)
            self.port = BoundSession(self.guard)
            self.client_id, self.backend_id, self.principal, self.issuer = client_id, backend_id, principal, issuer
            self.clock = clock
            self.failed = False
            self._deadline_ms = None
            self.catalog_identity = attest(self.guard)
        except Exception:
            raise V2IssuanceUnavailable() from None

    def _check(self):
        if self.failed:
            raise V2IssuanceUnavailable()
        self.guard.check()
        if attest(self.guard) != self.catalog_identity:
            self.failed = True
            raise V2IssuanceUnavailable()

    def _row(self, *args, **kwargs):
        return _snapshot(self.guard.row(*args, **kwargs))

    def _operation(self, operation_id):
        hex64(operation_id)
        self.guard.sql(
            "SELECT pg_catalog.pg_advisory_xact_lock(:key)",
            {"key": int.from_bytes(bytes.fromhex(operation_id)[:8], "big", signed=True)},
        )
        offer = self._row(V2Offer, V2Offer.operation_id, operation_id)
        parent = self._row(V2Parent, V2Parent.operation_id, operation_id)
        envelope = v2.parse_authorization_envelope_v2(offer.wire)
        if (
            envelope.context.pairing_id != operation_id
            or offer.subject != envelope.pre_enrollment.subject
            or offer.request_id != envelope.pre_enrollment.request_id
            or offer.authorization_digest != v2.authorization_v2_digest(offer.wire)
            or offer.created_at != envelope.context.created_at * 1000
            or offer.expires_at != envelope.context.expires_at * 1000
            or (offer.client_id, offer.backend_id, offer.service_principal, offer.issuer)
            != (self.client_id, self.backend_id, self.principal, self.issuer)
        ):
            raise V2IssuanceUnavailable()
        return offer, parent, envelope

    def _owners(self, envelope, parent, *, require_binding):
        """Shared request/Full/User/device/key -> client/issuer/browser/token/session/binding."""
        hex64(parent.session_id)
        hex64(parent.browser_id)
        if re.fullmatch(r"[0-9a-f]{32}", parent.token_id) is None:
            raise V2IssuanceUnavailable()
        storage = SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(self.port)
        storage._lock_request(envelope.pre_enrollment.request_id)
        storage._lock_mutation(
            subject=envelope.pre_enrollment.subject,
            device_id=envelope.pre_enrollment.device_id,
            public_keys=(envelope.x25519_public_key,),
        )
        g = self._row(OAuthSessionGeneration, OAuthSessionGeneration.token_id, parent.token_id)
        u = self._row(User, User.id, parent.user_id, lock=True)
        c = self._row(OAuthClient, OAuthClient.client_id, self.client_id, lock=True)
        r = self._row(SocialSessionIssuer, SocialSessionIssuer.client_id, self.client_id, lock=True)
        b = self._row(OAuthBrowserGeneration, OAuthBrowserGeneration.generation_id, parent.browser_id, lock=True)
        t = self._row(OAuthToken, OAuthToken.id, parent.token_id, lock=True)
        s = self._row(Session, Session.session_id, parent.session_id, lock=True)
        now = trusted_now(self.clock)
        if (
            (g.session_id, g.browser_generation_id, g.user_id, g.client_id, g.subject)
            != (parent.session_id, parent.browser_id, parent.user_id, self.client_id, envelope.pre_enrollment.subject)
            or u.is_active is not True
            or u.pubkey != g.subject
            or c.is_active is not True
            or r.is_active is not True
            or (r.backend_id, r.service_principal) != (self.backend_id, self.principal)
            or (b.user_id, b.client_id, b.subject) != (u.id, self.client_id, g.subject)
            or b.is_active is not True
            or t.is_revoked is not False
            or (t.user_id, t.client_id) != (u.id, self.client_id)
            or s.is_active is not True
            or s.user_id != u.id
            or s.session_type != "web"
            or s.metadata_json is not None
            or t.refresh_token is not None
            or t.refresh_token_expires_at is not None
            or t.token_type != "Bearer"
            or not set(SCOPE.split()) <= set((t.scope or "").split())
            or t.metadata_json.get("token_contract") != TOKEN_CONTRACT
            or t.metadata_json.get("token_use") != "access"
            or t.metadata_json.get("issuer") != self.issuer
            or t.metadata_json.get("audience") != self.client_id
            or not hmac.compare_digest(parent.continuity, continuity(g, s, envelope.context.desktop_context))
            or any(
                not utc(row.created_at) <= now < utc(expiry)
                for row, expiry in ((b, b.expires_at), (t, t.access_token_expires_at), (s, s.expires_at))
            )
        ):
            raise V2IssuanceUnavailable()
        validate_client_scopes(
            frozenset(SCOPE.split()), client_allowed_scopes({"scope": c.scope, "metadata": c.metadata_json})
        )
        if self._row(V2Invalidation, V2Invalidation.operation_id, envelope.context.pairing_id, optional=True):
            raise V2IssuanceUnavailable()
        binding = binding_from_wire(envelope.wire)
        if (
            require_binding
            and SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(self.port).binding_for_id(binding.binding_id)
            != binding
        ):
            raise V2IssuanceUnavailable()
        # Evidence-and-proof provenance comes from exactly one locked evaluation.
        # Its legacy second clock is floored, followed by a fresh exact UTC check.
        full = SqlAlchemyTransactionBoundCurrentFullVerifier(self.port).verify_with_evidence_in_transaction(
            g.subject, now=trusted_now(self.clock).replace(microsecond=0)
        )
        after = trusted_now(self.clock)
        if not full.verified_entitlement.valid_from <= after < full.verified_entitlement.expires_at:
            raise V2IssuanceUnavailable()
        deadline = min(milliseconds(b.expires_at), milliseconds(t.access_token_expires_at), milliseconds(s.expires_at))
        v2.validate_acceptance_time_v2(envelope.wire, now_ms=milliseconds(after))
        self._deadline_ms = min(
            deadline,
            milliseconds(full.verified_entitlement.expires_at),
            envelope.context.expires_at * 1000,
            envelope.semantic.expires_at * 1000,
            envelope.pre_enrollment.expires_at,
            envelope.x25519_binding_expires_at_ms,
        )
        if milliseconds(after) >= self._deadline_ms:
            raise V2IssuanceUnavailable()
        return u, full, deadline, binding

    def _acceptance(self, offer, parent):
        a = self._row(V2Acceptance, V2Acceptance.operation_id, offer.operation_id)
        birth = self._row(V2BindingBirth, V2BindingBirth.binding_id, a.binding_id)
        if birth.operation_id != offer.operation_id or birth.birth_xid != a.birth_xid:
            raise V2IssuanceUnavailable()
        accepted = v2.parse_acceptance_v2(a.wire, approval_event_wire=a.approval_wire)
        if (
            accepted.approval.envelope.wire != offer.wire
            or accepted.acceptance_id != a.acceptance_id
            or accepted.approval.event_id != a.approval_id
            or a.binding_id != accepted.approval.envelope.semantic.binding_id
            or not offer.created_at <= a.accepted_at < offer.expires_at
            or not a.accepted_at < a.full_expires_at
            or v2.canonical_acceptance_v2_bytes(a.approval_wire, now_ms=a.accepted_at).decode("ascii") != a.wire
        ):
            raise V2IssuanceUnavailable()
        hex64(a.possession_proof)
        return a

    def _revision(self, i, p, a):
        return issuance_revision(
            operation_id=i.operation_id,
            acceptance_wire=a.wire,
            approval_wire=a.approval_wire,
            issuance_id=i.issuance_id,
            token_id=i.token_id,
            parent_token_id=p.token_id,
            parent_session_id=p.session_id,
            parent_browser_id=p.browser_id,
            client_id=i.client_id,
            backend_id=i.backend_id,
            principal=i.service_principal,
            issuer=i.issuer,
            delivery=i.delivery_commitment,
            signing_kid=i.kid,
            issued_at=i.issued_at,
            expires_at=i.expires_at,
        )

    def read(self, issuance_id, *, verification_input_wire=None):
        """No commit, independent Session, caller evidence, or latest-row shortcut."""
        try:
            self._check()
            initial = self._row(V2Issuance, V2Issuance.issuance_id, hex64(issuance_id))
            offer, p, envelope = self._operation(initial.operation_id)
            i = self._row(V2Issuance, V2Issuance.operation_id, offer.operation_id)
            a = self._acceptance(offer, p)
            u, full, parent_deadline, binding = self._owners(envelope, p, require_binding=True)
            token_birth = self._row(V2TokenBirth, V2TokenBirth.token_id, i.token_id)
            if token_birth.birth_xid != i.birth_xid or i.birth_xid != a.birth_xid:
                raise V2IssuanceUnavailable()
            child = self._row(OAuthToken, OAuthToken.id, i.token_id, lock=True)
            now = trusted_now(self.clock)
            maximum = min(
                parent_deadline,
                envelope.context.expires_at * 1000,
                envelope.semantic.expires_at * 1000,
                envelope.pre_enrollment.expires_at,
                envelope.x25519_binding_expires_at_ms,
            )
            if (
                i.issuance_id != issuance_id
                or i.acceptance_id != a.acceptance_id
                or i.subject != u.pubkey
                or i.user_id != u.id
                or i.revision != self._revision(i, p, a)
                or (i.client_id, i.backend_id, i.service_principal, i.issuer)
                != (self.client_id, self.backend_id, self.principal, self.issuer)
                or child.is_revoked is not False
                or (child.user_id, child.client_id) != (u.id, self.client_id)
                or child.scope != SCOPE
                or child.token_type != "Bearer"
                or child.refresh_token is not None
                or child.refresh_token_expires_at is not None
                or milliseconds(child.created_at) != i.issued_at * 1000
                or milliseconds(child.access_token_expires_at) != i.expires_at * 1000
                or not i.issued_at * 1000 <= milliseconds(now) < i.expires_at * 1000 <= maximum
                or child.metadata_json
                != dict(
                    token_contract=TOKEN_CONTRACT,
                    token_use="access",
                    issuer=self.issuer,
                    audience=self.client_id,
                    kid=i.kid,
                    digest_algorithm="sha256",
                    scope_policy_version=SCOPE_POLICY_VERSION,
                )
                or self._row(OAuthSessionGeneration, OAuthSessionGeneration.token_id, child.id, optional=True)
            ):
                raise V2IssuanceUnavailable()
            input_digest = None
            if verification_input_wire is not None:
                parsed = v2.parse_preaccepted_enrollment_verification_input_v2(verification_input_wire)
                if parsed.approval.wire != a.approval_wire or parsed.acceptance_id != a.acceptance_id:
                    raise V2IssuanceUnavailable()
                v2.validate_preaccepted_enrollment_time_v2(
                    verification_input_wire,
                    now_ms=milliseconds(trusted_now(self.clock)),
                    phone_session_expires_at_ms=i.expires_at * 1000,
                    approver_session_expires_at_ms=parent_deadline,
                    full_expires_at_ms=milliseconds(full.verified_entitlement.expires_at),
                    x25519_binding_expires_at_ms=envelope.x25519_binding_expires_at_ms,
                )
                input_digest = v2.preaccepted_enrollment_verification_input_v2_digest(verification_input_wire)
            self._check()
            self._deadline_ms = min(i.expires_at * 1000, self._deadline_ms)
            observed = milliseconds(trusted_now(self.clock))
            if observed >= self._deadline_ms:
                raise V2IssuanceUnavailable()
            facts = _Facts(
                i.issuance_id,
                i.revision,
                i.token_id,
                i.operation_id,
                a.acceptance_id,
                a.approval_id,
                offer.authorization_digest,
                v2.pre_enrollment_v2_digest(envelope.pre_enrollment.wire),
                a.approval_wire,
                a.wire,
                u.pubkey,
                binding.device_id,
                offer.request_id,
                self.client_id,
                self.backend_id,
                self.issuer,
                self.principal,
                p.token_id,
                p.session_id,
                p.browser_id,
                p.token_id,
                p.session_id,
                p.browser_id,
                binding.binding_id,
                binding.binding_version,
                envelope.pre_enrollment.x25519_public_key_commitment,
                i.expires_at * 1000,
                parent_deadline,
                envelope.x25519_binding_expires_at_ms,
                milliseconds(full.verified_entitlement.expires_at),
                full.evidence_id,
                full.evidence_version,
                full.source_evidence_sha256,
                full.verified_entitlement.proof_id,
                observed,
                input_digest,
            )
            result = object.__new__(LockedV2Authority)
            _RECORDS[result] = (self, facts)
            return result
        except Exception:
            self.failed = True
            self.guard.poisoned = True
            raise V2IssuanceUnavailable() from None

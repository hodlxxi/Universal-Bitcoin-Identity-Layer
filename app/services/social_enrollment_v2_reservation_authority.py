"""Native pending-only reservation authority in one caller-owned transaction.

The narrow storage lookup intentionally couples to the frozen store's checked
Connection/table and row reparser. It adds discovery BEFORE signing. The table
lock conflicts with existing writers too, including ones without advisory locks.
"""

import weakref
from typing import NamedTuple

from sqlalchemy import or_, select, text

from app.services import social_admission_session_binding as bindings
from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence
from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_contract as pending
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_storage as durable
from app.services.social_device_challenge_revision_storage import (
    SqlAlchemyTransactionBoundIssuedChallengeRevisionReader,
)
from app.services.social_device_ed25519_association_storage import SqlAlchemyEd25519AssociationStore
from app.services.social_enrollment_v2_reservation_contract import ReservationConfig, _deny, _freeze_config, _sanitized
from app.services.social_session_issuance_v2_authority import BoundSession, NativeV2AuthorityReader, validated_facts
from app.services.social_session_issuance_v2_contract import hex64, milliseconds, trusted_now
from app.services.social_session_issuance_v2_storage import TransactionGuard

RUNTIME_ENABLED = False
_RECORDS = weakref.WeakKeyDictionary()
_POISONED_ROOTS = weakref.WeakSet()


class LockedReservationCandidate:
    """No fields or public constructor; identity alone indexes private authority."""

    __slots__ = ("__weakref__",)

    def __new__(cls):
        _deny()


class _Candidate(NamedTuple):
    owner: object
    guard: object
    input_wire: str
    issuance_id: str
    facts: object
    challenge_revision: int
    payload_wire: str
    trust: object
    observed_at: int
    expires_at: int

    def __repr__(self):
        return "<private locked reservation snapshot>"


def _binding_preimages(f):
    device = bindings.canonical_session_binding_preimage_v1_bytes(
        subject=f.subject,
        device_id=f.device_id,
        x25519_binding_id=f.binding_id,
        social_session_issuance_id=f.issuance_id,
        social_session_token_id=f.token_id,
        parent_oauth_token_id=f.parent_token_id,
        parent_oauth_session_id=f.parent_session_id,
        parent_oauth_browser_generation_id=f.parent_browser_id,
        client_id=f.client_id,
    ).decode("ascii")
    approver = bindings.canonical_approver_session_binding_preimage_v1_bytes(
        subject=f.subject,
        oauth_token_id=f.approver_token_id,
        oauth_session_id=f.approver_session_id,
        oauth_browser_generation_id=f.approver_browser_id,
        client_id=f.client_id,
    ).decode("ascii")
    return device, approver


def _match_input(p, f, config):
    c, e, envelope = p.context, p.enrollment, p.approval.envelope
    pre = envelope.pre_enrollment
    accepted = v2.parse_acceptance_v2(f.acceptance_wire, approval_event_wire=f.approval_wire)
    if (
        f.issuer != config.evidence_config.issuer
        or f.client_id != config.evidence_config.client_id
        or f.backend_id != config.backend_id
        or f.service_principal != config.evidence_config.service_principal
        or c.audience != config.verification_audience
        or e.audience != config.verification_audience
        or p.approval.wire != f.approval_wire
        or accepted.approval.wire != p.approval.wire
        or accepted.acceptance_id != p.acceptance_id
        or f.acceptance_id != p.acceptance_id
        or f.approval_id != p.approval.event_id
        or f.authorization_digest != v2.authorization_v2_digest(envelope.wire)
        or f.pre_enrollment_digest != v2.pre_enrollment_v2_digest(pre.wire)
        or f.operation_id != envelope.context.pairing_id
        or pre.pairing_id != f.operation_id
        or f.input_digest != v2.preaccepted_enrollment_verification_input_v2_digest(p.wire)
        or (f.subject, f.device_id, f.request_id) != (pre.subject, pre.device_id, pre.request_id)
        or (c.subject, c.device_id) != (f.subject, f.device_id)
        or (e.subject, e.device_id) != (f.subject, f.device_id)
        or (f.binding_id, f.binding_version, f.public_key_commitment)
        != (pre.x25519_binding_id, pre.x25519_binding_version, pre.x25519_public_key_commitment)
        or (c.binding_id, c.binding_version, c.x25519_public_key_commitment)
        != (f.binding_id, f.binding_version, f.public_key_commitment)
        or (e.x25519_binding_id, e.x25519_binding_version, e.x25519_public_key_commitment)
        != (f.binding_id, f.binding_version, f.public_key_commitment)
        or f.binding_expires_at_ms != envelope.x25519_binding_expires_at_ms
        or c.full_proof_id != f.full_proof_id
        or c.approver_full_proof_id != f.full_proof_id
        or c.challenge_kind != "enrollment-v2"
        or c.challenge_id != e.enrollment_challenge_id
        or c.association_id != p.association_id
        or c.association_version != 1
        or c.authority_epoch != 1
        or c.predecessor_association_id is not None
        or c.ed25519_public_key != pre.ed25519_public_key
        or e.ed25519_public_key != pre.ed25519_public_key
        or envelope.semantic.operation != "register"
    ):
        _deny()
    device, approver = _binding_preimages(f)
    bindings.require_session_binding_match_v1(device, c.session_binding)
    bindings.require_approver_session_binding_match_v1(approver, c.approver_session_binding)


def _payload(p, f, config, observed, expires):
    """Internal serialization only; this function does not register a candidate.

    Reuse the ONE canonical serializer and domain helpers from the frozen byte
    contract. No public raw-field payload or signing authority constructor.
    """
    ec = config.evidence_config
    values = dict(
        schema=evidence.EVIDENCE_SCHEMA,
        version=1,
        purpose=ec.purpose,
        iss=ec.issuer,
        aud=ec.audience,
        clientId=ec.client_id,
        servicePrincipal=ec.service_principal,
        subject=f.subject,
        deviceId=f.device_id,
        requestId=f.request_id,
        operation="register",
        operationId=f.operation_id,
        acceptanceId=f.acceptance_id,
        approvalEventId=f.approval_id,
        authorizationDigest=f.authorization_digest,
        associationId=p.association_id,
        associationVersion=1,
        attemptId=p.context.attempt_id,
        enrollmentChallengeId=p.enrollment.enrollment_challenge_id,
        socialSessionIssuanceId=f.issuance_id,
        socialSessionIssuanceRevision=f.revision,
        socialSessionTokenId=f.token_id,
        parentOAuthTokenId=f.parent_token_id,
        parentOAuthSessionId=f.parent_session_id,
        parentOAuthBrowserGenerationId=f.parent_browser_id,
        approverOAuthTokenId=f.approver_token_id,
        approverOAuthSessionId=f.approver_session_id,
        approverOAuthBrowserGenerationId=f.approver_browser_id,
        fullEvidenceId=f.full_evidence_id,
        fullEvidenceVersion=f.full_evidence_version,
        fullSourceEvidenceSha256=f.full_source_evidence_sha256,
        fullProofId=f.full_proof_id,
        x25519BindingId=f.binding_id,
        x25519BindingVersion=f.binding_version,
        x25519PublicKeyCommitment=f.public_key_commitment,
        phoneSessionExpiresAt=f.phone_expires_at_ms,
        approverSessionExpiresAt=f.approver_expires_at_ms,
        fullExpiresAt=f.full_expires_at_ms,
        x25519BindingExpiresAt=f.binding_expires_at_ms,
        observedAt=observed,
        expiresAt=expires,
        reservationRevision=1,
        inputDigest=f.input_digest,
        inputPayloadDigest=evidence.deadline_evidence_input_payload_digest_v1(p.wire),
    )
    values["reservationId"] = evidence._reservation_id_from_values(values)
    values["jti"] = evidence._jti_from_values(values)
    wire = evidence._canonical(values)
    evidence.parse_messaging_device_verification_deadline_evidence_payload_v1(wire, expected_input_wire=p.wire)
    return wire


class NativeReservationAuthority:
    @_sanitized
    def __init__(self, session, *, config=ReservationConfig(), clock):
        self.failed = False
        config = _freeze_config(config)
        self.config = config
        if type(config) is not ReservationConfig or config.enabled is not True or not callable(clock):
            _deny()
        self.clock = clock
        # The reused guard acquires a Connection during construction. Reject
        # an absent caller root FIRST so Session.connection cannot autobegin.
        root = session.get_transaction()
        nested = session.get_nested_transaction()
        if (
            root is None
            or not root.is_active
            or session.in_transaction() is not True
            or not session.is_active
            or nested is not None
            and not nested.is_active
            or session.new
            or session.dirty
            or session.deleted
            or session.get_bind().dialect.name != "postgresql"
        ):
            _deny()
        self.guard = TransactionGuard(session)
        self.port = BoundSession(self.guard)
        self.storage = durable.SqlAlchemyTransactionBoundAtomicAcceptanceStorage(self.port)
        self.native = None
        self.challenge_reader = None
        self.associations = None
        self._states = weakref.WeakKeyDictionary()
        self._active = None
        self._history_identity = None
        self._check()

    def _poison(self):
        self.failed = True
        if hasattr(self, "guard"):
            self.guard.poisoned = True
            _POISONED_ROOTS.add(self.guard.root)
            _POISONED_ROOTS.add(self.guard.connection_root)
        for name in ("storage", "challenge_reader", "associations"):
            port = getattr(self, name, None)
            if port is not None:
                port._failed = True
        if getattr(self, "native", None) is not None:
            self.native.failed = True

    def _check(self):
        if self.failed:
            _deny()
        if self.guard.root in _POISONED_ROOTS or self.guard.connection_root in _POISONED_ROOTS:
            _deny()
        self.guard.check()
        if self.storage._check_transaction() is not self.guard.connection:
            _deny()
        self.guard.check()

    def now(self):
        self._check()
        return milliseconds(trusted_now(self.clock))

    @_sanitized
    def discover(self, input_wire):
        p = v2.parse_preaccepted_enrollment_verification_input_v2(input_wire)
        self._check()
        # PostgreSQL row locks alone do not protect absence. This fixed table
        # lock blocks ALL INSERT/UPDATE writers, not only this new owner.
        self.guard.sql(
            'LOCK TABLE "public"."social_preaccepted_enrollment_v2_atomic_acceptances" IN SHARE ROW EXCLUSIVE MODE'
        )
        rows = self._collisions(p)
        if not rows:
            return None
        if len(rows) != 1:
            _deny()
        stored = durable.parse_stored_atomic_acceptance_v1(rows[0], evidence_config=self.config.evidence_config)
        if stored.input_wire != p.wire or stored.reservation.state != "pending":
            _deny()
        self._live_stored(stored)
        return stored

    def _collisions(self, p, signed=None):
        self._check()
        t = self.storage._table
        values = dict(
            request_id=p.approval.envelope.pre_enrollment.request_id,
            operation_id=p.approval.envelope.context.pairing_id,
            device_id=p.context.device_id,
            acceptance_id=p.acceptance_id,
            challenge_id=p.context.challenge_id,
            association_id=p.association_id,
            input_digest=v2.preaccepted_enrollment_verification_input_v2_digest(p.wire),
        )
        # Reservation identity is already derivable before authority or signing.
        reservation_values = dict(
            acceptanceId=p.acceptance_id,
            associationId=p.association_id,
            deviceId=p.context.device_id,
            enrollmentChallengeId=p.context.challenge_id,
            inputDigest=values["input_digest"],
            operation="register",
            operationId=values["operation_id"],
            requestId=values["request_id"],
            subject=p.context.subject,
        )
        values["reservation_id"] = evidence._reservation_id_from_values(reservation_values)
        if signed is not None:
            values.update(
                evidence_token_id=signed.reservation.evidence_token_id,
                evidence_digest=signed.reservation.evidence_digest,
            )
        rows = (
            self.guard.connection.execute(
                select(t)
                .where(or_(*(t.c[name] == value for name, value in values.items())))
                .order_by(t.c.reservation_id)
                .with_for_update()
                .execution_options(autoflush=False)
            )
            .mappings()
            .all()
        )
        self._check()
        return tuple(dict(row) for row in rows)

    def _live_stored(self, stored):
        r = stored.reservation
        if r.state != "pending" or not r.created_at <= self.now() < r.expires_at:
            _deny()
        auth = evidence.verify_messaging_device_verification_deadline_evidence_v1(
            stored.evidence_compact_jws,
            config=self.config.evidence_config,
            expected_input_wire=stored.input_wire,
            now=r.created_at,
        )
        projection = evidence.project_authenticated_messaging_device_verification_deadline_evidence_v1(auth)
        if (
            projection["keyId"],
            projection["trustRevision"],
            projection["trustRecordId"],
        ) not in self.config.trust_pins:
            _deny()
        if not r.created_at <= self.now() < r.expires_at:
            _deny()
        return projection["claims"]

    def _read_graph(self, p, issuance_id):
        self._check()
        if self.native is None:
            ec = self.config.evidence_config
            self.native = NativeV2AuthorityReader(
                self.port,
                client_id=ec.client_id,
                backend_id=self.config.backend_id,
                principal=ec.service_principal,
                issuer=ec.issuer,
                clock=self.clock,
            )
        locked = self.native.read(hex64(issuance_id), verification_input_wire=p.wire)
        f = validated_facts(locked, self.native)
        _match_input(p, f, self.config)
        if self.challenge_reader is None:
            self.challenge_reader = SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(self.port)
        issued = self.challenge_reader.read_issued_with_revision_in_transaction(
            p.context.challenge_id, observed_at=self.now()
        )
        ch = issued.challenge
        if (
            type(issued.challenge_revision) is not int
            or issued.challenge_revision != 1
            or ch.state != "issued"
            or ch.context.wire != p.context.wire
            or ch.challenge_wire != p.enrollment_wire
            or ch.routing_request_wire is not None
            or ch.inspect_deadline(now=self.now()).disposition != "current"
        ):
            _deny()
        if self.associations is None:
            self.associations = SqlAlchemyEd25519AssociationStore(self.port)
        identities = self.guard.sql(
            "SELECT c.oid::bigint, c.reltype::bigint, c.relowner::bigint, c.relkind, "
            "pg_catalog.to_regclass(c.relname)::oid = c.oid AS resolves, "
            "c.relrowsecurity, c.relforcerowsecurity, "
            "pg_catalog.pg_has_role(current_user, c.relowner, 'MEMBER') AS runtime_owns_or_inherits "
            "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relname IN "
            "('social_device_ed25519_association_chains','social_device_ed25519_association_events',"
            "'social_device_enrollment_admission_receipts') ORDER BY c.relname"
        ).all()
        identities = tuple(tuple(row) for row in identities)
        if len(identities) != 3 or any(row[3:] != ("r", True, False, False, False) for row in identities):
            _deny()
        if self._history_identity is None:
            self._history_identity = identities
        elif self._history_identity != identities:
            _deny()
        history = self.associations.lock_history(f.subject, f.device_id)
        if history.current is not None or history.history or history.authority_epoch != 0:
            _deny()
        # Same guarded Connection, no legacy orchestration or cached ORM read.
        # Damaged JSON raises and poisons rather than proving receipt absence.
        receipt = self.guard.sql(
            "SELECT receipt_id FROM public.social_device_enrollment_admission_receipts "
            "WHERE challenge_id = :challenge OR proposed_association_id = :association "
            "OR ((authority_wire::jsonb ->> 'deviceId') = :device "
            "AND (authority_wire::jsonb ->> 'subject') = :subject) FOR UPDATE",
            dict(challenge=p.context.challenge_id, association=p.association_id, device=f.device_id, subject=f.subject),
        ).all()
        if receipt:
            _deny()
        self._check()
        validated_facts(locked, self.native)
        v2.validate_preaccepted_enrollment_time_v2(
            p.wire,
            now_ms=self.now(),
            phone_session_expires_at_ms=f.phone_expires_at_ms,
            approver_session_expires_at_ms=f.approver_expires_at_ms,
            full_expires_at_ms=f.full_expires_at_ms,
            x25519_binding_expires_at_ms=f.binding_expires_at_ms,
        )
        return f, issued.challenge_revision

    @_sanitized
    def prepare(self, input_wire, issuance_id):
        self._active = None
        p = v2.parse_preaccepted_enrollment_verification_input_v2(input_wire)
        # Always acquire serialization through the native lookup, even if a
        # caller directly invokes this internal owner seam.
        discovered = self.discover(p.wire)
        f, revision = self._read_graph(p, issuance_id)
        if discovered is not None:
            claims = self._live_stored(discovered)
            if discovered.reservation.challenge_revision != revision or claims.payload_wire != _payload(
                p, f, self.config, claims.observed_at, claims.expires_at
            ):
                _deny()
            return discovered
        trust = self.config.selected_trust()
        observed = self.now()  # after ALL lock waits; one immutable observation
        expires = min(
            observed + evidence.MAX_EVIDENCE_LIFETIME_MS,
            f.phone_expires_at_ms,
            f.approver_expires_at_ms,
            f.full_expires_at_ms,
            f.binding_expires_at_ms,
            p.enrollment.expires_at,
            p.approval.envelope.pre_enrollment.expires_at,
            trust.not_after,
        )
        if not trust.not_before <= observed < expires or trust.revoked_at is not None:
            _deny()
        candidate = object.__new__(LockedReservationCandidate)
        record = _Candidate(
            self,
            self.guard,
            p.wire,
            issuance_id,
            f,
            revision,
            _payload(p, f, self.config, observed, expires),
            trust,
            observed,
            expires,
        )
        _RECORDS[candidate] = record
        self._states[candidate] = "ready"
        self._active = weakref.ref(candidate)
        return candidate

    def _candidate(self, candidate, state):
        if type(candidate) is not LockedReservationCandidate or candidate not in _RECORDS:
            _deny()
        record = _RECORDS[candidate]
        if (
            record.owner is not self
            or record.guard is not self.guard
            or self._states.get(candidate) != state
            or self._active is None
            or self._active() is not candidate
        ):
            _deny()
        self._check()
        if not record.observed_at <= self.now() < record.expires_at:
            _deny()
        if self.config.selected_trust() != record.trust:
            _deny()
        return record

    @_sanitized
    def _claim_signing(self, candidate):
        record = self._candidate(candidate, "ready")
        self._states[candidate] = "signing"
        self._recheck(record)
        return record

    def _recheck(self, record):
        p = v2.parse_preaccepted_enrollment_verification_input_v2(record.input_wire)
        f, revision = self._read_graph(p, record.issuance_id)
        if (
            revision != record.challenge_revision
            or _payload(p, f, self.config, record.observed_at, record.expires_at) != record.payload_wire
        ):
            _deny()
        if not record.observed_at <= self.now() < record.expires_at:
            _deny()

    @_sanitized
    def _signed(self, candidate):
        record = self._candidate(candidate, "signing")
        self._recheck(record)
        self._states[candidate] = "signed"

    @_sanitized
    def persist(self, candidate, compact_jws):
        record = self._candidate(candidate, "signed")
        self._recheck(record)
        authenticated = evidence.verify_messaging_device_verification_deadline_evidence_v1(
            compact_jws,
            config=self.config.evidence_config,
            expected_input_wire=record.input_wire,
            now=self.now(),
        )
        if (
            authenticated.claims.payload_wire != record.payload_wire
            or authenticated.trust_record_id != record.trust.trust_record_id
        ):
            _deny()
        stored = self.storage.reserve_pending(
            evidence_compact_jws=compact_jws,
            evidence_config=self.config.evidence_config,
            expected_input_wire=record.input_wire,
            observed_at=record.observed_at,
            challenge_revision=record.challenge_revision,
            now=self.now(),
        )
        self._recheck(record)  # expiry/continuity after persistence; caller rollback on failure
        p = v2.parse_preaccepted_enrollment_verification_input_v2(record.input_wire)
        rows = self._collisions(p, stored)
        if len(rows) != 1:
            _deny()
        reparsed = durable.parse_stored_atomic_acceptance_v1(rows[0], evidence_config=self.config.evidence_config)
        expected = pending.canonical_pending_atomic_acceptance_reservation_v1_bytes(
            evidence_compact_jws=compact_jws,
            evidence_config=self.config.evidence_config,
            expected_input_wire=record.input_wire,
            observed_at=record.observed_at,
            challenge_revision=record.challenge_revision,
        ).decode("ascii")
        if (
            reparsed != stored
            or reparsed.input_wire != record.input_wire
            or reparsed.evidence_compact_jws != compact_jws
            or reparsed.reservation.wire != expected
        ):
            _deny()
        self._live_stored(reparsed)
        self._states[candidate] = "persisted"
        return reparsed

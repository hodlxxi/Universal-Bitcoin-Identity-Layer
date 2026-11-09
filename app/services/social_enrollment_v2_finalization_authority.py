"""Locked V2 owner; ordinary parsed model output is never a write capability."""

import weakref
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from typing import NamedTuple

from sqlalchemy import event, select

from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence
from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_contract as canonical
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_storage as durable
from app.services import social_preaccepted_enrollment_verification_statement_v2 as statement
from app.services.social_enrollment_v2_finalization_contract import _deny, _sanitized, freeze_config
from app.services.social_enrollment_v2_reservation_authority import NativeReservationAuthority, _match_input, _payload
from app.services.social_session_issuance_v2_authority import validated_facts

RUNTIME_ENABLED = False
_PLANS = weakref.WeakKeyDictionary()
_OWNERS = weakref.WeakKeyDictionary()
_DISCOVERIES = weakref.WeakKeyDictionary()
_ROUTES = weakref.WeakKeyDictionary()
_Reservation = namedtuple("_Reservation", canonical.AtomicAcceptanceReservationV1.__slots__)
_Reservation.__repr__ = lambda self: "<private immutable reservation snapshot>"


class _Stored(NamedTuple):
    reservation: object
    input_wire: str
    evidence_compact_jws: str

    def __repr__(self):
        return "<private immutable authenticated reservation>"


def _stored_snapshot(stored):
    if (
        type(stored) is not durable.StoredAtomicAcceptanceV1
        or type(stored.reservation) is not canonical.AtomicAcceptanceReservationV1
    ):
        _deny()
    r = stored.reservation
    parsed = canonical.parse_atomic_acceptance_reservation_v1(r.wire)
    for name in r.__slots__:
        if type(getattr(r, name)) is not type(getattr(parsed, name)) or getattr(r, name) != getattr(parsed, name):
            _deny()
    return _Stored(
        _Reservation(*(getattr(parsed, name) for name in parsed.__slots__)),
        stored.input_wire,
        stored.evidence_compact_jws,
    )


class _Observation(NamedTuple):
    wire: str
    observed_at: int

    def __repr__(self):
        return "<private immutable finalization observation>"


class _Receipt(NamedTuple):
    wire: str


class _CanonicalPlan(NamedTuple):
    observation: _Observation
    effect_wire: str
    effect_id: str
    effect_digest: str
    receipt: _Receipt
    reservation_after_wire: str
    finalization_request_digest: str

    def __repr__(self):
        return "<private immutable canonical effect plan>"


def _plan_snapshot(plan):
    return _CanonicalPlan(
        _Observation(plan.observation.wire, plan.observation.observed_at),
        plan.effect_wire,
        plan.effect_id,
        plan.effect_digest,
        _Receipt(plan.receipt.wire),
        plan.reservation_after_wire,
        plan.finalization_request_digest,
    )


def _watch_transactions(owner, session, connection):
    """Observe completed SQLAlchemy savepoint ABA, not just current objects.

    Listeners retain only a weak owner reference. Root changes are also pinned
    by the existing guard's native XID. Raw driver/savepoint SQL is outside the
    supported caller contract, as in the original native readers.
    """
    reference = weakref.ref(owner)
    _ROUTES[owner] = (session, connection)
    _check_routes(session, connection)

    def changed(*args):
        value = reference()
        if value is not None:
            value._poison()

    for name in ("after_transaction_create", "after_transaction_end"):
        event.listen(session, name, changed)
    for name in ("savepoint", "rollback_savepoint", "release_savepoint"):
        event.listen(connection, name, changed)


def _check_routes(session, connection):
    from app.models import (
        CurrentEntitlementEvidence,
        OAuthBrowserGeneration,
        OAuthClient,
        OAuthSessionGeneration,
        OAuthToken,
        Session,
        User,
    )
    from app.services.social_messaging_device_storage import SocialMessagingDeviceBindingRow
    from app.services.social_session_issuance_v2_storage import (
        V2Acceptance,
        V2BindingBirth,
        V2Issuance,
        V2Offer,
        V2Parent,
        V2TokenBirth,
    )

    for model in (
        User,
        CurrentEntitlementEvidence,
        OAuthBrowserGeneration,
        OAuthClient,
        OAuthSessionGeneration,
        OAuthToken,
        Session,
        SocialMessagingDeviceBindingRow,
        V2Acceptance,
        V2BindingBirth,
        V2Issuance,
        V2Offer,
        V2Parent,
        V2TokenBirth,
        durable.SocialPreacceptedEnrollmentV2AtomicAcceptanceRow,
    ):
        for bind in (session.get_bind(mapper=model), session.get_bind(clause=model.__table__)):
            if bind is not connection and bind is not connection.engine:
                _deny()


class LockedFinalizationPlan:
    __slots__ = ("__weakref__",)

    def __new__(cls):
        _deny()

    def __init_subclass__(cls, **kwargs):
        _deny()

    def __copy__(self):
        _deny()

    def __deepcopy__(self, memo):
        _deny()

    def __reduce_ex__(self, protocol):
        _deny()


class _Plan(NamedTuple):
    owner: object
    guard: object
    stored: object
    input_wire: str
    issuance_id: str
    facts: object
    revision: int
    statement_wire: str
    canonical_plan: object
    evidence_pin: tuple
    statement_pin: tuple

    def __repr__(self):
        return "<private transaction-bound finalization plan>"


class NativeFinalizationAuthority(NativeReservationAuthority):
    def _check(self):
        super()._check()
        routes = _ROUTES.get(self)
        if routes is not None:
            _check_routes(*routes)

    @_sanitized
    def __init__(self, session, *, config, clock):
        self.failed = False
        self.finalization_config = freeze_config(config)
        if not self.finalization_config.enabled or not callable(clock):
            _deny()
        self._millisecond_clock = clock

        def native_clock():
            value = canonical._integer(clock())
            return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=value)

        super().__init__(session, config=self.finalization_config.reservation_config, clock=native_clock)
        self._plan_states = weakref.WeakKeyDictionary()
        _OWNERS[self] = (self.guard, self.port, self.storage)
        _watch_transactions(self, session, self.guard.connection)

    def now(self):
        self._check()
        return canonical._integer(self._millisecond_clock())

    @_sanitized
    def discover_finalization(self, reservation_id, revision, input_wire, evidence_wire, statement_wire):
        """Exact decision row is discovered before any current authority read."""
        p = v2.parse_preaccepted_enrollment_verification_input_v2(input_wire)
        if type(revision) is not int or revision != 1:
            _deny()
        key = canonical._hex64(reservation_id)
        self._check()
        self.guard.sql(
            'LOCK TABLE "public"."social_preaccepted_enrollment_v2_atomic_acceptances" IN SHARE ROW EXCLUSIVE MODE'
        )
        rows = self._collisions(p)
        if len(rows) != 1:
            _deny()
        stored = durable.parse_stored_atomic_acceptance_v1(
            rows[0],
            evidence_config=self.config.evidence_config,
            statement_config=self.finalization_config.statement_config,
        )
        r = stored.reservation
        if (
            r.reservation_id != key
            or r.reservation_revision != revision
            or stored.input_wire != p.wire
            or stored.evidence_compact_jws != evidence_wire
            or r.state not in ("pending", "accepted")
            or r.state == "accepted"
            and stored.statement_compact_jws != statement_wire
        ):
            _deny()
        at = r.decided_at if r.state == "accepted" else self.now()
        self.authenticate(stored, statement_wire, at)
        self._discovered = stored
        _DISCOVERIES[self] = (stored, _stored_snapshot(stored))
        self._check()
        return stored

    def authenticate(self, stored, statement_wire, at):
        auth = evidence.verify_messaging_device_verification_deadline_evidence_v1(
            stored.evidence_compact_jws,
            config=self.config.evidence_config,
            expected_input_wire=stored.input_wire,
            now=at,
        )
        projection = evidence.project_authenticated_messaging_device_verification_deadline_evidence_v1(auth)
        ep = (projection["keyId"], projection["trustRevision"], projection["trustRecordId"])
        if ep not in self.config.trust_pins:
            _deny()
        claims = projection["claims"]
        p = v2.parse_preaccepted_enrollment_verification_input_v2(stored.input_wire)
        authenticated = statement.verify_social_preaccepted_enrollment_verification_statement_v2(
            statement_wire,
            config=self.finalization_config.statement_config,
            expected_context_wire=p.context.wire,
            expected_input_wire=p.wire,
            now=at,
            phone_session_expires_at_ms=claims.phone_session_expires_at,
            approver_session_expires_at_ms=claims.approver_session_expires_at,
            full_expires_at_ms=claims.full_expires_at,
            x25519_binding_expires_at_ms=claims.x25519_binding_expires_at,
        )
        sp = statement.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(authenticated)
        pins = [pin for pin in self.finalization_config.statement_pins if pin.key_id == sp["keyId"]]
        if len(pins) != 1:
            _deny()
        pin = pins[0]
        if (
            pin.fingerprint != sp["keyFingerprint"]
            or pin.revoked_at is not None
            or not pin.not_before <= sp["issuedAt"] <= at < sp["expiresAt"] <= pin.not_after
            or not claims.observed_at <= sp["issuedAt"]
            or sp["expiresAt"] > claims.expires_at
        ):
            _deny()
        return auth, claims, ep, tuple(pin.__getattribute__(name) for name in pin.__slots__)

    @_sanitized
    def prepare_finalization(self, stored, statement_wire, issuance_id):
        discovery = _DISCOVERIES.get(self)
        if (
            discovery is None
            or stored is not discovery[0]
            or stored.reservation.state != "pending"
            or _stored_snapshot(stored) != discovery[1]
        ):
            _deny()
        p = v2.parse_preaccepted_enrollment_verification_input_v2(stored.input_wire)
        f, revision = self._read_graph(p, issuance_id)
        # Frozen canonical provenance must agree at the ORIGINAL signed time.
        _, claims, _, _ = self.authenticate(stored, statement_wire, self.now())
        if revision != stored.reservation.challenge_revision or claims.payload_wire != _payload(
            p, f, self.config, claims.observed_at, claims.expires_at
        ):
            _deny()
        # The native evidence's same validated facts, not caller claims, supply
        # the closed authority projection. Reuse the existing exact constructor.
        observed = self.now()
        native_claims = evidence.parse_messaging_device_verification_deadline_evidence_payload_v1(
            _payload(p, f, self.config, claims.observed_at, claims.expires_at),
            expected_input_wire=p.wire,
            freshness_profile=self.config.evidence_config.freshness_profile,
        )
        authority_wire = canonical._authority_wire_from_authenticated_claims(native_claims, observed)
        observation = canonical._canonical(
            dict(
                schema=canonical.FINALIZATION_OBSERVATION_SCHEMA,
                version=1,
                reservationId=stored.reservation.reservation_id,
                reservationRevision=1,
                challengeId=p.context.challenge_id,
                challengeRevision=revision,
                challengeState="issued",
                associationState="absent",
                associationCurrentId=None,
                associationVersion=0,
                associationAuthorityEpoch=0,
                authoritySnapshot=authority_wire,
                authoritySnapshotDigest=canonical.current_authority_snapshot_digest_v1(authority_wire),
                observedAt=observed,
            )
        )
        plan = canonical.model_atomic_acceptance_and_cas_v1(
            reservation_wire=stored.reservation.wire,
            finalization_observation_wire=observation,
            expected_input_wire=p.wire,
            expected_context_wire=p.context.wire,
            evidence_compact_jws=stored.evidence_compact_jws,
            evidence_config=self.config.evidence_config,
            statement_compact_jws=statement_wire,
            statement_config=self.finalization_config.statement_config,
            decided_at=observed,
        )
        _, _, ep, sp = self.authenticate(stored, statement_wire, self.now())
        candidate = object.__new__(LockedFinalizationPlan)
        _PLANS[candidate] = _Plan(
            self,
            self.guard,
            _stored_snapshot(stored),
            p.wire,
            issuance_id,
            f,
            revision,
            statement_wire,
            _plan_snapshot(plan),
            ep,
            sp,
        )
        self._plan_states[candidate] = "prepared"
        self.resolve(candidate)
        return candidate

    def resolve(self, candidate, *, expected_state="prepared"):
        self._check()
        if _OWNERS.get(self) != (self.guard, self.port, self.storage):
            _deny()
        record = _PLANS.get(candidate) if type(candidate) is LockedFinalizationPlan else None
        if (
            record is None
            or record.owner is not self
            or record.guard is not self.guard
            or self._plan_states.get(candidate) != expected_state
        ):
            _deny()
        # Resolve the immutable record ONCE; never inspect public candidate facts.
        return record

    @_sanitized
    def recheck(self, candidate, *, phase):
        record = self.resolve(candidate, expected_state=phase)
        p = v2.parse_preaccepted_enrollment_verification_input_v2(record.input_wire)
        locked = self.native.read(record.issuance_id, verification_input_wire=p.wire)
        f = validated_facts(locked, self.native)
        _match_input(p, f, self.config)
        if f._replace(observed_at_ms=record.facts.observed_at_ms) != record.facts:
            _deny()
        at = self.now()
        _, _, ep, sp = self.authenticate(record.stored, record.statement_wire, at)
        if (
            ep != record.evidence_pin
            or sp != record.statement_pin
            or at < record.canonical_plan.observation.observed_at
        ):
            _deny()
        self._check()
        return record

    def move(self, candidate, previous, following):
        self.resolve(candidate, expected_state=previous)
        self._plan_states[candidate] = following

    def locked_row(self, reservation_id):
        t = self.storage._table
        rows = (
            self.guard.connection.execute(
                select(t)
                .where(t.c.reservation_id == reservation_id)
                .with_for_update()
                .execution_options(autoflush=False)
            )
            .mappings()
            .all()
        )
        if len(rows) != 1:
            _deny()
        return durable.parse_stored_atomic_acceptance_v1(
            rows[0],
            evidence_config=self.config.evidence_config,
            statement_config=self.finalization_config.statement_config,
        )

"""Dormant first-enrollment challenge producer, on the existing native graph.

No new byte domain, association write, HTTP route, environment connection,
signing key or default factory installation. A challenge is not admission.
"""

import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import wraps

from app.services.social_enrollment_v2_runtime_composition import _fresh_clock, _run_owned, _system_clock

RUNTIME_ENABLED = False
DM_TRANSPORT_ENABLED = False
DENIED_MESSAGE = "social enrollment v2 challenge unavailable"
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# One original challenge per immutable native issuance/session commitment.
# LIMIT 2 distinguishes absence, a single original, and an ambiguous history.
LOOKUP_SQL = (
    "SELECT challenge_id FROM public.social_device_admission_challenges "
    "WHERE context_wire::jsonb ->> 'sessionBinding' = :binding "
    "ORDER BY challenge_id LIMIT 2 FOR UPDATE"
)
LOCK_SQL = 'LOCK TABLE "public"."social_device_admission_challenges" IN SHARE ROW EXCLUSIVE MODE'


class EnrollmentChallengeUnavailable(ValueError):
    def __init__(self):
        super().__init__(DENIED_MESSAGE)


def _deny():
    raise EnrollmentChallengeUnavailable() from None


def _sanitized(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            if args and hasattr(args[0], "_poison"):
                args[0]._poison()
        _deny()

    return call


@dataclass(frozen=True, slots=True, repr=False)
class EnrollmentChallengeConfig:
    enabled: bool = False
    client_id: str = ""
    backend_id: str = ""
    service_principal: str = ""
    issuer: str = ""
    audience: str = ""
    lifetime_ms: int = 60_000

    @_sanitized
    def __post_init__(self):
        if type(self.enabled) is not bool or type(self.lifetime_ms) is not int or not 1 <= self.lifetime_ms <= 60_000:
            _deny()
        names = (self.client_id, self.backend_id, self.service_principal, self.issuer, self.audience)
        if any(type(value) is not str for value in names):
            _deny()
        if not self.enabled and names == ("", "", "", "", ""):
            return
        for value in names[:3]:
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}", value) is None:
                _deny()
        from app.services.social_messaging_device_verification_deadline_evidence_v1 import _https_origin

        _https_origin(self.issuer)
        _https_origin(self.audience)


def _freeze(config):
    if type(config) is not EnrollmentChallengeConfig:
        _deny()
    return EnrollmentChallengeConfig(*(getattr(config, name) for name in config.__slots__))


@dataclass(frozen=True, slots=True, repr=False)
class ProvisionalEnrollmentChallenge:
    context_wire: str
    enrollment_wire: str
    approval_event_wire: str
    issued_at: int
    expires_at: int
    challenge_revision: int = field(default=1, init=False)
    publication_status: str = field(default="provisional_until_caller_commit", init=False)
    final_admission: str = field(default="denied", init=False)
    bearer_authority: str = field(default="none", init=False)


@dataclass(frozen=True, slots=True, repr=False)
class CommittedEnrollmentChallenge:
    context_wire: str
    enrollment_wire: str
    approval_event_wire: str
    issued_at: int
    expires_at: int
    challenge_revision: int = field(default=1, init=False)
    publication_status: str = field(default="committed", init=False)
    final_admission: str = field(default="denied", init=False)
    bearer_authority: str = field(default="none", init=False)


def _binding(facts):
    from app.services.social_admission_session_binding import derive_session_binding_v1
    from app.services.social_enrollment_v2_reservation_authority import _binding_preimages

    device, _ = _binding_preimages(facts)
    return derive_session_binding_v1(device)


def _wires(facts, approval, config, *, challenge_id, attempt_id, issued_at, expires_at):
    from app.services import social_admission_session_binding as bindings
    from app.services import social_messaging_device_admission_contract as admission
    from app.services.social_enrollment_v2_reservation_authority import _binding_preimages
    from app.services.social_messaging_device_ed25519_association_lifecycle import association_id_v1
    from app.services.social_messaging_device_proof_profile import DEVICE_PROOF_PROFILE, canonical_enrollment_v2_bytes

    pre = approval.envelope.pre_enrollment
    enrollment = canonical_enrollment_v2_bytes(
        audience=config.audience,
        device_id=facts.device_id,
        ed25519_public_key=pre.ed25519_public_key,
        enrollment_challenge_id=challenge_id,
        expires_at=expires_at,
        issued_at=issued_at,
        subject=facts.subject,
        x25519_binding_id=facts.binding_id,
        x25519_binding_version=facts.binding_version,
        x25519_public_key_commitment=facts.public_key_commitment,
    ).decode("ascii")
    device, approver = _binding_preimages(facts)
    context = admission.canonical_verification_context_v1_bytes(
        challenge_kind="enrollment-v2",
        challenge_id=challenge_id,
        attempt_id=attempt_id,
        audience=config.audience,
        subject=facts.subject,
        device_id=facts.device_id,
        binding_id=facts.binding_id,
        binding_version=facts.binding_version,
        x25519_public_key_commitment=facts.public_key_commitment,
        profile=DEVICE_PROOF_PROFILE,
        ed25519_public_key=pre.ed25519_public_key,
        association_id=association_id_v1(enrollment, 1, None),
        association_version=1,
        predecessor_association_id=None,
        authority_epoch=1,
        session_binding=bindings.derive_session_binding_v1(device),
        approver_session_binding=bindings.derive_approver_session_binding_v1(approver),
        full_proof_id=facts.full_proof_id,
        approver_full_proof_id=facts.full_proof_id,
    ).decode("ascii")
    return context, enrollment


class NativeV2EnrollmentChallengeOwner:
    """One guarded caller root, first enrollment only; no commit or association.

    Uses the native issuance principal with challenge INSERT, not the separate
    finalization principal whose closed role profile forbids that privilege.
    The existing immutable revision trigger alone creates generation 1.
    """

    @_sanitized
    def __init__(self, session, *, lifecycle, config=EnrollmentChallengeConfig(), clock):
        from app.services.oauth_session_lifecycle import SqlAlchemyOAuthSessionLifecycle
        from app.services.social_device_challenge_revision_storage import (
            SqlAlchemyTransactionBoundIssuedChallengeRevisionReader,
        )
        from app.services.social_device_challenge_store import SqlAlchemyDeviceChallengeStore
        from app.services.social_enrollment_v2_finalization_authority import _watch_transactions
        from app.services.social_session_issuance_v2_authority import NativeV2AuthorityReader

        self.failed = False
        self.used = False
        self._result = None
        self.config = _freeze(config)
        self.lifecycle = lifecycle
        if (
            self.config.enabled is not True
            or type(lifecycle) is not SqlAlchemyOAuthSessionLifecycle
            or lifecycle.client_id != self.config.client_id
            or lifecycle._validation.issuer != self.config.issuer
            or not callable(clock)
        ):
            _deny()
        self._clock = _fresh_clock(clock)
        root = session.get_transaction()
        if root is None or not root.is_active or session.get_nested_transaction() is not None:
            _deny()  # Never let Connection acquisition autobegin a caller transaction.
        self.native = NativeV2AuthorityReader(
            session,
            client_id=self.config.client_id,
            backend_id=self.config.backend_id,
            principal=self.config.service_principal,
            issuer=self.config.issuer,
            clock=lambda: _EPOCH + timedelta(milliseconds=self._clock()),
        )
        self.guard = self.native.guard
        _watch_transactions(self, session, self.guard.connection)
        self.revisions = SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(self.native.port)
        self.store = SqlAlchemyDeviceChallengeStore(self.native.port)

    def _poison(self):
        self.failed = True
        if hasattr(self, "guard"):
            self.guard.poisoned = True
        if hasattr(self, "native"):
            self.native.failed = True
        for name in ("store", "revisions"):
            if hasattr(self, name):
                getattr(self, name)._failed = True

    def _check(self):
        from app.services.social_enrollment_v2_finalization_authority import _ROUTES, _check_routes

        if self.failed:
            _deny()
        self.native._check()
        routes = _ROUTES.get(self)
        if routes is None:
            _deny()
        _check_routes(*routes)

    def _authority(self, issuance_id, bearer):
        from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
        from app.services.social_session_issuance_v2_authority import validated_facts

        self._check()
        viewer = self.lifecycle._validate(self.native.port, bearer)
        facts = validated_facts(self.native.read(issuance_id), self.native)
        viewer = self.lifecycle._validate(self.native.port, bearer)
        approval = v2.parse_approval_event_v2(facts.approval_wire)
        envelope, pre = approval.envelope, approval.envelope.pre_enrollment
        accepted = v2.parse_acceptance_v2(facts.acceptance_wire, approval_event_wire=approval.wire)
        if (
            viewer.jti != facts.token_id
            or viewer.subject != facts.subject
            or envelope.semantic.operation != "register"
            or accepted.acceptance_id != facts.acceptance_id
            or approval.event_id != facts.approval_id
            or envelope.context.pairing_id != facts.operation_id
            or facts.authorization_digest != v2.authorization_v2_digest(envelope.wire)
            or facts.pre_enrollment_digest != v2.pre_enrollment_v2_digest(pre.wire)
            or (facts.subject, facts.device_id, facts.request_id) != (pre.subject, pre.device_id, pre.request_id)
            or (facts.binding_id, facts.binding_version, facts.public_key_commitment)
            != (pre.x25519_binding_id, pre.x25519_binding_version, pre.x25519_public_key_commitment)
        ):
            _deny()
        return facts, approval

    def _lookup(self, facts):
        rows = self.guard.sql(LOOKUP_SQL, {"binding": _binding(facts)}).all()
        if len(rows) > 1:
            _deny()
        return rows

    def _read(self, challenge_id, facts, approval):
        issued = self.revisions.read_issued_with_revision_in_transaction(challenge_id, observed_at=self._clock())
        challenge = issued.challenge
        if challenge.issued_at < approval.envelope.pre_enrollment.issued_at or challenge.expires_at > min(
            challenge.issued_at + self.config.lifetime_ms,
            self.native._deadline_ms,
            approval.envelope.pre_enrollment.expires_at,
        ):
            _deny()
        expected = _wires(
            facts,
            approval,
            self.config,
            challenge_id=challenge.context.challenge_id,
            attempt_id=challenge.context.attempt_id,
            issued_at=challenge.issued_at,
            expires_at=challenge.expires_at,
        )
        if (
            issued.challenge_revision != 1
            or (challenge.context.wire, challenge.challenge_wire) != expected
            or challenge.actual_request_wire is not None
            or challenge.routing_request_wire is not None
        ):
            _deny()
        # The revision lookup can wait. Its earlier observed_at is not freshness
        # after that wait; sample again against every retained native deadline.
        if not challenge.issued_at <= self._clock() < min(challenge.expires_at, self.native._deadline_ms):
            _deny()
        return challenge

    @_sanitized
    def create(self, issuance_id, *, viewer_bearer):
        if self.used or self.failed:
            _deny()
        self.used = True
        facts, approval = self._authority(issuance_id, viewer_bearer)
        # Native graph locks precede the fixed table lock. It serializes absence
        # against INSERT writers, without inventing an unenforced advisory key.
        self.guard.sql(LOCK_SQL)
        self._check()
        if self._clock() >= self.native._deadline_ms:
            _deny()
        rows = self._lookup(facts)
        if rows:
            challenge_id = rows[0][0]
        else:
            observed = self._clock()  # The challenge timer starts after lock waits.
            expires = min(observed + self.config.lifetime_ms, self.native._deadline_ms)
            if not approval.envelope.pre_enrollment.issued_at <= observed < expires:
                _deny()
            challenge_id, attempt_id = secrets.token_hex(32), secrets.token_hex(32)
            context, enrollment = _wires(
                facts,
                approval,
                self.config,
                challenge_id=challenge_id,
                attempt_id=attempt_id,
                issued_at=observed,
                expires_at=expires,
            )
            self.store.create_issued(context_wire=context, challenge_wire=enrollment)
        challenge = self._read(challenge_id, facts, approval)
        result = ProvisionalEnrollmentChallenge(
            challenge.context.wire, challenge.challenge_wire, approval.wire, challenge.issued_at, challenge.expires_at
        )
        self._result = result
        self._snapshot = tuple(getattr(result, name) for name in result.__slots__)
        self._facts, self._issuance, self._bearer = facts, issuance_id, viewer_bearer
        return result

    @_sanitized
    def check_before_commit(self, result):
        if (
            self.failed
            or result is not self._result
            or type(result) is not ProvisionalEnrollmentChallenge
            or tuple(getattr(result, name) for name in result.__slots__) != self._snapshot
        ):
            _deny()
        facts, approval = self._authority(self._issuance, self._bearer)
        if facts._replace(observed_at_ms=self._facts.observed_at_ms) != self._facts:
            _deny()
        rows = self._lookup(facts)
        if len(rows) != 1:
            _deny()
        challenge = self._read(rows[0][0], facts, approval)
        if (challenge.context.wire, challenge.challenge_wire, approval.wire) != (
            result.context_wire,
            result.enrollment_wire,
            result.approval_event_wire,
        ):
            _deny()
        return result.issued_at, min(result.expires_at, self.native._deadline_ms)


class EnrollmentV2ChallengeComposition:
    @_sanitized
    def __init__(self, *, lifecycle, config=EnrollmentChallengeConfig(), clock=None):
        from app.services.oauth_session_lifecycle import SqlAlchemyOAuthSessionLifecycle

        self.config = _freeze(config)
        if (
            self.config.enabled is not True
            or type(lifecycle) is not SqlAlchemyOAuthSessionLifecycle
            or lifecycle.client_id != self.config.client_id
            or lifecycle._validation.issuer != self.config.issuer
            or not callable(lifecycle._factory)
            or clock is not None
            and not callable(clock)
        ):
            _deny()
        self.lifecycle = lifecycle
        self._factory = lifecycle._factory
        self._clock = _system_clock if clock is None else clock

    @_sanitized
    def challenge(self, issuance_id, *, viewer_bearer):
        def operation(session, now):
            owner = NativeV2EnrollmentChallengeOwner(session, lifecycle=self.lifecycle, config=self.config, clock=now)
            return owner.create(issuance_id, viewer_bearer=viewer_bearer), owner.check_before_commit

        result = _run_owned(self._factory, self._clock, operation)
        return CommittedEnrollmentChallenge(
            result.context_wire, result.enrollment_wire, result.approval_event_wire, result.issued_at, result.expires_at
        )


def build_enrollment_v2_challenge_composition(
    *, enabled=False, lifecycle=None, config=EnrollmentChallengeConfig(), clock=None
):
    if enabled is False:
        return None
    if enabled is not True:
        _deny()
    return EnrollmentV2ChallengeComposition(lifecycle=lifecycle, config=config, clock=clock)

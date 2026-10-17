"""Explicit caller transaction ownership; no HTTP, factory install or DB fallback.

The small transaction boundary imports no infrastructure. Actual V2 owners and
their frozen public trust are loaded only by explicit enabled composition.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from time import time_ns

from app.services.social_enrollment_v2_catalog_roles import catalog_role_scope

RUNTIME_ENABLED = False
DM_TRANSPORT_ENABLED = False
DENIED_MESSAGE = "social enrollment v2 composition unavailable"
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class EnrollmentCompositionUnavailable(ValueError):
    def __init__(self):
        super().__init__(DENIED_MESSAGE)


def _deny():
    raise EnrollmentCompositionUnavailable() from None


def _integer(value):
    if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
        _deny()
    return value


def _system_clock():
    return time_ns() // 1_000_000


def _fresh_clock(clock):
    previous = None

    def now():
        nonlocal previous
        value = _integer(clock())
        if previous is not None and value < previous:
            _deny()
        previous = value
        return value

    return now


def _check_window(window, current):
    if window is None:
        return  # Retained historical receipt only; no renewed current authority.
    if type(window) is not tuple or len(window) != 2:
        _deny()
    start, end = (_integer(value) for value in window)
    if not start <= current < end:
        _deny()


def _run_owned(session_factory, clock, operation, *, challenge_writer_role=None):
    """One fresh Session and root transaction, no retries and no early result.

    operation and its precommit closure are private trusted composition code,
    never request-supplied callbacks or detached authorization results.
    """
    try:
        now = _fresh_clock(clock)
        now()  # Reject an invalid clock before even opening a Session.
        with session_factory() as session:
            if (
                session.get_transaction() is not None
                or session.get_nested_transaction() is not None
                or session.is_active is not True
                or session.new
                or session.dirty
                or session.deleted
            ):
                _deny()
            bind = session.get_bind()
            in_transaction = getattr(bind, "in_transaction", None)
            if callable(in_transaction) and in_transaction() is not False:
                _deny()  # Do not adopt an externally owned Connection transaction.
            with session.begin():
                with catalog_role_scope(session, challenge_writer_role):
                    value, before_commit = operation(session, now)
                    session.flush()
                    window = before_commit(value)
                    _check_window(window, now())
            # A commit failure (including an uncertain outcome) never reaches
            # here. Closing the Session must also finish before publication.
        _check_window(window, now())
        return value
    except Exception:
        pass
    _deny()


@dataclass(frozen=True, slots=True, repr=False)
class CommittedReservation:
    evidence_compact_jws: str = field(repr=False)
    reservation_id: str = field(repr=False)
    observed_at: int
    expires_at: int
    publication_status: str = field(default="committed", init=False)
    final_admission: str = field(default="denied", init=False)
    bearer_authority: str = field(default="none", init=False)


@dataclass(frozen=True, slots=True, repr=False)
class CommittedFinalization:
    receipt_wire: str = field(repr=False)
    historical_recovery: bool
    publication_status: str = field(default="committed", init=False)
    final_admission: str = field(default="denied", init=False)
    bearer_authority: str = field(default="none", init=False)


class SocialEnrollmentV2Composition:
    """Own complete transactions around the existing real V2 owners.

    session_factory must create a fresh PostgreSQL Session against one explicit
    database, without request-dependent binds or an existing transaction. clock
    is trusted server configuration, not a browser timestamp. No credentials,
    connections, enable flags or freshness profiles are read from environment.
    """

    def __init__(self, *, session_factory, signer, config, clock=None):
        try:
            from app.services.social_enrollment_v2_finalization_contract import freeze_config
            from app.services.social_enrollment_v2_reservation_signer import DedicatedRS256EvidenceSigner

            frozen = freeze_config(config)
            if (
                frozen.enabled is not True
                or type(signer) is not DedicatedRS256EvidenceSigner
                or signer._config != frozen.reservation_config
                or not callable(session_factory)
                or clock is not None
                and not callable(clock)
            ):
                _deny()
            self._factory = session_factory
            self._signer = signer
            self._config = frozen
            self._clock = _system_clock if clock is None else clock
            return
        except Exception:
            pass
        _deny()

    def reserve(self, verification_input_wire, *, issuance_id):
        from app.services.social_enrollment_v2_reservation import V2ReservationOwner

        def operation(session, now):
            owner = V2ReservationOwner(
                session,
                signer=self._signer,
                config=self._config.reservation_config,
                clock=lambda: _EPOCH + timedelta(milliseconds=now()),
            )
            result = owner.reserve(verification_input_wire, issuance_id=issuance_id)

            def before_commit(original):
                # The existing discover-before-signing retry performs a fresh
                # locked native read. It returns the ORIGINAL pending bytes and
                # deadline; it cannot issue a second signature or renewal.
                checked = owner.reserve(verification_input_wire, issuance_id=issuance_id)
                if checked != original:
                    _deny()
                return original.observed_at, original.expires_at

            return result, before_commit

        result = _run_owned(
            self._factory, self._clock, operation, challenge_writer_role=self._config.challenge_writer_role
        )
        return CommittedReservation(
            result.evidence_compact_jws, result.reservation_id, result.observed_at, result.expires_at
        )

    def finalize(
        self,
        *,
        reservation_id,
        reservation_revision,
        verification_input_wire,
        evidence_compact_jws,
        statement_compact_jws,
        issuance_id,
    ):
        from app.services.social_enrollment_v2_finalization import V2FinalizationOwner

        def operation(session, now):
            owner = V2FinalizationOwner(session, config=self._config, clock=now)
            result = owner.finalize(
                reservation_id=reservation_id,
                reservation_revision=reservation_revision,
                verification_input_wire=verification_input_wire,
                evidence_compact_jws=evidence_compact_jws,
                statement_compact_jws=statement_compact_jws,
                issuance_id=issuance_id,
            )
            return result, owner.check_before_commit

        result = _run_owned(
            self._factory, self._clock, operation, challenge_writer_role=self._config.challenge_writer_role
        )
        return CommittedFinalization(result.receipt_wire, result.historical_recovery)


def build_social_enrollment_v2_composition(
    *, enabled=False, session_factory=None, signer=None, config=None, clock=None
):
    """Default off even before infrastructure imports. This installs nothing."""
    if enabled is False:
        return None
    if enabled is not True:
        _deny()
    return SocialEnrollmentV2Composition(session_factory=session_factory, signer=signer, config=config, clock=clock)

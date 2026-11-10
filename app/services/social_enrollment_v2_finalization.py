"""Dormant V2 finalization API. Caller alone owns rollback and commit."""

from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
from app.services import social_preaccepted_enrollment_verification_statement_v2 as statement
from app.services.social_enrollment_v2_finalization_authority import NativeFinalizationAuthority
from app.services.social_enrollment_v2_finalization_contract import (
    FinalizationConfig,
    FinalizationResult,
    _deny,
    _sanitized,
)
from app.services.social_enrollment_v2_finalization_storage import NativeV2Effects

RUNTIME_ENABLED = False
DM_TRANSPORT_ENABLED = False


class V2FinalizationOwner:
    @_sanitized
    def __init__(self, session, *, clock, config=FinalizationConfig()):
        self.failed = False
        self.used = False
        self._completed_result = None
        self._completed_plan = None
        self._completed_snapshot = None
        self.authority = NativeFinalizationAuthority(session, config=config, clock=clock)
        self.effects = NativeV2Effects(self.authority)

    def _poison(self):
        self.failed = True
        if hasattr(self, "authority"):
            self.authority._poison()

    @_sanitized
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
        if self.failed or self.used:
            _deny()
        self.used = True
        a = self.authority
        stored = a.discover_finalization(
            reservation_id, reservation_revision, verification_input_wire, evidence_compact_jws, statement_compact_jws
        )
        if stored.reservation.state == "accepted":
            # Original signatures/time and retained native history FIRST. No
            # live NativeV2AuthorityReader or new mutation on this branch.
            _, claims, ep, sp = a.authenticate(stored, statement_compact_jws, stored.reservation.decided_at)
            if claims.social_session_issuance_id != issuance_id:
                _deny()
            receipt = self.effects.verify_history(stored, evidence_pin=ep, statement_pin=sp)
            a.authenticate(stored, statement_compact_jws, stored.reservation.decided_at)
            a._check()
            result = FinalizationResult(receipt, True)
            self._completed_result = result
            self._completed_snapshot = (receipt, True)
            return result
        candidate = a.prepare_finalization(stored, statement_compact_jws, issuance_id)
        self.effects.execute(candidate)
        self.effects.check()
        record = a.recheck(candidate, phase="effects_written")
        p = v2.parse_preaccepted_enrollment_verification_input_v2(record.input_wire)
        accepted = a.storage.finalize_accepted(
            reservation_id,
            finalization_observation_wire=record.canonical_plan.observation.wire,
            expected_input_wire=record.input_wire,
            expected_context_wire=p.context.wire,
            evidence_compact_jws=record.stored.evidence_compact_jws,
            evidence_config=a.config.evidence_config,
            statement_compact_jws=record.statement_wire,
            statement_config=a.finalization_config.statement_config,
            decided_at=record.canonical_plan.observation.observed_at,
        )
        a.move(candidate, "effects_written", "accepted")
        a.recheck(candidate, phase="accepted")
        retained = a.locked_row(reservation_id)
        if retained != accepted or retained.receipt.wire != record.canonical_plan.receipt.wire:
            _deny()
        receipt = self.effects.verify_history(
            retained, evidence_pin=record.evidence_pin, statement_pin=record.statement_pin, provisional=True
        )
        self.effects.check()
        a.recheck(candidate, phase="accepted")
        a.move(candidate, "accepted", "used")
        result = FinalizationResult(receipt, False)
        self._completed_plan = candidate
        self._completed_result = result
        self._completed_snapshot = (receipt, False)
        return result

    @_sanitized
    def check_before_commit(self, result):
        """Recheck this owner's exact result after caller flush, before commit.

        Returns the original exclusive publication interval, or None for an
        authenticated historical receipt. This never commits, renews a signed
        deadline, or promotes a provisional receipt into current admission.
        """
        if (
            self.failed
            or not self.used
            or result is not self._completed_result
            or type(result) is not FinalizationResult
            or (result.receipt_wire, result.historical_recovery) != self._completed_snapshot
            or type(result.historical_recovery) is not bool
        ):
            _deny()
        a = self.authority
        self.effects.check()
        if self._completed_plan is None:
            # finalize already authenticated retained original history at its
            # original decision time. Its locked rows cannot become new work.
            a._check()
            return None
        record = a.recheck(self._completed_plan, phase="used")
        if result.receipt_wire != record.canonical_plan.receipt.wire:
            _deny()
        at = a.now()
        _, claims, _, _ = a.authenticate(record.stored, record.statement_wire, at)
        p = v2.parse_preaccepted_enrollment_verification_input_v2(record.input_wire)
        authenticated = statement.verify_social_preaccepted_enrollment_verification_statement_v2(
            record.statement_wire,
            config=a.finalization_config.statement_config,
            expected_context_wire=p.context.wire,
            expected_input_wire=p.wire,
            now=at,
            phone_session_expires_at_ms=claims.phone_session_expires_at,
            approver_session_expires_at_ms=claims.approver_session_expires_at,
            full_expires_at_ms=claims.full_expires_at,
            x25519_binding_expires_at_ms=claims.x25519_binding_expires_at,
        )
        projection = statement.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(
            authenticated
        )
        expires = min(claims.expires_at, projection["expiresAt"])
        current = a.now()
        if not record.canonical_plan.observation.observed_at <= at <= current < expires:
            _deny()
        return current, expires

"""Dormant public source API: canonical V2 input + native issuance selector only."""

from app.services.social_enrollment_v2_reservation_authority import (
    LockedReservationCandidate,
    NativeReservationAuthority,
)
from app.services.social_enrollment_v2_reservation_contract import (
    ProvisionalReservation,
    ReservationConfig,
    _deny,
    _sanitized,
)
from app.services.social_enrollment_v2_reservation_signer import DedicatedRS256EvidenceSigner

RUNTIME_ENABLED = False
V2_FINALIZATION_IMPLEMENTED = False
DM_TRANSPORT_ENABLED = False


class V2ReservationOwner:
    @_sanitized
    def __init__(self, session, *, signer, clock, config=ReservationConfig()):
        self.failed = False
        if type(signer) is not DedicatedRS256EvidenceSigner or signer._config != config:
            _deny()
        self.authority = NativeReservationAuthority(session, config=config, clock=clock)
        self.signer = signer

    def _poison(self):
        self.failed = True
        if hasattr(self, "authority"):
            self.authority._poison()

    @_sanitized
    def reserve(self, verification_input_wire, *, issuance_id):
        if self.failed:
            _deny()
        prepared = self.authority.prepare(verification_input_wire, issuance_id)
        if type(prepared) is LockedReservationCandidate:
            compact = self.signer.sign(prepared, owner=self.authority)
            stored = self.authority.persist(prepared, compact)
        else:
            stored = prepared
        # Fresh check after every potentially slow authentication/persistence.
        self.authority._live_stored(stored)
        r = stored.reservation
        return ProvisionalReservation(stored.evidence_compact_jws, r.reservation_id, r.created_at, r.expires_at)

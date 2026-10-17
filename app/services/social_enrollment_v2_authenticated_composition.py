"""Phone-authenticated callers on the same original guarded owner transaction.

No HTTP parsing, new authority, SQL, key provider or environment fallback.
The lower-level green owners and their historical recovery stay unchanged.
"""

from datetime import timedelta

from app.services.social_enrollment_v2_runtime_composition import (
    _EPOCH,
    CommittedFinalization,
    CommittedReservation,
    SocialEnrollmentV2Composition,
    _deny,
    _run_owned,
)


class AuthenticatedEnrollmentV2Composition:
    def __init__(self, *, composition, lifecycle):
        from app.services.oauth_session_lifecycle import SqlAlchemyOAuthSessionLifecycle

        if (
            type(composition) is not SocialEnrollmentV2Composition
            or type(lifecycle) is not SqlAlchemyOAuthSessionLifecycle
        ):
            _deny()
        ec = composition._config.reservation_config.evidence_config
        if (
            lifecycle._factory is not composition._factory
            or lifecycle.client_id != ec.client_id
            or lifecycle._validation.issuer != ec.issuer
        ):
            _deny()
        self.composition, self.lifecycle = composition, lifecycle

    def _configuration(self):
        ec = self.composition._config.reservation_config.evidence_config
        if (
            self.lifecycle._factory is not self.composition._factory
            or self.lifecycle.client_id != ec.client_id
            or self.lifecycle._validation.issuer != ec.issuer
        ):
            _deny()
        return self.composition

    def _phone(self, authority, bearer, now):
        from app.services.oauth_bearer_validation import BearerPrincipal
        from app.services.social_session_issuance_v2_contract import milliseconds

        authority._check()
        viewer = self.lifecycle._validate(authority.port, bearer)
        authority._check()
        if type(viewer) is not BearerPrincipal or viewer.client_id != self.lifecycle.client_id:
            _deny()
        interval = milliseconds(viewer.issued_at), milliseconds(viewer.expires_at)
        # Canonical JWT validation may allow clock skew. This publication fence
        # still uses the original exact exclusive phone expiry, with no leeway.
        if not interval[0] <= now() < interval[1]:
            _deny()
        return viewer, interval

    def _evidence_phone(self, authority, bearer, wire, input_wire, issuance_id, now, *, historical=False):
        from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence

        ec = self.composition._config.reservation_config.evidence_config
        at = now()
        if historical:
            # Used ONLY to authenticate original identity before effects. It
            # grants no current freshness; finalize independently decides new
            # work versus exact retained history with its unchanged validators.
            if type(wire) is not str or not 0 < len(wire) <= evidence.MAX_EVIDENCE_BYTES or wire.count(".") != 2:
                _deny()
            payload = evidence._base64url_decode(wire.split(".")[1]).decode("ascii")
            parsed = evidence.parse_messaging_device_verification_deadline_evidence_payload_v1(
                payload,
                expected_input_wire=input_wire,
                freshness_profile=ec.freshness_profile,
            )
            at = parsed.observed_at
        authentic = evidence.verify_messaging_device_verification_deadline_evidence_v1(
            wire,
            config=ec,
            expected_input_wire=input_wire,
            now=at,
        )
        projected = evidence.project_authenticated_messaging_device_verification_deadline_evidence_v1(authentic)
        claims = projected["claims"]
        viewer, interval = self._phone(authority, bearer, now)
        if (
            (projected["keyId"], projected["trustRevision"], projected["trustRecordId"])
            not in self.composition._config.reservation_config.trust_pins
            or claims.social_session_issuance_id != issuance_id
            or (viewer.jti, viewer.subject, viewer.client_id)
            != (claims.social_session_token_id, claims.subject, claims.client_id)
        ):
            _deny()
        return interval

    def reserve(self, input_wire, *, issuance_id, viewer_bearer):
        from app.services.social_enrollment_v2_reservation import V2ReservationOwner

        c = self._configuration()

        def operation(session, now):
            owner = V2ReservationOwner(
                session,
                signer=c._signer,
                config=c._config.reservation_config,
                clock=lambda: _EPOCH + timedelta(milliseconds=now()),
            )
            self._phone(owner.authority, viewer_bearer, now)
            result = owner.reserve(input_wire, issuance_id=issuance_id)
            self._evidence_phone(
                owner.authority, viewer_bearer, result.evidence_compact_jws, input_wire, issuance_id, now
            )

            def before_commit(original):
                checked = owner.reserve(input_wire, issuance_id=issuance_id)
                if checked != original:
                    _deny()
                interval = self._evidence_phone(
                    owner.authority, viewer_bearer, original.evidence_compact_jws, input_wire, issuance_id, now
                )
                return max(original.observed_at, interval[0]), min(original.expires_at, interval[1])

            return result, before_commit

        result = _run_owned(c._factory, c._clock, operation, challenge_writer_role=c._config.challenge_writer_role)
        return CommittedReservation(
            result.evidence_compact_jws, result.reservation_id, result.observed_at, result.expires_at
        )

    def finalize(self, *, viewer_bearer, **arguments):
        from app.services.social_enrollment_v2_finalization import V2FinalizationOwner

        c = self._configuration()

        def operation(session, now):
            owner = V2FinalizationOwner(session, config=c._config, clock=now)

            def phone():
                return self._evidence_phone(
                    owner.authority,
                    viewer_bearer,
                    arguments["evidence_compact_jws"],
                    arguments["verification_input_wire"],
                    arguments["issuance_id"],
                    now,
                    historical=True,
                )

            phone()  # Match an authentic ORIGINAL phone identity before native effects.
            result = owner.finalize(**arguments)

            def before_commit(original):
                window = owner.check_before_commit(original)
                interval = phone()
                if window is None:
                    return interval  # Authenticated history, no new receipt freshness.
                return max(window[0], interval[0]), min(window[1], interval[1])

            return result, before_commit

        result = _run_owned(c._factory, c._clock, operation, challenge_writer_role=c._config.challenge_writer_role)
        return CommittedFinalization(result.receipt_wire, result.historical_recovery)

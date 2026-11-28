"""Narrow message-challenge writer, preserving the native finalizer's SQL ACL."""

from sqlalchemy import text

from app.services.social_device_challenge_store import SqlAlchemyDeviceChallengeStore, _deny, _parse_evidence
from app.services.social_registered_device_session_owner_v1 import credential_digest


class RegisteredDeviceMessageStoreV1(SqlAlchemyDeviceChallengeStore):
    def __init__(self, session, *, session_id, credential):
        super().__init__(session)
        self.session_id = session_id
        self.digest = credential_digest(credential)

    def create_issued(self, *, context_wire, challenge_wire, actual_request_wire=None, routing_request_wire=None):
        try:
            evidence = _parse_evidence(
                context_wire=context_wire,
                challenge_wire=challenge_wire,
                routing_request_wire=routing_request_wire,
                state="issued",
            )
            if (
                actual_request_wire != evidence.actual_request_wire
                or evidence.context.challenge_kind != "device-request-v1"
            ):
                _deny()
            self._check_transaction()
            self._connection.execute(
                text(
                    "SELECT public.create_registered_device_message_challenge_v1(:session,:digest,:context,:challenge,:routing)"
                ),
                dict(
                    session=self.session_id,
                    digest=self.digest,
                    context=context_wire,
                    challenge=challenge_wire,
                    routing=routing_request_wire,
                ),
            )
            stored = self.read(evidence.context.challenge_id)
            if stored != evidence:
                _deny()
            return stored
        except Exception:
            self._failed = True
        _deny()

"""Transaction owner for registered-device login, intentionally not installed.

Requires an operator-owned finalization configuration, the same PG16 authority
role scope as the historical observer, and explicit ACLs on the three new
tables. No generic OAuth token, historical bearer or role assertion is revived.
All returned credentials are provisional until the caller commits.
"""

from dataclasses import dataclass
import hashlib
import secrets

from sqlalchemy import text

from app.services import social_registered_device_session_contract_v1 as contract
from app.services.social_enrollment_v2_finalization_contract import freeze_config
from app.services.social_registered_device_observation_v1 import observe_registered_device_v1
from app.services.social_registered_device_session_statement_v1 import verify_statement

RUNTIME_ENABLED = False
SESSION_LIFETIME_MS = 300_000


@dataclass(frozen=True, repr=False)
class IssuedRegisteredDeviceSessionV1:
    session_id: str
    credential: str
    expires_at: int


def credential_digest(credential):
    if not contract._matches(contract._HEX64, credential):
        contract._deny()
    return hashlib.sha256(b"HODLXXI_REGISTERED_DEVICE_SESSION_CREDENTIAL_V1\0" + credential.encode("ascii")).hexdigest()


def _matches_observation(challenge, observed):
    return (
        challenge["subject"],
        challenge["deviceId"],
        challenge["bindingId"],
        challenge["bindingVersion"],
        challenge["associationId"],
        challenge["authorityEpoch"],
        challenge["associationVersion"],
        challenge["ed25519PublicKey"],
        challenge["x25519PublicKeyCommitment"],
    ) == (
        observed.subject,
        observed.device_id,
        observed.binding_id,
        observed.binding_version,
        observed.association_id,
        observed.authority_epoch,
        1,
        observed.ed25519_public_key,
        observed.x25519_public_key_commitment,
    )


class RegisteredDeviceSessionOwnerV1:
    def __init__(self, session, *, config, clock):
        self.db = session
        self.config = freeze_config(config)
        self.clock = clock
        self.tx = session.get_transaction()
        self.connection = session.connection()
        self.connection_tx = self.connection.get_transaction()
        self.used = False
        self._check()

    def _check(self):
        if (
            not self.config.enabled
            or self.tx is None
            or not self.tx.is_active
            or self.db.get_transaction() is not self.tx
            or self.db.get_nested_transaction() is not None
            or self.connection.get_transaction() is not self.connection_tx
            or self.connection.get_nested_transaction() is not None
            or self.db.connection() is not self.connection
            or self.connection.dialect.name != "postgresql"
        ):
            contract._deny()

    def _start(self):
        self._check()
        if self.used:
            contract._deny()
        self.used = True

    def _now(self):
        now = self.clock()
        if not contract._integer(now):
            contract._deny()
        return now

    def _sql(self, sql, values):
        self._check()
        return self.connection.execute(text(sql), values)

    def _observe(self, subject, device):
        value = observe_registered_device_v1(
            self.db, subject=subject, device_id=device, config=self.config, clock=self.clock
        )
        self._check()
        return value

    def _pins(self, context):
        if not contract._matches(contract._HEX64, context):
            contract._deny()
        ec = self.config.reservation_config.evidence_config
        return dict(
            issuer=ec.issuer,
            audience=self.config.reservation_config.verification_audience,
            client_id=ec.client_id,
            context_commitment=context,
        )

    def _lock_device(self, subject, device):
        # Same ordering for all commands: historical observation/authority locks
        # before device-scoped serialization. No lock depends on a raw credential.
        self._sql(
            "SELECT pg_advisory_xact_lock(hashtextextended(:key,0))",
            {"key": "registered-device-session-v1:" + subject + ":" + device},
        )

    def issue(self, *, subject, device_id, context_commitment):
        self._start()
        pins = self._pins(context_commitment)
        observed = self._observe(subject, device_id)
        self._lock_device(subject, device_id)
        now = self._now()
        # One challenge per device per 60s, including consumed challenges.
        # Production retention/rate budgets still require a deployment policy.
        recent = self._sql(
            "SELECT 1 FROM public.social_registered_device_challenges_v1 "
            "WHERE subject=:subject AND device_id=:device AND issued_at>:cutoff LIMIT 1",
            dict(subject=subject, device=device_id, cutoff=now - contract.MAX_LIFETIME_MS),
        ).first()
        expires = min(now + contract.MAX_LIFETIME_MS, observed.current_until_ms)
        if recent is not None or expires <= now:
            contract._deny()
        value = dict(
            associationId=observed.association_id,
            associationVersion=1,
            audience=pins["audience"],
            authorityEpoch=observed.authority_epoch,
            bindingId=observed.binding_id,
            bindingVersion=observed.binding_version,
            challengeId=secrets.token_hex(32),
            clientId=pins["client_id"],
            contextCommitment=context_commitment,
            deviceId=device_id,
            domain=contract.CHALLENGE_DOMAIN,
            ed25519PublicKey=observed.ed25519_public_key,
            expiresAt=expires,
            issuedAt=now,
            issuer=pins["issuer"],
            schema=contract.CHALLENGE_SCHEMA,
            subject=subject,
            version=1,
            x25519PublicKeyCommitment=observed.x25519_public_key_commitment,
        )
        wire = contract.canonical(value)
        contract.require_current_challenge_v1(wire, **pins, now=now)
        self._sql(
            "INSERT INTO public.social_registered_device_challenges_v1 "
            "(challenge_id,subject,device_id,challenge_wire,issued_at,expires_at) "
            "VALUES(:id,:subject,:device,:wire,:issued,:expires)",
            dict(id=value["challengeId"], subject=subject, device=device_id, wire=wire, issued=now, expires=expires),
        )
        self._check()
        if not now <= self._now() < expires:
            contract._deny()
        return wire

    def consume(self, *, challenge_wire, proof_wire, statement_wire, context_commitment):
        self._start()
        pins = self._pins(context_commitment)
        challenge = contract.require_current_challenge_v1(challenge_wire, **pins, now=self._now())
        contract.parse_proof_v1(proof_wire, challenge_wire=challenge_wire)
        observed = self._observe(challenge["subject"], challenge["deviceId"])
        self._lock_device(observed.subject, observed.device_id)
        row = self._sql(
            "SELECT challenge_wire,subject,device_id,issued_at,expires_at "
            "FROM public.social_registered_device_challenges_v1 WHERE challenge_id=:id",
            {"id": challenge["challengeId"]},
        ).mappings().one_or_none()
        now = self._now()
        if (
            row is None
            or tuple(row[k] for k in ("challenge_wire", "subject", "device_id", "issued_at", "expires_at"))
            != (challenge_wire, observed.subject, observed.device_id, challenge["issuedAt"], challenge["expiresAt"])
            or not _matches_observation(challenge, observed)
            or not challenge["issuedAt"] <= now < min(challenge["expiresAt"], observed.current_until_ms)
        ):
            contract._deny()
        verify_statement(statement_wire, challenge_wire=challenge_wire, proof_wire=proof_wire, config=self.config, now=now)
        if self._sql(
            "SELECT 1 FROM public.social_registered_device_sessions_v1 WHERE challenge_id=:id",
            {"id": challenge["challengeId"]},
        ).first() is not None:
            contract._deny()
        credential, session_id = secrets.token_hex(32), secrets.token_hex(32)
        expires = min(now + SESSION_LIFETIME_MS, observed.current_until_ms)
        self._sql(
            "INSERT INTO public.social_registered_device_sessions_v1 "
            "(session_id,challenge_id,credential_digest,issued_at,expires_at) "
            "VALUES(:session,:challenge,:digest,:issued,:expires)",
            dict(session=session_id, challenge=challenge["challengeId"], digest=credential_digest(credential),
                 issued=now, expires=expires),
        )
        self._check()
        if not now <= self._now() < min(expires, challenge["expiresAt"]):
            contract._deny()
        return IssuedRegisteredDeviceSessionV1(session_id, credential, expires)

    def _current(self, session_id, credential, context):
        pins = self._pins(context)
        if not contract._matches(contract._HEX64, session_id):
            contract._deny()
        query = (
            "SELECT c.challenge_wire,s.issued_at,s.expires_at,r.session_id IS NOT NULL AS revoked "
            "FROM public.social_registered_device_sessions_v1 s "
            "JOIN public.social_registered_device_challenges_v1 c ON c.challenge_id=s.challenge_id "
            "LEFT JOIN public.social_registered_device_revocations_v1 r ON r.session_id=s.session_id "
            "WHERE s.session_id=:id AND s.credential_digest=:digest"
        )
        values = dict(id=session_id, digest=credential_digest(credential))
        row = self._sql(query, values).mappings().one_or_none()
        if row is None or row["revoked"]:
            contract._deny()
        challenge = contract.parse_challenge_v1(row["challenge_wire"])
        if (challenge["issuer"], challenge["audience"], challenge["clientId"], challenge["contextCommitment"]) != (
            pins["issuer"], pins["audience"], pins["client_id"], pins["context_commitment"]
        ):
            contract._deny()
        observed = self._observe(challenge["subject"], challenge["deviceId"])
        self._lock_device(observed.subject, observed.device_id)
        again = self._sql(query, values).mappings().one_or_none()
        now = self._now()
        if (
            again is None
            or dict(again) != dict(row)
            or not _matches_observation(challenge, observed)
            or not challenge["issuedAt"] <= row["issued_at"] < challenge["expiresAt"]
            or not row["issued_at"] <= now < min(row["expires_at"], observed.current_until_ms)
        ):
            contract._deny()
        self._check()
        return observed, min(row["expires_at"], observed.current_until_ms)

    def read(self, *, session_id, credential, context_commitment):
        self._start()
        return self._current(session_id, credential, context_commitment)

    def revoke(self, *, session_id, credential, context_commitment):
        self._start()
        self._current(session_id, credential, context_commitment)
        self._sql(
            "INSERT INTO public.social_registered_device_revocations_v1(session_id,revoked_at) VALUES(:id,:now)",
            dict(id=session_id, now=self._now()),
        )
        self._check()

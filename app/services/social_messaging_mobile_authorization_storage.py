"""Dormant PostgreSQL owner for mobile authorization; no HTTP or login issuer.

Every public command commits before returning. The injected session factory
must use PostgreSQL READ COMMITTED. Authentication uses the existing durable
Session/User authority, freshly read on every desktop/LEGACY command. A future
browser adapter must map its authenticated session to that authority explicitly.
"""

from __future__ import annotations

import hmac
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import BigInteger, Column, ForeignKey, String, Text, select, text

from app.models import Base, Session, User
from app.services import social_messaging_mobile_authorization as protocol
from app.services.current_entitlement_evidence_storage import (
    SqlAlchemyTransactionBoundCurrentFullVerifier,
    _lock_subject_for_evidence_change,
)
from app.services.social_messaging_device_binding_authorization import Bip340IdentitySignatureVerifier, _parse_timestamp
from app.services.social_messaging_device_binding_authorization_storage import (
    SocialMessagingDeviceBindingAuthorizationEvidenceRow,
    SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage,
    _advisory_lock,
    _TransactionPorts,
)
from app.services.social_messaging_device_contract import MessagingDeviceBinding
from app.services.social_messaging_device_storage import (
    SqlAlchemyTransactionBoundSocialMessagingDeviceStorage,
    _lock_subject_user,
)

REQUESTS = "social_messaging_device_authorization_requests"
OPERATIONS = "social_messaging_mobile_operations"
RECEIPTS = "social_messaging_mobile_acceptances"
EXCHANGES = "social_messaging_mobile_exchanges"
ISSUANCES = "social_messaging_mobile_session_handoffs"
TERMINAL = frozenset(("accepted", "expired", "cancelled", "abandoned", "rejected"))
_OPERATION_LOCK = b"HODLXXI_SOCIAL_MOBILE_OPERATION_LOCK_V1\x00"
_REQUIRED_TRIGGERS = (
    ("social_messaging_device_binding_authorization_replay", "trg_social_nostr_global_request"),
    (REQUESTS, "trg_social_global_request_immutable"),
    (OPERATIONS, "trg_social_mobile_operation_guard"),
    ("social_messaging_device_binding_authorization_evidence", "trg_social_nostr_binding_owner"),
    (RECEIPTS, "trg_social_mobile_binding_owner"),
    ("social_messaging_device_authorization_binding_owners", "trg_social_binding_owner_immutable"),
    (OPERATIONS, "trg_social_mobile_operation_receipt"),
    (RECEIPTS, "trg_social_mobile_receipt_state"),
    (RECEIPTS, "trg_social_mobile_receipt_immutable"),
    (EXCHANGES, "trg_social_mobile_exchange_guard"),
    (EXCHANGES, "trg_social_mobile_exchange_immutable"),
    (ISSUANCES, "trg_social_mobile_handoff_guard"),
    (ISSUANCES, "trg_social_mobile_handoff_immutable"),
)


class MobileRequestRow(Base):
    __tablename__ = REQUESTS
    request_id = Column(String(64), primary_key=True)
    owner = Column(String(6), nullable=False)
    digest = Column(String(64), nullable=False)


class MobileOperationRow(Base):
    __tablename__ = OPERATIONS
    operation_id = Column(String(64), primary_key=True)
    method = Column(String(24), nullable=False)
    subject = Column(String(64), nullable=False)
    context_id = Column(String(64), nullable=False)
    session_commitment = Column(String(64), nullable=False)
    created_at = Column(BigInteger, nullable=False)
    expires_at = Column(BigInteger, nullable=False)
    revision = Column(String(64))
    secret_commitment = Column(String(64))
    request_id = Column(String(64), ForeignKey(REQUESTS + ".request_id"), unique=True)
    authorization_digest = Column(String(64), unique=True)
    source = Column(Text)
    status = Column(String(24), nullable=False)


class MobileAcceptanceRow(Base):
    __tablename__ = RECEIPTS
    operation_id = Column(String(64), ForeignKey(OPERATIONS + ".operation_id"), primary_key=True)
    request_id = Column(String(64), ForeignKey(REQUESTS + ".request_id"), nullable=False, unique=True)
    authorization_digest = Column(String(64), nullable=False, unique=True)
    binding_id = Column(
        String(64), ForeignKey("social_messaging_device_bindings.binding_id"), nullable=False, unique=True
    )
    proof_source = Column(Text, nullable=False)
    result_source = Column(Text, nullable=False)
    accepted_at = Column(BigInteger, nullable=False)
    current_full_proof_id = Column(String(112), nullable=False)
    current_full_expires_at = Column(BigInteger, nullable=False)


class MobileExchangeRow(Base):
    __tablename__ = EXCHANGES
    operation_id = Column(String(64), ForeignKey(RECEIPTS + ".operation_id"), primary_key=True)
    expires_at = Column(BigInteger, nullable=False)


class MobileSessionHandoffRow(Base):
    """Immutable issuer work item. This is metadata, never a bearer session."""

    __tablename__ = ISSUANCES
    operation_id = Column(String(64), ForeignKey(EXCHANGES + ".operation_id"), primary_key=True)
    identity_source = Column(Text, nullable=False)
    consumed_at = Column(BigInteger, nullable=False)


def _stamp(second):
    return datetime.fromtimestamp(second, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _session_time(value):
    if type(value) is not datetime:
        raise ValueError
    # Existing Session columns use naive UTC timestamps.
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _binding(candidate):
    record = protocol.parse_json(candidate.semantic.binding_record)
    return MessagingDeviceBinding(
        subject=record["subject"],
        device_id=record["deviceId"],
        binding_id=candidate.semantic.binding_id,
        public_key=record["publicKey"],
        binding_version=record["bindingVersion"],
        valid_from=_parse_timestamp(record["validFrom"]),
        expires_at=_parse_timestamp(record["expiresAt"]),
        operation=record["operation"],
        prior_binding_id=record["priorBindingId"],
        request_id=record["requestId"],
        active=record["operation"] != "revoke",
    )


def _acceptance(candidate):
    return protocol.CanonicalAcceptance(
        candidate.digest, candidate.semantic.binding_id, candidate.semantic.subject, candidate.semantic.request_id
    )


def _result(candidate):
    # A closed confidential result, separate from a routing proof or session.
    return protocol.canonical(
        dict(
            schema="hodlxxi.social_mobile_authorization_acceptance.v1",
            version=1,
            authorizationDigest=candidate.digest,
            bindingId=candidate.semantic.binding_id,
            subject=candidate.semantic.subject,
            requestId=candidate.semantic.request_id,
        )
    )


class SqlAlchemyMobileAuthorizationService:
    """Injected durable service. Inputs are confidential coordination contracts.

    session_id must come from authenticated ingress, never from request JSON.
    context_id is the original trusted loginContext/desktopContext. Existing
    durable session invalidation, replacement and subject changes deny access.
    No default factory, Redis fallback, clock tolerance or session minting exists.
    """

    def __init__(self, session_factory, *, clock=None, legacy_challenge_factory=None):
        if (
            not callable(session_factory)
            or clock is not None
            and not callable(clock)
            or legacy_challenge_factory is not None
            and not callable(legacy_challenge_factory)
        ):
            raise protocol.MobileAuthorizationUnavailable()
        self._factory = session_factory
        self._clock = clock or (lambda: int(datetime.now(timezone.utc).timestamp()))
        self._legacy_challenge_factory = legacy_challenge_factory or (lambda: str(uuid4()))

    def _now(self):
        value = self._clock()
        if type(value) is not int or value < 0:
            raise ValueError
        return value

    def _run(self, command):
        try:
            with self._factory() as session:
                with session.begin():
                    if session.get_bind().dialect.name != "postgresql":
                        raise ValueError
                    if session.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed":
                        raise ValueError
                    # ORM create_all is not a substitute for the reviewed
                    # migration: its shared replay and state guards are required.
                    pairs = ",".join(f"(to_regclass('{table}'), '{trigger}')" for table, trigger in _REQUIRED_TRIGGERS)
                    installed = session.execute(
                        text(
                            "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal "
                            "AND tgenabled = 'O' AND (tgrelid, tgname) IN (" + pairs + ")"
                        )
                    ).scalar_one()
                    if installed != len(_REQUIRED_TRIGGERS):
                        raise ValueError
                    result = command(session)
                    session.flush()
                # No result is exposed before the outer commit succeeds.
                return result
        except Exception:
            raise protocol.MobileAuthorizationUnavailable() from None

    def _auth(self, session, *, session_id, subject, context_id):
        protocol._hex(subject)
        protocol._hex(context_id)
        if type(session_id) is not str or not 1 <= len(session_id) <= 255:
            raise ValueError
        _lock_subject_for_evidence_change(session, subject)
        _lock_subject_user(session, subject)
        auth = session.get(Session, session_id, with_for_update=True)
        user = None if auth is None else session.get(User, auth.user_id, with_for_update=True)
        now = self._now()
        if (
            auth is None
            or user is None
            or auth.is_active is not True
            or user.is_active is not True
            or user.pubkey != subject
            or auth.session_type not in ("web", "api")
            or not _session_time(auth.created_at)
            <= datetime.fromtimestamp(now, timezone.utc)
            < _session_time(auth.expires_at).replace(microsecond=0)
        ):
            raise ValueError
        # Commit to the exact durable authentication generation, without
        # copying its opaque credential into mobile rows or outward results.
        return protocol.digest(
            "HODLXXI_SOCIAL_MOBILE_SESSION_CONTINUITY_V1\x00"
            + protocol.canonical(
                [session_id, auth.user_id, auth.created_at.isoformat(), auth.session_type, subject, context_id]
            )
        )

    def _owned(self, session, operation_id, *, method, session_id, subject, context_id):
        if type(operation_id) is not str or not 1 <= len(operation_id) <= 64:
            raise ValueError
        _advisory_lock(session, _OPERATION_LOCK, operation_id)
        row = session.get(MobileOperationRow, operation_id, with_for_update=True)
        if row is None or row.method != method or row.subject != subject or row.context_id != context_id:
            raise ValueError
        if row.request_id is not None:
            SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(session)._lock_request(row.request_id)
        commitment = self._auth(session, session_id=session_id, subject=subject, context_id=context_id)
        if not hmac.compare_digest(row.session_commitment, commitment):
            raise ValueError
        return row

    def _reserve_request(self, session, candidate):
        storage = SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(session)
        storage._lock_request(candidate.semantic.request_id)
        if session.get(MobileRequestRow, candidate.semantic.request_id) is not None:
            raise ValueError
        session.add(MobileRequestRow(request_id=candidate.semantic.request_id, owner="mobile", digest=candidate.digest))
        session.flush()

    def reserve_legacy(self, content, *, session_id, subject, login_context):
        """Generate and reserve a fresh UUID before releasing it for signing.

        Callers supply semantic content, never a challenge or method envelope.
        UUID injection is trusted construction-time test infrastructure.
        """

        def command(session):
            source = protocol.create_authorization(
                content,
                protocol.canonical(dict(challenge=self._legacy_challenge_factory(), loginContext=login_context)),
                protocol.LEGACY,
                subject=subject,
                now=self._now(),
            )
            candidate = protocol.parse_authorization(
                source, subject=subject, expected_method=protocol.LEGACY, now=self._now()
            )
            context = protocol.parse_json(source)["context"]
            if context["loginContext"] != login_context:
                raise ValueError
            _advisory_lock(session, _OPERATION_LOCK, context["challenge"])
            self._reserve_request(session, candidate)
            commitment = self._auth(session, session_id=session_id, subject=subject, context_id=login_context)

            def reserve(_ids, exact_source):
                session.add(
                    MobileOperationRow(
                        operation_id=context["challenge"],
                        method=protocol.LEGACY,
                        subject=subject,
                        context_id=login_context,
                        session_commitment=commitment,
                        created_at=candidate.semantic.issued_at,
                        expires_at=candidate.semantic.expires_at,
                        request_id=candidate.semantic.request_id,
                        authorization_digest=candidate.digest,
                        source=exact_source,
                        status="reserved",
                    )
                )
                session.flush()
                return True

            return protocol.issue_legacy_challenge(
                source, subject=subject, reserve_once=reserve, now=self._now(), enabled=True
            )

        return self._run(command)

    def create_pairing(self, *, session_id, subject, desktop_context, revision, ttl=300, random_bytes=None):
        def command(session):
            commitment = self._auth(session, session_id=session_id, subject=subject, context_id=desktop_context)

            def reserve(offer):
                session.add(
                    MobileOperationRow(
                        operation_id=offer.pairing_id,
                        method=protocol.QR,
                        subject=offer.subject,
                        context_id=offer.desktop_context,
                        session_commitment=commitment,
                        created_at=protocol._second(offer.created_at),
                        expires_at=protocol._second(offer.expires_at),
                        revision=offer.revision,
                        secret_commitment=offer.secret_commitment,
                        status="created",
                    )
                )
                session.flush()
                return True

            options = {} if random_bytes is None else dict(random_bytes=random_bytes)
            return protocol.create_pairing_offer(
                subject=subject,
                desktop_context=desktop_context,
                revision=revision,
                ttl=ttl,
                now=self._now(),
                enabled=True,
                reserve_once=reserve,
                **options,
            )

        return self._run(command)

    @staticmethod
    def _offer(row):
        return protocol.PairingOffer(
            row.operation_id,
            row.secret_commitment,
            row.context_id,
            row.subject,
            _stamp(row.created_at),
            _stamp(row.expires_at),
            row.revision,
            row.status,
        )

    def pairing_offer_for_scan(self, *, qr):
        """Resolve only public offer fields needed to construct the transcript.

        The confidential coordination transport must carry the locator in a
        no-store POST body. Possession permits inspection/proposal, never login.
        """

        def command(session):
            pairing_id, secret = protocol.parse_pairing_qr(qr)
            row = session.get(MobileOperationRow, pairing_id, with_for_update=True)
            if (
                row is None
                or row.method != protocol.QR
                or row.status != "created"
                or row.source is not None
                or not row.created_at <= self._now() < row.expires_at
                or not hmac.compare_digest(protocol.pairing_secret_commitment(secret), row.secret_commitment)
            ):
                raise ValueError
            return self._offer(row)

        return self._run(command)

    def scan_pairing(self, source, *, qr, possession_proof):
        def command(session):
            pairing_id, _secret = protocol.parse_pairing_qr(qr)
            _advisory_lock(session, _OPERATION_LOCK, pairing_id)
            row = session.get(MobileOperationRow, pairing_id, with_for_update=True)
            if row is None or row.method != protocol.QR:
                raise ValueError

            def claim(_offer, candidate):
                self._reserve_request(session, candidate)
                row.source = candidate.source
                row.authorization_digest = candidate.digest
                row.request_id = candidate.semantic.request_id
                row.status = "awaiting-approval"
                session.flush()
                return True

            return protocol.submit_pairing_scan(
                self._offer(row),
                source,
                qr=qr,
                possession_proof=possession_proof,
                claim_once=claim,
                now=self._now(),
            )

        return self._run(command)

    def claim_approval(
        self, pairing_id, *, session_id, subject, desktop_context, revision, authorization_digest, human_code
    ):
        def command(session):
            row = self._owned(
                session,
                pairing_id,
                method=protocol.QR,
                session_id=session_id,
                subject=subject,
                context_id=desktop_context,
            )
            if row.status != "awaiting-approval" or row.revision != protocol._hex(revision):
                raise ValueError
            candidate = protocol.parse_authorization(
                row.source, subject=subject, expected_method=protocol.QR, now=self._now()
            )
            if candidate.digest != authorization_digest or human_code != protocol.comparison_code(candidate.digest):
                raise ValueError
            row.status = "approval-claimed"
            return "approval-claimed"

        return self._run(command)

    def _verified(self, row, proof_source, now):
        if row.method == protocol.LEGACY:
            return protocol.verify_legacy_submission(
                row.source, proof_source, subject=row.subject, login_context=row.context_id, now=now
            )
        return protocol.verify_event(
            row.source, proof_source, subject=row.subject, expected_method=protocol.QR, now=now
        )

    def _predecessor_authority(self, session, binding_id):
        receipts = (
            session.execute(select(MobileAcceptanceRow).where(MobileAcceptanceRow.binding_id == binding_id))
            .scalars()
            .all()
        )
        old = _TransactionPorts(
            session, signature_verifier=Bip340IdentitySignatureVerifier()
        ).authorization_for_binding(
            binding_id,
            now=datetime.fromtimestamp(self._now(), timezone.utc),
            maximum=2,
        )
        if len(receipts) + len(old.records) != 1 or old.truncated or not old.complete:
            raise ValueError
        if receipts:
            receipt = receipts[0]
            original = session.get(MobileOperationRow, receipt.operation_id)
            if original is None or original.status != "accepted":
                raise ValueError
            verified = self._verified(original, receipt.proof_source, receipt.accepted_at)
            if verified.candidate.semantic.binding_id != binding_id or receipt.result_source != _result(
                verified.candidate
            ):
                raise ValueError

    def accept(
        self,
        operation_id,
        proof_source,
        *,
        method,
        session_id,
        subject,
        context_id,
        authorization_digest,
        revision=None,
    ):
        def command(session):
            row = self._owned(
                session, operation_id, method=method, session_id=session_id, subject=subject, context_id=context_id
            )
            if row.authorization_digest != protocol._hex(authorization_digest) or row.revision != revision:
                raise ValueError
            receipt = session.get(MobileAcceptanceRow, operation_id)
            if receipt is not None:
                # Recover historical acceptance, not fresh authorization. The
                # exact public proof is rechecked at its committed timestamp.
                verified = self._verified(row, proof_source, receipt.accepted_at)
                if (
                    row.status != "accepted"
                    or receipt.proof_source != proof_source
                    or receipt.authorization_digest != verified.candidate.digest
                    or receipt.request_id != verified.candidate.semantic.request_id
                    or receipt.binding_id != verified.candidate.semantic.binding_id
                    or receipt.result_source != _result(verified.candidate)
                ):
                    raise ValueError
                return receipt.result_source
            if row.status != ("reserved" if method == protocol.LEGACY else "approval-claimed"):
                raise ValueError
            storage = SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(session)
            storage._lock_request(row.request_id)
            owner = session.get(MobileRequestRow, row.request_id, with_for_update=True)
            if owner is None or owner.owner != "mobile" or owner.digest != row.authorization_digest:
                raise ValueError
            verified = self._verified(row, proof_source, self._now())
            candidate = verified.candidate
            binding = _binding(candidate)
            storage._lock_mutation(subject=subject, device_id=binding.device_id, public_keys=(binding.public_key,))
            self._auth(session, session_id=session_id, subject=subject, context_id=context_id)
            now = self._now()

            def atomic_accept(exact_verified, full):
                if exact_verified != verified:
                    raise ValueError
                bindings = SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(session)
                if candidate.semantic.operation == "adopt":
                    if bindings.binding_for_id(binding.binding_id) != binding:
                        raise ValueError
                    if not binding.valid_from <= datetime.fromtimestamp(now, timezone.utc) < binding.expires_at:
                        raise ValueError
                else:
                    if binding.prior_binding_id is not None:
                        self._predecessor_authority(session, binding.prior_binding_id)
                    bindings.apply_authorized(binding, now=datetime.fromtimestamp(now, timezone.utc))
                if session.get(SocialMessagingDeviceBindingAuthorizationEvidenceRow, binding.binding_id) is not None:
                    raise ValueError
                session.flush()
                row.status = "accepted"
                session.add(
                    MobileAcceptanceRow(
                        operation_id=operation_id,
                        request_id=candidate.semantic.request_id,
                        authorization_digest=candidate.digest,
                        binding_id=binding.binding_id,
                        proof_source=proof_source,
                        result_source=_result(candidate),
                        accepted_at=now,
                        current_full_proof_id=full.proof_id,
                        current_full_expires_at=int(full.expires_at.timestamp()),
                    )
                )
                session.flush()
                return _acceptance(candidate)

            protocol.accept_verified_candidate(
                verified,
                current_full=SqlAlchemyTransactionBoundCurrentFullVerifier(session),
                atomic_accept=atomic_accept,
                now=now,
            )
            if method == protocol.QR and candidate.semantic.operation != "revoke":
                session.add(MobileExchangeRow(operation_id=operation_id, expires_at=candidate.semantic.expires_at))
            return _result(candidate)

        return self._run(command)

    def close(self, operation_id, *, method, session_id, subject, context_id, status="cancelled"):
        def command(session):
            row = self._owned(
                session, operation_id, method=method, session_id=session_id, subject=subject, context_id=context_id
            )
            if status not in ("cancelled", "abandoned", "rejected") or row.status in TERMINAL:
                raise ValueError
            row.status = "expired" if self._now() >= self._deadline(row) else status
            return row.status

        return self._run(command)

    @staticmethod
    def _deadline(row):
        if row.source is None:
            return row.expires_at
        semantic = protocol.inspect_claim(protocol.parse_json(row.source)["content"], row.subject)
        return min(row.expires_at, semantic.expires_at)

    def status(self, operation_id, *, method, session_id, subject, context_id):
        def command(session):
            row = self._owned(
                session, operation_id, method=method, session_id=session_id, subject=subject, context_id=context_id
            )
            if row.status not in TERMINAL and self._now() >= self._deadline(row):
                row.status = "expired"
            # No subject, proposal, credential or proof in the status contract.
            return protocol.canonical(dict(status=row.status, authorizationDigest=row.authorization_digest))

        return self._run(command)

    def phone_status(self, pairing_id, *, verifier, authorization_digest, revision):
        def command(session):
            row = session.get(MobileOperationRow, protocol._hex(pairing_id), with_for_update=True)
            if row is None or row.method != protocol.QR or row.source is None or row.revision != revision:
                raise ValueError
            context = protocol.parse_json(row.source)["context"]
            if row.authorization_digest != authorization_digest or not hmac.compare_digest(
                protocol.phone_exchange_commitment(verifier), context["exchangeCommitment"]
            ):
                raise ValueError
            if row.status not in TERMINAL and self._now() >= self._deadline(row):
                row.status = "expired"
            return protocol.canonical(dict(status=row.status, authorizationDigest=row.authorization_digest))

        return self._run(command)

    def pairing_snapshot(self, pairing_id, *, session_id, subject, desktop_context, revision):
        """Read the exact public offer/transcript for the authenticated desktop."""

        def command(session):
            row = self._owned(
                session,
                pairing_id,
                method=protocol.QR,
                session_id=session_id,
                subject=subject,
                context_id=desktop_context,
            )
            if row.revision != protocol._hex(revision):
                raise ValueError
            if row.status not in TERMINAL and self._now() >= self._deadline(row):
                row.status = "expired"
            if row.source is None:
                return self._offer(row)
            accepted = None
            receipt = session.get(MobileAcceptanceRow, pairing_id)
            if row.status == "accepted":
                if receipt is None:
                    raise ValueError
                verified = self._verified(row, receipt.proof_source, receipt.accepted_at)
                if (
                    receipt.result_source != _result(verified.candidate)
                    or receipt.authorization_digest != verified.candidate.digest
                    or receipt.binding_id != verified.candidate.semantic.binding_id
                    or receipt.request_id != verified.candidate.semantic.request_id
                ):
                    raise ValueError
                accepted = _acceptance(verified.candidate)
            elif receipt is not None:
                raise ValueError
            return protocol.PairingState(row.source, row.revision, row.status, accepted)

        return self._run(command)

    def recover_pairing_proposal(self, source, *, qr, possession_proof, verifier, revision):
        """Inspect a possibly lost scan without claiming or reopening an offer.

        The phone supplies only its original public proposal and transient
        possession proofs. A historical validation time permits inspection of
        an expired proposal; it is never used to accept or extend that proposal.
        """

        def command(session):
            pairing_id, _secret = protocol.parse_pairing_qr(qr)
            _advisory_lock(session, _OPERATION_LOCK, pairing_id)
            row = session.get(MobileOperationRow, pairing_id, with_for_update=True)
            if row is None or row.method != protocol.QR or row.revision != protocol._hex(revision):
                raise ValueError
            semantic = protocol.inspect_claim(protocol.parse_json(source)["content"], row.subject)
            candidate = protocol.verify_pairing_scan(
                source,
                qr=qr,
                possession_proof=possession_proof,
                subject=row.subject,
                now=semantic.issued_at,
            )
            context = protocol.parse_json(source)["context"]
            expected = dict(
                pairingId=row.operation_id,
                desktopContext=row.context_id,
                secretCommitment=row.secret_commitment,
                createdAt=_stamp(row.created_at),
                expiresAt=_stamp(row.expires_at),
                exchangeCommitment=protocol.phone_exchange_commitment(verifier),
            )
            if context != expected or semantic.issued_at > self._now():
                raise ValueError
            if row.status not in TERMINAL and self._now() >= self._deadline(row):
                row.status = "expired"
            if row.source == source:
                status = row.status
            elif row.source is None and row.status in TERMINAL:
                status = row.status
            else:
                status = "never-accepted"
            return protocol.canonical(dict(status=status, authorizationDigest=candidate.digest))

        return self._run(command)

    def consume_exchange(self, pairing_id, *, verifier, subject, revision, authorization_digest):
        def command(session):
            _advisory_lock(session, _OPERATION_LOCK, protocol._hex(pairing_id))
            row = session.get(MobileOperationRow, pairing_id, with_for_update=True)
            if row is None or row.method != protocol.QR or row.subject != subject or row.status != "accepted":
                raise ValueError
            receipt = session.get(MobileAcceptanceRow, pairing_id)
            exchange = session.get(MobileExchangeRow, pairing_id)
            if receipt is None or exchange is None or receipt.authorization_digest != authorization_digest:
                raise ValueError
            verified = self._verified(row, receipt.proof_source, receipt.accepted_at)
            if receipt.result_source != _result(verified.candidate):
                raise ValueError
            handoff = session.get(MobileSessionHandoffRow, pairing_id)
            if handoff is None:
                _lock_subject_for_evidence_change(session, subject)
                _lock_subject_user(session, subject)
                binding = SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(session).binding_for_id(
                    receipt.binding_id
                )
                if binding != _binding(verified.candidate) or not binding.active:
                    raise ValueError
            now = self._now()
            # An equal retry recovers only the committed handoff metadata. It
            # never causes a second consumption or issues another session.
            check_time = now if handoff is None else handoff.consumed_at
            identity = protocol.consume_phone_exchange(
                protocol.PairingState(row.source, row.revision, "accepted", _acceptance(verified.candidate)),
                verifier=verifier,
                subject=subject,
                expected_revision=revision,
                consume_once=lambda *_args: True,
                now=check_time,
            )
            if exchange.expires_at != verified.candidate.semantic.expires_at:
                raise ValueError
            if handoff is not None:
                if handoff.identity_source != identity:
                    raise ValueError
                return identity
            if now >= exchange.expires_at:
                raise ValueError
            session.add(MobileSessionHandoffRow(operation_id=pairing_id, identity_source=identity, consumed_at=now))
            return identity

        return self._run(command)

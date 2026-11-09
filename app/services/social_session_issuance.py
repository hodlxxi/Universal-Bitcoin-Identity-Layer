"""Dormant one-shot mobile authority owner; all releases follow PostgreSQL commit.

Canonical OAuthToken stores only the existing SHA-256 credential digest. The
separate immutable issuance relation never impersonates a browser generation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone

import jwt
from sqlalchemy import BigInteger, Boolean, Column, String, select, text

from app.jwks import get_key_by_kid
from app.models import OAuthSessionGeneration, OAuthToken, Session, _OAuthSessionBase
from app.services import social_messaging_mobile_authorization as protocol
from app.services.current_entitlement_evidence_storage import SqlAlchemyTransactionBoundCurrentFullVerifier
from app.services.oauth_bearer_validation import TOKEN_CONTRACT
from app.services.oauth_scope_policy import SCOPE_POLICY_VERSION, client_allowed_scopes, validate_client_scopes
from app.services.oauth_session_lifecycle import SqlAlchemyOAuthSessionLifecycle, _utc
from app.services.social_messaging_device_binding_authorization_storage import (
    SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage,
    _advisory_lock,
)
from app.services.social_messaging_device_storage import SqlAlchemyTransactionBoundSocialMessagingDeviceStorage
from app.services.social_messaging_mobile_authorization_storage import (
    _OPERATION_LOCK,
    MobileAcceptanceRow,
    MobileOperationRow,
    MobileSessionHandoffRow,
    SqlAlchemyMobileAuthorizationService,
    _binding,
    _stamp,
)
from app.tokens import issue_rs256_jwt

ISSUERS = "social_session_issuers"
PARENTS = "social_session_pairing_parents"
ISSUANCES = "social_session_issuances"
SCOPE = "openid profile"
_GUARDS = (
    (ISSUERS, "trg_social_session_issuer_guard"),
    (PARENTS, "trg_social_session_parent_guard"),
    (ISSUANCES, "trg_social_session_issuance_guard"),
    ("oauth_tokens", "trg_social_session_token_guard"),
    ("sessions", "trg_social_session_parent_invalidation"),
    ("social_messaging_device_bindings", "trg_social_session_binding_invalidation"),
    ("oauth_clients", "trg_social_session_client_invalidation"),
)


class SessionIssuanceUnavailable(ValueError):
    def __init__(self):
        super().__init__("Social session issuance unavailable")


class SocialSessionIssuer(_OAuthSessionBase):
    __tablename__ = ISSUERS
    client_id = Column(String(255), primary_key=True)
    backend_id = Column(String(255), nullable=False)
    service_principal = Column(String(255), nullable=False)
    is_active = Column(Boolean, nullable=False)


class SocialSessionPairingParent(_OAuthSessionBase):
    __tablename__ = PARENTS
    operation_id = Column(String(64), primary_key=True)
    parent_token_id = Column(String(36), nullable=False)
    client_id = Column(String(255), nullable=False)


class SocialSessionIssuance(_OAuthSessionBase):
    __tablename__ = ISSUANCES
    operation_id = Column(String(64), primary_key=True)
    issuance_id = Column(String(64), nullable=False, unique=True)
    token_id = Column(String(36), nullable=False, unique=True)
    parent_token_id = Column(String(36), nullable=False)
    client_id = Column(String(255), nullable=False)
    backend_id = Column(String(255), nullable=False)
    service_principal = Column(String(255), nullable=False)
    user_id = Column(String(36), nullable=False)
    subject = Column(String(64), nullable=False)
    binding_id = Column(String(64), nullable=False)
    device_id = Column(String(64), nullable=False)
    method = Column(String(24), nullable=False)
    operation = Column(String(8), nullable=False)
    request_id = Column(String(64), nullable=False)
    authorization_digest = Column(String(64), nullable=False)
    revision = Column(String(64), nullable=False)
    delivery_commitment = Column(String(64), nullable=False)
    issued_at = Column(BigInteger, nullable=False)
    expires_at = Column(BigInteger, nullable=False)


def record_pairing_parent(db, operation_id, session_id, client_id):
    """Called only during opt-in offer creation, with the real locked Session.

    The immutable canonical mapping is not a subject-only or JSON assertion.
    The migration rejects late attachment, including unsigned historical offers.
    """
    generation = db.execute(
        select(OAuthSessionGeneration).where(
            OAuthSessionGeneration.session_id == session_id, OAuthSessionGeneration.client_id == client_id
        )
    ).scalar_one()
    db.add(
        SocialSessionPairingParent(operation_id=operation_id, parent_token_id=generation.token_id, client_id=client_id)
    )
    db.flush()


class SqlAlchemySocialSessionIssuance:
    def __init__(self, *, mobile, lifecycle, backend_id, service_principal):
        if (
            type(mobile) is not SqlAlchemyMobileAuthorizationService
            or type(lifecycle) is not SqlAlchemyOAuthSessionLifecycle
            or mobile._factory is not lifecycle._factory
            or mobile._issuance_client_id != lifecycle.client_id
            or any(
                type(v) is not str or not 1 <= len(v) <= 255 or v.strip() != v for v in (backend_id, service_principal)
            )
        ):
            raise SessionIssuanceUnavailable()
        self.mobile, self.lifecycle = mobile, lifecycle
        self.backend_id, self.service_principal = backend_id, service_principal
        self.client_id = lifecycle.client_id
        self._factory = lifecycle._factory

    def _run(self, command):
        def guarded(db):
            pairs = ",".join(f"(to_regclass('{table}'), '{name}')" for table, name in _GUARDS)
            count = db.execute(
                text(
                    "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O' "
                    "AND (tgrelid,tgname) IN (" + pairs + ")"
                )
            ).scalar_one()
            if count != len(_GUARDS):
                raise ValueError
            # Reuse both owners' required migration/dialect checks, in this one
            # outer transaction; no nested service command or independent commit.
            from app.services.social_messaging_mobile_authorization_storage import _REQUIRED_TRIGGERS

            pairs = ",".join(f"(to_regclass('{t}'), '{n}')" for t, n in _REQUIRED_TRIGGERS)
            if db.execute(
                text(
                    "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' "
                    "AND (tgrelid,tgname) IN (" + pairs + ")"
                )
            ).scalar_one() != len(_REQUIRED_TRIGGERS):
                raise ValueError
            return command(db)

        try:
            return self.lifecycle._run(guarded)
        except Exception:
            raise SessionIssuanceUnavailable() from None

    def _issuer(self, db, *, active):
        issuer = db.get(SocialSessionIssuer, self.client_id, with_for_update=True, populate_existing=True)
        if (
            issuer is None
            or issuer.backend_id != self.backend_id
            or issuer.service_principal != self.service_principal
            or active
            and issuer.is_active is not True
        ):
            raise ValueError
        return issuer

    def _history(self, db, data):
        for name in ("pairingId", "revision", "authorizationDigest", "verifier", "deliveryKey"):
            protocol._hex(data[name])
        operation_id = data["pairingId"]
        _advisory_lock(db, _OPERATION_LOCK, operation_id)
        row = db.get(MobileOperationRow, operation_id, with_for_update=True, populate_existing=True)
        handoff = db.get(MobileSessionHandoffRow, operation_id)
        if row is None or handoff is None:
            raise ValueError
        # This invocation is deliberately history-only: no missing handoff can
        # be consumed implicitly by issuance. It reuses the exact phone proof.
        self.mobile._consume_exchange(
            db,
            operation_id,
            verifier=data["verifier"],
            subject=row.subject,
            revision=data["revision"],
            authorization_digest=data["authorizationDigest"],
        )
        parent = db.get(SocialSessionPairingParent, operation_id)
        if parent is None or parent.client_id != self.client_id:
            raise ValueError
        receipt = db.get(MobileAcceptanceRow, operation_id)
        candidate = self.mobile._verified(row, receipt.proof_source, receipt.accepted_at).candidate
        commitment = protocol.digest(
            "HODLXXI_SOCIAL_SESSION_DELIVERY_V1\0"
            + protocol.canonical(
                [
                    self.client_id,
                    self.backend_id,
                    self.service_principal,
                    operation_id,
                    data["verifier"],
                    data["deliveryKey"],
                ]
            )
        )
        issued = db.get(SocialSessionIssuance, operation_id)
        if issued is not None and (
            issued.client_id != self.client_id
            or issued.backend_id != self.backend_id
            or issued.service_principal != self.service_principal
            or not hmac.compare_digest(issued.delivery_commitment, commitment)
        ):
            raise ValueError
        return row, parent, candidate, commitment, issued

    def _current(self, db, row, parent, candidate):
        storage = SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(db)
        storage._lock_request(row.request_id)
        binding = _binding(candidate)
        # Includes the same subject/User, device and public-key locks as actual
        # binding revoke/rotation; parent mutations share User/client/token locks.
        storage._lock_mutation(subject=row.subject, device_id=binding.device_id, public_keys=(binding.public_key,))
        generation = db.get(OAuthSessionGeneration, parent.parent_token_id)
        if generation is None or generation.client_id != self.client_id or generation.subject != row.subject:
            raise ValueError
        user, client = self.lifecycle._owner(db, generation.user_id)
        self._issuer(db, active=True)
        self.lifecycle._browser(db, generation.browser_generation_id, user)
        token = db.get(OAuthToken, generation.token_id, with_for_update=True, populate_existing=True)
        auth = db.get(Session, generation.session_id, with_for_update=True, populate_existing=True)
        continuity = self.mobile._auth(
            db, session_id=generation.session_id, subject=row.subject, context_id=row.context_id
        )
        now = self.mobile._now()
        if (
            not hmac.compare_digest(continuity, row.session_commitment)
            or token.is_revoked is not False
            or token.client_id != self.client_id
            or token.user_id != user.id
            or not frozenset(SCOPE.split()).issubset(frozenset(token.scope.split()))
            or generation.subject != user.pubkey
            or not _utc(token.created_at)
            <= datetime.fromtimestamp(now, timezone.utc)
            < _utc(token.access_token_expires_at)
            or candidate.semantic.operation == "revoke"
            or not row.created_at <= now < min(row.expires_at, candidate.semantic.expires_at)
            or SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(db).binding_for_id(binding.binding_id) != binding
            or not binding.active
            or not binding.valid_from <= datetime.fromtimestamp(now, timezone.utc) < binding.expires_at
        ):
            raise ValueError
        validate_client_scopes(
            frozenset(SCOPE.split()), client_allowed_scopes({"scope": client.scope, "metadata": client.metadata_json})
        )
        expires = min(
            row.expires_at,
            candidate.semantic.expires_at,
            int(binding.expires_at.timestamp()),
            int(_utc(auth.expires_at).timestamp()),
            int(_utc(token.access_token_expires_at).timestamp()),
        )
        return user, now, expires

    def _credential(self, db, issued):
        token = db.get(OAuthToken, issued.token_id, populate_existing=True)
        key = get_key_by_kid(self.lifecycle._validation.jwks_dir, token.metadata_json["kid"])
        if key is None:
            raise ValueError
        # Same field order and RS256 encoding as issue_rs256_jwt. Persisted
        # claims contain no bearer. Verify the recovered bytes against digest.
        claims = dict(
            iss=self.lifecycle._validation.issuer,
            aud=self.client_id,
            sub=issued.subject,
            iat=issued.issued_at,
            exp=issued.expires_at,
            jti=issued.token_id,
            scope=SCOPE,
            token_use="access",
            token_contract=TOKEN_CONTRACT,
        )
        credential = jwt.encode(claims, key, algorithm="RS256", headers={"kid": token.metadata_json["kid"]})
        if not hmac.compare_digest(hashlib.sha256(credential.encode("ascii")).hexdigest(), token.access_token):
            raise ValueError
        return credential

    @staticmethod
    def _receipt(issued):
        return dict(
            schema="hodlxxi.social_session_issuance.v1",
            version=1,
            issuanceId=issued.issuance_id,
            issuedAt=_stamp(issued.issued_at),
            expiresAt=_stamp(issued.expires_at),
        )

    def _delivery(self, db, issued, row, parent, candidate):
        token = db.get(OAuthToken, issued.token_id, populate_existing=True)
        now = self.mobile._now()
        active = token.is_revoked is False and issued.issued_at <= now < issued.expires_at
        if active:
            self._current(db, row, parent, candidate)
            credential = self._credential(db, issued)
            self.lifecycle._validate(db, credential)
        else:
            credential = None
        return dict(
            receipt=self._receipt(issued),
            currentActive=active,
            subject=issued.subject if active else None,
            viewerAccessToken=credential,
        )

    def issue(self, data, *, recover_only=False):
        def command(db):
            row, parent, candidate, commitment, issued = self._history(db, data)
            if issued is not None:
                # Immutable ownership is checked even for expired/revoked history.
                return self._delivery(db, issued, row, parent, candidate)
            if recover_only:
                raise ValueError
            user, now, expires = self._current(db, row, parent, candidate)
            # Current-Full is checked now, never copied into scope/authority.
            SqlAlchemyTransactionBoundCurrentFullVerifier(db).verify_in_transaction(
                row.subject, now=datetime.fromtimestamp(now, timezone.utc)
            )
            issued = SocialSessionIssuance(
                operation_id=row.operation_id,
                issuance_id=secrets.token_hex(32),
                token_id=secrets.token_hex(16),
                parent_token_id=parent.parent_token_id,
                client_id=self.client_id,
                backend_id=self.backend_id,
                service_principal=self.service_principal,
                user_id=user.id,
                subject=row.subject,
                binding_id=candidate.semantic.binding_id,
                device_id=_binding(candidate).device_id,
                method=protocol.QR,
                operation=candidate.semantic.operation,
                request_id=row.request_id,
                authorization_digest=row.authorization_digest,
                revision=row.revision,
                delivery_commitment=commitment,
                issued_at=now,
                expires_at=expires,
            )
            credential = issue_rs256_jwt(
                row.subject,
                dict(
                    aud=self.client_id,
                    iat=now,
                    exp=expires,
                    jti=issued.token_id,
                    scope=SCOPE,
                    token_use="access",
                    token_contract=TOKEN_CONTRACT,
                ),
                cfg=self.lifecycle._config,
            )
            db.add(
                OAuthToken(
                    id=issued.token_id,
                    access_token=hashlib.sha256(credential.encode("ascii")).hexdigest(),
                    token_type="Bearer",
                    client_id=self.client_id,
                    user_id=user.id,
                    scope=SCOPE,
                    created_at=datetime.fromtimestamp(now, timezone.utc).replace(tzinfo=None),
                    access_token_expires_at=datetime.fromtimestamp(expires, timezone.utc).replace(tzinfo=None),
                    is_revoked=False,
                    metadata_json=dict(
                        token_contract=TOKEN_CONTRACT,
                        token_use="access",
                        issuer=self.lifecycle._validation.issuer,
                        audience=self.client_id,
                        kid=jwt.get_unverified_header(credential)["kid"],
                        digest_algorithm="sha256",
                        scope_policy_version=SCOPE_POLICY_VERSION,
                    ),
                )
            )
            db.flush()
            db.add(issued)
            db.flush()
            self._current(db, row, parent, candidate)
            SqlAlchemyTransactionBoundCurrentFullVerifier(db).verify_in_transaction(
                row.subject, now=datetime.fromtimestamp(self.mobile._now(), timezone.utc)
            )
            if self.mobile._now() >= expires:
                raise ValueError
            return self._delivery(db, issued, row, parent, candidate)

        return self._run(command)

    def recover(self, data):
        return self.issue(data, recover_only=True)

    def resolve(self, issuance_id, viewer_token):
        def command(db):
            protocol._hex(issuance_id)
            viewer = self.lifecycle._validate(db, viewer_token)
            issued = db.execute(
                select(SocialSessionIssuance).where(SocialSessionIssuance.issuance_id == issuance_id)
            ).scalar_one()
            if (
                viewer.jti != issued.token_id
                or issued.client_id != self.client_id
                or issued.backend_id != self.backend_id
            ):
                raise ValueError
            _advisory_lock(db, _OPERATION_LOCK, issued.operation_id)
            row = db.get(MobileOperationRow, issued.operation_id, with_for_update=True)
            parent = db.get(SocialSessionPairingParent, row.operation_id)
            receipt = db.get(MobileAcceptanceRow, row.operation_id)
            candidate = self.mobile._verified(row, receipt.proof_source, receipt.accepted_at).candidate
            self._current(db, row, parent, candidate)
            self.lifecycle._validate(db, viewer_token)
            if not issued.issued_at <= self.mobile._now() < issued.expires_at:
                raise ValueError
            return dict(receipt=self._receipt(issued), subject=issued.subject, currentActive=True)

        return self._run(command)

    def revoke(self, issuance_id, viewer_token):
        """Exact original credential, including after expiry/revocation, can
        revoke only its own issuance. No phone verifier must be retained after
        delivery. Reconstructing signed bytes confers no authentication here.
        """

        def command(db):
            protocol._hex(issuance_id)
            if type(viewer_token) is not str or not 1 <= len(viewer_token) <= 8192 or not viewer_token.isascii():
                raise ValueError
            issued = db.execute(
                select(SocialSessionIssuance).where(SocialSessionIssuance.issuance_id == issuance_id)
            ).scalar_one()
            if (
                issued.client_id != self.client_id
                or issued.backend_id != self.backend_id
                or issued.service_principal != self.service_principal
                or self.mobile._now() < issued.issued_at
            ):
                raise ValueError
            _advisory_lock(db, _OPERATION_LOCK, issued.operation_id)
            self._issuer(db, active=False)
            token = db.get(OAuthToken, issued.token_id, with_for_update=True, populate_existing=True)
            # The existing RS256 key plus immutable claims reproduce exactly
            # the original signed credential. Neither an issuance ID nor JWT
            # claims alone prove possession. Missing original key denies retry.
            if not hmac.compare_digest(self._credential(db, issued), viewer_token):
                raise ValueError
            token.is_revoked = True
            db.flush()
            return dict(
                schema="hodlxxi.social_session_revocation.v1",
                version=1,
                issuanceId=issued.issuance_id,
                status="revoked",
            )

        return self._run(command)

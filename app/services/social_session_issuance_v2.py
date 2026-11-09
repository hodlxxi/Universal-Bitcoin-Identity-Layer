"""Dormant native V2 offer, first acceptance/binding and one-shot basic OAuth.

The configured owner commits before any credential response. No route/factory,
key discovery, replacement generation, dedicated evidence signer or admission.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone

import jwt
from sqlalchemy import update

from app.models import OAuthSessionGeneration, OAuthToken
from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
from app.services.oauth_bearer_validation import TOKEN_CONTRACT
from app.services.oauth_scope_policy import SCOPE_POLICY_VERSION
from app.services.oauth_session_lifecycle import SqlAlchemyOAuthSessionLifecycle
from app.services.social_messaging_device_storage import SqlAlchemyTransactionBoundSocialMessagingDeviceStorage
from app.services.social_session_issuance_v2_authority import NativeV2AuthorityReader
from app.services.social_session_issuance_v2_contract import (
    SCOPE,
    V2IssuanceUnavailable,
    claims,
    continuity,
    delivery_commitment,
    hex64,
    milliseconds,
    receipt,
    trusted_now,
    verify_phone,
)
from app.services.social_session_issuance_v2_storage import V2Acceptance, V2Issuance, V2Offer, V2Parent, V2TokenBirth
from app.tokens import issue_rs256_jwt


class NativeV2SessionIssuer:
    def __init__(self, *, lifecycle, backend_id, principal):
        if type(lifecycle) is not SqlAlchemyOAuthSessionLifecycle:
            raise V2IssuanceUnavailable()
        self.lifecycle = lifecycle
        self.backend_id, self.principal = backend_id, principal

    def _reader(self, db):
        return NativeV2AuthorityReader(
            db,
            client_id=self.lifecycle.client_id,
            backend_id=self.backend_id,
            principal=self.principal,
            issuer=self.lifecycle._validation.issuer,
            clock=self.lifecycle._now,
        )

    def _run(self, command):
        try:
            # Commit context exits successfully before the response is accessible.
            # Uncertain/failed commit discards the transient result; retry reads history.
            with self.lifecycle._factory() as db:
                with db.begin():
                    reader = self._reader(db)
                    result = command(reader)
                    reader._check()
                    db.flush()
                    # Attestation and writes can also take time. Final exclusive
                    # fence is immediately before the owner commit.
                    now = trusted_now(reader.clock)
                    if isinstance(result, dict) and result.get("currentActive"):
                        if milliseconds(now) >= result["receipt"]["expiresAt"]:
                            raise V2IssuanceUnavailable()
                    elif type(result) is str:
                        v2.validate_acceptance_time_v2(result, now_ms=milliseconds(now))
                    if type(result) is str or isinstance(result, dict) and result.get("currentActive"):
                        if reader._deadline_ms is None or milliseconds(now) >= reader._deadline_ms:
                            raise V2IssuanceUnavailable()
                # Nothing can escape on failed/uncertain commit. Resample before
                # delivery too; expiry after successful commit retains history.
                if isinstance(result, dict) and result.get("currentActive"):
                    if milliseconds(trusted_now(self.lifecycle._now)) >= min(
                        result["receipt"]["expiresAt"], reader._deadline_ms
                    ):
                        result = dict(result, currentActive=False, subject=None, viewerAccessToken=None)
                return result
        except Exception:
            raise V2IssuanceUnavailable() from None

    def create_offer(self, authorization_wire, *, desktop_bearer):
        """Create exact original V2 offer and parent together; never attach later.

        The phone's already canonical proposal includes its original exchange
        commitment. The authenticated desktop token selects the real native
        generation. Returned bytes are released only after the owner commit.
        """

        def command(r):
            e = v2.parse_authorization_envelope_v2(authorization_wire)
            # Serialize the first creation and exact retries on the same native
            # operation fence used by acceptance. Never replace an old offer.
            r.guard.sql(
                "SELECT pg_catalog.pg_advisory_xact_lock(:key)",
                {"key": int.from_bytes(bytes.fromhex(e.context.pairing_id)[:8], "big", signed=True)},
            )
            viewer = self.lifecycle._validate(r.port, desktop_bearer)
            g = r._row(OAuthSessionGeneration, OAuthSessionGeneration.token_id, viewer.jti)
            if viewer.subject != e.pre_enrollment.subject or g.client_id != self.lifecycle.client_id:
                raise ValueError
            p = V2Parent(
                operation_id=e.context.pairing_id,
                token_id=g.token_id,
                session_id=g.session_id,
                browser_id=g.browser_generation_id,
                user_id=g.user_id,
                continuity="0" * 64,
            )
            # First read native owners; compute continuity from the locked original
            # Session, rather than an exported/caller "verified browser" value.
            from app.models import Session

            s = r._row(Session, Session.session_id, g.session_id)
            p.continuity = continuity(g, s, e.context.desktop_context)
            existing = r._row(V2Offer, V2Offer.operation_id, e.context.pairing_id, optional=True)
            if existing is not None:
                original, parent, envelope = r._operation(e.context.pairing_id)
                if original.wire != authorization_wire or (
                    parent.token_id,
                    parent.session_id,
                    parent.browser_id,
                    parent.user_id,
                    parent.continuity,
                ) != (p.token_id, p.session_id, p.browser_id, p.user_id, p.continuity):
                    raise ValueError
                r._owners(envelope, parent, require_binding=False)
                v2.validate_acceptance_time_v2(original.wire, now_ms=milliseconds(trusted_now(r.clock)))
                return original.wire
            r._owners(e, p, require_binding=False)
            now = trusted_now(r.clock)
            v2.validate_acceptance_time_v2(authorization_wire, now_ms=milliseconds(now))
            offer = V2Offer(
                operation_id=e.context.pairing_id,
                request_id=e.pre_enrollment.request_id,
                authorization_digest=v2.authorization_v2_digest(authorization_wire),
                wire=authorization_wire,
                subject=e.pre_enrollment.subject,
                client_id=r.client_id,
                backend_id=r.backend_id,
                service_principal=r.principal,
                issuer=r.issuer,
                created_at=e.context.created_at * 1000,
                expires_at=e.context.expires_at * 1000,
                birth_xid=r.guard.xid,
            )
            r.port.add(offer)
            r.port.add(p)
            # Fresh after both writes, before owner commit/release.
            r._owners(e, p, require_binding=False)
            return authorization_wire

        return self._run(command)

    def _credential(self, r, i, token):
        # Existing canonical signer receives the existing injected configuration.
        # Recovery requests precisely the original claims; active-key changes deny
        # unless the original configured representation is restored. No key load
        # or original-key substitution is implemented here.
        value = issue_rs256_jwt(i.subject, claims(i), cfg=self.lifecycle._config)
        header = jwt.get_unverified_header(value)
        if header.get("kid") != i.kid or header.get("alg") != "RS256":
            raise ValueError
        if not hmac.compare_digest(hashlib.sha256(value.encode("ascii")).hexdigest(), token.access_token):
            raise ValueError
        self.lifecycle._validate(r.port, value)
        return value

    def _delivery(self, r, i, p, a):
        token = r._row(OAuthToken, OAuthToken.id, i.token_id, lock=True)
        now = trusted_now(r.clock)
        active = token.is_revoked is False and i.issued_at * 1000 <= milliseconds(now) < i.expires_at * 1000
        value = None
        if active:
            r.read(i.issuance_id)
            value = self._credential(r, i, token)
            # Signer/validation work may consume time: fence release again.
            r.read(i.issuance_id)
        return dict(
            receipt=receipt(i), currentActive=active, subject=i.subject if active else None, viewerAccessToken=value
        )

    def issue(
        self,
        operation_id,
        *,
        approval_wire,
        secret,
        possession_proof,
        verifier,
        delivery_key,
        approver_bearer=None,
        recover_only=False,
    ):
        def command(r):
            offer, p, e = r._operation(hex64(operation_id))
            verify_phone(offer.wire, secret=secret, possession_proof=possession_proof, verifier=verifier)
            approval = v2.parse_approval_event_v2(approval_wire)
            if approval.envelope.wire != offer.wire:
                raise ValueError
            commitment = delivery_commitment(
                issuer=r.issuer,
                client_id=r.client_id,
                backend_id=r.backend_id,
                principal=r.principal,
                operation_id=operation_id,
                verifier=verifier,
                delivery_key=delivery_key,
            )
            existing = r._row(V2Issuance, V2Issuance.operation_id, operation_id, optional=True)
            if existing is not None:
                a = r._acceptance(offer, p)
                if (
                    a.approval_wire != approval_wire
                    or a.possession_proof != possession_proof
                    or existing.delivery_commitment != commitment
                    or existing.revision != r._revision(existing, p, a)
                ):
                    raise ValueError
                return self._delivery(r, existing, p, a)
            if recover_only:
                raise ValueError
            u, full, deadline, binding = r._owners(e, p, require_binding=False)
            viewer = self.lifecycle._validate(r.port, approver_bearer)
            if viewer.jti != p.token_id or viewer.subject != u.pubkey:
                raise ValueError
            now = trusted_now(r.clock)
            verify_phone(
                offer.wire,
                secret=secret,
                possession_proof=possession_proof,
                verifier=verifier,
                now_ms=milliseconds(now),
            )
            acceptance_wire = v2.canonical_acceptance_v2_bytes(approval_wire, now_ms=milliseconds(now)).decode("ascii")
            # The raw V2 event was genuinely verified above. This primitive applies
            # the exact binding with history/key/capacity checks; no V1 event verifier.
            SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(r.port).apply_authorized(
                binding, now=now.replace(microsecond=0)
            )
            a = V2Acceptance(
                operation_id=operation_id,
                acceptance_id=v2.acceptance_id_v2(approval_wire),
                approval_id=approval.event_id,
                approval_wire=approval_wire,
                wire=acceptance_wire,
                binding_id=binding.binding_id,
                accepted_at=milliseconds(now),
                possession_proof=possession_proof,
                full_evidence_id=full.evidence_id,
                full_evidence_version=full.evidence_version,
                full_source_hash=full.source_evidence_sha256,
                full_proof_id=full.verified_entitlement.proof_id,
                full_expires_at=milliseconds(full.verified_entitlement.expires_at),
                birth_xid=r.guard.xid,
            )
            r.port.add(a)
            u, full, deadline, binding = r._owners(e, p, require_binding=True)
            now = trusted_now(r.clock)
            issued_at = milliseconds(now) // 1000
            expires_at = (
                min(
                    deadline,
                    e.context.expires_at * 1000,
                    e.semantic.expires_at * 1000,
                    e.pre_enrollment.expires_at,
                    e.x25519_binding_expires_at_ms,
                )
                // 1000
            )
            if expires_at <= issued_at or milliseconds(now) >= expires_at * 1000:
                raise ValueError
            i = V2Issuance(
                operation_id=operation_id,
                acceptance_id=a.acceptance_id,
                issuance_id=secrets.token_hex(32),
                token_id=secrets.token_hex(16),
                subject=u.pubkey,
                client_id=r.client_id,
                backend_id=r.backend_id,
                service_principal=r.principal,
                issuer=r.issuer,
                user_id=u.id,
                delivery_commitment=commitment,
                issued_at=issued_at,
                expires_at=expires_at,
                birth_xid=r.guard.xid,
            )
            if i.issuance_id in (
                operation_id,
                a.acceptance_id,
                a.approval_id,
                offer.request_id,
                offer.authorization_digest,
            ):
                raise ValueError
            credential = issue_rs256_jwt(i.subject, claims(i), cfg=self.lifecycle._config)
            header = jwt.get_unverified_header(credential)
            if header.get("alg") != "RS256" or type(header.get("kid")) is not str:
                raise ValueError
            i.kid = header["kid"]
            i.revision = r._revision(i, p, a)
            token = OAuthToken(
                id=i.token_id,
                access_token=hashlib.sha256(credential.encode("ascii")).hexdigest(),
                token_type="Bearer",
                client_id=i.client_id,
                user_id=i.user_id,
                scope=SCOPE,
                created_at=datetime.fromtimestamp(i.issued_at, timezone.utc).replace(tzinfo=None),
                access_token_expires_at=datetime.fromtimestamp(i.expires_at, timezone.utc).replace(tzinfo=None),
                refresh_token=None,
                refresh_token_expires_at=None,
                is_revoked=False,
                metadata_json=dict(
                    token_contract=TOKEN_CONTRACT,
                    token_use="access",
                    issuer=i.issuer,
                    audience=i.client_id,
                    kid=i.kid,
                    digest_algorithm="sha256",
                    scope_policy_version=SCOPE_POLICY_VERSION,
                ),
            )
            r.port.add(token)
            r.port.add(i)
            self.lifecycle._validate(r.port, credential)
            r.read(i.issuance_id)
            return self._delivery(r, i, p, a)

        return self._run(command)

    def recover(self, operation_id, **proofs):
        return self.issue(operation_id, recover_only=True, **proofs)

    def resolve(self, issuance_id, *, viewer_bearer):
        def command(r):
            viewer = self.lifecycle._validate(r.port, viewer_bearer)
            facts = r.read(issuance_id).facts
            if viewer.jti != facts.token_id or viewer.subject != facts.subject:
                raise ValueError
            i = r._row(V2Issuance, V2Issuance.issuance_id, issuance_id)
            return dict(receipt=receipt(i), subject=facts.subject, currentActive=True)

        return self._run(command)

    def revoke(self, issuance_id, *, viewer_bearer):
        """Cancel only the original digest-bound child, including expired history.

        No signer/key lookup or active-parent grant is needed for self-cancellation.
        Native causal history, catalog guards and token mutation triggers remain
        mandatory. An expired bearer can cancel itself but cannot resolve or issue.
        """

        def command(r):
            if (
                type(viewer_bearer) is not str
                or not 0 < len(viewer_bearer) <= 8192
                or any(not 32 <= ord(c) <= 126 for c in viewer_bearer)
            ):
                raise ValueError
            i = r._row(V2Issuance, V2Issuance.issuance_id, hex64(issuance_id))
            offer, parent, _ = r._operation(i.operation_id)
            a = r._acceptance(offer, parent)
            birth = r._row(V2TokenBirth, V2TokenBirth.token_id, i.token_id)
            token = r._row(OAuthToken, OAuthToken.id, i.token_id, lock=True)
            if (
                (i.client_id, i.backend_id, i.service_principal, i.issuer, i.user_id)
                != (r.client_id, r.backend_id, r.principal, r.issuer, parent.user_id)
                or i.acceptance_id != a.acceptance_id
                or i.revision != r._revision(i, parent, a)
                or birth.birth_xid != i.birth_xid
                or a.birth_xid != i.birth_xid
                or (token.user_id, token.client_id) != (i.user_id, i.client_id)
                or milliseconds(trusted_now(r.clock)) < i.issued_at * 1000
                or not hmac.compare_digest(
                    hashlib.sha256(viewer_bearer.encode("ascii")).hexdigest(), token.access_token
                )
            ):
                raise ValueError
            r.port.execute(update(OAuthToken).where(OAuthToken.id == i.token_id).values(is_revoked=True))
            r.port.flush()
            return dict(
                schema="hodlxxi.social_session_revocation.v2", version=2, issuanceId=i.issuance_id, status="revoked"
            )

        return self._run(command)

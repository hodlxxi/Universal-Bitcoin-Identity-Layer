"""Dormant registered-device observation independent of an expired pairing.

No bearer issuance, admission, runtime route or device authentication is granted
here. The caller owns the PG16 transaction and the existing finalizer catalog
role scope. A future possession-challenge owner must consume this observation
inside that same transaction and recheck it before commit.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re

from app.services import social_messaging_device_proof_profile as profile
from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
from app.services.current_entitlement_evidence_storage import SqlAlchemyTransactionBoundCurrentFullVerifier
from app.services.oauth_scope_policy import client_allowed_scopes, validate_client_scopes
from app.services.social_device_ed25519_association_storage import SqlAlchemyEd25519AssociationStore
from app.services.social_enrollment_v2_finalization_authority import NativeFinalizationAuthority
from app.services.social_enrollment_v2_finalization_storage import NativeV2Effects
from app.services.social_messaging_device_storage import SqlAlchemyTransactionBoundSocialMessagingDeviceStorage
from app.services.social_session_issuance_v2_contract import SCOPE, milliseconds

RUNTIME_ENABLED = False
SESSION_ISSUANCE_IMPLEMENTED = False
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class RegisteredDeviceUnavailable(ValueError):
    def __init__(self):
        super().__init__("registered device observation unavailable")


@dataclass(frozen=True, repr=False)
class RegisteredDeviceObservationV1:
    """Provisional projection, not an authenticated device session."""

    subject: str
    device_id: str
    binding_id: str
    binding_version: int
    association_id: str
    authority_epoch: int
    ed25519_public_key: str
    x25519_public_key_commitment: str
    full_proof_id: str
    current_until_ms: int
    receipt_id: str


def observe_registered_device_v1(session, *, subject, device_id, config, clock):
    """Read original committed native history and freshly locked Full/binding.

    The input IDs are selectors only. In particular, no historical bearer,
    enrollment challenge or approver session is treated as current authority.
    Initial native associations only; rotation support requires a separate
    verified lifecycle contract and is deliberately denied by this reader.
    """
    authority = None
    try:
        if any(type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None for value in (subject, device_id)):
            raise RegisteredDeviceUnavailable()
        authority = NativeFinalizationAuthority(session, config=config, clock=clock)
        guard = authority.guard
        ec = authority.config.evidence_config
        # Same ordering and absence fence as original finalization.
        guard.sql(
            'LOCK TABLE "public"."social_preaccepted_enrollment_v2_atomic_acceptances" IN SHARE ROW EXCLUSIVE MODE'
        )
        row = (
            guard.sql(
                "SELECT r.reservation_id,r.reservation_revision,r.input_wire,r.evidence_compact_jws,"
                "r.statement_compact_jws,i.issuance_id,i.user_id,i.client_id,i.backend_id,i.service_principal,i.issuer "
                "FROM public.social_preaccepted_enrollment_v2_atomic_acceptances r "
                "JOIN public.social_session_v2_issuances i ON i.operation_id=r.operation_id "
                "WHERE r.subject=:subject AND r.device_id=:device AND r.state='accepted' LIMIT 2",
                {"subject": subject, "device": device_id},
            )
            .mappings()
            .one()
        )
        if (row["client_id"], row["backend_id"], row["service_principal"], row["issuer"]) != (
            ec.client_id,
            authority.config.backend_id,
            ec.service_principal,
            ec.issuer,
        ):
            raise RegisteredDeviceUnavailable()
        stored = authority.discover_finalization(
            row["reservation_id"],
            row["reservation_revision"],
            row["input_wire"],
            row["evidence_compact_jws"],
            row["statement_compact_jws"],
        )
        r = stored.reservation
        if r.state != "accepted" or (r.subject, r.device_id) != (subject, device_id):
            raise RegisteredDeviceUnavailable()
        _, claims, evidence_pin, statement_pin = authority.authenticate(
            stored, row["statement_compact_jws"], r.decided_at
        )
        if claims.social_session_issuance_id != row["issuance_id"]:
            raise RegisteredDeviceUnavailable()
        effects = NativeV2Effects(authority)
        if effects.verify_history(stored, evidence_pin=evidence_pin, statement_pin=statement_pin) != stored.receipt.wire:
            raise RegisteredDeviceUnavailable()
        enrollment = profile.parse_enrollment_v2(
            v2.parse_preaccepted_enrollment_verification_input_v2(stored.input_wire).enrollment_wire
        )
        # These are current owners, not the original OAuth token/browser/session.
        owners = (
            guard.sql(
                "SELECT u.is_active,c.is_active AS client_active,c.scope,c.metadata,"
                "s.is_active AS issuer_active,s.backend_id,s.service_principal "
                "FROM public.users u JOIN public.oauth_clients c ON c.client_id=:client "
                "JOIN public.social_session_issuers s ON s.client_id=c.client_id "
                "WHERE u.id=:user AND u.pubkey=:subject FOR UPDATE OF u,c,s",
                {"user": row["user_id"], "subject": subject, "client": ec.client_id},
            )
            .mappings()
            .one()
        )
        if (
            owners["is_active"] is not True
            or owners["client_active"] is not True
            or owners["issuer_active"] is not True
            or (owners["backend_id"], owners["service_principal"]) != (authority.config.backend_id, ec.service_principal)
        ):
            raise RegisteredDeviceUnavailable()
        validate_client_scopes(
            frozenset(SCOPE.split()), client_allowed_scopes({"scope": owners["scope"], "metadata": owners["metadata"]})
        )
        binding = SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(authority.port).binding_for_id(
            enrollment.x25519_binding_id
        )
        association = SqlAlchemyEd25519AssociationStore(authority.port, read_only=True).lock_current_association(
            subject, device_id
        )
        if (
            binding is None
            or binding.active is not True
            or binding.operation != "register"
            or (binding.subject, binding.device_id, binding.binding_id, binding.binding_version)
            != (subject, device_id, enrollment.x25519_binding_id, enrollment.x25519_binding_version)
            or profile.x25519_public_key_commitment_v1(binding.public_key) != enrollment.x25519_public_key_commitment
            or association is None
            or association.state != "active"
            or association.authority_epoch != 1
            or association.association_version != 1
            or association.association_id != r.association_id
            or association.ed25519_public_key != enrollment.ed25519_public_key
        ):
            raise RegisteredDeviceUnavailable()
        observed = authority.now()
        full = SqlAlchemyTransactionBoundCurrentFullVerifier(authority.port).verify_with_evidence_in_transaction(
            subject, now=(_EPOCH + timedelta(milliseconds=observed)).replace(microsecond=0)
        ).verified_entitlement
        effects.check()
        final = authority.now()
        deadline = min(milliseconds(binding.expires_at), milliseconds(full.expires_at))
        if (
            full.subject != subject
            or not milliseconds(binding.valid_from) <= final < deadline
            or not milliseconds(full.valid_from) <= final
            or final < observed
        ):
            raise RegisteredDeviceUnavailable()
        return RegisteredDeviceObservationV1(
            subject,
            device_id,
            binding.binding_id,
            binding.binding_version,
            association.association_id,
            association.authority_epoch,
            association.ed25519_public_key,
            enrollment.x25519_public_key_commitment,
            full.proof_id,
            deadline,
            r.receipt_id,
        )
    except Exception:
        if authority is not None:
            authority._poison()
        raise RegisteredDeviceUnavailable() from None

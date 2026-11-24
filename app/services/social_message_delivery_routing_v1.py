"""Concrete transaction-bound routing over approved native V2 binding history."""

from datetime import datetime, timezone
import hashlib

from sqlalchemy import select

from app.services.current_entitlement_evidence_storage import SqlAlchemyTransactionBoundCurrentFullVerifier
from app.services.privacy_safe_full_directory import derive_privacy_directory_alias
from app.services.social_messaging_device_storage import (
    SqlAlchemyTransactionBoundSocialMessagingDeviceStorage,
)
from app.services.social_messaging_recipient_routing import (
    SocialMessagingRecipientRoutingGateV1,
    VerifiedBindingAuthorization,
    derive_recipient_device_handle,
)
from app.services.social_messaging_recipient_routing_storage import SqlAlchemyRecipientRoutingRepository
from app.services.social_session_issuance_v2_storage import V2Acceptance, V2BindingBirth
from app.services.social_session_issuance_v2_contract import binding_from_wire
from app.services import social_messaging_mobile_pre_enrollment_v2 as v2


class NativeV2BindingVerifier:
    def __init__(self, session):
        self.session = session

    def verify(self, binding, *, now):
        accepted = self.session.execute(
            select(V2Acceptance).where(V2Acceptance.binding_id == binding.binding_id)
        ).scalar_one()
        birth = self.session.execute(
            select(V2BindingBirth).where(V2BindingBirth.binding_id == binding.binding_id)
        ).scalar_one()
        approval = v2.parse_approval_event_v2(accepted.approval_wire)
        record = v2.parse_acceptance_v2(accepted.wire, approval_event_wire=approval.wire)
        if (
            accepted.acceptance_id != record.acceptance_id
            or accepted.approval_id != approval.event_id
            or accepted.operation_id != birth.operation_id
            or accepted.birth_xid != birth.birth_xid
            or binding_from_wire(approval.envelope.wire) != binding
        ):
            raise ValueError("binding authority unavailable")
        from app.services.social_device_ed25519_association_storage import SqlAlchemyEd25519AssociationStore
        from app.services.social_messaging_device_proof_profile import (
            parse_enrollment_v2,
            x25519_public_key_commitment_v1,
        )

        history = SqlAlchemyEd25519AssociationStore(self.session, read_only=True).lock_history(
            binding.subject, binding.device_id
        )
        if history.current is None:
            raise ValueError("binding authority unavailable")
        enrolled = parse_enrollment_v2(history.history[-1].enrollment_wire)
        if (enrolled.x25519_binding_id, enrolled.x25519_binding_version, enrolled.x25519_public_key_commitment) != (
            binding.binding_id,
            binding.binding_version,
            x25519_public_key_commitment_v1(binding.public_key),
        ):
            raise ValueError("binding authority unavailable")
        # Native V2 stores epoch milliseconds. Routing evidence uses UTC seconds.
        observed = datetime.fromtimestamp(accepted.accepted_at // 1000, timezone.utc)
        if not binding.valid_from <= observed <= now < binding.expires_at or not binding.active:
            raise ValueError("binding authority unavailable")
        digest = hashlib.sha256(
            b"HODLXXI_ACCEPTED_NATIVE_V2_BINDING\0" + accepted.wire.encode("ascii") + approval.wire.encode("ascii")
        ).hexdigest()
        return VerifiedBindingAuthorization(
            "hodlxxi-mobile-binding-authorization-v1-sha256:" + digest,
            binding.subject,
            binding.device_id,
            binding.binding_id,
            binding.binding_version,
            binding.public_key,
            binding.valid_from,
            binding.expires_at,
            observed,
            binding.expires_at,
        )


class MessageDeliveryRoutingV1:
    def __init__(self, session, privacy_runtime):
        self.session, self.privacy = session, privacy_runtime
        self.repository = SqlAlchemyRecipientRoutingRepository(session)
        binding_storage = SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(session)
        verifier = SqlAlchemyTransactionBoundCurrentFullVerifier(session)

        class Bindings:
            def current_for_subject(self, subject, *, now, maximum):
                return list(binding_storage.current_for_subject(subject, now=now, maximum=maximum))

        class Full:
            def verify(self, subject, *, now):
                return verifier.verify_in_transaction(subject, now=now)

        self.gate = SocialMessagingRecipientRoutingGateV1(
            repository=self.repository,
            binding_provider=Bindings(),
            binding_authorization_verifier=NativeV2BindingVerifier(session),
            full_entitlement_verifier=Full(),
            alias_secret=privacy_runtime.alias_secret,
            alias_version=privacy_runtime.alias_version,
            mobile_authorization_enabled=True,
        )

    def package(self, viewer, alias, resolver):
        package = resolver.resolve(viewer_subject=viewer, recipient_alias=alias)
        population = self.privacy.full_population_provider()
        targets = [
            entry["subject"]
            for entry in population["entitlements"]
            if entry["subject"] != viewer
            and derive_privacy_directory_alias(
                viewer=viewer,
                target=entry["subject"],
                alias_secret=self.privacy.alias_secret,
                alias_version=self.privacy.alias_version,
            )
            == alias
        ]
        if len(targets) != 1:
            raise ValueError("recipient unavailable")
        self.gate.retain_recipient_package(
            viewer_subject=viewer, recipient_subject=targets[0], recipient_package=package
        )
        return package

    def validate_selection(self, wire, viewer, alias):
        from app.services.social_messaging_recipient_routing import parse_recipient_routing_request

        value = parse_recipient_routing_request(wire)
        snapshot = self.repository.read_snapshot(value.recipient_package_snapshot_id)
        if (
            snapshot is None
            or snapshot.viewer_subject != viewer
            or derive_privacy_directory_alias(
                viewer=viewer,
                target=snapshot.recipient_subject,
                alias_secret=self.privacy.alias_secret,
                alias_version=self.privacy.alias_version,
            )
            != alias
        ):
            raise ValueError("recipient unavailable")

    def _recheck_decision(self, decision):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        full = SqlAlchemyTransactionBoundCurrentFullVerifier(self.session)
        for subject in sorted((decision.viewer_subject, decision.recipient_subject)):
            full.verify_in_transaction(subject, now=now)
        bindings = SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(self.session).current_for_subject(
            decision.recipient_subject, now=now, maximum=16
        )
        if sorted((b.device_id, b.binding_id, b.binding_version) for b in bindings) != sorted(
            (r.device_id, r.binding_id, r.binding_version) for r in decision.routes
        ):
            raise ValueError("recipient unavailable")
        for binding in bindings:
            NativeV2BindingVerifier(self.session).verify(binding, now=now)

    def resolve(self, wire, *, authenticated_viewer_subject):
        from app.services.social_messaging_recipient_routing import parse_recipient_routing_request

        request = parse_recipient_routing_request(wire)
        # A committed exact decision can recover a mailbox write after a crash,
        # even after its package expires. It never substitutes for fresh sender
        # proof, current Full or current independently authorized recipient keys.
        old = self.repository._load_decision(request.message_id, lock=False)
        if old is not None:
            if (
                old.viewer_subject,
                old.envelope_digest,
                old.recipient_package_snapshot_id,
                tuple(r.device_handle for r in old.routes),
            ) != (
                authenticated_viewer_subject,
                request.envelope_digest,
                request.recipient_package_snapshot_id,
                request.recipient_device_handles,
            ):
                raise ValueError("conflicting message id")
            self._recheck_decision(old)
            return old
        decision = self.gate.resolve(wire, authenticated_viewer_subject=authenticated_viewer_subject)
        self._recheck_decision(decision)
        if int(datetime.now(timezone.utc).timestamp() * 1000) >= decision.expires_at:
            raise ValueError("recipient package expired")
        return decision

    def sender_handle(self, facts):
        return derive_recipient_device_handle(
            viewer=facts.subject,
            target=facts.subject,
            binding_id=facts.binding_id,
            alias_secret=self.privacy.alias_secret,
            alias_version=self.privacy.alias_version,
        )

    def lock_historical_handle_owner(self, handle):
        return self.repository.lock_historical_handle_owner(handle)

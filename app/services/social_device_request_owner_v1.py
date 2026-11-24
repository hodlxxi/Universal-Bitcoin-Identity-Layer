"""Explicit atomic owner for enrolled-device message requests.

Native Enrollment V2 supplies the immutable device association and active
session graph. Social supplies only a purpose-bound strict-crypto statement.
UBID rechecks current authority and commits routing plus one exact receipt.
No ciphertext or plaintext is retained by this owner.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets

from sqlalchemy import text

from app.services import social_messaging_device_admission_contract as contract
from app.services import social_messaging_device_proof_profile as profile
from app.services.social_device_challenge_store import SqlAlchemyDeviceChallengeStore
from app.services.social_device_ed25519_association_storage import SqlAlchemyEd25519AssociationStore
from app.services.social_device_verification_statement import verify_social_device_verification_statement_v1
from app.services.social_enrollment_v2_challenge import _binding
from app.services.social_session_issuance_v2_authority import NativeV2AuthorityReader, validated_facts

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def milliseconds():
    return int((datetime.now(timezone.utc) - _EPOCH).total_seconds() * 1000)


class DeviceRequestDenied(ValueError):
    def __init__(self):
        super().__init__("messaging device request unavailable")


class NativeDeviceRequestAuthority:
    """Concrete current-authority port, not a caller-supplied public-key claim."""

    def __init__(self, session, *, lifecycle, client_id, backend_id, principal, issuer, clock=milliseconds):
        self.lifecycle, self.clock = lifecycle, clock
        self.reader = NativeV2AuthorityReader(
            session,
            client_id=client_id,
            backend_id=backend_id,
            principal=principal,
            issuer=issuer,
            clock=lambda: _EPOCH + timedelta(milliseconds=clock()),
        )
        self.session = session

    def read(self, issuance_id, bearer):
        viewer = self.lifecycle._validate(self.reader.port, bearer)
        facts = validated_facts(self.reader.read(issuance_id), self.reader)
        association = SqlAlchemyEd25519AssociationStore(self.reader.port, read_only=True).lock_current_association(
            facts.subject, facts.device_id
        )
        if (
            viewer.jti != facts.token_id
            or viewer.subject != facts.subject
            or association is None
            or association.state != "active"
        ):
            raise DeviceRequestDenied()
        # A consumed Enrollment V2 association is exact to this X25519 binding.
        history = SqlAlchemyEd25519AssociationStore(self.reader.port, read_only=True).lock_history(facts.subject, facts.device_id)
        enrollment = profile.parse_enrollment_v2(history.history[-1].enrollment_wire)
        if (
            enrollment.subject,
            enrollment.device_id,
            enrollment.x25519_binding_id,
            enrollment.x25519_binding_version,
            enrollment.x25519_public_key_commitment,
            enrollment.ed25519_public_key,
        ) != (
            facts.subject,
            facts.device_id,
            facts.binding_id,
            facts.binding_version,
            facts.public_key_commitment,
            association.ed25519_public_key,
        ):
            raise DeviceRequestDenied()
        return facts, association, self.reader._deadline_ms


class DeviceRequestOwnerV1:
    """One caller-owned PG transaction. Results are provisional until COMMIT."""

    def __init__(self, session, *, authority, routing, statement_config, audience, clock=milliseconds):
        if not session.in_transaction() or session.get_bind().dialect.name != "postgresql":
            raise DeviceRequestDenied()
        self.session, self.authority, self.routing = session, authority, routing
        self.statement_config, self.audience, self.clock = statement_config, audience, clock
        self.store = SqlAlchemyDeviceChallengeStore(session)

    def _context(self, facts, association, challenge_id, attempt_id):
        return contract.canonical_verification_context_v1_bytes(
            challenge_kind="device-request-v1",
            challenge_id=challenge_id,
            attempt_id=attempt_id,
            audience=self.audience,
            subject=facts.subject,
            device_id=facts.device_id,
            binding_id=facts.binding_id,
            binding_version=facts.binding_version,
            x25519_public_key_commitment=facts.public_key_commitment,
            profile=profile.DEVICE_PROOF_PROFILE,
            ed25519_public_key=association.ed25519_public_key,
            association_id=association.association_id,
            association_version=association.association_version,
            predecessor_association_id=None,
            authority_epoch=association.authority_epoch,
            session_binding=_binding(facts),
            approver_session_binding=None,
            full_proof_id=facts.full_proof_id,
            approver_full_proof_id=None,
        ).decode("ascii")

    def issue(self, *, issuance_id, bearer, operation, body_wire, routing_wire=None, recipient_alias=None):
        facts, association, deadline = self.authority.read(issuance_id, bearer)
        if operation not in ("ciphertext-submit", "recipient-self-read") or type(body_wire) is not str:
            raise DeviceRequestDenied()
        # Existing profile binds the canonical envelope bytes, or exact self
        # request, with the same frozen domain as the browser/server fixtures.
        if operation == "ciphertext-submit":
            from app.services.social_message_envelope_v128f1 import (
                parse_canonical_message_envelope_wire_v1,
                routing_request_wire_v1,
            )

            envelope = parse_canonical_message_envelope_wire_v1(body_wire)
            if routing_request_wire_v1(envelope, body_wire) != routing_wire:
                raise DeviceRequestDenied()
            self.routing.validate_selection(routing_wire, facts.subject, recipient_alias)
            recipient_handle = None
            path = "/messaging/v1/ciphertext-submit"
        else:
            value = json.loads(body_wire)
            if (
                set(value) != {"deviceHandle", "schema", "version"}
                or value["schema"] != profile.RECIPIENT_SELF_SCHEMA
                or type(value["version"]) is not int
                or value["version"] != 1
                or canonical(value) != body_wire
            ):
                raise DeviceRequestDenied()
            recipient_handle, path = value["deviceHandle"], "/messaging/v1/recipient-self-read"
        challenge_id = secrets.token_hex(32)
        context = self._context(facts, association, challenge_id, secrets.token_hex(32))
        request = canonical(
            dict(
                audience=self.audience,
                bindingId=facts.binding_id,
                bindingVersion=facts.binding_version,
                deviceId=facts.device_id,
                sessionBinding=_binding(facts),
                subject=facts.subject,
                bodyDigest="hodlxxi-social-device-request-body-v1-sha256:"
                + hashlib.sha256(b"HODLXXI_SOCIAL_DEVICE_REQUEST_BODY_V1\0" + body_wire.encode("ascii")).hexdigest(),
                method="POST",
                operation=operation,
                path=path,
                recipientHandle=recipient_handle,
                schema=profile.DEVICE_REQUEST_SCHEMA,
                version=1,
            )
        )
        now = self.clock()
        challenge = canonical(
            dict(
                challengeId=challenge_id,
                domain=profile.DEVICE_CHALLENGE_DOMAIN,
                issuedAt=now,
                expiresAt=min(now + 60000, deadline),
                request=request,
                schema=profile.DEVICE_CHALLENGE_SCHEMA,
                version=1,
            )
        )
        stored = self.store.create_issued(
            context_wire=context,
            challenge_wire=challenge,
            actual_request_wire=request,
            routing_request_wire=routing_wire,
        )
        return dict(
            contextWire=stored.context.wire,
            challengeWire=stored.challenge_wire,
            requestWire=stored.actual_request_wire,
            routingWire=stored.routing_request_wire,
        )

    def consume(self, *, issuance_id, bearer, proof_wire, statement, body_wire, recipient_alias=None):
        proof = profile.parse_device_proof_v1(proof_wire)
        stored = self.store.read_for_update(proof["challengeId"])
        if stored.state != "issued":
            raise DeviceRequestDenied()
        facts, association, deadline = self.authority.read(issuance_id, bearer)
        if (
            self._context(facts, association, stored.context.challenge_id, stored.context.attempt_id)
            != stored.context.wire
        ):
            raise DeviceRequestDenied()
        now = self.clock()
        if not stored.issued_at <= now < min(stored.expires_at, deadline):
            raise DeviceRequestDenied()
        request = json.loads(stored.actual_request_wire)
        digest = (
            "hodlxxi-social-device-request-body-v1-sha256:"
            + hashlib.sha256(b"HODLXXI_SOCIAL_DEVICE_REQUEST_BODY_V1\0" + body_wire.encode("ascii")).hexdigest()
        )
        if request["bodyDigest"] != digest:
            raise DeviceRequestDenied()
        input_wire = contract.canonical_verification_input_v1_bytes(
            context=stored.context.wire,
            challenge=stored.challenge_wire,
            proof=proof_wire,
            approval_event=None,
            actual_request=stored.actual_request_wire,
            routing_request=stored.routing_request_wire,
        ).decode("ascii")
        verify_social_device_verification_statement_v1(
            statement,
            config=self.statement_config,
            expected_context_wire=stored.context.wire,
            expected_input_wire=input_wire,
            now=now,
            challenge_expires_at=stored.expires_at,
            session_expires_at=deadline,
        )
        if request["operation"] == "ciphertext-submit":
            self.routing.validate_selection(stored.routing_request_wire, facts.subject, recipient_alias)
        input_digest = contract.verification_input_digest_v1(input_wire)
        old = (
            self.session.execute(
                text(
                    "SELECT input_digest,result_json FROM public.social_device_request_receipts_v1 WHERE challenge_id=:id"
                ),
                {"id": proof["challengeId"]},
            )
            .mappings()
            .one_or_none()
        )
        if old is not None:
            if old["input_digest"] != input_digest:
                raise DeviceRequestDenied()
            # Sender and recipient revocations apply independently to retries.
            if request["operation"] == "ciphertext-submit":
                self.routing.resolve(stored.routing_request_wire, authenticated_viewer_subject=facts.subject)
            return json.loads(old["result_json"])
        if request["operation"] == "ciphertext-submit":
            decision = self.routing.resolve(stored.routing_request_wire, authenticated_viewer_subject=facts.subject)
            result = dict(
                allowed=True,
                recipientPackageSnapshotId=decision.recipient_package_snapshot_id,
                recipientDeviceHandles=[route.device_handle for route in decision.routes],
                senderDeviceHandle=self.routing.sender_handle(facts),
            )
        else:
            handle = request["recipientHandle"]
            owner = self.routing.lock_historical_handle_owner(handle)
            if owner is None or (
                owner.recipient_subject,
                owner.device_id,
                owner.binding_id,
                owner.binding_version,
            ) != (
                facts.subject,
                facts.device_id,
                facts.binding_id,
                facts.binding_version,
            ):
                raise DeviceRequestDenied()
            result = dict(allowed=True, deviceHandle=handle)
        # Recheck the native chain and association after routing/lock waits.
        again, current, until = self.authority.read(issuance_id, bearer)
        if self._context(
            again, current, stored.context.challenge_id, stored.context.attempt_id
        ) != stored.context.wire or self.clock() >= min(until, stored.expires_at):
            raise DeviceRequestDenied()
        self.session.execute(
            text(
                "INSERT INTO public.social_device_request_receipts_v1(challenge_id,input_digest,result_json,consumed_at) VALUES(:id,:digest,:result,:at)"
            ),
            dict(id=proof["challengeId"], digest=input_digest, result=canonical(result), at=now),
        )
        return result

"""Explicit scoped sessions and message operations over committed native devices.

The finalizer's direct SQL role owns each transaction, including every current
Full/device check and routing decision. No OAuth bearer is minted or revived.
All results leave this boundary only after commit and a final deadline check.
"""

import hashlib
from dataclasses import dataclass
from types import SimpleNamespace

from sqlalchemy import text

from app.services import social_registered_device_session_contract_v1 as contract
from app.services.social_device_request_owner_v1 import DeviceRequestOwnerV1, milliseconds
from app.services.social_enrollment_v2_catalog_roles import catalog_role_scope
from app.services.social_message_delivery_routing_v1 import MessageDeliveryRoutingV1
from app.services.social_registered_device_message_store_v1 import RegisteredDeviceMessageStoreV1
from app.services.social_registered_device_session_owner_v1 import RegisteredDeviceSessionOwnerV1


@dataclass(frozen=True, repr=False)
class RegisteredDeviceRequestFactsV1:
    subject: str
    device_id: str
    binding_id: str
    binding_version: int
    public_key_commitment: str
    full_proof_id: str
    session_binding: str


class RegisteredDeviceRequestAuthorityV1:
    def __init__(self, db, *, config, context_commitment, clock=milliseconds):
        self.db, self.config, self.context, self.clock = db, config, context_commitment, clock

    def read(self, session_id, credential):
        device, deadline = RegisteredDeviceSessionOwnerV1(self.db, config=self.config, clock=self.clock).read(
            session_id=session_id, credential=credential, context_commitment=self.context
        )
        ec = self.config.reservation_config.evidence_config
        preimage = contract.canonical(
            dict(
                issuer=ec.issuer,
                audience=self.config.reservation_config.verification_audience,
                clientId=ec.client_id,
                sessionId=session_id,
                contextCommitment=self.context,
                subject=device.subject,
                deviceId=device.device_id,
                bindingId=device.binding_id,
                bindingVersion=device.binding_version,
                associationId=device.association_id,
                authorityEpoch=device.authority_epoch,
            )
        )
        binding = hashlib.sha256(
            b"HODLXXI_REGISTERED_DEVICE_MESSAGE_SESSION_BINDING_V1\0" + preimage.encode("ascii")
        ).hexdigest()
        facts = RegisteredDeviceRequestFactsV1(
            device.subject,
            device.device_id,
            device.binding_id,
            device.binding_version,
            device.x25519_public_key_commitment,
            device.full_proof_id,
            binding,
        )
        association = SimpleNamespace(
            association_id=device.association_id,
            association_version=1,
            authority_epoch=device.authority_epoch,
            ed25519_public_key=device.ed25519_public_key,
        )
        return facts, association, deadline

    @staticmethod
    def binding(facts):
        return facts.session_binding


class RegisteredDeviceRuntimeV1:
    def __init__(self, *, factory, config, privacy, recipient, statement_config, clock=milliseconds):
        self.factory, self.config, self.privacy = factory, config, privacy
        self.recipient, self.statement_config, self.clock = recipient, statement_config, clock

    def execute(self, command, value, *, bearer):
        deadline = None
        with self.factory() as db, db.begin(), catalog_role_scope(db, self.config.challenge_writer_role):
            owner = RegisteredDeviceSessionOwnerV1(db, config=self.config, clock=self.clock)
            if command == "registered-challenge":
                if set(value) != {"subject", "deviceId", "contextCommitment"} or bearer is not None:
                    contract._deny()
                wire = owner.issue(
                    subject=value["subject"],
                    device_id=value["deviceId"],
                    context_commitment=value["contextCommitment"],
                )
                result, deadline = dict(challengeWire=wire), contract.parse_challenge_v1(wire)["expiresAt"]
            elif command == "registered-consume":
                if (
                    set(value) != {"challengeWire", "proofWire", "statementWire", "contextCommitment"}
                    or bearer is not None
                ):
                    contract._deny()
                issued = owner.consume(
                    challenge_wire=value["challengeWire"],
                    proof_wire=value["proofWire"],
                    statement_wire=value["statementWire"],
                    context_commitment=value["contextCommitment"],
                )
                challenge = contract.parse_challenge_v1(value["challengeWire"])
                deadline = issued.expires_at
                result = dict(
                    sessionId=issued.session_id,
                    credential=issued.credential,
                    expiresAt=deadline,
                    subject=challenge["subject"],
                    deviceId=challenge["deviceId"],
                )
            else:
                auth = value.get("registeredSession")
                if type(auth) is not dict or set(auth) != {"sessionId", "contextCommitment"}:
                    contract._deny()
                args = dict(
                    session_id=auth["sessionId"], context_commitment=auth["contextCommitment"], credential=bearer
                )
                if command == "registered-revoke":
                    if set(value) != {"registeredSession"}:
                        contract._deny()
                    owner.revoke(**args)
                    result = dict(sessionId=auth["sessionId"], status="revoked")
                else:
                    authority = RegisteredDeviceRequestAuthorityV1(
                        db, config=self.config, context_commitment=auth["contextCommitment"], clock=self.clock
                    )
                    facts, association, deadline = authority.read(auth["sessionId"], bearer)
                    result = self._protected(db, command, value, auth, bearer, authority, facts, association, deadline)
                    # Recheck after directory/routing locks and work. Same exact
                    # generation and current Full evidence, inside this transaction.
                    again, current, until = authority.read(auth["sessionId"], bearer)
                    if again != facts or vars(current) != vars(association):
                        contract._deny()
                    deadline = min(deadline, until)
            if deadline is not None and self.clock() >= deadline:
                contract._deny()
        if deadline is not None and self.clock() >= deadline:
            contract._deny()
        return result

    def _protected(self, db, command, value, auth, bearer, authority, facts, association, deadline):
        routing = MessageDeliveryRoutingV1(db, self.privacy)
        owner = DeviceRequestOwnerV1(
            db,
            authority=authority,
            routing=routing,
            statement_config=self.statement_config,
            audience=self.config.reservation_config.verification_audience,
            clock=self.clock,
        )
        owner.store = RegisteredDeviceMessageStoreV1(db, session_id=auth["sessionId"], credential=bearer)
        fields = set(value) - {"registeredSession"}
        if command == "registered-current" and not fields:
            return dict(
                sessionId=auth["sessionId"],
                subject=facts.subject,
                deviceId=facts.device_id,
                expiresAt=deadline,
                authority=dict(subject=facts.subject, status="full", valid=True),
            )
        if command == "registered-directory" and not fields:
            from app.services.privacy_safe_full_directory import PrivacySafeFullDirectoryV1

            return PrivacySafeFullDirectoryV1(
                viewer_subject=facts.subject,
                current_entitlement_resolver=self.privacy.current_entitlement_resolver,
                full_population_provider=self.privacy.full_population_provider,
                alias_secret=self.privacy.alias_secret,
                alias_version=self.privacy.alias_version,
            ).current_directory()
        if command == "registered-self" and not fields:
            handles = (
                db.execute(
                    text(
                        "SELECT device_handle FROM public.social_messaging_recipient_handle_owners "
                        "WHERE recipient_subject=:subject AND device_id=:device AND binding_id=:binding "
                        "AND binding_version=:version ORDER BY device_handle LIMIT 257"
                    ),
                    dict(
                        subject=facts.subject,
                        device=facts.device_id,
                        binding=facts.binding_id,
                        version=facts.binding_version,
                    ),
                )
                .scalars()
                .all()
            )
            if len(handles) > 256:
                contract._deny()
            return dict(
                deviceId=facts.device_id,
                bindingId=facts.binding_id,
                bindingVersion=facts.binding_version,
                publicKey=association.ed25519_public_key,
                handles=handles,
            )
        if command == "registered-package" and fields == {"recipientAlias"}:
            return routing.package(facts.subject, value["recipientAlias"], self.recipient.recipient_resolver)
        if command == "registered-message-challenge" and fields == {
            "operation",
            "bodyWire",
            "routingWire",
            "recipientAlias",
        }:
            return owner.issue(
                issuance_id=auth["sessionId"],
                bearer=bearer,
                operation=value["operation"],
                body_wire=value["bodyWire"],
                routing_wire=value["routingWire"],
                recipient_alias=value["recipientAlias"],
            )
        if command == "registered-inspect" and fields == {"challengeId"}:
            stored = owner.store.read(value["challengeId"])
            if (
                owner._context(facts, association, stored.context.challenge_id, stored.context.attempt_id)
                != stored.context.wire
            ):
                contract._deny()
            return dict(
                contextWire=stored.context.wire,
                challengeWire=stored.challenge_wire,
                requestWire=stored.actual_request_wire,
                routingWire=stored.routing_request_wire,
            )
        if command == "registered-message-consume" and fields == {
            "proofWire",
            "statement",
            "bodyWire",
            "recipientAlias",
        }:
            return owner.consume(
                issuance_id=auth["sessionId"],
                bearer=bearer,
                proof_wire=value["proofWire"],
                statement=value["statement"],
                body_wire=value["bodyWire"],
                recipient_alias=value["recipientAlias"],
            )
        contract._deny()

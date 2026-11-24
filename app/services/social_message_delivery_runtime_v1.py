"""Opt-in private message delivery assembled beside the native Enrollment V2 runtime."""

from dataclasses import replace

from flask import Blueprint, current_app, request
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.services.bearer_credentials import parse_bearer_authorization_header
from app.services.confidential_service_assertion_replay_storage import PostgresConfidentialServiceAssertionReplayStore
from app.services.confidential_service_credentials import (
    GRANT_TYPE,
    issue_service_access_token,
    verify_service_access_token,
)
from app.services.privacy_full_directory_internal_delivery import configured_internal_delivery_runtime
from app.services.social_device_request_owner_v1 import DeviceRequestOwnerV1, NativeDeviceRequestAuthority, canonical
from app.services.social_device_verification_statement import SocialDeviceVerificationStatementConfig
from app.services.social_enrollment_v2_runtime import read_operator_json
from app.services.social_message_delivery_routing_v1 import MessageDeliveryRoutingV1
from app.services.social_messaging_recipient_runtime_configuration import (
    configured_messaging_recipient_internal_runtime,
)

PREFIX = "/internal/v1/social/message-delivery"
EXTENSION = "social_message_delivery_runtime_v1"
bp = Blueprint(EXTENSION, __name__)


class MessageDeliveryRuntime:
    def __init__(self, *, factory, enrollment, privacy, recipient, service_config, statement_config, registered=None):
        self.factory, self.enrollment, self.privacy, self.recipient = factory, enrollment, privacy, recipient
        self.service_config, self.statement_config = service_config, statement_config
        self.replay = PostgresConfidentialServiceAssertionReplayStore(factory)
        self.registered = registered

    def execute(self, command, value, *, bearer):
        if command.startswith("registered-"):
            if self.registered is None:
                raise ValueError()
            return self.registered.execute(command, value, bearer=bearer)
        cfg = self.enrollment.challenge.config
        with self.factory() as db, db.begin():
            authority = NativeDeviceRequestAuthority(
                db,
                lifecycle=self.enrollment.challenge.lifecycle,
                client_id=cfg.client_id,
                backend_id=cfg.backend_id,
                principal=cfg.service_principal,
                issuer=cfg.issuer,
            )
            routing = MessageDeliveryRoutingV1(db, self.privacy)
            owner = DeviceRequestOwnerV1(
                db,
                authority=authority,
                routing=routing,
                statement_config=self.statement_config,
                audience=cfg.audience,
            )
            if command == "self":
                if set(value) != {"issuanceId"}:
                    raise ValueError()
                facts, association, _ = authority.read(value["issuanceId"], bearer)
                handles = (
                    db.execute(
                        text(
                            "SELECT device_handle FROM public.social_messaging_recipient_handle_owners WHERE recipient_subject=:subject AND device_id=:device AND binding_id=:binding AND binding_version=:version ORDER BY device_handle LIMIT 257"
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
                    raise ValueError()
                return dict(
                    deviceId=facts.device_id,
                    bindingId=facts.binding_id,
                    bindingVersion=facts.binding_version,
                    publicKey=association.ed25519_public_key,
                    handles=handles,
                )
            if command == "package":
                if set(value) != {"issuanceId", "recipientAlias"}:
                    raise ValueError()
                facts, _, _ = authority.read(value["issuanceId"], bearer)
                return routing.package(facts.subject, value["recipientAlias"], self.recipient.recipient_resolver)
            if command == "challenge":
                if set(value) != {"issuanceId", "operation", "bodyWire", "routingWire", "recipientAlias"}:
                    raise ValueError()
                return owner.issue(
                    issuance_id=value["issuanceId"],
                    bearer=bearer,
                    operation=value["operation"],
                    body_wire=value["bodyWire"],
                    routing_wire=value["routingWire"],
                    recipient_alias=value["recipientAlias"],
                )
            if command == "inspect":
                if set(value) != {"issuanceId", "challengeId"}:
                    raise ValueError()
                facts, association, _ = authority.read(value["issuanceId"], bearer)
                stored = owner.store.read(value["challengeId"])
                if (
                    owner._context(facts, association, stored.context.challenge_id, stored.context.attempt_id)
                    != stored.context.wire
                ):
                    raise ValueError()
                return dict(
                    contextWire=stored.context.wire,
                    challengeWire=stored.challenge_wire,
                    requestWire=stored.actual_request_wire,
                    routingWire=stored.routing_request_wire,
                )
            if command == "consume":
                if set(value) != {"issuanceId", "proofWire", "statement", "bodyWire", "recipientAlias"}:
                    raise ValueError()
                return owner.consume(
                    issuance_id=value["issuanceId"],
                    bearer=bearer,
                    proof_wire=value["proofWire"],
                    statement=value["statement"],
                    body_wire=value["bodyWire"],
                    recipient_alias=value["recipientAlias"],
                )
            raise ValueError()


def _reply(value, status=200):
    response = current_app.response_class(canonical(value), status=status, content_type="application/json")
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.post(PREFIX + "/<command>", provide_automatic_options=False)
def command(command):
    runtime = current_app.extensions.get(EXTENSION)
    if type(runtime) is not MessageDeliveryRuntime:
        return _reply({"error": "unavailable"}, 404)
    try:
        if (
            request.query_string
            or request.content_type != "application/json"
            or request.headers.get("Content-Encoding")
            or not request.content_length
            or not 1 <= request.content_length <= 65536
        ):
            return _reply({"error": "invalid_request"}, 400)
        raw = request.get_data(as_text=True)
        import json

        value = json.loads(raw)
        if type(value) is not dict or canonical(value) != raw:
            return _reply({"error": "invalid_request"}, 400)
        if command == "service-token":
            if set(value) != {"assertion"}:
                raise ValueError()
            token = issue_service_access_token(
                value["assertion"],
                config=runtime.service_config,
                replay_consumer=runtime.replay,
                signing_key=runtime.privacy.service_signing_key,
                signing_kid=runtime.privacy.service_signing_kid,
            )
            return _reply({"access_token": token, "token_type": "Bearer"})
        service = parse_bearer_authorization_header(request.headers.get("Authorization", ""))
        verify_service_access_token(service, config=runtime.service_config)
        if command in ("registered-challenge", "registered-consume"):
            if request.headers.get("X-HODLXXI-Viewer-Authorization") is not None:
                raise ValueError()
            bearer = None
        else:
            bearer = parse_bearer_authorization_header(request.headers.get("X-HODLXXI-Viewer-Authorization", ""))
        result = runtime.execute(command, value, bearer=bearer)
        # COMMIT completed before the result can leave the private boundary.
        return _reply(result)
    except Exception:
        return _reply({"error": "unavailable"}, 403)


def install_message_delivery(app, enrollment_runtime, path=None):
    if path is None:
        return False
    manifest = read_operator_json(path)
    registered_enabled = manifest.get("registeredDeviceSessions", False)
    if (
        set(manifest) - {"registeredDeviceSessions"}
        != {"schema", "enabled", "databaseCredentialsPath", "roleName", "roleOid", "statementTrust"}
        or type(registered_enabled) is not bool
        or manifest["schema"] != "ubid.social_message_delivery.runtime.v1"
        or manifest["enabled"] is not True
    ):
        raise ValueError("invalid message delivery configuration")
    credentials = read_operator_json(manifest["databaseCredentialsPath"])
    if (
        set(credentials) != {"schema", "dsn"}
        or credentials["schema"] != "ubid.social_message_delivery.database_credentials.v1"
    ):
        raise ValueError("invalid message delivery configuration")
    engine = create_engine(credentials["dsn"], hide_parameters=True, pool_pre_ping=True)
    try:
        with engine.connect() as db:
            identity = db.execute(
                text(
                    "SELECT current_database(),current_user,session_user,r.oid,r.rolsuper,r.rolcreatedb,r.rolcreaterole,current_setting('server_version_num')::int FROM pg_roles r WHERE rolname=current_user"
                )
            ).one()
            if (
                identity[0] != enrollment_runtime.engines[0].url.database
                or identity[1] != enrollment_runtime.engines[0].url.username
                or tuple(identity[1:4]) != (manifest["roleName"], manifest["roleName"], manifest["roleOid"])
                or any(identity[4:7])
                or not 160000 <= identity[7] < 170000
            ):
                raise ValueError()
            if db.execute(
                text(
                    "SELECT pg_has_role(current_user,tableowner,'MEMBER') FROM pg_tables WHERE schemaname='public' AND tablename='social_device_request_receipts_v1'"
                )
            ).scalar_one():
                raise ValueError()
        privacy = configured_internal_delivery_runtime(app)
        recipient = configured_messaging_recipient_internal_runtime(app)
        cfg = replace(
            privacy.service_config,
            service_scope="social:message-delivery",
            service_purpose="social_message_delivery",
            token_endpoint_audience=privacy.service_config.issuer + PREFIX + "/service-token",
            service_resource_audience=privacy.service_config.issuer + PREFIX,
        )
        trust_value = dict(manifest["statementTrust"])
        trust_value["trusted_jwks"] = tuple(trust_value["trusted_jwks"])
        trust = SocialDeviceVerificationStatementConfig(**trust_value)
        if (
            trust.issuer != enrollment_runtime.enrollment.challenge.config.audience
            or trust.client_id != enrollment_runtime.enrollment.challenge.config.client_id
            or trust.audience != cfg.issuer + "/internal/v1/social/device-admission/consume"
        ):
            raise ValueError()
        registered = None
        if registered_enabled:
            from app.services.social_registered_device_runtime_v1 import RegisteredDeviceRuntimeV1

            composition = enrollment_runtime.enrollment.operations.composition
            registered = RegisteredDeviceRuntimeV1(
                factory=composition._factory,
                config=composition._config,
                privacy=privacy,
                recipient=recipient,
                statement_config=trust,
            )
        app.extensions[EXTENSION] = MessageDeliveryRuntime(
            factory=sessionmaker(engine),
            enrollment=enrollment_runtime.enrollment,
            privacy=privacy,
            recipient=recipient,
            service_config=cfg,
            statement_config=trust,
            registered=registered,
        )
        app.register_blueprint(bp)
        return True
    except Exception:
        engine.dispose()
        raise ValueError("invalid message delivery configuration") from None

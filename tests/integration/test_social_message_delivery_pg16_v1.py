"""Native authority and private message delivery on disposable PG16 only."""

from datetime import datetime, timezone
from types import SimpleNamespace

from sqlalchemy.orm import Session

from app.services.social_session_issuance_v2_authority import NativeV2AuthorityReader
from tests.integration.message_delivery_pg16 import message_pg16
from tests.integration.test_social_session_issuance_v2_postgresql import native_graph


def test_genuine_enrollment_proof_finalizes_before_message_authority(message_pg16, monkeypatch):
    import json
    import subprocess
    import time
    from pathlib import Path

    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

    from app.services import social_messaging_device_proof_profile as profile
    from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
    from app.services.social_device_request_owner_v1 import NativeDeviceRequestAuthority
    from app.services.social_enrollment_v2_finalization import V2FinalizationOwner
    from tests.integration.test_social_enrollment_v2_reservation_postgresql import owner as reserve_owner
    from tests.integration.test_social_enrollment_v2_reservation_postgresql import reservation_native
    from tests.unit.test_social_enrollment_v2_finalization import signed_statement

    owner, issuer, finalizer, reader = message_pg16
    reader = issuer
    ed = ed25519.Ed25519PrivateKey.generate()
    graph = native_graph.__wrapped__(
        (owner, issuer),
        monkeypatch,
        SimpleNamespace(
            param={"ed25519_public_key": ed.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}
        ),
    )
    fixture = reservation_native.__wrapped__(
        graph, SimpleNamespace(module=SimpleNamespace(NATIVE_FRESHNESS_PROFILE="native-v2-60s-v1"))
    )
    parsed = v2.parse_preaccepted_enrollment_verification_input_v2(fixture[2])
    signature = ed.sign(profile.canonical_enrollment_proof_signing_preimage_v2(parsed.enrollment_wire)).hex()
    proof = profile.canonical_enrollment_proof_v2_bytes(
        enrollment_challenge_id=parsed.context.challenge_id,
        enrollment_digest=profile.enrollment_v2_digest(parsed.enrollment_wire),
        public_key=parsed.context.ed25519_public_key,
        signature=signature,
    ).decode()
    wire = v2.canonical_preaccepted_enrollment_verification_input_v2_bytes(
        approval_event_wire=parsed.approval.wire,
        context_wire=parsed.context.wire,
        enrollment_wire=parsed.enrollment_wire,
        phone_proof_wire=proof,
    ).decode()
    fixture = fixture[:2] + (wire,) + fixture[3:]
    from sqlalchemy import text

    from app.services.social_enrollment_v2_catalog_roles import ChallengeWriterCatalogPin, catalog_role_scope

    with owner.connect() as db:
        oid = db.execute(text("SELECT oid FROM pg_roles WHERE rolname='h588_message_issuer'")).scalar_one()
    pin = ChallengeWriterCatalogPin("h588_message_issuer", oid)
    with Session(finalizer) as db, db.begin(), catalog_role_scope(db, pin):
        reservation = reserve_owner(db, fixture).reserve(wire, issuance_id=fixture[3])
    service_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time() * 1000)
    config, _ = signed_statement(wire, fixture[4], now, key=service_key, expires_at=reservation.expires_at)
    from dataclasses import replace

    from sqlalchemy import text

    from app.services.social_enrollment_v2_catalog_roles import ChallengeWriterCatalogPin

    with owner.connect() as db:
        oid = db.execute(text("SELECT oid FROM pg_roles WHERE rolname='h588_message_issuer'")).scalar_one()
    config = replace(config, challenge_writer_role=ChallengeWriterCatalogPin("h588_message_issuer", oid))
    sc = config.statement_config
    with Session(issuer) as db, db.begin():
        facts = graph[2]._reader(db).read(fixture[3]).facts
    social = Path(__file__).resolve().parents[3] / "social"
    node = social.parent / ".toolchains/node20/bin/node"
    if not social.is_dir() or not node.is_file():
        __import__("pytest").skip("explicit paired Social/Node20 release required")
    request = dict(
        serviceSigningKeyPem=service_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode(),
        freshnessProfile="native-v2-60s-v1",
        signer=dict(
            algorithm="RS256",
            audience=sc.audience,
            clientId=sc.client_id,
            issuer=sc.issuer,
            kid=sc._keys[0].kid,
            purpose=sc.purpose,
            servicePrincipal=sc.service_principal,
        ),
        request=dict(
            approverSessionExpiresAtMs=facts.approver_expires_at_ms,
            contextWire=parsed.context.wire,
            expectedAudience=sc.audience,
            expectedAlgorithm="RS256",
            expectedClientId=sc.client_id,
            expectedIssuer=sc.issuer,
            expectedKid=sc._keys[0].kid,
            expectedPurpose=sc.purpose,
            expectedServicePrincipal=sc.service_principal,
            fullExpiresAtMs=facts.full_expires_at_ms,
            inputWire=wire,
            now=now,
            phoneSessionExpiresAtMs=facts.phone_expires_at_ms,
            statementLifetimeMs=reservation.expires_at - now,
            x25519BindingExpiresAtMs=facts.binding_expires_at_ms,
        ),
    )
    result = subprocess.run(
        [str(node), str(social / "scripts/verify-native-enrollment-release-v2.mjs")],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 0, "real Social strict enrollment verifier failed"
    import sys

    locations = []

    def trace(frame, event, arg):
        if event == "exception" and frame.f_code.co_name == "_attest_relation_definition":
            actual = frame.f_locals.get("r", {})
            wanted = frame.f_locals.get("wanted", {})
            print(
                "NATIVE_CATALOG_DIFF",
                frame.f_locals.get("relation", {}).get("relname"),
                {
                    key: (actual.get(key), wanted.get(key))
                    for key in set(actual) | set(wanted)
                    if actual.get(key) != wanted.get(key)
                },
            )
        if event == "exception" and "/app/services/" in frame.f_code.co_filename:
            locations.append((frame.f_code.co_filename.rsplit("/", 1)[-1], frame.f_lineno, arg[0].__name__))
        return trace

    if __import__("os").environ.get("H588_TEST_TRACE") == "1":
        sys.settrace(trace)
    try:
        with Session(finalizer) as db, db.begin(), catalog_role_scope(db, pin):
            accepted = V2FinalizationOwner(db, config=config, clock=lambda: int(time.time() * 1000)).finalize(
                reservation_id=reservation.reservation_id,
                reservation_revision=1,
                verification_input_wire=wire,
                evidence_compact_jws=reservation.evidence_compact_jws,
                statement_compact_jws=result.stdout,
                issuance_id=fixture[3],
            )
    except Exception:
        print("NATIVE_FINALIZATION_EXCEPTION_LOCATIONS", locations[-25:])
        raise
    finally:
        sys.settrace(None)
    assert json.loads(accepted.receipt_wire)["status"] == "committed"
    delivered = graph[2].recover(graph[3], **graph[4])
    with Session(reader) as db, db.begin():
        authority = NativeDeviceRequestAuthority(
            db,
            lifecycle=graph[2].lifecycle,
            client_id=sc.client_id,
            backend_id="synthetic-backend",
            principal=sc.service_principal,
            issuer="https://synthetic-ubid.example",
        )
        current, association, _ = authority.read(fixture[3], delivered["viewerAccessToken"])
        assert current.subject == parsed.context.subject
        assert association.ed25519_public_key == parsed.context.ed25519_public_key

    # The new observation deliberately does not authenticate an expired
    # original bearer. Its current Full and binding must still be valid.
    import pytest

    from app.services.social_registered_device_observation_v1 import (
        RegisteredDeviceUnavailable,
        observe_registered_device_v1,
    )

    later = delivered["receipt"]["expiresAt"] + 1
    with Session(finalizer) as db, db.begin(), catalog_role_scope(db, pin):
        observed = observe_registered_device_v1(
            db,
            subject=parsed.context.subject,
            device_id=parsed.context.device_id,
            config=config,
            clock=lambda: later,
        )
        assert observed.subject == parsed.context.subject
        assert observed.device_id == parsed.context.device_id
        assert observed.association_id == association.association_id
        assert observed.ed25519_public_key == association.ed25519_public_key
        assert observed.current_until_ms > later
    with pytest.raises(RegisteredDeviceUnavailable):
        with Session(finalizer) as db, db.begin(), catalog_role_scope(db, pin):
            observe_registered_device_v1(
                db,
                subject=parsed.context.subject,
                device_id="0" * 64,
                config=config,
                clock=lambda: later,
            )
    with pytest.raises(RegisteredDeviceUnavailable):
        with Session(finalizer) as db, db.begin(), catalog_role_scope(db, pin):
            observe_registered_device_v1(
                db,
                subject=parsed.context.subject,
                device_id=parsed.context.device_id,
                config=config,
                clock=lambda: observed.current_until_ms,
            )

    from app.services import social_registered_device_session_contract_v1 as login
    from app.services.social_registered_device_session_owner_v1 import RegisteredDeviceSessionOwnerV1, credential_digest

    context = "ab" * 32

    def login_owner(db, at=later):
        return RegisteredDeviceSessionOwnerV1(db, config=config, clock=lambda: at)

    from app.services.social_registered_device_runtime_v1 import RegisteredDeviceRuntimeV1

    runtime = RegisteredDeviceRuntimeV1(
        factory=lambda: Session(finalizer),
        config=config,
        privacy=SimpleNamespace(alias_secret=b"p" * 32, alias_version=1),
        recipient=None,
        statement_config=None,
        clock=lambda: later,
    )
    challenge_wire = runtime.execute(
        "registered-challenge",
        dict(subject=parsed.context.subject, deviceId=parsed.context.device_id, contextCommitment=context),
        bearer=None,
    )["challengeWire"]
    challenge = login.parse_challenge_v1(challenge_wire)
    proof_wire = login.canonical(
        dict(
            challengeId=challenge["challengeId"],
            schema=login.PROOF_SCHEMA,
            signature=ed.sign(login.signing_preimage_v1(challenge_wire)).hex(),
            version=1,
        )
    )
    result = subprocess.run(
        [str(node), str(social / "scripts/verify-registered-device-session-release-v1.mjs")],
        input=json.dumps(
            dict(
                serviceSigningKeyPem=request["serviceSigningKeyPem"],
                kid=sc._keys[0].kid,
                request=dict(
                    challengeWire=challenge_wire,
                    proofWire=proof_wire,
                    issuer=challenge["issuer"],
                    audience=challenge["audience"],
                    clientId=challenge["clientId"],
                    contextCommitment=context,
                    now=later,
                ),
            )
        ),
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 0, "real Social registered-device proof verification failed"
    args = dict(
        challenge_wire=challenge_wire,
        proof_wire=proof_wire,
        statement_wire=result.stdout,
        context_commitment=context,
    )
    with pytest.raises(login.RegisteredDeviceSessionContractError):
        with Session(finalizer) as db, db.begin(), catalog_role_scope(db, pin):
            login_owner(db).consume(**dict(args, context_commitment="cd" * 32))
    with pytest.raises(login.RegisteredDeviceSessionContractError):
        with Session(finalizer) as db, db.begin(), catalog_role_scope(db, pin):
            login_owner(db, challenge["expiresAt"]).consume(**args)
    issued_wire = runtime.execute(
        "registered-consume",
        dict(
            challengeWire=challenge_wire,
            proofWire=proof_wire,
            statementWire=result.stdout,
            contextCommitment=context,
        ),
        bearer=None,
    )
    issued = SimpleNamespace(
        session_id=issued_wire["sessionId"], credential=issued_wire["credential"], expires_at=issued_wire["expiresAt"]
    )
    assert issued.expires_at > later
    with Session(owner) as db, db.begin():
        stored = db.execute(
            text("SELECT credential_digest FROM public.social_registered_device_sessions_v1 WHERE session_id=:id"),
            {"id": issued.session_id},
        ).scalar_one()
        assert stored == credential_digest(issued.credential)
        assert stored != issued.credential
    with pytest.raises(login.RegisteredDeviceSessionContractError):
        with Session(finalizer) as db, db.begin(), catalog_role_scope(db, pin):
            login_owner(db).consume(**args)
    auth = dict(session_id=issued.session_id, credential=issued.credential, context_commitment=context)
    scoped = dict(registeredSession=dict(sessionId=issued.session_id, contextCommitment=context))
    current = runtime.execute("registered-current", scoped, bearer=issued.credential)
    assert current["authority"] == dict(subject=parsed.context.subject, status="full", valid=True)
    device = runtime.execute("registered-self", scoped, bearer=issued.credential)
    assert device["deviceId"] == parsed.context.device_id
    assert device["publicKey"] == association.ed25519_public_key
    # Message proofs receive a new generation binding, independent of the
    # expired enrollment's OAuth/preimage. This challenge is real PG storage.
    body_wire = login.canonical(
        dict(deviceHandle="d_AAAAAAAAAAAAAAAAAAAAAA", schema=profile.RECIPIENT_SELF_SCHEMA, version=1)
    )
    message_challenge = runtime.execute(
        "registered-message-challenge",
        dict(scoped, operation="recipient-self-read", bodyWire=body_wire, routingWire=None, recipientAlias=None),
        bearer=issued.credential,
    )
    ctx = json.loads(message_challenge["contextWire"])
    assert ctx["subject"] == parsed.context.subject
    assert ctx["sessionBinding"] != json.loads(parsed.context.wire)["sessionBinding"]
    assert (
        ctx["sessionBinding"] == json.loads(json.loads(message_challenge["challengeWire"])["request"])["sessionBinding"]
    )
    from app.services.social_device_verification_statement import SocialDeviceVerificationStatementConfig
    from app.services.social_messaging_recipient_routing import (
        SNAPSHOT_SCHEMA,
        SOURCE,
        RecipientRoutingSnapshot,
        RecipientRoutingSnapshotRoute,
    )
    from app.services.social_messaging_recipient_routing_storage import SqlAlchemyRecipientRoutingRepository

    # Synthetic retained route owned by this exact registered receiving device.
    # It is not an assertion that a second real browser has completed enrollment.
    with Session(finalizer) as db, db.begin():
        SqlAlchemyRecipientRoutingRepository(db).retain_snapshot(
            RecipientRoutingSnapshot(
                schema=SNAPSHOT_SCHEMA,
                version=1,
                source=SOURCE,
                viewer_subject="c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                recipient_subject=parsed.context.subject,
                alias_version=1,
                recipient_package_snapshot_id="sha256:" + "22" * 32,
                issued_at=later,
                expires_at=later + 60000,
                complete=True,
                routes=(
                    RecipientRoutingSnapshotRoute(
                        device_handle="d_AAAAAAAAAAAAAAAAAAAAAA",
                        device_id=parsed.context.device_id,
                        binding_id=parsed.context.binding_id,
                        binding_version=parsed.context.binding_version,
                        authorization_proof_id="hodlxxi-mobile-binding-authorization-v1-sha256:" + "33" * 32,
                        authorization_valid_from=later - 1000,
                        authorization_expires_at=later + 60000,
                    ),
                ),
            )
        )
    runtime.statement_config = SocialDeviceVerificationStatementConfig(
        enabled=True,
        issuer=challenge["audience"],
        audience=challenge["issuer"] + "/internal/v1/social/device-admission/consume",
        client_id=sc.client_id,
        service_principal=sc.service_principal,
        trusted_jwks=sc.trusted_jwks,
    )
    msg_proof = profile.canonical_device_proof_v1_bytes(
        challenge_id=ctx["challengeId"],
        public_key=association.ed25519_public_key,
        signature=ed.sign(
            profile.canonical_device_proof_signing_preimage_v1(
                message_challenge["challengeWire"], association.ed25519_public_key
            )
        ).hex(),
    ).decode("ascii")
    message_statement = subprocess.run(
        [str(node), str(social / "scripts/verify-registered-message-release-v1.mjs")],
        input=json.dumps(
            dict(
                serviceSigningKeyPem=request["serviceSigningKeyPem"],
                kid=sc._keys[0].kid,
                issuerOrigin=challenge["issuer"],
                socialOrigin=challenge["audience"],
                clientId=sc.client_id,
                servicePrincipal=sc.service_principal,
                stored=message_challenge,
                proofWire=msg_proof,
                now=later,
            )
        ),
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert message_statement.returncode == 0, "real Social strict registered-device message proof failed"
    request_value = dict(
        scoped, proofWire=msg_proof, statement=message_statement.stdout, bodyWire=body_wire, recipientAlias=None
    )
    allowed = runtime.execute("registered-message-consume", request_value, bearer=issued.credential)
    assert allowed == dict(allowed=True, deviceHandle="d_AAAAAAAAAAAAAAAAAAAAAA")
    # An exact lost-response retry recovers the same immutable authorization.
    assert runtime.execute("registered-message-consume", request_value, bearer=issued.credential) == allowed
    with pytest.raises(login.RegisteredDeviceSessionContractError):
        runtime.execute(
            "registered-message-consume",
            dict(request_value, registeredSession=dict(sessionId=issued.session_id, contextCommitment="cd" * 32)),
            bearer=issued.credential,
        )
    with Session(finalizer) as db, db.begin(), catalog_role_scope(db, pin):
        device, deadline = login_owner(db).read(**auth)
        assert device.association_id == association.association_id
        assert deadline == issued.expires_at
    for invalid in (dict(auth, credential="00" * 32), dict(auth, context_commitment="cd" * 32)):
        with pytest.raises(login.RegisteredDeviceSessionContractError):
            with Session(finalizer) as db, db.begin(), catalog_role_scope(db, pin):
                login_owner(db).read(**invalid)
    with Session(finalizer) as db, db.begin(), catalog_role_scope(db, pin):
        login_owner(db).revoke(**auth)
    # Termination is idempotent and remains possible after session expiry.
    runtime.clock = lambda: issued.expires_at + 1
    assert runtime.execute("registered-revoke", scoped, bearer=issued.credential)["status"] == "revoked"
    with pytest.raises(login.RegisteredDeviceSessionContractError):
        with Session(finalizer) as db, db.begin(), catalog_role_scope(db, pin):
            login_owner(db).read(**auth)
    from app.services import social_registered_device_session_owner_v1 as session_owner
    from app.services.social_registered_device_catalog_v1 import attest_registered_device_catalog_v1

    with monkeypatch.context() as patch:
        patch.setattr(session_owner, "MAX_RETAINED_CHALLENGES", 1)
        runtime.clock = lambda: later + 60001
        with pytest.raises(login.RegisteredDeviceSessionContractError):
            runtime.execute(
                "registered-challenge",
                dict(subject=parsed.context.subject, deviceId=parsed.context.device_id, contextCommitment=context),
                bearer=None,
            )
    with Session(finalizer) as db, db.begin():
        assert attest_registered_device_catalog_v1(db.connection())
    with Session(owner) as db, db.begin():
        db.execute(text("DROP TRIGGER registered_session_immutable_v1 ON public.social_registered_device_sessions_v1"))
    with pytest.raises(login.RegisteredDeviceSessionContractError):
        with Session(finalizer) as db, db.begin():
            attest_registered_device_catalog_v1(db.connection())

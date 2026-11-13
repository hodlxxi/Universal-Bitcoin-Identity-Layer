from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base
from app.services import social_device_ed25519_association_storage as storage
from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_device_ed25519_association_lifecycle as lifecycle
from app.services import social_messaging_device_proof_profile as profile
from app.services.social_device_verification_statement import (
    AuthenticatedSocialDeviceVerificationStatementV1,
    SocialDeviceVerificationStatementConfig,
    verify_social_device_verification_statement_v1,
)

FIXTURES = Path(__file__).parents[1] / "fixtures"
VECTORS = json.loads((FIXTURES / "social_messaging_device_ed25519_association_lifecycle_v1.json").read_bytes())
ADMISSION = json.loads((FIXTURES / "social_device_admission_v1.json").read_bytes())
MIGRATION = Path(__file__).parents[2] / "migrations/2026-09-22_social_device_ed25519_association_storage_v1.sql"
ERROR = "^social device ed25519 association storage unavailable$"


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def evidence(name="initial", *, version=1, epoch=1, predecessor=None, enrollment_wire=None):
    """Synthetic exact shape; the verifier's signed-vector tests own RSA proof."""
    enrollment_wire = enrollment_wire or VECTORS["enrollmentWires"][name]
    enrollment = profile.parse_enrollment_v2(enrollment_wire)
    association_id = lifecycle.association_id_v1(enrollment_wire, version, predecessor)
    fields = json.loads(ADMISSION["vectors"]["enrollmentV2"]["contextWire"])
    fields.update(
        associationId=association_id,
        associationVersion=version,
        authorityEpoch=epoch,
        predecessorAssociationId=predecessor,
        subject=enrollment.subject,
        deviceId=enrollment.device_id,
        ed25519PublicKey=enrollment.ed25519_public_key,
        challengeId=enrollment.enrollment_challenge_id,
        audience=enrollment.audience,
        bindingId=enrollment.x25519_binding_id,
        bindingVersion=enrollment.x25519_binding_version,
        x25519PublicKeyCommitment=enrollment.x25519_public_key_commitment,
    )
    context_wire = canonical(fields)
    admission.parse_verification_context_v1(context_wire)
    proof = profile.canonical_enrollment_proof_v2_bytes(
        enrollment_challenge_id=enrollment.enrollment_challenge_id,
        enrollment_digest=profile.enrollment_v2_digest(enrollment_wire),
        public_key=enrollment.ed25519_public_key,
        signature="11" * 64,
    ).decode("ascii")
    unsigned = profile.enrollment_approval_unsigned_event_v2(enrollment_wire)
    event_id = hashlib.sha256(
        canonical(
            [
                0,
                enrollment.subject,
                unsigned["created_at"],
                unsigned["kind"],
                unsigned["tags"],
                unsigned["content"],
            ]
        ).encode("ascii")
    ).hexdigest()
    approval = canonical({**unsigned, "pubkey": enrollment.subject, "id": event_id, "sig": "22" * 64})
    input_wire = admission.canonical_verification_input_v1_bytes(
        context=context_wire,
        challenge=enrollment_wire,
        proof=proof,
        approval_event=approval,
        actual_request=None,
        routing_request=None,
    ).decode("ascii")
    statement = object.__new__(AuthenticatedSocialDeviceVerificationStatementV1)
    for field, value in {
        "result": admission.ENROLLMENT_V2_RESULT,
        "purpose": admission.STATEMENT_PURPOSE,
        "issuer": enrollment.audience,
        "challenge_kind": "enrollment-v2",
        "challenge_id": enrollment.enrollment_challenge_id,
        "attempt_id": fields["attemptId"],
        "context_digest": admission.verification_context_digest_v1(context_wire),
        "input_digest": admission.verification_input_digest_v1(input_wire),
        "issued_at": enrollment.issued_at,
        "expires_at": enrollment.expires_at,
    }.items():
        object.__setattr__(statement, field, value)
    return input_wire, statement, enrollment.issued_at


def test_sqlite_shared_metadata_create_drop_and_authority_rejected():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    assert storage.CHAIN_TABLE in Base.metadata.tables
    assert storage.EVENT_TABLE in Base.metadata.tables
    factory = sessionmaker(engine)
    with (
        factory.begin() as session,
        pytest.raises(storage.SocialDeviceEd25519AssociationStorageUnavailable, match=ERROR),
    ):
        storage.SqlAlchemyEd25519AssociationStore(session)
    Base.metadata.drop_all(engine)


def test_synthetic_enrollment_evidence_binds_frozen_creation_vectors():
    for name, version, epoch, predecessor in (
        ("initial", 1, 1, None),
        ("firstRotation", 2, 2, VECTORS["creationVectors"]["initial"]["associationId"]),
        ("secondRotation", 3, 5, VECTORS["creationVectors"]["firstRotation"]["associationId"]),
        ("reenrollment", 4, 7, VECTORS["creationVectors"]["secondRotation"]["associationId"]),
    ):
        input_wire, statement, now = evidence(name, version=version, epoch=epoch, predecessor=predecessor)
        parsed = admission.parse_verification_input_v1(input_wire)
        assert parsed.context.association_id == VECTORS["creationVectors"][name]["associationId"]
        assert statement.input_digest == admission.verification_input_digest_v1(input_wire)
        assert now == profile.parse_enrollment_v2(parsed.challenge_wire).issued_at


def test_real_statement_verifier_output_is_accepted_by_storage_boundary():
    input_wire, _synthetic, issued_at = evidence()
    value = admission.parse_verification_input_v1(input_wire)
    now = issued_at + 1000
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()

    def encoded_integer(number):
        raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    config = SocialDeviceVerificationStatementConfig(
        enabled=True,
        issuer=value.context.audience,
        audience=ADMISSION["configuration"]["audience"],
        client_id=ADMISSION["configuration"]["clientId"],
        service_principal=ADMISSION["configuration"]["servicePrincipal"],
        trusted_jwks=(
            {
                "kty": "RSA",
                "use": "sig",
                "alg": admission.STATEMENT_ALGORITHM,
                "kid": "synthetic-association-verifier",
                "n": encoded_integer(numbers.n),
                "e": encoded_integer(numbers.e),
            },
        ),
    )
    header = admission.canonical_verification_statement_protected_header_v1_bytes(
        kid="synthetic-association-verifier"
    ).decode("ascii")
    payload = admission.canonical_verification_statement_payload_v1_bytes(
        issuer=config.issuer,
        audience=config.audience,
        client_id=config.client_id,
        service_principal=config.service_principal,
        result=admission.ENROLLMENT_V2_RESULT,
        challenge_kind="enrollment-v2",
        challenge_id=value.context.challenge_id,
        attempt_id=value.context.attempt_id,
        context_digest=admission.verification_context_digest_v1(value.context.wire),
        input_digest=admission.verification_input_digest_v1(input_wire),
        issued_at=now,
        expires_at=now + 9000,
        token_id="aa" * 32,
    ).decode("ascii")
    signing_input = ".".join(
        base64.urlsafe_b64encode(part.encode("ascii")).decode("ascii").rstrip("=") for part in (header, payload)
    ).encode("ascii")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    signed = admission.compact_verification_statement_v1(
        protected_header_wire=header, payload_wire=payload, signature=signature
    )
    authenticated = verify_social_device_verification_statement_v1(
        signed,
        config=config,
        expected_context_wire=value.context.wire,
        expected_input_wire=input_wire,
        now=now,
        challenge_expires_at=now + 59000,
        session_expires_at=now + 59000,
        approver_session_expires_at=now + 59000,
    )
    state = lifecycle.initial_association_v1(lifecycle.AssociationLifecycleV1(), value.challenge_wire)
    assert (
        storage.SqlAlchemyEd25519AssociationStore._authenticated_enrollment(
            input_wire, authenticated, now, lifecycle.association_snapshot_v1(state)
        )
        == value.challenge_wire
    )


def test_migration_is_additive_and_has_immutable_guards():
    sql = MIGRATION.read_text(encoding="ascii")
    assert "CREATE TABLE social_device_ed25519_association_chains" in sql
    assert "CREATE TABLE social_device_ed25519_association_events" in sql
    assert "CREATE TRIGGER trg_social_ed25519_event_guard" in sql
    assert "CREATE TRIGGER trg_social_ed25519_chain_guard" in sql
    assert "DELETE FROM " not in sql and "UPDATE users" not in sql

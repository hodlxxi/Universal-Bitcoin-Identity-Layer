"""Pure, genuinely RSA-authenticated native V1 fixture regressions; no SQL."""

import base64
import hashlib
import json
from pathlib import Path

import pytest

from app.services import social_device_verification_statement as verifier
from app.services import social_enrollment_transition_authority as transition
from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_device_ed25519_association_lifecycle as lifecycle
from tests.integration.test_social_enrollment_v2_finalization_postgresql import verified_legacy_initial_native_fixture

FIXTURE = Path(__file__).parents[1] / "fixtures/social_device_admission_v1.json"
FIXED_SHA256 = "09722ca9ab230a7bbc73b2228dfed5e80cdd2c2bb44a32e8571bdcf246ca4324"


def authorize(value, authenticated, now, deadline):
    return transition.authorize_enrollment_transition_v1(
        value,
        authenticated,
        lifecycle.AssociationLifecycleV1(),
        observed_at=now,
        locked_deadline_ms=deadline,
        full_proof_id=value.context.full_proof_id,
        approver_full_proof_id=value.context.approver_full_proof_id,
    )


def test_legacy_native_fixture_real_verifier_matches_initial_lifecycle():
    value, authenticated, now, deadline = verified_legacy_initial_native_fixture()
    assert type(authenticated) is verifier.AuthenticatedSocialDeviceVerificationStatementV1
    assert authenticated.context_digest == admission.verification_context_digest_v1(value.context.wire)
    assert authenticated.input_digest == admission.verification_input_digest_v1(value.wire)
    authority = authorize(value, authenticated, now, deadline)
    assert authority.transition_kind == "initial"
    assert authority.pre_effect_association_state == "absent"
    assert authority.pre_effect_authority_epoch == 0
    assert authority.proposed_association_version == authority.proposed_authority_epoch == 1
    assert authority.proposed_association_id == lifecycle.association_id_v1(value.challenge_wire, 1, None)


def test_legacy_native_fixture_preserves_frozen_proof_bytes_and_old_deadlines():
    raw = FIXTURE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIXED_SHA256
    fixed = json.loads(raw)["vectors"]["enrollmentV2"]
    value, authenticated, now, deadline = verified_legacy_initial_native_fixture()
    before, after = json.loads(fixed["inputWire"]), json.loads(value.wire)
    for field in before:
        if field != "context":
            assert before[field] == after[field]
    before_context, after_context = json.loads(before["context"]), json.loads(after["context"])
    assert set(before_context) == set(after_context)
    assert {k for k in before_context if before_context[k] != after_context[k]} <= {
        "associationId",
        "associationVersion",
        "authorityEpoch",
        "predecessorAssociationId",
    }
    encoded = fixed["compactJws"].split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert authenticated.issued_at == claims["issuedAt"]
    assert authenticated.expires_at == claims["expiresAt"]
    assert 0 < authenticated.expires_at - authenticated.issued_at <= 10000
    assert authenticated.issued_at <= now < authenticated.expires_at <= deadline
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == FIXED_SHA256


def test_original_signed_shape_fixture_does_not_authorize_an_absent_lifecycle():
    raw = FIXTURE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIXED_SHA256
    fixed = json.loads(raw)
    v = fixed["vectors"]["enrollmentV2"]
    value = admission.parse_verification_input_v1(v["inputWire"])
    config = fixed["configuration"]
    deadline = min(v["sessionExpiresAt"], v["approverSessionExpiresAt"], json.loads(value.challenge_wire)["expiresAt"])
    authenticated = verifier.verify_social_device_verification_statement_v1(
        v["compactJws"],
        config=verifier.SocialDeviceVerificationStatementConfig(
            enabled=True,
            issuer=config["issuer"],
            audience=config["audience"],
            client_id=config["clientId"],
            service_principal=config["servicePrincipal"],
            trusted_jwks=(fixed["publicVerificationMaterial"]["jwk"],),
        ),
        expected_context_wire=value.context.wire,
        expected_input_wire=value.wire,
        now=v["now"],
        challenge_expires_at=json.loads(value.challenge_wire)["expiresAt"],
        session_expires_at=v["sessionExpiresAt"],
        approver_session_expires_at=v["approverSessionExpiresAt"],
    )
    with pytest.raises(transition.SocialEnrollmentTransitionAuthorityUnavailable):
        authorize(value, authenticated, v["now"], deadline)

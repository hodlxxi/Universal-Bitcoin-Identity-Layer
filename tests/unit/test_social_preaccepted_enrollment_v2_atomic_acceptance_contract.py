from __future__ import annotations

import ast
import base64
import hashlib
import json
from pathlib import Path

import pytest

from app.services import social_messaging_device_verification_deadline_evidence_v1 as deadline
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_contract as contract
from app.services import social_preaccepted_enrollment_verification_statement_v2 as statement

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "tests/fixtures/social_preaccepted_enrollment_v2_atomic_acceptance_v1.json"
EVIDENCE_PATH = ROOT / "tests/fixtures/social_messaging_device_verification_deadline_evidence_v1.json"
STATEMENT_PATH = ROOT / "tests/fixtures/social_preaccepted_enrollment_verification_statement_v2.json"
SOURCE_PATH = ROOT / "tests/fixtures/social_preacceptance_ed25519_handoff_v2.json"
FIXTURE = json.loads(FIXTURE_PATH.read_bytes())
EVIDENCE = json.loads(EVIDENCE_PATH.read_bytes())
STATEMENT = json.loads(STATEMENT_PATH.read_bytes())
SOURCE = json.loads(SOURCE_PATH.read_bytes())
VECTOR = FIXTURE["vector"]
INPUT_WIRE = SOURCE["vector"]["preacceptedEnrollmentVerificationInputWire"]
CONTEXT_WIRE = SOURCE["vector"]["verificationContextWire"]
DENIED = contract.SocialPreacceptedEnrollmentV2AtomicAcceptanceDenied
ERROR = "^social preaccepted enrollment v2 atomic acceptance denied$"


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def evidence_compact() -> str:
    vector = EVIDENCE["vector"]
    return deadline.compact_messaging_device_verification_deadline_evidence_v1(
        protected_header_wire=vector["protectedHeaderWire"],
        payload_wire=vector["payloadWire"],
        signature=bytes.fromhex(vector["signature"]),
    )


def evidence_config() -> deadline.MessagingDeviceVerificationDeadlineEvidenceV1Config:
    trust = EVIDENCE["trustRecord"]
    config = EVIDENCE["configuration"]
    record = deadline.DeadlineEvidenceTrustRecordV1(
        public_jwk=dict(trust["jwk"]),
        trust_revision=trust["trustRevision"],
        not_before=trust["notBefore"],
        not_after=trust["notAfter"],
        revoked_at=trust["revokedAt"],
    )
    return deadline.MessagingDeviceVerificationDeadlineEvidenceV1Config(
        enabled=True,
        issuer=config["issuer"],
        audience=config["audience"],
        client_id=config["clientId"],
        service_principal=config["servicePrincipal"],
        trust_records=(record,),
    )


def authenticated_evidence():
    return deadline.verify_messaging_device_verification_deadline_evidence_v1(
        evidence_compact(),
        config=evidence_config(),
        expected_input_wire=INPUT_WIRE,
        now=EVIDENCE["deadlines"]["observedAt"],
    )


def statement_config() -> statement.SocialPreacceptedEnrollmentVerificationStatementV2Config:
    config = STATEMENT["configuration"]
    return statement.SocialPreacceptedEnrollmentVerificationStatementV2Config(
        enabled=True,
        issuer=config["issuer"],
        audience=config["audience"],
        client_id=config["clientId"],
        service_principal=config["servicePrincipal"],
        trusted_jwks=(dict(STATEMENT["publicVerificationMaterial"]["jwk"]),),
    )


def authenticated_statement():
    claims = json.loads(EVIDENCE["vector"]["payloadWire"])
    return statement.verify_social_preaccepted_enrollment_verification_statement_v2(
        STATEMENT["vector"]["compactJws"],
        config=statement_config(),
        expected_context_wire=CONTEXT_WIRE,
        expected_input_wire=INPUT_WIRE,
        now=STATEMENT["deadlines"]["now"],
        phone_session_expires_at_ms=claims["phoneSessionExpiresAt"],
        approver_session_expires_at_ms=claims["approverSessionExpiresAt"],
        full_expires_at_ms=claims["fullExpiresAt"],
        x25519_binding_expires_at_ms=claims["x25519BindingExpiresAt"],
    )


def model(**changes: object) -> contract.ProvisionalAtomicAcceptanceV1:
    values = {
        "reservation_wire": VECTOR["pendingReservationWire"],
        "finalization_observation_wire": VECTOR["finalizationObservationWire"],
        "expected_input_wire": INPUT_WIRE,
        "expected_context_wire": CONTEXT_WIRE,
        "evidence_compact_jws": evidence_compact(),
        "evidence_config": evidence_config(),
        "statement_compact_jws": STATEMENT["vector"]["compactJws"],
        "statement_config": statement_config(),
        "decided_at": VECTOR["decidedAt"],
    }
    values.update(changes)
    return contract.model_atomic_acceptance_and_cas_v1(**values)


def denied(callable_value) -> None:
    with pytest.raises(DENIED, match=ERROR) as failure:
        callable_value()
    assert failure.value.args == (contract.DENIED_MESSAGE,)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


def changed_wire(source: str, **changes: object) -> str:
    return canonical({**json.loads(source), **changes})


def changed_observation_authority(**changes: object) -> str:
    observation = json.loads(VECTOR["finalizationObservationWire"])
    authority = {**json.loads(observation["authoritySnapshot"]), **changes}
    authority_wire = canonical(authority)
    observation["authoritySnapshot"] = authority_wire
    observation["authoritySnapshotDigest"] = contract.current_authority_snapshot_digest_v1(authority_wire)
    if "observedAt" in changes:
        observation["observedAt"] = changes["observedAt"]
    return canonical(observation)


def test_golden_fixture_sources_and_deterministic_effect_receipt_bytes_are_exact():
    fixture_bytes = FIXTURE_PATH.read_bytes()
    assert len(fixture_bytes) == 9_638
    assert hashlib.sha256(fixture_bytes).hexdigest() == (
        "6bbbf4c94f3120dbad57def6bceed7d5a9b563723402afb7cf1ca1e3121db7e8"
    )
    for name, path in (("deadlineEvidenceFixture", EVIDENCE_PATH), ("verificationStatementFixture", STATEMENT_PATH)):
        expected = FIXTURE["sources"][name]
        assert len(path.read_bytes()) == expected["bytes"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected["sha256"]
    reservation = contract.canonical_pending_atomic_acceptance_reservation_v1_bytes(
        evidence_compact_jws=evidence_compact(),
        evidence_config=evidence_config(),
        expected_input_wire=INPUT_WIRE,
        observed_at=EVIDENCE["deadlines"]["observedAt"],
        challenge_revision=1,
    ).decode("ascii")
    assert reservation == VECTOR["pendingReservationWire"]
    result = model(reservation_wire=reservation)
    assert result.effect_wire == VECTOR["effectWire"]
    assert result.effect_id == VECTOR["effectId"]
    assert result.effect_digest == VECTOR["effectDigest"]
    assert result.finalization_request_digest == VECTOR["finalizationRequestDigest"]
    assert result.receipt.wire == VECTOR["receiptWire"]
    assert result.receipt.receipt_id == VECTOR["receiptId"]
    accepted = contract.parse_atomic_acceptance_reservation_v1(result.reservation_after_wire)
    assert accepted.state == "accepted"
    assert accepted.receipt_id == result.receipt.receipt_id
    assert accepted.effect_id == result.effect_id
    assert result.publication_status == "provisional_until_caller_commit"
    assert result.locks_proven is False
    assert result.persistence_proven is False
    assert result.commit_proven is False
    assert result.final_admission == "denied"
    assert result.runtime_enabled is False


@pytest.mark.parametrize("offset", (-1, 1))
def test_pending_reservation_observation_must_equal_signed_observation_exactly(offset: int):
    denied(
        lambda: contract.canonical_pending_atomic_acceptance_reservation_v1_bytes(
            evidence_compact_jws=evidence_compact(),
            evidence_config=evidence_config(),
            expected_input_wire=INPUT_WIRE,
            observed_at=EVIDENCE["deadlines"]["observedAt"] + offset,
            challenge_revision=1,
        )
    )


def test_cross_contract_bindings_use_v2_identities_without_reinterpreting_v1_authority():
    result = model()
    evidence_claims = authenticated_evidence().claims
    statement_projection = dict(
        statement.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(
            authenticated_statement()
        )
    )
    reservation = result.reservation_before
    assert reservation.acceptance_id == evidence_claims.acceptance_id == statement_projection["acceptanceId"]
    assert reservation.association_id == evidence_claims.association_id == statement_projection["associationId"]
    assert (
        reservation.challenge_id
        == evidence_claims.enrollment_challenge_id
        == statement_projection["enrollmentChallengeId"]
    )
    assert reservation.input_digest == evidence_claims.input_digest == statement_projection["inputDigest"]
    assert reservation.request_id == evidence_claims.request_id
    assert reservation.operation_id == evidence_claims.operation_id
    assert result.receipt.reservation_id == evidence_claims.reservation_id
    assert contract.RUNTIME_ENABLED is False


@pytest.mark.parametrize(
    "field",
    (
        "socialSessionIssuanceId",
        "socialSessionIssuanceRevision",
        "socialSessionTokenId",
        "parentOAuthTokenId",
        "parentOAuthSessionId",
        "parentOAuthBrowserGenerationId",
        "approverOAuthTokenId",
        "approverOAuthSessionId",
        "approverOAuthBrowserGenerationId",
        "fullEvidenceId",
        "fullEvidenceVersion",
        "fullSourceEvidenceSha256",
        "fullProofId",
        "x25519BindingId",
        "x25519BindingVersion",
        "x25519PublicKeyCommitment",
        "phoneSessionExpiresAt",
        "approverSessionExpiresAt",
        "fullExpiresAt",
        "x25519BindingExpiresAt",
    ),
)
def test_replacement_rotation_revocation_or_concurrent_authority_change_denies(field: str):
    authority = json.loads(json.loads(VECTOR["finalizationObservationWire"])["authoritySnapshot"])
    current = authority[field]
    if type(current) is int:
        replacement = current + 1
    elif field == "fullEvidenceId":
        replacement = "123e4567-e89b-42d3-a456-426614174001"
    elif type(current) is str and len(current) == 32:
        replacement = "ff" * 16
    elif type(current) is str and len(current) == 64:
        replacement = "ff" * 32
    elif field == "fullProofId":
        replacement = "hodlxxi-full-entitlement-v1-sha256:" + "ff" * 32
    elif field == "x25519PublicKeyCommitment":
        replacement = "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "ff" * 32
    else:
        replacement = "replacement-current-full-v2"
    denied(lambda: model(finalization_observation_wire=changed_observation_authority(**{field: replacement})))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("challengeRevision", 2),
        ("challengeState", "consumed"),
        ("associationState", "active"),
        ("associationCurrentId", "ff" * 32),
        ("associationVersion", 1),
        ("associationAuthorityEpoch", 1),
    ),
)
def test_exact_challenge_and_association_cas_mismatch_denies(field: str, value: object):
    denied(
        lambda: model(
            finalization_observation_wire=changed_wire(VECTOR["finalizationObservationWire"], **{field: value})
        )
    )


def test_observation_expiry_statement_expiry_and_decision_time_are_exclusive():
    denied(lambda: model(decided_at=EVIDENCE["deadlines"]["evidenceExpiresAt"]))
    denied(
        lambda: model(
            finalization_observation_wire=changed_observation_authority(
                observedAt=EVIDENCE["deadlines"]["evidenceExpiresAt"]
            ),
            decided_at=EVIDENCE["deadlines"]["evidenceExpiresAt"],
        )
    )
    denied(lambda: model(decided_at=True))
    denied(lambda: model(decided_at=float(VECTOR["decidedAt"])))


def test_pending_lost_response_and_accepted_lost_response_are_exactly_idempotent():
    pending = contract.reservation_retry_disposition_v1(
        VECTOR["pendingReservationWire"],
        expected_input_wire=INPUT_WIRE,
        evidence_compact_jws=evidence_compact(),
        now=EVIDENCE["deadlines"]["observedAt"],
    )
    assert pending.outcome == "return_existing_pending_evidence_without_resigning"
    assert pending.device_id_reuse == "reserved_by_exact_pending_request"
    assert pending.effect_execution == "none"
    assert pending.automatic_resigning == "forbidden"
    accepted_wire = model().reservation_after_wire
    accepted = contract.reservation_retry_disposition_v1(
        accepted_wire,
        expected_input_wire=INPUT_WIRE,
        evidence_compact_jws=evidence_compact(),
        statement_compact_jws=STATEMENT["vector"]["compactJws"],
        receipt_wire=VECTOR["receiptWire"],
        now=VECTOR["decidedAt"] + 1,
    )
    assert accepted.outcome == "return_immutable_receipt_without_effect"
    assert accepted.device_id_reuse == "denied_association_committed"
    assert accepted.effect_execution == "none"


def test_accepted_history_reconciliation_is_strict_but_not_current_key_verification():
    result = model()
    accepted = contract.reservation_retry_disposition_v1(
        result.reservation_after_wire,
        expected_input_wire=INPUT_WIRE,
        evidence_compact_jws=evidence_compact(),
        statement_compact_jws=STATEMENT["vector"]["compactJws"],
        receipt_wire=result.receipt.wire,
        now=EVIDENCE["deadlines"]["evidenceExpiresAt"] + 1,
    )
    assert accepted.outcome == "return_immutable_receipt_without_effect"


def test_changed_request_identity_is_denied_for_accepted_history_too():
    result = model()
    changed = changed_wire(result.reservation_after_wire, requestId="ff" * 32)
    denied(
        lambda: contract.reservation_retry_disposition_v1(
            changed,
            expected_input_wire=INPUT_WIRE,
            evidence_compact_jws=evidence_compact(),
            statement_compact_jws=STATEMENT["vector"]["compactJws"],
            receipt_wire=result.receipt.wire,
            now=VECTOR["decidedAt"] + 1,
        )
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("reservationId", "ff" * 32),
        ("subject", "ff" * 32),
        ("deviceId", "ff" * 32),
        ("operationId", "ff" * 32),
        ("acceptanceId", "ff" * 32),
        ("challengeId", "ff" * 32),
        ("associationId", "ff" * 32),
        ("evidenceTokenId", "ff" * 32),
        ("createdAt", EVIDENCE["deadlines"]["observedAt"] + 1),
        ("expiresAt", EVIDENCE["deadlines"]["evidenceExpiresAt"] - 1),
    ),
)
def test_every_retry_row_identity_frozen_by_evidence_is_compared(field: str, value: object):
    denied(
        lambda: contract.reservation_retry_disposition_v1(
            changed_wire(VECTOR["pendingReservationWire"], **{field: value}),
            expected_input_wire=INPUT_WIRE,
            evidence_compact_jws=evidence_compact(),
            now=EVIDENCE["deadlines"]["observedAt"] + 1,
        )
    )


def test_same_receipt_id_with_changed_decision_time_is_not_immutable_history():
    result = model()
    mutated_receipt = changed_wire(result.receipt.wire, decidedAt=result.receipt.decided_at + 1)
    assert json.loads(mutated_receipt)["receiptId"] == result.receipt.receipt_id
    denied(
        lambda: contract.reservation_retry_disposition_v1(
            result.reservation_after_wire,
            expected_input_wire=INPUT_WIRE,
            evidence_compact_jws=evidence_compact(),
            statement_compact_jws=STATEMENT["vector"]["compactJws"],
            receipt_wire=mutated_receipt,
            now=VECTOR["decidedAt"] + 1,
        )
    )


def test_changed_byte_digest_identity_or_expired_pending_retry_denies_without_resigning():
    changed_evidence = evidence_compact()[:-1] + ("A" if evidence_compact()[-1] != "A" else "B")
    denied(
        lambda: contract.reservation_retry_disposition_v1(
            VECTOR["pendingReservationWire"],
            expected_input_wire=INPUT_WIRE,
            evidence_compact_jws=changed_evidence,
            now=EVIDENCE["deadlines"]["observedAt"],
        )
    )
    denied(
        lambda: contract.reservation_retry_disposition_v1(
            VECTOR["pendingReservationWire"],
            expected_input_wire=INPUT_WIRE,
            evidence_compact_jws=evidence_compact(),
            now=EVIDENCE["deadlines"]["evidenceExpiresAt"],
        )
    )
    reservation = json.loads(VECTOR["pendingReservationWire"])
    reservation["requestId"] = "ff" * 32
    denied(
        lambda: contract.reservation_retry_disposition_v1(
            canonical(reservation),
            expected_input_wire=INPUT_WIRE,
            evidence_compact_jws=evidence_compact(),
            now=EVIDENCE["deadlines"]["observedAt"],
        )
    )


@pytest.mark.parametrize(
    ("state", "decided_at"),
    (
        ("rejected", 1788906601000),
        ("cancelled", 1788906601000),
        ("expired", 1788906610000),
    ),
)
def test_terminal_states_are_fail_closed_and_device_reuse_requires_a_new_locked_reservation(
    state: str, decided_at: int
):
    wire = contract.transition_pending_reservation_terminal_v1_bytes(
        VECTOR["pendingReservationWire"], state=state, decided_at=decided_at
    ).decode("ascii")
    parsed = contract.parse_atomic_acceptance_reservation_v1(wire)
    assert parsed.state == state
    assert contract.terminal_device_id_reuse_semantics_v1(wire) == (
        "new_reservation_only_after_locked_no_effect_no_receipt_no_association_proof;"
        "new_request_challenge_input_and_reservation_required"
    )
    denied(
        lambda: contract.reservation_retry_disposition_v1(
            wire,
            expected_input_wire=INPUT_WIRE,
            evidence_compact_jws=evidence_compact(),
            now=decided_at,
        )
    )
    denied(lambda: contract.transition_pending_reservation_terminal_v1_bytes(wire, state=state, decided_at=decided_at))


def test_noncanonical_duplicate_unknown_bool_float_and_oversize_inputs_deny():
    reservation = VECTOR["pendingReservationWire"]
    duplicate = reservation.replace("{", '{"state":"pending",', 1)
    denied(lambda: contract.parse_atomic_acceptance_reservation_v1(duplicate))
    denied(lambda: contract.parse_atomic_acceptance_reservation_v1(changed_wire(reservation, unknown=True)))
    denied(lambda: contract.parse_atomic_acceptance_reservation_v1(changed_wire(reservation, challengeRevision=True)))
    denied(lambda: contract.parse_atomic_acceptance_reservation_v1(changed_wire(reservation, createdAt=1.0)))
    denied(lambda: contract.parse_atomic_acceptance_reservation_v1("{" + "a" * contract.MAX_RESERVATION_BYTES + "}"))
    denied(lambda: contract.parse_atomic_acceptance_receipt_v1(changed_wire(VECTOR["receiptWire"], decidedAt=True)))


def test_forged_or_parsed_values_do_not_prove_authentication_locks_persistence_or_commit():
    parsed_claims = deadline.parse_messaging_device_verification_deadline_evidence_payload_v1(
        EVIDENCE["vector"]["payloadWire"], expected_input_wire=INPUT_WIRE
    )
    denied(
        lambda: contract.canonical_pending_atomic_acceptance_reservation_v1_bytes(
            evidence_compact_jws=EVIDENCE["vector"]["payloadWire"],
            evidence_config=evidence_config(),
            expected_input_wire=INPUT_WIRE,
            observed_at=EVIDENCE["deadlines"]["observedAt"],
            challenge_revision=1,
        )
    )
    denied(lambda: model(evidence_config=parsed_claims))
    denied(lambda: model(statement_config=object()))
    reservation = contract.parse_atomic_acceptance_reservation_v1(VECTOR["pendingReservationWire"])
    observation = contract.parse_finalization_observation_v1(VECTOR["finalizationObservationWire"])
    assert not hasattr(reservation, "locks_proven")
    assert not hasattr(observation, "persistence_proven")


def test_contract_has_no_database_network_runtime_or_private_signing_surface():
    source = (ROOT / "app/services/social_preaccepted_enrollment_v2_atomic_acceptance_contract.py").read_text("utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names
    }
    assert not imports & {"sqlalchemy", "socket", "requests", "redis", "subprocess", "app.models"}
    for forbidden in ("private_key", "signExact", "create_app", "Session(", "commit(", "rollback("):
        assert forbidden not in source
    assert contract.LOCKING == "not_performed_by_pure_contract"
    assert contract.PERSISTENCE == "not_performed_by_pure_contract"
    assert contract.COMMIT == "not_performed_by_pure_contract"
    assert contract.FINAL_ADMISSION == "denied"


def test_public_failures_drop_secret_bearing_nonserializable_and_circular_context():
    secret = '{"bearer":"do-not-leak-atomic-secret"}'
    circular: dict[str, object] = {}
    circular["self"] = circular
    for malformed in (secret, object(), circular):
        denied(lambda malformed=malformed: contract.parse_atomic_acceptance_reservation_v1(malformed))

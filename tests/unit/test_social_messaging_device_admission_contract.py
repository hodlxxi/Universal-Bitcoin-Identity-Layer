from __future__ import annotations

import ast
import base64
import hashlib
import inspect
import json
from dataclasses import fields, replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from app.services import social_messaging_device_admission_contract as contract

ROOT = Path(__file__).parents[2]
FIXTURE_PATH = ROOT / "tests/fixtures/social_device_admission_v1.json"
FIXTURE_BYTES = FIXTURE_PATH.read_bytes()
VECTORS = json.loads(FIXTURE_BYTES)
CONFIG = VECTORS["configuration"]
ERROR = "^social messaging device admission unavailable$"

CONTEXT_FIELDS = {
    "approverFullProofId",
    "approverSessionBinding",
    "associationId",
    "associationVersion",
    "attemptId",
    "audience",
    "authorityEpoch",
    "bindingId",
    "bindingVersion",
    "challengeId",
    "challengeKind",
    "deviceId",
    "ed25519PublicKey",
    "fullProofId",
    "predecessorAssociationId",
    "profile",
    "schema",
    "sessionBinding",
    "subject",
    "version",
    "x25519PublicKeyCommitment",
}
INPUT_FIELDS = {
    "actualRequest",
    "approvalEvent",
    "challenge",
    "context",
    "proof",
    "routingRequest",
    "schema",
    "version",
}
STATEMENT_FIELDS = {
    "aud",
    "attemptId",
    "challengeId",
    "challengeKind",
    "clientId",
    "contextDigest",
    "expiresAt",
    "inputDigest",
    "iss",
    "issuedAt",
    "jti",
    "purpose",
    "result",
    "schema",
    "servicePrincipal",
    "version",
}


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def b64url(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def vector(name):
    return VECTORS["vectors"][name]


def inspect_vector(name, **changes):
    value = vector(name)
    statement = changes.pop("statement", value["compactJws"])
    arguments = {
        "expected_kid": CONFIG["kid"],
        "expected_issuer": CONFIG["issuer"],
        "expected_audience": CONFIG["audience"],
        "expected_client_id": CONFIG["clientId"],
        "expected_service_principal": CONFIG["servicePrincipal"],
        "expected_context_wire": value["contextWire"],
        "expected_input_wire": value["inputWire"],
        "now": value["now"],
        "challenge_expires_at": value["challengeExpiresAt"],
        "session_expires_at": value["sessionExpiresAt"],
        "approver_session_expires_at": value["approverSessionExpiresAt"],
    }
    arguments.update(changes)
    return contract.inspect_verification_statement_shape_v1(statement, **arguments)


def statement_with(name, *, header=None, payload=None, signature=None):
    value = vector(name)
    header_wire = value["protectedHeaderWire"] if header is None else canonical(header)
    payload_wire = value["payloadWire"] if payload is None else canonical(payload)
    if signature is None:
        signature = base64.urlsafe_b64decode(value["compactJws"].split(".")[2] + "==")
    return ".".join((b64url(header_wire.encode("ascii")), b64url(payload_wire.encode("ascii")), b64url(signature)))


def mutated_input(name, **changes):
    value = {**json.loads(vector(name)["inputWire"]), **changes}
    return canonical(value)


def mutated_context(name, **changes):
    value = {**json.loads(vector(name)["contextWire"]), **changes}
    return canonical(value)


def enrollment_state_response(
    state,
    *,
    challenge_present,
    context_present,
    phone_proof_present,
    approval_event_present,
    receipt_present,
):
    value = json.loads(VECTORS["responseWires"]["/enrollment-read"])
    value["state"] = state
    if not challenge_present:
        value["challengeWire"] = None
    if not context_present:
        value["contextWire"] = None
    if not phone_proof_present:
        value["phoneProofWire"] = None
    if not approval_event_present:
        value["approvalEventWire"] = None
    if not receipt_present:
        value["receipt"] = None
    return value


def nostr_event_id(value):
    preimage = json.dumps(
        [0, value["pubkey"], value["created_at"], value["kind"], value["tags"], value["content"]],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(preimage.encode("ascii")).hexdigest()


@pytest.mark.parametrize("name", ("enrollmentV2", "ciphertextSubmit", "recipientSelfRead"))
def test_independent_fixed_context_input_statement_and_digest_vectors(name):
    value = vector(name)
    context = contract.parse_verification_context_v1(value["contextWire"])
    parsed_input = contract.parse_verification_input_v1(value["inputWire"])
    assert context.wire == value["contextWire"]
    assert parsed_input.context == context
    assert parsed_input.challenge_wire == value["challengeWire"]
    assert parsed_input.proof_wire == value["proofWire"]
    assert parsed_input.approval_event_wire == value["approvalEventWire"]
    assert parsed_input.actual_request_wire == value["actualRequestWire"]
    assert parsed_input.routing_request_wire == value["routingRequestWire"]
    independent_context_digest = (
        "hodlxxi-social-device-verification-context-v1-sha256:"
        + hashlib.sha256(
            b"HODLXXI_SOCIAL_DEVICE_VERIFICATION_CONTEXT_V1\0" + value["contextWire"].encode("ascii")
        ).hexdigest()
    )
    independent_input_digest = (
        "hodlxxi-social-device-verification-input-v1-sha256:"
        + hashlib.sha256(
            b"HODLXXI_SOCIAL_DEVICE_VERIFICATION_INPUT_V1\0" + value["inputWire"].encode("ascii")
        ).hexdigest()
    )
    assert canonical(json.loads(value["contextWire"])) == value["contextWire"]
    assert canonical(json.loads(value["inputWire"])) == value["inputWire"]
    assert value["contextDigest"] == independent_context_digest
    assert value["inputDigest"] == independent_input_digest
    assert contract.verification_context_digest_v1(value["contextWire"]) == independent_context_digest
    assert contract.verification_input_digest_v1(value["inputWire"]) == independent_input_digest
    result = inspect_vector(name)
    assert result.protected_header_wire == value["protectedHeaderWire"]
    assert result.payload_wire == value["payloadWire"]
    assert result.signing_input.decode("ascii") == value["protectedHeaderSegment"] + "." + value["payloadSegment"]


def test_fixture_is_frozen_public_only_and_rsa_signatures_are_independently_valid():
    assert hashlib.sha256(FIXTURE_BYTES).hexdigest() == (
        "09722ca9ab230a7bbc73b2228dfed5e80cdd2c2bb44a32e8571bdcf246ca4324"
    )
    text = FIXTURE_BYTES.decode("ascii")
    assert "BEGIN PRIVATE KEY" not in text
    assert "BEGIN RSA PRIVATE KEY" not in text
    assert not {"d", "p", "q", "dp", "dq", "qi", "oth"} & set(VECTORS["publicVerificationMaterial"]["jwk"])
    public = serialization.load_pem_public_key(VECTORS["publicVerificationMaterial"]["spkiPem"].encode("ascii"))
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert "sha256:" + hashlib.sha256(der).hexdigest() == VECTORS["publicVerificationMaterial"]["spkiSha256"]
    for value in VECTORS["vectors"].values():
        signature = base64.urlsafe_b64decode(value["compactJws"].split(".")[2] + "==")
        public.verify(
            signature,
            (value["protectedHeaderSegment"] + "." + value["payloadSegment"]).encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )


@pytest.mark.parametrize("name", ("enrollmentV2", "ciphertextSubmit", "recipientSelfRead"))
def test_constructor_round_trips_are_exact_fixture_bytes(name):
    value = vector(name)
    context = json.loads(value["contextWire"])
    context_arguments = {
        "challenge_kind": context["challengeKind"],
        "challenge_id": context["challengeId"],
        "attempt_id": context["attemptId"],
        "audience": context["audience"],
        "subject": context["subject"],
        "device_id": context["deviceId"],
        "binding_id": context["bindingId"],
        "binding_version": context["bindingVersion"],
        "x25519_public_key_commitment": context["x25519PublicKeyCommitment"],
        "profile": context["profile"],
        "ed25519_public_key": context["ed25519PublicKey"],
        "association_id": context["associationId"],
        "association_version": context["associationVersion"],
        "predecessor_association_id": context["predecessorAssociationId"],
        "authority_epoch": context["authorityEpoch"],
        "session_binding": context["sessionBinding"],
        "approver_session_binding": context["approverSessionBinding"],
        "full_proof_id": context["fullProofId"],
        "approver_full_proof_id": context["approverFullProofId"],
    }
    assert contract.canonical_verification_context_v1_bytes(**context_arguments).decode("ascii") == value["contextWire"]
    assert (
        contract.canonical_verification_input_v1_bytes(
            context=value["contextWire"],
            challenge=value["challengeWire"],
            proof=value["proofWire"],
            approval_event=value["approvalEventWire"],
            actual_request=value["actualRequestWire"],
            routing_request=value["routingRequestWire"],
        ).decode("ascii")
        == value["inputWire"]
    )
    claims = json.loads(value["payloadWire"])
    assert (
        contract.canonical_verification_statement_payload_v1_bytes(
            issuer=claims["iss"],
            audience=claims["aud"],
            client_id=claims["clientId"],
            service_principal=claims["servicePrincipal"],
            result=claims["result"],
            challenge_kind=claims["challengeKind"],
            challenge_id=claims["challengeId"],
            attempt_id=claims["attemptId"],
            context_digest=claims["contextDigest"],
            input_digest=claims["inputDigest"],
            issued_at=claims["issuedAt"],
            expires_at=claims["expiresAt"],
            token_id=claims["jti"],
        ).decode("ascii")
        == value["payloadWire"]
    )
    assert (
        contract.canonical_verification_statement_protected_header_v1_bytes(kid=CONFIG["kid"]).decode("ascii")
        == value["protectedHeaderWire"]
    )


@pytest.mark.parametrize("field", sorted(CONTEXT_FIELDS))
def test_context_rejects_every_missing_field(field):
    value = json.loads(vector("enrollmentV2")["contextWire"])
    del value[field]
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_verification_context_v1(canonical(value))


def test_context_rejects_unknown_duplicate_alternate_escape_and_non_ascii():
    base = json.loads(vector("enrollmentV2")["contextWire"])
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_verification_context_v1(canonical({**base, "unknown": None}))
    for source in VECTORS["negativeBoundaryCases"].values():
        if isinstance(source, str) and source.startswith("{"):
            with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
                contract.parse_verification_context_v1(source)


def test_context_branch_nullability_first_enrollment_epoch_and_successor_shape_are_exact():
    enrollment = json.loads(vector("enrollmentV2")["contextWire"])
    request = json.loads(vector("ciphertextSubmit")["contextWire"])
    invalid = (
        {**enrollment, "approverSessionBinding": None},
        {**enrollment, "approverFullProofId": None},
        {**enrollment, "associationVersion": 2},
        {**enrollment, "authorityEpoch": 2},
        {**request, "predecessorAssociationId": "61" * 32},
        {**request, "approverSessionBinding": "62" * 32},
        {**request, "approverFullProofId": "hodlxxi-full-entitlement-v1-sha256:" + "63" * 32},
    )
    for value in invalid:
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            contract.parse_verification_context_v1(canonical(value))
    successor = {
        **enrollment,
        "associationVersion": 2,
        "authorityEpoch": 4,
        "predecessorAssociationId": "64" * 32,
    }
    assert contract.parse_verification_context_v1(canonical(successor)).predecessor_association_id == "64" * 32


@pytest.mark.parametrize("field", sorted(INPUT_FIELDS))
def test_input_rejects_every_missing_field(field):
    value = json.loads(vector("enrollmentV2")["inputWire"])
    del value[field]
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_verification_input_v1(canonical(value))


def test_input_rejects_unknown_duplicate_alternate_escape_and_non_ascii():
    source = vector("enrollmentV2")["inputWire"]
    value = json.loads(source)
    candidates = (
        canonical({**value, "unknown": None}),
        source[:-1] + ',"version":1}',
        source.replace("https://social.example", "https:\\/\\/social.example"),
        source.replace(value["context"][:1], "é", 1),
    )
    for candidate in candidates:
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            contract.parse_verification_input_v1(candidate)


@pytest.mark.parametrize(
    "name,inner_field",
    (
        ("enrollmentV2", "challengeWire"),
        ("enrollmentV2", "proofWire"),
        ("enrollmentV2", "approvalEventWire"),
        ("ciphertextSubmit", "challengeWire"),
        ("ciphertextSubmit", "proofWire"),
        ("ciphertextSubmit", "actualRequestWire"),
        ("ciphertextSubmit", "routingRequestWire"),
        ("recipientSelfRead", "challengeWire"),
        ("recipientSelfRead", "proofWire"),
        ("recipientSelfRead", "actualRequestWire"),
    ),
)
def test_every_embedded_document_rejects_each_missing_and_unknown_member(name, inner_field):
    value = vector(name)
    wire = value[inner_field]
    decoded = json.loads(wire)
    input_field = {
        "challengeWire": "challenge",
        "proofWire": "proof",
        "approvalEventWire": "approvalEvent",
        "actualRequestWire": "actualRequest",
        "routingRequestWire": "routingRequest",
    }[inner_field]
    for field in tuple(decoded):
        changed = dict(decoded)
        del changed[field]
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            contract.parse_verification_input_v1(mutated_input(name, **{input_field: canonical(changed)}))
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_verification_input_v1(
            mutated_input(name, **{input_field: canonical({**decoded, "unknown": None})})
        )


@pytest.mark.parametrize(
    "name,changes",
    (
        ("enrollmentV2", {"actualRequest": vector("ciphertextSubmit")["actualRequestWire"]}),
        ("enrollmentV2", {"routingRequest": vector("ciphertextSubmit")["routingRequestWire"]}),
        ("enrollmentV2", {"approvalEvent": None}),
        ("ciphertextSubmit", {"approvalEvent": vector("enrollmentV2")["approvalEventWire"]}),
        ("ciphertextSubmit", {"routingRequest": None}),
        ("ciphertextSubmit", {"actualRequest": None}),
        ("recipientSelfRead", {"routingRequest": vector("ciphertextSubmit")["routingRequestWire"]}),
        ("recipientSelfRead", {"approvalEvent": vector("enrollmentV2")["approvalEventWire"]}),
    ),
)
def test_enrollment_submit_and_self_read_nullability_is_separate(name, changes):
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_verification_input_v1(mutated_input(name, **changes))


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("subject", "31" * 32),
        ("deviceId", "32" * 32),
        ("sessionBinding", "33" * 32),
        ("audience", "https://other.example"),
        ("profile", "other.profile"),
        ("bindingId", "34" * 32),
        ("bindingVersion", 2),
        ("associationId", "35" * 32),
        ("associationVersion", 2),
        ("authorityEpoch", 3),
        ("challengeId", "36" * 32),
        ("attemptId", "37" * 32),
        ("ed25519PublicKey", "38" * 32),
        ("fullProofId", "hodlxxi-full-entitlement-v1-sha256:" + "39" * 32),
    ),
)
def test_every_context_identity_substitution_breaks_input_or_statement_binding(field, replacement):
    name = "ciphertextSubmit"
    changed_context = mutated_context(name, **{field: replacement})
    source = mutated_input(name, context=changed_context)
    try:
        contract.parse_verification_input_v1(source)
    except contract.SocialMessagingDeviceAdmissionUnavailable:
        return
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        inspect_vector(name, expected_context_wire=changed_context, expected_input_wire=source)


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("approverSessionBinding", "51" * 32),
        ("approverFullProofId", "hodlxxi-full-entitlement-v1-sha256:" + "52" * 32),
        ("associationId", "53" * 32),
        ("attemptId", "54" * 32),
    ),
)
def test_enrollment_approver_association_and_attempt_substitutions_break_statement_binding(field, replacement):
    name = "enrollmentV2"
    changed_context = mutated_context(name, **{field: replacement})
    changed_input = mutated_input(name, context=changed_context)
    contract.parse_verification_input_v1(changed_input)
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        inspect_vector(name, expected_context_wire=changed_context, expected_input_wire=changed_input)


def test_statement_issuer_must_equal_the_fully_rebound_context_audience():
    name = "ciphertextSubmit"
    alternate_issuer = "https://alternate-social.example"
    value = vector(name)

    request = {**json.loads(value["actualRequestWire"]), "audience": alternate_issuer}
    request_wire = canonical(request)
    challenge = {**json.loads(value["challengeWire"]), "request": request_wire}
    challenge_wire = canonical(challenge)
    context_wire = mutated_context(name, audience=alternate_issuer)
    input_wire = mutated_input(
        name,
        actualRequest=request_wire,
        challenge=challenge_wire,
        context=context_wire,
    )
    parsed = contract.parse_verification_input_v1(input_wire)
    assert parsed.context.audience == alternate_issuer
    assert parsed.actual_request_wire == request_wire
    assert input_wire != value["inputWire"]

    payload = {
        **json.loads(value["payloadWire"]),
        "contextDigest": contract.verification_context_digest_v1(context_wire),
        "inputDigest": contract.verification_input_digest_v1(input_wire),
    }
    assert payload["iss"] == CONFIG["issuer"]
    assert payload["contextDigest"] != value["contextDigest"]
    assert payload["inputDigest"] != value["inputDigest"]
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        inspect_vector(
            name,
            statement=statement_with(name, payload=payload),
            expected_context_wire=context_wire,
            expected_input_wire=input_wire,
        )


@pytest.mark.parametrize("field", sorted(STATEMENT_FIELDS))
def test_statement_payload_rejects_every_missing_field(field):
    value = json.loads(vector("enrollmentV2")["payloadWire"])
    del value[field]
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.inspect_verification_statement_shape_v1(
            statement_with("enrollmentV2", payload=value),
            **{
                key: val
                for key, val in {
                    "expected_kid": CONFIG["kid"],
                    "expected_issuer": CONFIG["issuer"],
                    "expected_audience": CONFIG["audience"],
                    "expected_client_id": CONFIG["clientId"],
                    "expected_service_principal": CONFIG["servicePrincipal"],
                    "expected_context_wire": vector("enrollmentV2")["contextWire"],
                    "expected_input_wire": vector("enrollmentV2")["inputWire"],
                    "now": vector("enrollmentV2")["now"],
                    "challenge_expires_at": vector("enrollmentV2")["challengeExpiresAt"],
                    "session_expires_at": vector("enrollmentV2")["sessionExpiresAt"],
                    "approver_session_expires_at": vector("enrollmentV2")["approverSessionExpiresAt"],
                }.items()
            },
        )


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("iss", "https://other.example"),
        ("aud", "https://ubid.example/internal/v1/social/device-admission/recover"),
        ("clientId", "other-client"),
        ("servicePrincipal", "other-principal"),
        ("purpose", "service_access"),
        ("challengeKind", "enrollment-v2"),
        ("challengeId", "41" * 32),
        ("attemptId", "42" * 32),
        ("contextDigest", contract.CONTEXT_DIGEST_PREFIX + "43" * 32),
        ("inputDigest", contract.INPUT_DIGEST_PREFIX + "44" * 32),
        ("result", contract.ENROLLMENT_V2_RESULT),
    ),
)
def test_statement_rejects_every_identity_purpose_digest_and_result_substitution(field, replacement):
    name = "ciphertextSubmit"
    payload = {**json.loads(vector(name)["payloadWire"]), field: replacement}
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        inspect_vector(name, statement=statement_with(name, payload=payload))


def test_protected_header_is_closed_canonical_and_rejects_algorithm_type_key_metadata_and_kid_changes():
    name = "ciphertextSubmit"
    base = json.loads(vector(name)["protectedHeaderWire"])
    candidates = (
        {**base, "alg": "none"},
        {**base, "alg": "PS256"},
        {**base, "typ": "JWT"},
        {**base, "kid": "other-key"},
        {**base, "jwk": {}},
        {**base, "jku": "https://example.test/key"},
        {**base, "x5u": "https://example.test/cert"},
    )
    for header in candidates:
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            inspect_vector(name, statement=statement_with(name, header=header))
    for field in ("alg", "kid", "typ"):
        header = dict(base)
        del header[field]
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            inspect_vector(name, statement=statement_with(name, header=header))


def test_statement_payload_rejects_unknown_duplicate_and_noncanonical_json():
    name = "ciphertextSubmit"
    value = json.loads(vector(name)["payloadWire"])
    unknown = statement_with(name, payload={**value, "unknown": None})
    payload_segment = b64url((vector(name)["payloadWire"][:-1] + ',"version":1}').encode("ascii"))
    segments = vector(name)["compactJws"].split(".")
    duplicate = ".".join((segments[0], payload_segment, segments[2]))
    noncanonical_wire = json.dumps(
        dict(reversed(tuple(value.items()))), ensure_ascii=True, separators=(",", ":"), sort_keys=False
    )
    noncanonical = ".".join((segments[0], b64url(noncanonical_wire.encode("ascii")), segments[2]))
    for statement in (unknown, duplicate, noncanonical):
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            inspect_vector(name, statement=statement)


def test_compact_jws_rejects_noncanonical_base64url_segments_and_json():
    value = vector("ciphertextSubmit")
    segments = value["compactJws"].split(".")
    candidates = (
        VECTORS["negativeBoundaryCases"]["paddedProtectedSegment"],
        ".".join((segments[0] + "+", segments[1], segments[2])),
        ".".join((segments[0], segments[1] + "/", segments[2])),
        ".".join((segments[0], segments[1], "")),
        value["compactJws"] + ".extra",
        ".".join(
            (
                b64url(
                    b'{"kid":"social-device-verifier-rs256-v1","alg":"RS256",'
                    b'"typ":"hodlxxi-social-device-verification+jws"}'
                ),
                segments[1],
                segments[2],
            )
        ),
    )
    for candidate in candidates:
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            inspect_vector("ciphertextSubmit", statement=candidate)


def test_statement_expiry_is_exclusive_zero_skew_and_capped_by_all_deadlines():
    name = "enrollmentV2"
    payload = json.loads(vector(name)["payloadWire"])
    assert inspect_vector(name, now=payload["issuedAt"]).final_admission == "denied"
    assert inspect_vector(name, now=payload["expiresAt"] - 1).final_admission == "denied"
    for observed in (payload["issuedAt"] - 1, payload["expiresAt"]):
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            inspect_vector(name, now=observed)
    for changes in (
        {"expiresAt": payload["issuedAt"]},
        {"expiresAt": payload["issuedAt"] + 10_001},
        {"expiresAt": vector(name)["challengeExpiresAt"] + 1},
    ):
        changed = {**payload, **changes}
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            inspect_vector(name, statement=statement_with(name, payload=changed))
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        inspect_vector(name, session_expires_at=payload["expiresAt"] - 1)
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        inspect_vector(name, approver_session_expires_at=payload["expiresAt"] - 1)


def test_shape_inspection_never_claims_signature_crypto_authority_effect_or_admission():
    for name in ("enrollmentV2", "ciphertextSubmit", "recipientSelfRead"):
        result = inspect_vector(name)
        assert result.canonical_structure == "valid"
        assert result.rsa_signature_verification == "not_evaluated"
        assert result.cryptographic_verification == "not_evaluated"
        assert result.current_authority == "not_evaluated"
        assert result.challenge_consumption == "not_implemented"
        assert result.operation_effect == "not_implemented"
        assert result.final_admission == "denied"
        assert result.runtime_enabled is False
        assert result.atomic_owner == "ubid_selected_not_implemented"
        mutated_signature = bytes([result.signature[0] ^ 1]) + result.signature[1:]
        changed = statement_with(name, signature=mutated_signature)
        assert inspect_vector(name, statement=changed).rsa_signature_verification == "not_evaluated"


@pytest.mark.parametrize(
    "field,maximum",
    (
        ("context", contract.MAX_CONTEXT_BYTES),
        ("challenge", contract.MAX_CHALLENGE_BYTES),
        ("proof", contract.MAX_PROOF_BYTES),
        ("approvalEvent", contract.MAX_APPROVAL_EVENT_BYTES),
        ("actualRequest", contract.MAX_ACTUAL_REQUEST_BYTES),
        ("routingRequest", contract.MAX_ROUTING_REQUEST_BYTES),
    ),
)
def test_every_embedded_input_size_cap_rejects_maximum_plus_one(field, maximum):
    value = json.loads(vector("enrollmentV2")["inputWire"])
    value[field] = "x" * (maximum + 1)
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_verification_input_v1(canonical(value))


def test_outer_size_caps_and_exact_ascii_inner_boundary_are_enforced():
    for parser, maximum in (
        (contract.parse_verification_context_v1, contract.MAX_CONTEXT_BYTES),
        (contract.parse_verification_input_v1, contract.MAX_INPUT_BYTES),
    ):
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            parser("x" * (maximum + 1))
    assert contract._ascii_string("x" * contract.MAX_PROOF_BYTES, maximum=contract.MAX_PROOF_BYTES) == (
        "x" * contract.MAX_PROOF_BYTES
    )
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract._ascii_string("x" * (contract.MAX_PROOF_BYTES + 1), maximum=contract.MAX_PROOF_BYTES)
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        inspect_vector("ciphertextSubmit", statement="x" * (contract.MAX_STATEMENT_BYTES + 1))
    assert VECTORS["limits"] == {
        "actualRequestBytes": contract.MAX_ACTUAL_REQUEST_BYTES,
        "approvalEventBytes": contract.MAX_APPROVAL_EVENT_BYTES,
        "challengeBytes": contract.MAX_CHALLENGE_BYTES,
        "contextBytes": contract.MAX_CONTEXT_BYTES,
        "inputBytes": contract.MAX_INPUT_BYTES,
        "proofBytes": contract.MAX_PROOF_BYTES,
        "routingRequestBytes": contract.MAX_ROUTING_REQUEST_BYTES,
        "statementBytes": contract.MAX_STATEMENT_BYTES,
        "statementLifetimeMs": contract.MAX_STATEMENT_LIFETIME_MS,
    }


def test_exact_route_command_and_response_fixture_round_trips_and_mismatches_fail():
    assert [list(item) for item in contract.ADMISSION_ROUTE_TUPLES] == VECTORS["routeTuples"]
    assert len(contract.ADMISSION_ROUTE_TUPLES) == 11
    for suffix, wire in VECTORS["commandWires"].items():
        path = contract.ADMISSION_PREFIX + suffix
        parsed = contract.parse_admission_command_v1(path, wire)
        assert parsed.route.path == path
        for field in json.loads(wire):
            changed = json.loads(wire)
            del changed[field]
            with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
                contract.parse_admission_command_v1(path, canonical(changed))
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            contract.parse_admission_command_v1(path, canonical({**json.loads(wire), "unknown": None}))
        other = next(item for item in contract.ADMISSION_ROUTES.values() if item.command != parsed.route.command)
        changed = canonical({**json.loads(wire), "command": other.command})
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            contract.parse_admission_command_v1(path, changed)
    for suffix, wire in VECTORS["responseWires"].items():
        path = contract.ADMISSION_PREFIX + suffix
        assert contract.parse_admission_response_v1(path, wire).route.path == path
        for field in json.loads(wire):
            changed = json.loads(wire)
            del changed[field]
            with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
                contract.parse_admission_response_v1(path, canonical(changed))
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            contract.parse_admission_response_v1(path, canonical({**json.loads(wire), "unknown": None}))
        changed = canonical({**json.loads(wire), "kind": "wrong-kind"})
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            contract.parse_admission_response_v1(path, changed)
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_admission_command_v1(contract.ADMISSION_PREFIX + "/unknown", "{}")


def test_challenge_command_device_id_must_equal_the_canonical_actual_request_device_id():
    path = contract.ADMISSION_PREFIX + "/challenge"
    value = json.loads(VECTORS["commandWires"]["/challenge"])
    request = {**json.loads(value["actualRequestWire"]), "deviceId": "31" * 32}
    value["actualRequestWire"] = canonical(request)
    source = canonical(value)
    assert request["deviceId"] != value["deviceId"]
    assert contract._parse_request(value["actualRequestWire"])["deviceId"] == request["deviceId"]
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_admission_command_v1(path, source)


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("enrollmentChallengeId", "61" * 32),
        ("audience", "https://other.example"),
        ("subject", "62" * 32),
        ("deviceId", "63" * 32),
        ("x25519BindingId", "64" * 32),
        ("x25519BindingVersion", 2),
        (
            "x25519PublicKeyCommitment",
            "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "65" * 32,
        ),
        ("ed25519PublicKey", "66" * 32),
    ),
)
def test_enrollment_challenge_response_rejects_each_canonical_context_cross_binding_mismatch(field, replacement):
    path = contract.ADMISSION_PREFIX + "/enrollment-challenge"
    value = json.loads(VECTORS["responseWires"]["/enrollment-challenge"])
    challenge = {**json.loads(value["challengeWire"]), field: replacement}
    value["challengeWire"] = canonical(challenge)
    assert canonical(json.loads(value["challengeWire"])) == value["challengeWire"]
    contract.parse_enrollment_v2(value["challengeWire"])
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_admission_response_v1(path, canonical(value))


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("challengeId", "71" * 32),
        ("audience", "https://other.example"),
        ("subject", "72" * 32),
        ("deviceId", "73" * 32),
        ("bindingId", "74" * 32),
        ("bindingVersion", 2),
        ("sessionBinding", "75" * 32),
    ),
)
def test_device_request_challenge_response_rejects_each_canonical_context_cross_binding_mismatch(field, replacement):
    path = contract.ADMISSION_PREFIX + "/challenge-read"
    value = json.loads(VECTORS["responseWires"]["/challenge-read"])
    challenge = json.loads(value["challengeWire"])
    if field == "challengeId":
        challenge[field] = replacement
    else:
        challenge["request"] = canonical({**json.loads(challenge["request"]), field: replacement})
    value["challengeWire"] = canonical(challenge)
    assert canonical(json.loads(value["challengeWire"])) == value["challengeWire"]
    contract._parse_request_challenge(value["challengeWire"])
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_admission_response_v1(path, canonical(value))


@pytest.mark.parametrize(
    "state,challenge_present,context_present,phone_proof_present,approval_event_present,receipt_present",
    (
        [("prepared", False, False, False, False, False)]
        + [("challenged", True, True, phone, approval, False) for phone in (False, True) for approval in (False, True)]
        + [("consumed", True, True, True, True, True)]
        + [(state, False, False, False, False, False) for state in ("cancelled", "expired", "invalidated")]
        + [
            (state, True, True, phone, approval, False)
            for state in ("cancelled", "expired", "invalidated")
            for phone in (False, True)
            for approval in (False, True)
        ]
    ),
)
def test_complete_enrollment_state_matrix_accepts_only_frozen_positive_shapes(
    state,
    challenge_present,
    context_present,
    phone_proof_present,
    approval_event_present,
    receipt_present,
):
    value = enrollment_state_response(
        state,
        challenge_present=challenge_present,
        context_present=context_present,
        phone_proof_present=phone_proof_present,
        approval_event_present=approval_event_present,
        receipt_present=receipt_present,
    )
    parsed = contract.parse_admission_response_v1(
        contract.ADMISSION_PREFIX + "/enrollment-read",
        canonical(value),
    )
    assert parsed.values["state"] == state


@pytest.mark.parametrize(
    "state,challenge_present,context_present,phone_proof_present,approval_event_present,receipt_present",
    (
        [
            ("prepared", challenge, context, phone, approval, receipt)
            for challenge, context, phone, approval, receipt in (
                (True, False, False, False, False),
                (False, True, False, False, False),
                (False, False, True, False, False),
                (False, False, False, True, False),
                (False, False, False, False, True),
            )
        ]
        + [
            ("challenged", challenge, context, False, False, receipt)
            for challenge, context, receipt in (
                (False, False, False),
                (True, False, False),
                (False, True, False),
                (True, True, True),
            )
        ]
        + [
            ("consumed", challenge, context, phone, approval, receipt)
            for challenge, context, phone, approval, receipt in (
                (False, True, True, True, True),
                (True, False, True, True, True),
                (True, True, False, True, True),
                (True, True, True, False, True),
                (True, True, True, True, False),
            )
        ]
        + [
            (state, challenge, context, phone, approval, receipt)
            for state in ("cancelled", "expired", "invalidated")
            for challenge, context, phone, approval, receipt in (
                (True, False, False, False, False),
                (False, True, False, False, False),
                (False, False, True, False, False),
                (False, False, False, True, False),
                (False, False, False, False, True),
                (True, True, False, False, True),
            )
        ]
    ),
)
def test_complete_enrollment_state_matrix_rejects_every_forbidden_presence_shape(
    state,
    challenge_present,
    context_present,
    phone_proof_present,
    approval_event_present,
    receipt_present,
):
    value = enrollment_state_response(
        state,
        challenge_present=challenge_present,
        context_present=context_present,
        phone_proof_present=phone_proof_present,
        approval_event_present=approval_event_present,
        receipt_present=receipt_present,
    )
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_admission_response_v1(
            contract.ADMISSION_PREFIX + "/enrollment-read",
            canonical(value),
        )


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("enrollmentChallengeId", "81" * 32),
        (
            "enrollmentDigest",
            "hodlxxi-social-messaging-device-enrollment-v2-sha256:" + "82" * 32,
        ),
        ("publicKey", "83" * 32),
    ),
)
def test_consumed_enrollment_state_rejects_each_phone_proof_binding_substitution(field, replacement):
    value = enrollment_state_response(
        "consumed",
        challenge_present=True,
        context_present=True,
        phone_proof_present=True,
        approval_event_present=True,
        receipt_present=True,
    )
    value["phoneProofWire"] = canonical({**json.loads(value["phoneProofWire"]), field: replacement})
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_admission_response_v1(
            contract.ADMISSION_PREFIX + "/enrollment-read",
            canonical(value),
        )


@pytest.mark.parametrize("state", ("challenged", "cancelled", "expired", "invalidated"))
def test_optional_enrollment_state_phone_proof_is_strictly_bound_when_present(state):
    value = enrollment_state_response(
        state,
        challenge_present=True,
        context_present=True,
        phone_proof_present=True,
        approval_event_present=False,
        receipt_present=False,
    )
    proof = {**json.loads(value["phoneProofWire"]), "publicKey": "84" * 32}
    value["phoneProofWire"] = canonical(proof)
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_admission_response_v1(
            contract.ADMISSION_PREFIX + "/enrollment-read",
            canonical(value),
        )


@pytest.mark.parametrize("state", ("challenged", "cancelled", "expired", "invalidated"))
def test_optional_enrollment_state_approval_event_is_strictly_bound_when_present(state):
    value = enrollment_state_response(
        state,
        challenge_present=True,
        context_present=True,
        phone_proof_present=False,
        approval_event_present=True,
        receipt_present=False,
    )
    event = {**json.loads(value["approvalEventWire"]), "id": "88" * 32}
    value["approvalEventWire"] = canonical(event)
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_admission_response_v1(
            contract.ADMISSION_PREFIX + "/enrollment-read",
            canonical(value),
        )


def test_enrollment_state_reuses_complete_challenge_context_cross_binding():
    value = enrollment_state_response(
        "challenged",
        challenge_present=True,
        context_present=True,
        phone_proof_present=False,
        approval_event_present=False,
        receipt_present=False,
    )
    challenge = {**json.loads(value["challengeWire"]), "audience": "https://other.example"}
    value["challengeWire"] = canonical(challenge)
    contract.parse_enrollment_v2(value["challengeWire"])
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_admission_response_v1(
            contract.ADMISSION_PREFIX + "/enrollment-read",
            canonical(value),
        )


@pytest.mark.parametrize("substitution", ("enrollment", "subject", "event-id"))
def test_consumed_enrollment_state_strictly_binds_approval_event(substitution):
    value = enrollment_state_response(
        "consumed",
        challenge_present=True,
        context_present=True,
        phone_proof_present=True,
        approval_event_present=True,
        receipt_present=True,
    )
    event = json.loads(value["approvalEventWire"])
    if substitution == "enrollment":
        event["content"] = canonical({**json.loads(event["content"]), "deviceId": "85" * 32})
    elif substitution == "subject":
        event["pubkey"] = "86" * 32
        event["id"] = nostr_event_id(event)
    else:
        event["id"] = "87" * 32
    value["approvalEventWire"] = canonical(event)
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_admission_response_v1(
            contract.ADMISSION_PREFIX + "/enrollment-read",
            canonical(value),
        )


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("challengeId", "91" * 32),
        ("operation", "ciphertext-submit"),
        ("status", "pending"),
    ),
)
def test_consumed_enrollment_state_requires_exact_committed_enrollment_receipt(field, replacement):
    value = enrollment_state_response(
        "consumed",
        challenge_present=True,
        context_present=True,
        phone_proof_present=True,
        approval_event_present=True,
        receipt_present=True,
    )
    value["receipt"] = {**value["receipt"], field: replacement}
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_admission_response_v1(
            contract.ADMISSION_PREFIX + "/enrollment-read",
            canonical(value),
        )


@pytest.mark.parametrize("operation", contract.OPERATIONS)
def test_receipt_vectors_are_exact_immutable_history_and_never_bearers(operation):
    wire = VECTORS["receipts"][operation]
    receipt = contract.parse_admission_receipt_v1(wire)
    assert receipt.operation == operation
    assert (
        contract.canonical_admission_receipt_v1_bytes(
            receipt_id=receipt.receipt_id,
            challenge_id=receipt.challenge_id,
            operation=receipt.operation,
            decided_at=receipt.decided_at,
        ).decode("ascii")
        == wire
    )
    inspection = contract.inspect_admission_receipt_v1(wire)
    assert inspection.bearer_authority == "none"
    assert inspection.reexecution_authority == "none"
    assert inspection.final_admission == "denied"
    for field in json.loads(wire):
        changed = json.loads(wire)
        del changed[field]
        with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            contract.parse_admission_receipt_v1(canonical(changed))
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.parse_admission_receipt_v1(canonical({**json.loads(wire), "unknown": None}))


@pytest.mark.parametrize(
    "machine,previous,next_state",
    [
        (machine, previous, next_state)
        for machine, transitions in (
            ("enrollment", contract.ENROLLMENT_TRANSITIONS),
            ("challenge", contract.CHALLENGE_TRANSITIONS),
            ("association", contract.ASSOCIATION_TRANSITIONS),
            ("receipt", contract.RECEIPT_TRANSITIONS),
        )
        for previous, next_states in transitions.items()
        for next_state in next_states
    ],
)
def test_every_allowed_state_transition_is_typed_and_has_no_commit_claim(machine, previous, next_state):
    result = contract.validate_state_transition_v1(machine, previous, next_state)
    assert result.machine == machine
    assert result.previous_state == previous
    assert result.next_state == next_state
    assert result.commit_claim == "not_evaluated"
    assert result.rollback_claim == "not_evaluated"


@pytest.mark.parametrize(
    "machine,terminal,next_state",
    (
        ("enrollment", "consumed", "prepared"),
        ("enrollment", "cancelled", "challenged"),
        ("challenge", "consumed", "issued"),
        ("challenge", "expired", "consumed"),
        ("association", "rotated", "active"),
        ("association", "revoked", "active"),
        ("receipt", "committed", "committed"),
    ),
)
def test_terminal_states_cannot_reopen_or_transition(machine, terminal, next_state):
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        contract.validate_state_transition_v1(machine, terminal, next_state)


def test_exclusive_deadline_and_atomic_rollback_deadlock_nonclaims_are_frozen():
    assert contract.inspect_exclusive_deadline_v1(issued_at=10, expires_at=20, observed_at=9).disposition == (
        "not_yet_valid"
    )
    assert contract.inspect_exclusive_deadline_v1(issued_at=10, expires_at=20, observed_at=10).disposition == "current"
    assert contract.inspect_exclusive_deadline_v1(issued_at=10, expires_at=20, observed_at=19).disposition == "current"
    assert contract.inspect_exclusive_deadline_v1(issued_at=10, expires_at=20, observed_at=20).disposition == "expired"
    owner = contract.inspect_atomic_owner_v1()
    assert owner.owner == "ubid"
    assert owner.implementation == "selected_not_implemented"
    assert owner.rollback_claim == "no_effect_or_receipt_or_consumption_commit"
    assert owner.commit_claim == "durable_publication_not_implemented"
    assert owner.deadlock_outcome == "deny_and_roll_back"
    assert owner.lock_timeout_outcome == "deny_and_roll_back"
    assert owner.uncertain_commit_outcome == "reconcile_history_never_reexecute"
    assert owner.final_admission == "denied"


def test_ports_cannot_accept_or_return_a_bare_boolean_verification_result():
    protocols = (
        contract.ChallengeStorageOwner,
        contract.AuthenticatedSocialVerificationStatementVerifier,
        contract.TransactionBoundAdmissionAuthority,
        contract.ExactAtomicOperationEffectPort,
        contract.ReceiptHistoryProjection,
    )
    for protocol in protocols:
        for name, member in protocol.__dict__.items():
            if name.startswith("_") or not callable(member):
                continue
            signature = inspect.signature(member)
            assert signature.return_annotation not in (bool, "bool")
            assert all(parameter.annotation not in (bool, "bool") for parameter in signature.parameters.values())
            assert all(
                parameter.name not in {"verified", "admit", "admitted"} for parameter in signature.parameters.values()
            )
    source = (ROOT / "app/services/social_messaging_device_admission_contract.py").read_text()
    assert "def admit(" not in source
    assert "verified=True" not in source
    assert "verified: bool" not in source


def test_challenge_storage_protocol_separates_receipted_consumption_from_receipt_free_terminalization():
    consumed = inspect.signature(contract.ChallengeStorageOwner.record_consumed_challenge_transition)
    non_consumed = inspect.signature(contract.ChallengeStorageOwner.record_non_consumed_terminal_challenge_transition)
    assert tuple(consumed.parameters) == ("self", "challenge", "transition", "receipt")
    assert consumed.parameters["receipt"].annotation in (
        contract.AdmissionReceiptV1,
        "AdmissionReceiptV1",
    )
    assert consumed.parameters["receipt"].default is inspect.Signature.empty
    assert tuple(non_consumed.parameters) == ("self", "challenge", "transition")
    assert "receipt" not in non_consumed.parameters
    assert not hasattr(contract.ChallengeStorageOwner, "record_terminal_challenge_transition")

    source = inspect.getsource(contract.ChallengeStorageOwner)
    assert "record_consumed_challenge_transition" in source
    assert "record_non_consumed_terminal_challenge_transition" in source
    assert source.count("receipt: AdmissionReceiptV1") == 1


def test_inspection_nonclaims_have_no_constructor_override_fields():
    result_fields = {field.name for field in fields(contract.VerificationStatementInspectionV1)}
    required = {
        "rsa_signature_verification",
        "cryptographic_verification",
        "current_authority",
        "challenge_consumption",
        "operation_effect",
        "final_admission",
        "runtime_enabled",
        "atomic_owner",
    }
    assert required <= result_fields
    result = inspect_vector("ciphertextSubmit")
    for name in required:
        assert next(field for field in fields(result) if field.name == name).init is False
        with pytest.raises(ValueError):
            replace(result, **{name: "forbidden-override"})


def test_no_io_route_factory_runtime_or_framework_import_exists():
    source_path = ROOT / "app/services/social_messaging_device_admission_contract.py"
    tree = ast.parse(source_path.read_text())
    imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    assert not any(
        name.startswith(("flask", "sqlalchemy", "socket", "requests", "urllib", "redis", "psycopg")) for name in imports
    )
    for path in ("app/factory.py", "app/config.py"):
        assert "social_messaging_device_admission_contract" not in (ROOT / path).read_text()
    assert not (ROOT / "app/blueprints/internal_social_device_admission.py").exists()


def test_all_five_c0_shared_fixtures_are_byte_identical():
    expected = {
        "social_messaging_device_proof_profile_v1.json": (
            "f616cee3db22d906d309953ae74b5626109a643884edd27b00fba68325508477"
        ),
        "social_mobile_device_authorization_v1.json": (
            "26f335b718a771d08aacc7ebbe63895d395e2e2376d12484fb19ab30c0db7356"
        ),
        "social_mobile_authorization_ingress_v1.json": (
            "d8f40ccc552c18c1beadb5ddb9d6a12b4b42c48dbe1eaf82c96f97233eca2e7d"
        ),
        "social_session_issuance_v1.json": "474bdfa4d3c300da0e78e5cde9a2b8dd263ee1e68227bb3a5000687d2ce230f3",
        "social_messaging_phase3_routing_v1.json": "90f7c3726a9dfcfa655630626d53d65b410e5e330456d5114d04982a53da2f1c",
    }
    for name, digest in expected.items():
        assert hashlib.sha256((ROOT / "tests/fixtures" / name).read_bytes()).hexdigest() == digest

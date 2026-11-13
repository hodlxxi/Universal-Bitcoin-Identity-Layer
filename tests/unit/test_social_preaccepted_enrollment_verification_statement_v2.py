from __future__ import annotations

import ast
import base64
import builtins
import copy
import gc
import hashlib
import inspect
import json
import pickle
import socket
import weakref
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, is_dataclass, replace
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.services import social_device_verification_statement as v1_verifier
from app.services import social_messaging_device_admission_contract as v1_contract
from app.services import social_preaccepted_enrollment_verification_statement_v2 as verifier

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "tests/fixtures/social_preaccepted_enrollment_verification_statement_v2.json"
SOURCE_FIXTURE_PATH = ROOT / "tests/fixtures/social_preacceptance_ed25519_handoff_v2.json"
V1_FIXTURE_PATH = ROOT / "tests/fixtures/social_device_admission_v1.json"
FIXTURE = json.loads(FIXTURE_PATH.read_bytes())
SOURCE = json.loads(SOURCE_FIXTURE_PATH.read_bytes())
V1_FIXTURE = json.loads(V1_FIXTURE_PATH.read_bytes())
VECTOR = FIXTURE["vector"]
SOURCE_VECTOR = SOURCE["vector"]
CONFIG = FIXTURE["configuration"]
DEADLINES = FIXTURE["deadlines"]
JWK = FIXTURE["publicVerificationMaterial"]["jwk"]
DENIED = verifier.SocialPreacceptedEnrollmentVerificationStatementV2Denied
ERROR = "^social preaccepted enrollment verification statement denied$"


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def configuration(**changes: object) -> verifier.SocialPreacceptedEnrollmentVerificationStatementV2Config:
    values = {
        "enabled": True,
        "issuer": CONFIG["issuer"],
        "audience": CONFIG["audience"],
        "client_id": CONFIG["clientId"],
        "service_principal": CONFIG["servicePrincipal"],
        "trusted_jwks": (dict(JWK),),
    }
    values.update(changes)
    return verifier.SocialPreacceptedEnrollmentVerificationStatementV2Config(**values)


def arguments(**changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "expected_context_wire": SOURCE_VECTOR["verificationContextWire"],
        "expected_input_wire": SOURCE_VECTOR["preacceptedEnrollmentVerificationInputWire"],
        "now": DEADLINES["now"],
        "phone_session_expires_at_ms": DEADLINES["phoneSessionExpiresAtMs"],
        "approver_session_expires_at_ms": DEADLINES["approverSessionExpiresAtMs"],
        "full_expires_at_ms": DEADLINES["fullExpiresAtMs"],
        "x25519_binding_expires_at_ms": DEADLINES["x25519BindingExpiresAtMs"],
    }
    values.update(changes)
    return values


def verify(**changes: object) -> verifier.AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2:
    statement = changes.pop("statement", VECTOR["compactJws"])
    config = changes.pop("config", configuration())
    return verifier.verify_social_preaccepted_enrollment_verification_statement_v2(
        statement, config=config, **arguments(**changes)
    )


def statement_with(*, header: str | None = None, payload: str | None = None, signature: bytes | None = None) -> str:
    return ".".join(
        (
            b64((VECTOR["protectedHeaderWire"] if header is None else header).encode("ascii")),
            b64((VECTOR["payloadWire"] if payload is None else payload).encode("ascii")),
            VECTOR["signature"] if signature is None else b64(signature),
        )
    )


def payload_with(**changes: object) -> str:
    value = {**json.loads(VECTOR["payloadWire"]), **changes}
    if "jti" not in changes:
        without_jti = {key: item for key, item in value.items() if key != "jti"}
        value["jti"] = hashlib.sha256(
            verifier.STATEMENT_JTI_DOMAIN.encode("ascii") + b"\0" + canonical(without_jti).encode("ascii")
        ).hexdigest()
    return canonical(value)


def denied(callable_value) -> None:
    with pytest.raises(DENIED, match=ERROR) as failure:
        callable_value()
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


def test_fixed_contract_bytes_signature_jti_and_projection_are_exact():
    assert len(FIXTURE_PATH.read_bytes()) == 12_018
    assert hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest() == (
        "fdbbed748f28d1ef850ef3d82b1680e7dca12b0f7a2d863acf14dc7b75770f39"
    )
    header, payload, signature = VECTOR["compactJws"].split(".")
    assert header == VECTOR["protectedHeaderSegment"] == b64(VECTOR["protectedHeaderWire"].encode("ascii"))
    assert payload == VECTOR["payloadSegment"] == b64(VECTOR["payloadWire"].encode("ascii"))
    assert signature == VECTOR["signature"]
    assert VECTOR["signingInput"] == header + "." + payload
    public_key = serialization.load_pem_public_key(FIXTURE["publicVerificationMaterial"]["spkiPem"].encode("ascii"))
    public_key.verify(unb64(signature), VECTOR["signingInput"].encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    assert (
        verifier.canonical_preaccepted_enrollment_verification_statement_protected_header_v2_bytes(
            kid=CONFIG["kid"]
        ).decode("ascii")
        == VECTOR["protectedHeaderWire"]
    )
    payload_arguments = {
        "issuer": CONFIG["issuer"],
        "audience": CONFIG["audience"],
        "client_id": CONFIG["clientId"],
        "service_principal": CONFIG["servicePrincipal"],
        "expected_context_wire": SOURCE_VECTOR["verificationContextWire"],
        "expected_input_wire": SOURCE_VECTOR["preacceptedEnrollmentVerificationInputWire"],
        "issued_at": json.loads(VECTOR["payloadWire"])["issuedAt"],
        "expires_at": json.loads(VECTOR["payloadWire"])["expiresAt"],
    }
    assert (
        verifier.canonical_preaccepted_enrollment_verification_statement_payload_without_jti_v2_bytes(
            **payload_arguments
        ).decode("ascii")
        == VECTOR["payloadWithoutJtiWire"]
    )
    assert (
        verifier.preaccepted_enrollment_verification_statement_jti_v2(VECTOR["payloadWithoutJtiWire"]) == VECTOR["jti"]
    )
    assert (
        verifier.canonical_preaccepted_enrollment_verification_statement_payload_v2_bytes(**payload_arguments).decode(
            "ascii"
        )
        == VECTOR["payloadWire"]
    )
    assert (
        verifier.compact_preaccepted_enrollment_verification_statement_v2(
            protected_header_wire=VECTOR["protectedHeaderWire"],
            payload_wire=VECTOR["payloadWire"],
            signature=unb64(VECTOR["signature"]),
        )
        == VECTOR["compactJws"]
    )
    result = verify()
    assert type(result) is verifier.AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2
    assert dict(verifier.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(result)) == (
        VECTOR["expectedAuthenticatedProjection"]
    )
    assert repr(result).find(result.token_id) == -1
    assert not hasattr(result, "__dict__")
    with pytest.raises(FrozenInstanceError):
        result.expires_at += 1


def test_signature_verification_uses_the_original_ascii_segments():
    config = configuration()
    trusted = config._keys[0]
    observed = Mock(spec=rsa.RSAPublicKey, wraps=trusted.public_key)
    observed.key_size = trusted.public_key.key_size
    object.__setattr__(
        config,
        "_keys",
        (verifier._TrustedRSAKeyV2(trusted.kid, observed, trusted.fingerprint),),
    )
    result = verify(config=config)
    assert result.key_id == CONFIG["kid"]
    observed.verify.assert_called_once()
    call = observed.verify.call_args.args
    assert call[0] == unb64(VECTOR["signature"])
    assert call[1] == VECTOR["signingInput"].encode("ascii")
    assert isinstance(call[2], padding.PKCS1v15)
    assert isinstance(call[3], hashes.SHA256)


def test_empty_configuration_is_disabled_and_no_truthy_gate_exists():
    assert verifier.SocialPreacceptedEnrollmentVerificationStatementV2Config().enabled is False
    denied(
        lambda: verifier.verify_social_preaccepted_enrollment_verification_statement_v2(
            VECTOR["compactJws"], **arguments()
        )
    )
    denied(lambda: verify(config=configuration(enabled=False)))
    for enabled in (1, "true", None):
        denied(lambda enabled=enabled: configuration(enabled=enabled))


def test_exact_kid_selection_duplicate_kids_and_same_kid_wrong_key_substitution():
    other = {**JWK, "kid": "other-v2-key"}
    assert verify(config=configuration(trusted_jwks=(other, JWK))).key_id == CONFIG["kid"]
    denied(lambda: configuration(trusted_jwks=(JWK, dict(JWK))))
    denied(lambda: configuration(trusted_jwks=(JWK, {**JWK, "n": "AQ"})))
    wrong = {**JWK, "n": b64(bytes([unb64(JWK["n"])[0] ^ 1]) + unb64(JWK["n"])[1:])}
    denied(lambda: verify(config=configuration(trusted_jwks=(wrong,))))
    unknown_header = canonical({**json.loads(VECTOR["protectedHeaderWire"]), "kid": "unknown-v2-key"})
    denied(lambda: verify(statement=statement_with(header=unknown_header)))


@pytest.mark.parametrize("parameter", ("d", "p", "q", "dp", "dq", "qi", "oth", "k"))
@pytest.mark.parametrize("value", (None, "forbidden"))
@pytest.mark.parametrize("enabled", (False, True))
def test_private_or_symmetric_jwk_material_is_rejected_even_when_disabled(parameter, value, enabled):
    denied(lambda: configuration(enabled=enabled, trusted_jwks=({**JWK, parameter: value},)))


@pytest.mark.parametrize(
    "changes",
    (
        {"kty": "oct", "k": "c3ludGhldGlj"},
        {"kty": "EC"},
        {"kty": "OKP"},
        {"use": "enc"},
        {"alg": "none"},
        {"alg": "HS256"},
        {"alg": "PS256"},
        {"kid": ""},
        {"kid": " padded"},
        {"kid": True},
        {"n": ""},
        {"n": None},
        {"n": "!!"},
        {"n": "AQ"},
        {"n": "AA"},
        {"n": JWK["n"] + "="},
        {"n": b64(b"\0" + unb64(JWK["n"]))},
        {"n": b64((int.from_bytes(unb64(JWK["n"]), "big") - 1).to_bytes(256, "big"))},
        {"n": "A" * 1367},
        {"e": ""},
        {"e": "AQ"},
        {"e": "Aw"},
        {"e": "AQAB="},
        {"e": "AAEAAQ"},
        {"e": "A" * 17},
        {"jwk": {}},
        {"jku": "https://keys.example"},
        {"x5u": "https://keys.example"},
        {"x5c": []},
        {"x5t": "certificate"},
        {"key_ops": ["verify"]},
        {"pem": "not-a-key"},
    ),
)
def test_malformed_weak_nonminimal_or_nonpublic_jwk_fails_closed(changes):
    denied(lambda: configuration(trusted_jwks=({**JWK, **changes},)))


@pytest.mark.parametrize("missing", sorted(JWK))
def test_every_public_jwk_field_is_required(missing):
    value = dict(JWK)
    del value[missing]
    denied(lambda: configuration(trusted_jwks=(value,)))


@pytest.mark.parametrize("keys", ((), [], (True,), ("not-a-jwk",), ({},)))
def test_empty_or_non_plain_registration_is_rejected(keys):
    denied(lambda: configuration(trusted_jwks=keys))


@pytest.mark.parametrize(
    "changes",
    (
        {"issuer": ""},
        {"issuer": "https://social.example/"},
        {"audience": CONFIG["issuer"]},
        {"audience": "https://ubid.example/internal/v1/social/device-admission/consume"},
        {"audience": "https://ubid.example/other"},
        {"client_id": ""},
        {"service_principal": ""},
        {"purpose": v1_contract.STATEMENT_PURPOSE},
        {"purpose": ""},
        {"purpose": True},
        {"issuer": True},
    ),
)
def test_invalid_trust_identity_v1_audience_or_purpose_is_rejected(changes):
    denied(lambda: configuration(**changes))


def test_trust_registration_is_copied_and_retains_public_material_only():
    caller_key = dict(JWK)
    config = configuration(trusted_jwks=(caller_key,))
    caller_key["n"] = "invalid"
    caller_key["d"] = "forbidden"
    assert verify(config=config).key_id == CONFIG["kid"]
    assert dict(config.trusted_jwks[0]) == JWK
    assert set(config.trusted_jwks[0]) == {"kty", "use", "alg", "kid", "n", "e"}
    assert isinstance(config._keys[0].public_key, rsa.RSAPublicKey)
    assert not hasattr(config._keys[0].public_key, "private_numbers")
    assert not hasattr(config._keys[0].public_key, "sign")
    with pytest.raises(TypeError):
        config.trusted_jwks[0]["n"] = "invalid"
    with pytest.raises(FrozenInstanceError):
        config.enabled = False
    denied(lambda: verify(config=True))
    denied(lambda: verify(config={"enabled": True}))


@pytest.mark.parametrize(
    "changes",
    (
        {"alg": "none"},
        {"alg": "HS256"},
        {"alg": "PS256"},
        {"alg": "RS384"},
        {"typ": "JWT"},
        {"typ": v1_contract.STATEMENT_TYPE},
        {"jwk": JWK},
        {"jku": "https://keys.example"},
        {"x5u": "https://keys.example"},
        {"x5c": []},
        {"x5t": "certificate"},
        {"crit": []},
        {"b64": False},
        {"kid": ""},
        {"kid": True},
    ),
)
def test_protected_header_rejects_algorithm_type_and_extension_substitution(changes):
    header = canonical({**json.loads(VECTOR["protectedHeaderWire"]), **changes})
    denied(lambda: verify(statement=statement_with(header=header)))


@pytest.mark.parametrize("field", ("alg", "kid", "typ"))
def test_every_header_field_is_required_and_every_mutation_is_rejected(field):
    original = json.loads(VECTOR["protectedHeaderWire"])
    missing = dict(original)
    del missing[field]
    denied(lambda: verify(statement=statement_with(header=canonical(missing))))
    mutated = {**original, field: {"alg": "PS256", "kid": "other", "typ": "other+jws"}[field]}
    denied(lambda: verify(statement=statement_with(header=canonical(mutated))))
    denied(lambda: verify(statement=statement_with(header=canonical({**original, "unknown": None}))))


PAYLOAD_MUTATIONS = {
    "acceptanceId": "00" * 32,
    "associationId": "01" * 32,
    "attemptId": "02" * 32,
    "aud": "https://ubid.example/internal/v1/social/device-admission/consume",
    "clientId": "other-client-v2",
    "enrollmentChallengeId": "03" * 32,
    "expiresAt": json.loads(VECTOR["payloadWire"])["expiresAt"] - 1,
    "inputDigest": "hodlxxi-social-preaccepted-enrollment-verification-input-v2-sha256:" + "04" * 32,
    "iss": "https://other.example",
    "issuedAt": json.loads(VECTOR["payloadWire"])["issuedAt"] + 1,
    "jti": "05" * 32,
    "purpose": v1_contract.STATEMENT_PURPOSE,
    "result": v1_contract.ENROLLMENT_V2_RESULT,
    "schema": v1_contract.VERIFICATION_STATEMENT_SCHEMA,
    "servicePrincipal": "other-principal-v2",
    "version": 1,
}

AUTHENTIC_FACT_MUTATIONS = (
    ("issuer", "issuer", "https://attacker.example"),
    (
        "audience",
        "audience",
        "https://attacker.example/internal/v2/social/device-admission/consume",
    ),
    ("client_id", "clientId", "attacker-client-v2"),
    ("service_principal", "servicePrincipal", "attacker-principal-v2"),
    ("purpose", "purpose", "attacker_social_preaccepted_verification_v2"),
    ("result", "result", "attacker-preaccepted-enrollment-v2-valid"),
    ("acceptance_id", "acceptanceId", "a1" * 32),
    ("association_id", "associationId", "a2" * 32),
    ("enrollment_challenge_id", "enrollmentChallengeId", "a3" * 32),
    ("attempt_id", "attemptId", "a4" * 32),
    (
        "input_digest",
        "inputDigest",
        "hodlxxi-social-preaccepted-enrollment-verification-input-v2-sha256:" + "a5" * 32,
    ),
    ("issued_at", "issuedAt", 1788906600001),
    ("expires_at", "expiresAt", 1788906609999),
    ("token_id", "tokenId", "a6" * 32),
    ("key_id", "keyId", "attacker-v2-key"),
    ("key_fingerprint", "keyFingerprint", "sha256:" + "a7" * 32),
)

BOUNDARY_REBINDINGS = (
    ("AUTHORITY", "authority", "attacker-granted"),
    ("DURABLE_ACCEPTANCE", "durableAcceptance", "attacker-established"),
    ("CURRENT_AUTHORITY", "currentAuthority", "attacker-current"),
    ("CHALLENGE_CONSUMPTION", "challengeConsumption", "attacker-consumed"),
    ("ASSOCIATION_COMMITMENT", "associationCommitment", "attacker-committed"),
    ("RECEIPT", "receipt", "attacker-issued"),
    ("FINAL_ADMISSION", "finalAdmission", "attacker-admitted"),
    ("RUNTIME_ENABLED", "runtimeEnabled", True),
)


@pytest.mark.parametrize("field", sorted(PAYLOAD_MUTATIONS))
def test_every_payload_field_is_required_and_every_mutation_is_rejected(field):
    original = json.loads(VECTOR["payloadWire"])
    missing = dict(original)
    del missing[field]
    denied(lambda: verify(statement=statement_with(payload=canonical(missing))))
    denied(lambda: verify(statement=statement_with(payload=payload_with(**{field: PAYLOAD_MUTATIONS[field]}))))
    denied(lambda: verify(statement=statement_with(payload=canonical({**original, "unknown": None}))))


@pytest.mark.parametrize("segment", ("header", "payload"))
@pytest.mark.parametrize("mutation", ("duplicate", "spaces", "newline", "order", "escape", "unknown"))
def test_duplicate_or_noncanonical_header_and_payload_json_is_rejected(segment, mutation):
    original = VECTOR["protectedHeaderWire" if segment == "header" else "payloadWire"]
    value = json.loads(original)
    field = next(iter(value))
    options = {
        "duplicate": '{"' + field + '":' + canonical(value[field]) + "," + original[1:],
        "spaces": json.dumps(value, sort_keys=True),
        "newline": original + "\n",
        "order": json.dumps(dict(reversed(list(value.items()))), separators=(",", ":")),
        "escape": original.replace('"' + field + '"', '"\\u' + format(ord(field[0]), "04x") + field[1:] + '"', 1),
        "unknown": canonical({**value, "unknown": None}),
    }
    denied(lambda: verify(statement=statement_with(**{segment: options[mutation]})))


@pytest.mark.parametrize("segment", (0, 1, 2))
def test_padded_or_noncanonical_base64url_is_rejected_in_every_segment(segment):
    parts = VECTOR["compactJws"].split(".")
    parts[segment] += "="
    denied(lambda: verify(statement=".".join(parts)))
    parts = VECTOR["compactJws"].split(".")
    parts[segment] = "+" + parts[segment][1:]
    denied(lambda: verify(statement=".".join(parts)))


def test_nonzero_unused_base64url_bits_are_rejected():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    parts = VECTOR["compactJws"].split(".")
    original = parts[2]
    parts[2] = original[:-1] + alphabet[alphabet.index(original[-1]) + 1]
    assert unb64(parts[2]) == unb64(original)
    denied(lambda: verify(statement=".".join(parts)))


@pytest.mark.parametrize(
    "statement",
    (None, True, {}, b"a.b.c", "", "a.b", "a.b.c.d", "a..c", "a.b.c", "x" * 4097, "é.b.c"),
)
def test_malformed_empty_extra_segment_or_non_ascii_statement_has_one_failure(statement):
    denied(lambda: verify(statement=statement))


@pytest.mark.parametrize("kind", ("bit", "truncated", "extended", "empty"))
def test_signature_truncation_extension_bit_mutation_and_empty_segment_are_rejected(kind):
    signature = unb64(VECTOR["signature"])
    changed = {
        "bit": bytes([signature[0] ^ 1]) + signature[1:],
        "truncated": signature[:-1],
        "extended": signature + b"\0",
        "empty": b"",
    }[kind]
    statement = statement_with(signature=changed)
    denied(lambda: verify(statement=statement))


def mutate_expected_input(category: str, field: str, value: object) -> tuple[str, str]:
    input_value = json.loads(SOURCE_VECTOR["preacceptedEnrollmentVerificationInputWire"])
    expected_context = SOURCE_VECTOR["verificationContextWire"]
    if category == "input":
        input_value[field] = value
    elif category == "context":
        context = json.loads(input_value["context"])
        context[field] = value
        expected_context = canonical(context)
        input_value["context"] = expected_context
    elif category == "enrollment":
        enrollment = json.loads(input_value["enrollment"])
        enrollment[field] = value
        input_value["enrollment"] = canonical(enrollment)
    elif category == "proof":
        proof = json.loads(input_value["phoneProof"])
        proof[field] = value
        input_value["phoneProof"] = canonical(proof)
    else:
        approval = json.loads(input_value["approvalEvent"])
        authorization = json.loads(approval["content"])
        if category == "event":
            approval[field] = value
        elif category == "authorization":
            authorization[field] = value
            approval["content"] = canonical(authorization)
        elif category == "authorizationContext":
            authorization["context"][field] = value
            approval["content"] = canonical(authorization)
        elif category == "preEnrollment":
            pre_enrollment = json.loads(authorization["preEnrollment"])
            pre_enrollment[field] = value
            authorization["preEnrollment"] = canonical(pre_enrollment)
            approval["content"] = canonical(authorization)
        elif category == "bindingAuthorization":
            binding = json.loads(authorization["content"])
            binding["authorization"][field] = value
            authorization["content"] = canonical(binding)
            approval["content"] = canonical(authorization)
        input_value["approvalEvent"] = canonical(approval)
    return canonical(input_value), expected_context


@pytest.mark.parametrize(
    "category,field,value",
    (
        ("input", "acceptanceId", "10" * 32),
        ("context", "subject", "11" * 32),
        ("context", "deviceId", "12" * 32),
        ("context", "attemptId", "13" * 32),
        ("context", "challengeId", "14" * 32),
        ("context", "bindingId", "15" * 32),
        ("context", "bindingVersion", 2),
        (
            "context",
            "x25519PublicKeyCommitment",
            "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "16" * 32,
        ),
        ("context", "ed25519PublicKey", "17" * 32),
        ("context", "associationId", "18" * 32),
        ("context", "associationVersion", 2),
        ("context", "authorityEpoch", 2),
        ("context", "sessionBinding", "19" * 32),
        ("context", "approverSessionBinding", "1a" * 32),
        ("context", "fullProofId", "hodlxxi-full-entitlement-v1-sha256:" + "1b" * 32),
        ("context", "approverFullProofId", "hodlxxi-full-entitlement-v1-sha256:" + "1c" * 32),
        ("preEnrollment", "subject", "21" * 32),
        ("preEnrollment", "deviceId", "2d" * 32),
        ("preEnrollment", "requestId", "23" * 32),
        ("preEnrollment", "ed25519PublicKey", "24" * 32),
        ("preEnrollment", "x25519BindingId", "25" * 32),
        ("preEnrollment", "x25519BindingVersion", 2),
        (
            "preEnrollment",
            "x25519PublicKeyCommitment",
            "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "26" * 32,
        ),
        ("preEnrollment", "bindingAuthorizationDigest", "27" * 32),
        ("preEnrollment", "pairingId", "28" * 32),
        ("preEnrollment", "transitionKind", "rotate"),
        ("preEnrollment", "proposedAssociationVersion", 2),
        ("preEnrollment", "proposedAuthorityEpoch", 2),
        ("authorizationContext", "desktopContext", "29" * 32),
        ("authorizationContext", "exchangeCommitment", "2a" * 32),
        ("authorizationContext", "secretCommitment", "2b" * 32),
        ("bindingAuthorization", "subject", "31" * 32),
        ("bindingAuthorization", "deviceId", "32" * 32),
        ("bindingAuthorization", "requestId", "3d" * 32),
        ("bindingAuthorization", "bindingVersion", 2),
        ("bindingAuthorization", "publicKey", "34" * 32),
        ("enrollment", "subject", "41" * 32),
        ("enrollment", "deviceId", "42" * 32),
        ("enrollment", "enrollmentChallengeId", "43" * 32),
        ("enrollment", "ed25519PublicKey", "44" * 32),
        ("enrollment", "x25519BindingId", "45" * 32),
        ("enrollment", "x25519BindingVersion", 2),
        (
            "enrollment",
            "x25519PublicKeyCommitment",
            "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "46" * 32,
        ),
        ("enrollment", "issuedAt", 1788906600001),
        ("enrollment", "expiresAt", 1788906660001),
        ("proof", "enrollmentChallengeId", "51" * 32),
        (
            "proof",
            "enrollmentDigest",
            "hodlxxi-social-messaging-device-enrollment-v2-sha256:" + "52" * 32,
        ),
        ("proof", "publicKey", "53" * 32),
        ("proof", "signature", "54" * 64),
        ("event", "id", "61" * 32),
        ("event", "sig", "62" * 64),
        ("authorization", "method", "qr_desktop_v1"),
    ),
)
def test_every_equality_critical_nested_identity_and_phone_proof_mutation_is_rejected(category, field, value):
    input_wire, expected_context = mutate_expected_input(category, field, value)
    denied(
        lambda: verify(
            expected_input_wire=input_wire,
            expected_context_wire=expected_context,
        )
    )


def test_exact_input_and_context_wire_equality_is_required_not_equivalent_json():
    context = SOURCE_VECTOR["verificationContextWire"]
    input_wire = SOURCE_VECTOR["preacceptedEnrollmentVerificationInputWire"]
    for changed_context in (context + " ", json.dumps(json.loads(context), sort_keys=True), json.loads(context), True):
        denied(lambda changed_context=changed_context: verify(expected_context_wire=changed_context))
    for changed_input in (
        input_wire + " ",
        json.dumps(json.loads(input_wire), sort_keys=True),
        json.loads(input_wire),
        True,
    ):
        denied(lambda changed_input=changed_input: verify(expected_input_wire=changed_input))
    alternate_context = canonical({**json.loads(context), "attemptId": "fe" * 32})
    denied(lambda: verify(expected_context_wire=alternate_context))


def test_phone_signature_change_that_remains_shape_valid_changes_digest_and_denies():
    input_value = json.loads(SOURCE_VECTOR["preacceptedEnrollmentVerificationInputWire"])
    proof = json.loads(input_value["phoneProof"])
    proof["signature"] = "00" * 64
    input_value["phoneProof"] = canonical(proof)
    changed_input = canonical(input_value)
    denied(lambda: verify(expected_input_wire=changed_input))


def test_epoch_millisecond_clock_boundaries_are_exclusive_with_zero_skew():
    payload = json.loads(VECTOR["payloadWire"])
    for now in (payload["issuedAt"], payload["expiresAt"] - 1):
        assert verify(now=now).issued_at == payload["issuedAt"]
    for now in (payload["issuedAt"] - 1, payload["expiresAt"], payload["expiresAt"] + 1):
        denied(lambda now=now: verify(now=now))


@pytest.mark.parametrize(
    "deadline",
    (
        "phone_session_expires_at_ms",
        "approver_session_expires_at_ms",
        "full_expires_at_ms",
    ),
)
def test_each_explicit_session_or_full_deadline_is_required_and_bounds_underlying_enrollment(deadline):
    enrollment_expiry = json.loads(SOURCE_VECTOR["enrollmentWire"])["expiresAt"]
    assert verify(**{deadline: enrollment_expiry}).expires_at == json.loads(VECTOR["payloadWire"])["expiresAt"]
    for value in (enrollment_expiry - 1, 0, -1, True, "later", 2**53, enrollment_expiry // 1000):
        denied(lambda value=value: verify(**{deadline: value}))


def test_x25519_deadline_is_freshly_reparsed_and_cannot_be_substituted():
    assert verify(x25519_binding_expires_at_ms=DEADLINES["x25519BindingExpiresAtMs"])
    for value in (
        DEADLINES["x25519BindingExpiresAtMs"] - 1,
        DEADLINES["x25519BindingExpiresAtMs"] + 1,
        DEADLINES["x25519BindingExpiresAtMs"] // 1000,
        True,
        -1,
        2**53,
    ):
        denied(lambda value=value: verify(x25519_binding_expires_at_ms=value))


@pytest.mark.parametrize("value", (True, -1, 2**53, 1788906600))
def test_clock_rejects_booleans_negatives_unsafe_integers_and_seconds(value):
    denied(lambda: verify(now=value))


@pytest.mark.parametrize("lifetime", (0, -1, 10_001))
def test_statement_lifetime_is_positive_and_at_most_ten_seconds(lifetime):
    payload = json.loads(VECTOR["payloadWire"])
    kwargs = {
        "issuer": CONFIG["issuer"],
        "audience": CONFIG["audience"],
        "client_id": CONFIG["clientId"],
        "service_principal": CONFIG["servicePrincipal"],
        "expected_context_wire": SOURCE_VECTOR["verificationContextWire"],
        "expected_input_wire": SOURCE_VECTOR["preacceptedEnrollmentVerificationInputWire"],
        "issued_at": payload["issuedAt"],
        "expires_at": payload["issuedAt"] + lifetime,
    }
    denied(lambda: verifier.canonical_preaccepted_enrollment_verification_statement_payload_v2_bytes(**kwargs))


def test_statement_interval_cannot_escape_reparsed_enrollment_interval():
    payload = json.loads(VECTOR["payloadWire"])
    enrollment = json.loads(SOURCE_VECTOR["enrollmentWire"])
    common = {
        "issuer": CONFIG["issuer"],
        "audience": CONFIG["audience"],
        "client_id": CONFIG["clientId"],
        "service_principal": CONFIG["servicePrincipal"],
        "expected_context_wire": SOURCE_VECTOR["verificationContextWire"],
        "expected_input_wire": SOURCE_VECTOR["preacceptedEnrollmentVerificationInputWire"],
    }
    denied(
        lambda: verifier.canonical_preaccepted_enrollment_verification_statement_payload_v2_bytes(
            **common,
            issued_at=enrollment["issuedAt"] - 1,
            expires_at=payload["expiresAt"],
        )
    )
    denied(
        lambda: verifier.canonical_preaccepted_enrollment_verification_statement_payload_v2_bytes(
            **common,
            issued_at=enrollment["expiresAt"] - 1,
            expires_at=enrollment["expiresAt"] + 1,
        )
    )


def test_v1_and_v2_statement_protocols_reject_each_other_without_fallback():
    v1_vector = V1_FIXTURE["vectors"]["enrollmentV2"]
    denied(lambda: verify(statement=v1_vector["compactJws"]))
    v1_config = V1_FIXTURE["configuration"]
    with pytest.raises(v1_verifier.SocialDeviceVerificationStatementDenied):
        v1_verifier.verify_social_device_verification_statement_v1(
            VECTOR["compactJws"],
            config=v1_verifier.SocialDeviceVerificationStatementConfig(
                enabled=True,
                issuer=v1_config["issuer"],
                audience=v1_config["audience"],
                client_id=v1_config["clientId"],
                service_principal=v1_config["servicePrincipal"],
                trusted_jwks=(dict(V1_FIXTURE["publicVerificationMaterial"]["jwk"]),),
            ),
            expected_context_wire=v1_vector["contextWire"],
            expected_input_wire=v1_vector["inputWire"],
            now=v1_vector["now"],
            challenge_expires_at=v1_vector["challengeExpiresAt"],
            session_expires_at=v1_vector["sessionExpiresAt"],
            approver_session_expires_at=v1_vector["approverSessionExpiresAt"],
        )


def test_repeated_verification_is_stateless_and_consumes_or_mutates_nothing():
    first = verify()
    second = verify()
    assert first == second
    assert first is not second
    assert dict(verifier.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(first)) == (
        dict(verifier.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(second))
    )
    assert verifier.RUNTIME_ENABLED is False
    assert verifier.DURABLE_ACCEPTANCE == "not_established"
    assert verifier.CURRENT_AUTHORITY == "not_evaluated"
    assert verifier.CHALLENGE_CONSUMPTION == "not_implemented"
    assert verifier.ASSOCIATION_COMMITMENT == "not_implemented"
    assert verifier.FINAL_ADMISSION == "denied"
    assert verifier.RECEIPT == "not_issued"


def test_authenticated_result_is_narrow_frozen_hidden_and_projection_requires_internal_identity_brand():
    result = verify()
    assert not is_dataclass(result)
    assert type(result).__slots__ == ("__weakref__",)
    assert not hasattr(result, "_snapshot")
    for attribute, _, _ in AUTHENTIC_FACT_MUTATIONS:
        assert isinstance(inspect.getattr_static(type(result), attribute), property)

    authentic_type = verifier.AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2
    forged_object = object.__new__(authentic_type)
    facts = {attribute: getattr(result, attribute) for attribute, _, _ in AUTHENTIC_FACT_MUTATIONS}
    for attribute, _, mutation in AUTHENTIC_FACT_MUTATIONS:
        with pytest.raises(AttributeError):
            object.__setattr__(forged_object, attribute, mutation)
        denied(lambda attribute=attribute: getattr(forged_object, attribute))
    for forged in (
        forged_object,
        facts,
        SimpleNamespace(**facts),
        object(),
        True,
        None,
    ):
        denied(
            lambda forged=forged: (
                verifier.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(forged)
            )
        )
    for supplied in ((), (True,), (facts,), tuple(facts.values())):
        denied(lambda supplied=supplied: authentic_type(*supplied))
    denied(lambda: type("ForgedSubclass", (authentic_type,), {}))
    with pytest.raises(TypeError):
        replace(result, expires_at=result.expires_at + 1)
    denied(lambda: copy.copy(result))
    denied(lambda: copy.deepcopy(result))
    denied(lambda: pickle.dumps(result))


@pytest.mark.parametrize("attribute,projection_key,mutation", AUTHENTIC_FACT_MUTATIONS)
def test_registered_result_object_setattr_cannot_change_direct_or_projected_authenticated_fact(
    attribute, projection_key, mutation
):
    result = verify()
    original_direct = getattr(result, attribute)
    original_projection = dict(
        verifier.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(result)
    )
    assert mutation != original_direct

    try:
        object.__setattr__(result, attribute, mutation)
    except (AttributeError, FrozenInstanceError):
        pass

    assert getattr(result, attribute) == original_direct
    projected = dict(verifier.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(result))
    assert projected == original_projection
    assert projected[projection_key] == original_direct


def test_private_authenticated_snapshot_is_complete_immutable_and_not_publicly_exposed():
    result = verify()
    snapshot = verifier._AUTHENTIC_RESULTS[id(result)][1]
    expected_fields = tuple(attribute for attribute, _, _ in AUTHENTIC_FACT_MUTATIONS)
    assert snapshot._fields == expected_fields
    assert not hasattr(result, "_snapshot")
    assert "_AuthenticatedSnapshotV2" not in verifier.__all__

    for attribute, _, mutation in AUTHENTIC_FACT_MUTATIONS:
        assert getattr(snapshot, attribute) == getattr(result, attribute)
        with pytest.raises(AttributeError):
            object.__setattr__(snapshot, attribute, mutation)


@pytest.mark.parametrize("constant,projection_key,mutation", BOUNDARY_REBINDINGS)
def test_public_boundary_module_name_rebinding_cannot_change_projection(
    monkeypatch, constant, projection_key, mutation
):
    result = verify()
    original = dict(verifier.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(result))
    assert mutation != original[projection_key]

    monkeypatch.setattr(verifier, constant, mutation, raising=False)

    projected = dict(verifier.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(result))
    assert projected == original
    assert projected[projection_key] != mutation


def test_concurrent_object_setattr_and_projection_never_returns_mixed_or_forged_facts():
    result = verify()
    original = dict(verifier.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(result))
    barrier = Barrier(4)

    def mutate() -> None:
        barrier.wait()
        for _ in range(32):
            for attribute, _, mutation in AUTHENTIC_FACT_MUTATIONS:
                try:
                    object.__setattr__(result, attribute, mutation)
                except (AttributeError, FrozenInstanceError):
                    pass

    def project() -> tuple[str, ...]:
        barrier.wait()
        outcomes = []
        for _ in range(256):
            try:
                projected = dict(
                    verifier.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(result)
                )
            except DENIED as failure:
                assert str(failure) == verifier.DENIED_MESSAGE
                assert failure.__cause__ is None
                assert failure.__context__ is None
                outcomes.append("denied")
            else:
                assert projected == original
                for attribute, projection_key, _ in AUTHENTIC_FACT_MUTATIONS:
                    assert getattr(result, attribute) == original[projection_key]
                outcomes.append("original")
        return tuple(outcomes)

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(mutate), executor.submit(mutate), executor.submit(project), executor.submit(project)]
        observed = [outcome for future in futures[2:] for outcome in future.result()]
        for future in futures[:2]:
            future.result()

    assert observed
    assert set(observed) <= {"original", "denied"}


def test_authenticated_snapshot_registry_retains_exact_weak_cleanup_behavior():
    result = verify()
    identity = id(result)
    reference = weakref.ref(result)
    assert identity in verifier._AUTHENTIC_RESULTS

    del result
    gc.collect()

    assert reference() is None
    assert identity not in verifier._AUTHENTIC_RESULTS
    assert all(registration[0]() is not None for registration in verifier._AUTHENTIC_RESULTS.values())


def test_no_caller_verified_accepted_current_or_authority_boolean_exists():
    parameters = inspect.signature(verifier.verify_social_preaccepted_enrollment_verification_statement_v2).parameters
    for name in ("verified", "accepted", "current", "authorized", "admitted"):
        assert name not in parameters
        with pytest.raises(TypeError):
            verify(**{name: True})


def test_no_io_network_database_environment_or_logging_during_configuration_and_verification(monkeypatch, caplog):
    config = configuration()

    def forbidden(*args, **kwargs):
        pytest.fail("unexpected I/O or ambient discovery")

    with monkeypatch.context() as guard:
        guard.setattr(builtins, "open", forbidden)
        guard.setattr(Path, "open", forbidden)
        guard.setattr(socket, "socket", forbidden)
        guard.setattr(socket, "create_connection", forbidden)
        verify(config=config)
        denied(lambda: verify(statement="a.b.c", config=config))
    assert not caplog.records


def test_import_graph_has_no_io_network_database_environment_runtime_or_generic_jwt_decoder():
    path = ROOT / "app/services/social_preaccepted_enrollment_verification_statement_v2.py"
    tree = ast.parse(path.read_text())
    imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    forbidden_imports = {
        "os",
        "socket",
        "pathlib",
        "subprocess",
        "requests",
        "urllib",
        "sqlalchemy",
        "redis",
        "jwt",
        "app.models",
        "app.factory",
        "app.config",
    }
    assert not imports.intersection(forbidden_imports)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            assert ast.unparse(node.func) not in {
                "open",
                "print",
                "eval",
                "exec",
                "jwt.decode",
                "jwt.get_unverified_header",
            }
    module_name = "social_preaccepted_enrollment_verification_statement_v2"
    for filename in ("app/services/__init__.py", "app/app.py", "app/factory.py", "app/config.py"):
        assert module_name not in (ROOT / filename).read_text()
    assert not (ROOT / "app/blueprints/internal_social_preaccepted_enrollment_verification_v2.py").exists()


def test_source_fixture_exact_cross_repository_identity_and_v1_bytes_remain_pinned():
    assert len(SOURCE_FIXTURE_PATH.read_bytes()) == 32_998
    assert hashlib.sha256(SOURCE_FIXTURE_PATH.read_bytes()).hexdigest() == (
        "4f79dd0f24fd8ded4c2e4e3e644811dd42ca620d8c0e09aea177237dd5d199dc"
    )
    assert FIXTURE["sourceFixture"] == {
        "bytes": 32_998,
        "path": "tests/fixtures/social_preacceptance_ed25519_handoff_v2.json",
        "sha256": "4f79dd0f24fd8ded4c2e4e3e644811dd42ca620d8c0e09aea177237dd5d199dc",
        "verificationInputDigest": SOURCE_VECTOR["preacceptedEnrollmentVerificationInputDigest"],
        "verificationInputSha256": hashlib.sha256(
            SOURCE_VECTOR["preacceptedEnrollmentVerificationInputWire"].encode("ascii")
        ).hexdigest(),
    }
    expected = {
        "app/services/social_messaging_device_admission_contract.py": (
            "f77d93d0407f91f2efd434807ca7af63fbfef2c04f8130ad492bb78799b08a8b"
        ),
        "app/services/social_device_verification_statement.py": (
            "af84b086ce79675fa5416ad6cdc20e616791ea897d6118f7cfe27ec900e06cc8"
        ),
        "tests/fixtures/social_device_admission_v1.json": (
            "09722ca9ab230a7bbc73b2228dfed5e80cdd2c2bb44a32e8571bdcf246ca4324"
        ),
    }
    for relative, digest in expected.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == digest
    assert v1_contract.VERIFICATION_STATEMENT_SCHEMA == "hodlxxi.social_device_verification_statement.v1"
    assert v1_contract.STATEMENT_TYPE == "hodlxxi-social-device-verification+jws"
    assert v1_contract.STATEMENT_PURPOSE == "social_device_cryptographic_verification_v1"
    assert v1_contract.CONSUME_PATH == "/internal/v1/social/device-admission/consume"
    assert verifier.STATEMENT_CONSUME_PATH == "/internal/v2/social/device-admission/consume"


def test_fixture_contains_public_material_only_and_all_required_frozen_artifacts():
    assert set(VECTOR) == {
        "compactJws",
        "expectedAuthenticatedProjection",
        "jti",
        "payloadSegment",
        "payloadWire",
        "payloadWithoutJtiWire",
        "protectedHeaderSegment",
        "protectedHeaderWire",
        "signature",
        "signingInput",
    }
    assert set(JWK) == {"kty", "use", "alg", "kid", "n", "e"}
    text = FIXTURE_PATH.read_text()
    for forbidden in ("PRIVATE KEY", "privateKey", "private_key", "seed"):
        assert forbidden not in text

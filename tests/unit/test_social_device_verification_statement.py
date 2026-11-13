from __future__ import annotations

import ast
import base64
import builtins
import hashlib
import inspect
import json
import socket
from dataclasses import FrozenInstanceError, asdict, fields, replace
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.services import social_device_verification_statement as verifier
from app.services import social_messaging_device_admission_contract as contract

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/social_device_admission_v1.json"
PUBLIC = json.loads(FIXTURE.read_bytes())
VECTORS = PUBLIC["vectors"]
CONFIG = PUBLIC["configuration"]
JWK = PUBLIC["publicVerificationMaterial"]["jwk"]
ERROR = "^social device verification statement denied$"
DENIED = verifier.SocialDeviceVerificationStatementDenied


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def configuration(**changes):
    values = dict(
        enabled=True,
        issuer=CONFIG["issuer"],
        audience=CONFIG["audience"],
        client_id=CONFIG["clientId"],
        service_principal=CONFIG["servicePrincipal"],
        trusted_jwks=(dict(JWK),),
    )
    values.update(changes)
    return verifier.SocialDeviceVerificationStatementConfig(**values)


def arguments(name="ciphertextSubmit", **changes):
    value = VECTORS[name]
    args = dict(
        expected_context_wire=value["contextWire"],
        expected_input_wire=value["inputWire"],
        now=value["now"],
        challenge_expires_at=value["challengeExpiresAt"],
        session_expires_at=value["sessionExpiresAt"],
        approver_session_expires_at=value["approverSessionExpiresAt"],
    )
    args.update(changes)
    return args


def verify(name="ciphertextSubmit", **changes):
    statement = changes.pop("statement", VECTORS[name]["compactJws"])
    config = changes.pop("config", configuration())
    return verifier.verify_social_device_verification_statement_v1(
        statement, config=config, **arguments(name, **changes)
    )


def shape(name="ciphertextSubmit", **changes):
    statement = changes.pop("statement", VECTORS[name]["compactJws"])
    config = changes.pop("config", configuration())
    return contract.inspect_verification_statement_shape_v1(
        statement,
        expected_kid=CONFIG["kid"],
        expected_issuer=config.issuer,
        expected_audience=config.audience,
        expected_client_id=config.client_id,
        expected_service_principal=config.service_principal,
        **arguments(name, **changes),
    )


def statement_with(name="ciphertextSubmit", *, header=None, payload=None, signature=None):
    value = VECTORS[name]
    return ".".join(
        (
            b64((header if header is not None else value["protectedHeaderWire"]).encode("ascii")),
            b64((payload if payload is not None else value["payloadWire"]).encode("ascii")),
            b64(signature) if signature is not None else value["compactJws"].split(".")[2],
        )
    )


def denied(call):
    with pytest.raises(DENIED, match=ERROR) as failure:
        call()
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


def shape_and_verifier_deny(name="ciphertextSubmit", **changes):
    # Establish that the binding/canonical guard fails independently of the
    # necessarily invalid signature on a mutated fixed public vector.
    with pytest.raises(contract.SocialMessagingDeviceAdmissionUnavailable):
        shape(name, **changes)
    denied(lambda: verify(name, **changes))


def test_disabled_by_default_and_no_truthy_gate():
    assert verifier.SocialDeviceVerificationStatementConfig().enabled is False
    denied(
        lambda: verifier.verify_social_device_verification_statement_v1(
            VECTORS["ciphertextSubmit"]["compactJws"], **arguments()
        )
    )
    denied(lambda: verify(config=configuration(enabled=False)))
    for enabled in (1, "true", None):
        denied(lambda: configuration(enabled=enabled))


@pytest.mark.parametrize("name", VECTORS)
def test_fixed_public_signatures_exact_bytes_and_typed_authenticated_facts(name):
    value = VECTORS[name]
    header, payload, signature = value["compactJws"].split(".")
    assert header == value["protectedHeaderSegment"] == b64(value["protectedHeaderWire"].encode("ascii"))
    assert payload == value["payloadSegment"] == b64(value["payloadWire"].encode("ascii"))
    public_key = serialization.load_pem_public_key(PUBLIC["publicVerificationMaterial"]["spkiPem"].encode("ascii"))
    public_key.verify(unb64(signature), (header + "." + payload).encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    assert configuration()._keys[0].public_key.public_numbers() == public_key.public_numbers()
    with patch.object(
        contract, "inspect_verification_statement_shape_v1", wraps=contract.inspect_verification_statement_shape_v1
    ) as called:
        result = verify(name)
    called.assert_called_once()
    assert called.call_args.args == (value["compactJws"],)
    assert called.call_args.kwargs["expected_context_wire"] == value["contextWire"]
    assert called.call_args.kwargs["expected_input_wire"] == value["inputWire"]
    inspected = shape(name)
    assert inspected.signing_input == (header + "." + payload).encode("ascii")
    assert inspected.signature == unb64(signature)
    assert inspected.rsa_signature_verification == "not_evaluated"
    assert type(result) is verifier.AuthenticatedSocialDeviceVerificationStatementV1
    assert asdict(result) == {
        **asdict(inspected.claims),
        "purpose": contract.STATEMENT_PURPOSE,
        "key_id": CONFIG["kid"],
        "key_fingerprint": PUBLIC["publicVerificationMaterial"]["spkiSha256"],
    }
    with pytest.raises(FrozenInstanceError):
        result.expires_at += 1
    denied(lambda: replace(result, expires_at=result.expires_at + 1))
    assert not hasattr(result, "__dict__")
    assert "compactJws" not in repr(result)


@pytest.mark.parametrize("reverse", (False, True))
def test_exact_kid_selection_with_multiple_registered_public_keys(reverse):
    # An alternative public exponent requires no private key generation.
    other = {**JWK, "kid": "other-public-key", "e": "Aw"}
    keys = (other, JWK) if reverse else (JWK, other)
    assert verify(config=configuration(trusted_jwks=keys)).key_id == CONFIG["kid"]


def test_no_key_fallback_for_unknown_or_wrong_selected_kid():
    denied(lambda: verify(config=configuration(trusted_jwks=({**JWK, "kid": "unknown"},))))
    wrong = {**JWK, "e": "Aw"}
    denied(lambda: verify(config=configuration(trusted_jwks=(wrong,))))
    # A matching key elsewhere cannot rescue a wrong key under the selected kid.
    denied(lambda: verify(config=configuration(trusted_jwks=(wrong, {**JWK, "kid": "alias"}))))
    header = {**json.loads(VECTORS["ciphertextSubmit"]["protectedHeaderWire"]), "kid": "unknown"}
    denied(lambda: verify(statement=statement_with(header=canonical(header))))


@pytest.mark.parametrize("duplicate", (dict(JWK), {**JWK, "e": "Aw"}))
def test_duplicate_kid_registration_is_rejected(duplicate):
    denied(lambda: configuration(trusted_jwks=(JWK, duplicate)))


@pytest.mark.parametrize("parameter", ("d", "p", "q", "dp", "dq", "qi", "oth", "k"))
@pytest.mark.parametrize("value", (None, "forbidden"))
@pytest.mark.parametrize("enabled", (False, True))
def test_every_private_parameter_is_rejected_even_if_empty_or_disabled(parameter, value, enabled):
    denied(lambda: configuration(enabled=enabled, trusted_jwks=({**JWK, parameter: value},)))


@pytest.mark.parametrize(
    "changes",
    (
        {"kty": "oct", "k": "c3ludGhldGlj"},
        {"kty": "EC"},
        {"kty": "OKP"},
        {"use": "enc"},
        {"alg": "PS256"},
        {"alg": "HS256"},
        {"kid": ""},
        {"kid": " padded"},
        {"kid": True},
        {"kid": "x" * 256},
        {"n": ""},
        {"n": None},
        {"n": "!!"},
        {"n": "AQ"},
        {"n": "AA"},
        {"n": "A" * 1367},
        {"n": JWK["n"] + "="},
        {"n": b64(b"\0" + unb64(JWK["n"]))},
        {"n": b64((int.from_bytes(unb64(JWK["n"]), "big") - 1).to_bytes(256, "big"))},
        {"e": "AA"},
        {"e": "AQ"},
        {"e": "Ag"},
        {"e": ""},
        {"e": True},
        {"e": "AQAB="},
        {"e": "AAEAAQ"},
        {"e": "A" * 17},
        {"jwk": {}},
        {"jku": "https://keys.example"},
        {"x5u": "https://keys.example"},
        {"key_ops": ["sign"]},
        {"pem": "not-a-key"},
    ),
)
def test_malformed_nonpublic_or_noncanonical_jwk_fails_closed(changes):
    denied(lambda: configuration(trusted_jwks=({**JWK, **changes},)))


@pytest.mark.parametrize("missing", JWK)
def test_all_public_jwk_fields_required(missing):
    value = dict(JWK)
    del value[missing]
    denied(lambda: configuration(trusted_jwks=(value,)))


@pytest.mark.parametrize("keys", ((), [], (True,), ("not-a-jwk",), ({},)))
def test_invalid_or_empty_registration(keys):
    denied(lambda: configuration(trusted_jwks=keys))


@pytest.mark.parametrize(
    "changes",
    (
        {"issuer": ""},
        {"issuer": "https://social.example/"},
        {"audience": CONFIG["issuer"]},
        {"audience": "https://ubid.example/other"},
        {"client_id": ""},
        {"service_principal": ""},
        {"purpose": "social_full_directory_read"},
        {"purpose": ""},
        {"purpose": True},
        {"issuer": True},
    ),
)
def test_invalid_trust_identity_or_purpose(changes):
    denied(lambda: configuration(**changes))


def test_trust_is_copied_frozen_public_only_and_cannot_accept_injected_verification():
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
    with pytest.raises(TypeError):
        configuration(_keys=(lambda: True,))
    denied(lambda: verify(config=True))
    denied(lambda: verify(config={"enabled": True}))


@pytest.mark.parametrize("kind", ("corrupt", "empty", "truncated", "overlong"))
def test_invalid_signature_bytes(kind):
    signature = unb64(VECTORS["ciphertextSubmit"]["compactJws"].split(".")[2])
    changed = {
        "corrupt": bytes([signature[0] ^ 1]) + signature[1:],
        "empty": b"",
        "truncated": signature[:-1],
        "overlong": signature + b"\0",
    }[kind]
    statement = statement_with(signature=changed)
    if changed:
        assert shape(statement=statement).rsa_signature_verification == "not_evaluated"
    denied(lambda: verify(statement=statement))


def test_canonical_bit_flipped_signing_input_passes_shape_but_not_authentication():
    payload = VECTORS["ciphertextSubmit"]["payloadWire"]
    token_id = json.loads(payload)["jti"]
    first = token_id[0]
    alternate = next(char for char in "0123456789abcdef" if (ord(first) ^ ord(char)).bit_count() == 1)
    changed = payload.replace('"jti":"' + first, '"jti":"' + alternate, 1)
    assert sum((a ^ b).bit_count() for a, b in zip(payload.encode(), changed.encode())) == 1
    statement = statement_with(payload=changed)
    shape(statement=statement)
    denied(lambda: verify(statement=statement))


@pytest.mark.parametrize(
    "changes",
    (
        {"alg": "none"},
        {"alg": "HS256"},
        {"alg": "PS256"},
        {"alg": "RS384"},
        {"alg": "RS512"},
        {"typ": "JWT"},
        {"typ": contract.STATEMENT_TYPE.upper()},
        {"jwk": JWK},
        {"jku": "https://keys.example"},
        {"x5u": "https://keys.example"},
        {"crit": []},
        {"kid": ""},
        {"kid": True},
    ),
)
def test_header_algorithm_type_and_closed_vocabulary(changes):
    header = {**json.loads(VECTORS["ciphertextSubmit"]["protectedHeaderWire"]), **changes}
    shape_and_verifier_deny(statement=statement_with(header=canonical(header)))


@pytest.mark.parametrize(
    "field,value",
    (
        ("iss", "https://other.example"),
        ("aud", "https://other.example" + contract.CONSUME_PATH),
        ("aud", [CONFIG["audience"]]),
        ("clientId", "other-client"),
        ("servicePrincipal", "other-principal"),
        ("purpose", "social_full_directory_read"),
        ("challengeKind", "enrollment-v2"),
        ("result", contract.ENROLLMENT_V2_RESULT),
        ("challengeId", "aa" * 32),
        ("attemptId", "bb" * 32),
        ("contextDigest", contract.CONTEXT_DIGEST_PREFIX + "cc" * 32),
        ("inputDigest", contract.INPUT_DIGEST_PREFIX + "dd" * 32),
        ("version", True),
        ("schema", "other"),
        ("jti", ""),
        ("issuedAt", True),
        ("expiresAt", 2**53),
    ),
)
def test_exact_statement_claims_and_bindings(field, value):
    payload = {**json.loads(VECTORS["ciphertextSubmit"]["payloadWire"]), field: value}
    shape_and_verifier_deny(statement=statement_with(payload=canonical(payload)))


def test_coherently_changed_challenge_kind_and_result_still_rejects_context_mismatch():
    payload = {
        **json.loads(VECTORS["ciphertextSubmit"]["payloadWire"]),
        "challengeKind": "enrollment-v2",
        "result": contract.ENROLLMENT_V2_RESULT,
    }
    shape_and_verifier_deny(statement=statement_with(payload=canonical(payload)))


@pytest.mark.parametrize("name", VECTORS)
def test_exact_challenge_kind_result_relationship(name):
    payload = json.loads(VECTORS[name]["payloadWire"])
    payload["result"] = contract.STRICT_ED25519_RESULT if name == "enrollmentV2" else contract.ENROLLMENT_V2_RESULT
    shape_and_verifier_deny(name, statement=statement_with(name, payload=canonical(payload)))


@pytest.mark.parametrize("segment", ("protectedHeaderWire", "payloadWire"))
def test_each_header_and_payload_field_is_required(segment):
    original = json.loads(VECTORS["ciphertextSubmit"][segment])
    for missing in original:
        changed = dict(original)
        del changed[missing]
        kwargs = {"header" if segment == "protectedHeaderWire" else "payload": canonical(changed)}
        shape_and_verifier_deny(statement=statement_with(**kwargs))


@pytest.mark.parametrize(
    "field,value",
    (
        ("issuer", "https://other.example"),
        ("audience", "https://other.example" + contract.CONSUME_PATH),
        ("client_id", "other-client"),
        ("service_principal", "other-principal"),
    ),
)
def test_valid_signature_does_not_override_expected_trust_identity(field, value):
    shape_and_verifier_deny(config=configuration(**{field: value}))


def test_coherent_alternate_context_audience_is_not_the_trusted_issuer():
    value = VECTORS["ciphertextSubmit"]
    context = canonical({**json.loads(value["contextWire"]), "audience": "https://other.example"})
    request = canonical({**json.loads(value["actualRequestWire"]), "audience": "https://other.example"})
    challenge = canonical({**json.loads(value["challengeWire"]), "request": request})
    input_wire = canonical(
        {**json.loads(value["inputWire"]), "context": context, "actualRequest": request, "challenge": challenge}
    )
    contract.parse_verification_input_v1(input_wire)
    payload = canonical(
        {
            **json.loads(value["payloadWire"]),
            "contextDigest": contract.verification_context_digest_v1(context),
            "inputDigest": contract.verification_input_digest_v1(input_wire),
        }
    )
    shape_and_verifier_deny(
        statement=statement_with(payload=payload), expected_context_wire=context, expected_input_wire=input_wire
    )


@pytest.mark.parametrize("field,value", (("challengeId", "ee" * 32), ("attemptId", "ff" * 32)))
def test_expected_context_substitution(field, value):
    context = canonical({**json.loads(VECTORS["ciphertextSubmit"]["contextWire"]), field: value})
    shape_and_verifier_deny(expected_context_wire=context)


@pytest.mark.parametrize("name", VECTORS)
def test_issued_at_and_exclusive_expiry_boundaries_have_zero_skew(name):
    payload = json.loads(VECTORS[name]["payloadWire"])
    for now in (payload["issuedAt"], payload["expiresAt"] - 1):
        assert verify(name, now=now).issued_at == payload["issuedAt"]
    for now in (payload["issuedAt"] - 1, payload["expiresAt"], payload["expiresAt"] + 1):
        shape_and_verifier_deny(name, now=now)


@pytest.mark.parametrize("name", VECTORS)
@pytest.mark.parametrize("deadline", ("challenge_expires_at", "session_expires_at", "approver_session_expires_at"))
def test_statement_cannot_outlive_challenge_or_relevant_session(name, deadline):
    if deadline == "approver_session_expires_at" and name != "enrollmentV2":
        shape_and_verifier_deny(name, **{deadline: VECTORS[name]["sessionExpiresAt"]})
        return
    expires = json.loads(VECTORS[name]["payloadWire"])["expiresAt"]
    assert verify(name, **{deadline: expires}).expires_at == expires
    for value in (expires - 1, VECTORS[name]["now"], 0, True, "later"):
        shape_and_verifier_deny(name, **{deadline: value})


def test_enrollment_requires_approver_deadline_requests_require_none():
    shape_and_verifier_deny("enrollmentV2", approver_session_expires_at=None)
    assert verify("recipientSelfRead", approver_session_expires_at=None)
    assert verify("ciphertextSubmit", approver_session_expires_at=None)


@pytest.mark.parametrize("lifetime", (0, -1, 10001))
def test_statement_lifetime_is_positive_and_bounded(lifetime):
    payload = json.loads(VECTORS["ciphertextSubmit"]["payloadWire"])
    payload["expiresAt"] = payload["issuedAt"] + lifetime
    shape_and_verifier_deny(statement=statement_with(payload=canonical(payload)))


@pytest.mark.parametrize(
    "field,value",
    (("issuedAt", VECTORS["ciphertextSubmit"]["now"] + 1), ("expiresAt", VECTORS["ciphertextSubmit"]["now"] + 1)),
)
def test_embedded_challenge_deadline_cannot_be_bypassed_by_later_injected_deadline(field, value):
    original = VECTORS["ciphertextSubmit"]
    challenge = canonical({**json.loads(original["challengeWire"]), field: value})
    input_wire = canonical({**json.loads(original["inputWire"]), "challenge": challenge})
    payload = canonical(
        {**json.loads(original["payloadWire"]), "inputDigest": contract.verification_input_digest_v1(input_wire)}
    )
    statement = statement_with(payload=payload)
    # PR 1 accepts the injected deadline; the verifier additionally checks the
    # exact challenge's interval before even trying the RSA signature.
    shape(statement=statement, expected_input_wire=input_wire)
    real_key = configuration()._keys[0].public_key
    observed_key = Mock(spec=rsa.RSAPublicKey, wraps=real_key)
    observed_key.key_size = real_key.key_size
    with patch.object(verifier.RSAAlgorithm, "from_jwk", return_value=observed_key):
        config = configuration()
        denied(lambda: verify(statement=statement, expected_input_wire=input_wire, config=config))
    observed_key.verify.assert_not_called()


@pytest.mark.parametrize("segment", (0, 1, 2))
def test_padded_or_noncanonical_base64url_is_rejected(segment):
    parts = VECTORS["ciphertextSubmit"]["compactJws"].split(".")
    parts[segment] += "="
    shape_and_verifier_deny(statement=".".join(parts))
    parts = VECTORS["ciphertextSubmit"]["compactJws"].split(".")
    parts[segment] = "+" + parts[segment][1:]
    shape_and_verifier_deny(statement=".".join(parts))


def test_nonzero_unused_base64url_bits_rejected():
    parts = VECTORS["ciphertextSubmit"]["compactJws"].split(".")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    original = parts[2]
    parts[2] = original[:-1] + alphabet[alphabet.index(original[-1]) + 1]
    assert unb64(parts[2]) == unb64(original)
    shape_and_verifier_deny(statement=".".join(parts))


@pytest.mark.parametrize("segment", ("header", "payload"))
@pytest.mark.parametrize("mutation", ("duplicate", "spaces", "newline", "order", "escape", "unknown"))
def test_duplicate_or_noncanonical_json_is_rejected(segment, mutation):
    original = VECTORS["ciphertextSubmit"]["protectedHeaderWire" if segment == "header" else "payloadWire"]
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
    shape_and_verifier_deny(statement=statement_with(**{segment: options[mutation]}))


@pytest.mark.parametrize("argument", ("expected_context_wire", "expected_input_wire"))
def test_context_and_input_must_be_exact_canonical_wires(argument):
    original = arguments()[argument]
    for value in (original + "\n", original.replace('"version":1', '"version":1.0'), json.loads(original), True, None):
        shape_and_verifier_deny(**{argument: value})


@pytest.mark.parametrize(
    "statement", (None, True, {}, b"a.b.c", "", "a.b", "a.b.c.d", "a..c", "a.b.c", "x" * 4097, "\u00e9.b.c")
)
def test_malformed_statement_has_one_non_sensitive_failure(statement):
    denied(lambda: verify(statement=statement))


def test_shape_or_boolean_cannot_construct_authenticated_result_or_skip_crypto():
    inspected = shape()
    for arguments_ in ((), (True,), (inspected,), (inspected.claims,)):
        denied(lambda: verifier.AuthenticatedSocialDeviceVerificationStatementV1(*arguments_))
    for name in ("verified", "admitted", "authorized"):
        denied(lambda: verifier.AuthenticatedSocialDeviceVerificationStatementV1(**{name: True}))
        with pytest.raises(TypeError):
            verify(**{name: True})
    denied(lambda: verify(statement=inspected))
    denied(lambda: verify(statement=True))
    denied(lambda: type("Forged", (verifier.AuthenticatedSocialDeviceVerificationStatementV1,), {}))
    assert "verifier" not in inspect.signature(verifier.verify_social_device_verification_statement_v1).parameters


def test_result_has_only_authenticated_facts_and_no_effect_capability_or_replay_state():
    result = verify()
    assert {field.name for field in fields(result)} == {
        "issuer",
        "audience",
        "client_id",
        "service_principal",
        "purpose",
        "result",
        "challenge_kind",
        "challenge_id",
        "attempt_id",
        "context_digest",
        "input_digest",
        "issued_at",
        "expires_at",
        "token_id",
        "key_id",
        "key_fingerprint",
    }
    assert all(not callable(getattr(result, name)) for name in dir(result) if not name.startswith("_"))
    assert result == verify()  # Reverification is not consumption or replay acceptance.
    assert verifier.FINAL_ADMISSION == "denied"
    assert verifier.CHALLENGE_CONSUMPTION == "not_implemented"
    assert verifier.CURRENT_AUTHORITY == "not_evaluated"
    assert verifier.RUNTIME_ENABLED is False


def test_no_io_during_configuration_or_verification_and_no_logs(monkeypatch, caplog):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected I/O")

    # Load backend lazily once; measure this pure boundary, not Python's loader.
    configuration()
    with monkeypatch.context() as guard:
        guard.setattr(builtins, "open", forbidden)
        guard.setattr(Path, "open", forbidden)
        guard.setattr(socket, "socket", forbidden)
        guard.setattr(socket, "create_connection", forbidden)
        for name in VECTORS:
            verify(name)
        denied(lambda: verify(statement="a.b.c"))
        denied(lambda: configuration(trusted_jwks=({**JWK, "d": "forbidden"},)))
    assert not caplog.records


def test_import_graph_has_no_io_database_redis_route_factory_or_generic_token_decoder():
    path = ROOT / "app/services/social_device_verification_statement.py"
    tree = ast.parse(path.read_text())
    imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    assert imports == {
        "__future__",
        "hashlib",
        "json",
        "dataclasses",
        "types",
        "typing",
        "app.services",
        "cryptography.hazmat.primitives",
        "cryptography.hazmat.primitives.asymmetric",
        "jwt.algorithms",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "app.services":
            assert [alias.name for alias in node.names] == ["social_messaging_device_admission_contract"]
        if isinstance(node, ast.Call):
            assert ast.unparse(node.func) not in {
                "open",
                "print",
                "eval",
                "exec",
                "jwt.decode",
                "jwt.get_unverified_header",
            }
    for filename in ("app/factory.py", "app/config.py"):
        assert "social_device_verification_statement" not in (ROOT / filename).read_text()
    assert not (ROOT / "app/blueprints/internal_social_device_admission.py").exists()


def test_all_public_fixture_hashes_remain_pinned():
    expected = {
        "social_device_admission_v1.json": "09722ca9ab230a7bbc73b2228dfed5e80cdd2c2bb44a32e8571bdcf246ca4324",
        "social_messaging_device_proof_profile_v1.json": "f616cee3db22d906d309953ae74b5626109a643884edd27b00fba68325508477",
        "social_mobile_device_authorization_v1.json": "26f335b718a771d08aacc7ebbe63895d395e2e2376d12484fb19ab30c0db7356",
        "social_mobile_authorization_ingress_v1.json": "d8f40ccc552c18c1beadb5ddb9d6a12b4b42c48dbe1eaf82c96f97233eca2e7d",
        "social_session_issuance_v1.json": "474bdfa4d3c300da0e78e5cde9a2b8dd263ee1e68227bb3a5000687d2ce230f3",
        "social_messaging_phase3_routing_v1.json": "90f7c3726a9dfcfa655630626d53d65b410e5e330456d5114d04982a53da2f1c",
    }
    for filename, digest in expected.items():
        assert hashlib.sha256((FIXTURE.parent / filename).read_bytes()).hexdigest() == digest
    assert set(JWK) == {"kty", "use", "alg", "kid", "n", "e"}
    assert "PRIVATE KEY-----" not in FIXTURE.read_text()

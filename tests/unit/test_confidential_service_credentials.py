from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    CredentialDenied,
    CredentialUnavailable,
    MAX_CLOCK_SKEW_SECONDS,
    VerifiedServiceCredential,
    issue_service_access_token,
    validate_client_assertion,
    verify_service_access_token,
)

NOW = 2_000_000_000
CLIENT = "social-confidential-backend"
PRINCIPAL = "service:social-full-directory"
ISSUER = "https://identity.example"
ENDPOINT = "https://identity.example/oauth/service-token"
RESOURCE = "https://social.example/full-directory"


@pytest.fixture(scope="module")
def material():
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def public_jwk(key, kid):
        value = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
        value.update({"kid": kid, "use": "sig", "alg": "RS256"})
        return value

    return client_key, service_key, public_jwk(client_key, "client-key"), public_jwk(service_key, "service-key")


@pytest.fixture
def configured(material):
    return ConfidentialServiceConfig(
        enabled=True,
        client_id=CLIENT,
        service_principal=PRINCIPAL,
        issuer=ISSUER,
        token_endpoint_audience=ENDPOINT,
        service_resource_audience=RESOURCE,
        client_jwks=(material[2],),
        service_jwks=(material[3],),
    )


def assertion(material, **changes):
    claims = {
        "iss": CLIENT,
        "sub": CLIENT,
        "aud": ENDPOINT,
        "iat": NOW,
        "exp": NOW + 60,
        "jti": "assertion-1",
        "token_use": "client_assertion",
        "grant_type": "client_credentials",
        "purpose": "service_client_authentication",
    }
    headers = {"kid": "client-key"}
    claims.update(changes.pop("claims", {}))
    headers.update(changes.pop("headers", {}))
    return jwt.encode(
        claims, changes.pop("key", material[0]), algorithm=changes.pop("algorithm", "RS256"), headers=headers
    )


def service_token(material, **changes):
    claims = {
        "iss": ISSUER,
        "aud": RESOURCE,
        "sub": PRINCIPAL,
        "azp": CLIENT,
        "scope": "social:full-directory:read",
        "grant_type": "client_credentials",
        "token_use": "service_access",
        "purpose": "social_full_directory_read",
        "iat": NOW,
        "exp": NOW + 60,
        "jti": "service-token-1",
    }
    headers = {"kid": "service-key"}
    claims.update(changes.pop("claims", {}))
    headers.update(changes.pop("headers", {}))
    return jwt.encode(
        claims, changes.pop("key", material[1]), algorithm=changes.pop("algorithm", "RS256"), headers=headers
    )


def base64url_uint_with_leading_zero(value):
    assert isinstance(value, str)
    return jwt.utils.base64url_encode(b"\x00" + jwt.utils.base64url_decode(value.encode())).decode()


def test_disabled_by_default(material):
    with pytest.raises(CredentialDenied, match="^credential denied$"):
        validate_client_assertion(assertion(material), config=ConfidentialServiceConfig(), now=NOW)


def test_distinct_client_and_service_keys_remain_valid_and_issue_once_with_default_skew_deadline(material, configured):
    assert (material[2]["n"], material[2]["e"]) != (material[3]["n"], material[3]["e"])
    calls = []
    encoded = issue_service_access_token(
        assertion(material),
        config=configured,
        replay_consumer=lambda jti, deadline: calls.append((jti, deadline)) is None,
        signing_key=material[1],
        signing_kid="service-key",
        now=NOW,
        token_jti="service-token-1",
    )
    evidence = verify_service_access_token(encoded, config=configured, now=NOW + 1)
    assert calls == [("assertion-1", NOW + 66)]
    assert evidence == VerifiedServiceCredential(
        PRINCIPAL, CLIENT, "social:full-directory:read", NOW, NOW + 60, "service-token-1"
    )
    with pytest.raises(FrozenInstanceError):
        evidence.scope = "other"


@pytest.mark.parametrize("clock_skew_seconds", [0, MAX_CLOCK_SKEW_SECONDS])
def test_replay_deadline_uses_protocol_maximum_for_allowed_skew_settings(material, configured, clock_skew_seconds):
    skew_config = replace(configured, clock_skew_seconds=clock_skew_seconds)
    calls = []

    issue_service_access_token(
        assertion(material),
        config=skew_config,
        replay_consumer=lambda jti, deadline: calls.append((jti, deadline)) is None,
        signing_key=material[1],
        signing_kid="service-key",
        now=NOW,
        token_jti=f"service-token-{clock_skew_seconds}",
    )

    assert calls == [("assertion-1", NOW + 60 + MAX_CLOCK_SKEW_SECONDS + 1)]


def test_zero_skew_assertion_still_expires_without_local_grace(material, configured):
    zero_skew = replace(configured, clock_skew_seconds=0)

    with pytest.raises(CredentialDenied, match="^credential denied$"):
        validate_client_assertion(assertion(material), config=zero_skew, now=NOW + 61)


def test_assertion_accepts_final_default_skew_second_without_changing_public_result(material, configured):
    assert validate_client_assertion(assertion(material), config=configured, now=NOW + 65) == (
        "assertion-1",
        NOW + 60,
    )
    with pytest.raises(CredentialDenied, match="^credential denied$"):
        validate_client_assertion(assertion(material), config=configured, now=NOW + 66)


def test_replay_marker_rejects_reuse_through_complete_maximum_acceptance_window(material, configured):
    max_skew_config = replace(configured, clock_skew_seconds=MAX_CLOCK_SKEW_SECONDS)
    encoded = assertion(material)
    first_accepted = NOW - MAX_CLOCK_SKEW_SECONDS
    last_accepted = NOW + 60 + MAX_CLOCK_SKEW_SECONDS
    retention_deadline = last_accepted + 1
    clock = {"now": first_accepted}
    markers = {}

    def consume_once(jti, retention_deadline):
        for consumed_jti, deadline in tuple(markers.items()):
            if deadline <= clock["now"]:
                del markers[consumed_jti]
        if jti in markers:
            return False
        markers[jti] = retention_deadline
        return True

    issue_service_access_token(
        encoded,
        config=max_skew_config,
        replay_consumer=consume_once,
        signing_key=material[1],
        signing_kid="service-key",
        now=first_accepted,
        token_jti="service-token-1",
    )

    for accepted_now in range(first_accepted, retention_deadline):
        clock["now"] = accepted_now
        with pytest.raises(CredentialUnavailable, match="^credential service unavailable$"):
            issue_service_access_token(
                encoded,
                config=max_skew_config,
                replay_consumer=consume_once,
                signing_key=material[1],
                signing_kid="service-key",
                now=accepted_now,
                token_jti=f"service-token-{accepted_now}",
            )

    assert markers == {"assertion-1": retention_deadline}


@pytest.mark.parametrize("consumer", [None, lambda _jti, _deadline: False, lambda _jti, _deadline: None])
def test_issuance_fails_closed_without_atomic_consume(material, configured, consumer):
    with pytest.raises(CredentialUnavailable, match="^credential service unavailable$"):
        issue_service_access_token(
            assertion(material),
            config=configured,
            replay_consumer=consumer,
            signing_key=material[1],
            signing_kid="service-key",
            now=NOW,
        )


def test_issuance_fails_closed_when_replay_store_raises(material, configured):
    def unavailable(_jti, _deadline):
        raise OSError("internal detail")

    with pytest.raises(CredentialUnavailable, match="^credential service unavailable$"):
        issue_service_access_token(
            assertion(material),
            config=configured,
            replay_consumer=unavailable,
            signing_key=material[1],
            signing_kid="service-key",
            now=NOW,
        )


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": CLIENT.upper()},
        {"sub": CLIENT + "-other"},
        {"aud": [ENDPOINT]},
        {"aud": ENDPOINT + "/extra"},
        {"jti": ""},
        {"iat": NOW + 6},
        {"iat": NOW - 66},
        {"exp": NOW - 6},
        {"exp": NOW + 61},
        {"token_use": "access"},
        {"grant_type": "authorization_code"},
        {"purpose": "service_client_authentication_extra"},
        {"purpose": "*"},
    ],
)
def test_assertion_rejects_nonexact_and_invalid_claims(material, configured, claims):
    with pytest.raises(CredentialDenied, match="^credential denied$"):
        validate_client_assertion(assertion(material, claims=claims), config=configured, now=NOW)


@pytest.mark.parametrize("name", ["iss", "sub", "aud", "iat", "exp", "jti", "token_use", "grant_type", "purpose"])
def test_assertion_rejects_missing_claims(material, configured, name):
    encoded = assertion(material)
    claims = jwt.decode(encoded, options={"verify_signature": False})
    claims.pop(name)
    encoded = jwt.encode(claims, material[0], algorithm="RS256", headers={"kid": "client-key"})
    with pytest.raises(CredentialDenied):
        validate_client_assertion(encoded, config=configured, now=NOW)


def test_rejects_unknown_and_ambiguous_key_selection(material, configured):
    with pytest.raises(CredentialDenied):
        validate_client_assertion(assertion(material, headers={"kid": "unknown"}), config=configured, now=NOW)
    duplicate = replace(configured, client_jwks=(material[2], dict(material[2])))
    with pytest.raises(CredentialDenied):
        validate_client_assertion(assertion(material), config=duplicate, now=NOW)


def test_rejects_identical_client_and_service_jwk(material, configured):
    overlapping = replace(configured, service_jwks=(material[2],))

    with pytest.raises(CredentialDenied, match="^credential denied$"):
        validate_client_assertion(assertion(material), config=overlapping, now=NOW)


def test_rejects_client_and_service_jwk_with_same_rsa_numbers_and_different_kid(material, configured):
    overlapping_service_key = dict(material[2], kid="service-key-alias")
    overlapping = replace(configured, service_jwks=(overlapping_service_key,))

    with pytest.raises(CredentialDenied, match="^credential denied$"):
        validate_client_assertion(assertion(material), config=overlapping, now=NOW)


def test_rejects_client_and_service_jwk_with_equivalent_rsa_integer_encoding(material, configured):
    overlapping_service_key = dict(
        material[2],
        kid="service-key-alias",
        n=base64url_uint_with_leading_zero(material[2]["n"]),
        e=base64url_uint_with_leading_zero(material[2]["e"]),
    )
    assert overlapping_service_key["n"] != material[2]["n"]
    assert overlapping_service_key["e"] != material[2]["e"]
    overlapping = replace(configured, service_jwks=(overlapping_service_key,))

    with pytest.raises(CredentialDenied, match="^credential denied$"):
        validate_client_assertion(assertion(material), config=overlapping, now=NOW)


def test_invalid_overlapping_configuration_grants_no_issuance_or_verification_authority(material, configured):
    overlapping = replace(configured, service_jwks=(material[2],))
    replay_calls = []

    with pytest.raises(CredentialDenied, match="^credential denied$"):
        issue_service_access_token(
            assertion(material),
            config=overlapping,
            replay_consumer=lambda jti, deadline: replay_calls.append((jti, deadline)) is None,
            signing_key=material[1],
            signing_kid="service-key",
            now=NOW,
            token_jti="service-token-1",
        )
    assert replay_calls == []

    client_signed_service_token = service_token(material, key=material[0], headers={"kid": "client-key"})
    with pytest.raises(CredentialDenied, match="^credential denied$"):
        verify_service_access_token(client_signed_service_token, config=overlapping, now=NOW)


def test_rejects_algorithm_confusion_and_invalid_signature(material, configured):
    encoded = assertion(material)
    header, payload, signature = encoded.split(".")
    assert validate_client_assertion(encoded, config=configured, now=NOW) == (
        "assertion-1",
        NOW + 60,
    )

    decoded_header = jwt.api_jws.get_unverified_header(encoded)
    decoded_header["alg"] = "HS256"
    altered_header = jwt.utils.base64url_encode(json.dumps(decoded_header).encode()).decode()
    with pytest.raises(CredentialDenied, match="^credential denied$"):
        validate_client_assertion(".".join((altered_header, payload, signature)), config=configured, now=NOW)

    signature_bytes = jwt.utils.base64url_decode(signature.encode())
    altered_signature_bytes = bytearray(signature_bytes)
    altered_signature_bytes[0] ^= 0x01
    assert bytes(altered_signature_bytes) != signature_bytes
    altered_signature = jwt.utils.base64url_encode(bytes(altered_signature_bytes)).decode()
    invalid_signature = ".".join((header, payload, altered_signature))
    with pytest.raises(CredentialDenied, match="^credential denied$"):
        validate_client_assertion(invalid_signature, config=configured, now=NOW)


def test_configuration_copies_keys_and_caps_credential_size(material, configured):
    caller_key = dict(material[2])
    copied = replace(configured, client_jwks=(caller_key,))
    caller_key["kid"] = "mutated"
    validate_client_assertion(assertion(material), config=copied, now=NOW)
    with pytest.raises(CredentialDenied):
        validate_client_assertion(
            assertion(material),
            config=replace(configured, max_credential_length=16 * 1024 + 1),
            now=NOW,
        )


def test_public_errors_suppress_internal_exception_chains(material, configured):
    with pytest.raises(CredentialDenied) as denied:
        validate_client_assertion("a.b.c", config=configured, now=NOW)
    assert denied.value.__cause__ is None
    assert denied.value.__context__ is None

    def unavailable(_jti, _deadline):
        raise OSError("internal")

    with pytest.raises(CredentialUnavailable) as unavailable_error:
        issue_service_access_token(
            assertion(material),
            config=configured,
            replay_consumer=unavailable,
            signing_key=material[1],
            signing_kid="service-key",
            now=NOW,
        )
    assert unavailable_error.value.__cause__ is None
    assert unavailable_error.value.__context__ is None


@pytest.mark.parametrize("token", ["", "opaque", "a..c", "x" * (16 * 1024 + 1)])
def test_rejects_malformed_or_overlong_credentials(configured, token):
    with pytest.raises(CredentialDenied):
        verify_service_access_token(token, config=configured, now=NOW)


@pytest.mark.parametrize(
    "name,value",
    [
        ("iss", ISSUER.upper()),
        ("aud", [RESOURCE]),
        ("sub", PRINCIPAL + "x"),
        ("azp", CLIENT.upper()),
        ("scope", "social:full-directory:read extra"),
        ("grant_type", "authorization_code"),
        ("token_use", "access"),
        ("purpose", "social_full_directory"),
        ("exp", NOW + 61),
        ("iat", NOW + 6),
    ],
)
def test_service_token_rejects_nonexact_contract(material, configured, name, value):
    claims = {
        "iss": ISSUER,
        "aud": RESOURCE,
        "sub": PRINCIPAL,
        "azp": CLIENT,
        "scope": "social:full-directory:read",
        "grant_type": "client_credentials",
        "token_use": "service_access",
        "purpose": "social_full_directory_read",
        "iat": NOW,
        "exp": NOW + 60,
        "jti": "service-token-1",
    }
    claims[name] = value
    encoded = jwt.encode(claims, material[1], algorithm="RS256", headers={"kid": "service-key"})
    with pytest.raises(CredentialDenied):
        verify_service_access_token(encoded, config=configured, now=NOW)


def test_human_access_token_cannot_validate_as_service(material, configured):
    human = jwt.encode(
        {
            "iss": ISSUER,
            "aud": CLIENT,
            "sub": "a" * 64,
            "iat": NOW,
            "exp": NOW + 60,
            "jti": "human",
            "scope": "self:read",
            "token_use": "access",
            "token_contract": "hodlxxi.oauth.access-token.v1",
        },
        material[1],
        algorithm="RS256",
        headers={"kid": "service-key"},
    )
    with pytest.raises(CredentialDenied):
        verify_service_access_token(human, config=configured, now=NOW)

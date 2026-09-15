"""Real RS256 signing without serializing synthetic infrastructure private keys."""

import base64
import json

import jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app import tokens
from app.services import oauth_session_lifecycle, social_session_issuance

NOW = 1700000000
SUBJECT = "a" * 64
KID = "synthetic-key-object"
CONFIG = {
    "JWT_ISSUER": "https://identity.example",
    "JWT_AUDIENCE": "synthetic-viewer-client",
    "TOKEN_TTL": 300,
    "JWKS_DIR": "/synthetic/not-read",
}


class NonExportableTestKey(rsa.RSAPrivateKey):
    """Delegate real signing while making every private export a test failure."""

    def __init__(self, key):
        self._key = key

    @property
    def key_size(self):
        return self._key.key_size

    def public_key(self):
        return self._key.public_key()

    def sign(self, data, chosen_padding, algorithm):
        return self._key.sign(data, chosen_padding, algorithm)

    def private_bytes(self, *args, **kwargs):
        pytest.fail("private-key serialization attempted")

    def private_numbers(self):
        pytest.fail("private-key export attempted")

    def decrypt(self, *args, **kwargs):
        pytest.fail("unexpected private-key operation")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


@pytest.fixture(scope="module")
def signing_key():
    # Fixed, deliberately public test factors (known Mersenne primes). This
    # reproducible synthetic key must never be used outside tests. No export.
    p, q, e = (1 << 1279) - 1, (1 << 2203) - 1, 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    key = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=rsa.RSAPublicNumbers(e, p * q),
    ).private_key()
    return NonExportableTestKey(key)


def install_key(monkeypatch, signing_key):
    reads = []

    def get_key(directory):
        reads.append(directory)
        return KID, signing_key

    monkeypatch.setattr(tokens, "get_signing_key", get_key)
    monkeypatch.setattr(tokens.time, "time", lambda: NOW)
    return reads


def segment(value, *, sort_keys=False):
    source = json.dumps(value, separators=(",", ":"), sort_keys=sort_keys).encode("utf-8")
    return base64.urlsafe_b64encode(source).rstrip(b"=")


@pytest.mark.parametrize("consumer", [tokens, oauth_session_lifecycle, social_session_issuance])
def test_existing_consumers_sign_identical_rs256_bytes_without_export(monkeypatch, signing_key, consumer):
    reads = install_key(monkeypatch, signing_key)
    config = dict(CONFIG)
    claims = {"scope": "openid profile", "iat": NOW, "exp": NOW + 120, "jti": "synthetic-token-id"}
    original_claims = dict(claims)
    assert consumer.issue_rs256_jwt is tokens.issue_rs256_jwt
    encoded = consumer.issue_rs256_jwt(SUBJECT, claims, cfg=config)
    expected = {
        "iss": CONFIG["JWT_ISSUER"],
        "aud": CONFIG["JWT_AUDIENCE"],
        "sub": SUBJECT,
        "iat": NOW,
        "exp": NOW + 120,
        "scope": "openid profile",
        "jti": "synthetic-token-id",
    }
    # The existing JWT header, payload order and deterministic RS256 signature
    # remain byte-for-byte compatible. This oracle uses no private PEM either.
    header = {"alg": "RS256", "kid": KID, "typ": "JWT"}
    signing_input = segment(header, sort_keys=True) + b"." + segment(expected)
    signature = signing_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    expected_token = signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")
    assert encoded == expected_token.decode("ascii")
    assert jwt.get_unverified_header(encoded) == header
    assert (
        jwt.decode(
            encoded,
            signing_key.public_key(),
            algorithms=["RS256"],
            audience=CONFIG["JWT_AUDIENCE"],
            issuer=CONFIG["JWT_ISSUER"],
            options={"verify_exp": False, "verify_iat": False},
        )
        == expected
    )
    assert reads == [CONFIG["JWKS_DIR"]]
    assert config == CONFIG
    assert claims == original_claims


def test_default_trusted_config_retains_existing_claim_defaults(monkeypatch, signing_key):
    reads = install_key(monkeypatch, signing_key)
    monkeypatch.setattr(tokens, "get_config", lambda: dict(CONFIG))
    encoded = tokens.issue_rs256_jwt(SUBJECT)
    claims = jwt.decode(
        encoded,
        signing_key.public_key(),
        algorithms=["RS256"],
        audience=CONFIG["JWT_AUDIENCE"],
        options={"verify_exp": False, "verify_iat": False},
    )
    assert claims == {
        "iss": CONFIG["JWT_ISSUER"],
        "aud": CONFIG["JWT_AUDIENCE"],
        "sub": SUBJECT,
        "iat": NOW,
        "exp": NOW + 300,
    }
    assert reads == [CONFIG["JWKS_DIR"]]


def test_signing_failure_has_no_export_or_alternative_key_fallback(monkeypatch, signing_key):
    reads = install_key(monkeypatch, signing_key)

    def unavailable(*args):
        raise RuntimeError("synthetic signer unavailable")

    monkeypatch.setattr(signing_key, "sign", unavailable)
    with pytest.raises(RuntimeError, match="^synthetic signer unavailable$"):
        tokens.issue_rs256_jwt(SUBJECT, cfg=dict(CONFIG))
    assert reads == [CONFIG["JWKS_DIR"]]

import base64
import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from unittest.mock import patch

import jwt
import pytest

from app.factory import create_app
from app.jwks import ensure_rsa_keypair, get_signing_key
from app.tokens import issue_rs256_jwt


def test_factory_rejects_hs256_configuration():
    with (
        patch("app.factory.init_all"),
        patch("app.factory.init_audit_logger"),
    ):
        with pytest.raises(
            ValueError,
            match="JWT_ALGORITHM must be RS256",
        ):
            create_app(
                {
                    "FLASK_SECRET_KEY": "rs256-only-test",
                    "FLASK_ENV": "testing",
                    "JWT_ALGORITHM": "HS256",
                    "JWKS_DIR": os.environ["JWKS_DIR"],
                    "DATABASE_URL": "sqlite:///:memory:",
                    "TESTING": True,
                }
            )


def test_lazy_legacy_runtime_is_rs256_only(tmp_path):
    jwks_dir = tmp_path / "jwks"
    ensure_rsa_keypair(str(jwks_dir))

    environment = os.environ.copy()
    environment.update(
        {
            "JWT_ALGORITHM": "RS256",
            "JWKS_DIR": str(jwks_dir),
            "DATABASE_URL": "sqlite:///:memory:",
            "REDIS_URL": "redis://127.0.0.1:6399/15",
            "FLASK_ENV": "testing",
            "FLASK_SECRET_KEY": "rs256-only-legacy-test",
        }
    )

    script = r"""
import time
from unittest.mock import patch

import jwt

with (
    patch("app.database.init_all"),
    patch("app.audit_logger.init_audit_logger"),
):
    import app.app as legacy

assert legacy.JWT_ALG == "RS256"
assert legacy.JWT_ALLOWED_ALGORITHMS == ["RS256"]
assert legacy.JWKS_DOCUMENT["keys"]

now = int(time.time())
claims = {
    "sub": "legacy-rs256-proof",
    "iat": now,
    "exp": now + 60,
}

rs256_token = legacy.sign_jwt(claims)
rs256_header = jwt.get_unverified_header(rs256_token)

assert rs256_header["alg"] == "RS256"
assert rs256_header["kid"] == legacy.JWT_KID

decoded = legacy.decode_jwt(
    rs256_token,
    options={
        "verify_aud": False,
        "verify_iss": False,
    },
)
assert decoded["sub"] == "legacy-rs256-proof"

try:
    legacy.sign_jwt(
        claims,
        headers={"alg": "HS256"},
    )
except jwt.InvalidAlgorithmError:
    pass
else:
    raise AssertionError("HS256 signing override was accepted")

hs256_token = jwt.encode(
    claims,
    "isolated-hs256-test-secret",
    algorithm="HS256",
)

try:
    legacy.decode_jwt(
        hs256_token,
        options={
            "verify_aud": False,
            "verify_iss": False,
        },
    )
except jwt.InvalidAlgorithmError:
    pass
else:
    raise AssertionError("HS256 token was accepted")

print("legacy_rs256_signing_only=yes")
print("legacy_rs256_verification_only=yes")
print("legacy_hs256_rejected=yes")
"""

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(Path(__file__).resolve().parents[2]),
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )

    assert "legacy_rs256_signing_only=yes" in result.stdout
    assert "legacy_rs256_verification_only=yes" in result.stdout
    assert "legacy_hs256_rejected=yes" in result.stdout


def _pkce_pair(verifier: str = "contract-verifier"):
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def _build_client():
    app = create_app(
        {
            "FLASK_SECRET_KEY": "test_secret_key_oauth_contract",
            "FLASK_ENV": "testing",
            "JWKS_DIR": os.environ["JWKS_DIR"],
            "DATABASE_URL": "sqlite:///:memory:",
            "JWT_ISSUER": "https://test.example.com",
            "TESTING": True,
        }
    )
    return app.test_client()


def test_oidc_discovery_contract_fields_present():
    client = _build_client()
    resp = client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200

    data = resp.get_json()
    assert isinstance(data.get("issuer"), str)
    assert data.get("authorization_endpoint")
    assert data.get("token_endpoint")
    assert data.get("jwks_uri")
    assert data.get("response_types_supported")
    assert data.get("subject_types_supported")

    algs = data.get("id_token_signing_alg_values_supported") or []
    assert "RS256" in algs


def test_jwks_contract_public_only():
    client = _build_client()
    resp = client.get("/oauth/jwks.json")
    assert resp.status_code == 200

    data = resp.get_json()
    assert isinstance(data.get("keys"), list)
    assert data["keys"], "JWKS should include at least one key"

    private_fields = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
    for key in data["keys"]:
        assert key.get("kid")
        assert key.get("kty")
        assert key.get("use") or key.get("alg")
        assert private_fields.isdisjoint(key.keys())


def _jwks_directory_snapshot(directory):
    return {
        item.name: {
            "size": item.stat().st_size,
            "mtime_ns": item.stat().st_mtime_ns,
            "sha256": hashlib.sha256(item.read_bytes()).hexdigest(),
        }
        for item in sorted(directory.iterdir())
        if item.is_file()
    }


def test_factory_does_not_create_missing_jwks(tmp_path):
    jwks_dir = tmp_path / "missing-jwks"

    with (
        patch("app.factory.init_all"),
        patch("app.factory.init_audit_logger"),
    ):
        with pytest.raises(FileNotFoundError):
            create_app(
                {
                    "FLASK_SECRET_KEY": "readonly-factory-test",
                    "FLASK_ENV": "testing",
                    "JWKS_DIR": str(jwks_dir),
                    "DATABASE_URL": "sqlite:///:memory:",
                    "JWT_ISSUER": "https://test.example.com",
                    "TESTING": True,
                }
            )

    assert not jwks_dir.exists()


def test_factory_startup_does_not_mutate_jwks(tmp_path):
    jwks_dir = tmp_path / "jwks"
    ensure_rsa_keypair(str(jwks_dir))

    before = _jwks_directory_snapshot(jwks_dir)

    with (
        patch("app.factory.init_all"),
        patch("app.factory.init_audit_logger"),
    ):
        app = create_app(
            {
                "FLASK_SECRET_KEY": "readonly-factory-test",
                "FLASK_ENV": "testing",
                "JWKS_DIR": str(jwks_dir),
                "DATABASE_URL": "sqlite:///:memory:",
                "JWT_ISSUER": "https://test.example.com",
                "TESTING": True,
            }
        )

    assert app.config["JWT_ALGORITHM"] == "RS256"
    assert app.config["JWT_KID"]
    assert app.config["JWKS_DOCUMENT"]["keys"]
    assert _jwks_directory_snapshot(jwks_dir) == before


def test_token_issuance_does_not_mutate_key_directory(tmp_path):
    jwks_dir = tmp_path / "jwks"
    ensure_rsa_keypair(str(jwks_dir))

    before = _jwks_directory_snapshot(jwks_dir)

    config = {
        "JWKS_DIR": str(jwks_dir),
        "JWT_ISSUER": "https://test.example.com",
        "JWT_AUDIENCE": "test-audience",
        "JWT_ALGORITHM": "HS256",
    }

    with patch("app.tokens.get_config", return_value=config):
        token = issue_rs256_jwt(
            sub="test-subject",
            claims={"aud": "oauth-client"},
        )

    assert _jwks_directory_snapshot(jwks_dir) == before

    header = jwt.get_unverified_header(token)
    payload = jwt.decode(
        token,
        options={"verify_signature": False, "verify_aud": False},
    )

    assert header["alg"] == "RS256"
    assert header["kid"]
    assert payload["sub"] == "test-subject"
    assert payload["aud"] == "oauth-client"


def test_token_issuance_does_not_create_missing_keys(tmp_path):
    jwks_dir = tmp_path / "missing-jwks"

    config = {
        "JWKS_DIR": str(jwks_dir),
        "JWT_ISSUER": "https://test.example.com",
    }

    with patch("app.tokens.get_config", return_value=config):
        with pytest.raises(FileNotFoundError, match="No signing keys found"):
            issue_rs256_jwt(sub="test-subject")

    assert not jwks_dir.exists()


def test_jwks_get_does_not_mutate_key_directory(tmp_path):
    jwks_dir = tmp_path / "jwks"
    ensure_rsa_keypair(str(jwks_dir))

    app = create_app(
        {
            "FLASK_SECRET_KEY": "test-secret-jwks-read-only",
            "FLASK_ENV": "testing",
            "JWKS_DIR": str(jwks_dir),
            "DATABASE_URL": "sqlite:///:memory:",
            "JWT_ISSUER": "https://test.example.com",
            "TESTING": True,
        }
    )
    client = app.test_client()

    before = _jwks_directory_snapshot(jwks_dir)

    response = client.get("/oauth/jwks.json")

    assert response.status_code == 200
    assert _jwks_directory_snapshot(jwks_dir) == before


def test_jwks_get_does_not_recreate_missing_document(tmp_path):
    jwks_dir = tmp_path / "jwks"
    ensure_rsa_keypair(str(jwks_dir))

    app = create_app(
        {
            "FLASK_SECRET_KEY": "test-secret-jwks-missing",
            "FLASK_ENV": "testing",
            "JWKS_DIR": str(jwks_dir),
            "DATABASE_URL": "sqlite:///:memory:",
            "JWT_ISSUER": "https://test.example.com",
            "TESTING": True,
        }
    )
    client = app.test_client()

    jwks_path = jwks_dir / "jwks.json"
    jwks_path.unlink()

    before = _jwks_directory_snapshot(jwks_dir)

    response = client.get("/oauth/jwks.json")

    assert response.status_code == 503
    assert response.get_json() == {"error": "jwks_unavailable"}
    assert not jwks_path.exists()
    assert _jwks_directory_snapshot(jwks_dir) == before


def test_introspection_rejects_key_from_literal_fallback_directory(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    primary_dir = tmp_path / "primary-jwks"
    fallback_dir = tmp_path / "keys"

    ensure_rsa_keypair(str(primary_dir))
    ensure_rsa_keypair(str(fallback_dir))
    fallback_kid, fallback_private_key = get_signing_key(str(fallback_dir))

    issuer = "https://isolated.example.test"
    client_id = "isolated-client"
    client_secret = "isolated-secret"

    # Prevent this unit test from connecting to staging DB, Redis, or audit services.
    with (
        patch("app.factory.init_all"),
        patch("app.factory.init_audit_logger"),
    ):
        app = create_app(
            {
                "FLASK_SECRET_KEY": "isolated-test-secret",
                "FLASK_ENV": "testing",
                "JWKS_DIR": str(primary_dir),
                "DATABASE_URL": "sqlite:///:memory:",
                "JWT_ISSUER": issuer,
                "TESTING": True,
            }
        )

    client = app.test_client()

    public_response = client.get("/oauth/jwks.json")
    assert public_response.status_code == 200

    public_kids = {
        str(key.get("kid"))
        for key in public_response.get_json().get("keys", [])
        if isinstance(key, dict) and key.get("kid")
    }

    assert fallback_kid not in public_kids

    now = int(time.time())
    token = jwt.encode(
        {
            "iss": issuer,
            "aud": client_id,
            "sub": "isolated-subject",
            "iat": now,
            "exp": now + 300,
            "scope": "openid",
        },
        fallback_private_key,
        algorithm="RS256",
        headers={"kid": fallback_kid},
    )

    with patch(
        "app.blueprints.oauth.get_oauth_client",
        return_value={"client_secret": client_secret},
    ):
        response = client.post(
            "/oauth/introspect",
            data={
                "token": token,
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )

    assert response.status_code == 200
    assert response.get_json() == {"active": False}


def test_introspection_rejects_global_fallback_issuer(
    tmp_path,
):
    jwks_dir = tmp_path / "jwks"
    ensure_rsa_keypair(str(jwks_dir))

    configured_issuer = "https://configured.example.test"
    fallback_issuer = "https://fallback.example.test"
    client_id = "isolated-client"
    client_secret = "isolated-secret"

    with (
        patch("app.factory.init_all"),
        patch("app.factory.init_audit_logger"),
    ):
        app = create_app(
            {
                "FLASK_SECRET_KEY": "isolated-test-secret",
                "FLASK_ENV": "testing",
                "JWKS_DIR": str(jwks_dir),
                "DATABASE_URL": "sqlite:///:memory:",
                "JWT_ISSUER": configured_issuer,
                "TESTING": True,
            }
        )

    client = app.test_client()
    kid, private_key = get_signing_key(str(jwks_dir))
    now = int(time.time())

    token = jwt.encode(
        {
            "iss": fallback_issuer,
            "aud": client_id,
            "sub": "isolated-subject",
            "iat": now,
            "exp": now + 300,
            "scope": "openid",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )

    with (
        patch(
            "app.blueprints.oauth.get_oauth_client",
            return_value={"client_secret": client_secret},
        ),
        patch(
            "app.config.get_config",
            return_value={
                "JWKS_DIR": str(jwks_dir),
                "JWT_ISSUER": fallback_issuer,
            },
        ),
    ):
        response = client.post(
            "/oauth/introspect",
            data={
                "token": token,
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )

    assert response.status_code == 200
    assert response.get_json() == {"active": False}


def test_authorize_rejects_missing_client_id_without_500():
    client = _build_client()
    resp = client.get(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "redirect_uri": "https://app.example.com/callback",
            "code_challenge": "abc",
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["error"] == "invalid_request"


def test_authorize_rejects_invalid_redirect_uri_without_500():
    client = _build_client()
    with patch(
        "app.blueprints.oauth.get_oauth_client", return_value={"redirect_uris": ["https://app.example.com/callback"]}
    ):
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "02" + "a" * 64

        _, challenge = _pkce_pair()
        resp = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": "client_1",
                "redirect_uri": "https://evil.example.com/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )

    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_request"


def test_authorize_rejects_unsupported_response_type():
    client = _build_client()
    resp = client.get(
        "/oauth/authorize",
        query_string={
            "response_type": "token",
            "client_id": "client_1",
            "redirect_uri": "https://app.example.com/callback",
            "code_challenge": "abc",
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "unsupported_response_type"


def test_authorize_malformed_request_is_structured_error_not_500():
    client = _build_client()
    resp = client.get("/oauth/authorize")
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_request"


def test_pkce_requires_s256_challenge():
    client = _build_client()
    with patch(
        "app.blueprints.oauth.get_oauth_client", return_value={"redirect_uris": ["https://app.example.com/callback"]}
    ):
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "02" + "a" * 64

        plain_resp = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": "client_1",
                "redirect_uri": "https://app.example.com/callback",
                "code_challenge": "plain-challenge",
                "code_challenge_method": "plain",
            },
        )
        missing_resp = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": "client_1",
                "redirect_uri": "https://app.example.com/callback",
                "code_challenge_method": "S256",
            },
        )

    assert plain_resp.status_code == 400
    assert plain_resp.get_json()["error"] == "invalid_request"
    assert missing_resp.status_code == 400
    assert missing_resp.get_json()["error"] == "invalid_request"


def test_pkce_s256_authorize_and_bad_verifier_rejected_without_500():
    client = _build_client()
    verifier, challenge = _pkce_pair("correct-verifier")
    code_record = {
        "client_id": "client_1",
        "redirect_uri": "https://app.example.com/callback",
        "scope": "openid profile",
        "user_pubkey": "02" + "b" * 64,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    with (
        patch(
            "app.blueprints.oauth.get_oauth_client",
            return_value={"client_secret": "secret", "redirect_uris": ["https://app.example.com/callback"]},
        ),
        patch("app.blueprints.oauth.store_oauth_code") as _store,
        patch("app.blueprints.oauth.get_oauth_code", return_value=code_record),
        patch("app.blueprints.oauth.delete_oauth_code") as delete_code,
    ):
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = code_record["user_pubkey"]

        auth = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": "client_1",
                "redirect_uri": "https://app.example.com/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert auth.status_code == 302
        parsed = urlparse(auth.location)
        code = parse_qs(parsed.query).get("code", [None])[0]
        assert code

        bad_token = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example.com/callback",
                "client_id": "client_1",
                "client_secret": "secret",
                "code_verifier": verifier + "-wrong",
            },
        )

    assert bad_token.status_code == 400
    assert bad_token.get_json()["error"] == "invalid_grant"
    delete_code.assert_called()

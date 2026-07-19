import pytest

from app.services.oauth_bearer_validation import BearerValidationError, MAX_BEARER_LENGTH, validate_canonical_access_token


@pytest.mark.parametrize(
    "token",
    [None, "", "x" * (MAX_BEARER_LENGTH + 1), "opaque", "a..c", "a.b", "a.b.c.d", "a.b.c=", "***.b.c"],
)
def test_rejects_oversized_and_malformed_compact_credentials(app, token):
    with app.app_context(), pytest.raises(BearerValidationError):
        validate_canonical_access_token(token)


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "none", "kid": "key"},
        {"alg": "HS256", "kid": "key"},
        {"alg": "ES256", "kid": "key"},
        {"alg": "PS256", "kid": "key"},
        {"alg": "RS256"},
        {"alg": "RS256", "kid": ""},
    ],
)
def test_algorithm_and_kid_are_strictly_pinned(app, monkeypatch, header):
    monkeypatch.setattr("app.services.oauth_bearer_validation.jwt.get_unverified_header", lambda _token: header)
    with app.app_context(), pytest.raises(BearerValidationError):
        validate_canonical_access_token("a.b.c")


def test_database_failure_fails_closed_without_logging_token(app, monkeypatch, caplog):
    monkeypatch.setattr(
        "app.services.oauth_bearer_validation.jwt.get_unverified_header",
        lambda _token: {"alg": "RS256", "kid": "key"},
    )
    monkeypatch.setattr(
        "app.services.oauth_bearer_validation.jwt.decode",
        lambda *_args, **_kwargs: {"jti": "identifier", "aud": "client"},
    )

    def fail(_jti):
        raise RuntimeError("database down")

    monkeypatch.setattr("app.services.oauth_bearer_validation.get_canonical_jwt_record_by_jti", fail)
    with app.app_context(), pytest.raises(BearerValidationError):
        validate_canonical_access_token("aaa.bbb.ccc")
    assert "aaa.bbb.ccc" not in caplog.text

import hashlib

import pytest

from app.services.action_idempotency import (
    IDEMPOTENCY_KEY_DOMAIN,
    OPERATION_CONTRACT_VERSION,
    IdempotencyError,
    canonical_json_bytes,
    idempotency_key_sha256,
    request_fingerprint_sha256,
)


def bindings(**changes):
    value = dict(
        contract_version=OPERATION_CONTRACT_VERSION,
        actor_pubkey="ab" * 32,
        oauth_client_id="client",
        token_jti="jti",
        action="draft_create",
        resource_id=None,
        request_sha256="cd" * 32,
        step_up_challenge_id=None,
    )
    value.update(changes)
    return value


def test_key_is_unchanged_domain_separated_and_plaintext_is_not_digest():
    raw = "retry-Key_123"
    expected = hashlib.sha256(IDEMPOTENCY_KEY_DOMAIN.encode() + b"\0" + raw.encode()).hexdigest()
    assert idempotency_key_sha256(raw) == expected
    assert raw not in expected


@pytest.mark.parametrize(
    "value", [None, "", "short", " leading12", "trailing12 ", "has space", "line\nfeed", "x" * 201]
)
def test_invalid_keys(value):
    with pytest.raises(IdempotencyError, match="invalid_idempotency_key"):
        idempotency_key_sha256(value)


def test_fingerprint_is_deterministic_canonical_and_binds_every_field():
    baseline = request_fingerprint_sha256(**bindings())
    assert baseline == request_fingerprint_sha256(**bindings())
    assert canonical_json_bytes({"é": 1}) == b'{"\\u00e9":1}'
    mutations = {
        "contract_version": "wrong",
        "actor_pubkey": "ac" * 32,
        "oauth_client_id": "other",
        "token_jti": "other",
        "action": "other",
        "resource_id": "resource",
        "request_sha256": "de" * 32,
        "step_up_challenge_id": "12" * 16,
    }
    for field, value in mutations.items():
        if field == "contract_version":
            with pytest.raises(IdempotencyError):
                request_fingerprint_sha256(**bindings(**{field: value}))
        else:
            assert request_fingerprint_sha256(**bindings(**{field: value})) != baseline

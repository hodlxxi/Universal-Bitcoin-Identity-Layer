import copy
import inspect
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.services.action_receipt import (
    RECEIPT_FIELDS,
    RECEIPT_SCHEMA,
    SIGNATURE_DOMAIN,
    SIGNATURE_SCHEME,
    ActionReceiptError,
    canonical_json_bytes,
    canonical_timestamp,
    create_action_receipt,
    signing_envelope,
    verify_action_receipt,
)


def make_receipt(**changes):
    key = ec.derive_private_key(7, ec.SECP256K1())
    public = (
        key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint).hex()
    )
    values = dict(
        operation_id="11111111-1111-4111-8111-111111111111",
        idempotency_key_sha256="11" * 32,
        actor_pubkey="22" * 32,
        oauth_client_id="client",
        token_reference_sha256="33" * 32,
        action="draft_create",
        resource_id=None,
        request_sha256="44" * 32,
        policy_version="policy-v1",
        authorization_decision_sha256="55" * 32,
        step_up_challenge_id=None,
        step_up_verification_sha256=None,
        state="completed",
        started_at="2026-07-20T12:00:00.000000Z",
        completed_at="2026-07-20T12:00:01.000000Z",
        failure_code=None,
        result_sha256="66" * 32,
    )
    values.update(changes)
    calls = []

    def signer(message):
        calls.append(message)
        return key.sign(message, ec.ECDSA(hashes.SHA256())).hex()

    receipt = create_action_receipt(signer=signer, signer_public_key=public, **values)
    assert len(calls) == 1
    return receipt


def test_constants_allowlist_and_canonical_fixtures():
    assert (RECEIPT_SCHEMA, SIGNATURE_DOMAIN, SIGNATURE_SCHEME) == (
        "hodlxxi.action-receipt.v1",
        "HODLXXI_ACTION_RECEIPT_V1",
        "secp256k1_ecdsa_sha256_der_hex",
    )
    receipt = make_receipt()
    assert set(receipt) == RECEIPT_FIELDS
    assert canonical_json_bytes({"b": "é", "a": 1}) == b'{"a":1,"b":"\\u00e9"}'
    assert canonical_timestamp(datetime(2026, 7, 20, tzinfo=timezone.utc)) == "2026-07-20T00:00:00.000000Z"
    assert signing_envelope(receipt).startswith(b'{"domain":"HODLXXI_ACTION_RECEIPT_V1","receipt":{')


def test_real_der_signature_and_every_security_mutation_fails():
    receipt = make_receipt()
    assert verify_action_receipt(receipt)
    for field, value in {
        "actor_pubkey": "23" * 32,
        "oauth_client_id": "evil",
        "token_reference_sha256": "77" * 32,
        "action": "evil",
        "request_sha256": "88" * 32,
        "policy_version": "evil",
        "authorization_decision_sha256": "99" * 32,
        "result_sha256": "aa" * 32,
    }.items():
        changed = copy.deepcopy(receipt)
        changed[field] = value
        assert not verify_action_receipt(changed), field


@pytest.mark.parametrize(
    "change",
    [
        {"extra": 1},
        {"schema": "unknown"},
        {"state": "reserved"},
        {"signature": "zz"},
        {"signature": "00"},
        {"signer_public_key": "02" + "00" * 32},
    ],
)
def test_strict_malformed_unknown_and_extra_rejection(change):
    receipt = make_receipt()
    receipt.update(change)
    assert not verify_action_receipt(receipt)


def test_completed_and_failed_conditionals_and_secret_absence():
    assert verify_action_receipt(make_receipt())
    assert verify_action_receipt(make_receipt(state="failed", failure_code="dispatch_failed", result_sha256=None))
    with pytest.raises(ActionReceiptError):
        make_receipt(failure_code="bad")
    with pytest.raises(ActionReceiptError):
        make_receipt(state="failed", failure_code="bad")
    forbidden = {
        "token_jti",
        "bearer_token",
        "idempotency_key",
        "client_secret",
        "request_body",
        "result_body",
        "step_up_nonce",
        "proof_signature",
        "invoice",
        "payment",
        "created_at",
    }
    assert not (forbidden & RECEIPT_FIELDS)


def test_signer_failure_is_closed_and_module_has_no_key_loading():
    good = make_receipt()
    fields = {
        name: value
        for name, value in good.items()
        if name
        not in {"schema", "receipt_id", "signer_public_key", "signature_domain", "signature_scheme", "signature"}
    }
    with pytest.raises(ActionReceiptError) as exc:
        create_action_receipt(
            signer_public_key="02" + "11" * 32,
            signer=lambda _: (_ for _ in ()).throw(RuntimeError("/secret/key")),
            **fields,
        )
    assert str(exc.value) == "signing_failed" and "/secret" not in str(exc.value)
    with pytest.raises(ActionReceiptError, match="signing_failed"):
        create_action_receipt(signer_public_key=good["signer_public_key"], signer=lambda _: "not-hex", **fields)
    source = inspect.getsource(__import__("app.services.action_receipt", fromlist=["x"]))
    assert "AGENT_PRIVKEY" not in source and "getenv" not in source

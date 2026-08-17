"""Strict canonical final action-receipt contract with injected signing."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

RECEIPT_SCHEMA = "hodlxxi.action-receipt.v1"
SIGNATURE_DOMAIN = "HODLXXI_ACTION_RECEIPT_V1"
SIGNATURE_SCHEME = "secp256k1_ecdsa_sha256_der_hex"
RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "receipt_id",
        "operation_id",
        "idempotency_key_sha256",
        "actor_pubkey",
        "oauth_client_id",
        "token_reference_sha256",
        "action",
        "resource_id",
        "request_sha256",
        "policy_version",
        "authorization_decision_sha256",
        "step_up_challenge_id",
        "step_up_verification_sha256",
        "state",
        "started_at",
        "completed_at",
        "failure_code",
        "result_sha256",
        "signer_public_key",
        "signature_domain",
        "signature_scheme",
        "signature",
    }
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_DER_HEX = re.compile(r"^[0-9a-f]+$")
_SAFE_TEXT = re.compile(r"^[\x21-\x7e]+$")
Signer = Callable[[bytes], str]


class ActionReceiptError(ValueError):
    pass


def canonical_json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def canonical_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ActionReceiptError("invalid_receipt")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def signing_envelope(receipt: dict) -> bytes:
    unsigned = dict(receipt)
    unsigned.pop("signature", None)
    return canonical_json_bytes({"domain": SIGNATURE_DOMAIN, "receipt": unsigned})


def _bounded_text(value, maximum: int) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= maximum and bool(_SAFE_TEXT.fullmatch(value))


def _validate(receipt: dict, *, require_signature: bool = True) -> dict:
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise ActionReceiptError("invalid_receipt")
    if (
        receipt["schema"] != RECEIPT_SCHEMA
        or receipt["signature_domain"] != SIGNATURE_DOMAIN
        or receipt["signature_scheme"] != SIGNATURE_SCHEME
    ):
        raise ActionReceiptError("invalid_receipt")
    if receipt["state"] not in {"completed", "failed"}:
        raise ActionReceiptError("invalid_receipt")
    for field in (
        "idempotency_key_sha256",
        "actor_pubkey",
        "token_reference_sha256",
        "request_sha256",
        "authorization_decision_sha256",
    ):
        if not isinstance(receipt[field], str) or not _HEX64.fullmatch(receipt[field]):
            raise ActionReceiptError("invalid_receipt")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b"\x02" + bytes.fromhex(receipt["actor_pubkey"]))
    except ValueError:
        raise ActionReceiptError("invalid_receipt") from None
    if not _bounded_text(receipt["oauth_client_id"], 256) or not _bounded_text(receipt["action"], 64):
        raise ActionReceiptError("invalid_receipt")
    if receipt["resource_id"] is not None and not _bounded_text(receipt["resource_id"], 256):
        raise ActionReceiptError("invalid_receipt")
    if not _bounded_text(receipt["policy_version"], 64):
        raise ActionReceiptError("invalid_receipt")
    for field in ("receipt_id", "operation_id"):
        try:
            if str(uuid.UUID(receipt[field])) != receipt[field]:
                raise ValueError
        except (ValueError, TypeError):
            raise ActionReceiptError("invalid_receipt") from None
    pair = (receipt["step_up_challenge_id"], receipt["step_up_verification_sha256"])
    if (pair[0] is None) != (pair[1] is None) or (
        pair[0] is not None and (not _HEX32.fullmatch(pair[0]) or not _HEX64.fullmatch(pair[1]))
    ):
        raise ActionReceiptError("invalid_receipt")
    for field in ("started_at", "completed_at"):
        try:
            parsed = datetime.fromisoformat(receipt[field].replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            raise ActionReceiptError("invalid_receipt") from None
        if canonical_timestamp(parsed) != receipt[field]:
            raise ActionReceiptError("invalid_receipt")
    started_at = datetime.fromisoformat(receipt["started_at"].replace("Z", "+00:00"))
    completed_at = datetime.fromisoformat(receipt["completed_at"].replace("Z", "+00:00"))
    if completed_at < started_at:
        raise ActionReceiptError("invalid_receipt")
    if receipt["state"] == "completed":
        if (
            not isinstance(receipt["result_sha256"], str)
            or not _HEX64.fullmatch(receipt["result_sha256"])
            or receipt["failure_code"] is not None
        ):
            raise ActionReceiptError("invalid_receipt")
    elif not _bounded_text(receipt["failure_code"], 64) or receipt["result_sha256"] is not None:
        raise ActionReceiptError("invalid_receipt")
    if not isinstance(receipt["signer_public_key"], str) or not re.fullmatch(
        r"0[23][0-9a-f]{64}", receipt["signer_public_key"]
    ):
        raise ActionReceiptError("invalid_receipt")
    if require_signature and (
        not isinstance(receipt["signature"], str)
        or not _DER_HEX.fullmatch(receipt["signature"])
        or len(receipt["signature"]) % 2
    ):
        raise ActionReceiptError("invalid_receipt")
    return receipt


def create_action_receipt(*, signer: Signer, signer_public_key: str, **fields) -> dict:
    receipt = dict(fields)
    receipt.update(
        {
            "schema": RECEIPT_SCHEMA,
            "receipt_id": str(uuid.uuid4()),
            "signer_public_key": signer_public_key,
            "signature_domain": SIGNATURE_DOMAIN,
            "signature_scheme": SIGNATURE_SCHEME,
            "signature": "",
        }
    )
    _validate(receipt, require_signature=False)
    try:
        signature = signer(signing_envelope(receipt))
    except Exception:
        raise ActionReceiptError("signing_failed") from None
    receipt["signature"] = signature
    try:
        _validate(receipt)
        if not verify_action_receipt(receipt):
            raise ActionReceiptError("signing_failed")
    except Exception:
        raise ActionReceiptError("signing_failed") from None
    return receipt


def parse_action_receipt(value: bytes | str | dict) -> dict:
    def strict_object(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ActionReceiptError("invalid_receipt")
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=strict_object) if isinstance(value, (bytes, str)) else dict(value)
    except (ValueError, TypeError, ActionReceiptError):
        raise ActionReceiptError("invalid_receipt") from None
    return _validate(parsed)


def verify_action_receipt(value: bytes | str | dict) -> bool:
    try:
        receipt = parse_action_receipt(value)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), bytes.fromhex(receipt["signer_public_key"])
        )
        public_key.verify(bytes.fromhex(receipt["signature"]), signing_envelope(receipt), ec.ECDSA(hashes.SHA256()))
        return True
    except (ActionReceiptError, ValueError, InvalidSignature):
        return False


def receipt_sha256(receipt: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(parse_action_receipt(receipt))).hexdigest()

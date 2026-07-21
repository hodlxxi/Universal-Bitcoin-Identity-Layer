"""Pure, dormant hashing contracts for action idempotency."""

from __future__ import annotations

import hashlib
import json
import re

IDEMPOTENCY_KEY_DOMAIN = "HODLXXI_ACTION_IDEMPOTENCY_KEY_V1"
OPERATION_CONTRACT_VERSION = "hodlxxi.action-operation.v1"
IDEMPOTENCY_KEY_MIN_LENGTH = 8
IDEMPOTENCY_KEY_MAX_LENGTH = 200
_KEY_RE = re.compile(r"^[A-Za-z0-9._~:+/=-]+$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_XONLY_RE = re.compile(r"^[0-9a-f]{64}$")


class IdempotencyError(ValueError):
    pass


def canonical_json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def validate_idempotency_key(raw_key: str) -> str:
    """Return the unchanged canonical key; whitespace is never normalized."""
    if not isinstance(raw_key, str):
        raise IdempotencyError("invalid_idempotency_key")
    if not IDEMPOTENCY_KEY_MIN_LENGTH <= len(raw_key) <= IDEMPOTENCY_KEY_MAX_LENGTH:
        raise IdempotencyError("invalid_idempotency_key")
    if not _KEY_RE.fullmatch(raw_key):
        raise IdempotencyError("invalid_idempotency_key")
    return raw_key


def idempotency_key_sha256(raw_key: str) -> str:
    key = validate_idempotency_key(raw_key)
    material = IDEMPOTENCY_KEY_DOMAIN.encode("utf-8") + b"\x00" + key.encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def token_reference_sha256(token_jti: str) -> str:
    if not isinstance(token_jti, str) or not 1 <= len(token_jti) <= 128 or token_jti.strip() != token_jti:
        raise IdempotencyError("invalid_request_binding")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in token_jti):
        raise IdempotencyError("invalid_request_binding")
    return hashlib.sha256(token_jti.encode("utf-8")).hexdigest()


def request_fingerprint_sha256(
    *,
    contract_version: str,
    actor_pubkey: str,
    oauth_client_id: str,
    token_jti: str,
    action: str,
    resource_id: str | None,
    request_sha256: str,
    step_up_challenge_id: str | None,
) -> str:
    if contract_version != OPERATION_CONTRACT_VERSION:
        raise IdempotencyError("invalid_request_binding")
    if not _XONLY_RE.fullmatch(actor_pubkey) or not _HEX64_RE.fullmatch(request_sha256):
        raise IdempotencyError("invalid_request_binding")
    values = (oauth_client_id, token_jti, action)
    ceilings = (256, 128, 64)
    if any(not isinstance(v, str) or not 1 <= len(v) <= limit or v.strip() != v for v, limit in zip(values, ceilings)):
        raise IdempotencyError("invalid_request_binding")
    if resource_id is not None and (
        not isinstance(resource_id, str) or not 1 <= len(resource_id) <= 256 or resource_id.strip() != resource_id
    ):
        raise IdempotencyError("invalid_request_binding")
    if step_up_challenge_id is not None and not re.fullmatch(r"[0-9a-f]{32}", step_up_challenge_id):
        raise IdempotencyError("invalid_request_binding")
    payload = {
        "action": action,
        "actor_pubkey": actor_pubkey,
        "contract_version": contract_version,
        "oauth_client_id": oauth_client_id,
        "request_sha256": request_sha256,
        "resource_id": resource_id,
        "step_up_challenge_id": step_up_challenge_id,
        "token_jti": token_jti,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
from typing import Optional

from bech32 import bech32_decode, convertbits

# CHALLENGE_STORE_V1
# In-memory login/PoF challenge store (single worker/eventlet).
# If you scale workers, move this to Redis.
ACTIVE_CHALLENGES = {}
CHALLENGE_TTL_SECONDS = 300
# /CHALLENGE_STORE_V1


def mint_access_token(sub: str, scope: str = "basic") -> str:
    """
    Minimal placeholder token generator — not a real JWT.
    """
    token = base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip("=")
    return f"{sub}.{token}"


def is_valid_pubkey(pubkey: str) -> bool:
    """
    Accept:
      - Hex: 32-byte x-only, 33-byte compressed, 64/65-byte uncompressed
      - Nostr npub1… (bech32, 32-byte x-only)
    """
    if not pubkey:
        return False
    s = pubkey.strip()

    if s.lower().startswith("npub1"):
        try:
            hrp, data = bech32_decode(s)
            if hrp != "npub":
                return False
            b = convertbits(data, 5, 8, False)
            return b is not None and len(b) == 32
        except Exception:
            return False

    try:
        h = bytes.fromhex(s)
        return len(h) in (32, 33, 64, 65)
    except Exception:
        return False


NOSTR_LOGIN_MAX_AGE_SECONDS = int(os.getenv("NOSTR_LOGIN_MAX_AGE_SECONDS", "300"))
NOSTR_LOGIN_MAX_FUTURE_SKEW_SECONDS = int(os.getenv("NOSTR_LOGIN_MAX_FUTURE_SKEW_SECONDS", "60"))


def _nostr_compact_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _nostr_event_id(event: dict) -> str:
    payload = [
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"],
    ]
    return hashlib.sha256(_nostr_compact_json(payload).encode("utf-8")).hexdigest()


def _nostr_get_tag(event: dict, name: str) -> Optional[str]:
    tags = event.get("tags")
    if not isinstance(tags, list):
        return None

    for tag in tags:
        if (
            isinstance(tag, list)
            and len(tag) >= 2
            and isinstance(tag[0], str)
            and isinstance(tag[1], str)
            and tag[0] == name
        ):
            return tag[1]
    return None


def verify_nostr_login_event(
    event: dict,
    *,
    expected_pubkey: str,
    expected_challenge: str,
    expected_verify_url: Optional[str] = None,
    now_ts: Optional[int] = None,
) -> tuple[bool, Optional[str]]:
    if not isinstance(event, dict):
        return False, "Invalid nostr_event"

    required_fields = ("id", "pubkey", "created_at", "kind", "tags", "content", "sig")
    missing = [field for field in required_fields if field not in event]
    if missing:
        return False, f"Missing nostr_event field: {missing[0]}"

    event_pubkey = (event.get("pubkey") or "").strip().lower()
    event_id = (event.get("id") or "").strip().lower()
    event_sig = (event.get("sig") or "").strip().lower()
    expected_pubkey = (expected_pubkey or "").strip().lower()

    if not re.fullmatch(r"[0-9a-f]{64}", event_pubkey):
        return False, "Invalid nostr pubkey"
    if not re.fullmatch(r"[0-9a-f]{64}", event_id):
        return False, "Invalid nostr event id"
    if not re.fullmatch(r"[0-9a-f]{128}", event_sig):
        return False, "Invalid nostr signature"
    if event_pubkey != expected_pubkey:
        return False, "Pubkey mismatch"

    try:
        created_at = int(event.get("created_at"))
    except Exception:
        return False, "Invalid nostr created_at"

    try:
        kind = int(event.get("kind"))
    except Exception:
        return False, "Invalid nostr kind"

    if kind != 22242:
        return False, "Invalid nostr kind"
    if not isinstance(event.get("tags"), list):
        return False, "Invalid nostr tags"
    if not isinstance(event.get("content"), str):
        return False, "Invalid nostr content"

    now_ts = int(now_ts if now_ts is not None else time.time())
    if created_at < now_ts - NOSTR_LOGIN_MAX_AGE_SECONDS:
        return False, "Nostr event is too old"
    if created_at > now_ts + NOSTR_LOGIN_MAX_FUTURE_SKEW_SECONDS:
        return False, "Nostr event is too far in the future"

    challenge_tag = _nostr_get_tag(event, "challenge")
    if not challenge_tag or challenge_tag != expected_challenge:
        return False, "Challenge mismatch"

    # support both old "u" and new "url"
    url_tag = _nostr_get_tag(event, "u") or _nostr_get_tag(event, "url")
    if url_tag and expected_verify_url and url_tag != expected_verify_url:
        return False, "Nostr event URL mismatch"

    normalized_event = dict(event)
    normalized_event["pubkey"] = event_pubkey
    normalized_event["id"] = event_id
    normalized_event["sig"] = event_sig
    normalized_event["created_at"] = created_at
    normalized_event["kind"] = kind

    recomputed_id = _nostr_event_id(normalized_event)
    if recomputed_id != event_id:
        return False, "Nostr event id mismatch"

    try:
        from coincurve import PublicKeyXOnly

        verified = PublicKeyXOnly(bytes.fromhex(event_pubkey)).verify(
            bytes.fromhex(event_sig),
            bytes.fromhex(recomputed_id),
        )
    except Exception:
        return False, "Nostr signature verification unavailable"

    if not verified:
        return False, "Invalid nostr signature"

    return True, None

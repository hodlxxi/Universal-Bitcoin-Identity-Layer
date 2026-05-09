from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping


class SigningError(ValueError):
    """Raised when an SDK signing input is invalid."""


def canonical_json(payload: Mapping[str, Any]) -> str:
    """Return stable JSON suitable for challenge/receipt signing."""
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except TypeError as exc:
        raise SigningError(f"payload is not JSON serializable: {exc}") from exc


def sha256_hex(message: str | bytes) -> str:
    data = message.encode("utf-8") if isinstance(message, str) else message
    return hashlib.sha256(data).hexdigest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class Challenge:
    """HODLXXI challenge material prepared for external key signing."""

    challenge: str
    domain: str = "hodlxxi.com"
    purpose: str = "agent-auth"
    version: str = "hodlxxi-challenge-v1"

    def payload(self) -> dict[str, str]:
        if not self.challenge:
            raise SigningError("challenge is required")
        if not self.domain:
            raise SigningError("domain is required")
        if not self.purpose:
            raise SigningError("purpose is required")
        return {
            "version": self.version,
            "domain": self.domain,
            "purpose": self.purpose,
            "challenge": self.challenge,
        }

    def message(self) -> str:
        return canonical_json(self.payload())

    def digest_hex(self) -> str:
        return sha256_hex(self.message())


Signer = Callable[[bytes], str]


def sign_challenge(challenge: Challenge, signer: Signer) -> dict[str, str]:
    """Sign a challenge using a caller-provided signing function.

    The SDK does not own wallet/private-key handling. The caller provides a
    signer that accepts the UTF-8 challenge message bytes and returns a
    signature string.
    """
    msg = challenge.message().encode("utf-8")
    signature = signer(msg)
    if not signature:
        raise SigningError("signer returned an empty signature")

    return {
        "version": challenge.version,
        "domain": challenge.domain,
        "purpose": challenge.purpose,
        "challenge": challenge.challenge,
        "message": challenge.message(),
        "message_sha256": challenge.digest_hex(),
        "signature": signature,
    }

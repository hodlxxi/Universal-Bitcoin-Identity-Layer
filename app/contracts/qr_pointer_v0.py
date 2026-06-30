"""Fail-closed QR Pointer v0 boundary helpers.

QR Pointer v0 is a discovery pointer contract only. These helpers intentionally
avoid signing, storage, analytics, delegation, approval, payment, or identity
semantics.
"""

from __future__ import annotations

from urllib.parse import urlsplit

FORBIDDEN_CLAIM_KEYS = frozenset(
    {
        "identity",
        "human_identity",
        "consent",
        "approval",
        "delegation",
        "authorization",
        "execution",
        "receipt_validity",
        "payment",
        "trust",
        "reputation",
        "human_presence",
        "operator_approval",
    }
)

SECRET_LIKE_QR_KEYS = frozenset(
    {
        "token",
        "secret",
        "password",
        "private_key",
        "macaroon",
        "cookie",
        "bearer",
        "invoice",
        "preimage",
    }
)

ALLOWED_DISCOVERY_TARGET_PREFIXES = (
    "/.well-known/agent.json",
    "/.well-known/hodlxxi-operator.json",
    "/agent/verify/",
    "/agent/attestations/",
    "/agent/trust/events/",
)

FUTURE_DELEGATION_TARGET_PREFIXES = (
    "/.well-known/agent-delegation.json",
    "/agent/delegations/",
    "/agent/policy",
)


def is_local_bounded_target(path: str) -> bool:
    """Return True when path is a relative, local, allowlisted discovery target."""

    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        return False
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return False
    if path == "/agent/request" or path.startswith("/agent/request/"):
        return False
    if any(path == prefix or path.startswith(prefix) for prefix in FUTURE_DELEGATION_TARGET_PREFIXES):
        return False
    return any(path == prefix or path.startswith(prefix) for prefix in ALLOWED_DISCOVERY_TARGET_PREFIXES)

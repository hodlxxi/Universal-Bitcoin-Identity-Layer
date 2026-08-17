"""Canonical finite OAuth scope and client trust policy."""

from __future__ import annotations

import re

SCOPE_POLICY_VERSION = "hodlxxi.oauth.scope-policy.v1"
MAX_SCOPE_COUNT = 32
MAX_SCOPE_LENGTH = 1024

STANDARD_SCOPES = frozenset({"openid", "profile"})
ACTION_SCOPES = frozenset(
    {
        "self:read",
        "job:create",
        "job:read:self",
        "job:receipt:read:self",
        "action:receipt:read:self",
        "covenant:draft:create",
        "covenant:draft:read:self",
    }
)
RESERVED_SCOPES = frozenset({"covenant:draft:create", "covenant:draft:read:self"})
KNOWN_SCOPES = STANDARD_SCOPES | ACTION_SCOPES
DEFAULT_AUTHORIZATION_SCOPES = frozenset({"openid", "profile"})
PUBLIC_DYNAMIC_SCOPES = frozenset({"openid", "profile", "self:read"})
OPERATOR_MANAGED_SCOPES = frozenset(
    {
        "openid",
        "profile",
        "self:read",
        "job:create",
        "job:read:self",
        "job:receipt:read:self",
        "action:receipt:read:self",
    }
)
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._~-]*$")


class ScopePolicyError(ValueError):
    """An OAuth scope value fails the finite policy."""


def parse_scopes(value: str) -> frozenset[str]:
    if not isinstance(value, str):
        raise ScopePolicyError("scope must be a string")
    if not value or len(value) > MAX_SCOPE_LENGTH:
        raise ScopePolicyError("scope is empty or too long")
    if "," in value or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ScopePolicyError("scope contains forbidden characters")
    if value.strip() != value or re.search(r"\s", value.replace(" ", "")) or "  " in value:
        raise ScopePolicyError("scope has malformed whitespace")
    tokens = value.split(" ")
    if len(tokens) > MAX_SCOPE_COUNT or any(not _TOKEN.fullmatch(token) for token in tokens):
        raise ScopePolicyError("scope has invalid syntax")
    result = frozenset(tokens)
    if not result <= KNOWN_SCOPES:
        raise ScopePolicyError("scope contains an unknown value")
    return result


def serialize_scopes(scopes: frozenset[str]) -> str:
    if not isinstance(scopes, frozenset) or not scopes or not scopes <= KNOWN_SCOPES:
        raise ScopePolicyError("invalid canonical scope set")
    return " ".join(sorted(scopes))


def classify_scope(scope: str) -> str:
    if scope in STANDARD_SCOPES:
        return "standard"
    if scope in RESERVED_SCOPES:
        return "reserved"
    if scope in ACTION_SCOPES:
        return "action"
    raise ScopePolicyError("unknown scope")


def allowed_scopes_for_trust_class(trust_class: str) -> frozenset[str]:
    if trust_class == "public_dynamic":
        return PUBLIC_DYNAMIC_SCOPES
    if trust_class == "operator_managed":
        return OPERATOR_MANAGED_SCOPES
    raise ScopePolicyError("unknown client trust class")


def validate_client_scopes(scopes: frozenset[str], allowed: frozenset[str]) -> frozenset[str]:
    if scopes & RESERVED_SCOPES or not scopes <= allowed:
        raise ScopePolicyError("scope is not issuable to this client")
    return scopes


def client_allowed_scopes(client: dict) -> frozenset[str]:
    metadata = client.get("metadata")
    if not isinstance(metadata, dict):
        raise ScopePolicyError("client trust metadata is missing")
    policy_maximum = allowed_scopes_for_trust_class(metadata.get("trust_class"))
    stored = parse_scopes(client.get("scope"))
    return validate_client_scopes(stored, policy_maximum)


def issuable_discovery_scopes() -> list[str]:
    return sorted(STANDARD_SCOPES | OPERATOR_MANAGED_SCOPES)

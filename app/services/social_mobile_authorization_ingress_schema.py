"""Closed, bounded transport vocabulary for dormant confidential mobile ingress."""

from __future__ import annotations

import json
import re
from types import MappingProxyType

PREFIX = "/internal/v1/social/mobile-authorization"
TOKEN_PATH = PREFIX + "/service-token"
VIEWER_HEADER = "X-HODLXXI-Viewer-Authorization"
MAX_BODY_BYTES = 65536
GROUPS = ("desktop", "phone", "exchange", "invalidate")
SCOPES = MappingProxyType({group: "social:mobile-authorization:" + group for group in GROUPS})
PURPOSES = MappingProxyType({group: "social_mobile_authorization_" + group + "_v1" for group in GROUPS})
# Paths are literal constants. No request-supplied action or Python method name.
COMMANDS = MappingProxyType(
    {
        "legacy/reserve": ("desktop", ("content",)),
        "legacy/accept": ("desktop", ("operationId", "authorizationDigest", "proof")),
        "legacy/status": ("desktop", ("operationId",)),
        "legacy/close": ("desktop", ("operationId", "status")),
        "qr/create": ("desktop", ()),
        "qr/offer": ("phone", ("qr",)),
        "qr/scan": ("phone", ("source", "qr", "possessionProof")),
        "qr/snapshot": ("desktop", ("pairingId", "revision")),
        "qr/claim": ("desktop", ("pairingId", "revision", "authorizationDigest", "humanCode")),
        "qr/accept": ("desktop", ("pairingId", "revision", "authorizationDigest", "proof")),
        "qr/status": ("desktop", ("pairingId",)),
        "qr/close": ("desktop", ("pairingId", "status")),
        "phone/status": ("phone", ("pairingId", "revision", "authorizationDigest", "verifier")),
        "phone/recover": ("phone", ("source", "qr", "possessionProof", "verifier", "revision")),
        "phone/exchange": ("exchange", ("pairingId", "revision", "authorizationDigest", "verifier")),
        "oauth/invalidate": ("invalidate", ()),
    }
)


class InvalidMobileRequest(ValueError):
    def __init__(self):
        super().__init__("invalid mobile request")


def strict_json(raw: bytes) -> dict:
    """The outer envelope is flat. Signed nested objects travel as exact strings."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_BODY_BYTES:
            raise ValueError

        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        def nonfinite(_value):
            raise ValueError

        # Limit structural nesting before json.loads, including adversarial input.
        text = raw.decode("utf-8", errors="strict")
        quoted = escaped = False
        depth = 0
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > 1:
                    raise ValueError
            elif char in "]}":
                depth -= 1
        result = json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)
        if type(result) is not dict:
            raise ValueError
        if any(type(k) is not str or type(v) is not str for k, v in result.items()):
            raise ValueError
        return result
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise InvalidMobileRequest() from None


def command_body(command: str, raw: bytes) -> dict:
    value = strict_json(raw)
    if command not in COMMANDS or set(value) != set(COMMANDS[command][1]):
        raise InvalidMobileRequest()
    for name, item in value.items():
        if name in {"source", "proof", "content"}:
            valid = 0 < len(item) <= 16384 and all(32 <= ord(c) <= 126 for c in item)
        elif name == "operationId":
            valid = (
                re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", item) is not None
            )
        elif name == "qr":
            valid = re.fullmatch(r"hodlxxi-social-pair:v1:[0-9a-f]{64}:[0-9a-f]{64}", item) is not None
        elif name == "humanCode":
            valid = re.fullmatch(r"[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}", item) is not None
        elif name == "status":
            valid = item in {"cancelled", "abandoned", "rejected"}
        else:
            valid = re.fullmatch(r"[0-9a-f]{64}", item) is not None
        if not valid:
            raise InvalidMobileRequest()
    return value

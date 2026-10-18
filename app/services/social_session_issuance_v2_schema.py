"""Closed, separate V2 session transport. Protocol wires remain original strings."""

import re
from types import MappingProxyType

from app.services.social_enrollment_v2_ingress_schema import (
    ASSERTION_TYPE,
    MAX_BODY_BYTES,
    VIEWER_HEADER,
    InvalidMobileRequest,
    strict_json,
    token_form,
)

PREFIX = "/internal/v2/social/session-issuance"
TOKEN_PATH = PREFIX + "/service-token"
COMMANDS = MappingProxyType(
    {
        "offer": ("authorizationWire",),
        "issue": ("operationId", "approvalWire", "secret", "possessionProof", "verifier", "deliveryKey"),
        "recover": ("operationId", "approvalWire", "secret", "possessionProof", "verifier", "deliveryKey"),
        "resolve": ("issuanceId",),
        "revoke": ("issuanceId",),
    }
)
VIEWER_COMMANDS = frozenset(COMMANDS) - {"recover"}
SCOPES = MappingProxyType({name: "social:session-issuance-v2:" + name for name in COMMANDS})
PURPOSES = MappingProxyType({name: "social_session_issuance_v2_" + name + "_v1" for name in COMMANDS})


def command_body(command, raw):
    try:
        data = strict_json(raw)
        if type(command) is not str or command not in COMMANDS or set(data) != set(COMMANDS[command]):
            raise ValueError
        for name, value in data.items():
            if type(value) is not str:
                raise ValueError
            if name in {"authorizationWire", "approvalWire"}:
                if not 0 < len(value) <= 24576 or any(not 32 <= ord(c) <= 126 for c in value):
                    raise ValueError
            elif re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise ValueError
        return data
    except Exception:
        raise InvalidMobileRequest() from None


__all__ = [
    "ASSERTION_TYPE",
    "MAX_BODY_BYTES",
    "VIEWER_HEADER",
    "InvalidMobileRequest",
    "token_form",
    "PREFIX",
    "TOKEN_PATH",
    "COMMANDS",
    "VIEWER_COMMANDS",
    "SCOPES",
    "PURPOSES",
    "command_body",
]

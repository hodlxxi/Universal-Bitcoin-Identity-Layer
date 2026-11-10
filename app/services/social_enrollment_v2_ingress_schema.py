"""Closed transport only. Signed protocol objects remain exact ASCII strings."""

import re
from types import MappingProxyType
from urllib.parse import parse_qsl

from app.services.social_mobile_authorization_ingress_schema import InvalidMobileRequest, strict_json

PREFIX = "/internal/v2/social/enrollment"
TOKEN_PATH = PREFIX + "/service-token"
VIEWER_HEADER = "X-HODLXXI-Viewer-Authorization"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
MAX_BODY_BYTES = 65536
COMMANDS = MappingProxyType(
    {
        "challenge": ("issuanceId",),
        "reserve": ("issuanceId", "verificationInputWire"),
        "finalize": (
            "issuanceId",
            "reservationId",
            "reservationRevision",
            "verificationInputWire",
            "evidenceCompactJws",
            "statementCompactJws",
        ),
    }
)
SCOPES = MappingProxyType({name: "social:enrollment-v2:" + name for name in COMMANDS})
PURPOSES = MappingProxyType({name: "social_enrollment_v2_" + name + "_v1" for name in COMMANDS})
WIRE_LIMITS = MappingProxyType(
    {"verificationInputWire": 24576, "evidenceCompactJws": 16384, "statementCompactJws": 4096}
)
TOKEN_FIELDS = frozenset({"grant_type", "client_id", "client_assertion_type", "client_assertion", "scope"})


def command_body(command, raw):
    try:
        data = strict_json(raw)
        if type(command) is not str or command not in COMMANDS or set(data) != set(COMMANDS[command]):
            raise ValueError
        for name, value in data.items():
            if name in {"issuanceId", "reservationId"}:
                valid = re.fullmatch(r"[0-9a-f]{64}", value) is not None
            elif name == "reservationRevision":
                valid = value == "1"
            else:
                valid = 0 < len(value) <= WIRE_LIMITS[name] and all(32 <= ord(c) <= 126 for c in value)
            if not valid:
                raise ValueError
        return data
    except Exception:
        pass
    raise InvalidMobileRequest() from None


def token_form(raw):
    """No permissive Flask form coercion, repeated fields or extra credentials."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_BODY_BYTES:
            raise ValueError
        text = raw.decode("ascii")
        if any(ord(c) < 32 or ord(c) > 126 for c in text) or re.search(r"%(?![0-9A-Fa-f]{2})", text):
            raise ValueError
        pairs = parse_qsl(
            text,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=len(TOKEN_FIELDS),
        )
        data = dict(pairs)
        if len(pairs) != len(data) or set(data) != TOKEN_FIELDS:
            raise ValueError
        if any(
            not value or len(value) > 16384 or any(ord(c) < 32 or ord(c) > 126 for c in value)
            for value in data.values()
        ):
            raise ValueError
        return data
    except Exception:
        pass
    raise InvalidMobileRequest() from None

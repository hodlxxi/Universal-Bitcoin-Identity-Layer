"""Closed source-only issuance V1 vocabulary; no caller-provided authority."""

from types import MappingProxyType

from app.services.social_messaging_mobile_authorization import _hex
from app.services.social_mobile_authorization_ingress_schema import InvalidMobileRequest, strict_json

PREFIX = "/internal/v1/social/session-issuance"
TOKEN_PATH = PREFIX + "/service-token"
SCOPE = "social:session-issuance:manage"
PURPOSE = "social_session_issuance_v1"
PROOF_FIELDS = ("pairingId", "revision", "authorizationDigest", "verifier", "deliveryKey")
COMMANDS = MappingProxyType(
    {
        "issue": PROOF_FIELDS,
        "recover": PROOF_FIELDS,
        "resolve": ("issuanceId",),
        "revoke": ("issuanceId",),
    }
)


def command_body(command, raw):
    try:
        data = strict_json(raw)
        if command not in COMMANDS or set(data) != set(COMMANDS[command]):
            raise ValueError
        for value in data.values():
            _hex(value)
        return data
    except (ValueError, KeyError, TypeError):
        raise InvalidMobileRequest() from None

"""Source-only canonical bytes for registered-device session possession.

This is a new domain, not a native enrollment or messaging operation proof.
Validation here is shape/time/pin checking only: it never verifies Ed25519,
consumes a challenge, issues a bearer or authenticates a device.
"""

import json
import re

CHALLENGE_SCHEMA = "hodlxxi.social_registered_device_session_challenge.v1"
PROOF_SCHEMA = "hodlxxi.social_registered_device_session_proof.v1"
CHALLENGE_DOMAIN = "HODLXXI_SOCIAL_REGISTERED_DEVICE_SESSION_CHALLENGE_V1"
PROOF_DOMAIN = "HODLXXI_SOCIAL_REGISTERED_DEVICE_SESSION_PROOF_V1"
RUNTIME_ENABLED = False
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_LIFETIME_MS = 60_000
MAX_WIRE_BYTES = 4096
_HEX64 = re.compile(r"[0-9a-f]{64}").fullmatch
_HEX128 = re.compile(r"[0-9a-f]{128}").fullmatch
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}").fullmatch
_COMMITMENT = re.compile(r"hodlxxi-social-messaging-x25519-public-key-v1-sha256:[0-9a-f]{64}").fullmatch
_HEX_FIELDS = {
    "associationId",
    "bindingId",
    "challengeId",
    "contextCommitment",
    "deviceId",
    "ed25519PublicKey",
    "subject",
}
_FIELDS = _HEX_FIELDS | {
    "associationVersion",
    "audience",
    "authorityEpoch",
    "bindingVersion",
    "clientId",
    "domain",
    "expiresAt",
    "issuedAt",
    "issuer",
    "schema",
    "version",
    "x25519PublicKeyCommitment",
}
_PROOF_FIELDS = {"challengeId", "schema", "signature", "version"}


class RegisteredDeviceSessionContractError(ValueError):
    def __init__(self):
        super().__init__("registered device session proof unavailable")


def _deny():
    raise RegisteredDeviceSessionContractError()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _closed(source, fields):
    if type(source) is not str or not 1 <= len(source) <= MAX_WIRE_BYTES or not source.isascii():
        _deny()
    value = json.loads(source)
    # Canonical round-trip also rejects duplicate members and alternate numbers.
    if type(value) is not dict or set(value) != fields or canonical(value) != source:
        _deny()
    return value


def _integer(value):
    return type(value) is int and 0 <= value <= MAX_SAFE_INTEGER


def _matches(regex, value):
    return type(value) is str and regex(value) is not None


def _origin(value):
    # Deliberately DNS-only v1; operators pin exact HTTPS origins, no normalization.
    if type(value) is not str or not 1 <= len(value) <= 255:
        return False
    match = re.fullmatch(r"https://([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?", value)
    if match is None:
        return False
    host, port = match.groups()
    labels = host.split(".")
    return (
        (port is None or 1 <= int(port) <= 65535 and port != "443")
        and not re.fullmatch(r"[0-9]+|0x[0-9a-f]*", labels[-1])
        and all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) and not label.startswith("xn--")
            for label in labels
        )
    )


def parse_challenge_v1(source):
    try:
        value = _closed(source, _FIELDS)
        if (
            value["schema"] != CHALLENGE_SCHEMA
            or type(value["version"]) is not int
            or value["version"] != 1
            or value["domain"] != CHALLENGE_DOMAIN
            or not all(_matches(_HEX64, value[field]) for field in _HEX_FIELDS)
            or value["ed25519PublicKey"] == value["subject"]
            or not _origin(value["issuer"])
            or not _origin(value["audience"])
            or not _matches(_IDENTIFIER, value["clientId"])
            or not _matches(_COMMITMENT, value["x25519PublicKeyCommitment"])
            or not all(_integer(value[field]) for field in ("issuedAt", "expiresAt", "associationVersion", "authorityEpoch", "bindingVersion"))
            or not 1 <= value["bindingVersion"] <= 1024
            or not 1 <= value["associationVersion"] <= value["authorityEpoch"]
            or not 0 < value["expiresAt"] - value["issuedAt"] <= MAX_LIFETIME_MS
        ):
            _deny()
        return value
    except Exception:
        raise RegisteredDeviceSessionContractError() from None


def require_current_challenge_v1(source, *, issuer, audience, client_id, context_commitment, now):
    value = parse_challenge_v1(source)
    if (
        not _integer(now)
        or not value["issuedAt"] <= now < value["expiresAt"]
        or (value["issuer"], value["audience"], value["clientId"], value["contextCommitment"])
        != (issuer, audience, client_id, context_commitment)
    ):
        _deny()
    return value


def signing_preimage_v1(source):
    parse_challenge_v1(source)
    return (PROOF_DOMAIN + "\0" + source).encode("ascii")


def parse_proof_v1(source, *, challenge_wire):
    try:
        challenge = parse_challenge_v1(challenge_wire)
        value = _closed(source, _PROOF_FIELDS)
        if (
            value["schema"] != PROOF_SCHEMA
            or type(value["version"]) is not int
            or value["version"] != 1
            or value["challengeId"] != challenge["challengeId"]
            or not _matches(_HEX128, value["signature"])
        ):
            _deny()
        return value
    except Exception:
        raise RegisteredDeviceSessionContractError() from None

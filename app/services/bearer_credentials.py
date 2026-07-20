"""Strict, shared bearer credential parsing and compact-JWT classification."""

from __future__ import annotations

import re

DEFAULT_MAX_BEARER_LENGTH = 16 * 1024
_COMPACT_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")


class BearerHeaderError(ValueError):
    """The Authorization header is not one unambiguous bearer credential."""


def parse_bearer_authorization_header(
    header: object, *, max_credential_length: int = DEFAULT_MAX_BEARER_LENGTH
) -> str:
    """Return the credential from exactly ``Bearer<SP>credential``.

    The scheme is case-insensitive. Multiple values, commas, surrounding or
    embedded whitespace, and empty or oversized credentials are rejected.
    """
    if not isinstance(header, str) or not header or "," in header:
        raise BearerHeaderError("invalid Authorization header")
    separator = header.find(" ")
    if separator < 0 or header[:separator].casefold() != "bearer":
        raise BearerHeaderError("invalid Authorization header")
    credential = header[separator + 1 :]
    if not credential or any(character.isspace() for character in credential):
        raise BearerHeaderError("invalid Authorization header")
    if len(credential) > max_credential_length:
        raise BearerHeaderError("invalid Authorization header")
    return credential


def has_compact_jwt_shape(credential: object) -> bool:
    """Return true only for three non-empty unpadded base64url segments."""
    if not isinstance(credential, str):
        return False
    segments = credential.split(".")
    return len(segments) == 3 and all(_COMPACT_SEGMENT.fullmatch(segment) for segment in segments)

from __future__ import annotations

import re

from .errors import InvalidIdentifierError

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def validate_identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
        raise InvalidIdentifierError(
            f"{label} must be 1-128 characters and contain only letters, digits, '.', '_', ':', or '-'"
        )
    return value


def validate_limit(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100:
        raise InvalidIdentifierError("limit must be an integer from 1 to 100")
    return value


def validate_offset(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1_000_000:
        raise InvalidIdentifierError("offset must be an integer from 0 to 1000000")
    return value

"""Pure canonical encoding for bounded internal action request payloads."""

from __future__ import annotations

import json
import math

MAX_REQUEST_BYTES = 65_536


def _validate_json_value(value: object, active_containers: set[int]) -> None:
    value_type = type(value)
    if value is None or value_type in {bool, int, str}:
        return
    if value_type is float:
        if not math.isfinite(value):
            raise ValueError("invalid_request")
        return
    if value_type not in {list, dict}:
        raise ValueError("invalid_request")

    identity = id(value)
    if identity in active_containers:
        raise ValueError("invalid_request")
    active_containers.add(identity)
    try:
        if value_type is list:
            for item in value:
                _validate_json_value(item, active_containers)
        else:
            for key, item in value.items():
                if type(key) is not str:
                    raise ValueError("invalid_request")
                _validate_json_value(item, active_containers)
    finally:
        active_containers.remove(identity)


def canonical_payload_bytes(value: object, *, maximum: int = MAX_REQUEST_BYTES) -> bytes:
    """Return the gateway's exact compact, sorted, ASCII JSON representation."""
    _validate_json_value(value, set())
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("invalid_request") from exc
    if len(encoded) > maximum:
        raise ValueError("invalid_request")
    return encoded

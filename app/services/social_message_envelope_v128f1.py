"""Closed V1.28F.1 ciphertext envelope bytes shared with Social's fixed parser."""

import base64
import hashlib
import json
import re


def _closed(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError("invalid ciphertext envelope")
    return {name: value[name] for name in fields}


def _binary(value, minimum, maximum):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid ciphertext envelope")
    raw = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    if not minimum <= len(raw) <= maximum or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("invalid ciphertext envelope")


def parse_canonical_message_envelope_wire_v1(wire):
    if type(wire) is not str or not 1 <= len(wire) <= 32768 or not wire.isascii():
        raise ValueError("invalid ciphertext envelope")
    value = _closed(
        json.loads(wire),
        (
            "schema",
            "version",
            "suite",
            "messageId",
            "recipientPackageSnapshotId",
            "recipientDeviceHandles",
            "body",
            "keyWraps",
        ),
    )
    if (
        value["schema"] != "hodlxxi.social_message_envelope.v1"
        or type(value["version"]) is not int
        or value["version"] != 1
        or value["suite"] != "hodlxxi-hpke-x25519-hkdfsha256-aes128gcm-aes256gcm-v1"
    ):
        raise ValueError("invalid ciphertext envelope")
    if type(value["messageId"]) is not str or not value["messageId"].startswith("m_"):
        raise ValueError("invalid ciphertext envelope")
    _binary(value["messageId"][2:], 32, 32)
    if type(value["recipientPackageSnapshotId"]) is not str or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", value["recipientPackageSnapshotId"]
    ):
        raise ValueError("invalid ciphertext envelope")
    handles, wraps = value["recipientDeviceHandles"], value["keyWraps"]
    if (
        type(handles) is not list
        or not 1 <= len(handles) <= 16
        or type(wraps) is not list
        or len(wraps) != len(handles)
    ):
        raise ValueError("invalid ciphertext envelope")
    for position, handle in enumerate(handles):
        if type(handle) is not str or not handle.startswith("d_") or position and handles[position - 1] >= handle:
            raise ValueError("invalid ciphertext envelope")
        _binary(handle[2:], 16, 16)
        wrap = _closed(wraps[position], ("deviceHandle", "algorithm", "enc", "ciphertext"))
        if wrap["deviceHandle"] != handle or wrap["algorithm"] != "hpke-base-x25519-hkdfsha256-aes128gcm-v1":
            raise ValueError("invalid ciphertext envelope")
        _binary(wrap["enc"], 32, 32)
        _binary(wrap["ciphertext"], 48, 48)
        wraps[position] = wrap
    body = _closed(value["body"], ("algorithm", "nonce", "ciphertext"))
    if body["algorithm"] != "aes-256-gcm":
        raise ValueError("invalid ciphertext envelope")
    _binary(body["nonce"], 12, 12)
    _binary(body["ciphertext"], 17, 16400)
    value["body"] = body
    if json.dumps(value, separators=(",", ":"), ensure_ascii=True) != wire:
        raise ValueError("invalid ciphertext envelope")
    return value


def routing_request_wire_v1(envelope, wire):
    return json.dumps(
        dict(
            schema="hodlxxi.social_messaging_recipient_routing_request.v1",
            version=1,
            messageId=envelope["messageId"],
            envelopeDigest="hodlxxi-social-message-envelope-v1-sha256:"
            + hashlib.sha256(b"HODLXXI_SOCIAL_MESSAGE_ENVELOPE_DIGEST_V1\0" + wire.encode("ascii")).hexdigest(),
            recipientPackageSnapshotId=envelope["recipientPackageSnapshotId"],
            recipientDeviceHandles=envelope["recipientDeviceHandles"],
        ),
        sort_keys=True,
        separators=(",", ":"),
    )

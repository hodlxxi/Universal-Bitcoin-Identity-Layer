#!/usr/bin/env python3
"""Offline QR Pointer payload and image exporter.

This script intentionally keeps validation local and defensive so it can be used
without importing Flask/runtime modules or causing side effects.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
SECRET_LIKE_FIELDS = {
    "secret",
    "token_secret",
    "access_token",
    "refresh_token",
    "private_key",
    "password",
    "cookie",
    "macaroon",
    "credential",
    "invoice",
    "payment_request",
    "approval_token",
    "delegation_secret",
}
AUTHORITY_CLAIM_FIELDS = {
    "consent",
    "approval",
    "delegation",
    "authorization",
    "payment_proof",
    "receipt_validity",
    "trust",
    "reputation",
    "human_presence",
}
WARNING = (
    "QR Pointer export is discovery-only and does not prove identity, consent, approval, delegation, "
    "authorization, payment, receipt validity, reputation, trust, or human presence."
)


class ExportError(ValueError):
    """Safe operator-facing validation error."""


def _fail(message: str) -> None:
    raise ExportError(message)


def normalize_base_url(raw_base_url: str) -> str:
    parsed = urlparse(raw_base_url)
    if parsed.scheme not in {"http", "https"}:
        _fail("base-url must use http or https")
    if not parsed.netloc:
        _fail("base-url must include a host")
    if parsed.query:
        _fail("base-url must not include a query string")
    if parsed.fragment:
        _fail("base-url must not include a fragment")
    normalized_path = parsed.path.rstrip("/")
    return urlunparse((parsed.scheme, parsed.netloc, normalized_path, "", "", ""))


def validate_token(token: Any) -> str:
    if not isinstance(token, str) or not token:
        _fail("record token is required")
    if not TOKEN_RE.fullmatch(token):
        _fail("record token must match [A-Za-z0-9_-]{8,128}")
    return token


def _walk_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str):
                keys.add(key)
            keys.update(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_walk_keys(child))
    return keys


def validate_target(target: Any) -> str:
    if not isinstance(target, str) or not target:
        _fail("record target must be a local relative path")
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        _fail("record target must not be an external URL")
    if target.startswith("//"):
        _fail("record target must not be protocol-relative")
    if not target.startswith("/"):
        _fail("record target must be a local relative path beginning with /")
    return target


def validate_record(record: Any, requested_token: str | None = None) -> tuple[str, str]:
    if not isinstance(record, dict):
        _fail("record must be a JSON object")

    keys = _walk_keys(record)
    secret_fields = sorted(keys & SECRET_LIKE_FIELDS)
    if secret_fields:
        _fail(f"record contains forbidden secret-like field: {secret_fields[0]}")

    authority_fields = sorted(keys & AUTHORITY_CLAIM_FIELDS)
    if authority_fields:
        _fail(f"record contains forbidden authority-claim field: {authority_fields[0]}")

    token = validate_token(record.get("token"))
    if requested_token is not None and token != requested_token:
        _fail("record token does not match requested --token")

    target = validate_target(record.get("target"))
    return token, target


def load_json_file(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_record_from_registry(registry_dir: Path, token: str) -> Any:
    validate_token(token)
    candidates = [
        registry_dir / f"{token}.json",
        registry_dir / token / "pointer.json",
        registry_dir / "qr_pointers.json",
    ]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        data = load_json_file(candidate)
        if isinstance(data, dict) and data.get("token") == token:
            return data
        if isinstance(data, dict) and isinstance(data.get(token), dict):
            return data[token]
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict) and entry.get("token") == token:
                    return entry
    _fail("registry record not found for requested token")


def build_payload_url(base_url: str, token: str) -> str:
    return f"{normalize_base_url(base_url)}/qr/{token}"


def write_qr_image(payload_url: str, output_path: Path) -> None:
    suffix = output_path.suffix.lower()
    if suffix not in {".png", ".svg"}:
        _fail("--output must end with .png or .svg")

    try:
        import qrcode
    except ImportError as exc:  # pragma: no cover - covered via monkeypatch in tests
        raise ExportError(
            "QR image generation requires the optional 'qrcode' dependency. "
            "Install project requirements or run without --output for payload-only export."
        ) from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if suffix == ".svg":
        try:
            from qrcode.image.svg import SvgPathImage
        except ImportError as exc:  # pragma: no cover
            raise ExportError(
                "SVG QR output requires qrcode SVG support. Install project requirements or use .png output."
            ) from exc
        image = qrcode.make(payload_url, image_factory=SvgPathImage)
    else:
        image = qrcode.make(payload_url)
    image.save(output_path)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export an offline QR Pointer payload URL and optional QR image.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--record", type=Path, help="Path to a local static QR Pointer JSON record.")
    source.add_argument("--registry-dir", type=Path, help="Path to a local static QR Pointer registry directory.")
    parser.add_argument("--token", help="Token to load from --registry-dir.")
    parser.add_argument("--base-url", required=True, help="Public base URL, without query string or fragment.")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print without writing image output.")
    parser.add_argument("--output", type=Path, help="Optional .png or .svg output file.")
    args = parser.parse_args(argv)
    if args.registry_dir and not args.token:
        parser.error("--token is required with --registry-dir")
    if args.record and args.token:
        parser.error("--token is only valid with --registry-dir")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        record = (
            load_json_file(args.record) if args.record else load_record_from_registry(args.registry_dir, args.token)
        )
        token, target = validate_record(record, args.token)
        payload_url = build_payload_url(args.base_url, token)
        if args.output and not args.dry_run:
            write_qr_image(payload_url, args.output)
        status = "dry-run" if args.dry_run else "ok"
        print(f"payload_url: {payload_url}")
        print(f"target_path: {target}")
        print(f"status: {status}")
        if args.output:
            output_status = "not written (dry-run)" if args.dry_run else str(args.output)
            print(f"output: {output_status}")
        print(f"warning: {WARNING}")
    except (ExportError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

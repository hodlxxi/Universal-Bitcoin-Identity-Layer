#!/usr/bin/env python3
"""Verify NIP-59 frontend builder safety invariants.

This script intentionally does not install dependencies. It verifies that the
current production-safe skeleton remains non-crypto and non-delivery.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT_PACKAGE = Path("package.json")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def main() -> None:
    package = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))
    skeleton = json.loads(SKELETON.read_text(encoding="utf-8"))
    bundle = BUNDLE.read_text(encoding="utf-8")

    if package.get("dependencies") != {}:
        fail("root package dependencies must remain empty in P27")

    if package.get("devDependencies") != {}:
        fail("root package devDependencies must remain empty in P27")

    if skeleton.get("productionInstallAllowed") is not False:
        fail("production dependency install must remain disallowed")

    if skeleton.get("realCryptoImplemented") is not False:
        fail("real crypto must not be implemented in P27")

    if skeleton.get("sendEnabled") is not False:
        fail("send must remain disabled in P27")

    if skeleton.get("postEnabled") is not False:
        fail("POST must remain disabled in P27")

    if skeleton.get("relayPublishing") is not False:
        fail("relay publishing must remain disabled in P27")

    if 'status: "skeleton"' not in bundle:
        fail("static bundle must remain skeleton")

    forbidden = [
        "finalizeEvent",
        "getEventHash",
        "fetch(",
        "XMLHttpRequest",
        "privateKey",
        "private_key",
        "secretKey",
    ]

    for token in forbidden:
        if token in bundle:
            fail(f"forbidden token in skeleton bundle: {token}")

    print("ok: NIP-59 builder safety invariants hold")


if __name__ == "__main__":
    main()

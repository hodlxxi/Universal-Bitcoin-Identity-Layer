#!/usr/bin/env python3
"""Verify the static NIP-59 browser bundle remains safe.

This inspects the committed browser artifact. It does not build, install npm,
generate a lockfile, or approve browser crypto.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "app/static/js/nip59_client_bundle.js"

REQUIRED_TERMS = [
    'status: "skeleton"',
    "cryptoReady: false",
    "canFinalizeGiftWrap: false",
    "canPostEnvelope: false",
    "relayPublishing: false",
    "plaintextPost: false",
]

FORBIDDEN_TERMS = [
    "@nostr/tools/wasm",
    "nostr-wasm",
    "initNostrWasm",
    "setNostrWasm",
    "NostrWasm",
    "WebAssembly",
    "finalizeEvent",
    "generateSecretKey",
    "privateKey",
    "private_key",
    "secretKey",
    "fetch(",
    "XMLHttpRequest",
    "/api/messages/nip17/envelopes",
]


def inspect_bundle(path: Path = BUNDLE) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    violations: list[str] = []

    for term in REQUIRED_TERMS:
        if term not in text:
            violations.append(f"missing required skeleton term {term!r}")

    for term in FORBIDDEN_TERMS:
        if term in text:
            violations.append(f"contains forbidden bundle term {term!r}")

    return violations


def main() -> int:
    violations = inspect_bundle(BUNDLE)
    if violations:
        print("ERROR: NIP-59 static bundle inspection failed")
        for violation in violations:
            print(f"- {violation}")
        return 1

    print("ok: NIP-59 static bundle inspection holds")
    print(f"bundle={BUNDLE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

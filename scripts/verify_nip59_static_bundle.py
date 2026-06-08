#!/usr/bin/env python3
"""Verify the live static NIP-59 browser bundle remains generated no-send.

This inspects the committed live browser artifact. It does not build, install
npm, generate a lockfile, approve delivery, or enable relay publishing.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "app/static/js/nip59_client_bundle.js"

REQUIRED_TERMS = [
    'status: "generated-experiment-no-send"',
    "cryptoReady: false",
    "canFinalizeGiftWrap: false",
    "canPostEnvelope: false",
    "relayPublishing: false",
    "plaintextPost: false",
    "sendEnabled: false",
    "createLocalProbeEvent",
    "nostr-tools@2.23.5",
]

FORBIDDEN_TERMS = [
    "@nostr/tools/wasm",
    "nostr-wasm",
    "initNostrWasm",
    "setNostrWasm",
    "NostrWasm",
    "WebAssembly",
    "fetch(",
    "XMLHttpRequest",
    "/api/messages/nip17/envelopes",
    "SimplePool",
    "relayInit",
    "publish(",
    "fetchRelayInformation",
    "RelayList",
    "DirectMessageRelaysList",
    "BlockedRelaysList",
    "SearchRelaysList",
    "FavoriteRelays",
    "RelayReview",
    "Relaysets",
]


def inspect_bundle(path: Path = BUNDLE) -> list[str]:
    violations: list[str] = []

    if not path.exists():
        return [f"missing live static bundle {path.relative_to(ROOT)}"]

    text = path.read_text(encoding="utf-8", errors="replace")

    for term in REQUIRED_TERMS:
        if term not in text:
            violations.append(f"missing required live static bundle term {term!r}")

    for term in FORBIDDEN_TERMS:
        if term in text:
            violations.append(f"contains forbidden live static bundle term {term!r}")

    return violations


def main() -> int:
    violations = inspect_bundle(BUNDLE)
    if violations:
        print("ERROR: NIP-59 live static bundle inspection failed")
        for violation in violations:
            print(f"- {violation}")
        return 1

    print("ok: NIP-59 live static bundle inspection holds")
    print(f"bundle={BUNDLE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

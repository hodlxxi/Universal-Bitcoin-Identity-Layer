#!/usr/bin/env python3
"""Verify the reviewed generated NIP-59 browser bundle artifact remains no-send.

This inspects the committed generated artifact. It does not build, install npm,
generate a lockfile, replace the live static bundle, or enable delivery.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "frontend/nip59/dist/nip59_client_bundle.generated.js"

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
        return [f"missing generated bundle artifact {path.relative_to(ROOT)}"]

    text = path.read_text(encoding="utf-8", errors="replace")

    for term in REQUIRED_TERMS:
        if term not in text:
            violations.append(f"missing required generated bundle term {term!r}")

    for term in FORBIDDEN_TERMS:
        if term in text:
            violations.append(f"contains forbidden generated bundle term {term!r}")

    return violations


def main() -> int:
    violations = inspect_bundle(BUNDLE)
    if violations:
        print("ERROR: NIP-59 generated bundle inspection failed")
        for violation in violations:
            print(f"- {violation}")
        return 1

    print("ok: NIP-59 generated bundle inspection holds")
    print(f"bundle={BUNDLE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

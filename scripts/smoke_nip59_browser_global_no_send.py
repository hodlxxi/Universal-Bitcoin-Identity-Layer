#!/usr/bin/env python3
"""Smoke-check the NIP-59 live static browser global without enabling send."""

from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

LOCAL_BUNDLE = Path("app/static/js/nip59_client_bundle.js")

REQUIRED_TERMS = [
    "HODLXXINip59Bundle",
    'status: "generated-experiment-no-send"',
    "cryptoReady: false",
    "canFinalizeGiftWrap: false",
    "canPostEnvelope: false",
    "relayPublishing: false",
    "plaintextPost: false",
    "sendEnabled: false",
    "createLocalProbeEvent",
]

FORBIDDEN_TERMS = [
    "@nostr/tools/wasm",
    "nostr-wasm",
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
]


def read_source(source: str | None) -> tuple[str, str]:
    if not source:
        return str(LOCAL_BUNDLE), LOCAL_BUNDLE.read_text(encoding="utf-8", errors="replace")
    if source.startswith(("http://", "https://")):
        request = urllib.request.Request(source, headers={"User-Agent": "hodlxxi-nip59-smoke/1.0"})
        with urllib.request.urlopen(request, timeout=15) as response:
            return source, response.read().decode("utf-8", errors="replace")
    path = Path(source)
    return str(path), path.read_text(encoding="utf-8", errors="replace")


def inspect_bundle(text: str) -> list[str]:
    errors: list[str] = []
    for term in REQUIRED_TERMS:
        if term not in text:
            errors.append(f"missing required term: {term}")
    for term in FORBIDDEN_TERMS:
        if term in text:
            errors.append(f"forbidden delivery/network term present: {term}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=None)
    args = parser.parse_args()
    source, text = read_source(args.source)
    errors = inspect_bundle(text)
    if errors:
        print(f"FAIL: NIP-59 browser global no-send smoke failed for {source}", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("ok: NIP-59 browser global no-send smoke holds")
    print(f"source={source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

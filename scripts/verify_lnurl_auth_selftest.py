#!/usr/bin/env python3
"""Self-test LNURL-auth callback verification against a running HODLXXI base URL."""

import os
import sys
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from coincurve import PrivateKey


def force_base(base: str, url_or_path: str) -> str:
    """Resolve a returned LNURL-auth URL/path against BASE while preserving path/query."""
    base_parts = urlparse(base)
    parsed = urlparse(url_or_path)
    if parsed.scheme and parsed.netloc:
        return urlunparse((base_parts.scheme, base_parts.netloc, parsed.path, "", parsed.query, ""))
    return urljoin(base.rstrip("/") + "/", url_or_path.lstrip("/"))


def main() -> int:
    base = os.environ.get("BASE", "http://127.0.0.1:5000")

    create_response = requests.post(force_base(base, "/api/lnurl-auth/create"), timeout=10)
    create_response.raise_for_status()
    session = create_response.json()

    session_id = session["session_id"]
    params_url = session["params_url"]

    params_response = requests.get(force_base(base, params_url), timeout=10)
    params_response.raise_for_status()
    params = params_response.json()
    if params.get("tag") != "login" or not params.get("k1") or not params.get("callback"):
        print(f"invalid params response: {params}", file=sys.stderr)
        return 1

    k1 = params["k1"]
    if session.get("k1") and session["k1"] != k1:
        print(f"create k1 does not match params k1: {session['k1']} != {k1}", file=sys.stderr)
        return 1

    private_key = PrivateKey()
    sig = private_key.sign(bytes.fromhex(k1), hasher=None).hex()
    key = private_key.public_key.format(compressed=True).hex()

    callback_response = requests.get(
        force_base(base, params["callback"]),
        params={"k1": k1, "sig": sig, "key": key},
        timeout=10,
    )
    callback_response.raise_for_status()
    callback_body = callback_response.json()
    if callback_body != {"status": "OK"}:
        print(f"callback failed: {callback_body}", file=sys.stderr)
        return 1

    check_response = requests.get(force_base(base, f"/api/lnurl-auth/check/{session_id}"), timeout=10)
    check_response.raise_for_status()
    check_body = check_response.json()
    if check_body != {"verified": True, "pubkey": key}:
        print(f"verification check failed: {check_body}", file=sys.stderr)
        return 1

    print(f"LNURL-auth selftest OK for {base} session={session_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

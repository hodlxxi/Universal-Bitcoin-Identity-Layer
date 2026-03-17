#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import secrets
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

import requests
from coincurve import PrivateKey

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CHARSET_REV = {c: i for i, c in enumerate(CHARSET)}


def bech32_polymod(values: List[int]) -> int:
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generator[i]
    return chk


def bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp: str, data: List[int]) -> bool:
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_decode(bech: str) -> Tuple[Optional[str], Optional[List[int]]]:
    if not bech:
        return None, None
    if bech.lower() != bech and bech.upper() != bech:
        return None, None
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech):
        return None, None
    hrp = bech[:pos]
    data_part = bech[pos + 1 :]
    try:
        data = [CHARSET_REV[c] for c in data_part]
    except KeyError:
        return None, None
    if not bech32_verify_checksum(hrp, data):
        return None, None
    return hrp, data[:-6]


def convertbits(data: List[int], frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
    acc = 0
    bits = 0
    ret: List[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def decode_lnurl(lnurl: str) -> str:
    hrp, data = bech32_decode(lnurl.strip())
    if hrp is None or data is None:
        raise ValueError("Invalid LNURL bech32 string")
    decoded = convertbits(data, 5, 8, False)
    if decoded is None:
        raise ValueError("Failed to convert LNURL bits")
    return bytes(decoded).decode("utf-8")


DEFAULT_TIMEOUT = 20


def http_get_json(url: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


def http_post_json(url: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    r = requests.post(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


def sha256_hex_bytes(hex_str: str) -> bytes:
    return hashlib.sha256(bytes.fromhex(hex_str)).digest()


def normalize_base(base: str) -> str:
    return base.rstrip("/")


def create_session(base: str) -> Dict[str, Any]:
    url = f"{normalize_base(base)}/api/lnurl-auth/create"
    return http_post_json(url)


def fetch_params(base: str, sid: str) -> Dict[str, Any]:
    url = f"{normalize_base(base)}/api/lnurl-auth/params?sid={sid}"
    return http_get_json(url)


def fetch_check(base: str, sid: str) -> Dict[str, Any]:
    url = f"{normalize_base(base)}/api/lnurl-auth/check/{sid}"
    return http_get_json(url)


def sign_k1(k1_hex: str, privkey_hex: str) -> Tuple[str, str]:
    priv = PrivateKey(bytes.fromhex(privkey_hex))
    digest = sha256_hex_bytes(k1_hex)
    signature_der = priv.sign(digest, hasher=None)
    pubkey_hex = priv.public_key.format(compressed=True).hex()
    return signature_der.hex(), pubkey_hex


def call_callback(callback_url: str, k1_hex: str, sig_hex: str, pubkey_hex: str) -> Dict[str, Any]:
    sep = "&" if "?" in callback_url else "?"
    url = f"{callback_url}{sep}k1={k1_hex}&sig={sig_hex}&key={pubkey_hex}"
    return http_get_json(url)


def generate_privkey_hex() -> str:
    return secrets.token_hex(32)


def load_or_generate_privkey(path: Optional[str], explicit_hex: Optional[str]) -> str:
    if explicit_hex:
        explicit_hex = explicit_hex.strip().lower()
        if len(explicit_hex) != 64:
            raise ValueError("Private key hex must be 64 hex chars")
        int(explicit_hex, 16)
        return explicit_hex

    if path:
        if os.path.exists(path):
            val = open(path, "r", encoding="utf-8").read().strip().lower()
            if len(val) != 64:
                raise ValueError(f"Invalid key file at {path}")
            int(val, 16)
            return val
        key = generate_privkey_hex()
        with open(path, "w", encoding="utf-8") as f:
            f.write(key + "\n")
        os.chmod(path, 0o600)
        return key

    return generate_privkey_hex()


def run_full_flow(
    base: str,
    privkey_hex: Optional[str],
    keyfile: Optional[str],
    print_secret: bool = False,
) -> Dict[str, Any]:
    created = create_session(base)
    sid = created.get("session_id")
    if not sid:
        raise RuntimeError(f"No session_id returned: {created}")

    params = fetch_params(base, sid)
    k1 = params.get("k1")
    callback = params.get("callback")
    if not k1 or not callback:
        raise RuntimeError(f"Missing k1/callback from params: {params}")

    key_hex = load_or_generate_privkey(keyfile, privkey_hex)
    sig_hex, pubkey_hex = sign_k1(k1, key_hex)
    cb = call_callback(callback, k1, sig_hex, pubkey_hex)
    checked = fetch_check(base, sid)

    out = {
        "create": created,
        "params": params,
        "callback_result": cb,
        "check": checked,
        "pubkey": pubkey_hex,
    }
    if print_secret:
        out["privkey_hex"] = key_hex
    return out


def cmd_create(args: argparse.Namespace) -> int:
    print(json.dumps(create_session(args.base), indent=2, ensure_ascii=False))
    return 0


def cmd_params(args: argparse.Namespace) -> int:
    print(json.dumps(fetch_params(args.base, args.sid), indent=2, ensure_ascii=False))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    print(json.dumps(fetch_check(args.base, args.sid), indent=2, ensure_ascii=False))
    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    print(decode_lnurl(args.lnurl))
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    key_hex = load_or_generate_privkey(args.keyfile, args.privkey_hex)
    sig_hex, pubkey_hex = sign_k1(args.k1, key_hex)
    out = {
        "k1": args.k1,
        "pubkey": pubkey_hex,
        "signature_der_hex": sig_hex,
    }
    if args.print_secret:
        out["privkey_hex"] = key_hex
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


def cmd_callback(args: argparse.Namespace) -> int:
    print(json.dumps(call_callback(args.callback_url, args.k1, args.sig_hex, args.pubkey_hex), indent=2, ensure_ascii=False))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    result = run_full_flow(
        base=args.base,
        privkey_hex=args.privkey_hex,
        keyfile=args.keyfile,
        print_secret=args.print_secret,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="LNURL-auth CLI tool for HODLXXI / UBID")
    sub = p.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create")
    p_create.add_argument("--base", required=True)
    p_create.set_defaults(func=cmd_create)

    p_params = sub.add_parser("params")
    p_params.add_argument("--base", required=True)
    p_params.add_argument("--sid", required=True)
    p_params.set_defaults(func=cmd_params)

    p_check = sub.add_parser("check")
    p_check.add_argument("--base", required=True)
    p_check.add_argument("--sid", required=True)
    p_check.set_defaults(func=cmd_check)

    p_decode = sub.add_parser("decode")
    p_decode.add_argument("--lnurl", required=True)
    p_decode.set_defaults(func=cmd_decode)

    p_sign = sub.add_parser("sign")
    p_sign.add_argument("--k1", required=True)
    p_sign.add_argument("--privkey-hex")
    p_sign.add_argument("--keyfile")
    p_sign.add_argument("--print-secret", action="store_true")
    p_sign.set_defaults(func=cmd_sign)

    p_cb = sub.add_parser("callback")
    p_cb.add_argument("--callback-url", required=True)
    p_cb.add_argument("--k1", required=True)
    p_cb.add_argument("--sig-hex", required=True)
    p_cb.add_argument("--pubkey-hex", required=True)
    p_cb.set_defaults(func=cmd_callback)

    p_run = sub.add_parser("run")
    p_run.add_argument("--base", required=True)
    p_run.add_argument("--privkey-hex")
    p_run.add_argument("--keyfile")
    p_run.add_argument("--print-secret", action="store_true")
    p_run.set_defaults(func=cmd_run)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except requests.HTTPError as e:
        resp = e.response
        body = resp.text if resp is not None else ""
        print(json.dumps({
            "error": "http_error",
            "status_code": resp.status_code if resp is not None else None,
            "body": body,
        }, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1
    except Exception as e:
        print(json.dumps({"error": str(e)}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import os
import json
import subprocess
from typing import Any

from flask import Blueprint, jsonify, session

lnd_status_bp = Blueprint("lnd_status", __name__)


def _env_first(*names: str) -> str:
    for name in names:
        value = (os.getenv(name) or "").strip()
        if value:
            return value
    return ""


def resolve_lnd_env() -> dict[str, Any]:
    """Resolve LND status command env without exposing secret values.

    Canonical names are preferred. Legacy helper names remain as fallbacks
    while older systemd drop-ins and code paths are retired safely.
    """
    lncli_bin = _env_first("LND_LNCLI_BIN") or "lncli"
    rpcserver = _env_first("LND_RPCSERVER")
    tlscertpath = _env_first("LND_TLSCERTPATH", "LND_TLS_CERT")
    macaroonpath = _env_first("LND_MACAROONPATH", "LND_READONLY_MACAROON")

    return {
        "lncli_bin": lncli_bin,
        "rpcserver": rpcserver,
        "tlscertpath": tlscertpath,
        "macaroonpath": macaroonpath,
        "has_rpcserver": bool(rpcserver),
        "has_tlscertpath": bool(tlscertpath),
        "has_macaroonpath": bool(macaroonpath),
    }


def build_lnd_base_command() -> list[str]:
    resolved = resolve_lnd_env()
    cmd = [resolved["lncli_bin"]]

    if resolved["rpcserver"]:
        cmd.append(f"--rpcserver={resolved['rpcserver']}")
    if resolved["tlscertpath"]:
        cmd.append(f"--tlscertpath={resolved['tlscertpath']}")
    if resolved["macaroonpath"]:
        cmd.append(f"--macaroonpath={resolved['macaroonpath']}")

    return cmd


def build_lnd_getinfo_command() -> list[str]:
    return build_lnd_base_command() + ["getinfo"]


def run_lnd_json(args: list[str], timeout: float = 8.0) -> dict[str, Any]:
    result = subprocess.run(
        build_lnd_base_command() + args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    if result.returncode != 0:
        msg = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(msg[:300] if msg else "lncli error")

    out = (result.stdout or "").strip()
    return json.loads(out) if out else {}


def _logged_in_pubkey() -> str:
    return (session.get("logged_in_pubkey") or session.get("pubkey") or "").strip()


def _access_level() -> str:
    return (session.get("access_level") or "").strip().lower()


@lnd_status_bp.route("/api/lnd/status", methods=["GET"])
def api_lnd_status():
    if not _logged_in_pubkey():
        return jsonify({"error": "Not logged in", "ok": False}), 401
    if _access_level() != "full":
        return jsonify({"error": "Full access required", "ok": False}), 403

    resolved = resolve_lnd_env()
    missing = [
        name
        for name, present in (
            ("LND_RPCSERVER", resolved["has_rpcserver"]),
            ("LND_TLSCERTPATH", resolved["has_tlscertpath"]),
            ("LND_MACAROONPATH", resolved["has_macaroonpath"]),
        )
        if not present
    ]

    if missing:
        return (
            jsonify(
                {
                    "ok": False,
                    "active": False,
                    "state": "missing_env",
                    "missing": missing,
                }
            ),
            503,
        )

    try:
        try:
            timeout = float(os.getenv("LND_STATUS_TIMEOUT", "8.0"))
        except Exception:
            timeout = 8.0

        info = run_lnd_json(["getinfo"], timeout=timeout)
        wb = run_lnd_json(["walletbalance"], timeout=timeout)
        cb = run_lnd_json(["channelbalance"], timeout=timeout)
        ch = run_lnd_json(["listchannels"], timeout=max(timeout, 12.0))

        chans = ch.get("channels") or []
        local_sum = sum(int(x.get("local_balance") or 0) for x in chans)
        remote_sum = sum(int(x.get("remote_balance") or 0) for x in chans)

        return jsonify(
            {
                "ok": True,
                "active": True,
                "state": "active",
                "getinfo": {
                    "alias": info.get("alias"),
                    "synced_to_chain": info.get("synced_to_chain"),
                    "synced_to_graph": info.get("synced_to_graph"),
                    "block_height": info.get("block_height"),
                    "num_peers": info.get("num_peers"),
                    "num_active_channels": info.get("num_active_channels"),
                },
                "walletbalance": {
                    "confirmed_balance": wb.get("confirmed_balance"),
                    "unconfirmed_balance": wb.get("unconfirmed_balance"),
                    "total_balance": wb.get("total_balance"),
                },
                "channelbalance": {
                    "balance": cb.get("balance"),
                    "pending_open_balance": cb.get("pending_open_balance"),
                },
                "channels_summary": {
                    "count": len(chans),
                    "local_sum": local_sum,
                    "remote_sum": remote_sum,
                },
            }
        )
    except Exception:
        return jsonify({"ok": False, "active": False, "error": "Internal server error"}), 200

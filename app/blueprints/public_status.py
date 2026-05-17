from __future__ import annotations

import os
import subprocess
import time
from typing import Any

from flask import Blueprint, jsonify

from bitcoinrpc.authproxy import AuthServiceProxy

from app.socket_state import ACTIVE_SOCKETS, ONLINE_META, ONLINE_USERS

public_status_bp = Blueprint("public_status", __name__)

_PROCESS_START_TIME = time.time()
_BTC_CACHE: dict[str, Any] = {}
_BTC_CACHE_TTL_SECONDS = 10
_LND_CACHE: dict[str, Any] = {}
_LND_CACHE_TTL_SECONDS = 10


def _empty_btc_status() -> dict[str, Any]:
    return {
        "chain": None,
        "block_height": None,
        "headers": None,
        "ibd": None,
        "verificationprogress": None,
        "mempool_size": None,
        "mempool_bytes": None,
        "peers": None,
        "error": None,
    }


def _safe_btc_status() -> dict[str, Any]:
    global _BTC_CACHE

    now = time.time()
    if _BTC_CACHE and (now - float(_BTC_CACHE.get("ts", 0))) < _BTC_CACHE_TTL_SECONDS:
        cached = _BTC_CACHE.get("data")
        if isinstance(cached, dict):
            return dict(cached)

    btc = _empty_btc_status()

    rpc_user = (os.getenv("RPC_USER") or "").strip()
    rpc_pass = os.getenv("RPC_PASSWORD") or ""
    rpc_host = (os.getenv("RPC_HOST") or "127.0.0.1").strip()
    rpc_port = (os.getenv("RPC_PORT") or "8332").strip()
    rpc_wallet = (os.getenv("RPC_WALLET") or "").strip()

    if not rpc_user or not rpc_pass or not rpc_wallet:
        btc["error"] = "rpc_error:missing_env"
        return btc

    try:
        try:
            timeout = float(os.getenv("PUBLIC_STATUS_BTC_RPC_TIMEOUT", "2.0"))
        except Exception:
            timeout = 2.0

        url = f"http://{rpc_user}:{rpc_pass}@{rpc_host}:{rpc_port}/wallet/{rpc_wallet}"
        rpc = AuthServiceProxy(url, timeout=timeout)
        btc["block_height"] = int(rpc.getblockcount())
        _BTC_CACHE = {"ts": now, "data": btc}
        return btc
    except Exception as e:
        cached = _BTC_CACHE.get("data") if isinstance(_BTC_CACHE, dict) else None
        if isinstance(cached, dict) and cached:
            btc = dict(cached)
            btc["cached"] = True
            btc["cache_reason"] = e.__class__.__name__
            return btc
        btc["error"] = f"rpc_error:{e.__class__.__name__}"
        return btc


def _safe_lnd_status() -> dict[str, Any]:
    global _LND_CACHE

    now = time.time()
    if _LND_CACHE and (now - float(_LND_CACHE.get("ts", 0))) < _LND_CACHE_TTL_SECONDS:
        cached = _LND_CACHE.get("data")
        if isinstance(cached, dict):
            return dict(cached)

    try:
        try:
            timeout = float(os.getenv("PUBLIC_STATUS_LND_SYSTEMCTL_TIMEOUT", "2.0"))
        except Exception:
            timeout = 2.0

        r = subprocess.run(
            ["systemctl", "is-active", "lnd.service"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        state = (r.stdout or "").strip() or (r.stderr or "").strip() or "unknown"
        lnd = {"active": True if state == "active" else False, "state": state}
        _LND_CACHE = {"ts": now, "data": lnd}
        return lnd
    except Exception as e:
        cached = _LND_CACHE.get("data") if isinstance(_LND_CACHE, dict) else None
        if isinstance(cached, dict) and cached:
            lnd = dict(cached)
            lnd["cached"] = True
            lnd["cache_reason"] = e.__class__.__name__
            return lnd
        return {"active": False, "state": f"unknown:{e.__class__.__name__}"}


def _online_role_counts() -> dict[str, int]:
    roles = {"full": 0, "limited": 0, "pin": 0, "random": 0, "other": 0}
    for pk in list(ONLINE_USERS):
        role = ONLINE_META.get(pk) or "other"
        if role not in roles:
            role = "other"
        roles[role] += 1
    return roles


@public_status_bp.route("/api/public/status", methods=["GET"])
def api_public_status():
    now = int(time.time())
    iso = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now))

    btc = _safe_btc_status()
    lnd = _safe_lnd_status()

    try:
        uptime_sec = int(time.time() - _PROCESS_START_TIME)
    except Exception:
        uptime_sec = None

    try:
        l1, l5, l15 = os.getloadavg()
        load = {"1": l1, "5": l5, "15": l15}
    except Exception:
        load = None

    height = btc.get("block_height")
    err = btc.get("error")

    return jsonify(
        {
            "server_time_epoch": now,
            "server_time_utc": iso,
            "block_height": height,
            "error": err,
            "online_users": len(ONLINE_USERS),
            "active_sockets": len(ACTIVE_SOCKETS),
            "online_roles": _online_role_counts(),
            "uptime_sec": uptime_sec,
            "load": load,
            "btc": btc,
            "lnd": lnd,
        }
    )

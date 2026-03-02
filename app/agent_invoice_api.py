import os, json, subprocess, hmac
from flask import Blueprint, request, jsonify

bp = Blueprint("agent_invoice_api", __name__)

LNCLI = os.environ.get("LNCLI_BIN", "/usr/local/bin/lncli")
LND_RPC = os.environ.get("LND_RPCSERVER", "127.0.0.1:10009")
LND_TLS = os.environ.get("LND_TLS_CERT", "/etc/hodlxxi/secrets/lnd.tls.cert")
LND_MAC = os.environ.get("LND_INVOICE_MACAROON", "/etc/hodlxxi/secrets/lnd-invoice.macaroon")
AGENT_TOKEN = os.environ.get("AGENT_INVOICE_TOKEN", "")

# IMPORTANT: under ProtectSystem=strict + ReadWritePaths, keep lncli state in /srv/ubid/runtime
LNDIR = os.environ.get("LNCLI_LNDDIR", "/srv/ubid/runtime/lncli")

def _auth_ok() -> bool:
    got = (request.headers.get("Authorization") or "").strip()
    if not got.startswith("Bearer "):
        return False
    tok = got.split(" ", 1)[1].strip()
    return bool(AGENT_TOKEN) and hmac.compare_digest(tok, AGENT_TOKEN)

def _local_only() -> bool:
    # Allow ONLY direct loopback calls (agent -> http://127.0.0.1:5000).
    # If request came through nginx proxy, it typically carries X-Forwarded-* headers.
    if request.headers.get("X-Forwarded-For") or request.headers.get("X-Real-IP"):
        return False
    return request.remote_addr in ("127.0.0.1", "::1")

def _lncli(args: list[str], timeout: int = 8) -> dict:
    os.makedirs(LNDIR, exist_ok=True)
    cmd = [
        LNCLI,
        f"--rpcserver={LND_RPC}",
        f"--lnddir={LNDIR}",
        f"--tlscertpath={LND_TLS}",
        f"--macaroonpath={LND_MAC}",
        *args,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or "").strip()[:500])
    return json.loads(p.stdout)

@bp.post("/api/internal/agent/invoice")
def agent_create_invoice():
    if not _local_only():
        return jsonify({"ok": False, "error": "forbidden"}), 403
    if not _auth_ok():
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    j = request.get_json(force=True, silent=True) or {}
    amt = int(j.get("amt_sat") or 0)
    memo = str(j.get("memo") or "")[:120]

    if amt <= 0 or amt > 200000:
        return jsonify({"ok": False, "error": "bad amt_sat"}), 400

    try:
        res = _lncli(["addinvoice", f"--amt={amt}", f"--memo={memo}"])
        return jsonify({
            "ok": True,
            "r_hash": res.get("r_hash"),
            "payment_request": res.get("payment_request"),
            "add_index": res.get("add_index"),
            "payment_addr": res.get("payment_addr"),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:300]}), 500

@bp.get("/api/internal/agent/invoice/<rhash>")
def agent_lookup_invoice(rhash: str):
    if not _local_only():
        return jsonify({"ok": False, "error": "forbidden"}), 403
    if not _auth_ok():
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    rhash = (rhash or "").strip()
    if len(rhash) != 64:
        return jsonify({"ok": False, "error": "bad rhash"}), 400

    try:
        res = _lncli(["lookupinvoice", rhash])
        # Don't ever leak preimage
        if isinstance(res, dict):
            res.pop("r_preimage", None)
        return jsonify({"ok": True, "invoice": res})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:300]}), 500

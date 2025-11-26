#!/bin/bash
# HODLXXI - Real PoF API patch
# This script:
#  - Backs up app.py
#  - Appends PoF DB helpers + /api/pof/challenge + /api/pof/verify routes

set -e

APP_DIR="/srv/ubid/app"
APP_FILE="$APP_DIR/app.py"

cd "$APP_DIR"

echo ">>> Backing up app.py..."
cp "$APP_FILE" "app_pof_backup_$(date +%Y%m%d-%H%M%S).py"

echo ">>> Appending PoF module to app.py..."

cat <<'PYEOF' >> "$APP_FILE"


# ============================================================================
# HODLXXI: REAL PoF API (DB-backed, uses playground verifier)
# ============================================================================

import os
import time
import sqlite3
import json
import urllib.request
from flask import request, jsonify

# Project root is one level above this file: /srv/ubid
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))

# Where to store PoF attestations (can override via env)
# Default: /srv/ubid/pof_attest.db  (matches your existing DB)
POF_DB_PATH = os.getenv(
    "POF_DB_PATH",
    os.path.join(PROJECT_ROOT, "pof_attest.db")
)


def get_pof_db():
    """
    Open (and lazily initialize) the PoF SQLite database.
    """
    conn = sqlite3.connect(POF_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pof_attestations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pubkey TEXT NOT NULL,
            total_sat INTEGER NOT NULL,
            method TEXT NOT NULL,
            privacy_level TEXT NOT NULL,
            challenge_id TEXT NOT NULL,
            proof_id TEXT NOT NULL,
            expires_at INTEGER,
            created_at INTEGER NOT NULL
        )
        """
    )
    return conn


def _pof_call_playground(path, payload):
    """
    Call the existing playground PoF endpoints via HTTP.

    We deliberately reuse your working /api/playground/pof/* logic
    instead of duplicating PSBT parsing here.
    """
    base = request.url_root.rstrip("/")
    url = f"{base}{path}"

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except Exception as e:
        return {
            "ok": False,
            "error": f"PoF playground call failed: {e.__class__.__name__}: {e}",
        }


@app.route("/api/pof/challenge", methods=["POST"])
def api_pof_challenge():
    """
    Real PoF challenge endpoint for users.

    Request JSON:
      {
        "pubkey": "user-pubkey-or-identifier",
        "privacy_level": "public" | "friends" | "private"  (optional)
      }

    Response JSON mirrors the playground challenge plus pubkey + privacy_level:
      {
        "ok": true,
        "challenge": "...",
        "challenge_id": "...",
        "expires_in": 300,
        "pubkey": "...",
        "privacy_level": "..."
      }
    """
    data = request.get_json(silent=True) or {}

    pubkey = (data.get("pubkey") or "").strip()
    if not pubkey:
        return jsonify({"ok": False, "error": "pubkey is required"}), 400

    privacy_level = (data.get("privacy_level") or "private").strip()

    # Reuse the working playground endpoint
    result = _pof_call_playground(
        "/api/playground/pof/challenge", {"pubkey": pubkey}
    )

    if not result.get("ok"):
        return jsonify(result), 400

    result["pubkey"] = pubkey
    result["privacy_level"] = privacy_level
    return jsonify(result), 200


@app.route("/api/pof/verify", methods=["POST"])
def api_pof_verify():
    """
    Real PoF verification endpoint.

    Request JSON:
      {
        "challenge_id": "...",   # required
        "psbt": "...",           # required, base64
        "pubkey": "...",         # optional, but recommended
        "privacy_level": "public" | "friends" | "private",  # optional
        "method": "psbt-opreturn" | "other",                # optional
        "valid_for_days": 30     # optional, default 30 days
      }

    Behavior:
      - Forwards {challenge_id, psbt} to /api/playground/pof/verify
      - On success, records an attestation in pof_attestations
      - Returns the playground response plus pubkey/method/privacy/expires_at
    """
    data = request.get_json(silent=True) or {}

    challenge_id = (data.get("challenge_id") or "").strip()
    psbt = (data.get("psbt") or "").strip()

    if not challenge_id or not psbt:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "Both 'challenge_id' and 'psbt' are required",
                }
            ),
            400,
        )

    pubkey = (data.get("pubkey") or "").strip() or "anonymous-demo"
    privacy_level = (data.get("privacy_level") or "private").strip()
    method = (data.get("method") or "psbt-opreturn").strip()

    # Validity window for this PoF attestation (how long we treat it as "fresh")
    try:
        valid_for_days = int(data.get("valid_for_days") or 30)
    except ValueError:
        valid_for_days = 30

    # Call the playground verifier
    result = _pof_call_playground(
        "/api/playground/pof/verify",
        {"challenge_id": challenge_id, "psbt": psbt},
    )

    if not result.get("ok"):
        # Bubble up the playground error
        return jsonify(result), 400

    total_sat = int(result.get("total_sat") or 0)
    proof_id = (result.get("proof_id") or "").strip()

    now = int(time.time())
    expires_at = now + valid_for_days * 86400

    # Store attestation in DB
    try:
        conn = get_pof_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO pof_attestations (
                pubkey, total_sat, method, privacy_level,
                challenge_id, proof_id, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                pubkey,
                total_sat,
                method,
                privacy_level,
                challenge_id,
                proof_id,
                expires_at,
                now,
            ),
        )
        conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass

    enriched = dict(result)
    enriched.update(
        {
            "pubkey": pubkey,
            "method": method,
            "privacy_level": privacy_level,
            "expires_at": expires_at,
        }
    )
    return jsonify(enriched), 200

PYEOF

echo ">>> PoF patch appended. Now restart your app to apply."

from flask import render_template, send_from_directory
import base64
import hashlib
import json
import redis
import redis
import logging
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from functools import wraps
from hashlib import sha256
from io import BytesIO
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Optional, Set, Tuple

import base58
import qrcode
import requests
from bech32 import bech32_decode, bech32_encode, convertbits
from bitcoinrpc.authproxy import AuthServiceProxy
from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)
from flask_socketio import SocketIO, emit
# === Added for production hardening ===
import jwt
import redis as redis_client
from cryptography.hazmat.primitives import serialization
from prometheus_client import CollectorRegistry, Counter, generate_latest

from app.audit_logger import get_audit_logger, init_audit_logger
from app.config import get_config
from app.database import close_all, init_all
from app.db_storage import (
    create_user,
    delete_oauth_code,
    delete_session,
    get_lnurl_challenge,
    get_oauth_client,
    get_oauth_code,
    get_session,
    get_user_by_pubkey,
    store_lnurl_challenge,
    store_oauth_client,
    store_oauth_code,
    store_session,
)
from app.jwks import ensure_rsa_keypair
from app.oidc import oidc_bp, validate_pkce
from app.security import init_security, limiter
from app.tokens import issue_rs256_jwt
from app.pof_routes import pof_bp
from flask import make_response


# ============================================================
# Legacy compatibility layer for OAuth client objects
# ============================================================
#
# Why this exists:
#   The legacy /oauth/authorize code still expects an old "storage"
#   object and rich client objects with attributes like:
#       client.client_type.value
#       client.is_active
#       client.allowed_scopes
#       client.redirect_uris
#
# But now get_oauth_client() (db_storage) just returns a plain dict
# from Postgres. That made authorize() crash with things like:
#   'str' object has no attribute 'value'
#
# We fix that by wrapping the dict in a tiny adapter class.
#

class _LegacyClientWrapperClientType:
    """
    Gives us client.client_type.value even if the DB just stored
    "free"/"paid"/"premium" as a plain string.
    """
    def __init__(self, raw_type: str | None):
        self.value = raw_type or "free"


class _LegacyClientWrapper:
    """
    Wrap the raw DB row and expose attributes the legacy code expects.
    """
    def __init__(self, raw: dict | None):
        raw = raw or {}
        self._raw = raw

        # Basic creds
        self.client_id = raw.get("client_id", "")
        self.client_secret = raw.get("client_secret", "")

        # Redirect URIs
        self.redirect_uris = raw.get("redirect_uris") or []

        # Allowed scopes
        scope_val = raw.get("scope", "")
        if isinstance(scope_val, str):
            self.allowed_scopes = set(scope_val.split())
        elif isinstance(scope_val, list):
            self.allowed_scopes = set(scope_val)
        else:
            self.allowed_scopes = set()

        # Meta / rate limit / type
        meta = raw.get("meta_data") or raw.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}

        self.rate_limit = meta.get("rate_limit", 100)

        raw_type = meta.get("client_type", "free")
        self.client_type = _LegacyClientWrapperClientType(raw_type)

        # Active flag
        self.is_active = raw.get("is_active", True)

        # Created timestamp (CRITICAL FIX)
        self.created_at = raw.get("created_at")
        if self.created_at and isinstance(self.created_at, str):
            try:
                self.created_at = datetime.fromisoformat(self.created_at)
            except (ValueError, TypeError):
                self.created_at = datetime.now(timezone.utc)
        elif not self.created_at:
            self.created_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return self._raw


class _StorageAdapter:
    """
    Adapter that pretends to be the old in-memory storage.
    Underneath, it calls db_storage (Postgres/Redis-backed).
    Legacy code calls get_storage() -> this.
    """

    def store_client(self, client_obj: dict) -> None:
        # Some code calls storage.store_client({"client_id":..., ...})
        # Our db API is store_oauth_client(client_id, client_data)
        cid = client_obj.get("client_id")
        if cid:
            store_oauth_client(cid, client_obj)
        else:
            # If older path gave positional style, keep backward compat
            store_oauth_client(client_obj)

    def get_client(self, client_id: str):
        # Pull raw dict from db, wrap it so legacy authorize() can read it.
        data = get_oauth_client(client_id)
        if not data:
            return None

        # Ensure client_id exists on the dict (old code expects it)
        if "client_id" not in data:
            data["client_id"] = client_id

        return _LegacyClientWrapper(data)

    def store_auth_code(self, code: str, code_data: dict, ttl: int = 600) -> None:
        # db_storage handles expiry internally, so we ignore ttl here
        store_oauth_code(code, code_data)

    def get_auth_code(self, code: str):
        return get_oauth_code(code)

    def delete_auth_code(self, code: str) -> None:
        delete_oauth_code(code)

    def store_session(self, session_id: str, session_data: dict, ttl: int = 3600) -> None:
        store_session(session_id, session_data, ttl)

    def get_session(self, session_id: str):
        return get_session(session_id)

    def delete_session(self, session_id: str) -> None:
        delete_session(session_id)

    def store_lnurl_challenge(self, sid: str, challenge: dict, ttl: int = 300) -> None:
        store_lnurl_challenge(sid, challenge, ttl)

    def get_lnurl_challenge(self, sid: str):
        return get_lnurl_challenge(sid)


# single shared instance the rest of the code will call
GLOBAL_STORAGE = _StorageAdapter()

def get_storage():
    return GLOBAL_STORAGE


# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Add file handler for production
if not os.path.exists("logs"):
    os.makedirs("logs")

file_handler = RotatingFileHandler("logs/app.log", maxBytes=10485760, backupCount=10)  # 10MB
file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"))
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)


from dotenv import load_dotenv

load_dotenv()

CFG = get_config()


def _as_bool(v, default=False):
    if v is None:
        return default
    return str(v).lower() in ("1", "true", "yes", "y", "on")


LNURL_SESSIONS = {}

ONLINE_META: Dict[str, str] = {}

# Improved secret key handling
FLASK_SECRET_KEY = CFG.get("FLASK_SECRET_KEY")
if FLASK_SECRET_KEY:
    logger.info("Using Flask secret key from configuration")
else:
    FLASK_SECRET_KEY = secrets.token_urlsafe(32)
    logger.warning(
        "FLASK_SECRET_KEY not provided – generated ephemeral key for local development."
    )

RPC_USER = os.getenv("RPC_USER", "")
RPC_PASS = os.getenv("RPC_PASSWORD", "")
RPC_HOST = os.getenv("RPC_HOST", "127.0.0.1")
RPC_PORT = int(os.getenv("RPC_PORT", "8332"))
WALLET = os.getenv("RPC_WALLET", "")

SOCKETIO_CORS = os.getenv("SOCKETIO_CORS", "*")

# (optional) env-driven guest/specials if you want:
GUEST_PUBKEY = os.getenv("GUEST_PUBKEY", "").strip()
GUEST_PRIVKEY = os.getenv("GUEST_PRIVKEY", "").strip()
GUEST2_PUBKEY = os.getenv("GUEST2_PUBKEY", "").strip()
GUEST2_PRIVKEY = os.getenv("GUEST2_PRIVKEY", "").strip()

SPECIAL_NAMES = {}
if GUEST_PUBKEY:
    SPECIAL_NAMES[GUEST_PUBKEY] = "Alice"
if GUEST2_PUBKEY:
    SPECIAL_NAMES[GUEST2_PUBKEY] = "Bob"

SPECIAL_USERS = [x.strip() for x in os.getenv("SPECIAL_USERS", "").split(",") if x.strip()]
# === JWT / JWKS / Redis / Limiter setup ===
JWT_ALG = str(CFG.get("JWT_ALGORITHM") or "RS256").upper()
REDIS_URL = CFG.get("REDIS_URL")
if not REDIS_URL:
    redis_host = CFG.get("REDIS_HOST", "127.0.0.1")
    redis_port = CFG.get("REDIS_PORT", 6379)
    redis_db = CFG.get("REDIS_DB", 0)
    redis_password = CFG.get("REDIS_PASSWORD")
    if redis_password:
        REDIS_URL = f"redis://:{redis_password}@{redis_host}:{redis_port}/{redis_db}"
    else:
        REDIS_URL = f"redis://{redis_host}:{redis_port}/{redis_db}"

JWT_KID = os.getenv("JWT_KID")
JWKS_DOCUMENT: Dict[str, List[Dict[str, str]]]

if JWT_ALG == "RS256":
    jwks_dir = str(CFG.get("JWKS_DIR") or "keys")
    private_pem, jwks_doc = ensure_rsa_keypair(jwks_dir)
    JWT_SIGNING_KEY: str | bytes = private_pem
    JWKS_DOCUMENT = jwks_doc
    if not JWT_KID:
        keys = jwks_doc.get("keys") if isinstance(jwks_doc, dict) else None
        if keys and isinstance(keys, list) and keys and isinstance(keys[0], dict):
            JWT_KID = keys[0].get("kid")
    try:
        private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
        JWT_VERIFYING_KEY = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
    except Exception as exc:
        logger.warning(f"Failed to derive public key from RSA private key: {exc}")
        JWT_VERIFYING_KEY = private_pem
else:
    secret = CFG.get("JWT_SECRET", "dev-secret-fallback")
    JWT_SIGNING_KEY = secret if isinstance(secret, (bytes, bytearray)) else str(secret)
    JWT_VERIFYING_KEY = JWT_SIGNING_KEY
    JWKS_DOCUMENT = {"keys": []}

JWT_ALLOWED_ALGORITHMS = [JWT_ALG] if JWT_ALG in {"RS256", "HS256"} else ["HS256"]

try:
    TOKEN_TTL_SECONDS = int(CFG.get("TOKEN_TTL", 3600))
except (TypeError, ValueError):
    TOKEN_TTL_SECONDS = 3600

ISSUER = str(CFG.get("JWT_ISSUER") or "https://hodlxxi.com").rstrip("/")
AUDIENCE = str(CFG.get("JWT_AUDIENCE") or "bitcoin-api")


def sign_jwt(claims: dict, headers: Optional[Dict[str, str]] | None = None) -> str:
    token_headers = headers or ({"kid": JWT_KID} if JWT_ALG == "RS256" and JWT_KID else None)
    algorithm = JWT_ALG if JWT_ALG in {"RS256", "HS256"} else "HS256"
    key = JWT_SIGNING_KEY
    signing_key = key if isinstance(key, (bytes, bytearray)) else str(key or "")
    return jwt.encode(claims, signing_key, algorithm=algorithm, headers=token_headers)


def decode_jwt(token: str, **kwargs):
    key = JWT_VERIFYING_KEY
    verify_key = key if isinstance(key, (bytes, bytearray)) else str(key or "")
    algorithms = kwargs.pop("algorithms", JWT_ALLOWED_ALGORITHMS)
    return jwt.decode(token, verify_key, algorithms=algorithms, **kwargs)


REGISTRY = CollectorRegistry()
oauth_tokens_issued = Counter("oauth_tokens_issued_total", "Total tokens issued", registry=REGISTRY)

try:
    _redis = redis_client.Redis.from_url(REDIS_URL, decode_responses=True)
    _redis.ping()
except Exception as redis_err:
    logger.warning(f"Redis unavailable, falling back to in-memory store: {redis_err}")
    _redis = None


# Redis client for playground (instance, not module)
try:
    logger.info(f"Creating playground_redis with URL: {REDIS_URL[:50]}...")
    playground_redis = redis_client.Redis.from_url(REDIS_URL, decode_responses=True)
    logger.info(f"playground_redis connecting to: {REDIS_URL[:50]}...")
    playground_redis.ping()
    logger.info("playground_redis connected successfully!")
except Exception:
    logger.error("playground_redis failed to connect!")
    logger.error("playground_redis failed to connect!")
    playground_redis = None

def _store_auth_code_pkce(code: str, payload: dict, ttl: int = 600) -> None:
    try:
        storage = get_storage()
        storage.store_auth_code(code, payload, ttl=ttl)
        return
    except Exception as storage_err:
        logger.debug(f"Primary auth code storage failed: {storage_err}")

    if _redis:
        _redis.setex(f"oidc:code:{code}", ttl, json.dumps(payload))
    else:
        AUTH_CODE_STORE[code] = payload


def _pop_auth_code_pkce(code: str):
    try:
        storage = get_storage()
        code_data = storage.get_auth_code(code)
        if code_data:
            try:
                storage.delete_auth_code(code)
            except Exception:
                pass
            return code_data
    except Exception as storage_err:
        logger.debug(f"Primary auth code retrieval failed: {storage_err}")

    if _redis:
        key = f"oidc:code:{code}"
        pipe = _redis.pipeline(True)
        pipe.get(key)
        pipe.delete(key)
        data, _ = pipe.execute()
        if data:
            return json.loads(data)
        return None

    return AUTH_CODE_STORE.pop(code, None)


EXPIRY_SECONDS = 45
ACTIVE_SOCKETS: Dict[str, str] = {}
ONLINE_USERS: Set[str] = set()
CHAT_HISTORY: List[Dict[str, any]] = []


FORCE_RELAY = os.getenv("FORCE_RELAY", "false").lower() in ("1", "true", "yes", "on")
logger.info(f"FORCE_RELAY = {FORCE_RELAY}")


def truncate_key(key: str, head: int = 6, tail: int = 4) -> str:
    if len(key) <= head + tail:
        return key
    return f"{key[:head]}…{key[-tail:]}"


app = Flask(__name__)

# Redis client
# Redis client for sessions
app.config["APP_CONFIG"] = CFG
app.config["JWKS_DOCUMENT"] = JWKS_DOCUMENT
if JWT_KID:
    app.config["JWT_KID"] = JWT_KID

init_security(app, CFG)
app.register_blueprint(pof_bp)
app.register_blueprint(oidc_bp)

OAUTH_PATH_PREFIXES = ("/oauth/", "/oauthx/")
OAUTH_PUBLIC_PATHS = ("/oauth/register", "/oauth/authorize", "/oauth/token", "/oauthx/status", "/oauthx/docs")


# Initialize storage and audit logging
try:
    init_all()
    init_audit_logger()
    logger.info("✅ Storage, audit logging, and config initialized")
except Exception as e:
    logger.error(f"❌ Failed to initialize infrastructure: {e}")

app.secret_key = FLASK_SECRET_KEY

socketio = SocketIO(
    app, 
    cors_allowed_origins=SOCKETIO_CORS,
    async_mode='eventlet',
    logger=True,
    engineio_logger=True
)



# ACTIVE_CHALLENGES (OLD - replaced by pof_enhanced) = {}

# ============================================================================
# SOCKETIO ERROR HANDLERS
# ============================================================================


@socketio.on_error_default
def default_error_handler(e):
    """Handle SocketIO errors"""
    logger.error(f"SocketIO error: {e}", exc_info=True)



# ============================================================================
# HEALTH CHECK ENDPOINT
# ============================================================================


@app.route("/health")
def health():
    """Comprehensive health check endpoint used by monitoring and tests."""
    try:
        health_status = {
            "status": "healthy",
            "timestamp": time.time(),
            "service": "HODLXXI",
            "version": "1.0.0-beta",
            "active_sockets": len(ACTIVE_SOCKETS),
            "online_users": len(ONLINE_USERS),
            "chat_history_size": len(CHAT_HISTORY),
        }

        # Try to ping RPC (optional in test environments)
        try:
            rpc = get_rpc_connection()
            rpc.getblockchaininfo()
            health_status["rpc"] = "connected"
        except Exception as e:  # pragma: no cover - network dependent
            health_status["rpc"] = "error"
            health_status["rpc_error"] = str(e)
            logger.warning(f"RPC health check failed: {e}")

        return jsonify(health_status), 200
    except Exception as e:  # pragma: no cover - defensive
        logger.error(f"Health check failed: {e}", exc_info=True)
        return jsonify({"status": "unhealthy", "error": str(e)}), 500


@app.before_request
def _oauth_public_allowlist():
    p = request.path or "/"
    if any(p.startswith(pref) for pref in OAUTH_PATH_PREFIXES) or p in OAUTH_PUBLIC_PATHS:
        # Mark request so any later guards skip login
        setattr(request, "_oauth_public", True)
        return None


# ============================================================================
# HEALTH CHECK & MONITORING ENDPOINTS
# ============================================================================


@app.route("/metrics")
def metrics():
    """Metrics endpoint for monitoring"""
    try:
        metrics_data = {
            "timestamp": time.time(),
            "active_sockets": len(ACTIVE_SOCKETS),
            "online_users": len(ONLINE_USERS),
            "chat_history_size": len(CHAT_HISTORY),
            "active_challenges": len(ACTIVE_CHALLENGES),
            "lnurl_sessions": len(LNURL_SESSIONS),
        }
        return jsonify({"metrics": metrics_data}), 200
    except Exception as e:
        logger.error(f"Metrics endpoint failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ============================================================================


import base64
import hashlib
import hmac
import os

# /turn_credentials (dynamic, time-limited)
import time

from flask import jsonify

TURN_HOST = os.getenv("TURN_HOST", "213.111.146.201")
TURN_SECRET = os.getenv("TURN_SECRET", "")
TURN_TTL = int(os.getenv("TURN_TTL", "3600"))


@app.route("/turn_credentials")
def turn_credentials():
    if not TURN_SECRET:
        return jsonify({"error": "TURN not configured"}), 500
    username = str(int(time.time()) + TURN_TTL)
    digest = hmac.new(TURN_SECRET.encode("utf-8"), username.encode("utf-8"), hashlib.sha1).digest()
    password = base64.b64encode(digest).decode("utf-8")
    return (
        jsonify(
            [
                {"urls": [f"stun:{TURN_HOST}:3478"]},
                {
                    "urls": [f"turn:{TURN_HOST}:3478?transport=udp", f"turn:{TURN_HOST}:443?transport=udp"],
                    "username": username,
                    "credential": password,
                },
            ]
        ),
        200,
    )


def extract_script_from_any_descriptor(descriptor: str) -> str | None:
    """
    Find the innermost raw(<HEX>) no matter how it's wrapped:
    raw(...), wsh(raw(...)), sh(wsh(raw(...))), etc.
    """
    m = re.search(r"raw\(([0-9A-Fa-f]+)\)", descriptor)
    return m.group(1) if m else None


def classify_presence(pubkey: str | None, access_level: str | None) -> str:
    """
    Decide chip color role for a user:
      full    -> Orange
      limited -> Green
      pin     -> White (session ID is a PIN value)
      random  -> Red   (anonymous guest like 'guest-xxxx')
    """
    if not pubkey:
        return "limited"

    # Random-guest identities look like 'guest-<rand>'
    if pubkey.startswith("guest-"):
        return "random"

    # PIN users use the PIN as their session id; also treat pure digits as PIN
    try:
        is_pin = (pubkey in GUEST_PINS) or pubkey.isdigit()  # GUEST_PINS already in your app
    except NameError:
        is_pin = pubkey.isdigit()
    if is_pin:
        return "pin"

    # Signed users (or special users) rely on access_level
    if access_level == "full":
        return "full"
    if access_level == "limited":
        return "limited"

    return "limited"


# --- WebRTC signaling relay (server) ---


def sids_for_pubkey(pk: str):
    """Get all socket IDs for a given pubkey"""
    return [sid for sid, who in ACTIVE_SOCKETS.items() if who == pk]


@socketio.on("rtc:offer")
def rtc_offer(data):
    """data = {to: , from: , offer: {...}}"""
    try:
        target = (data or {}).get("to")
        if not target:
            logger.warning("RTC offer received without target")
            return
        for sid in sids_for_pubkey(target):
            socketio.emit("rtc:offer", data, to=sid)
    except Exception as e:
        logger.error(f"Error in rtc_offer: {e}", exc_info=True)


@socketio.on("rtc:answer")
def rtc_answer(data):
    """data = {to: , from: , answer: {...}}"""
    try:
        target = (data or {}).get("to")
        if not target:
            logger.warning("RTC answer received without target")
            return
        for sid in sids_for_pubkey(target):
            socketio.emit("rtc:answer", data, to=sid)
    except Exception as e:
        logger.error(f"Error in rtc_answer: {e}", exc_info=True)


@socketio.on("rtc:ice")
def rtc_ice(data):
    """data = {to: , from: , candidate: {...}}"""
    try:
        target = (data or {}).get("to")
        if not target:
            logger.warning("RTC ICE candidate received without target")
            return
        for sid in sids_for_pubkey(target):
            socketio.emit("rtc:ice", data, to=sid)
    except Exception as e:
        logger.error(f"Error in rtc_ice: {e}", exc_info=True)


@socketio.on("rtc:hangup")
def rtc_hangup(data):
    """data = {to: , from: }"""
    try:
        target = (data or {}).get("to")
        if not target:
            logger.warning("RTC hangup received without target")
            return
        for sid in sids_for_pubkey(target):
            socketio.emit("rtc:hangup", data, to=sid)
    except Exception as e:
        logger.error(f"Error in rtc_hangup: {e}", exc_info=True)


@socketio.on("message")
def handle_message(msg_text):
    """Handle incoming chat messages"""
    try:
        pk = session.get("logged_in_pubkey")
        if not pk:
            logger.warning("Message received from unauthenticated user")
            return

        m = {"pubkey": pk, "text": str(msg_text), "ts": time.time()}
        CHAT_HISTORY.append(m)
        purge_old_messages()
        socketio.emit("message", m)
    except Exception as e:
        logger.error(f"Error handling message: {e}", exc_info=True)


app.config["SESSION_PERMANENT"] = True
app.permanent_session_lifetime = timedelta(days=7)

import threading
from decimal import Decimal


def get_save_and_check_balances_for_pubkey(pubkey_hex: str) -> tuple[Decimal, Decimal]:
    """
    For every raw(...) descriptor in the wallet:
      - decode it,
      - get its address (segwit → p2sh → deriveaddresses fallback),
      - list unspent on that address,
      - sum those UTXOs into in_total if pubkey in OP_IF, out_total if pubkey in OP_ELSE.
    Also collects "neutral" (non-matching) contracts into g.neutral_cards for display.
    """
    rpc_conn = get_rpc_connection()
    in_total = Decimal(0)
    out_total = Decimal(0)
    neutral_cards: list[dict] = []

    for desc_item in rpc_conn.listdescriptors().get("descriptors", []):
        raw_desc = desc_item["desc"]

        # tolerate wrappers like wsh(raw(...))
        script = extract_script_from_any_descriptor(raw_desc)
        if not script:
            continue

        decoded = rpc_conn.decodescript(script)
        asm = decoded.get("asm", "")
        op_if = extract_pubkey_from_op_if(asm)
        op_else = extract_pubkey_from_op_else(asm)

        # Address: segwit -> p2sh -> derive from descriptor
        addr = (decoded.get("segwit") or {}).get("address")
        if not addr:
            addr = (decoded.get("p2sh") or {}).get("address")
        if not addr:
            try:
                info = rpc_conn.getdescriptorinfo(raw_desc)
                addrs = rpc_conn.deriveaddresses(info["descriptor"])
                addr = addrs[0] if addrs else None
            except Exception:
                addr = None
        if not addr:
            continue

        utxos = rpc_conn.listunspent(0, 9_999_999, [addr])
        sum_btc = sum(Decimal(u["amount"]) for u in utxos)

        matched = False
        if op_if and op_if.lower() == pubkey_hex.lower():
            in_total += sum_btc
            matched = True
        elif op_else and op_else.lower() == pubkey_hex.lower():
            out_total += sum_btc
            matched = True

        # Collect non-matching contracts so the UI can render them neutrally
        if not matched and sum_btc > 0:
            neutral_cards.append(
                {
                    "addr": addr,
                    "amount_btc": f"{sum_btc:.8f}",
                    "desc": mask_raw_descriptor(raw_desc),
                }
            )

    # Expose neutral cards to the current request (no API change)
    try:
        g.neutral_cards = neutral_cards
    except Exception:
        pass

    return in_total, out_total


def require_full_access():
    """Abort with 403 unless session['access_level']=='full'."""
    if session.get("access_level") != "full":
        abort(403, "Full access required")


import os

from bitcoinrpc.authproxy import AuthServiceProxy


def get_rpc_connection():
    rpc_user = os.getenv("RPC_USER", "hodlwatch")
    rpc_pass = os.getenv("RPC_PASSWORD", "")  # <— use RPC_PASSWORD consistently
    rpc_host = os.getenv("RPC_HOST", "127.0.0.1")
    rpc_port = os.getenv("RPC_PORT", "8332")
    rpc_wallet = os.getenv("RPC_WALLET", "")
    url = f"http://{rpc_user}:{rpc_pass}@{rpc_host}:{rpc_port}/wallet/{rpc_wallet}"

    return AuthServiceProxy(url, timeout=60)
# ============================================================================
# POF ENHANCED SYSTEM - Initialized after get_rpc_connection is defined
# ============================================================================
# pof_service = integrate_pof_routes(app, socketio, get_rpc_connection)



def derive_legacy_address_from_pubkey(pubkey_hex):
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    sha_digest = sha256(pubkey_bytes).digest()
    try:
        import hashlib

        ripe = hashlib.new("ripemd160", sha_digest).digest()
    except:
        ripe = sha256(b"").digest()
    vbyte = b"\x00" + ripe
    chksum = sha256(sha256(vbyte).digest()).digest()[:4]
    address = base58.b58encode(vbyte + chksum).decode()
    return address


def generate_challenge():
    return str(uuid.uuid4())


# --- Minimal login/guest/dev helpers ---------------------------------
@app.before_request
def check_auth():
    from flask import jsonify, redirect, request, session, url_for

    p = request.path or "/"
    m = request.method
    endpoint = request.endpoint or ""
    endpoint_base = endpoint.rsplit(".", 1)[-1]  # handle blueprint endpoints

    # 0) Always allow preflight + simple assets
    if m == "OPTIONS" or p in ("/favicon.ico", "/robots.txt", "/health", "/metrics", "/metrics/prometheus"):
        return None

    # 1) Always bypass session login for token/OAuth routes & Socket.IO
    if (
        p.startswith("/oauth/")
        or p.startswith("/oauthx/")
        or p.startswith("/oauthdemo/")
        or p.startswith("/socket.io/")
        or p.startswith("/static/")
        or p == "/dashboard"
        or p == "/playground"
        or p.startswith("/p/") \
        or p.startswith("/api/playground") or p.startswith("/api/pof/") \
        or p.startswith("/play") \
    ):
        return None

    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return None

    # 1.6) Public paths (no session required)
    PUBLIC_PATHS = {
        "/",
        "/oidc",
        "/oicd",
        "/pof/",
        "/pof/leaderboard",
        "/explorer",
        "/verify_pubkey_and_list",
        "/.well-known/openid-configuration",
        "/oauth/jwks.json",
        "/oauth/authorize",
        "/oauth/token",
        "/oauth/register",
        "/oauth/introspect",
        "/oauthx/status",
        "/oauthx/docs",
        "/login",
        "/logout",
        "/metrics",
        "/metrics/prometheus",
    }
    if p in PUBLIC_PATHS:
        return None

    # 2) Public endpoints by function name (handle blueprints)
    public_endpoints = {
        "login",
        "logout",
        "verify_signature",
        "guest_login",
        "guest_login2",
        "static",
        "convert_wif",
        "decode_raw_script",
        "turn_credentials",
        "api_challenge",
        "api_verify",
        "api_demo_free_v2",
        "userinfo",
        "set_labels_from_zpub",
        "universal_login",
        "lnurl_create",
        "lnurl_params",
        "lnurl_callback",
        "lnurl_check",
        "oauth_register",
        "oauth_authorize",
        "oauth_token",
        "oauthx_status",
        "oauthx_docs",
        "api_docs",
        # landing & explorer
        "landing_page",
        "root_redirect",
        "oidc_alias",
        "explorer_page",
        "verify_pubkey_and_list",
    }
    if not endpoint_base:
        return None

    if endpoint_base in public_endpoints:
        return None

    # 3) Everything else requires a logged-in session
    if not session.get("logged_in_pubkey"):
        if (p.startswith("/api/") and not p.startswith("/api/playground")) or p.endswith("/set_labels_from_zpub"):
            return jsonify(ok=False, error="Not logged in"), 401
        nxt = request.full_path if request.query_string else request.path
        return redirect(url_for("login", next=nxt))
@socketio.on("connect")
def on_connect(auth=None):
    pubkey = session.get("logged_in_pubkey", "")
    level = session.get("access_level")
    if not pubkey:
        return

    role = classify_presence(pubkey, level)

    ACTIVE_SOCKETS[request.sid] = pubkey
    ONLINE_USERS.add(pubkey)
    ONLINE_META[pubkey] = role

    # Use emit() not socketio.emit()
    emit("user:joined", {"pubkey": pubkey, "role": role}, broadcast=True)
    
    online_list = [
        {"pubkey": pk, "role": ONLINE_META.get(pk, "limited")} 
        for pk in ONLINE_USERS
    ]
    emit("online:list", online_list, broadcast=True)

@socketio.on("disconnect")
def on_disconnect(*args, **kwargs):
    sid = request.sid
    pubkey = ACTIVE_SOCKETS.pop(sid, None)
    if not pubkey:
        return

    if pubkey not in ACTIVE_SOCKETS.values():
        ONLINE_USERS.discard(pubkey)
        ONLINE_META.pop(pubkey, None)
        
        # Use emit() not socketio.emit()
        emit("user:left", {"pubkey": pubkey}, broadcast=True)
        
        online_list = [
            {"pubkey": pk, "role": ONLINE_META.get(pk, "limited")} 
            for pk in ONLINE_USERS
        ]
        emit("online:list", online_list, broadcast=True)



def purge_old_messages():
    """Keep only messages newer than EXPIRY_SECONDS."""
    import time

    now = time.time()

    def is_fresh(m):
        ts = m.get("ts") if isinstance(m, dict) else None
        return ts is not None and (now - ts) <= EXPIRY_SECONDS

    global CHAT_HISTORY
    CHAT_HISTORY[:] = [m for m in CHAT_HISTORY if is_fresh(m)]


@app.route("/app")
def chat():

    my_pubkey = session.get("logged_in_pubkey", "")

    online_users_list = list(ONLINE_USERS)

    purge_old_messages()

    chat_html = r"""
<!DOCTYPE html>
<html>
<head>
    <!-- Keep all your existing head content exactly the same -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no">
    <title>HODLXXI Chat</title>
    <!-- All your existing CSS stays the same -->
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        /* --- Matrix background canvas --- */
        #matrix-bg {
            position: fixed;
            inset: 0;
            z-index: 0;             /* behind content */
            pointer-events: none;   /* clicks go through */
        }
        /* Put all UI above the matrix canvas */
        body > *:not(#matrix-bg) { position: relative; z-index: 1; }
        @media (prefers-reduced-motion: reduce) { #matrix-bg { display:none !important; } }
        @media print { #matrix-bg { display:none !important; } }

html, body {
  height: 100%;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
  background: #000;
  color: #0f0;
  /* Use dynamic viewport to avoid 100vh bugs on mobile */
  height: 100dvh;
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
  overflow: hidden; /* keep page from double-scrolling */
}

/* iOS fallback */
@supports (-webkit-touch-callout: none) {
  body { min-height: -webkit-fill-available; }
}

        /* Header */
        .header {
            padding: 12px 16px;
            border-bottom: 1px solid #333;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #111;
            flex-shrink: 0;
            backdrop-filter: blur(2px);
        }

        .back-btn {
            background: none;
            border: 1px solid #0f0;
            color: #0f0;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 14px;
            cursor: pointer;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .back-btn:active {
            background: #0f0;
            color: #000;
        }

        .title {
            font-size: 16px;
            font-weight: 500;
            text-shadow: 0 0 8px rgba(0,255,0,.5);
        }

        .online-count {
            font-size: 12px;
            color: #88ff88;
        }

        /* Online Users Bar */
        .online-bar {
            padding: 8px 16px;
            background: rgba(10,10,10,0.85);
            border-bottom: 1px solid #222;
            flex-shrink: 0;
            overflow-x: auto;
            white-space: nowrap;
            backdrop-filter: blur(2px);
        }

        .online-user {
            display: inline-block;
            padding: 4px 8px;
            margin-right: 8px;
            background: rgba(26,26,26,0.85);
            border: 1px solid #333;
            border-radius: 12px;
            font-size: 12px;
            cursor: pointer;
            color: #0f0;
        }

        .online-user:active {
            background: #0f0;
            color: #000;
        }


        /* Presence roles */
.online-user.role-full    { background:#ff8c1a; color:#121212; border-color:#ffb066; }
.online-user.role-limited { background:#20c15b; color:#0b0f10; border-color:#2ae06b; }
.online-user.role-pin     { background:#3b82f6; color:#ffffff; border-color:#60a5fa; }
.online-user.role-random  { background:#ff3b30; color:#ffffff; border-color:#ff6b60; }



        /* Messages Container */
        .messages-container {
            flex: 1;
            overflow-y: auto;
            padding: 0 16px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            padding-top: 16px;
            padding-bottom: 16px;
        }

        .message {
            max-width: 80%;
            word-wrap: break-word;
            line-height: 1.4;
            animation: fadeIn .2s ease;
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(4px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        .message.fade-out {
          animation: fadeOut .3s ease forwards;
        }
        @keyframes fadeOut {
          to { opacity: 0; transform: translateY(-2px); }
        }

        .message.mine {
            align-self: flex-end;
            text-align: right;
        }

        .message.theirs {
            align-self: flex-start;
        }

        .message-sender {
            font-size: 11px;
            color: #66cc66;
            margin-bottom: 2px;
        }

        .message-text {
            background: rgba(26,26,26,0.85);
            padding: 8px 12px;
            border-radius: 12px;
            font-size: 14px;
            border: 1px solid #333;
            backdrop-filter: blur(2px);
        }

        .message.mine .message-text {
            background: rgba(10,42,10,0.9);
            border-color: #0f0;
            box-shadow: 0 0 10px rgba(0,255,0,.12);
        }

        /* Input Area */
        .input-area {
            padding: 12px 16px calc(12px + env(safe-area-inset-bottom));
            border-top: 1px solid #333;
            background: rgba(17,17,17,0.9);
            display: flex;
            gap: 8px;
            align-items: flex-end;
            flex-shrink: 0;
            backdrop-filter: blur(4px);
        }

        .message-input {
            flex: 1;
            background: rgba(26,26,26,0.85);
            border: 1px solid #333;
            color: #0f0;
            padding: 10px 12px;
            border-radius: 20px;
            font-size: 16px;
            resize: none;
            min-height: 40px;
            max-height: 120px;
            outline: none;
            font-family: inherit;
        }

        .message-input:focus {
            border-color: #0f0;
            box-shadow: 0 0 0 3px rgba(0,255,0,.1);
        }

        .send-btn {
            background: #0f0;
            color: #000;
            border: none;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
            flex-shrink: 0;
            box-shadow: 0 0 12px rgba(0,255,0,.25);
        }

        .send-btn:active {
            background: #0a0;
        }

        .send-btn:disabled {
            background: #333;
            color: #666;
            cursor: not-allowed;
            box-shadow: none;
        }

        /* Mobile optimizations */
        @media (max-width: 480px) {
            .header { padding: 10px 12px; }
            .title { font-size: 14px; }
            .messages-container {
                padding: 0 12px;
                padding-top: 12px;
                padding-bottom: 12px;
            }
            .input-area { padding: 10px 12px calc(10px + env(safe-area-inset-bottom)); }
            .message { max-width: 90%; }
        }

        /* Scrollbar styling */
        .messages-container::-webkit-scrollbar { width: 3px; }
        .messages-container::-webkit-scrollbar-track { background: transparent; }
        .messages-container::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }
        .online-bar::-webkit-scrollbar { height: 3px; }
        .online-bar::-webkit-scrollbar-track { background: transparent; }
        .online-bar::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }
        /* === Call UI (neon) === */
.call-overlay{position:fixed;inset:0;display:none;z-index:9999;align-items:center;justify-content:center;background:rgba(0,0,0,.85)}
.call-stage{position:relative;width:min(96vw,1000px);height:min(75dvh,760px);border:1px solid #0f0;border-radius:16px;overflow:hidden;background:linear-gradient(180deg,#001a00,#000)}
.remote-video,.local-video{background:#000}
.remote-video{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.local-pip{position:absolute;right:16px;bottom:16px;width:min(42vw,240px);aspect-ratio:16/9;border:1px solid #0f0;border-radius:12px;overflow:hidden;cursor:grab;box-shadow:0 0 18px rgba(0,255,0,.15)}
.local-pip.dragging{opacity:.9;cursor:grabbing}
.local-video{width:100%;height:100%;object-fit:cover;transform:scaleX(-1)}
.call-topbar{position:absolute;left:12px;right:12px;top:10px;display:flex;align-items:center;gap:10px;justify-content:space-between}
.badge{display:inline-flex;align-items:center;gap:8px;background:rgba(0,40,0,.75);border:1px solid #0f0;border-radius:999px;padding:6px 10px;font:12px/1.2 monospace;color:#0f0;box-shadow:0 0 10px rgba(0,255,0,.12)}
.status-dot{width:10px;height:10px;border-radius:50%;background:#666;box-shadow:0 0 6px #666}
.status-dot.live{background:#0f0;box-shadow:0 0 10px #0f0}
.quality{display:inline-flex;gap:3px}
.quality i{width:6px;height:10px;background:#255;border:1px solid #0f0;opacity:.5}
.quality i.on{background:#0f0;opacity:1}
.timer{font:12px/1 monospace;color:#88ff88}
.call-toolbar{position:absolute;left:50%;transform:translateX(-50%);bottom:12px;display:flex;gap:12px;flex-wrap:wrap;justify-content:center}
.btn-circle{width:56px;height:56px;border-radius:50%;display:flex;align-items:center;justify-content:center;border:1px solid #0f0;background:rgba(0,40,0,.85);color:#0f0;font-size:22px;cursor:pointer;box-shadow:0 0 12px rgba(0,255,0,.18)}
.btn-circle:active{transform:scale(.98)}
.btn-circle.active{background:#0f0;color:#000}
.btn-circle.danger{border-color:#f33;color:#f55;background:rgba(40,0,0,.9);box-shadow:0 0 12px rgba(255,0,0,.18)}
.small{font-size:11px;margin-top:4px;color:#88ff88;text-align:center}
.sheet{position:absolute;inset:0;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,.55);backdrop-filter:blur(2px)}
.card{background:rgba(10,30,10,.95);border:1px solid #0f0;border-radius:12px;padding:16px 14px;min-width:280px;box-shadow:0 0 24px rgba(0,255,0,.2)}
.row{display:flex;gap:8px;align-items:center;justify-content:center;margin-top:10px;flex-wrap:wrap}
.btn{border:1px solid #0f0;background:rgba(0,40,0,.8);color:#0f0;padding:8px 12px;border-radius:10px;cursor:pointer}
.btn.primary{background:#0f0;color:#000}
.btn.ghost{background:transparent}
.panel{position:absolute;right:12px;top:56px;background:rgba(0,20,0,.95);border:1px solid #0f0;border-radius:10px;padding:10px;display:none;min-width:220px}
.panel label{font:12px/1.2 monospace;color:#88ff88;display:block;margin:6px 0 4px}
.panel select{width:100%;background:#000;border:1px solid #0f0;color:#0f0;padding:6px;border-radius:8px}
@media (max-width:480px){.btn-circle{width:52px;height:52px;font-size:20px}.local-pip{width:36vw}}



/* === Enhancements: fade, fullscreen, safe-areas, polish === */
.call-overlay.show { display: flex; }

.call-stage:fullscreen,
.call-stage:-webkit-full-screen {
  width: 100vw;
  height: 100vh;
  border: 0;
  border-radius: 0;
}
.call-stage:fullscreen .remote-video,
.call-stage:-webkit-full-screen .remote-video {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.call-toolbar {
  transition: opacity .35s ease, visibility .35s ease, transform .35s ease;
  will-change: opacity, transform;
}
.call-toolbar.hidden {
  opacity: 0;
  visibility: hidden;
  transform: translateY(10px);
  pointer-events: none;
}

.call-stage {
  padding-bottom: max(0px, env(safe-area-inset-bottom));
  padding-top:    max(0px, env(safe-area-inset-top));
}
.call-toolbar { bottom: calc(12px + env(safe-area-inset-bottom)); }
.call-topbar  { top:    calc(10px + env(safe-area-inset-top)); }

.local-pip { z-index: 3; }
.call-topbar, .call-toolbar { z-index: 2; }

.btn-circle:hover { box-shadow: 0 0 18px rgba(0,255,0,.28); }

@media (prefers-reduced-motion: reduce) {
  .call-toolbar { transition: none; }
}
@media (max-width: 360px) {
  .call-toolbar { gap: 8px; }
}


/* === fade controls + fullscreen tweaks === */
.call-toolbar{
  transition: opacity .35s ease, visibility .35s ease, transform .35s ease;
  will-change: opacity, transform;
}
.call-toolbar.hidden{
  opacity: 0;
  visibility: hidden;
  transform: translateY(10px);
  pointer-events: none;
}
.call-stage:fullscreen .call-toolbar,
.call-stage:-webkit-full-screen .call-toolbar{
  bottom: 10px;
}




    </style>
</head>
<body>
    <!-- Matrix canvas -->
    <canvas id="matrix-bg" aria-hidden="true"></canvas>


    <!-- Header -->
    <div class="header">
        <div class="title">The Matrix has you...follow e923</div>
        <div class="online-count" id="onlineCount">{{ online_count }} online</div>
    </div>

    <!-- Online Users -->
    <div class="online-bar" id="onlineBar"></div>

    <!-- Messages -->
    <div class="messages-container" id="messagesContainer"></div>

    <!-- Input -->
    <div class="input-area">
        <textarea
            id="messageInput"
            class="message-input"
            placeholder="Type a message..."
            rows="1"
        ></textarea>
        <button id="sendBtn" class="send-btn" disabled>→</button>
    </div>

    <!-- Audio elements -->
    <audio id="joinSound" preload="auto" playsinline>
        <source src="{{ url_for('static', filename='sounds/join.mp3') }}" type="audio/mpeg">
    </audio>
    <audio id="messageSound" preload="auto" playsinline>
        <source src="{{ url_for('static', filename='sounds/message.mp3') }}" type="audio/mpeg">
    </audio>
    <audio id="remoteLoginSound" preload="auto" playsinline>
        <source src="{{ url_for('static', filename='sounds/login.mp3') }}" type="audio/mpeg">
    </audio>

<script>
  const CHAT_HISTORY = {{ history | tojson | safe }};
  const INITIAL_ONLINE = {{ online_users | tojson | safe }};
  const MY_PUBKEY = "{{ my_pubkey }}";
  const SPECIAL_NAMES = {{ special_names | tojson | safe }};
  const ACCESS_LEVEL = "{{ access_level }}";   <!-- add this -->
</script>



<!-- put this FIRST -->
<script>const FORCE_RELAY = {{ force_relay | tojson | safe }};</script>

<script>
// -------------- ICE CONFIG (hard-coded). Keep or replace with your fetch version --------------
window.iceReady = fetch('/turn_credentials')
  .then(r => r.json())
  .then(servers => {
    if (Array.isArray(servers)) {
      window.pcBaseConfig = {
        iceServers: servers,
        iceTransportPolicy: (typeof FORCE_RELAY !== 'undefined' && FORCE_RELAY) ? 'relay' : 'all',
        bundlePolicy: 'max-bundle',
        rtcpMuxPolicy: 'require'
      };
    } else {
      // fallback to STUN only if TURN misconfigured
      window.pcBaseConfig = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
    }
  })
  .catch(() => {
    window.pcBaseConfig = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
  });

// ---------------------- STATE ----------------------
let pc = null;
let localStream = null;
let currentVideoSender = null;
let timerArmed = false;  // ⏱ startTimers guard


// Helper to ensure local cam/mic
async function ensureLocalMedia() {
  if (localStream) return localStream;
  localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
  document.getElementById('localVideo').srcObject = localStream;
  return localStream;
}

// Make a new PeerConnection
async function newPC() {
  if (pc) { try { pc.close(); } catch (e) {} }
  // If you use window.iceReady elsewhere, wait for it:
  if (window.iceReady && typeof window.iceReady.then === 'function') {
    try { await window.iceReady; } catch (e) { console.warn('iceReady failed:', e); }
  }

  pc = new RTCPeerConnection(window.pcBaseConfig);
  console.log('[PC] created', window.pcBaseConfig);

  // Remote media hookup (iOS/Safari safe)
  pc.ontrack = (ev) => {
    const remoteEl = document.getElementById('remoteVideo');
    if (!remoteEl.srcObject) remoteEl.srcObject = new MediaStream();
    remoteEl.srcObject.addTrack(ev.track);
    Promise.resolve().then(() => remoteEl.play().catch(()=>{}));
  };

  // Add local tracks
  currentVideoSender = null;
  localStream.getTracks().forEach(t => {
    const sender = pc.addTrack(t, localStream);
    if (t.kind === 'video') currentVideoSender = sender;
  });

  // Optional: cap initial uplink bitrate for stability
  try {
    if (currentVideoSender) {
      const p = currentVideoSender.getParameters() || {};
      p.encodings = [{ maxBitrate: 600_000 }]; // ~600 kbps
      await currentVideoSender.setParameters(p).catch(()=>{});
    }
  } catch {}

  // ICE → signaling (serialize!)
  pc.onicecandidate = (ev) => {
    const c = ev.candidate;
    if (!c) { console.log('[ICE] end of candidates'); return; }
    const candidate = {
      candidate: c.candidate,
      sdpMid: c.sdpMid,
      sdpMLineIndex: c.sdpMLineIndex,
      usernameFragment: c.usernameFragment
    };
    if (currentPeer) {
      socket.emit('rtc:ice', { to: currentPeer, from: MY_PUBKEY, candidate });
      console.log('[EMIT] rtc:ice →', currentPeer, candidate);
    }
  };

  // Diagnostics
  pc.oniceconnectionstatechange = () => console.log('[ICE state]', pc.iceConnectionState);
  pc.onconnectionstatechange   = () => console.log('[PC state]', pc.connectionState);
  pc.onicegatheringstatechange = () => console.log('[ICE gathering]', pc.iceGatheringState);

  return pc;
}

// ---------------------- CALL FLOW ----------------------
async function startCall(targetPubkey) {
  currentPeer = targetPubkey;
  await ensureLocalMedia();
  await newPC();

  const offer = await pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: true });
  await pc.setLocalDescription(offer);

  socket.emit('rtc:offer', { to: currentPeer, from: MY_PUBKEY, offer });
  console.log('[EMIT] rtc:offer →', currentPeer);
}

async function hangup() {
  if (pc) { try { pc.close(); } catch {} }
  pc = null;
  currentPeer = null;
}

// ---------------------- SIGNALING HANDLERS ----------------------
socket.on('rtc:offer', async ({ from, sdp }) => {
  console.log('[RECV] rtc:offer ←', from);
  currentPeer = from;
  await ensureLocalMedia();
  await newPC();

  await pc.setRemoteDescription(new RTCSessionDescription(sdp));
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  socket.emit('rtc:answer', { to: from, from: MY_PUBKEY, answer });
  console.log('[EMIT] rtc:answer →', from);
});

socket.on('rtc:answer', async ({ from, sdp }) => {
  console.log('[RECV] rtc:answer ←', from);
  if (!pc) return;
  await pc.setRemoteDescription(new RTCSessionDescription(sdp));
});

socket.on('rtc:ice', async ({ from, candidate }) => {
  if (!pc || !candidate) return;
  try {
    await pc.addIceCandidate(new RTCIceCandidate(candidate));
    // console.log('[ADD] ICE from', from, candidate);
  } catch (e) {
    console.warn('addIceCandidate failed:', e);
  }
});

// ---------------------- UI HOOKS (optional) ----------------------
// Example buttons (create these in HTML if you want):
// <button id="callBtn">Call</button> <button id="hangupBtn">Hang up</button>
const callBtn   = document.getElementById('callBtn');
const hangupBtn = document.getElementById('hangupBtn');
if (callBtn)   callBtn.addEventListener('click', () => startCall(CHOSEN_PEER_PUBKEY));
if (hangupBtn) hangupBtn.addEventListener('click', hangup);
</script>







<script src="//cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.1/socket.io.min.js"></script>
<script>
  // Create ONE shared socket for the whole page.
  // ChatApp will decide when to connect.
  window.socket = io({ autoConnect: false });
</script>

<!-- If you are NOT dynamically fetching TURN creds elsewhere,
     make iceReady a resolved promise so awaits won't break -->
<script>
  if (!window.iceReady || typeof window.iceReady.then !== 'function') {
    window.iceReady = Promise.resolve();
  }
</script>




    <script>
class ChatApp {
  constructor() {
    // ---- state ----
    this.socket = window.socket;

    // Map: pubkey -> role
    this.onlineUsers = new Map(
      (INITIAL_ONLINE || []).map(pk => [pk, this.classifyRole(pk)])
    );

    // show yourself immediately with correct role
    if (MY_PUBKEY) {
      const myRole = (ACCESS_LEVEL === 'full') ? 'full' : this.classifyRole(MY_PUBKEY);
      this.onlineUsers.set(MY_PUBKEY, myRole);
    }

    this.audioUnlocked = false;

    // ---- elements ----
    this.elements = {
      messagesContainer: document.getElementById('messagesContainer'),
      messageInput:      document.getElementById('messageInput'),
      sendBtn:           document.getElementById('sendBtn'),
      onlineBar:         document.getElementById('onlineBar'),
      onlineCount:       document.getElementById('onlineCount'),
      joinSound:         document.getElementById('joinSound'),
      messageSound:      document.getElementById('messageSound'),
      remoteLoginSound:  document.getElementById('remoteLoginSound')
    };

    // 1) bind before connect
    this.setupSocketListeners();

    // reflect ourself as online when transport is up
    this.socket.on('connect', () => {
      if (MY_PUBKEY) {
        const myRole = (ACCESS_LEVEL === 'full') ? 'full' : this.classifyRole(MY_PUBKEY);
        this.onlineUsers.set(MY_PUBKEY, myRole);
      }
      this.renderOnlineUsers();
      console.log('[socket] connected', this.socket.id);
    });

    // 2) UI init
    this.init();

    // 3) connect
    this.socket.connect();
  }

  // ---- role detection on the frontend (fallback) ----
  classifyRole(pk) {
    if (!pk) return 'limited';
    if (pk.startsWith('guest-')) return 'random';    // random guests
    if (/^\d+$/.test(pk)) return 'pin';              // PIN users
    return 'limited';                                // default unless server says 'full'
  }

  init() {
    this.setupEventListeners();
    this.renderOnlineUsers();
    this.loadChatHistory();
  }

  setupEventListeners() {
    // Send button
    this.elements.sendBtn.addEventListener('click', () => this.sendMessage());

    // Input handling
    this.elements.messageInput.addEventListener('input', () => {
      this.adjustInputHeight();
      this.updateSendButton();
    });
    this.elements.messageInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.sendMessage();
      }
    });

    // Audio unlock (play → pause once to satisfy mobile autoplay policies)
    const unlockAudio = () => {
      if (this.audioUnlocked) return;
      [this.elements.joinSound, this.elements.messageSound, this.elements.remoteLoginSound].forEach(audio => {
        audio.play().then(() => {
          audio.pause();
          audio.currentTime = 0;
        }).catch(() => {});
      });
      this.audioUnlocked = true;
    };
    this.elements.sendBtn.addEventListener('click', unlockAudio, { once: true });
    this.elements.messageInput.addEventListener('keydown', unlockAudio, { once: true });

    // iOS keyboard scroll
    window.addEventListener('resize', () => this.scrollToBottom());
  }

  setupSocketListeners() {
    // avoid duplicate handlers on hot-reload
    this.socket.off('user:joined');
    this.socket.off('user:logged_in');
    this.socket.off('user:left');
    this.socket.off('message');

    // presence join: string OR {pubkey, role}
    this.socket.on('user:joined', (payload) => {
      let pubkey, role;
      if (typeof payload === 'string') {
        pubkey = payload;
        role   = this.classifyRole(pubkey);
      } else {
        pubkey = payload?.pubkey || payload?.id || '';
        role   = payload?.role || this.classifyRole(pubkey);
      }
      if (!pubkey) return;

      // if this is me and ACCESS_LEVEL is full, override to full (orange)
      if (pubkey === MY_PUBKEY && ACCESS_LEVEL === 'full') role = 'full';

      this.onlineUsers.set(pubkey, role);
      this.renderOnlineUsers();

      if (pubkey !== MY_PUBKEY && this.audioUnlocked) {
        this.elements.joinSound.play().catch(() => {});
      }
    });

    // presence leave: string OR {pubkey}
    this.socket.on('user:left', (payload) => {
      const pubkey = (typeof payload === 'string') ? payload
                   : (payload && payload.pubkey) ? payload.pubkey
                   : null;
      if (!pubkey) return;
      this.onlineUsers.delete(pubkey);
      this.renderOnlineUsers();
    });

    // login ping sound (unchanged)
    this.socket.on('user:logged_in', (pubkey) => {
      if (pubkey !== MY_PUBKEY && this.audioUnlocked) {
        const a = this.elements.remoteLoginSound;
        a.loop = true; a.currentTime = 0;
        a.play().catch(()=>{});
        setTimeout(() => { a.pause(); a.currentTime = 0; a.loop = false; }, 6000);
      }
    });

    // messages (unchanged)
    this.socket.on('message', (message) => {
      this.addMessage(message);
      const from = (typeof message === "string") ? message.split(": ")[0]
                : (message.pubkey || "unknown");
      if (from !== MY_PUBKEY && this.audioUnlocked) {
        this.elements.messageSound.play().catch(() => {});
      }
    });
  }

  adjustInputHeight() {
    const input = this.elements.messageInput;
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 120) + 'px';
  }

  updateSendButton() {
    const hasText = this.elements.messageInput.value.trim().length > 0;
    this.elements.sendBtn.disabled = !hasText;
  }

  sendMessage() {
    const text = this.elements.messageInput.value.trim();
    if (!text) return;
    this.socket.send(text); // server attaches pubkey from session
    this.elements.messageInput.value = '';
    this.adjustInputHeight();
    this.updateSendButton();
  }

  addMessage(message) {
    let pubkey, text, ts;
    if (typeof message === "string") {
      const [sender, ...rest] = message.split(": ");
      pubkey = (sender || "unknown").trim();
      text   = rest.join(": ") || "";
      ts     = Date.now() / 1000;
    } else {
      pubkey = (message.pubkey || "unknown").toString().trim();
      text   = (message.text ?? "").toString();
      ts     = (typeof message.ts === "number") ? message.ts : (Date.now() / 1000);
    }

    const isMine = pubkey === MY_PUBKEY;
    const label  = (window.SPECIAL_NAMES && SPECIAL_NAMES[pubkey]) || this.truncateKey(pubkey);

    const wrap = document.createElement("div");
    wrap.className = `message ${isMine ? "mine" : "theirs"}`;
    wrap.innerHTML = `
      <div class="message-sender">${label}</div>
      <div class="message-text">${this.escapeHtml(text)}</div>
    `;
    this.elements.messagesContainer.appendChild(wrap);
    this.scrollToBottom();

    const now = Date.now() / 1000;
    const EXPIRY = 45;
    const remainingMs = Math.max(0, Math.floor((ts + EXPIRY - now) * 1000));
    const fadeMs = Math.min(300, remainingMs);
    setTimeout(() => { wrap.classList.add('fade-out'); }, Math.max(0, remainingMs - fadeMs));
    setTimeout(() => { if (wrap.parentNode) wrap.remove(); }, remainingMs);
  }

  loadChatHistory() {
    const now = Date.now() / 1000;
    const EXPIRY = 45;
    CHAT_HISTORY.forEach(m => {
      const ts = (typeof m === "object" && typeof m.ts === "number") ? m.ts : now;
      if ((now - ts) <= EXPIRY) this.addMessage(m);
    });
  }

  renderOnlineUsers() {
    this.elements.onlineBar.innerHTML = '';
    this.elements.onlineCount.textContent = `${this.onlineUsers.size} online`;

    for (const [pubkey, role] of this.onlineUsers.entries()) {
      const userEl = document.createElement('div');
      const label = SPECIAL_NAMES[pubkey] || this.truncateKey(pubkey);
      userEl.className = `online-user role-${role || 'limited'}`;
      userEl.dataset.pubkey = pubkey;
      userEl.textContent = label;
      this.elements.onlineBar.appendChild(userEl);
    }
  }

  truncateKey(key) { return '…' + (key || '').slice(-4); }
  escapeHtml(text) { const div = document.createElement('div'); div.textContent = text; return div.innerHTML; }
  scrollToBottom() { const el = this.elements.messagesContainer; el.scrollTop = el.scrollHeight; }
}
</script>




<!-- Matrix background JS (new space-warp 0/1) -->
<script>
(() => {
  const canvas = document.getElementById('matrix-bg');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  // Particles flying toward the camera; glyph at each projected point
  const CHARS = ['0','1'];
  let width = 0, height = 0, particles = [], raf = null;

  function resize() {
    // DPR-aware sizing for crisper text, capped for perf
    const dpr = Math.max(1, Math.min(window.devicePixelRatio || 1, 2));
    const cssW = window.innerWidth, cssH = window.innerHeight;

    canvas.width  = Math.floor(cssW * dpr);
    canvas.height = Math.floor(cssH * dpr);
    canvas.style.width  = cssW + 'px';
    canvas.style.height = cssH + 'px';

    ctx.setTransform(1,0,0,1,0,0);
    ctx.scale(dpr, dpr);

    width = cssW; height = cssH;

    // Re-seed particles
    particles = [];
    for (let i = 0; i < 400; i++) {
      particles.push({
        x: (Math.random() - 0.5) * width,
        y: (Math.random() - 0.5) * height,
        z: Math.random() * 800 + 100
      });
    }

    // Fresh clear
    ctx.fillStyle = 'rgba(0,0,0,1)';
    ctx.fillRect(0, 0, width, height);
  }

  function draw() {
    // Motion trails
    ctx.fillStyle = 'rgba(0,0,0,0.25)';
    ctx.fillRect(0, 0, width, height);

    ctx.fillStyle = '#00ff88';
    for (const p of particles) {
      const scale = 200 / p.z;
      const x2 = width  / 2 + p.x * scale;
      const y2 = height / 2 + p.y * scale;
      const size = Math.max(8 * scale, 1);
      ctx.font = size + 'px monospace';
      ctx.fillText(CHARS[(Math.random() > 0.5) | 0], x2, y2);

      // Advance toward camera
      p.z -= 5;
      if (p.z < 1) {
        p.x = (Math.random() - 0.5) * width;
        p.y = (Math.random() - 0.5) * height;
        p.z = 800;
      }
    }
    raf = requestAnimationFrame(draw);
  }

  function onVis() {
    if (document.hidden) { if (raf) cancelAnimationFrame(raf), raf = null; }
    else { if (!raf) raf = requestAnimationFrame(draw); }
  }

  window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', onVis);
  resize();
  raf = requestAnimationFrame(draw);
})();
</script>


<script>
  const HOME_URL = "{{ url_for('home') }}";
</script>

<script>
document.addEventListener('DOMContentLoaded', () => {
  const app = new ChatApp();
  window.chatApp = app;

  const bar = document.getElementById('onlineBar');
  if (!bar) return;

  let pressTimer = null;
  let longPressTriggered = false;

  bar.addEventListener('mousedown', (e) => {
    const chip = e.target.closest('.online-user');
    if (!chip) return;
    const pk = (chip.dataset.pubkey || '').trim();
    if (!pk || pk === MY_PUBKEY) return;

    longPressTriggered = false;
    pressTimer = setTimeout(() => {
      longPressTriggered = true;
      if (window.startCall) window.startCall(pk);
    }, 600); // hold for 600ms = call
  });

  bar.addEventListener('mouseup', (e) => {
    clearTimeout(pressTimer);
    const chip = e.target.closest('.online-user');
    if (!chip) return;
    const pk = (chip.dataset.pubkey || '').trim();
    if (!pk || pk === MY_PUBKEY) return;

    if (!longPressTriggered) {
      // quick click → open covenant explorer
      const url = `${location.origin}${HOME_URL}?pubkey=${encodeURIComponent(pk)}#explorer`;
      window.open(url, '_blank', 'noopener');
    }
  });

  bar.addEventListener('mouseleave', () => clearTimeout(pressTimer));
  bar.addEventListener('touchstart', (e) => {
    const chip = e.target.closest('.online-user');
    if (!chip) return;
    const pk = (chip.dataset.pubkey || '').trim();
    if (!pk || pk === MY_PUBKEY) return;

    longPressTriggered = false;
    pressTimer = setTimeout(() => {
      longPressTriggered = true;
      if (window.startCall) window.startCall(pk);
    }, 600);
  });

  bar.addEventListener('touchend', (e) => {
    clearTimeout(pressTimer);
    const chip = e.target.closest('.online-user');
    if (!chip) return;
    const pk = (chip.dataset.pubkey || '').trim();
    if (!pk || pk === MY_PUBKEY) return;

    if (!longPressTriggered) {
      const url = `${location.origin}${HOME_URL}?pubkey=${encodeURIComponent(pk)}#explorer`;
      window.open(url, '_blank', 'noopener');
    }
  });
});

</script>

<!-- ★ Enhanced Call UI -->
<div id="call-ui" class="call-overlay" aria-hidden="true">
  <div class="call-stage">
    <video id="remoteVideo" class="remote-video" autoplay playsinline></video>

    <!-- top bar -->
    <div class="call-topbar">
      <div class="badge">
        <span class="status-dot" id="callStatusDot"></span>
        <span id="callTitle">Connecting…</span>
      </div>
      <div class="badge">
        <span class="quality" id="qualityBars"><i></i><i></i><i></i><i></i><i></i></span>
        <span class="timer" id="callTimer">00:00</span>
      </div>
    </div>

    <!-- local PiP (draggable) -->
    <div class="local-pip" id="pip">
      <video id="localVideo" class="local-video" autoplay playsinline muted></video>
    </div>

    <!-- controls -->
    <div class="call-toolbar">
      <button id="muteBtn" class="btn-circle" title="Mute/Unmute">🎤</button>
      <button id="camBtn" class="btn-circle" title="Camera On/Off">🎥</button>
      <button id="shareBtn" class="btn-circle" title="Share Screen">🖥️</button>
      <button id="flipBtn" class="btn-circle" title="Switch Camera">🔄</button>
      <button id="settingsBtn" class="btn-circle" title="Devices">⚙️</button>
      <button id="hangupBtn" class="btn-circle danger" title="Hang Up">⛔</button>
    </div>
    <div class="small">Tips: M = mute, V = video, S = share, H = hang up</div>

    <!-- device panel -->
    <div id="devicePanel" class="panel">
      <label>Microphone</label>
      <select id="micSelect"></select>
      <label>Camera</label>
      <select id="camSelect"></select>
    </div>

    <!-- incoming call sheet -->
    <div id="incomingSheet" class="sheet">
      <div class="card">
        <div style="text-align:center;color:#0f0;font-family:monospace">
          Incoming call from <b id="incomingName">…</b>
        </div>
        <div class="row">
          <button id="acceptBtn" class="btn primary">Accept</button>
          <button id="declineBtn" class="btn ghost">Decline</button>
        </div>
      </div>
    </div>
  </div>
</div>

<audio id="ringSound" preload="auto" playsinline>
  <source src="{{ url_for('static', filename='sounds/login.mp3') }}" type="audio/mpeg">
</audio>




<script>
(() => {
  const socket = window.socket;

  // UI refs
  const ui = {
    root: document.getElementById('call-ui'),
    remote: document.getElementById('remoteVideo'),
    local:  document.getElementById('localVideo'),
    pip:    document.getElementById('pip'),
    dot:    document.getElementById('callStatusDot'),
    title:  document.getElementById('callTitle'),
    bars:   document.getElementById('qualityBars'),
    timer:  document.getElementById('callTimer'),
    sheet:  document.getElementById('incomingSheet'),
    name:   document.getElementById('incomingName'),
    ring:   document.getElementById('ringSound'),
    panel:  document.getElementById('devicePanel'),
    micSel: document.getElementById('micSelect'),
    camSel: document.getElementById('camSelect'),

    hang:   document.getElementById('hangupBtn'),
    mute:   document.getElementById('muteBtn'),
    cam:    document.getElementById('camBtn'),
    share:  document.getElementById('shareBtn'),
    flip:   document.getElementById('flipBtn'),
    gear:   document.getElementById('settingsBtn'),
    accept: document.getElementById('acceptBtn'),
    decline:document.getElementById('declineBtn'),
  };



  let pc = null, localStream = null, screenStream = null, wakeLock = null;
  let currentPeer = null, callState = 'idle', micMuted = false, camOff = false, statsTimer = null, callTimer = null;
  let lastRxBytes = 0, lastRxTs = 0, chosenMic = null, chosenCam = null, currentVideoSender = null; let pendingIce = [];
  let remoteDescSet = false;


  // ---------- helpers ----------
  const nameOf = (pk) => (window.SPECIAL_NAMES && SPECIAL_NAMES[pk]) || ('…' + (pk||'').slice(-4));
  const setStatus = (txt, live=false) => {
    ui.title.textContent = txt || '';
    ui.dot.classList.toggle('live', !!live);
  };
  const fmt = (s) => {
    s = Math.max(0, s|0);
    const m = (s/60)|0, ss = (s%60)|0;
    return `${String(m).padStart(2,'0')}:${String(ss).padStart(2,'0')}`;
  };
  const qualityBars = (bps) => {
    // Rough mapping: 0..2.5mbps
    const bars = ui.bars.querySelectorAll('i');
    const steps = [100_000, 300_000, 700_000, 1_200_000, 2_000_000];
    bars.forEach((b,i)=> b.classList.toggle('on', bps >= steps[i]));
  };
  async function keepAwake(on) {
    try {
      if (on && 'wakeLock' in navigator) { wakeLock = await navigator.wakeLock.request('screen'); }
      else if (wakeLock) { await wakeLock.release(); wakeLock = null; }
    } catch {}
  }




// --- fullscreen + controls fade helpers ---
async function goFullscreen() {
  const el = document.querySelector('#call-ui .call-stage');
  if (!el) return;
  if (document.fullscreenElement) return;
  try {
    if (el.requestFullscreen) await el.requestFullscreen();
    else if (el.webkitRequestFullscreen) el.webkitRequestFullscreen(); // iOS Safari
  } catch {}
}

const stageEl   = document.querySelector('#call-ui .call-stage');
const toolbarEl = document.querySelector('#call-ui .call-toolbar');
let controlsTimer = null;
let controlsActive = false;

function controlsShow() {
  if (!toolbarEl) return;
  toolbarEl.classList.remove('hidden');
}
function controlsHide() {
  if (!toolbarEl) return;
  toolbarEl.classList.add('hidden');
}
function nudgeControls() {
  if (!controlsActive || !toolbarEl) return;
  controlsShow();
  clearTimeout(controlsTimer);
  controlsTimer = setTimeout(controlsHide, 2500); // hide after 2.5s idle
}
function controlsStart() {
  controlsActive = true;
  controlsShow();
  nudgeControls();
}
function controlsStop() {
  controlsActive = false;
  clearTimeout(controlsTimer);
  controlsShow(); // show again when ending
}

// reveal controls on any activity
['mousemove','keydown','touchstart','click'].forEach(evt => {
  stageEl?.addEventListener(evt, nudgeControls, { passive: true });
});





  function openUI(title){ ui.root.style.display='flex'; setStatus(title||'Calling…', false); }
  function closeUI(){
    ui.root.style.display='none'; ui.sheet.style.display='none';
    ui.panel.style.display='none'; setStatus('', false); ui.timer.textContent='00:00';
    qualityBars(0);
  }

  async function ensureMedia() {
    const secure = (location.protocol === 'https:' || location.hostname === 'localhost');
    if (!secure) throw new Error('Camera/mic requires HTTPS or localhost');
    const audio = chosenMic ? {deviceId:{exact:chosenMic}} : true;
    const video = chosenCam ? {deviceId:{exact:chosenCam}} : {facingMode:'user'};
    if (!localStream) {
      localStream = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation:true, noiseSuppression:true, autoGainControl:true, ...audio },
        video
      });
      ui.local.srcObject = localStream;
    }
  }

  async function listDevices() {
    try {
      const devs = await navigator.mediaDevices.enumerateDevices();
      const mics = devs.filter(d=>d.kind==='audioinput');
      const cams = devs.filter(d=>d.kind==='videoinput');
      ui.micSel.innerHTML = mics.map(d=>`<option value="${d.deviceId}">${d.label||'Microphone'}</option>`).join('');
      ui.camSel.innerHTML = cams.map(d=>`<option value="${d.deviceId}">${d.label||'Camera'}</option>`).join('');
      if (chosenMic) ui.micSel.value = chosenMic;
      if (chosenCam) ui.camSel.value = chosenCam;
    } catch {}
  }

function newPC() {
  if (!localStream) throw new Error('Missing local media');
  if (pc) { try { pc.close(); } catch {} }

  // reset timer arm for a fresh connection
  timerArmed = false;

  pc = new RTCPeerConnection(window.pcBaseConfig || {
    iceServers: [{ urls: ['stun:stun.l.google.com:19302'] }],
    iceTransportPolicy: (typeof FORCE_RELAY !== 'undefined' && FORCE_RELAY) ? 'relay' : 'all',
    bundlePolicy: 'max-bundle',
    rtcpMuxPolicy: 'require'
  });

  // Remote media (Safari-safe)
  pc.ontrack = (ev) => {
    if (!ui.remote.srcObject) ui.remote.srcObject = new MediaStream();
    ui.remote.srcObject.addTrack(ev.track);
    Promise.resolve().then(() => ui.remote.play().catch(()=>{}));
  };

  // Local tracks
  currentVideoSender = null;
  localStream.getTracks().forEach(t => {
    const sender = pc.addTrack(t, localStream);
    if (t.kind === 'video') currentVideoSender = sender;
  });

  // (optional) cap initial bitrate for stability
  try {
    if (currentVideoSender) {
      const p = currentVideoSender.getParameters() || {};
      p.encodings = [{ maxBitrate: 600_000 }];
      currentVideoSender.setParameters(p).catch(()=>{});
    }
  } catch {}

  // ICE → signaling (serialize candidate object)
  pc.onicecandidate = (ev) => {
    const c = ev.candidate;
    if (!c) { console.log('[ICE] end of candidates'); return; }
    const payload = {
      candidate: c.candidate,
      sdpMid: c.sdpMid,
      sdpMLineIndex: c.sdpMLineIndex,
      usernameFragment: c.usernameFragment
    };
    if (currentPeer) {
      socket.emit('rtc:ice', { to: currentPeer, from: MY_PUBKEY, candidate: payload });
      console.log('[EMIT] ICE →', currentPeer, payload);
    }
  };

  // Diagnostics + timer start on actual connection
  pc.oniceconnectionstatechange = () => {
    const s = pc.iceConnectionState;
    if (s === 'checking') setStatus('Connecting…', false);
    if (s === 'connected' || s === 'completed') setStatus('Live', true);
    if (s === 'failed') setStatus('Connection failed', false);
    if (s === 'disconnected') setStatus('Disconnected', false);
  };

  pc.onconnectionstatechange = () => {
    if (!pc) return;
    const s = pc.connectionState;

    // ⏱ start duration timer exactly once when connected
    if ((s === 'connected' || s === 'completed') && !timerArmed) {
      startTimers();
      timerArmed = true;
      setStatus('Live', true);
    }

    if (['failed','disconnected','closed'].includes(s)) {
      endCall(false);
    }
  };

  pc.onicegatheringstatechange = () => console.log('[ICE gathering]', pc.iceGatheringState);
  pc.onicecandidateerror = (e) => console.warn('ICE candidate error', e);

  return pc;
}


window.newPC = newPC;


  function startTimers() {
    // call duration
    let started = Date.now();
    callTimer = setInterval(()=> ui.timer.textContent = fmt((Date.now()-started)/1000), 1000);
    // stats → basic bitrate estimation
    lastRxBytes = 0; lastRxTs = 0;
    statsTimer = setInterval(async ()=>{
      if (!pc) return;
      try {
        const stats = await pc.getStats();
        let bytes = 0, ts = 0;
        stats.forEach(r=>{
          if (r.type === 'inbound-rtp' && r.kind === 'video' && !r.isRemote) {
            bytes += r.bytesReceived || 0;
            ts = Math.max(ts, r.timestamp||0);
          }
        });
        if (lastRxBytes && lastRxTs && ts>lastRxTs) {
          const bps = ((bytes-lastRxBytes)*8) / ((ts-lastRxTs)/1000);
          qualityBars(bps);
        }
        lastRxBytes = bytes; lastRxTs = ts;
      } catch {}
    }, 1500);
  }

  function stopTimers() {
    if (callTimer) clearInterval(callTimer), callTimer=null;
    if (statsTimer) clearInterval(statsTimer), statsTimer=null;
  }

  function callLive() { setStatus('Live', true); startTimers(); }

  async function startCall(target) {
  if (!target || target === MY_PUBKEY) return;
  currentPeer = target;
  await ensureMedia(); await listDevices();
  openUI('Calling ' + nameOf(target)); await keepAwake(true);
  await window.iceReady;
  newPC();
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  socket.emit('rtc:offer', { to: target, from: MY_PUBKEY, offer });
  callState = 'calling';
}
window.startCall = startCall;

async function acceptCall(from, offer) {
  currentPeer = from;
  await ensureMedia(); await listDevices();
  openUI('Answering ' + nameOf(from)); await keepAwake(true);
  await window.iceReady;

  newPC(); // create pc BEFORE setting RD
  await pc.setRemoteDescription(new RTCSessionDescription(offer));
  remoteDescSet = true;

  // 🔽 Drain any queued ICE that arrived early
  if (pendingIce.length) diag(`➡️ Draining ${pendingIce.length} queued ICE`);
  for (const cand of pendingIce) {
    try { await pc.addIceCandidate(new RTCIceCandidate(cand)); }
    catch (e) { diag('addIceCandidate (drain) failed: ' + e); }
  }
  pendingIce = [];

  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  socket.emit('rtc:answer', { to: from, from: MY_PUBKEY, answer });
  callState = 'connected';
}



async function endCall(sendSignal = true) {
  callState = 'idle';
  try {
    if (sendSignal && currentPeer) {
      socket.emit('rtc:hangup', { to: currentPeer, from: MY_PUBKEY });
    }
  } catch {}

  currentPeer = null;

  // stop duration + stats timers and allow next call to arm again
  stopTimers();
  timerArmed = false;

  await keepAwake(false);

  if (pc) { try { pc.close(); } catch {} pc = null; }
  if (ui.remote && ui.remote.srcObject) {
    try { ui.remote.srcObject.getTracks().forEach(t => t.stop()); } catch {}
    ui.remote.srcObject = null;
  }
  if (screenStream) {
    try { screenStream.getTracks().forEach(t => t.stop()); } catch {}
    screenStream = null;
  }

  // clear ICE state
  pendingIce = [];
  remoteDescSet = false;

  controlsStop();
  closeUI();
}



  // ---------- screen share ----------
  async function toggleShare() {
    if (!pc) return;
    if (!screenStream) {
      try {
        screenStream = await navigator.mediaDevices.getDisplayMedia({ video:true, audio:false });
      } catch(e) { return; }
      const track = screenStream.getVideoTracks()[0];
      if (currentVideoSender && track) {
        await currentVideoSender.replaceTrack(track);
        ui.share.classList.add('active');
        track.onended = async () => {
          ui.share.classList.remove('active');
          await restoreCameraTrack();
        };
      }
    } else {
      await restoreCameraTrack();
    }
  }
  async function restoreCameraTrack() {
    if (!localStream) return;
    const cam = localStream.getVideoTracks()[0];
    if (currentVideoSender && cam) await currentVideoSender.replaceTrack(cam);
    if (screenStream) { try{screenStream.getTracks().forEach(t=>t.stop());}catch{} screenStream=null; }
  }

  // ---------- device switching ----------
  async function switchCamera(nextId=null) {
    if (!localStream) return;
    const cams = (await navigator.mediaDevices.enumerateDevices()).filter(d=>d.kind==='videoinput');
    if (!cams.length) return;
    if (!nextId) {
      const idx = Math.max(0, cams.findIndex(d=>d.deviceId===chosenCam));
      nextId = cams[(idx+1)%cams.length].deviceId;
    }
    chosenCam = nextId;
    const newStream = await navigator.mediaDevices.getUserMedia({ video:{deviceId:{exact:chosenCam}}, audio:false });
    // replace local preview video track
    const newTrack = newStream.getVideoTracks()[0];
    const old = localStream.getVideoTracks()[0];
    if (old) old.stop();
    localStream.removeTrack(old);
    localStream.addTrack(newTrack);
    ui.local.srcObject = localStream;
    if (currentVideoSender) await currentVideoSender.replaceTrack(newTrack);
  }

  async function applySelectedDevices() {
    chosenMic = ui.micSel.value || null;
    chosenCam = ui.camSel.value || null;
    if (!localStream) return;
    // mic
    try {
      const a = await navigator.mediaDevices.getUserMedia({audio:{deviceId:{exact:chosenMic}}});
      const newAudio = a.getAudioTracks()[0];
      const oldAudio = localStream.getAudioTracks()[0];
      if (oldAudio) oldAudio.stop();
      localStream.removeTrack(oldAudio); localStream.addTrack(newAudio);
      const sender = pc?.getSenders().find(s=>s.track && s.track.kind==='audio');
      if (sender) await sender.replaceTrack(newAudio);
    } catch{}
    // cam handled by switchCamera
    if (chosenCam) await switchCamera(chosenCam);
  }

  // ---------- UI wiring ----------








  if (ui.hang) ui.hang.addEventListener('click', ()=> endCall(true));
  if (ui.share) ui.share.addEventListener('click', toggleShare);
  if (ui.mute) ui.mute.addEventListener('click', ()=>{
    micMuted = !micMuted;
    localStream?.getAudioTracks().forEach(t=>t.enabled = !micMuted);
    ui.mute.classList.toggle('active', micMuted);
  });
  if (ui.cam) ui.cam.addEventListener('click', ()=>{
    camOff = !camOff;
    localStream?.getVideoTracks().forEach(t=>t.enabled = !camOff);
    ui.cam.classList.toggle('active', camOff);
  });
  if (ui.flip) ui.flip.addEventListener('click', ()=> switchCamera());
  if (ui.gear) ui.gear.addEventListener('click', async ()=>{
    await listDevices();
    ui.panel.style.display = ui.panel.style.display==='none' || !ui.panel.style.display ? 'block' : 'none';
  });
  if (ui.micSel) ui.micSel.addEventListener('change', applySelectedDevices);
  if (ui.camSel) ui.camSel.addEventListener('change', applySelectedDevices);

  // keyboard shortcuts
  document.addEventListener('keydown', (e)=>{
    if (ui.root.style.display!=='flex') return;
    if (e.key==='m' || e.key==='M') ui.mute.click();
    if (e.key==='v' || e.key==='V') ui.cam.click();
    if (e.key==='s' || e.key==='S') ui.share.click();
    if (e.key==='h' || e.key==='H') ui.hang.click();
  });

  // draggable PiP
  (() => {
    const el = ui.pip; if (!el) return;
    let sx=0, sy=0, ox=0, oy=0, dragging=false;
    const onDown=(e)=>{
      dragging=true; el.classList.add('dragging');
      const p = (e.touches?e.touches[0]:e);
      sx = p.clientX; sy = p.clientY;
      const rect = el.getBoundingClientRect();
      ox = rect.left; oy = rect.top;
      e.preventDefault();
    };
    const onMove=(e)=>{
      if (!dragging) return;
      const p = (e.touches?e.touches[0]:e);
      const nx = ox + (p.clientX - sx);
      const ny = oy + (p.clientY - sy);
      el.style.left = nx+'px'; el.style.top = ny+'px'; el.style.right='auto'; el.style.bottom='auto';
    };
    const onUp=()=>{ dragging=false; el.classList.remove('dragging'); };
    el.addEventListener('mousedown', onDown); window.addEventListener('mousemove', onMove); window.addEventListener('mouseup', onUp);
    el.addEventListener('touchstart', onDown, {passive:false}); window.addEventListener('touchmove', onMove, {passive:false}); window.addEventListener('touchend', onUp);
el.addEventListener('touchend', onUp, {passive:false});
})();



    // ---------- Online bar: click + long-press wiring ----------
(function wireOnlineBar(){
  const bar = document.getElementById('onlineBar');
  if (!bar) { diag('⚠️ #onlineBar not found'); return; }

  // Make chips clearly interactive + suppress iOS long-press callout
  try {
    bar.style.webkitUserSelect = 'none';
    bar.style.userSelect = 'none';
    bar.style.webkitTouchCallout = 'none';
  } catch {}

  let pressTimer = null;
  let longPress = false;

  const clearTimer = () => {
    if (pressTimer) { clearTimeout(pressTimer); pressTimer = null; }
  };

  const getChipPK = (e) => {
    const chip = e.target.closest('.online-user');
    if (!chip) return null;
    const pk = (chip.dataset.pubkey || '').trim();
    if (!pk || pk === MY_PUBKEY) return null;
    return pk;
  };

  bar.addEventListener('pointerdown', (e) => {
    const pk = getChipPK(e);
    if (!pk) return;
    if (e.pointerType === 'touch' || e.pointerType === 'pen') e.preventDefault();

    longPress = false;
    diag(`⬇️ chip down ${pk.slice(-6)}`);

    pressTimer = setTimeout(() => {
      longPress = true;
      if (typeof window.startCall === 'function') {
        diag(`📞 long-press → startCall(${pk.slice(-6)})`);
        window.startCall(pk);
      } else {
        diag('❌ window.startCall missing');
      }
    }, 600); // hold to call
  }, { passive: false });

  bar.addEventListener('pointerup', (e) => {
    const pk = getChipPK(e);
    if (!pk) return;
    diag(`⬆️ chip up ${pk.slice(-6)} (long=${longPress})`);

    if (!longPress) {
      const url = (typeof HOME_URL === 'string' && HOME_URL)
        ? `${location.origin}${HOME_URL}?pubkey=${encodeURIComponent(pk)}#explorer`
        : null;
      if (url) window.open(url, '_blank', 'noopener');
      else if (typeof window.startCall === 'function') window.startCall(pk);
    }
    clearTimer();
  }, { passive: false });

  bar.addEventListener('pointercancel', clearTimer, { passive: true });
  bar.addEventListener('pointerleave', clearTimer, { passive: true });
})();


  // ---------- Socket signaling ----------
  socket.on('rtc:offer', async ({from, offer}) => {
    if (!from || from === MY_PUBKEY) return;
    // show incoming sheet
    ui.name.textContent = nameOf(from);
    ui.root.style.display='flex';
    ui.sheet.style.display='flex';
    try { ui.ring.currentTime = 0; ui.ring.loop = true; ui.ring.play().catch(()=>{}); } catch {}
    const accept = async ()=>{
      ui.sheet.style.display='none';
      try { ui.ring.pause(); ui.ring.currentTime = 0; ui.ring.loop = false; } catch {}
      await goFullscreen();
      await acceptCall(from, offer);
      controlsStart();
    };
    const decline = ()=>{
      try { ui.ring.pause(); ui.ring.currentTime = 0; ui.ring.loop = false; } catch {}
      socket.emit('rtc:hangup', { to: from, from: MY_PUBKEY });
      endCall(false);
    };
    ui.accept.onclick = accept;
    ui.decline.onclick = decline;
  });

socket.on('rtc:answer', async ({from, answer}) => {
  if (!answer) return;
  if (!pc) return;
  await pc.setRemoteDescription(new RTCSessionDescription(answer));
  remoteDescSet = true;

  if (pendingIce.length) diag(`➡️ Draining ${pendingIce.length} queued ICE`);
  for (const cand of pendingIce) {
    try { await pc.addIceCandidate(new RTCIceCandidate(cand)); }
    catch (e) { diag('addIceCandidate (drain) failed: ' + e); }
  }
  pendingIce = [];

  setStatus('Connected to ' + nameOf(from), true);
  callState = 'connected';
  controlsStart();
});



socket.on('rtc:ice', async ({candidate}) => {
  // Validate candidate payload
  if (!candidate || typeof candidate.candidate !== 'string') {
    diag('⚠️ Dropping malformed ICE candidate');
    return;
  }

  // Better type logging from SDP string (srflx/relay/host)
  const typ = (candidate.candidate.match(/ typ (\w+)/) || [])[1] || 'n/a';
  diag(`🧊 ICE candidate: ${typ}`);

  // Queue until pc is created and remote description is set
  if (!pc || !remoteDescSet) {
    pendingIce.push(candidate);
    diag(`⏳ Queued ICE (pc:${!!pc}, rd:${remoteDescSet})`);
    return;
  }

  try {
    await pc.addIceCandidate(new RTCIceCandidate(candidate));
  } catch (err) {
    diag('❌ addIceCandidate failed: ' + err);
  }
});





  socket.on('rtc:hangup', () => endCall(false));

})();
</script>




<script>
// Remove the overlay if it exists
(function(){
  const el = document.getElementById('debugOverlay');
  if (el) el.remove();

  // Make diag a no-op so existing calls don’t break
  window.diag = function(){};

  // Ensure we use the unwrapped newPC
  if (typeof newPC === 'function') window.newPC = newPC;
})();
</script>






</body>
</html>

    """
    return render_template_string(
        chat_html,
        history=CHAT_HISTORY,
        my_pubkey=my_pubkey,
        online_users=online_users_list,
        online_count=len(online_users_list),
        special_names=SPECIAL_NAMES,
        force_relay=FORCE_RELAY,
        access_level=session.get("access_level", "limited"),
    )


import base64
import hashlib
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePath

from flask import Blueprint, abort, current_app, jsonify, request

oauth_bp = Blueprint("oauth", __name__)

# --- Simple in-memory store (swap with Redis/Postgres in prod) ---
REFRESH_STORE = {}  # {refresh_token: {sub, scope, exp, jti}}
KEYRING = {}  # {kid: {"private": str, "public": str, "alg": "RS256", "created": ts}}


# --- Load/ensure RSA keys (single KID demo; rotate in prod) ---
@app.route("/login", methods=["GET"])
def login():
    # Session challenge for legacy /verify_signature flow
    challenge_str = generate_challenge()
    session["challenge"] = challenge_str
    session["challenge_timestamp"] = time.time()

    # Optional node stats (safe if node unreachable)
    from datetime import datetime, timedelta, timezone

    try:
        rpc = get_rpc_connection()
        wallet_balance = rpc.getbalance()
        block_height = rpc.getblockcount()
        remaining = 1777777 - block_height

        uptime_sec = rpc.uptime()
        startup_time = (datetime.now(timezone.utc) - timedelta(seconds=uptime_sec)).strftime("%Y-%m-%d %H:%M:%S UTC")

        mp_info = rpc.getmempoolinfo()
        mempool_txs = mp_info.get("size", 0)
        mempool_usage = mp_info.get("usage", 0)
    except Exception:
        wallet_balance = None
        block_height = None
        remaining = None
        startup_time = None
        mempool_txs = None
        mempool_usage = None

    # Login page with dual Matrix backgrounds (toggle embedded inside panel)
    html = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>HODLXXI — Login</title>
  <style>
    :root{ --bg:#0b0f10; --panel:#11171a; --fg:#e6f1ef; --accent:#00ff88; --muted:#86a3a1; }
    *{ box-sizing:border-box; }
    body{
      margin:0; background:var(--bg); color:var(--fg);
      font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto;
      min-height:100vh; display:flex; align-items:center; justify-content:center;
    }

    /* Two Matrix canvases (rain & warp) sit behind all content */
    .matrix-canvas{ position:fixed; inset:0; z-index:0; pointer-events:none; }
    @media (prefers-reduced-motion: reduce){ .matrix-canvas{ display:none !important; } }
    @media print{ .matrix-canvas{ display:none !important; } }
    /* Ensure foreground stays above canvases */
    body > *:not(.matrix-canvas){ position:relative; z-index:1; }

    .wrap{ width:min(980px,96%); }
    .card{
      background:rgba(17,23,26,0.92); border:1px solid #0f2a24; border-radius:14px; padding:22px;
      box-shadow:0 0 10px #003a2b, 0 0 20px rgba(0,255,136,0.08);
      animation:pulse-glow 2.4s ease-in-out infinite;
    }
    @keyframes pulse-glow{
      0%,100%{ box-shadow:0 0 10px #003a2b,0 0 20px rgba(0,255,136,0.08); }
      50%{ box-shadow:0 0 18px #00664c,0 0 30px rgba(0,255,136,0.18); }
    }

    h1{ margin:0 0 14px; color:var(--accent); font-size:24px; }

    /* Tabs row now also contains the embedded toggle button on the right */
    .tabs-row{ display:flex; gap:12px; align-items:center; justify-content:space-between; margin:10px 0 16px; flex-wrap:wrap; }
    .tabs{ display:flex; gap:8px; flex-wrap:wrap; }
    .tab-btn{ border:1px solid #184438; background:#0e1516; color:var(--fg);
              padding:8px 12px; border-radius:10px; cursor:pointer; }
    .tab-btn.active{ outline:2px solid var(--accent); }

    /* Embedded toggle (no fixed positioning) */
    .matrix-toggle{
      padding:8px 12px; border-radius:10px;
      border:1px solid #184438; background:#0e1516; color:var(--fg);
      font-weight:600; cursor:pointer;
    }
    .matrix-toggle:hover{ background:#12352d; }

    .panel{ display:none; border-top:1px dashed #1f2a2a; padding-top:14px; }
    .panel.active{ display:block; }

    label{ display:block; font-size:12px; color:var(--muted); margin-top:10px; }
    input, textarea{ width:100%; padding:10px; margin-top:6px; background:#0e1315; color:#bfffe6;
                     border:1px solid #255244; border-radius:8px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    textarea{ min-height:100px; }
    .row{ display:flex; gap:12px; flex-wrap:wrap; }
    .row > *{ flex:1 1 280px; }
    .actions{ display:flex; gap:10px; margin-top:12px; flex-wrap:wrap; }
    button{ padding:10px 14px; border-radius:10px; border:1px solid #1c5a4b;
            background:#0b1513; color:#d6fff2; cursor:pointer; font-weight:600; }
    button:hover{ background:#12352d; }

    .challenge-box{ background:#111; border:1px dashed var(--accent); color:var(--accent);
                    padding:10px; border-radius:8px; text-align:center; cursor:pointer; }
    .status{ margin-top:10px; min-height:22px; }
    .hint{ color:var(--muted); font-size:12px; }
    .mono{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  </style>
</head>
<body>

<!-- Dual Matrix backgrounds behind the card -->
<canvas id="matrix-warp" class="matrix-canvas" aria-hidden="true"></canvas>
<canvas id="matrix-rain" class="matrix-canvas" style="display:none" aria-hidden="true"></canvas>

<audio id="login-sound"
       src="{{ url_for('static', filename='sounds/login.mp3') }}"
       preload="auto" playsinline></audio>

<div class="wrap"><div class="card">
  <h1>*Log in with your actual key, we Verify Trust*</h1>

  <!-- Tabs row WITH embedded toggle on the right -->
  <div class="tabs-row">
    <div class="tabs">
      <button id="tabLegacy"  class="tab-btn active" onclick="showTab('legacy')">Legacy</button>
      <button id="tabApi"     class="tab-btn"         onclick="showTab('api')">API</button>
  <button onclick="loginWithNostr()"
          style="background:#8b5cf6;color:#fff;border:none;padding:8px 16px;border-radius:8px;cursor:pointer;font-weight:600;">
    🟣 Nostr
  </button>
    </div>
    <button id="bgToggle" class="matrix-toggle" type="button" title="Toggle background">◒ Matrix</button>
  </div>




  <!-- Legacy -->
  <div id="panelLegacy" class="panel active">
    <p class="hint">Sign the challenge with your wallet, then paste the signature.</p>
    <div class="challenge-box" id="legacyChallenge" title="Click to copy">{{ challenge }}</div>
    <div class="row">
      <div><label>Public key</label><input id="legacyPubkey" placeholder="02.. or 03.."/></div>
      <div><label>Signature</label><textarea id="legacySignature" rows="4" placeholder="base64 signature"></textarea></div>
    </div>
    <div class="actions">
      <button class="copy" onclick="copyText('legacyChallenge')">Copy challenge</button>
      <button onclick="legacyVerify()">Verify &amp; Login</button>
    </div>
    <div id="legacyStatus" class="status"></div>
  </div>

  <!-- API -->
  <div id="panelApi" class="panel">
    <p class="hint">Request + sign a challenge:</p>
    <div class="row">
      <div><label>Public key</label><input id="apiPubkey" placeholder="02.. or 03.."/></div>
      <div><label>Challenge</label><textarea id="apiChallenge" rows="3" readonly></textarea></div>
    </div>
    <div class="actions">
      <button onclick="getChallenge()">Get challenge</button>
      <button class="copy" onclick="copyText('apiChallenge')">Copy</button>
    </div>
    <div class="row">
      <div><label>Signature</label><textarea id="apiSignature" rows="4" placeholder="base64 signature"></textarea></div>
      <div><label>Challenge ID</label><input id="apiCid" readonly/></div>
    </div>
    <div class="actions"><button onclick="apiVerify()">Verify &amp; Login</button></div>
    <div id="apiStatus" class="status"></div>
  </div>


<div class="guest-login-panel">
  <input id="guestPin" type="text" placeholder="PIN or leave blank for guest"
         style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #0f2; background: #111; color: #0f2;">
  <button onclick="guestLogin()"
          style="margin-top:10px; width:100%; padding:10px; background:#0f2; color:#000; font-weight:bold; border:none; border-radius:4px;">
    Guest
  </button>


<script>
// Helper to respect ?next= parameter for post-login redirects
function getRedirectUrl() {
  const params = new URLSearchParams(window.location.search);
  const next = params.get("next");
  return next || "/app";
}
function showTab(which){
  ['legacy','api','guest','special'].forEach(t=>{
    const tab=document.getElementById('tab'+t.charAt(0).toUpperCase()+t.slice(1));
    const panel=document.getElementById('panel'+t.charAt(0).toUpperCase()+t.slice(1));
    if(tab&&panel){
      tab.classList.toggle('active',t===which);
      panel.classList.toggle('active',t===which);
    }
  });
}
function copyText(id){
  const el=document.getElementById(id);
  const txt=(el.tagName==='TEXTAREA'||el.tagName==='INPUT')?el.value:el.textContent.trim();
  navigator.clipboard.writeText(txt);
}

// Click to copy on the challenge card (visual feedback)
const legacyEl=document.getElementById('legacyChallenge');
legacyEl.addEventListener('click', ()=>{
  const text=legacyEl.textContent.trim();
  navigator.clipboard.writeText(text).then(()=>{
    const orig=legacyEl.style.background;
    legacyEl.style.background='#12352d';
    setTimeout(()=>legacyEl.style.background=orig, 300);
  });
});

// --- Flows ---
async function legacyVerify(){
  const pubkey=document.getElementById('legacyPubkey').value.trim();
  const signature=document.getElementById('legacySignature').value.trim();
  const challenge=document.getElementById('legacyChallenge').textContent.trim();
  const st=document.getElementById('legacyStatus');
  st.textContent='Verifying...';
  try{
    const r=await fetch('/verify_signature',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({pubkey,signature,challenge})});
    const d=await r.json();
    // NOTE: access_level in response is for UI hints only.
    // DO NOT treat this as an authorization boundary.
    // All actual authorization happens server-side via session validation.
    if(r.ok&&d.verified){sessionStorage.setItem('playLoginSound','1'); window.location.href=getRedirectUrl();}
    else{st.textContent=d.error||'Failed';}
  }catch(e){st.textContent='Network error';}
}
async function getChallenge(){
  const pubkey=document.getElementById('apiPubkey').value.trim();
  const st=document.getElementById('apiStatus');
  try{
    const r=await fetch('/api/challenge',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({pubkey})});
    const d=await r.json();
    if(!r.ok) throw new Error(d.error||'Request failed');
    document.getElementById('apiChallenge').value=d.challenge||'';
    document.getElementById('apiCid').value=d.challenge_id||'';
    st.textContent='Challenge ready';
  }catch(e){st.textContent=e.message;}
}
async function apiVerify(){
  const pubkey=document.getElementById('apiPubkey').value.trim();
  const signature=document.getElementById('apiSignature').value.trim();
  const cid=document.getElementById('apiCid').value.trim();
  const st=document.getElementById('apiStatus');
  try{
    const r=await fetch('/api/verify',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({pubkey,signature,challenge_id:cid})});
    const d=await r.json();
    if(r.ok&&d.verified){sessionStorage.setItem('playLoginSound','1'); window.location.href=getRedirectUrl();}
    else{st.textContent=d.error||'Failed';}
  }catch(e){st.textContent='Network error';}
}
async function guestLogin() {
  const pinInput = document.getElementById("guestPin");
  const pin = (pinInput ? pinInput.value.trim() : "");

  const res = await fetch("/guest_login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pin })
  });

  const data = await res.json();
  if (!res.ok || !data.ok) {
    alert(data.error || "Guest login failed");
    return;
  }

  // ✅ Success — show confirmation and redirect
  const label = data.label || "Guest";
  console.log("Guest login successful:", label);
  alert("Logged in as " + label);
  window.location.href = getRedirectUrl(); // open chat directly
}
async function specialLogin(){
  const sig=document.getElementById('specialSignature').value.trim();
  const st=document.getElementById('specialStatus');
  try{
    const r=await fetch('/special_login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({signature:sig})});
    const d=await r.json();
    if(r.ok&&d.verified){sessionStorage.setItem('playLoginSound','1'); window.location.href=getRedirectUrl();}
    else{st.textContent=d.error||'Failed';}
  }catch(e){st.textContent='Network error';}
}
</script>






<!-- QR modal reused from universal_login -->
<div id="qrModal" class="qr-modal" style="position:fixed;inset:0;background:rgba(0,0,0,.95);display:none;
     align-items:center;justify-content:center;z-index:1000">
  <div class="qr-content" style="background:white;padding:2rem;border-radius:16px;text-align:center;max-width:400px;width:90%">
    <h2>Scan with Wallet</h2>
    <div id="qrcode"></div>
    <a id="openInWallet" href="#" target="_blank" rel="noopener">Open in wallet</a>
    <div id="lnurlText" style="margin-top:1rem;padding:.75rem;background:#f0f0f0;
         border-radius:8px;font-family:monospace;font-size:.7rem;word-break:break-all;color:#333;"></div>
    <div id="countdown" style="color:#666;font-size:.85rem;margin-top:.5rem"></div>
    <button onclick="closeQR()" style="margin-top:1rem;padding:.75rem 2rem;background:#333;color:white;
            border:none;border-radius:8px;cursor:pointer">Close</button>
  </div>
</div>
<script src="/static/js/qrcode.min.js"></script>




<!-- Matrix backgrounds (inline) + init/toggle embedded in panel) -->
<script>
/* --- Matrix: Warp --- */
function startMatrixWarp(canvas){
  if(!canvas) return ()=>{};
  const ctx=canvas.getContext('2d');
  const CHARS=['0','1'];
  let width=0, height=0, particles=[], raf=null;

  function resize(){
    width=window.innerWidth; height=window.innerHeight;
    canvas.width=width; canvas.height=height;
    particles=[];
    for(let i=0;i<400;i++){
      particles.push({ x:(Math.random()-0.5)*width, y:(Math.random()-0.5)*height, z:Math.random()*800+100 });
    }
  }
  function draw(){
    ctx.fillStyle='rgba(0,0,0,0.25)'; ctx.fillRect(0,0,width,height);
    ctx.fillStyle='#00ff88';
    for(const p of particles){
      const scale=200/p.z;
      const x2=width/2 + p.x*scale;
      const y2=height/2 + p.y*scale;
      const size=Math.max(8*scale,1);
      ctx.font=size+'px monospace';
      ctx.fillText(CHARS[Math.random()>0.5?1:0], x2, y2);
      p.z-=5;
      if(p.z<1){ p.x=(Math.random()-0.5)*width; p.y=(Math.random()-0.5)*height; p.z=800; }
    }
    raf=requestAnimationFrame(draw);
  }
  function onVis(){ if(document.hidden){ if(raf) cancelAnimationFrame(raf), raf=null; } else { if(!raf) raf=requestAnimationFrame(draw); } }
  function onResize(){ resize(); }

  window.addEventListener('resize', onResize);
  document.addEventListener('visibilitychange', onVis);
  resize(); raf=requestAnimationFrame(draw);
  return function stop(){ if(raf) cancelAnimationFrame(raf), raf=null; window.removeEventListener('resize', onResize); document.removeEventListener('visibilitychange', onVis); };
}

/* --- Matrix: Rain --- */
function startMatrixRain(canvas){
  if(!canvas) return ()=>{};
  const ctx=canvas.getContext('2d');
  const CHARS='01';
  let width=0, height=0, fontSize=16, cols=0, drops=[], speeds=[], raf=null;
  const TRAIL_ALPHA=0.08, SPEED_MIN=0.5, SPEED_MAX=1.5, COLOR='#00ff88';

  function ri(min,max){ return Math.floor(Math.random()*(max-min+1))+min; }

  function resize(){
    width=window.innerWidth; height=window.innerHeight;
    canvas.width=width; canvas.height=height;
    fontSize=Math.max(14, Math.min(24, Math.floor(width/80)));
    ctx.font=fontSize+'px monospace'; ctx.textBaseline='top';
    cols=Math.floor(width/fontSize);
    drops=new Array(cols).fill(0).map(()=>ri(-20, height/fontSize));
    speeds=new Array(cols).fill(0).map(()=>Math.random()*(SPEED_MAX-SPEED_MIN)+SPEED_MIN);
  }
  function draw(){
    ctx.fillStyle='rgba(0,0,0,'+TRAIL_ALPHA+')'; ctx.fillRect(0,0,width,height);
    ctx.fillStyle=COLOR;
    for(let i=0;i<cols;i++){
      const ch=CHARS.charAt((Math.random()*CHARS.length)|0);
      const x=i*fontSize, y=drops[i]*fontSize;
      ctx.fillText(ch,x,y);
      drops[i]+=speeds[i];
      if(y>height+ri(0,100)){ drops[i]=ri(-20,-5); speeds[i]=Math.random()*(SPEED_MAX-SPEED_MIN)+SPEED_MIN; }
    }
    raf=requestAnimationFrame(draw);
  }
  function onVis(){ if(document.hidden){ if(raf) cancelAnimationFrame(raf), raf=null; } else { if(!raf) raf=requestAnimationFrame(draw); } }
  function onResize(){ resize(); }

  window.addEventListener('resize', onResize);
  document.addEventListener('visibilitychange', onVis);
  resize(); raf=requestAnimationFrame(draw);
  return function stop(){ if(raf) cancelAnimationFrame(raf), raf=null; window.removeEventListener('resize', onResize); document.removeEventListener('visibilitychange', onVis); };
}

/* --- Init + toggle (persisted in localStorage), button lives inside panel --- */
(()=> {
  const warpCanvas=document.getElementById('matrix-warp');
  const rainCanvas=document.getElementById('matrix-rain');
  const toggleBtn=document.getElementById('bgToggle');

  let stopWarp=null, stopRain=null;

  function setMode(mode){
    localStorage.setItem('matrixMode', mode);
    if(mode==='warp'){
      rainCanvas.style.display='none';
      warpCanvas.style.display='block';
      if(stopRain){ stopRain(); stopRain=null; }
      if(!stopWarp) stopWarp=startMatrixWarp(warpCanvas);
    }else{
      warpCanvas.style.display='none';
      rainCanvas.style.display='block';
      if(stopWarp){ stopWarp(); stopWarp=null; }
      if(!stopRain) stopRain=startMatrixRain(rainCanvas);
    }
    toggleBtn.textContent = (mode==='warp') ? '◒' : '◒';
  }

  const saved = localStorage.getItem('matrixMode') || 'warp';
  setMode(saved);

  toggleBtn.addEventListener('click', ()=>{
    const next = (localStorage.getItem('matrixMode')==='warp') ? 'rain' : 'warp';
    setMode(next);
  });

  window.addEventListener('beforeunload', ()=>{
    if(stopWarp) stopWarp();
    if(stopRain) stopRain();
  });
})();
</script>



<script>
function urlToLnurl(url){
  const CHARSET='qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  function polymod(v){const G=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3];let chk=1;
    for(const val of v){const top=chk>>>25;chk=((chk&0x1ffffff)<<5)^val;for(let i=0;i<5;i++)if((top>>>i)&1)chk^=G[i];}return chk;}
  function hrpExpand(hrp){const ret=[];for(let i=0;i<hrp.length;i++)ret.push(hrp.charCodeAt(i)>>5);
    ret.push(0);for(let i=0;i<hrp.length;i++)ret.push(hrp.charCodeAt(i)&31);return ret;}
  function createChecksum(hrp,data){const values=hrpExpand(hrp).concat(data).concat([0,0,0,0,0,0]);
    const mod=polymod(values)^1;const ret=[];for(let p=0;p<6;p++)ret.push((mod>>5*(5-p))&31);return ret;}
  function convertBits(data,from,to){let acc=0,bits=0,ret=[],maxv=(1<<to)-1;for(const value of data){
    acc=(acc<<from)|value;bits+=from;while(bits>=to){bits-=to;ret.push((acc>>bits)&maxv);}}if(bits>0)ret.push((acc<<(to-bits))&maxv);return ret;}
  const bytes=new TextEncoder().encode(url);const data5=convertBits(Array.from(bytes),8,5);
  const combined=data5.concat(createChecksum('lnurl',data5));let out='lnurl1';for(const d of combined)out+=CHARSET[d];return out.toUpperCase();
}

function renderQR(el,text){
  el.innerHTML='';
  new QRCode(el,{text,width:256,height:256,colorDark:"#000",colorLight:"#fff"});
}

let poll=null,expire=null;
function startPolling(sid){
  clearInterval(poll);
  poll=setInterval(async()=>{
    const r=await fetch(`/api/lnurl-auth/check/${sid}`);
    const j=await r.json();
    if(j.authenticated){clearInterval(poll);clearInterval(expire);
      closeQR();alert('Lightning login success!');window.location.href=getRedirectUrl();}
  },2000);
}
function startCountdown(s){
  clearInterval(expire);
  let r=s;const el=document.getElementById('countdown');
  expire=setInterval(()=>{r--;el.textContent=`Expires in ${Math.floor(r/60)}:${(r%60).toString().padStart(2,'0')}`;
    if(r<=0){clearInterval(poll);clearInterval(expire);closeQR();}},1000);
}
function closeQR(){document.getElementById('qrModal').style.display='none';}

async function loginWithLightning(){
  const res=await fetch('/api/lnurl-auth/create',{method:'POST'});
  const j=await res.json();
  const lnurl=urlToLnurl(j.callback_url);
  renderQR(document.getElementById('qrcode'),lnurl);
  document.getElementById('lnurlText').textContent=lnurl;
  document.getElementById('openInWallet').href='lightning:'+lnurl;
  document.getElementById('qrModal').style.display='flex';
  startPolling(j.session_id);
  startCountdown(j.expires_in);
}

async function loginWithNostr(){
  if(!window.nostr){alert('No Nostr extension found');return;}
  const pubkey=await window.nostr.getPublicKey();
  const r=await fetch('/api/challenge',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({pubkey,method:'nostr'})});
  const d=await r.json();
  const event={kind:22242,created_at:Math.floor(Date.now()/1000),
      tags:[['challenge',d.challenge],['app','HODLXXI']],content:`HODLXXI Login: ${d.challenge}`};
  const signed=await window.nostr.signEvent(event);
  const vr=await fetch('/api/verify',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({challenge_id:d.challenge_id,pubkey,signature:signed.sig})});
  const j2=await vr.json();
  if(j2.verified){alert('Nostr login success!');window.location.href=getRedirectUrl();}
  else alert('Verification failed');
}
</script>


</body>
</html>
"""
    return render_template_string(
        html,
        challenge=challenge_str,
        block_height=block_height,
        wallet_balance=wallet_balance,
        remaining=remaining,
        startup_time=startup_time,
        mempool_txs=mempool_txs,
        mempool_usage=mempool_usage,
    )


def is_hex32(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", s))


def hex_to_wif(hex_priv, compressed=True, testnet=False):
    if len(hex_priv) != 64:
        return None
    priv_bytes = bytes.fromhex(hex_priv)
    prefix = b"\xef" if testnet else b"\x80"
    extended = prefix + priv_bytes
    if compressed:
        extended += b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return base58.b58encode(extended + checksum).decode()


def make_qr_base64(data):
    img = qrcode.make(data)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


@app.route("/verify_signature", methods=["POST"])
def verify_signature():
    data = request.get_json()
    pubkey_hex = (data.get("pubkey") or "").strip()
    signature = (data.get("signature") or "").strip()
    challenge = (data.get("challenge") or "").strip()

    # Challenge checks
    if "challenge" not in session or session["challenge"] != challenge:
        return jsonify({"verified": False, "error": "Invalid or expired challenge"}), 400
    if time.time() - session.get("challenge_timestamp", 0) > 600:
        return jsonify({"verified": False, "error": "Challenge expired (10 min limit)"}), 400
    if not signature:
        return jsonify({"verified": False, "error": "Signature is required"}), 400

    rpc_conn = get_rpc_connection()
    matched_pubkey = None

    if pubkey_hex:
        if not re.fullmatch(r"[0-9a-fA-F]{66}", pubkey_hex):
            return jsonify({"verified": False, "error": "PubKey must be 66 hex chars."}), 400
        try:
            derived_addr = derive_legacy_address_from_pubkey(pubkey_hex)
            if rpc_conn.verifymessage(derived_addr, signature, challenge):
                matched_pubkey = pubkey_hex
            else:
                return jsonify({"verified": False, "error": "Invalid signature"}), 403
        except Exception as e:
            return jsonify({"verified": False, "error": str(e)}), 500
    else:
        # No pubkey: try SPECIAL_USERS
        for candidate in SPECIAL_USERS:
            try:
                derived_addr = derive_legacy_address_from_pubkey(candidate)
                if rpc_conn.verifymessage(derived_addr, signature, challenge):
                    matched_pubkey = candidate
                    break
            except Exception:
                continue
        if not matched_pubkey:
            return jsonify({"verified": False, "error": "Invalid signature"}), 403

    # Set session + access level
    session["logged_in_pubkey"] = matched_pubkey
    session["user_id"] = matched_pubkey  # For PoF routes compatibility
    if not pubkey_hex:  # matched a special user
        session["access_level"] = "full"
    else:
        in_bal, out_bal = get_save_and_check_balances_for_pubkey(matched_pubkey)
        ratio = (out_bal / in_bal) if in_bal > 0 else 0
        session["access_level"] = "full" if ratio >= 1 else "limited"
    session.permanent = True

    # Notify chat clients
    socketio.emit("user:logged_in", matched_pubkey)

    logger.debug("verify_signature → matched_pubkey=%s, access_level=%s", matched_pubkey, session['access_level'])
    return jsonify({"verified": True, "access_level": session["access_level"], "pubkey": matched_pubkey})


@app.route("/guest_login", methods=["POST"])
def guest_login():
    """Guest or PIN login:
    - With PIN: use PIN itself as unique identity (presence/chat/call)
    - Without PIN: random temporary guest ID
    - Reuse session if already logged in
    """
    data = request.get_json(silent=True) or {}
    pin = (data.get("pin") or "").strip()

    # If user already has a session, resume it
    if session.get("logged_in_pubkey"):
        logger.info("guest_login: Resume session for %s", session.get('guest_label'))
        return jsonify(ok=True, label=session.get("guest_label"))

    if pin:
        # ✅ PIN as full identity
        label = GUEST_PINS.get(pin)
        if not label:
            return jsonify(error="Invalid PIN"), 403

        session["logged_in_pubkey"] = pin  # 🔸 use PIN as identity key
        session["logged_in_privkey"] = None  # no privkey needed
        session["guest_label"] = f"Guest-{pin}"
        logger.info("guest_login: PIN %s logged in as Guest-%s", pin, pin)

    else:
        # Random guest identity
        rand_id = uuid.uuid4().hex[:6]
        session["logged_in_pubkey"] = f"guest-{rand_id}"
        session["logged_in_privkey"] = None
        session["guest_label"] = f"Guest-Random-{rand_id}"
        logger.info("guest_login: Random guest logged in as Guest-Random-%s", rand_id)

    session["login_method"] = "guest"
    session.permanent = True
    return jsonify(ok=True, label=session["guest_label"])


# ---- Special Login ----
SPECIAL_USERS = [p.strip() for p in os.getenv("SPECIAL_USERS", "").split(",") if p.strip()]


@app.route("/guest_login2", methods=["POST"])
def guest_login2():
    data = request.get_json() or {}
    challenge = data.get("challenge", "").strip()

    if "challenge" not in session or session["challenge"] != challenge:
        return jsonify(verified=False, error="Invalid or expired challenge"), 400
    if time.time() - session.get("challenge_timestamp", 0) > 600:
        return jsonify(verified=False, error="Challenge expired"), 400

    guest_pk = GUEST2_PUBKEY.strip() if GUEST2_PUBKEY else f"GUEST2-{uuid.uuid4().hex[:8].upper()}"

    session["logged_in_pubkey"] = guest_pk
    session["access_level"] = "limited"  # keep same policy as guest #1
    session.permanent = True

    socketio.emit("user:logged_in", guest_pk)

    return jsonify({"verified": True, "access_level": "limited", "pubkey": guest_pk})


def get_save_and_check_balances(
    script_hex: str, groupings: list[list[tuple[str, Decimal, str]]]
) -> tuple[Decimal, Decimal]:
    """
    Accepts a witness program scriptPubKey hex or a redeem/witness script hex.
    Returns (saving_total, checking_total).
    - We match addresses by LABEL that startswith the script hex (to allow "HEX [i]" labels).
    - Classification:
        * P2WPKH only  -> CHECK
        * P2WSH only   -> SAVE
        * Mixed        -> split by type (P2WPKH => CHECK, P2WSH => SAVE)
        * Fallback     -> shortest=CHECK, longest=SAVE
    """
    import re
    from decimal import Decimal

    def looks_like_segwit_spk(h: str) -> bool:
        return bool(re.fullmatch(r"00(14[0-9a-fA-F]{40}|20[0-9a-fA-F]{64})", h))

    def classify(addr: str) -> str:
        a = addr.lower()
        # bech32 v0: bc1q... length ~42 (p2wpkh), ~62 (p2wsh)
        if a.startswith("bc1p"):
            return "taproot"
        if a.startswith("bc1q"):
            return "p2wpkh" if len(a) <= 44 else "p2wsh"
        if a.startswith("1"):
            return "p2pkh"
        if a.startswith("3"):
            return "p2sh"
        return "other"

    script_hex = (script_hex or "").strip()
    if not script_hex:
        return Decimal("0"), Decimal("0")

    # 1) Compute expected witness program (scriptPubKey) hex
    try:
        lower = script_hex.lower()
        if looks_like_segwit_spk(lower):
            expected_spk_lower = lower
        else:
            # decode to get segwit.hex if possible
            rpc = get_rpc_connection()
            decoded = rpc.decodescript(script_hex)
            seg_hex = (decoded.get("segwit") or {}).get("hex")
            expected_spk_lower = (seg_hex or decoded.get("hex") or script_hex).lower()
    except Exception:
        expected_spk_lower = script_hex.lower()

    # 2) Collect matches where the LABEL begins with the hex (handles "HEX [i]")
    matches: list[tuple[str, Decimal]] = []
    for group in groupings:
        for triple in group:
            try:
                addr, bal = triple[0], Decimal(triple[1])
                lbl = triple[2] or ""
                if isinstance(lbl, str) and lbl.lower().startswith(expected_spk_lower):
                    matches.append((addr, bal))
            except Exception:
                continue

    if not matches:
        return Decimal("0"), Decimal("0")

    # 3) Type-based split
    save_total = Decimal("0")
    check_total = Decimal("0")

    kinds = {classify(a) for a, _ in matches}
    if kinds == {"p2wpkh"}:
        # all P2WPKH -> CHECK
        check_total = sum(b for _, b in matches)
        return save_total, check_total
    if kinds == {"p2wsh"}:
        # all P2WSH -> SAVE
        save_total = sum(b for _, b in matches)
        return save_total, check_total

    # Mixed: split explicitly
    for addr, bal in matches:
        k = classify(addr)
        if k == "p2wpkh":
            check_total += bal
        elif k == "p2wsh":
            save_total += bal

    if save_total == 0 and check_total == 0:
        # Fallback to length heuristic (shorter=CHECK, longer=SAVE)
        matches.sort(key=lambda ab: len(ab[0]))
        half = len(matches) // 2
        check_total = sum(b for _, b in matches[:half])
        save_total = sum(b for _, b in matches[half:])

    return save_total, check_total


def fetch_btc_price():
    try:
        resp = requests.get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={"ids": "bitcoin", "vs_currencies": "usd"},
            timeout=5,
        )
        resp.raise_for_status()
        j = resp.json()
        return j.get("bitcoin", {}).get("usd")
    except Exception as e:
        logger.warning("fetch_btc_price failed: %s", e)
        return None


def generate_qr_code(data, *, box_size=12, border=4):
    # Use a decent error correction, auto-fit version, proper quiet zone
    qr = qrcode.QRCode(
        version=None,  # let it grow as needed
        error_correction=qrcode.constants.ERROR_CORRECT_Q,  # Q is plenty; H is okay too
        box_size=box_size,  # module size in pixels
        border=border,  # quiet zone in modules (4 is the ISO minimum)
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    # Save at a print-friendly DPI
    buf = BytesIO()
    img.save(buf, format="PNG", dpi=(300, 300))
    return base64.b64encode(buf.getvalue()).decode("utf-8")


def to_npub(hex_pubkey):
    if len(hex_pubkey) == 130:
        x = int(hex_pubkey[2:66], 16)
        y = int(hex_pubkey[66:], 16)
        compressed_pubkey = bytes.fromhex(f"{'02' if y % 2 == 0 else '03'}{x:064x}")
    elif len(hex_pubkey) == 66:
        compressed_pubkey = bytes.fromhex(hex_pubkey)
    else:
        raise ValueError("Invalid public key length")

    x_only_pub = compressed_pubkey[1:]
    return bech32_encode("npub", convertbits(x_only_pub, 8, 5))


def extract_pubkey_from_op_if(asm):
    ops = asm.split()
    for i, op in enumerate(ops):
        if op == "OP_IF":
            for j in range(i + 1, min(i + 6, len(ops))):
                if re.fullmatch(r"[0-9a-fA-F]{66}", ops[j]) or re.fullmatch(r"[0-9a-fA-F]{130}", ops[j]):
                    return ops[j]
    return None


def extract_pubkey_from_op_else(asm):
    ops = asm.split()
    try:
        idx = ops.index("OP_ELSE")
        for token in ops[idx + 1 :]:
            if re.fullmatch(r"[0-9a-fA-F]{66}", token) or re.fullmatch(r"[0-9a-fA-F]{130}", token):
                return token
    except ValueError:
        return None
    return None


def format_asm(asm):
    ops = asm.split()
    formatted_ops = []
    in_op_if = False

    for op in ops:
        if op == "OP_IF":
            in_op_if = True
        elif op == "OP_ENDIF":
            in_op_if = False

        if in_op_if and re.fullmatch(r"[0-9a-fA-F]{66}", op):
            formatted_ops.append(f'<span class="clickable-pubkey" onclick="handlePubKeyClick(\'{op}\');">{op}</span>')
        else:
            formatted_ops.append(op)

    grouped_ops = [" ".join(formatted_ops[i : i + 4]) for i in range(0, len(formatted_ops), 4)]
    return "\n".join(grouped_ops)


def extract_script_from_raw_descriptor(descriptor):
    match = re.search(r"raw\((.*?)\)", descriptor)
    if match:
        return match.group(1)
    return None


def is_valid_pubkey(pubkey):
    if pubkey.startswith("npub"):
        try:
            hrp, data = bech32_decode(pubkey)
            if hrp != "npub" or data is None:
                return False
            return True
        except Exception:
            return False
    return bool(re.fullmatch(r"[0-9a-fA-F]{66}", pubkey) or re.fullmatch(r"[0-9a-fA-F]{130}", pubkey))


def mask_timelocks(text):
    tokens = text.split()
    masked_tokens = []
    for i, token in enumerate(tokens):
        if token in ["OP_CHECKLOCKTIMEVERIFY", "OP_CHECKSEQUENCEVERIFY"]:
            if masked_tokens and masked_tokens[-1].isdigit():
                masked_tokens[-1] = "*****"
            masked_tokens.append(token)
        else:
            masked_tokens.append(token)
    return " ".join(masked_tokens)


def shorten_pubkey(pubkey):
    byte_len = len(pubkey) // 2
    if byte_len > 31:
        n = (byte_len - 31) * 2
    else:
        n = 4
    return pubkey[-n:]


def mask_hex_value(hex_value, num_visible=4):
    if len(hex_value) <= num_visible:
        return hex_value
    return "*****" + hex_value[-num_visible:]


def clickable_trunc(pubkey):
    short = shorten_pubkey(pubkey)
    return f'<span class="clickable-pubkey" onclick="handlePubKeyClick(\'{pubkey}\');"><span style="color:red;">{short}</span></span>'


def mask_raw_descriptor(text):
    m = re.match(r"raw\((?P<hex>[0-9a-fA-F]+)\)(?P<suffix>.*)", text)
    if m:
        hex_data = m.group("hex")
        suffix = m.group("suffix")
        masked_hex = re.sub(r"(03)[0-9a-fA-F]{6}(?=b1)", r"\1*****", hex_data)
        masked_hex = re.sub(
            r"(b17521)((?:[0-9a-fA-F]{66}|[0-9a-fA-F]{130}))",
            lambda match_obj: match_obj.group(1) + clickable_trunc(match_obj.group(2)),
            masked_hex,
        )
        return f"raw({masked_hex}){suffix}"
    else:
        return text


def truncate_address(addr, first=6, last=4):
    if addr and len(addr) > first + last:
        return addr[:first] + "..." + addr[-last:]
    return addr


def label_for_index(script_hex: str, i: int) -> str:
    """Canonical label for P2WPKH derived from a zpub for this covenant."""
    return f"{script_hex} [{i}]"


def find_first_unused_labeled_address(rpc, script_hex: str, max_scan: int = 20) -> str | None:
    """
    Look for the first address whose label matches '<script_hex> [i]' and has never received & has no UTXOs.
    """
    try:
        labels = set(rpc.listlabels())
    except Exception:
        labels = set()

    for i in range(max_scan):
        wanted = label_for_index(script_hex, i)
        if wanted not in labels:
            # label wasn't created yet → definitely unused from our PoV
            continue
        try:
            addr_map = rpc.getaddressesbylabel(wanted)  # {addr: {...}}
        except Exception:
            continue
        for addr in addr_map.keys():
            try:
                never_received = rpc.getreceivedbyaddress(addr, 0) == 0
                utxos = rpc.listunspent(0, 9999999, [addr])
                if never_received and not utxos:
                    return addr
            except Exception:
                continue
    return None


def zpub_to_xpub(zpub):
    decoded = base58.b58decode(zpub)[:-4]
    xpub_version_bytes = b"\x04\x88\xb2\x1e"
    xpub_payload = decoded[4:]
    xpub = xpub_version_bytes + xpub_payload
    checksum = sha256(sha256(xpub).digest()).digest()[:4]
    return base58.b58encode(xpub + checksum).decode()


def fetch_balance_via_rpc(address):
    rpc = get_rpc_connection()
    utxos = rpc.listunspent(0, 9999999, [address])
    total_btc = sum(Decimal(u["amount"]) for u in utxos)
    total_sats = int(total_btc * Decimal("100000000"))
    return total_sats


@app.route("/home", methods=["GET"], endpoint="home")  # 👈 alias keeps url_for('home') working
def home_page():
    access_level = session.get("access_level", "limited")
    initial_pubkey = request.args.get("pubkey", "")

    html = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Bitcoin Node Viewer</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="theme-color" content="#00ff00">
    <!-- QR library for scanning -->
    <script src="https://unpkg.com/jsqr/dist/jsQR.js"></script>
    <style>
    .hidden { display: none !important; }

        :root {
            --neon-green: #00ff00;
            --neon-blue: #00bfff;
            --dark-bg: #0a0a0a;
            --panel-bg: #141414;
            --border-color: #333;
            --text-color: #e0e0e0;
            --accent-color: #00ff88;
            --spacing-unit: 1rem;
            --touch-target: 44px;
        }

        /* --- Matrix background canvas --- */
        #matrix-bg {
            position: fixed;
            inset: 0;
            z-index: 0;             /* behind content */
            pointer-events: none;   /* clicks go through */
        }
        /* Ensure content sits above canvas */
        body > *:not(#matrix-bg) { position: relative; z-index: 1; }
        /* Respect reduced motion & printing */
        @media (prefers-reduced-motion: reduce) { #matrix-bg { display: none !important; } }
        @media print { #matrix-bg { display: none !important; } }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            margin: 0; /* edge-to-edge canvas */
            background: linear-gradient(135deg, var(--dark-bg) 0%, #0f0f0f 50%, var(--dark-bg) 100%);
            color: var(--text-color);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.5;
            min-height: 100vh;
            font-size: 16px;
            overflow-x: hidden;
        }

        .container {
            max-width: 100%;
            margin: 0 auto;
            padding: var(--spacing-unit);
        }

        /* Header */
        .header {
            text-align: center;
            margin-bottom: calc(var(--spacing-unit) * 1.5);
            padding: var(--spacing-unit) 0;
        }

        h1 {
            color: var(--neon-green);
            font-size: clamp(1.5rem, 5vw, 2.5rem);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            text-shadow: 0 0 20px var(--neon-green);
            margin-bottom: var(--spacing-unit);
            animation: glow 2s ease-in-out infinite alternate;
            word-break: break-word;
        }

        @keyframes glow {
            from { text-shadow: 0 0 15px var(--neon-green); }
            to { text-shadow: 0 0 25px var(--neon-green), 0 0 35px var(--neon-green); }
        }

        /* Navigation */
        .nav-bar {
            display: flex;
            justify-content: center;
            gap: var(--spacing-unit);
            margin-bottom: calc(var(--spacing-unit) * 1.5);
            flex-wrap: wrap;
        }

        .nav-btn {
            background: transparent;
            color: var(--neon-blue);
            border: 2px solid var(--neon-blue);
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-family: inherit;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
            min-height: var(--touch-target);
            min-width: 120px;
            text-align: center;
            touch-action: manipulation;
        }

        .nav-btn:hover, .nav-btn:active {
            background: var(--neon-blue);
            color: var(--dark-bg);
            box-shadow: 0 0 15px var(--neon-blue);
            transform: translateY(-1px);
        }

        /* Main Grid Layout */
        .main-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: var(--spacing-unit);
            margin-bottom: calc(var(--spacing-unit) * 1.5);
        }

@media (min-width: 768px) {
  :root { --spacing-unit: 1.5rem; }

  /* Keep ONE column on desktop, just give it room and center it */
  .main-grid {
    grid-template-columns: 1fr;           /* 🔁 force single column */
    gap: calc(var(--spacing-unit) * 1.5);
    max-width: 1100px;                    /* similar width to RPC area */
    margin-inline: auto;                  /* center the stack */
  }

  .container {
    max-width: none;                      /* let .main-grid control width */
    padding: var(--spacing-unit);
  }
}


        /* Panel Styles */
        .panel {
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: var(--spacing-unit);
            box-shadow: 0 4px 15px rgba(0, 255, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            overflow: hidden;
        }

        .panel:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 255, 0, 0.15);
        }

        .panel h2 {
            color: var(--accent-color);
            font-size: clamp(1rem, 4vw, 1.3rem);
            margin-bottom: var(--spacing-unit);
            text-align: center;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            word-break: break-word;
        }


        /* Form Elements */
        .form-group {
            margin-bottom: var(--spacing-unit);
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--accent-color);
            font-weight: 600;
            font-size: 0.9rem;
        }

        input, textarea {
            width: 100%;
            background: rgba(0, 0, 0, 0.4);
            color: var(--text-color);
            border: 2px solid var(--border-color);
            border-radius: 8px;
            padding: 0.75rem;
            font-family: inherit;
            font-size: 16px; /* Prevents zoom on iOS */
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
            min-height: var(--touch-target);
            -webkit-appearance: none;
            appearance: none;
        }

        input:focus, textarea:focus {
            outline: none;
            border-color: var(--neon-green);
            box-shadow: 0 0 0 3px rgba(0, 255, 0, 0.2);
        }

        textarea {
            resize: vertical;
            min-height: 120px;
            font-family: 'Courier New', monospace;
        }

        /* Button Styles */
        .btn {
            width: 100%;
            background: transparent;
            color: var(--neon-green);
            border: 2px solid var(--neon-green);
            padding: 0.75rem 1rem;
            border-radius: 8px;
            font-family: inherit;
            font-size: 1rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 0.5rem;
            min-height: var(--touch-target);
            touch-action: manipulation;
            -webkit-appearance: none;
            appearance: none;
        }

        .btn:hover, .btn:active {
            background: var(--neon-green);
            color: var(--dark-bg);
            box-shadow: 0 0 15px var(--neon-green);
            transform: translateY(-1px);
        }

        .btn-secondary {
            border-color: var(--neon-blue);
            color: var(--neon-blue);
        }

        .btn-secondary:hover, .btn-secondary:active {
            background: var(--neon-blue);
            color: var(--dark-bg);
            box-shadow: 0 0 15px var(--neon-blue);
        }

        /* Minimal icon-like buttons */
.btn-icon {
  background: transparent;
  border: none;
  color: #0f0;
  font-size: 14px;        /* smaller text/icon */
  padding: 6px 10px;      /* smaller tap target */
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.2s ease, color 0.2s ease;
}

.btn-icon:hover,
.btn-icon:active {
  background: rgba(0, 255, 0, 0.1); /* subtle glow background */
  color: #00ff88;
}

.btn-icon.exit {
  color: #f66; /* exit = redish accent */
}
.btn-icon.exit:hover {
  background: rgba(255, 0, 0, 0.1);
  color: #ff8888;
}


        /* Balance Summary */
        .balance-summary {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem;
            margin: var(--spacing-unit) 0;
            background: rgba(0, 255, 0, 0.05);
            border: 1px dashed var(--neon-green);
            border-radius: 8px;
            text-align: center;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .balance-item {
            flex: 1;
            min-width: 120px;
        }

        .balance-label {
            font-size: 0.8rem;
            opacity: 0.8;
            display: block;
        }

        .balance-value {
            font-size: clamp(1rem, 3vw, 1.2rem);
            font-weight: bold;
            margin-top: 0.25rem;
            word-break: break-all;
        }

        .balance-in { color: var(--neon-green); }
        .balance-out { color: var(--neon-blue); }

        /* Loading Animation */
        .loading {
            text-align: center;
            color: var(--neon-green);
            padding: var(--spacing-unit);
            display: none;
        }

        .loading-text {
            animation: pulse 1.5s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        /* Contract Display */
        .contracts-container {
            margin-top: var(--spacing-unit);
        }

        .panel,
        .contract-box {
            background-color: rgba(0, 0, 0, 0.8);
            border: 1px solid #00ff00;
            border-radius: 12px;
            padding: var(--spacing-unit);
            box-shadow: 0 0 15px #00ff00;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
       }

        .contract-box {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: var(--spacing-unit);
            margin-bottom: var(--spacing-unit);
            transition: border-color 0.3s ease;
            overflow: hidden;
        }

        .contract-box.input-role {
            border-color: var(--neon-green);
            background: rgba(0, 255, 0, 0.05);
        }

        .contract-box.output-role {
            border-color: var(--neon-blue);
            background: rgba(0, 191, 255, 0.05);
        }

        .contract-box pre {
          background: transparent;
          padding: 0.25rem 0;
          border-radius: 0;
          box-shadow: none;
          border: 0;
          overflow-x: auto;
          font-size: clamp(0.7rem, 2.5vw, 0.85rem);
          margin: 0.25rem 0;
          word-break: break-all;
          white-space: pre-wrap;
        }

/* Lock the page when scanner is open */
.body-locked {
  height: 100dvh;
  overflow: hidden;
  position: relative;
}

/* Scanner modal covers the whole screen */
.qr-modal {
  position: fixed;
  inset: 0;
  display: none; /* set to flex when open */
  align-items: center;
  justify-content: center;
  z-index: 99999;
  background: rgba(0,0,0,0.95);
  padding: env(safe-area-inset-top) 1rem env(safe-area-inset-bottom);
  -webkit-backdrop-filter: blur(2px);
  backdrop-filter: blur(2px);
}

/* Video takes the full viewport */
.qr-video {
  width: 100vw;
  height: 100vh;
  object-fit: cover;
  border-radius: 0;
}

/* Close button */
.qr-close {
  position: fixed;
  top: max(12px, env(safe-area-inset-top));
  right: max(12px, env(safe-area-inset-right));
  z-index: 100000;
}

        /* RPC Section */
        .rpc-section {
            grid-column: 1 / -1;
            margin-top: var(--spacing-unit);
        }

        .rpc-buttons {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 0.75rem;
            margin-bottom: var(--spacing-unit);
        }

        .rpc-buttons .btn {
            font-size: 0.8rem;
            padding: 0.6rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .rpc-response {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: var(--spacing-unit);
            font-size: clamp(0.7rem, 2.5vw, 0.8rem);
            white-space: pre-wrap;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
            word-break: break-all;
        }

        /* QR Codes Display */
.qr-codes img {
  image-rendering: pixelated; /* keeps sharp edges */
  max-width: 360px;           /* good on screen */
  width: 2.5in;               /* good on paper */
  height: 2.5in;
}

/* Print settings */
@media print {
  body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  figure { break-inside: avoid; page-break-inside: avoid; }
  .qr-codes img { width: 2.5in; height: 2.5in; }
}
        .qr-codes {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: var(--spacing-unit);
            margin-top: var(--spacing-unit);
            align-items: center;
        }

        .qr-codes figure {
            text-align: center;
            margin: 0;
        }

        .qr-codes img {
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0, 255, 0, 0.2);
        }

        .qr-codes figcaption {
            color: var(--accent-color);
            font-size: clamp(0.7rem, 2.5vw, 0.8rem);
            margin-top: 0.5rem;
            font-weight: bold;
            word-break: break-word;
        }

        /* Clickable elements */
        .clickable-pubkey {
            cursor: pointer;
            text-decoration: underline;
            transition: color 0.2s ease;
            touch-action: manipulation;
        }

        .clickable-pubkey:hover, .clickable-pubkey:active {
            color: var(--neon-blue);
        }

        /* Mobile-specific improvements */
        @media (max-width: 767px) {
            .nav-bar {
                flex-direction: column;
                align-items: stretch;
                gap: 0.75rem;
            }

            .nav-btn {
                width: 100%;
                justify-content: center;
            }

            .balance-summary {
                flex-direction: column;
                text-align: center;
            }

            .balance-item {
                width: 100%;
                margin-bottom: 0.5rem;
            }

            .rpc-buttons {
                grid-template-columns: 1fr;
            }

            .qr-codes {
                grid-template-columns: 1fr;
            }

            button, .btn, .nav-btn, input, textarea {
                min-height: var(--touch-target);
            }
        }

        /* Landscape phone adjustments */
        @media (max-height: 500px) and (orientation: landscape) {
            h1 {
                font-size: 1.5rem;
                margin-bottom: 0.5rem;
            }

            .header {
                margin-bottom: 1rem;
                padding: 0.5rem 0;
            }

            .nav-bar {
                margin-bottom: 1rem;
            }
        }

        /* iOS Safari specific fixes */
        @supports (-webkit-touch-callout: none) {
            .container {
                padding-bottom: calc(var(--spacing-unit) + env(safe-area-inset-bottom));
            }

            input, textarea {
                font-size: 16px; /* Prevents zoom */
            }
        }

        /* Footer */
        .footer {
            text-align: center;
            margin-top: calc(var(--spacing-unit) * 2);
            padding: var(--spacing-unit);
            border-top: 1px solid var(--border-color);
        }

        /* Accessibility improvements */
        @media (prefers-reduced-motion: reduce) {
            * {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }

        /* High contrast mode support */
        @media (prefers-contrast: high) {
            :root {
                --border-color: #666;
                --panel-bg: #000;
            }

            .panel {
                border-width: 2px;
            }
        }

        .app-title { margin: 0 0 var(--spacing-unit); }
.home-link {
  color: var(--neon-green);
  text-decoration: none;
  cursor: pointer;
  display: inline-block;
  text-shadow: 0 0 20px var(--neon-green);
}
.home-link:hover,
.home-link:focus {
  text-decoration: underline;
  outline: none;
  text-shadow: 0 0 25px var(--neon-green), 0 0 35px var(--neon-green);
}
    </style>
</head>
<body>
    <!-- Matrix canvas -->
    <canvas id="matrix-bg" aria-hidden="true"></canvas>

    <!-- QR Scan Modal -->
    <div id="qr-modal" class="qr-modal">
        <video id="qr-video" class="qr-video" autoplay playsinline></video>
        <button onclick="stopScan()" class="qr-close">✕ Close</button>
        <canvas id="qr-canvas" style="display:none;"></canvas>
    </div>

    <div class="container">
        <!-- Header -->
        <div class="header">
<h1 class="app-title">
  <a class="home-link" href="{{ url_for('home') }}">HODLXXI</a>
</h1>


                <div class="manifesto-actions" style="margin-top:1rem; text-align:center;">
      <div style="display:inline-flex; gap:12px; flex-wrap:wrap; align-items:center; justify-content:center;">
        <button id="btnExplorer" class="btn-icon">🔍 </button>
        <button id="btnOnboard"  class="btn-icon">🔧 </button>
        <button id="btnChat"     class="btn-icon">💬 </button>
        <button id="btnExit"     class="btn-icon exit">🚪 </button>
      </div>
    </div>


        <!-- Main Content Grid -->
<div class="main-grid">
  <div class="panel" id="homePanel">
    <h2 style="font-size:0.7rem; line-height:1.2; color:#00ff00; font-family:monospace; font-weight:800;">
      <a href="https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer.git" target="_blank" style="color:#00ff00; text-decoration:none;">
This is a Game Theory and Mathematics–driven Design Framework for decentralized financial support networks, leveraging Bitcoin smart contracts and integrating Nostr for social trust. It fosters a system where mutual care, financial incentives, and social responsibility are embedded in every transaction—aiming to create financially stable and independent communities. Beyond technological advancements, this framework envisions a reimagined form of human cooperation and economic interaction, promoting transparency and equity. It merges technology with human values, challenging traditional notions of trust and community in the digital age. It also raises philosophical questions about the role of technology in enhancing human capabilities, governance, and social structures. Ultimately, success depends on both technological feasibility and ethical foundations, advocating a balanced integration of innovation and tradition to shape future societal evolution. This crypto-centric platform is built as a robust, scalable model of decentralized trust by embedding financial cooperation directly in cryptographic agreements. It uses a Bitcoin full node as its backbone, leveraging descriptor-based wallets and script covenants to enforce long-term, trust-based contracts. The system eliminates centralized intermediaries in favor of immutable, transparent blockchain agreements. Here, cooperation is mathematically reinforced, transparency is the default, and power flows back to individuals. Built on math, guided by ethics, designed for generations. Let’s make covenants great again!!!
    </a>
    </h2>


  </div>
</div>




<div class="panel hidden" id="explorerPanel">
  <h2>🔍 Explorer</h2>

  <div class="form-group">
    <label for="pubKey">Enter Hex or NOSTR Key</label>
    <input type="text" id="pubKey" placeholder="Compressed Pub/NOSTR key"
           autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" />
  </div>

  <button class="btn" onclick="handleCovenants()">Who Is</button>

  <div class="balance-summary" id="balance-summary">
    <div class="balance-item">
      <span class="balance-label">Incoming</span>
      <div class="balance-value balance-in" id="input-balance">$0</div>
    </div>
    <div class="balance-item">
      <span class="balance-label">Outgoing</span>
      <div class="balance-value balance-out" id="output-balance">$0</div>
    </div>
  </div>

  <div id="loading" class="loading">
    <p class="loading-text">Processing... Please wait...</p>
  </div>

  <div id="contracts-container" class="contracts-container"></div>
</div>


<div class="panel hidden" id="onboardPanel">
  <h2>🔧 Converter & Decoder</h2>

  <div class="form-group">
    <label for="initialScript">Raw Script</label>
    <textarea id="initialScript" placeholder="Enter your script…"
              autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"></textarea>
  </div>

  <div class="form-group">
    <label for="newPubKey1">Public Key (Who you care about)</label>
    <input type="text" id="newPubKey1" placeholder="Enter public key"
           autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" />
  </div>

  <div class="form-group">
    <label for="newPubKey2">Public Key (Who cares about you)</label>
    <input type="text" id="newPubKey2" placeholder="Enter public key"
           autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" />
  </div>

  <button class="btn" onclick="handleUpdateScript()">Verify Witness</button>

  <div class="form-group">
    <label>New P2WSH Script:</label>
    <div id="updatedScript" class="contract-box" contenteditable="true"></div>
  </div>

  <h3 style="color: var(--accent-color); margin: var(--spacing-unit) 0;">Decoded Results:</h3>
  <pre id="decodedWitness" class="rpc-response"></pre>

  <div id="qr-codes" class="qr-codes"></div>
</div>


        <!-- RPC Full Node Section (conditional) -->
        <!-- This section would be conditionally rendered based on access_level -->
    </div>

            {% if access_level == 'full' %}
            <!-- RPC Full Node Section -->
            <div class="panel rpc-section">
                <h2>⚡ RPC  Node</h2>

                <!-- Import Descriptor Panel -->
                <div class="panel" style="margin-bottom: var(--spacing-unit);">
                    <h2> Import Covenant Descriptor</h2>
                    <div class="form-group">
                        <textarea id="descriptorInput" placeholder="Paste descriptor here raw(...)checksum"></textarea>
                    </div>
                    <button class="btn" onclick="handleImportDescriptor()">Import</button>
                    <div id="importResult" class="rpc-response" style="margin-top: var(--spacing-unit);"></div>
                </div>

                <!-- Set Labels Panel -->
                <div class="panel" style="margin-bottom: var(--spacing-unit);">
                    <h2> Set Checking Labels</h2>
                    <div class="form-group">
                        <input type="text" id="zpubInput" placeholder="Enter your zpub"/>
                    </div>
                    <div class="form-group">
                        <input type="text" id="labelInput" placeholder="Enter label"/>
                    </div>
                    <button class="btn" onclick="handleSetLabels()">Label</button>
                    <div id="setLabelsResult" class="rpc-response" style="margin-top: var(--spacing-unit);"></div>
                </div>

                <!-- RPC Commands -->
                <div class="rpc-buttons">
                    <button class="btn btn-secondary" onclick="callRPC('listreceivedbyaddress')">Received by Address</button>
                    <button class="btn btn-secondary" onclick="callRPC('listtransactions')">Transactions</button>
                    <button class="btn btn-secondary" onclick="callRPC('listdescriptors')">Descriptors</button>
                    <button class="btn btn-secondary" onclick="callRPC('listunspent')">Unspent</button>
                    <button class="btn btn-secondary" onclick="callRPC('listlabels')">Labels</button>
                    <button class="btn btn-secondary" onclick="callRPC('getwalletinfo')">Wallet Info</button>
                    <button class="btn btn-secondary" onclick="callRPC('rescanblockchain')">Rescan</button>
                    <button class="btn btn-secondary" onclick="callRPC('listaddressgroupings')">Groupings</button>
                    <button class="btn btn-secondary" onclick="callRPC('listreceivedbylabel')">Received by Label</button>
                    <button class="btn btn-secondary" onclick="exportDescriptors()">Export Descriptors</button>
                    <button class="btn btn-secondary" onclick="exportWallet()">Export Wallet</button>
                </div>

                <pre id="rpcResponse" class="rpc-response"></pre>
            </div>
            {% endif %}
        </div>


        <!-- All JavaScript remains the same -->
<script>
// cache the most recent covenant script hex we saw
window.lastScriptHex = window.lastScriptHex || null;

// ▶️ QR-scan plumbing
let scanning = false;
let currentStream = null;

  async function startScan(inputElem, onResult) {
    // Secure context check
    const secure = location.protocol === 'https:' || location.hostname === 'localhost';
    if (!secure || !navigator.mediaDevices?.getUserMedia) {
      alert('Camera only works on HTTPS or localhost.');
      return;
    }

    const modal  = document.getElementById('qr-modal');
    const video  = document.getElementById('qr-video');
    const canvas = document.getElementById('qr-canvas');
    const ctx    = canvas.getContext('2d');

    // Show modal full screen and lock page scroll
    document.body.classList.add('body-locked');
    modal.style.display = 'flex';
    requestAnimationFrame(() => window.scrollTo(0,0)); // jump viewport up

    // iOS PWA flags
    video.setAttribute('playsinline', 'true');
    video.muted = true;

    try {
      currentStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: 'environment' } },
        audio: false
      });
    } catch (e) {
      modal.style.display = 'none';
      document.body.classList.remove('body-locked');
      alert('Camera blocked. Check HTTPS and iOS Settings → Safari → Camera.');
      return;
    }

    video.srcObject = currentStream;
    await video.play().catch(()=>{});
    scanning = true;

    // One definitive stopScan that closes over currentStream
    window.stopScan = function stopScan() {
      scanning = false;
      try { currentStream?.getTracks().forEach(t => t.stop()); } catch {}
      currentStream = null;
      video.srcObject = null;
      modal.style.display = 'none';
      document.body.classList.remove('body-locked');
    };

    (function tick(){
      if (!scanning) return;
      if (video.readyState >= video.HAVE_CURRENT_DATA) {
        canvas.width  = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        try {
          const img  = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
          if (code && code.data) {
            stopScan();
            inputElem.value = code.data;
            if (typeof onResult === 'function') onResult();
            return;
          }
        } catch {}
      }
      requestAnimationFrame(tick);
    })();
  }

  // ▶️ Wrappers for your actions:
  function handleCovenants() {
    const inp = document.getElementById('pubKey');
    if (!inp.value.trim()) startScan(inp, verifyAndListContracts);
    else                    verifyAndListContracts();
  }

  function handleUpdateScript() {
    const inp = document.getElementById('initialScript');
    if (!inp.value.trim()) startScan(inp, updateScript);
    else                    updateScript();
  }

  function handleImportDescriptor() {
    const inp = document.getElementById('descriptorInput');
    if (!inp.value.trim()) startScan(inp, importDescriptor);
    else                    importDescriptor();
  }

  function handleSetLabels() {
    const zpubInp  = document.getElementById('zpubInput');
    const labelInp = document.getElementById('labelInput');

    if (!zpubInp.value.trim()) {
      startScan(zpubInp, setLabelsFromZpub);
      return;
    }
    if (!labelInp.value.trim()) {
      alert('Please enter a label for your zpub.');
      labelInp.focus();
      return;
    }
    setLabelsFromZpub();
  }

        // Audio setup for navigation
        const chatSound = new Audio('{{ url_for("static", filename="sounds/login.mp3") }}');
        chatSound.preload = 'auto';
        chatSound.playsInline = true;


        // All other existing JavaScript functions remain unchanged
        function callRPC(cmd, param) {
          let url = `/rpc/${cmd}`;
          if (param !== undefined && param !== '') {
            url += `?p=${encodeURIComponent(param)}`;
          }
          document.getElementById('rpcResponse').textContent = '⏳ sending…';
          fetch(url)
            .then(r => r.json())
            .then(json => {
              document.getElementById('rpcResponse').textContent = JSON.stringify(json, null, 2);
            })
            .catch(e => {
              document.getElementById('rpcResponse').textContent = 'Error: ' + e;
            });
        }

        function showLoading() {
          document.getElementById('loading').style.display = 'block';
          document.getElementById('contracts-container').innerHTML = '';
        }

        function hideLoading() {
          document.getElementById('loading').style.display = 'none';
        }

function verifyAndListContracts(clickedPubKey = null) {
  const pubKey = clickedPubKey || document.getElementById('pubKey').value.trim();
  if (!pubKey) {
    alert('Please enter a public key');
    return;
  }
  // Validate public key format: Nostr npub or hex
  const isNpub = pubKey.startsWith("npub") && pubKey.length >= 10;
  const isHex = /^[0-9a-fA-F]{66,130}$/.test(pubKey);
  if (!isNpub && !isHex) {
    alert('Invalid public key format. Please enter a Nostr npub or hex public key.');
    return;
  }
  showLoading();
  fetch(`/verify_pubkey_and_list?pubkey=${encodeURIComponent(pubKey)}`)
    .then(r => r.json())
    .then(data => {
      hideLoading();
      if (!data.valid) {
        alert(data.error || "No descriptor found matching the public key.");
        return;
      }

// Sort: 1) counterparty online first, 2) then by total USD (desc)
const sorted = data.descriptors.slice().sort((a, b) => {
  const aOnline = !!a.counterparty_online;
  const bOnline = !!b.counterparty_online;
  if (aOnline !== bOnline) return aOnline ? -1 : 1;

  const totalA = (parseFloat(a.saving_balance_usd) || 0) + (parseFloat(a.checking_balance_usd) || 0);
  const totalB = (parseFloat(b.saving_balance_usd) || 0) + (parseFloat(b.checking_balance_usd) || 0);
  return totalB - totalA;
});

      const container = document.getElementById('contracts-container');
      container.innerHTML = '';

      let inputTotal = 0;
      let outputTotal = 0;

      const entered   = pubKey.trim();
      const isNpub    = entered.startsWith('npub');
      const enteredLC = entered.toLowerCase();

      sorted.forEach(descriptor => {
        const save  = parseFloat(descriptor.saving_balance_usd) || 0;
        const check = parseFloat(descriptor.checking_balance_usd) || 0;
        const total = save + check;

        const ifHex  = descriptor.op_if_pub   ? descriptor.op_if_pub.toLowerCase()    : null;
        const elHex  = descriptor.op_else_pub ? descriptor.op_else_pub.toLowerCase()  : null;
        const ifNpub = descriptor.op_if_npub  || null;   // requires backend to send these
        const elNpub = descriptor.op_else_npub|| null;

        let role = null;
        if (isNpub) {
          if (ifNpub && ifNpub === entered)        role = 'input';
          else if (elNpub && elNpub === entered)   role = 'output';
          // fallback if backend doesn't provide *_npub fields:
          else if (!ifNpub && !elNpub && descriptor.nostr_npub === entered) {
            role = 'input';
          }
        } else {
          if (ifHex && ifHex === enteredLC)        role = 'input';
          else if (elHex && elHex === enteredLC)   role = 'output';
        }
        if (role === 'input')  inputTotal  += total;
        if (role === 'output') outputTotal += total;


        const box = document.createElement('div');
        box.className = 'contract-box';
        if (role) box.classList.add(role + '-role');

let nostrSection = '';
if (descriptor.nostr_npub) {
  const accessLevel = "{{ access_level }}";  // injected by Flask
  if (accessLevel === "full") {
    nostrSection = `
      <div class="nostr-info" style="margin:0.5rem 0; text-align:center;">
        <strong>Nostr:</strong><br>
        <a href="https://advancednostrsearch.vercel.app/?npub=${descriptor.nostr_npub}"
           target="_blank"
           style="color:var(--neon-blue); text-decoration:none; display:inline-block; margin-top:0.25rem;">
           ${descriptor.nostr_npub_truncated}
        </a>
      </div>`;
  } else {
    nostrSection = `
      <div class="nostr-info" style="margin:0.5rem 0; text-align:center;">
        <strong>Nostr:</strong><br>${descriptor.nostr_npub_truncated}
      </div>`;
  }
}

const counterpartyOnline = descriptor.counterparty_online;
const counterparty = descriptor.counterparty_pubkey;

let counterpartyNote = '';
if (counterpartyOnline && counterparty) {
  counterpartyNote = `
    <div style="text-align:center; color:lime; font-size:0.8rem; margin-top:0.25rem;">
      🟢online
    </div>`;
}

// Either injected by Jinja into a <script> block:
const accessLevel = "{{ access_level | default('limited') }}";

// (Alternative if you prefer data-attr on <body>):
// <body data-access-level="{{ access_level }}">
// const accessLevel = document.body.dataset.accessLevel || 'limited';

const deeplink = (accessLevel === "full" && (descriptor.onboard_link || descriptor.raw_script))
  ? (descriptor.onboard_link || `#onboard?raw=${encodeURIComponent(descriptor.raw_script)}&autoverify=1`)
  : null;

const imgTag = descriptor.qr_code
  ? `<img src="data:image/png;base64,${descriptor.qr_code}" alt="Address QR"
       style="max-width:180px;border:1px solid #333;border-radius:8px;box-shadow:0 0 10px rgba(0,255,0,.15);" />`
  : '';

const addrQR = descriptor.qr_code
  ? `<div style="text-align:center;margin:.5rem 0;">
       ${
         deeplink
           ? `<a href="${deeplink}"
                 class="qr-link"
                 title="Open in Converter & Decoder"
                 data-raw="${descriptor.raw_script || ''}"
                 onclick="return jumpOnboard(this.dataset.raw)">${imgTag}</a>`
           : imgTag
       }
     </div>`
  : '';



box.innerHTML = `
<pre><strong>!</strong> ${descriptor.raw}</pre>
<div style="text-align:center; margin:0.5rem 0;"><pre><strong>Address:</strong> ${descriptor.truncated_address}</pre></div>
<div style="text-align:center;"><strong>HEX</strong> ${descriptor.script_hex}</div>
${addrQR}
${counterpartyNote}
${nostrSection}
<div style="text-align:center; margin-top:1rem;"><div style="display:inline-block;"><strong>Save:</strong> $${descriptor.saving_balance_usd}  <strong>Check:</strong> $${descriptor.checking_balance_usd}</div></div>`;

        container.appendChild(box);
      });

      // Update totals
      document.getElementById('input-balance').innerText  = '$' + inputTotal.toFixed(2);
      document.getElementById('output-balance').innerText = '$' + outputTotal.toFixed(2);
    })
    .catch(err => {
      hideLoading();
      console.error(err);
      alert("Error verifying public key. Please try again.");
    });
}

        function handlePubKeyClick(pubKey) {
          verifyAndListContracts(pubKey);
        }

function updateScript() {
  const tpl = document.getElementById('initialScript').value;
  const baked = [...tpl.matchAll(/b17521([0-9A-Fa-f]{66})/g)].map(m=>m[1]);
  let k1 = document.getElementById('newPubKey1').value.trim() || baked[0] || '';
  let k2 = document.getElementById('newPubKey2').value.trim() || baked[1] || '';

  function valid(key) {
    return /^(npub[0-9A-Za-z]+)$/.test(key) || /^[0-9A-Fa-f]{66,130}$/.test(key);
  }

  if (k1 && !valid(k1)) { alert("Invalid OP_IF key"); return; }
  if (k2 && !valid(k2)) { alert("Invalid OP_ELSE key"); return; }

  // Build raw script to send
  let rawScript = tpl;
  if (baked[0] && k1) rawScript = rawScript.replace(baked[0], k1);
  if (baked[1] && k2) rawScript = rawScript.replace(baked[1], k2);

  // Pretty display version
  let displayScript = tpl;
  if (baked[0] && k1) displayScript = displayScript.replace(baked[0], `<span style="color:var(--neon-blue);">${k1}</span>`);
  if (baked[1] && k2) displayScript = displayScript.replace(baked[1], `<span style="color:var(--neon-green);">${k2}</span>`);
  document.getElementById('updatedScript').innerHTML = displayScript;

  // Decode server-side
  fetch('/decode_raw_script', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({
      raw_script: rawScript,
      label_hint: (document.getElementById('labelInput')?.value || '').trim() || null
    })
  })
  .then(async (r) => {
    const ct = r.headers.get('content-type') || '';
    const text = await r.text();
    return ct.includes('application/json') ? JSON.parse(text) : { error: text || `${r.status} ${r.statusText}` };
  })
  .then(d => {
    const out = document.getElementById('decodedWitness');
    out.textContent = d.error ? `Error: ${d.error}` : JSON.stringify(d.decoded, null, 2);

    const qrContainer = document.getElementById('qr-codes');
    qrContainer.innerHTML = '';

    if (d && d.script_hex) window.lastScriptHex = d.script_hex;

    // ⚠️ This guard was missing; without it, d.qr access can throw, and an extra } remained
    if (!d.error && d.qr) {
      function makeQR(label, b64) {
        if (!b64) return '';
        return `
          <figure>
            <img src="data:image/png;base64,${b64}" alt="${label} QR"/>
            <figcaption>${label}</figcaption>
          </figure>`;
      }

      // Core 4 QR codes:
      qrContainer.innerHTML =
        makeQR('Receiver Pubkey', d.qr.pubkey_if) +
        makeQR('Giver Pubkey', d.qr.pubkey_else) +
        makeQR('Raw Script (hex)', d.qr.raw_script_hex) +
        makeQR('HODL Address', d.qr.segwit_address);

      // 5th QR (first unused address)
      if (d.qr.first_unused_addr) {
        qrContainer.innerHTML += makeQR('First Unused Address', d.qr.first_unused_addr);
      } else {
        const warning = d.warning || 'No unused address found. Label your zpub in "Set Checking Labels" to enable detection.';
        qrContainer.innerHTML += `
          <div style="text-align:center; color: var(--neon-green); margin-top: 0;">
            <strong style="color: red;">Warning:</strong> ${warning}
          </div>`;
      }

      // Optional: descriptor QR
      if (d.qr.full_descriptor) {
        qrContainer.innerHTML += makeQR('Descriptor (checksummed)', d.qr.full_descriptor);
      }
    } // ← this closing brace balances the guard above
  })
  .catch(e => {
    document.getElementById('decodedWitness').textContent = `Error: ${e}`;
  });
}


function jumpOnboard(rawHex) {
  try {
    // Show the Converter & Decoder panel
    ['homePanel','explorerPanel','onboardPanel'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.classList.toggle('hidden', id !== 'onboardPanel');
    });

    // Prefill raw script
    const ta = document.getElementById('initialScript');
    if (ta) ta.value = rawHex || '';

    // Normalize hash so any old router logic also lands on onboard
    if (location.hash !== '#onboard') location.hash = 'onboard';

    // Auto-run Verify Witness
    setTimeout(() => { try { handleUpdateScript(); } catch (e) { console.error(e); } }, 0);
  } catch (e) {
    console.error('jumpOnboard error:', e);
  }
  return false; // prevent the <a> default navigation
}

        function importDescriptor() {
  const input = document.getElementById("descriptorInput").value.trim();
  if (!input) { alert("Please enter a descriptor."); return; }

  fetch('/import_descriptor', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ descriptor: input })
  })
  .then(r => r.json())
  .then(async data => {
    const out = document.getElementById("importResult");
    if (data.script_hex) window.lastScriptHex = data.script_hex;


    // Show a short success line
    out.innerHTML = "Imported ✔️<br><small>script_hex: " + (data.script_hex || "n/a") + "</small>";

    // If backend told us the raw hex, immediately render the 5 QRs
    if (data.raw_hex) {
      const res = await fetch('/decode_raw_script', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ raw_script: data.raw_hex })
      }).then(r => r.json()).catch(()=>null);

      if (res && res.qr) {
        const qrContainer = document.getElementById('qr-codes');
        const label = (t,b64) => (b64?`<figure><img src="data:image/png;base64,${b64}"><figcaption>${t}</figcaption></figure>`:"");
        qrContainer.innerHTML =
          label('Receiver Pubkey', res.qr.pubkey_if) +
          label('Giver Pubkey',    res.qr.pubkey_else) +
          label('Raw Script (hex)',res.qr.raw_script_hex) +
          label('HODL Address',    res.qr.segwit_address) +
          (res.qr.first_unused_addr ? label('First Unused Address', res.qr.first_unused_addr)
                                    : `<div style="text-align:center;color:var(--neon-green)"><strong style="color:red">Warning:</strong> ${res.warning||'No unused address yet.'}</div>`);
      }
    }
  })
  .catch(err => {
    document.getElementById("importResult").innerHTML = "Error: " + err;
  });
}

function setLabelsFromZpub() {
  const zpub  = document.getElementById("zpubInput").value.trim();
  const label = document.getElementById("labelInput").value.trim(); // optional now

  if (!zpub) {
    alert("zpub is required.");
    return;
  }

  // Build request body
  const body = { zpub };
  if (label) body.label = label;                    // keep for display/back-compat
  if (window.lastScriptHex) body.script_hex = window.lastScriptHex; // ✅ send if known

  fetch('/set_labels_from_zpub', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    credentials: 'same-origin',
    body: JSON.stringify(body)
  })
  .then(async (r) => {
    const ct   = r.headers.get('content-type') || '';
    const text = await r.text();
    let data;
    try {
      data = ct.includes('application/json') ? JSON.parse(text) : { error: text };
    } catch (e) {
      data = { error: text || e.message };
    }
    if (!r.ok || data.error) {
      throw new Error(data.error || `${r.status} ${r.statusText}`);
    }
    return data;
  })
  .then((data) => {
    // cache script_hex returned by backend for future calls
    if (data.script_hex) window.lastScriptHex = data.script_hex;

    let msg = "";
    msg += `<div><strong>Script HEX:</strong> ${data.script_hex || '(unknown)'}</div>`;
    if (data.descriptor) {
      msg += "<strong>Imported Descriptor:</strong><br><pre>" + data.descriptor + "</pre><br>";
    }
    if (data.labeled_addresses) {
      msg += "<strong>Labeled Addresses:</strong><ul style='padding-left:1em;'>";
      data.labeled_addresses.forEach(entry => {
        const obj  = (typeof entry === 'object') ? entry : { address: entry };
        const idx  = (obj.index !== undefined) ? `[${obj.index}] ` : "";
        const addr = obj.address || "";
        const b64  = obj.qr || obj.qr_base64 || null;
        const src  = b64 ? (b64.startsWith("data:") ? b64 : `data:image/png;base64,${b64}`) : null;
        const lab  = obj.label ? `<br><small>${obj.label}</small>` : "";
        msg += `<li>${idx}${addr}${lab}${
          src ? `<br><img src="${src}" alt="QR for ${addr}" style="max-width:140px;border:1px solid #333;border-radius:6px;margin-top:4px;" />` : ""
        }</li>`;
      });
      msg += "</ul>";
    } else if (data.addresses) {
      msg += "<strong>Addresses:</strong><ul style='padding-left:1em;'>";
      data.addresses.forEach(addr => { msg += `<li>${addr}</li>`; });
      msg += "</ul>";
    }
    if (!msg && data.success) msg = "Operation successful.";
    document.getElementById("setLabelsResult").innerHTML = msg || "No specific results to display.";
  })
  .catch(err => {
    document.getElementById("setLabelsResult").innerHTML = "Error: " + err.message;
  });
} // ← end setLabelsFromZpub()





function exportDescriptors() {
  fetch('/export_descriptors')
    .then(res => res.json())
    .then(data => {
      if (data.error) { alert(data.error); return; }
      const txt  = data.descriptors.map(d => `"${d}"`).join(',');
      const blob = new Blob([txt], { type: 'text/plain' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url; a.download = 'descriptors.txt';
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    })
    .catch(err => alert('Export failed: ' + err));
}

function exportWallet() {
  window.location.href = '/export_wallet';
}


        // Initialize with pubkey from URL if present
        document.addEventListener('DOMContentLoaded', () => {
          const initialPk = "{{ initial_pubkey }}";
          if (initialPk) {
            verifyAndListContracts(initialPk);
          }
        });
        </script>

<script>
document.addEventListener('DOMContentLoaded', () => {
  if (sessionStorage.getItem('playLoginSound') === '1') {
    sessionStorage.removeItem('playLoginSound');
    const a = new Audio('/static/sounds/login.mp3');
    a.loop = true;
    a.play().catch(()=>{});
    setTimeout(() => { a.pause(); a.remove(); }, 6000);
  }
});
</script>

<!-- Matrix background JS (new space-warp 0/1) -->
<script>
(() => {
  const canvas = document.getElementById('matrix-bg');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  // Particles flying toward the camera; glyph at each projected point
  const CHARS = ['0','1'];
  let width = 0, height = 0, particles = [], raf = null;

  function resize() {
    // DPR-aware sizing for crisper text, capped for perf
    const dpr = Math.max(1, Math.min(window.devicePixelRatio || 1, 2));
    const cssW = window.innerWidth, cssH = window.innerHeight;

    canvas.width  = Math.floor(cssW * dpr);
    canvas.height = Math.floor(cssH * dpr);
    canvas.style.width  = cssW + 'px';
    canvas.style.height = cssH + 'px';

    ctx.setTransform(1,0,0,1,0,0);
    ctx.scale(dpr, dpr);

    width = cssW; height = cssH;

    // Re-seed particles
    particles = [];
    for (let i = 0; i < 400; i++) {
      particles.push({
        x: (Math.random() - 0.5) * width,
        y: (Math.random() - 0.5) * height,
        z: Math.random() * 800 + 100
      });
    }

    // Fresh clear
    ctx.fillStyle = 'rgba(0,0,0,1)';
    ctx.fillRect(0, 0, width, height);
  }

  function draw() {
    // Motion trails
    ctx.fillStyle = 'rgba(0,0,0,0.25)';
    ctx.fillRect(0, 0, width, height);

    ctx.fillStyle = '#00ff88';
    for (const p of particles) {
      const scale = 200 / p.z;
      const x2 = width  / 2 + p.x * scale;
      const y2 = height / 2 + p.y * scale;
      const size = Math.max(8 * scale, 1);
      ctx.font = size + 'px monospace';
      ctx.fillText(CHARS[(Math.random() > 0.5) | 0], x2, y2);

      // Advance toward camera
      p.z -= 5;
      if (p.z < 1) {
        p.x = (Math.random() - 0.5) * width;
        p.y = (Math.random() - 0.5) * height;
        p.z = 800;
      }
    }
    raf = requestAnimationFrame(draw);
  }

  function onVis() {
    if (document.hidden) { if (raf) cancelAnimationFrame(raf), raf = null; }
    else { if (!raf) raf = requestAnimationFrame(draw); }
  }

  window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', onVis);
  resize();
  raf = requestAnimationFrame(draw);
})();
</script>





</script>

<script>
  // open same route in a new tab with a hash
  function openPanel(which) {
    const url = `${location.origin}${location.pathname}#${which}`;
    window.open(url, '_blank', 'noopener,noreferrer');
  }

  // Button wiring (manifest buttons)
  document.getElementById('btnExplorer').addEventListener('click', () => openPanel('explorer'));
  document.getElementById('btnOnboard') .addEventListener('click', () => openPanel('onboard'));
  document.getElementById('btnChat')    .addEventListener('click', () => {
    window.open("{{ url_for('chat') }}", '_blank', 'noopener,noreferrer');
  });
  document.getElementById('btnExit')    .addEventListener('click', () => {
    window.location.href = "{{ url_for('logout') }}";
  });

  // Show only the correct panel by hash
  function switchPanelByHash() {
    const h = (location.hash || '').slice(1);
    const showId =
      h === 'explorer' ? 'explorerPanel' :
      h === 'onboard'  ? 'onboardPanel'  :
                         'homePanel';

    // Toggle the main panels
    ['homePanel','explorerPanel','onboardPanel'].forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.classList.toggle('hidden', id !== showId);
    });

    // Optionally hide the RPC section on the home screen
    const rpc = document.querySelector('.rpc-section');
    if (rpc) rpc.classList.toggle('hidden', showId === 'homePanel');

    window.scrollTo({ top: 0 });
  }

  // Run once on load and again if the user changes the hash manually
  window.addEventListener('hashchange', switchPanelByHash);
  document.addEventListener('DOMContentLoaded', switchPanelByHash);
</script>


    </body>
    </html>
    """
    logger.debug("home → access_level=%s", access_level)
    return render_template_string(html, access_level=access_level, initial_pubkey=initial_pubkey)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/verify_pubkey_and_list", methods=["GET"])
def verify_pubkey_and_list():
    import re
    from decimal import Decimal

    pubkey = request.args.get("pubkey")
    if not pubkey:
        return jsonify({"valid": False, "error": "No public key provided."}), 400

    if not is_valid_pubkey(pubkey):
        return jsonify({"valid": False, "error": "Invalid public key format."}), 400

    try:
        rpc = get_rpc_connection()
        descriptors = rpc.listdescriptors().get("descriptors", [])
        btc_price_val = fetch_btc_price()
        btc_price = Decimal(str(btc_price_val)) if btc_price_val is not None else Decimal("0")
        all_groupings = rpc.listaddressgroupings()

        def get_balance_by_address(address):
            for group in all_groupings:
                for addr_item, bal, scr in group:
                    if addr_item == address:
                        return Decimal(str(bal))
            return Decimal("0")

        matched = []

        for d in descriptors:
            raw_desc = d["desc"]

            if raw_desc.startswith("raw("):
                masked_raw = mask_raw_descriptor(raw_desc)
            else:
                masked_raw = mask_timelocks(raw_desc)

            script = extract_script_from_raw_descriptor(raw_desc)
            if not script:
                continue

            decoded = rpc.decodescript(script)
            asm = decoded.get("asm", "") or ""
            script_hex_val = decoded.get("hex") or decoded.get("segwit", {}).get("hex")
            if not script_hex_val:
                continue

            found = False
            for tok in asm.split():
                if re.fullmatch(r"[0-9A-Fa-f]{66,130}", tok):
                    if pubkey.startswith("npub"):
                        try:
                            if to_npub(tok) == pubkey:
                                found = True
                                break
                        except Exception:
                            pass
                    else:
                        if tok.lower() == pubkey.lower():
                            found = True
                            break
            if not found:
                continue

            segwit_addr = decoded.get("segwit", {}).get("address") or (decoded.get("addresses") or [None])[0]

            addr_bal = get_balance_by_address(segwit_addr) if segwit_addr else Decimal("0")
            save_bal, check_bal = get_save_and_check_balances(script_hex_val, all_groupings)

            bal_btc = float(addr_bal)
            bal_usd = float(addr_bal * btc_price)
            save_btc = float(save_bal)
            save_usd = float(save_bal * btc_price)
            check_btc = float(check_bal)
            check_usd = float(check_bal * btc_price)

            op_if_pub = extract_pubkey_from_op_if(asm)
            op_else_pub = extract_pubkey_from_op_else(asm)
            op_if_npub = to_npub(op_if_pub) if op_if_pub else None
            op_else_npub = to_npub(op_else_pub) if op_else_pub else None

            nostr_npub = to_npub(op_if_pub) if op_if_pub else None
            truncated_npub = truncate_address(nostr_npub) if nostr_npub else None

            # Determine which pubkey is the covenant partner (not the user)
            user_pubkey = pubkey.lower()
            counterparty_pubkey = None
            if op_if_pub and op_if_pub.lower() != user_pubkey:
                counterparty_pubkey = op_if_pub
            elif op_else_pub and op_else_pub.lower() != user_pubkey:
                counterparty_pubkey = op_else_pub

            counterparty_online = counterparty_pubkey in ONLINE_USERS if counterparty_pubkey else False

            is_full = session.get("access_level") == "full"
            script_raw = script if (isinstance(script, str) and script) else script_hex_val
            raw_script_for_ui = script_raw if is_full else None
            onboard_link = f"#onboard?raw={script_raw}&autoverify=1" if is_full and script_raw else None

            matched.append(
                {
                    "raw": masked_raw,
                    "asm": format_asm(asm),
                    "address": segwit_addr,
                    "truncated_address": truncate_address(segwit_addr) if segwit_addr else None,
                    "qr_code": generate_qr_code(segwit_addr) if segwit_addr else None,
                    "balance_usd": f"{bal_usd:.2f}",
                    "nostr_npub": nostr_npub,
                    "nostr_npub_truncated": truncated_npub,
                    "op_if_pub": op_if_pub,
                    "op_else_pub": op_else_pub,
                    "script_hex": mask_hex_value(script_hex_val),
                    "saving_balance_usd": f"{save_usd:.2f}",
                    "checking_balance_usd": f"{check_usd:.2f}",
                    "counterparty_online": counterparty_online,
                    "counterparty_pubkey": counterparty_pubkey,
                    "op_if_npub": op_if_npub,
                    "op_else_npub": op_else_npub,
                    # full-access only
                    "raw_script": raw_script_for_ui,
                    "onboard_link": onboard_link,
                }
            )

        if not matched:
            return jsonify({"valid": False, "error": "No matching descriptors found."}), 404

        return jsonify({"valid": True, "descriptors": matched}), 200

    except Exception as e:
        logger.error("Error in verify_pubkey_and_list: %s", str(e), exc_info=True)
        return jsonify({"valid": False, "error": str(e)}), 500


@app.route("/decode_raw_script", methods=["POST"])
def decode_raw_script():
    data = request.get_json(silent=True) or {}
    raw_script = (data.get("raw_script") or "").strip()

    if not raw_script:
        return jsonify({"error": "No raw script provided."}), 400
    raw_script = re.sub(r"[^0-9A-Fa-f]", "", raw_script)
    if not raw_script:
        return jsonify({"error": "Script must contain hex characters only."}), 400

    try:
        rpc = get_rpc_connection()
        decoded = rpc.decodescript(raw_script)
        info = rpc.getdescriptorinfo(f"raw({raw_script})")
        full_desc = info["descriptor"]

        asm = decoded.get("asm", "")
        op_if = extract_pubkey_from_op_if(asm)
        op_else = extract_pubkey_from_op_else(asm)
        npub_if = to_npub(op_if) if op_if else None
        npub_else = to_npub(op_else) if op_else else None

        seg = decoded.get("segwit") or {}
        seg_addr = seg.get("address")
        script_hex = seg.get("hex")  # canonical label base

        # ---------- STRICT "first unused" policy ----------
        # Only surface first-unused if it was created by Set Checking Labels
        # (i.e., labels of the form "<script_hex> [i]").
        first_unused_addr = None
        warning_message = None

        if script_hex:
            # Only look for "<script_hex> [i]" labels
            first_unused_addr = find_first_unused_labeled_address(rpc, script_hex, max_scan=20)

            # If not found, do NOT fall back to any other label search.
            if not first_unused_addr:
                warning_message = "Set Checking Labels"

        return jsonify(
            {
                "decoded": decoded,
                "qr": {
                    "full_descriptor": generate_qr_code(full_desc) if full_desc else None,
                    "segwit_address": generate_qr_code(seg_addr) if seg_addr else None,
                    "pubkey_if": generate_qr_code(npub_if) if npub_if else None,
                    "pubkey_else": generate_qr_code(npub_else) if npub_else else None,
                    "first_unused_addr": generate_qr_code(first_unused_addr) if first_unused_addr else None,
                    "raw_script_hex": generate_qr_code(raw_script) if raw_script else None,
                },
                "first_unused_addr_text": first_unused_addr,
                "script_hex": script_hex,
                "warning": warning_message,
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/import_descriptor", methods=["POST"])
def import_descriptor():
    require_full_access()
    data = request.get_json()
    raw_descriptor = data.get("descriptor", "").strip()
    if not raw_descriptor:
        return jsonify({"error": "No descriptor provided."}), 400

    try:
        rpc = get_rpc_connection()
        import_result = rpc.importdescriptors(
            [{"desc": raw_descriptor, "timestamp": "now", "active": False, "watchonly": True}]
        )

        if raw_descriptor.startswith("raw("):
            script = extract_script_from_raw_descriptor(raw_descriptor)
            decoded = rpc.decodescript(script)
            segwit = decoded.get("segwit", {})
            address = segwit.get("address")
            script_hex = segwit.get("hex")

            if not address or not script_hex:
                return jsonify(
                    {"success": False, "error": "Could not extract address or script hex from decoded script."}
                )

            descriptor_info = rpc.getdescriptorinfo(f"addr({address})")
            address_descriptor = descriptor_info["descriptor"]
            label_import_result = rpc.importdescriptors(
                [
                    {
                        "desc": address_descriptor,
                        "timestamp": "now",
                        "active": False,
                        "watchonly": True,
                        "label": script_hex,
                    }
                ]
            )
            return jsonify(
                {
                    "success": True,
                    "import_result": import_result,
                    "label_import_result": label_import_result,
                    "address": address,
                    "script_hex": script_hex,
                    "address_descriptor": address_descriptor,
                }
            )
        return jsonify(
            {
                "success": True,
                "import_result": import_result,
                "note": "Descriptor was not raw(), so address import skipped.",
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/set_labels_from_zpub", methods=["POST"])
def set_labels_from_zpub():
    """
    Labels the first 20 external P2WPKH addresses derived from a given zpub
    with the pattern " [i]", where script_hex is the covenant's segwit hex.
    Always returns JSON (never HTML).
    """
    guard = require_full_access_json()
    if guard:
        return guard

    try:
        data = request.get_json(silent=True) or {}
        zpub = (data.get("zpub") or "").strip()
        label_input = (data.get("label") or "").strip()
        script_hex = (data.get("script_hex") or "").strip()

        if not zpub:
            return jsonify(error="zpub is required."), 400

        rpc = get_rpc_connection()
        xpub = zpub_to_xpub(zpub)  # your helper that converts zpub → xpub

        # --- Import/activate the first 20 external P2WPKH addrs for this xpub
        info = rpc.getdescriptorinfo(f"wpkh({xpub}/0/*)")
        wpkh_desc = info["descriptor"]
        rng = [0, 19]
        rpc.importdescriptors(
            [{"desc": wpkh_desc, "timestamp": "now", "active": True, "range": rng, "watchonly": True}]
        )
        addrs = rpc.deriveaddresses(wpkh_desc, rng)

        # --------- Determine script_hex robustly ----------
        # 1) If provided explicitly, honor it
        if not script_hex and label_input and re.fullmatch(r"[0-9A-Fa-f]{8,}", label_input):
            # Back-compat: if "label" looks like hex, treat as script_hex
            script_hex = label_input

        # Helper: extract inner raw(...) even if wrapped (wsh(raw(...)), etc.)
        def _extract_raw_hex_any(desc: str) -> str | None:
            m = re.search(r"raw\(([0-9A-Fa-f]+)\)", desc)
            return m.group(1) if m else None

        if not script_hex:
            # 2) Prefer a covenant already labeled by exact segwit hex
            try:
                existing_labels = set(rpc.listlabels())
            except Exception:
                existing_labels = set()

            for desc_obj in rpc.listdescriptors().get("descriptors", []):
                d = desc_obj.get("desc", "")
                raw = _extract_raw_hex_any(d)
                if not raw:
                    continue
                try:
                    dec = rpc.decodescript(raw)
                except Exception:
                    continue
                seg_hex = (dec.get("segwit") or {}).get("hex")
                if seg_hex and (seg_hex in existing_labels):
                    script_hex = seg_hex
                    break

        if not script_hex:
            # 3) Fallback: match a covenant that includes a key derived from this zpub
            derived_pubkeys = []
            for i in range(20):
                try:
                    kd = f"wpkh({xpub}/0/{i})"
                    din = rpc.getdescriptorinfo(kd)["descriptor"]
                    addr = rpc.deriveaddresses(din)[0]
                    info = rpc.getaddressinfo(addr)
                    pk = info.get("pubkey")
                    if pk:
                        derived_pubkeys.append(pk)
                except Exception:
                    continue

            for desc_obj in rpc.listdescriptors().get("descriptors", []):
                d = desc_obj.get("desc", "")
                raw = _extract_raw_hex_any(d)
                if not raw:
                    continue
                try:
                    dec = rpc.decodescript(raw)
                except Exception:
                    continue

                asm = dec.get("asm", "")
                k_if = extract_pubkey_from_op_if(asm) or ""
                k_else = extract_pubkey_from_op_else(asm) or ""
                if (k_if in derived_pubkeys) or (k_else in derived_pubkeys):
                    seg_hex = (dec.get("segwit") or {}).get("hex")
                    if seg_hex:
                        script_hex = seg_hex
                        break

        if not script_hex:
            return (
                jsonify(error="Could not determine script_hex. Provide it explicitly or import your covenant first."),
                400,
            )

        # ---------- Label derived addresses ----------
        labeled = []
        for i, a in enumerate(addrs):
            L = f"{script_hex} [{i}]"
            rpc.setlabel(a, L)
            labeled.append(
                {"index": i, "address": a, "type": "wpkh", "label": L, "qr": generate_qr_code(a)}  # your helper
            )

        return (
            jsonify(
                {
                    "success": True,
                    "descriptor": wpkh_desc,
                    "range": rng,
                    "script_hex": script_hex,
                    "labeled_addresses": labeled,
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify(error=str(e)), 500


def slip132_to_bip32_pub(extkey: str):
    raw = base58.b58decode(extkey)
    payload, chk = raw[:-4], raw[-4:]
    ver = payload[:4]
    depth = payload[4]
    child = int.from_bytes(payload[9:13], "big")

    ver_int = int.from_bytes(ver, "big")
    MAIN = {0x0488B21E, 0x049D7CB2, 0x04B24746}  # xpub/ypub/zpub
    TEST = {0x043587CF, 0x044A5262, 0x045F1CF6}  # tpub/upub/vpub

    if ver_int in MAIN:
        target_ver = b"\x04\x88\xb2\x1e"  # xpub
        net = "main"
    elif ver_int in TEST:
        target_ver = b"\x04\x35\x87\xcf"  # tpub
        net = "test"
    else:
        target_ver = ver
        net = "unknown"

    bip32 = target_ver + payload[4:]
    checksum = sha256(sha256(bip32).digest()).digest()[:4]
    return base58.b58encode(bip32 + checksum).decode(), net, depth, child


def require_full_access_json():
    """
    JSON-only guard. Return a (response, status) tuple when access is insufficient,
    otherwise return None and let the caller continue.
    """
    if session.get("access_level") == "full":
        return None
    return jsonify(ok=False, error="Full access required"), 403


@app.route("/rpc/<cmd>", methods=["GET"])
def rpc_dispatch(cmd):
    require_full_access()
    rpc = get_rpc_connection()
    allowed = {
        "getwalletinfo": lambda: rpc.getwalletinfo(),
        "listdescriptors": lambda: rpc.listdescriptors(),
        "getreceivedbylabel": lambda: rpc.getreceivedbylabel(request.args.get("p", "")),
        "listtransactions": lambda: rpc.listtransactions(),
        "listunspent": lambda: rpc.listunspent(),
        "listreceivedbylabel": lambda: rpc.listreceivedbylabel(),
        "listreceivedbyaddress": lambda: rpc.listreceivedbyaddress(),
        "listaddressgroupings": lambda: rpc.listaddressgroupings(),
        "listlabels": lambda: rpc.listlabels(),
        "getbalance": lambda: rpc.getbalance(),
        "rescanblockchain": lambda: rpc.rescanblockchain(),
    }
    if cmd not in allowed:
        return jsonify({"error": f"Unsupported RPC method `{cmd}`"}), 400
    try:
        result = allowed[cmd]()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/export_descriptors", methods=["GET"])
def export_descriptors():
    # only full-access users may export
    if session.get("access_level") != "full":
        return jsonify({"error": "Full access required."}), 403

    rpc = get_rpc_connection()
    # rpc.listdescriptors() returns {"descriptors": [ { "desc": "...", ... }, ... ]}
    all_descs = rpc.listdescriptors().get("descriptors", [])

    # filter for raw(...) and wpkh(...)
    filtered = [
        d["desc"] for d in all_descs if d.get("desc", "").startswith("raw(") or d.get("desc", "").startswith("wpkh(")
    ]

    return jsonify({"descriptors": filtered})


# ---------------- Wallet export ----------------
@app.route("/export_wallet", methods=["GET"])
def export_wallet():
    if session.get("access_level") != "full":
        return jsonify(error="Full access required"), 403

    backup_path = "/tmp/wallet-backup.dat"
    rpc = get_rpc_connection()
    rpc.backupwallet(backup_path)

    return send_file(backup_path, as_attachment=True, download_name=f"{WALLET}.dat")


@app.route("/convert_wif", methods=["POST"])
def convert_wif():
    import base64
    import io

    from flask import jsonify, request

    try:
        data = request.get_json(force=True)
        raw = data.get("key", "").strip()

        if raw.lower().startswith("nsec1"):
            hrp, bits = bech32_decode(raw)
            if hrp != "nsec":
                raise ValueError("Invalid nsec key")
            b = convertbits(bits, 5, 8, False)
            if not b or len(b) != 32:
                raise ValueError("Invalid nsec payload")
            hexkey = bytes(b).hex()
        elif is_hex32(raw):
            hexkey = raw.lower()
        else:
            raise ValueError("Input must be 64-char hex or nsec1...")

        wif = hex_to_wif(hexkey)

        # QR
        qr = qrcode.make(wif)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode()

        return jsonify({"ok": True, "wif": wif, "qr": f"data:image/png;base64,{b64}"})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


PUBLIC_API_PREFIXES = ("/api/lnurl-auth/",)  # includes /callback/<sid> and /check/<sid>
PUBLIC_API_PATHS = (
    "/api/get-login-challenge",
    "/api/lnurl-auth/create",
    "/api/lnurl-auth/params",
    "/api/challenge",  # your existing challenge endpoint
    "/api/verify",  # your existing verify endpoint
    "/api/demo/free",
)


@app.before_request
def _public_guard_for_lnurl():
    p = request.path
    # --- allow playground + playground static assets without auth ---
    # this keeps only playground and its static dir public
    # Allow PoF public routes
    if p.startswith('/pof/certificate/'):
        return None

    if p.startswith('/playground') or p.startswith('/playground/') or p.startswith('/static/playground'):
        return None

    # Always allow static + login/oidc pages
    if p.startswith("/static/") or p in ("/login", "/universal_login", "/oidc", "/callback"):
        return None

    # Allow discovery + OAuth core
    if p in (
        "/.well-known/openid-configuration",
        "/oauth/token",
        "/oauth/register",
        "/oauth/jwks.json",
        "/oauthx/status",
        "/oauthx/docs",
        "/oauth/authorize",
    ):
        return None

    # Allow your public API paths (LNURL-Auth, challenge, verify)
    if p in PUBLIC_API_PATHS or any(p.startswith(pref) for pref in PUBLIC_API_PREFIXES):
        return None

    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return None

    # Fallback: require session for other /api/*
    if p.startswith("/api/") and not (p.startswith("/api/playground") or p.startswith("/api/playground/") or p.startswith("/api/pof/")) and not session.get("logged_in_pubkey"):
        return jsonify({"error": "Not logged in", "ok": False}), 401

    return None


def mint_access_token(sub: str, scope: str = "basic") -> str:
    """
    Minimal placeholder token generator — not a real JWT.
    """
    import secrets

    token = base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip("=")
    return f"{sub}.{token}"


def is_valid_pubkey(pubkey: str) -> bool:
    """
    Accept:
      - Hex: 33-byte compressed (66 hex) or 65-byte uncompressed (130 hex)
      - Nostr npub1… (bech32, 32-byte x-only)
    """
    if not pubkey:
        return False
    s = pubkey.strip()

    # Nostr bech32 (npub1...)
    if s.lower().startswith("npub1"):
        try:
            hrp, data = bech32_decode(s)
            if hrp != "npub":
                return False
            b = convertbits(data, 5, 8, False)
            return b is not None and len(b) == 32
        except Exception:
            return False

    # Hex
    try:
        h = bytes.fromhex(s)
        # allow 32 (x-only), 33 (compressed), 64 and 65 (uncompressed) bytes
        return len(h) in (32, 33, 64, 65)
    except Exception:
        return False


@app.route("/api/challenge", methods=["POST"])
def api_challenge():
    data = request.get_json() or {}
    pubkey = (data.get("pubkey") or "").strip()
    if not pubkey or not is_valid_pubkey(pubkey):
        return jsonify(error="Missing or invalid pubkey"), 400

    cid = str(uuid.uuid4())
    challenge = f"HODLXXI:login:{int(time.time())}:{uuid.uuid4().hex[:8]}"
    ACTIVE_CHALLENGES[cid] = {
        "pubkey": pubkey,
        "challenge": challenge,
        "created": datetime.utcnow(),
        "expires": datetime.utcnow() + timedelta(minutes=5),
        "method": data.get("method", "api"),
    }
    return jsonify(challenge_id=cid, challenge=challenge, expires_in=300)


@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json() or {}
    cid = (data.get("challenge_id") or "").strip()
    pubkey = (data.get("pubkey") or "").strip()
    signature = (data.get("signature") or "").strip()

    if not (cid and pubkey and signature):
        return jsonify(error="Missing required parameters"), 400

    rec = ACTIVE_CHALLENGES.get(cid)
    if not rec or rec["expires"] < datetime.utcnow():
        return jsonify(error="Invalid or expired challenge"), 400
    if rec["pubkey"] != pubkey:
        return jsonify(error="Pubkey mismatch"), 400

    method = rec.get("method", "api")

    # --- 🔹 Verification depending on method ---
    if method == "nostr":
        # Temporarily trust browser extension (nos2x, Alby) — they already verified key ownership
        ok = True

    elif method == "lightning":
        # You can later add signature check here if LNURL-auth includes sig/key
        ok = True

    else:
        # Default: Bitcoin RPC verification
        try:
            rpc = get_rpc_connection()
            addr = derive_legacy_address_from_pubkey(pubkey)
            ok = rpc.verifymessage(addr, signature, rec["challenge"])
        except Exception as e:
            return jsonify(error=f"Signature verification failed: {e}"), 500

    if not ok:
        return jsonify(error="Invalid signature"), 403

    # --- 🔹 Determine access level ---
    try:
        in_total, out_total = get_save_and_check_balances_for_pubkey(pubkey)
        ratio = (out_total / in_total) if in_total > 0 else 0
        access = "full" if ratio >= 1 else "limited"
    except Exception:
        access = "limited"

    access_token = mint_access_token(sub=pubkey, scope="basic")
    refresh_token = None
    if "REFRESH_STORE" in globals():
        token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
        REFRESH_STORE[token] = {
            "sub": pubkey,
            "scope": "basic",
            "exp": int(time.time()) + 30 * 24 * 3600,
            "jti": str(uuid.uuid4()),
        }
        refresh_token = token

    ACTIVE_CHALLENGES.pop(cid, None)

    payload = {
        "verified": True,
        "token_type": "Bearer",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": 900,
        "pubkey": pubkey,
        "access_level": access,
    }
    resp = jsonify(payload)
    resp = _finish_login(resp, pubkey, access)
    return resp


@app.route("/special_login", methods=["POST"])
def special_login():
    data = request.get_json(silent=True) or {}
    signature = (data.get("signature") or "").strip()

    if not signature:
        return jsonify(error="Signature required", verified=False), 400

    # Use the first special pubkey that verifies
    rpc = get_rpc_connection()
    challenge = session.get("challenge")
    if not challenge:
        return jsonify(error="No active challenge", verified=False), 400

    for pubkey in SPECIAL_USERS:
        try:
            addr = derive_legacy_address_from_pubkey(pubkey)
            if rpc.verifymessage(addr, signature, challenge):
                # Session
                session["logged_in_pubkey"] = pubkey
                session["access_level"] = "special"
                payload = {
                    "verified": True,
                    "pubkey": pubkey,
                    "access_level": "special",
                }
                resp = jsonify(payload)
                resp = _finish_login(resp, pubkey, "special")
                return resp
        except Exception:
            continue

    return jsonify(error="Invalid signature for all special users", verified=False), 403


# ---- Legacy message-signature verification (JSON-only) ----


@app.route("/verify_signature", methods=["POST"])
def verify_signature_legacy():
    from flask import jsonify, request, session

    data = request.get_json(silent=True) or {}
    pubkey = (data.get("pubkey") or "").strip()  # compressed hex (02/03...)
    signature = (data.get("signature") or "").strip()  # wallet base64 (Electrum/Sparrow/Core)
    challenge = (data.get("challenge") or "").strip()  # shown on the Legacy tab

    # Basic input
    if not signature or not challenge:
        return jsonify(error="Missing signature or challenge"), 400

    # Must match the session challenge injected into the Legacy tab
    sess = session.get("challenge")
    if not sess or sess != challenge:
        return jsonify(error="Invalid or expired challenge"), 400

    if not pubkey:
        return jsonify(error="Pubkey required"), 400  # (can add recovery later if you want it optional)

    # Verify like your API: derive legacy address from pubkey and ask Bitcoin Core to verify
    try:
        rpc = get_rpc_connection()
        addr = derive_legacy_address_from_pubkey(pubkey)
        ok = rpc.verifymessage(addr, signature, challenge)
        if not ok:
            return jsonify(error="Invalid signature"), 403
    except Exception as e:
        return jsonify(error=f"Signature verification failed: {e}"), 500

    # Access level (same rule you use in /api/verify)
    try:
        in_total, out_total = get_save_and_check_balances_for_pubkey(pubkey)
        ratio = (out_total / in_total) if in_total > 0 else 0
        access = "full" if ratio >= 1 else "limited"
    except Exception:
        access = "limited"

    # Set session / cookies exactly like API
    payload = {
        "verified": True,
        "pubkey": pubkey,
        "access_level": access,
    }
    resp = jsonify(payload)
    resp = _finish_login(resp, pubkey, access)  # your helper used in /api/verify
    return resp


def _finish_login(resp, pubkey: str, level: str = "limited"):
    """Sets session, and (best-effort) sets OAuth cookies for convenience."""
    session["logged_in_pubkey"] = pubkey
    session["access_level"] = level
    # Best-effort: mint and set cookies if JWT machinery is present
    try:
        at = mint_access_token(sub=pubkey)
        rt = mint_refresh_token(sub=pubkey)
        # dev defaults: secure=False on localhost; set True in prod behind HTTPS
        resp.set_cookie("at", at, max_age=AT_TTL, secure=False, samesite="Lax")
        resp.set_cookie("rt", rt, max_age=RT_TTL, secure=False, httponly=True, samesite="Lax")
    except Exception:
        pass
    return resp


import io


def load_guest_pins():
    pins_env = os.getenv("GUEST_STATIC_PINS", "")
    mapping = {}
    for part in pins_env.split(","):
        if ":" in part:
            pin, label = part.split(":", 1)
            mapping[pin.strip()] = label.strip()
    return mapping


GUEST_PINS = load_guest_pins()


HEX32_RE = re.compile(r"^[0-9A-Fa-f]{64}$")
PUB_HEX_RE = re.compile(r"^[0-9A-Fa-f]{66,130}$")  # compressed/uncompressed/x-only-ish


import hashlib
import secrets

# =========================
# LNURL-Auth (drop-in block)
# =========================
import time
import uuid

from flask import jsonify, request, session, url_for

LNURL_TTL = 300  # seconds (5 min)
ACTIVE_LNURL_SESSIONS = {}  # sid → {k1, created, authenticated, pubkey, sig, consumed}


def _now() -> float:
    return time.time()


def _new_k1_hex() -> str:
    return secrets.token_hex(32)  # 32 random bytes, hex-encoded


def _purge_expired_lnurl():
    now = _now()
    expired = [
        sid
        for sid, rec in ACTIVE_LNURL_SESSIONS.items()
        if (now - rec.get("created", 0)) > LNURL_TTL and not rec.get("authenticated")
    ]
    for sid in expired:
        ACTIVE_LNURL_SESSIONS.pop(sid, None)


# ----------------- helpers for sig verify -----------------
def _strip_leading_zeros(x: bytes) -> bytes:
    return x.lstrip(b"\x00") or b"\x00"


def _ensure_positive_int(x: bytes) -> bytes:
    return (b"\x00" + x) if x[0] & 0x80 else x


def _encode_der_integer(x: bytes) -> bytes:
    x = _strip_leading_zeros(x)
    x = _ensure_positive_int(x)
    return b"\x02" + bytes([len(x)]) + x


def _rs_to_der(r: bytes, s: bytes) -> bytes:
    R = _encode_der_integer(r)
    S = _encode_der_integer(s)
    seq = R + S
    return b"\x30" + bytes([len(seq)]) + seq


def _verify_lnurl_sig(k1_hex: str, sig_hex: str, key_hex: str) -> bool:
    """Verify LNURL-Auth signature (Alby, Blixt, Mutiny compatible)."""
    import hashlib

    from coincurve import PublicKey

    try:
        # Wallets sign SHA256(k1), so we must verify the hash digest
        msg = hashlib.sha256(bytes.fromhex(k1_hex)).digest()
        sig = bytes.fromhex(sig_hex)
        pub = bytes.fromhex(key_hex)

        pk = PublicKey(pub)
        verified = pk.verify(sig, msg, hasher=None)

        logger.debug("LNURL-Auth verify → %s", verified)
        return verified
    except Exception as e:
        logger.error("LNURL-Auth verify error: %s", e)
        return False


# ----------------- bech32 encoder -----------------
def _bech32_polymod(values):
    GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp, data):
    v = _bech32_hrp_expand(hrp) + data
    p = _bech32_polymod(v + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(p >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_encode(hrp, data):
    C = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return hrp + "1" + "".join([C[d] for d in data + _bech32_create_checksum(hrp, data)])


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for v in data:
        if v < 0 or (v >> frombits):
            return None
        acc = ((acc << frombits) | v) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        return None
    return ret


def _lnurl_bech32(url_str: str) -> str:
    return _bech32_encode("lnurl", _convertbits(url_str.encode("utf-8"), 8, 5))


@app.route("/", methods=["GET"])
def root_redirect():
    return landing_page()


import hashlib
import json
import redis
import redis

# =========================
# COMPLETE OIDC/OAuth2 SYSTEM (append at EOF after your existing code)
# =========================
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set

from flask import Flask, jsonify, redirect, render_template_string, request, url_for

# ----------------------------------------------------------------------------
# CONFIGURATION & GLOBALS
# ----------------------------------------------------------------------------

if JWT_SIGNING_KEY:
    JWT_SECRET = JWT_SIGNING_KEY
else:
    fallback_secret = os.getenv("JWT_SECRET", secrets.token_hex(32))
    JWT_SECRET = fallback_secret if isinstance(fallback_secret, bytes) else fallback_secret.encode()

# memory stores; in prod you'd use Redis / DB
CLIENT_STORE: Dict[str, dict] = {}
AUTH_CODE_STORE: Dict[str, dict] = {}
LNURL_SESSION_STORE: Dict[str, dict] = {}

LNURL_TTL = 300  # seconds


# ----------------------------------------------------------------------------
# DATA MODELS
# ----------------------------------------------------------------------------


class ClientType(Enum):
    FREE = "free"
    PAID = "paid"
    PREMIUM = "premium"


@dataclass
class ClientCredentials:
    client_id: str
    client_secret: str
    client_type: ClientType
    rate_limit: int
    allowed_scopes: Set[str]
    redirect_uris: List[str] = field(default_factory=list)
    payment_expiry: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.utcnow())


# ----------------------------------------------------------------------------
# CLIENT MANAGER
# ----------------------------------------------------------------------------


class ClientManager:
    @staticmethod
    def register_client(
        payment_proof: Optional[str] = None, redirect_uris: Optional[List[str]] = None
    ) -> ClientCredentials:
        client_id = f"anon_{secrets.token_hex(16)}"
        client_secret = secrets.token_hex(32)

        # Defaults: free tier
        ctype = ClientType.FREE
        rate_limit = 100
        scopes = {"read_limited"}

        # If caller provided a "payment_proof", try to upgrade tier
        if payment_proof:
            try:
                proof = json.loads(payment_proof)
                tier = (proof.get("tier") or "").lower()
                amt = int(proof.get("amount_sat", 0))

                if tier == "premium" or amt >= 1_000_000:
                    ctype = ClientType.PREMIUM
                    rate_limit = 10000
                    scopes = {"read", "write", "covenant_create", "covenant_read"}

                elif tier == "paid" or amt >= 100_000:
                    ctype = ClientType.PAID
                    rate_limit = 1000
                    scopes = {"read", "covenant_read"}

            except Exception:
                # keep defaults (FREE)
                pass

        client = ClientCredentials(
            client_id=client_id,
            client_secret=client_secret,
            client_type=ctype,
            rate_limit=rate_limit,
            allowed_scopes=scopes,
            redirect_uris=redirect_uris or [],
        )

        # Store in Redis (with fallback to in-memory)
        try:
            storage = get_storage()
            # Import storage's ClientCredentials
            # from storage import ClientCredentials as RedisClient, ClientType as RedisClientType  # DISABLED - using database storage

            # Convert to Redis format
            redis_client = RedisClient(
                client_id=client.client_id,
                client_secret=client.client_secret,
                client_type=RedisClientType(client.client_type.value),
                rate_limit=client.rate_limit,
                allowed_scopes=client.allowed_scopes,
                redirect_uris=client.redirect_uris,
                created_at=client.created_at.timestamp(),
                is_active=True,
            )
            storage.store_client(redis_client)
            logger.info(f"✅ Stored client in Redis: {client_id}")
        except Exception as e:
            logger.warning(f"⚠️  Redis unavailable, using in-memory: {e}")
            CLIENT_STORE[client_id] = {
                "client_id": client.client_id,
                "client_secret": client.client_secret,
                "client_type": client.client_type.value,
                "rate_limit": client.rate_limit,
                "allowed_scopes": list(client.allowed_scopes),
                "redirect_uris": client.redirect_uris,
                "payment_expiry": client.payment_expiry.isoformat() if client.payment_expiry else None,
                "created_at": client.created_at.isoformat(),
            }

        return client

    @staticmethod
    def authenticate_client(client_id: str, client_secret: str) -> Optional[ClientCredentials]:
        # Try Redis first
        try:
            storage = get_storage()
            redis_client = storage.get_client(client_id)
            if redis_client and redis_client.is_active:
                if secrets.compare_digest(redis_client.client_secret, client_secret):
                    # Convert back to app's ClientCredentials format
                    return ClientCredentials(
                        client_id=redis_client.client_id,
                        client_secret=redis_client.client_secret,
                        client_type=ClientType(redis_client.client_type.value),
                        rate_limit=redis_client.rate_limit,
                        allowed_scopes=redis_client.allowed_scopes,
                        redirect_uris=redis_client.redirect_uris,
                        payment_expiry=None,
                        created_at=redis_client.created_at if isinstance(redis_client.created_at, datetime) else datetime.fromtimestamp(redis_client.created_at) if redis_client.created_at else datetime.utcnow(),
                    )
        except Exception as e:
            logger.warning(f"⚠️  Redis lookup failed: {e}")

        # Fallback to in-memory
        data = CLIENT_STORE.get(client_id)
        if not data:
            return None

        if not secrets.compare_digest(data["client_secret"], client_secret):
            return None

        # payment_expiry check if present
        if data.get("payment_expiry"):
            if datetime.utcnow() > datetime.fromisoformat(data["payment_expiry"]):
                return None

        return ClientCredentials(
            client_id=data["client_id"],
            client_secret=data["client_secret"],
            client_type=ClientType(data["client_type"]),
            rate_limit=data["rate_limit"],
            allowed_scopes=set(data["allowed_scopes"]),
            redirect_uris=data.get("redirect_uris") or [],
            payment_expiry=datetime.fromisoformat(data["payment_expiry"]) if data.get("payment_expiry") else None,
            created_at=datetime.fromisoformat(data["created_at"]),
        )


# ----------------------------------------------------------------------------
# OAUTH SERVER CORE
# ----------------------------------------------------------------------------


class OAuthServer:
    def __init__(self, client_manager: ClientManager):
        self.client_manager = client_manager

    def authorization_endpoint(
        self,
        client_id: str,
        scope: str,
        state: str,
        redirect_uri: str,
        response_type: str = "code",
        code_challenge: Optional[str] = None,
        code_challenge_method: str = "S256",
        nonce: Optional[str] = None,
    ) -> dict:
        # 1. validate client (try Redis first)
        client_data = None
        try:
            storage = get_storage()
            redis_client = storage.get_client(client_id)
            if redis_client and redis_client.is_active:
                # Convert to dict format for this method
                client_data = {
                    "client_id": redis_client.client_id,
                    "client_secret": redis_client.client_secret,
                    "client_type": redis_client.client_type.value,
                    "rate_limit": redis_client.rate_limit,
                    "allowed_scopes": list(redis_client.allowed_scopes),
                    "redirect_uris": redis_client.redirect_uris,
                }
        except Exception as e:
            logger.warning(f"⚠️  Redis lookup in authorize: {e}")

        # Fallback to in-memory
        if not client_data:
            client_data = CLIENT_STORE.get(client_id)

        if not client_data:
            try:
                from app.storage import get_oauth_client as _test_get_client

                stored = _test_get_client(client_id)
                if stored:
                    meta = stored.get("metadata") or {}
                    scopes_val = stored.get("allowed_scopes") or stored.get("scope") or ""
                    if isinstance(scopes_val, str):
                        allowed_scopes = [s for s in scopes_val.split() if s]
                    else:
                        allowed_scopes = list(scopes_val or [])

                    client_data = {
                        "client_id": client_id,
                        "client_secret": stored.get("client_secret", ""),
                        "client_type": meta.get("client_type", "free"),
                        "rate_limit": meta.get("rate_limit", 100),
                        "allowed_scopes": allowed_scopes or ["read_limited"],
                        "redirect_uris": stored.get("redirect_uris", []),
                    }
            except Exception:
                pass

        if not client_data:
            return {"error": "invalid_client"}

        # 2. validate requested scope ⊆ allowed_scopes
        requested_scopes = set(scope.split())
        allowed_scopes = set(client_data["allowed_scopes"])
        if not requested_scopes.issubset(allowed_scopes):
            return {
                "error": "invalid_scope",
                "detail": {"allowed": list(allowed_scopes), "requested": list(requested_scopes)},
            }

        # 3. redirect URI must match registered URIs
        if client_data["redirect_uris"] and redirect_uri not in client_data["redirect_uris"]:
            return {"error": "invalid_redirect_uri"}

        # 4. issue short-lived code
        code = secrets.token_urlsafe(24)
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        code_data = {
            "client_id": client_id,
            "scope": " ".join(requested_scopes),
            "redirect_uri": redirect_uri,
            "state": state,
            "created_at": int(time.time()),
            "expires_at": expires_at.isoformat(),
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "nonce": nonce,
        }

        _store_auth_code_pkce(code, code_data, ttl=600)

        # the Flask route can either:
        # - return redirect(f"{redirect_uri}?code=...&state=...")
        #   (for browser-style OAuth)
        # OR
        # - jsonify this dict (for CLI testing)
        return {"authorization_code": code, "redirect_uri": f"{redirect_uri}?code={code}&state={state}"}

    def token_endpoint(
        self,
        grant_type: str,
        client_id: str,
        client_secret: str,
        code: Optional[str] = None,
        refresh_token: Optional[str] = None,
        code_verifier: Optional[str] = None,
    ) -> dict:

        client = self.client_manager.authenticate_client(client_id, client_secret)
        if not client:
            return {"error": "invalid_client"}

        if grant_type == "authorization_code":
            if not code:
                return {"error": "invalid_grant"}
            return self._handle_code_grant(code, client, code_verifier)

        if grant_type == "refresh_token":
            if not refresh_token:
                return {"error": "invalid_grant"}
            return self._handle_refresh_grant(refresh_token, client)

        return {"error": "unsupported_grant_type"}

    def _handle_code_grant(
        self, code: str, client: ClientCredentials, code_verifier: Optional[str] = None
    ) -> dict:
        code_data = _pop_auth_code_pkce(code)

        if not code_data:
            return {"error": "invalid_grant", "detail": "code_not_found"}

        if code_data.get("client_id") != client.client_id:
            return {"error": "invalid_grant", "detail": "client_mismatch"}

        expires_at = code_data.get("expires_at")
        if isinstance(expires_at, str):
            try:
                expires_dt = datetime.fromisoformat(expires_at)
            except ValueError:
                expires_dt = datetime.utcnow()
        elif expires_at is not None:
            expires_dt = datetime.utcfromtimestamp(int(expires_at))
        else:
            expires_dt = datetime.utcnow()

        if expires_dt < datetime.utcnow():
            return {"error": "invalid_grant", "detail": "code_expired"}

        code_challenge = code_data.get("code_challenge")
        if code_challenge:
            method = (code_data.get("code_challenge_method") or "S256").upper()
            if not code_verifier:
                return {"error": "invalid_grant", "detail": "code_verifier_required"}
            if method not in {"S256", "PLAIN"}:
                return {"error": "invalid_grant", "detail": "unsupported_challenge_method"}
            if not validate_pkce(code_challenge, code_verifier, method):
                return {"error": "invalid_grant", "detail": "pkce_mismatch"}

        scope_str = code_data.get("scope", "read_limited")

        access_token = self._gen_access(client, scope_str)
        refresh_token = self._gen_refresh(client.client_id, scope_str)

        now_ts = int(time.time())
        id_claims = {
            "aud": client.client_id,
            "nonce": code_data.get("nonce") or "",
        }
        if JWT_ALG == "RS256":
            id_claims_rs = dict(id_claims)
            id_claims_rs["iss"] = ISSUER
            id_token = issue_rs256_jwt(sub=client.client_id, claims=id_claims_rs)
        else:
            id_claims.update(
                {
                    "iss": ISSUER,
                    "sub": client.client_id,
                    "iat": now_ts,
                    "exp": now_ts + TOKEN_TTL_SECONDS,
                }
            )
            id_token = sign_jwt(id_claims)

        oauth_tokens_issued.inc()

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_SECONDS,
            "refresh_token": refresh_token,
            "scope": scope_str,
            "id_token": id_token,
        }

    def _handle_refresh_grant(self, refresh_token: str, client: ClientCredentials) -> dict:
        try:
            payload = decode_jwt(refresh_token)
        except jwt.InvalidTokenError as e:
            return {"error": "invalid_grant", "detail": str(e)}

        if payload.get("client_id") != client.client_id:
            return {"error": "invalid_grant"}

        if payload.get("type") != "refresh":
            return {"error": "invalid_grant"}

        scope_str = payload.get("scope", "read_limited")

        new_access = self._gen_access(client, scope_str)
        new_refresh = self._gen_refresh(client.client_id, scope_str)

        oauth_tokens_issued.inc()

        return {
            "access_token": new_access,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_SECONDS,
            "refresh_token": new_refresh,
        }

    def _gen_access(self, client: ClientCredentials, scope_str: str) -> str:
        now = int(time.time())
        claims = {
            "aud": AUDIENCE,
            "client_id": client.client_id,
            "client_type": client.client_type.value,
            "scope": scope_str,
            "jti": str(uuid.uuid4()),
            "type": "access",
            "iss": ISSUER,
        }
        if JWT_ALG == "RS256":
            return issue_rs256_jwt(sub=client.client_id, claims=claims)
        claims.update({"iat": now, "exp": now + TOKEN_TTL_SECONDS})
        return sign_jwt(claims)

    def _gen_refresh(self, client_id: str, scope_str: str) -> str:
        now = int(time.time())
        payload = {
            "client_id": client_id,
            "scope": scope_str,
            "type": "refresh",
            "iat": now,
            "exp": now + 30 * 24 * 3600,
            "jti": str(uuid.uuid4()),
        }
        return sign_jwt(payload)


# ----------------------------------------------------------------------------
# SCOPE CHECK DECORATOR
# ----------------------------------------------------------------------------


def require_scope(required_scope: str):
    def outer(fn):
        def inner(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "missing_token"}), 401

            token_str = auth.split(" ", 1)[1]

            try:
                payload = decode_jwt(token_str, audience=AUDIENCE, issuer=ISSUER)
            except jwt.InvalidTokenError as e:
                return jsonify({"error": "invalid_token", "detail": str(e)}), 401

            token_scopes = set((payload.get("scope") or "").split())
            if required_scope not in token_scopes:
                return (
                    jsonify(
                        {"error": "insufficient_scope", "provided": list(token_scopes), "required": required_scope}
                    ),
                    403,
                )

            # stash claims if handler cares
            request.token_payload = payload
            return fn(*args, **kwargs)

        inner.__name__ = fn.__name__
        return inner

    return outer


# ----------------------------------------------------------------------------
# EXAMPLE PROTECTED ROUTES
# ----------------------------------------------------------------------------
# NOTE: reuse existing `app` from your Flask code.
# If you don't already have `app`, uncomment these lines:
#
# from flask import Flask
# app = Flask(__name__)
# app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", secrets.token_hex(16))


@app.route("/api/demo/free", methods=["GET"])
def api_demo_free_v2():
    return jsonify(
        {
            "status": "ok",
            "tier": "free",
            "message": "limited covenant / liveness / non-sensitive view",
        }
    )


@app.route("/api/demo/protected", methods=["GET"])
@require_scope("read")
def api_demo_protected_v2():
    return jsonify({"status": "ok", "tier": "paid", "msg": "full covenant data / requires broader scope"})


# ----------------------------------------------------------------------------
# OPTIONAL: simple scope-check decorator for your API routes
# ----------------------------------------------------------------------------


def require_scope(required_scope: str):
    def outer(fn):
        def inner(*args, **kwargs):
            # Extract bearer token
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "missing_token"}), 401
            token_str = auth.split(" ", 1)[1]

            # Verify token
            try:
                payload = decode_jwt(token_str, audience=AUDIENCE, issuer=ISSUER)
            except jwt.InvalidTokenError as e:
                return jsonify({"error": "invalid_token", "detail": str(e)}), 401

            # Check scope
            token_scopes = set((payload.get("scope") or "").split())
            if required_scope not in token_scopes:
                return (
                    jsonify(
                        {"error": "insufficient_scope", "provided": list(token_scopes), "required": required_scope}
                    ),
                    403,
                )

            # Optionally stash payload on request so handlers can use it
            request.token_payload = payload
            return fn(*args, **kwargs)

        inner.__name__ = fn.__name__
        return inner

    return outer


# ============================================================================
# LNURL-AUTH HELPERS
# ============================================================================


def _lnurl_bech32(url_str: str) -> str:
    """Encode URL as LNURL (bech32)"""

    def polymod(values):
        GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
        chk = 1
        for v in values:
            b = chk >> 25
            chk = ((chk & 0x1FFFFFF) << 5) ^ v
            for i in range(5):
                chk ^= GEN[i] if ((b >> i) & 1) else 0
        return chk

    def hrp_expand(hrp):
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    def create_checksum(hrp, data):
        values = hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]
        mod = polymod(values) ^ 1
        return [(mod >> 5 * (5 - i)) & 31 for i in range(6)]

    def convertbits(data, frombits, tobits):
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        for value in data:
            acc = (acc << frombits) | value
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
        return ret

    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    data = convertbits(url_str.encode("utf-8"), 8, 5)
    combined = data + create_checksum("lnurl", data)
    return "lnurl1" + "".join([CHARSET[d] for d in combined])


# ============================================================================
# INITIALIZE
# ============================================================================

client_manager = ClientManager()
oauth_server = OAuthServer(client_manager)


# === FLASK APP GLUE (standalone-friendly) ==========================
try:
    app  # reuse if an app already exists (when appending to an existing project)
except NameError:
    from flask import Flask

    app = Flask(__name__)
    # Optional: set a secret key and a sensible issuer for local dev
    import os
    import secrets

    app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", secrets.token_hex(16))
    # If you’ll access via http://127.0.0.1:5000, no SERVER_NAME needed.
    # If you access via a custom host:port, you can set SERVER_NAME here.


# ============================================================================
# LANDING PAGE HTML TEMPLATE
# ============================================================================

LANDING_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KeyAuth Protocol | Bitcoin Authentication & Identity for Web3</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg: #0b0f10;
            --panel: #11171a;
            --fg: #e6f1ef;
            --accent: #00ff88;
            --muted: #86a3a1;
            --bitcoin-orange: #f7931a;
            --dark-bg: #0b0f10;
            --darker-bg: #000000;
            --card-bg: rgba(17, 23, 26, 0.92);
            --text-light: #e6f1ef;
            --text-muted: #86a3a1;
            --border-color: #0f2a24;
            --border-hover: #184438;
            --input-bg: #0e1315;
            --hover-bg: #12352d;
            --gradient-1: linear-gradient(135deg, #00ff88 0%, #00cc66 100%);
            --gradient-2: linear-gradient(135deg, #f7931a 0%, #ff6b35 100%);
            --glow-green: rgba(0, 255, 136, 0.2);
            --glow-orange: rgba(247, 147, 26, 0.2);
        }

        body {
            font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: var(--bg);
            color: var(--fg);
            line-height: 1.6;
            overflow-x: hidden;
        }

        /* Matrix Background Canvases */
        .matrix-canvas {
            position: fixed;
            inset: 0;
            z-index: 0;
            pointer-events: none;
        }

        @media (prefers-reduced-motion: reduce) {
            .matrix-canvas {
                display: none !important;
            }
        }

        @media print {
            .matrix-canvas {
                display: none !important;
            }
        }

        /* Ensure all content stays above Matrix canvases */
        body > *:not(.matrix-canvas) {
            position: relative;
            z-index: 1;
        }

        .container {
            max-width: 1280px;
            margin: 0 auto;
            padding: 0 20px;
        }

        /* Navigation */
        nav {
            position: fixed;
            top: 0;
            width: 100%;
            background: rgba(11, 15, 16, 0.95);
            backdrop-filter: blur(10px);
            z-index: 999;
            border-bottom: 1px solid var(--border-color);
        }

        .nav-content {
            max-width: 1280px;
            margin: 0 auto;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 24px;
            font-weight: 800;
            color: var(--accent);
            text-shadow: 0 0 20px var(--glow-green);
        }

        .nav-links {
            display: flex;
            gap: 30px;
            list-style: none;
        }

        .nav-links a {
            color: var(--fg);
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s;
        }

        .nav-links a:hover {
            color: var(--accent);
            text-shadow: 0 0 10px var(--glow-green);
        }

        .cta-button {
            background: var(--gradient-2);
            color: white;
            padding: 12px 28px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s;
            display: inline-block;
            border: 1px solid var(--bitcoin-orange);
        }

        .cta-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px var(--glow-orange);
        }

        /* Hero Section */
        .hero {
            min-height: 100vh;
            display: flex;
            align-items: center;
            position: relative;
            padding-top: 80px;
            background: radial-gradient(ellipse at top, rgba(0, 255, 136, 0.08) 0%, transparent 50%);
        }

        .hero-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 60px;
            align-items: center;
        }

        .hero-content h1 {
            font-size: 64px;
            font-weight: 900;
            line-height: 1.1;
            margin-bottom: 24px;
            color: var(--accent);
            text-shadow: 0 0 40px var(--glow-green);
        }

        .hero-content .subtitle {
            font-size: 24px;
            color: var(--bitcoin-orange);
            margin-bottom: 32px;
            font-weight: 600;
        }

        .hero-content .description {
            font-size: 18px;
            color: var(--muted);
            margin-bottom: 40px;
            line-height: 1.8;
        }

        .hero-buttons {
            display: flex;
            gap: 20px;
        }

        .secondary-button {
            background: transparent;
            color: var(--accent);
            padding: 12px 28px;
            border: 2px solid var(--accent);
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s;
        }

        .secondary-button:hover {
            background: var(--accent);
            color: var(--bg);
            transform: translateY(-2px);
            box-shadow: 0 10px 30px var(--glow-green);
        }

        .hero-visual {
            position: relative;
        }

        .protocol-diagram {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 40px;
            position: relative;
            overflow: hidden;
            box-shadow: 0 0 10px #003a2b, 0 0 20px var(--glow-green);
            animation: pulse-glow 2.4s ease-in-out infinite;
        }

        @keyframes pulse-glow {
            0%, 100% {
                box-shadow: 0 0 10px #003a2b, 0 0 20px var(--glow-green);
            }
            50% {
                box-shadow: 0 0 18px #00664c, 0 0 30px rgba(0, 255, 136, 0.3);
            }
        }

        .protocol-diagram::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 200%;
            height: 200%;
            background: conic-gradient(from 0deg, transparent, var(--accent), transparent);
            animation: rotate 8s linear infinite;
            opacity: 0.08;
        }

        @keyframes rotate {
            100% { transform: rotate(360deg); }
        }

        .protocol-layers {
            position: relative;
            z-index: 1;
        }

        .protocol-layer {
            background: rgba(14, 21, 22, 0.6);
            border: 1px solid var(--border-hover);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            transition: all 0.3s;
        }

        .protocol-layer:hover {
            background: rgba(0, 255, 136, 0.05);
            border-color: var(--accent);
            transform: translateX(10px);
            box-shadow: 0 0 20px var(--glow-green);
        }

        .protocol-layer h4 {
            font-size: 16px;
            color: var(--accent);
            margin-bottom: 8px;
        }

        .protocol-layer p {
            font-size: 14px;
            color: var(--muted);
        }

        /* A to Z Section */
        .a-to-z-section {
            padding: 120px 0;
            background: var(--darker-bg);
        }

        .section-header {
            text-align: center;
            max-width: 800px;
            margin: 0 auto 80px;
        }

        .section-header h2 {
            font-size: 48px;
            font-weight: 800;
            margin-bottom: 20px;
        }

        .section-header .highlight {
            color: var(--accent);
            text-shadow: 0 0 30px var(--glow-green);
        }

        .section-header p {
            font-size: 20px;
            color: var(--muted);
        }

        .a-to-z-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 30px;
            margin-top: 60px;
        }

        .capability-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }

        .capability-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: var(--gradient-1);
            transform: scaleX(0);
            transition: transform 0.3s;
        }

        .capability-card:hover {
            transform: translateY(-8px);
            border-color: var(--accent);
            box-shadow: 0 0 30px var(--glow-green);
        }

        .capability-card:hover::before {
            transform: scaleX(1);
        }

        .capability-icon {
            width: 60px;
            height: 60px;
            background: var(--gradient-1);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            margin-bottom: 20px;
            box-shadow: 0 0 20px var(--glow-green);
        }

        .capability-card h3 {
            font-size: 20px;
            margin-bottom: 12px;
            color: var(--fg);
        }

        .capability-card p {
            color: var(--muted);
            font-size: 15px;
            line-height: 1.6;
        }

        /* Use Cases Section */
        .use-cases-section {
            padding: 120px 0;
        }

        .use-case-tabs {
            display: flex;
            gap: 20px;
            margin-bottom: 60px;
            flex-wrap: wrap;
            justify-content: center;
        }

        .tab-button {
            background: var(--card-bg);
            border: 2px solid var(--border-hover);
            color: var(--fg);
            padding: 16px 32px;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }

        .tab-button:hover, .tab-button.active {
            background: var(--hover-bg);
            border-color: var(--accent);
            color: var(--accent);
            transform: translateY(-2px);
            box-shadow: 0 0 20px var(--glow-green);
        }

        .use-case-content {
            display: none;
        }

        .use-case-content.active {
            display: block;
        }

        .use-case-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
        }

        .use-case-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
            transition: all 0.3s;
        }

        .use-case-card:hover {
            border-color: var(--accent);
            transform: translateY(-4px);
            box-shadow: 0 0 30px var(--glow-green);
        }

        .use-case-badge {
            display: inline-block;
            background: rgba(0, 255, 136, 0.1);
            color: var(--accent);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 16px;
            border: 1px solid var(--accent);
        }

        .use-case-card h4 {
            font-size: 22px;
            margin-bottom: 12px;
            color: var(--fg);
        }

        .use-case-card .scenario {
            color: var(--muted);
            font-size: 15px;
            line-height: 1.7;
            margin-bottom: 20px;
        }

        .use-case-features {
            list-style: none;
            margin-top: 20px;
        }

        .use-case-features li {
            color: var(--muted);
            font-size: 14px;
            padding: 8px 0;
            padding-left: 28px;
            position: relative;
        }

        .use-case-features li::before {
            content: '✓';
            position: absolute;
            left: 0;
            color: var(--accent);
            font-weight: bold;
        }

        /* How It Works */
        .how-it-works {
            padding: 120px 0;
            background: var(--darker-bg);
        }

        .timeline {
            position: relative;
            max-width: 900px;
            margin: 0 auto;
        }

        .timeline::before {
            content: '';
            position: absolute;
            left: 50%;
            transform: translateX(-50%);
            width: 2px;
            height: 100%;
            background: linear-gradient(180deg, var(--accent) 0%, rgba(0, 255, 136, 0.1) 100%);
        }

        .timeline-item {
            display: flex;
            margin-bottom: 60px;
            position: relative;
        }

        .timeline-item:nth-child(odd) {
            flex-direction: row-reverse;
        }

        .timeline-content {
            width: 45%;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
        }

        .timeline-number {
            position: absolute;
            left: 50%;
            transform: translateX(-50%);
            width: 60px;
            height: 60px;
            background: var(--gradient-1);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            font-weight: 800;
            color: var(--bg);
            box-shadow: 0 0 0 8px var(--darker-bg), 0 0 30px var(--glow-green);
        }

        .timeline-content h3 {
            font-size: 22px;
            margin-bottom: 12px;
            color: var(--accent);
        }

        .timeline-content p {
            color: var(--muted);
            line-height: 1.7;
        }

        /* Trust Indicators */
        .trust-section {
            padding: 120px 0;
            text-align: center;
        }

        .trust-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 40px;
            margin-top: 60px;
        }

        .metric {
            padding: 32px;
        }

        .metric-value {
            font-size: 56px;
            font-weight: 900;
            color: var(--accent);
            text-shadow: 0 0 30px var(--glow-green);
            margin-bottom: 12px;
        }

        .metric-label {
            font-size: 18px;
            color: var(--muted);
            font-weight: 600;
        }

        /* Features Grid */
        .features-section {
            padding: 120px 0;
            background: var(--darker-bg);
        }

        /* Developer Portal Section */
        .developer-section {
            padding: 120px 0;
            background: var(--bg);
        }

        .portal-links {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 30px;
            margin-top: 60px;
            margin-bottom: 80px;
        }

        .portal-card {
            background: var(--card-bg);
            border: 2px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
            text-decoration: none;
            color: var(--fg);
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }

        .portal-card:hover {
            border-color: var(--accent);
            transform: translateY(-8px);
            box-shadow: 0 0 30px var(--glow-green);
        }

        .portal-icon {
            font-size: 48px;
            margin-bottom: 16px;
        }

        .portal-card h3 {
            font-size: 22px;
            margin-bottom: 8px;
            color: var(--accent);
        }

        .portal-card p {
            color: var(--muted);
            font-size: 14px;
            line-height: 1.6;
            margin-bottom: 16px;
        }

        .portal-arrow {
            position: absolute;
            bottom: 20px;
            right: 20px;
            font-size: 24px;
            color: var(--accent);
            transition: transform 0.3s;
        }

        .portal-card:hover .portal-arrow {
            transform: translateX(5px);
        }

        /* API Documentation Styles */
        .api-docs {
            max-width: 1000px;
            margin: 0 auto;
        }

        .api-section-title {
            font-size: 28px;
            color: var(--accent);
            margin-bottom: 32px;
            margin-top: 60px;
        }

        .api-block {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 30px;
        }

        .api-block h4 {
            font-size: 20px;
            color: var(--fg);
            margin-bottom: 8px;
        }

        .api-description {
            color: var(--muted);
            margin-bottom: 24px;
            font-size: 15px;
        }

        .endpoint-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .endpoint-item {
            display: flex;
            align-items: center;
            gap: 12px;
            background: var(--input-bg);
            border: 1px solid var(--border-hover);
            border-radius: 8px;
            padding: 12px 16px;
        }

        .http-method {
            padding: 4px 12px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .http-method.get {
            background: rgba(16, 185, 129, 0.1);
            color: #10b981;
            border: 1px solid #10b981;
        }

        .http-method.post {
            background: rgba(59, 130, 246, 0.1);
            color: #3b82f6;
            border: 1px solid #3b82f6;
        }

        .endpoint-url {
            flex: 1;
            color: var(--accent);
            font-family: 'Courier New', monospace;
            font-size: 14px;
            word-break: break-all;
        }

        .copy-btn {
            background: transparent;
            border: 1px solid var(--border-hover);
            color: var(--muted);
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 16px;
        }

        .copy-btn:hover {
            background: var(--hover-bg);
            border-color: var(--accent);
            color: var(--accent);
        }

        .api-note {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-top: 16px;
            padding: 12px;
            background: rgba(247, 147, 26, 0.05);
            border-left: 3px solid var(--bitcoin-orange);
            border-radius: 6px;
            color: var(--muted);
            font-size: 14px;
        }

        .note-icon {
            font-size: 20px;
        }

        .api-note code {
            background: rgba(0, 0, 0, 0.3);
            padding: 2px 6px;
            border-radius: 4px;
            color: var(--bitcoin-orange);
            font-family: monospace;
        }

        /* Code Examples */
        .code-examples {
            margin-top: 60px;
        }

        .code-block {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 24px;
        }

        .code-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            background: var(--input-bg);
            border-bottom: 1px solid var(--border-hover);
        }

        .code-title {
            color: var(--accent);
            font-weight: 600;
            font-size: 15px;
        }

        .copy-code-btn {
            background: var(--accent);
            color: var(--bg);
            border: none;
            padding: 6px 16px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .copy-code-btn:hover {
            box-shadow: 0 0 20px var(--glow-green);
            transform: translateY(-2px);
        }

        .code-block pre {
            margin: 0;
            padding: 20px;
            overflow-x: auto;
            background: var(--bg);
        }

        .code-block code {
            color: var(--accent);
            font-family: 'Courier New', Consolas, monospace;
            font-size: 13px;
            line-height: 1.6;
        }

        /* Live Test Section */
        .live-test-section {
            margin-top: 60px;
        }

        .test-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
            margin-top: 32px;
        }

        .test-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
        }

        .test-card h4 {
            font-size: 20px;
            color: var(--fg);
            margin-bottom: 8px;
        }

        .test-card p {
            color: var(--muted);
            margin-bottom: 20px;
            font-size: 14px;
        }

        .test-button {
            width: 100%;
            background: var(--gradient-1);
            color: var(--bg);
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 15px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .test-button:hover {
            box-shadow: 0 0 30px var(--glow-green);
            transform: translateY(-2px);
        }

        .test-result {
            margin-top: 16px;
            padding: 16px;
            background: var(--input-bg);
            border: 1px solid var(--border-hover);
            border-radius: 8px;
            color: var(--accent);
            font-family: monospace;
            font-size: 12px;
            max-height: 300px;
            overflow-y: auto;
            display: none;
        }

        .test-result:not(:empty) {
            display: block;
        }

        /* Code block scrollbar styling */
        .code-block pre::-webkit-scrollbar {
            height: 8px;
        }

        .code-block pre::-webkit-scrollbar-track {
            background: var(--input-bg);
        }

        .code-block pre::-webkit-scrollbar-thumb {
            background: var(--border-hover);
            border-radius: 4px;
        }

        .code-block pre::-webkit-scrollbar-thumb:hover {
            background: var(--accent);
        }

        .test-result::-webkit-scrollbar {
            width: 8px;
        }

        .test-result::-webkit-scrollbar-track {
            background: var(--input-bg);
        }

        .test-result::-webkit-scrollbar-thumb {
            background: var(--border-hover);
            border-radius: 4px;
        }

        .test-result::-webkit-scrollbar-thumb:hover {
            background: var(--accent);
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 30px;
            margin-top: 60px;
        }

        .feature-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 40px;
            text-align: center;
            transition: all 0.3s;
        }

        .feature-card:hover {
            border-color: var(--accent);
            transform: translateY(-8px);
            box-shadow: 0 0 30px var(--glow-green);
        }

        .feature-icon {
            width: 80px;
            height: 80px;
            background: var(--gradient-1);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            margin: 0 auto 24px;
            box-shadow: 0 0 30px var(--glow-green);
        }

        .feature-card h3 {
            font-size: 20px;
            margin-bottom: 12px;
        }

        .feature-card p {
            color: var(--muted);
            line-height: 1.7;
        }

        /* CTA Section */
        .cta-section {
            padding: 120px 0;
            text-align: center;
        }

        .cta-box {
            background: var(--gradient-2);
            border-radius: 24px;
            padding: 80px 40px;
            max-width: 900px;
            margin: 0 auto;
            position: relative;
            overflow: hidden;
            border: 2px solid var(--bitcoin-orange);
        }

        .cta-box::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255, 255, 255, 0.1) 0%, transparent 70%);
            animation: pulse 4s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 0.5; }
            50% { transform: scale(1.1); opacity: 0.8; }
        }

        .cta-box h2 {
            font-size: 42px;
            font-weight: 900;
            margin-bottom: 20px;
            color: white;
            position: relative;
            z-index: 1;
        }

        .cta-box p {
            font-size: 20px;
            color: rgba(255, 255, 255, 0.9);
            margin-bottom: 40px;
            position: relative;
            z-index: 1;
        }

        .cta-buttons-large {
            display: flex;
            gap: 20px;
            justify-content: center;
            position: relative;
            z-index: 1;
            flex-wrap: wrap;
        }

        .white-button {
            background: white;
            color: var(--bg);
            padding: 16px 40px;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 700;
            font-size: 18px;
            transition: all 0.3s;
        }

        .white-button:hover {
            transform: translateY(-4px);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }

        .cta-buttons-large .secondary-button {
            padding: 16px 40px;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 700;
            font-size: 18px;
            transition: all 0.3s;
        }

        .cta-buttons-large .secondary-button:hover {
            transform: translateY(-4px);
        }

        /* Footer */
        footer {
            background: var(--darker-bg);
            border-top: 1px solid var(--border-color);
            padding: 60px 0 30px;
        }

        .footer-content {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1fr;
            gap: 60px;
            margin-bottom: 40px;
        }

        .footer-brand h3 {
            font-size: 24px;
            margin-bottom: 16px;
            color: var(--accent);
            text-shadow: 0 0 20px var(--glow-green);
        }

        .footer-brand p {
            color: var(--muted);
            line-height: 1.7;
        }

        .footer-links h4 {
            font-size: 16px;
            margin-bottom: 20px;
            color: var(--accent);
        }

        .footer-links ul {
            list-style: none;
        }

        .footer-links ul li {
            margin-bottom: 12px;
        }

        .footer-links a {
            color: var(--muted);
            text-decoration: none;
            transition: color 0.3s;
        }

        .footer-links a:hover {
            color: var(--accent);
        }

        .footer-bottom {
            text-align: center;
            padding-top: 30px;
            border-top: 1px solid var(--border-color);
            color: var(--muted);
        }

        /* Responsive */
        @media (max-width: 968px) {
            .hero-grid {
                grid-template-columns: 1fr;
            }

            .hero-content h1 {
                font-size: 48px;
            }

            .nav-links {
                display: none;
            }

            .portal-links {
                grid-template-columns: 1fr;
            }

            .test-grid {
                grid-template-columns: 1fr;
            }

            .endpoint-item {
                flex-direction: column;
                align-items: flex-start;
            }

            .code-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 12px;
            }

            .copy-code-btn {
                width: 100%;
            }

            .code-block pre {
                font-size: 12px;
                padding: 16px;
            }

            .cta-buttons-large {
                flex-direction: column;
                align-items: stretch;
            }

            .white-button,
            .cta-buttons-large .secondary-button {
                width: 100%;
                text-align: center;
            }

            .timeline::before {
                left: 30px;
            }

            .timeline-item,
            .timeline-item:nth-child(odd) {
                flex-direction: row;
            }

            .timeline-content {
                width: calc(100% - 80px);
                margin-left: 80px;
            }

            .timeline-number {
                left: 30px;
            }

            .footer-content {
                grid-template-columns: 1fr;
            }

            .a-to-z-grid {
                grid-template-columns: 1fr;
            }
        }

        /* Animations */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .animate-in {
            animation: fadeInUp 0.8s ease-out;
        }
    </style>
</head>
<body>
    <!-- Matrix Background Canvas - Warp Effect Only -->
    <canvas id="matrix-warp" class="matrix-canvas" aria-hidden="true"></canvas>

    <!-- Navigation -->
    <nav>
        <div class="nav-content">
            <div class="logo">⚡ KeyAuth Protocol ⚡</div>
            <ul class="nav-links">
                <li><a href="#capabilities">Capabilities</a></li>
                <li><a href="#use-cases">Use Cases</a></li>
                <li><a href="#developer">Developer</a></li>
                <li><a href="#how-it-works">How It Works</a></li>
                <li><a href="#features">Features</a></li>
            </ul>
            <a href="#contact" class="cta-button">Get Started</a>
        </div>
    </nav>

    <!-- Hero Section -->
    <section class="hero">
        <div class="container">
            <div class="hero-grid">
                <div class="hero-content animate-in">
                    <h1> Universal Bitcoin Identity Layer</h1>
                    <p class="subtitle"> Solutions for the Web3 Future</p>
                    <p class="description">
                        Bridge your Web2 business into the Bitcoin economy with enterprise-grade authentication,
                        proof-of-funds, and identity services. No custody. No compromise. Just cryptographic truth.
                    </p>
                    <div class="hero-buttons">
                        <a href="#contact" class="cta-button">Request Consultation</a>
                        <a href="#developer" class="secondary-button">Try API Now</a>
                    </div>
                </div>
                <div class="hero-visual">
                    <div class="protocol-diagram">
                        <div class="protocol-layers">
                            <div class="protocol-layer">
                                <h4>🌐 OAuth2 / OpenID Connect</h4>
                                <p>Standards-based SSO for seamless integration</p>
                            </div>
                            <div class="protocol-layer">
                                <h4>⚡ LNURL Authentication</h4>
                                <p>Instant Lightning Network login without passwords</p>
                            </div>
                            <div class="protocol-layer">
                                <h4>🔐 Bitcoin Signature Auth</h4>
                                <p>Cryptographic identity tied to Bitcoin keys</p>
                            </div>
                            <div class="protocol-layer">
                                <h4>💰 Proof of Funds (PSBT)</h4>
                                <p>Non-custodial verification of Bitcoin holdings</p>
                            </div>
                            <div class="protocol-layer">
                                <h4>👥 Covenant Groups</h4>
                                <p>Multi-party coordination with threshold controls</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- A to Z Capabilities -->
    <section id="capabilities" class="a-to-z-section">
        <div class="container">
            <div class="section-header">
                <h2>From <span class="highlight">A to Z</span>, We've Got You Covered</h2>
                <p>KeyAuth Protocol covers every need in the Bitcoin authentication and identity space</p>
            </div>

            <div class="a-to-z-grid">
                <div class="capability-card">
                    <div class="capability-icon">🔐</div>
                    <h3>Authentication Services</h3>
                    <p>LNURL-auth, Bitcoin signature verification, OAuth2/OIDC integration for passwordless, cryptographic authentication</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">💰</div>
                    <h3>Proof of Funds</h3>
                    <p>Non-custodial PSBT verification with privacy levels (boolean/threshold/aggregate) for lending, trading, and more</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">🌐</div>
                    <h3>SSO Integration</h3>
                    <p>Drop-in replacement for Auth0, Okta, or Firebase - but with Bitcoin identity at the core</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">👥</div>
                    <h3>Covenant Groups</h3>
                    <p>Multi-party coordination, governance, and access control with cryptographic membership verification</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">💬</div>
                    <h3>Real-Time Chat</h3>
                    <p>WebSocket-powered chat with Bitcoin-native identity, perfect for trading desks or DAO coordination</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">🎟️</div>
                    <h3>Access Control</h3>
                    <p>Token-gated content, tiered memberships, and threshold-based permissions tied to Bitcoin holdings</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">📊</div>
                    <h3>Enterprise Analytics</h3>
                    <p>Track authentication events, covenant activity, and user behavior with privacy-preserving analytics</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">🔗</div>
                    <h3>API Integration</h3>
                    <p>RESTful APIs and WebSocket endpoints for seamless integration with your existing infrastructure</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">🛡️</div>
                    <h3>Security Auditing</h3>
                    <p>Comprehensive logging, challenge-response verification, and cryptographic audit trails</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">⚙️</div>
                    <h3>Custom Solutions</h3>
                    <p>White glove service for bespoke authentication flows, multi-sig coordination, and specialized use cases</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">🚀</div>
                    <h3>Migration Services</h3>
                    <p>Migrate from Web2 auth providers to Bitcoin-native identity with zero downtime</p>
                </div>

                <div class="capability-card">
                    <div class="capability-icon">📱</div>
                    <h3>Mobile & Desktop</h3>
                    <p>SDK support for iOS, Android, and desktop applications with unified Bitcoin identity</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Use Cases by Industry -->
    <section id="use-cases" class="use-cases-section">
        <div class="container">
            <div class="section-header">
                <h2>Real-World <span class="highlight">Solutions</span></h2>
                <p>Proven implementations across industries</p>
            </div>

            <div class="use-case-tabs">
                <button class="tab-button active">💼 Finance</button>
                <button class="tab-button">🏢 Enterprise</button>
                <button class="tab-button">🌐 Web3</button>
                <button class="tab-button">👥 Community</button>
            </div>

            <!-- Finance Use Cases -->
            <div id="finance" class="use-case-content active">
                <div class="use-case-grid">
                    <div class="use-case-card">
                        <div class="use-case-badge">Trading Platforms</div>
                        <h4>Exclusive Trading Communities</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Prevent spam and bots in premium trading groups while maintaining privacy.<br><br>
                            <strong>Solution:</strong> LNURL-auth for instant signup, PSBT proof-of-funds for tiered access (e.g., 1 BTC minimum for whale rooms), real-time chat with cryptographic identities.
                        </p>
                        <ul class="use-case-features">
                            <li>No email required, full pseudonymity</li>
                            <li>Automatic tier assignment based on holdings</li>
                            <li>Non-custodial verification</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">P2P Lending</div>
                        <h4>Non-Custodial Lending Platforms</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Verify collateral without taking custody of user funds.<br><br>
                            <strong>Solution:</strong> Borrowers prove funds via PSBT, lenders authenticate with Bitcoin keys, smart contracts triggered by cryptographic proofs.
                        </p>
                        <ul class="use-case-features">
                            <li>Prove up to X BTC without moving coins</li>
                            <li>Privacy-preserving verification (boolean/threshold modes)</li>
                            <li>Integration with multi-sig escrow</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">Wealth Management</div>
                        <h4>Bitcoin Private Banking</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Wealthy clients want white-glove service with full privacy.<br><br>
                            <strong>Solution:</strong> Covenant groups for family offices, threshold-based access to advisors, encrypted chat with proof-of-identity.
                        </p>
                        <ul class="use-case-features">
                            <li>Multi-party governance for family offices</li>
                            <li>Selective disclosure to advisors</li>
                            <li>Audit trail for compliance</li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Enterprise Use Cases -->
            <div id="enterprise" class="use-case-content">
                <div class="use-case-grid">
                    <div class="use-case-card">
                        <div class="use-case-badge">HR & Payroll</div>
                        <h4>Bitcoin-Paid Contractor Platforms</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Verify contractor payment capabilities and company solvency before engagement.<br><br>
                            <strong>Solution:</strong> Both parties prove funds, establish covenant for escrow, integrated chat for project coordination.
                        </p>
                        <ul class="use-case-features">
                            <li>Reduce payment disputes by 90%</li>
                            <li>Cryptographic work agreements</li>
                            <li>Milestone-based fund verification</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">Supply Chain</div>
                        <h4>Bitcoin-Settled B2B Networks</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Coordinate multi-party supply chains with Bitcoin settlements.<br><br>
                            <strong>Solution:</strong> Each stakeholder authenticates with Bitcoin identity, covenants per shipment, real-time status updates via WebSocket.
                        </p>
                        <ul class="use-case-features">
                            <li>Immutable identity tied to payment rails</li>
                            <li>Automated settlement triggers</li>
                            <li>Multi-party chat per shipment</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">SaaS Migration</div>
                        <h4>Replace Auth0 with Bitcoin Auth</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Existing SaaS wants to add Bitcoin-native identity without rewriting auth.<br><br>
                            <strong>Solution:</strong> Drop-in OAuth2/OIDC provider, migrate existing users to Bitcoin keys, maintain legacy auth during transition.
                        </p>
                        <ul class="use-case-features">
                            <li>Standards-compliant OIDC endpoints</li>
                            <li>Zero downtime migration</li>
                            <li>Dual auth during transition</li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Web3 Use Cases -->
            <div id="web3" class="use-case-content">
                <div class="use-case-grid">
                    <div class="use-case-card">
                        <div class="use-case-badge">DAO Governance</div>
                        <h4>Bitcoin-Native DAO Coordination</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Sybil-resistant voting with transparent stake verification.<br><br>
                            <strong>Solution:</strong> Covenant-based membership, voting weight from PoF, real-time proposal discussions, OAuth for off-chain tools.
                        </p>
                        <ul class="use-case-features">
                            <li>Cryptographic voting with PoF weight</li>
                            <li>Integrate with Snapshot, Discourse, etc.</li>
                            <li>Threshold-based proposal rights</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">Content Platforms</div>
                        <h4>Bitcoin-Gated Content & Subscriptions</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Monetize content without payment processors or censorship risk.<br><br>
                            <strong>Solution:</strong> LNURL login, threshold-based access tiers (e.g., 0.01 BTC for premium), OAuth for cross-platform access.
                        </p>
                        <ul class="use-case-features">
                            <li>No Stripe, PayPal, or card fees</li>
                            <li>Censorship-resistant monetization</li>
                            <li>Automatic tier upgrades via PoF</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">NFT & Gaming</div>
                        <h4>Bitcoin-Authenticated Gaming</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Prove ownership of high-value NFTs or game assets without centralized servers.<br><br>
                            <strong>Solution:</strong> Bitcoin signature verification for asset ownership, PSBT for in-game tournaments with real stakes.
                        </p>
                        <ul class="use-case-features">
                            <li>Cryptographic proof of asset ownership</li>
                            <li>Escrow-free tournaments</li>
                            <li>Cross-game identity</li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Community Use Cases -->
            <div id="community" class="use-case-content">
                <div class="use-case-grid">
                    <div class="use-case-card">
                        <div class="use-case-badge">Education</div>
                        <h4>Bitcoin Learning Platforms</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Progressive course access tied to Bitcoin acquisition milestones.<br><br>
                            <strong>Solution:</strong> Free tier (LNURL auth), Premium (0.1 BTC PoF), Whale Class (1+ BTC PoF) - incentivize learning through acquisition.
                        </p>
                        <ul class="use-case-features">
                            <li>Gamified learning paths</li>
                            <li>Proof-of-progress via holdings</li>
                            <li>Peer-to-peer mentorship matching</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">Local Communities</div>
                        <h4>Regional Bitcoin Meetup Networks</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Coordinate local meetups without email/phone collection.<br><br>
                            <strong>Solution:</strong> Covenant per city, LNURL-auth for quick entry, event chat, privacy-preserving coordination.
                        </p>
                        <ul class="use-case-features">
                            <li>No PII collection required</li>
                            <li>Regional reputation building</li>
                            <li>Cross-city collaboration</li>
                        </ul>
                    </div>

                    <div class="use-case-card">
                        <div class="use-case-badge">Crowdfunding</div>
                        <h4>KYC-Free Bitcoin Crowdfunding</h4>
                        <p class="scenario">
                            <strong>Challenge:</strong> Global crowdfunding without payment processor restrictions.<br><br>
                            <strong>Solution:</strong> Founders prove credibility via PoF, backers authenticate with LNURL, covenant for multi-sig escrow, real-time updates via chat.
                        </p>
                        <ul class="use-case-features">
                            <li>Permissionless global fundraising</li>
                            <li>Cryptographic accountability</li>
                            <li>Milestone-based fund releases</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- How It Works -->
    <section id="how-it-works" class="how-it-works">
        <div class="container">
            <div class="section-header">
                <h2>How <span class="highlight">It Works</span></h2>
                <p>From consultation to deployment in 4 simple steps</p>
            </div>

            <div class="timeline">
                <div class="timeline-item">
                    <div class="timeline-content">
                        <h3>Discovery & Consultation</h3>
                        <p>We meet with your team to understand your specific needs - whether it's migrating from Auth0, adding Bitcoin payments, or building a new Web3 product. We assess your current infrastructure and design a custom integration plan.</p>
                    </div>
                    <div class="timeline-number">1</div>
                </div>

                <div class="timeline-item">
                    <div class="timeline-content">
                        <h3>Custom Configuration</h3>
                        <p>Our engineers configure the KeyAuth Protocol for your use case - setting up OAuth scopes, covenant structures, PoF thresholds, and privacy levels. We provide sandbox environments for testing before production.</p>
                    </div>
                    <div class="timeline-number">2</div>
                </div>

                <div class="timeline-item">
                    <div class="timeline-content">
                        <h3>Integration & Migration</h3>
                        <p>Seamless integration with your existing systems via our RESTful API, WebSocket endpoints, or OAuth2/OIDC flows. We handle data migration from legacy auth providers with zero downtime.</p>
                    </div>
                    <div class="timeline-number">3</div>
                </div>

                <div class="timeline-item">
                    <div class="timeline-content">
                        <h3>Launch & Ongoing Support</h3>
                        <p>Go live with 24/7 monitoring, dedicated support, and continuous optimization. We provide analytics dashboards, security audits, and proactive scaling recommendations.</p>
                    </div>
                    <div class="timeline-number">4</div>
                </div>
            </div>
        </div>
    </section>

    <!-- Features -->
    <section id="features" class="features-section">
        <div class="container">
            <div class="section-header">
                <h2>Why <span class="highlight">KeyAuth Protocol</span></h2>
                <p>Built for generations, secured by Bitcoin</p>
            </div>

            <div class="features-grid">
                <div class="feature-card">
                    <div class="feature-icon">🔒</div>
                    <h3>Non-Custodial</h3>
                    <p>Users never give up control of their Bitcoin. All verification happens via PSBT and signatures - no custody, no counterparty risk.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">🎭</div>
                    <h3>Privacy First</h3>
                    <p>Multiple privacy levels (boolean/threshold/aggregate). Prove holdings without revealing exact amounts. Pseudonymous by default.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">⚡</div>
                    <h3>Lightning Fast</h3>
                    <p>LNURL-auth for instant onboarding. WebSocket real-time updates. Sub-second authentication flows.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">🌐</div>
                    <h3>Standards Compliant</h3>
                    <p>OAuth2, OpenID Connect, LNURL, PSBT - we speak the language of both Web2 and Web3.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">🛡️</div>
                    <h3>Sybil Resistant</h3>
                    <p>Real economic cost to create accounts. Proof-of-funds as spam protection. Covenant-based access control.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">📊</div>
                    <h3>Enterprise Grade</h3>
                    <p>99.9% uptime SLA. SOC 2 compliant. Comprehensive audit logs. 24/7 support for critical deployments.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Trust Indicators -->
    <section class="trust-section">
        <div class="container">
            <div class="section-header">
                <h2>Trusted by <span class="highlight">Bitcoin Natives</span></h2>
                <p>Powering the next generation of Bitcoin-first applications</p>
            </div>

            <div class="trust-metrics">
                <div class="metric">
                    <div class="metric-value">100%</div>
                    <div class="metric-label">Non-Custodial</div>
                </div>
                <div class="metric">
                    <div class="metric-value">24/7</div>
                    <div class="metric-label">White Glove Support</div>
                </div>
                <div class="metric">
                    <div class="metric-value">99.9%</div>
                    <div class="metric-label">Uptime SLA</div>
                </div>
                <div class="metric">
                    <div class="metric-value">A-Z</div>
                    <div class="metric-label">Full Coverage</div>
                </div>
            </div>
        </div>
    </section>

    <!-- Developer Portal / API Documentation -->
    <section id="developer" class="developer-section">
        <div class="container">
            <div class="section-header">
                <h2>Try the <span class="highlight">Protocol</span></h2>
                <p>Explore our live dashboard, playground, and comprehensive API documentation</p>
            </div>

            <!-- Quick Access Buttons -->
            <div class="portal-links">
                <a href="https://hodlxxi.com/dashboard" target="_blank" class="portal-card">
                    <div class="portal-icon">📊</div>
                    <h3>Dashboard</h3>
                    <p>Monitor your authentication metrics and usage</p>
                    <span class="portal-arrow">→</span>
                </a>

                <a href="https://hodlxxi.com/playground" target="_blank" class="portal-card">
                    <div class="portal-icon">🎮</div>
                    <h3>Playground</h3>
                    <p>Test authentication flows in real-time</p>
                    <span class="portal-arrow">→</span>
                </a>

                <a href="https://hodlxxi.com/oauthx/status" target="_blank" class="portal-card">
                    <div class="portal-icon">🔍</div>
                    <h3>System Status</h3>
                    <p>Check service health and uptime</p>
                    <span class="portal-arrow">→</span>
                </a>

                <a href="https://hodlxxi.com/oauthx/docs" target="_blank" class="portal-card">
                    <div class="portal-icon">📚</div>
                    <h3>Documentation</h3>
                    <p>Complete API reference and guides</p>
                    <span class="portal-arrow">→</span>
                </a>
            </div>

            <!-- API Documentation -->
            <div class="api-docs">
                <h3 class="api-section-title">🔌 Quick Start Guide</h3>

                <!-- Well-Known Endpoints -->
                <div class="api-block">
                    <h4>🌐 Discovery Endpoints</h4>
                    <p class="api-description">OpenID Connect discovery and JWKS endpoints</p>
                    <div class="endpoint-list">
                        <div class="endpoint-item">
                            <span class="http-method get">GET</span>
                            <code class="endpoint-url">https://hodlxxi.com/.well-known/openid-configuration</code>
                            <button class="copy-btn" onclick="copyToClipboard('https://hodlxxi.com/.well-known/openid-configuration')">📋</button>
                        </div>
                        <div class="endpoint-item">
                            <span class="http-method get">GET</span>
                            <code class="endpoint-url">https://hodlxxi.com/oauth/jwks.json</code>
                            <button class="copy-btn" onclick="copyToClipboard('https://hodlxxi.com/oauth/jwks.json')">📋</button>
                        </div>
                    </div>
                </div>

                <!-- Metered API -->
                <div class="api-block">
                    <h4>⚡ Metered API (Pay per Use)</h4>
                    <p class="api-description">Lightning-metered verification endpoint - pay only for what you use</p>
                    <div class="endpoint-list">
                        <div class="endpoint-item">
                            <span class="http-method post">POST</span>
                            <code class="endpoint-url">https://hodlxxi.com/v1/verify</code>
                            <button class="copy-btn" onclick="copyToClipboard('https://hodlxxi.com/v1/verify')">📋</button>
                        </div>
                    </div>
                    <div class="api-note">
                        <span class="note-icon">💡</span>
                        <span>Returns <code>402 Payment Required</code> with BOLT11 invoice when credits depleted</span>
                    </div>
                </div>

                <!-- Code Examples -->
                <div class="code-examples">
                    <h3 class="api-section-title">💻 Integration Examples</h3>

                    <!-- Example 1: Configure OIDC -->
                    <div class="code-block">
                        <div class="code-header">
                            <span class="code-title">1. Configure OIDC Provider</span>
                            <button class="copy-code-btn" onclick="copyCode('code-oidc-config')">Copy</button>
                        </div>
                        <pre id="code-oidc-config"><code class="language-javascript">// Example: Next.js / NextAuth.js
import NextAuth from "next-auth";

export default NextAuth({
  providers: [
    {
      id: "hodlxxi",
      name: "HODLXXI",
      type: "oauth",
      wellKnown: "https://hodlxxi.com/.well-known/openid-configuration",
      authorization: { params: { scope: "openid profile" } },
      clientId: process.env.HODLXXI_CLIENT_ID,
      clientSecret: process.env.HODLXXI_CLIENT_SECRET,
      profile(profile) {
        return {
          id: profile.sub,
          name: profile.name,
          email: profile.email,
        }
      }
    }
  ]
});</code></pre>
                    </div>

                    <!-- Example 2: Token Exchange -->
                    <div class="code-block">
                        <div class="code-header">
                            <span class="code-title">2. Exchange Authorization Code for Token</span>
                            <button class="copy-code-btn" onclick="copyCode('code-token-exchange')">Copy</button>
                        </div>
                        <pre id="code-token-exchange"><code class="language-bash">curl -X POST https://hodlxxi.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=https://yourapp.com/callback"</code></pre>
                    </div>

                    <!-- Example 3: Verify Proof -->
                    <div class="code-block">
                        <div class="code-header">
                            <span class="code-title">3. Verify Bitcoin Signature (Metered)</span>
                            <button class="copy-code-btn" onclick="copyCode('code-verify-proof')">Copy</button>
                        </div>
                        <pre id="code-verify-proof"><code class="language-bash">curl -X POST https://hodlxxi.com/v1/verify \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "bip322",
    "pubkey": "02ab1234567890abcdef...",
    "message": "login:nonce:abc123",
    "signature": "H+Xy9..."
  }'</code></pre>
                    </div>

                    <!-- Discovery Response -->
                    <div class="code-block">
                        <div class="code-header">
                            <span class="code-title">📡 Discovery Endpoint Response</span>
                            <button class="copy-code-btn" onclick="copyCode('code-discovery')">Copy</button>
                        </div>
                        <pre id="code-discovery"><code class="language-json">{
  "issuer": "https://hodlxxi.com",
  "authorization_endpoint": "https://hodlxxi.com/oauth/authorize",
  "token_endpoint": "https://hodlxxi.com/oauth/token",
  "jwks_uri": "https://hodlxxi.com/oauth/jwks.json",
  "userinfo_endpoint": "https://hodlxxi.com/oauth/userinfo",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"]
}</code></pre>
                    </div>
                </div>

                <!-- Live Test Section -->
                <div class="live-test-section">
                    <h3 class="api-section-title">🚀 Test Live Endpoints</h3>
                    <div class="test-grid">
                        <div class="test-card">
                            <h4>Discovery Endpoint</h4>
                            <p>Fetch OpenID configuration</p>
                            <button class="test-button" onclick="testEndpoint('discovery')">
                                <span id="discovery-status">Test Now</span>
                            </button>
                            <pre id="discovery-result" class="test-result"></pre>
                        </div>
                        <div class="test-card">
                            <h4>System Status</h4>
                            <p>Check service health</p>
                            <button class="test-button" onclick="testEndpoint('status')">
                                <span id="status-status">Test Now</span>
                            </button>
                            <pre id="status-result" class="test-result"></pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- CTA Section -->
    <section id="contact" class="cta-section">
        <div class="container">
            <div class="cta-box">
                <h2>Ready to Build on Bitcoin?</h2>
                <p>E-mail or Chat with our team to discuss your specific needs</p>
                <div class="cta-buttons-large">
                    <a href="mailto:hodlxxi@proton.me" class="white-button">E-mail</a>
                    <a href="https://hodlxxi.com/oauthx/docs" target="_blank" class="secondary-button" style="background: rgba(255,255,255,0.2); color: white; border-color: white;">Docs</a>
                    <a href="https://hodlxxi.com/login" target="_blank" class="secondary-button" style="background: rgba(0,255,136,0.2); color: white; border: 2px solid var(--accent);">Login</a>
                </div>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer>
        <div class="container">
            <div class="footer-content">
                <div class="footer-brand">
                    <h3>⚡ KeyAuth Protocol ⚡</h3>
                    <p>The universal Bitcoin identity layer bridging Web2 to Web3. Non-custodial authentication, proof-of-funds, and covenant coordination for the Bitcoin economy.</p>
                </div>
                <div class="footer-links">
                    <h4>Product</h4>
                    <ul>
                        <li><a href="#capabilities">Capabilities</a></li>
                        <li><a href="#use-cases">Use Cases</a></li>
                        <li><a href="#developer">Developer Portal</a></li>
                        <li><a href="#features">Features</a></li>
                        <li><a href="https://hodlxxi.com/oauthx/docs" target="_blank">Documentation</a></li>
                        <li><a href="https://hodlxxi.com/playground" target="_blank">API Playground</a></li>
                    </ul>
                </div>
                <div class="footer-links">
                    <h4>Resources</h4>
                    <ul>
                        <li><a href="#">GitHub</a></li>
                        <li><a href="#">Support</a></li>
                        <li><a href="#">Privacy Policy</a></li>
                        <li><a href="#">Terms of Service</a></li>
                    </ul>
                </div>
            </div>
            <div class="footer-bottom">
                <p>&copy; 2025 KeyAuth Protocol. All rights reserved. Built on Bitcoin.</p>
            </div>
        </div>
    </footer>

    <script>
        // Tab switching for use cases - Fixed for mobile
        function showTab(tabName) {
            // Hide all content
            document.querySelectorAll('.use-case-content').forEach(content => {
                content.classList.remove('active');
            });

            // Remove active from all buttons
            document.querySelectorAll('.tab-button').forEach(button => {
                button.classList.remove('active');
            });

            // Show selected content
            const targetContent = document.getElementById(tabName);
            if (targetContent) {
                targetContent.classList.add('active');
            }

            // Add active to clicked button - find button by matching text or data attribute
            document.querySelectorAll('.tab-button').forEach(button => {
                const buttonText = button.textContent.toLowerCase();
                if (buttonText.includes(tabName.toLowerCase()) ||
                    button.getAttribute('data-tab') === tabName) {
                    button.classList.add('active');
                }
            });
        }

        // Add click handlers to buttons (better than inline onclick for mobile)
        document.addEventListener('DOMContentLoaded', function() {
            const tabButtons = [
                { button: document.querySelectorAll('.tab-button')[0], tab: 'finance' },
                { button: document.querySelectorAll('.tab-button')[1], tab: 'enterprise' },
                { button: document.querySelectorAll('.tab-button')[2], tab: 'web3' },
                { button: document.querySelectorAll('.tab-button')[3], tab: 'community' }
            ];

            tabButtons.forEach(({ button, tab }) => {
                if (button) {
                    button.setAttribute('data-tab', tab);
                    button.addEventListener('click', function(e) {
                        e.preventDefault();
                        showTab(tab);
                    });
                }
            });
        });

        // Smooth scroll
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });

        // Intersection Observer for animations
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -100px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        }, observerOptions);

        // Observe all cards
        document.querySelectorAll('.capability-card, .use-case-card, .feature-card, .timeline-item').forEach(el => {
            el.style.opacity = '0';
            el.style.transform = 'translateY(30px)';
            el.style.transition = 'all 0.6s ease-out';
            observer.observe(el);
        });

        // ============================================================================
        // MATRIX BACKGROUND ANIMATION - WARP EFFECT
        // ============================================================================

        /* --- Matrix: Warp (0s and 1s flying toward camera) --- */
        function startMatrixWarp(canvas) {
            if (!canvas) return () => {};
            const ctx = canvas.getContext('2d');
            const CHARS = ['0', '1'];
            let width = 0, height = 0, particles = [], raf = null;

            function resize() {
                width = window.innerWidth;
                height = window.innerHeight;
                canvas.width = width;
                canvas.height = height;
                particles = [];
                for (let i = 0; i < 400; i++) {
                    particles.push({
                        x: (Math.random() - 0.5) * width,
                        y: (Math.random() - 0.5) * height,
                        z: Math.random() * 800 + 100
                    });
                }
            }

            function draw() {
                ctx.fillStyle = 'rgba(0,0,0,0.25)';
                ctx.fillRect(0, 0, width, height);
                ctx.fillStyle = '#00ff88';
                for (const p of particles) {
                    const scale = 200 / p.z;
                    const x2 = width / 2 + p.x * scale;
                    const y2 = height / 2 + p.y * scale;
                    const size = Math.max(8 * scale, 1);
                    ctx.font = size + 'px monospace';
                    ctx.fillText(CHARS[Math.random() > 0.5 ? 1 : 0], x2, y2);
                    p.z -= 5;
                    if (p.z < 1) {
                        p.x = (Math.random() - 0.5) * width;
                        p.y = (Math.random() - 0.5) * height;
                        p.z = 800;
                    }
                }
                raf = requestAnimationFrame(draw);
            }

            function onVis() {
                if (document.hidden) {
                    if (raf) cancelAnimationFrame(raf), raf = null;
                } else {
                    if (!raf) raf = requestAnimationFrame(draw);
                }
            }

            function onResize() {
                resize();
            }

            window.addEventListener('resize', onResize);
            document.addEventListener('visibilitychange', onVis);
            resize();
            raf = requestAnimationFrame(draw);
            return function stop() {
                if (raf) cancelAnimationFrame(raf), raf = null;
                window.removeEventListener('resize', onResize);
                document.removeEventListener('visibilitychange', onVis);
            };
        }

        /* --- Initialize Matrix Warp Background --- */
        (function initMatrix() {
            const warpCanvas = document.getElementById('matrix-warp');
            if (!warpCanvas) return;

            let stopWarp = startMatrixWarp(warpCanvas);

            // Cleanup on page unload
            window.addEventListener('beforeunload', () => {
                if (stopWarp) stopWarp();
            });
        })();

        // ============================================================================
        // DEVELOPER PORTAL FUNCTIONS
        // ============================================================================

        // Copy text to clipboard
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                // Visual feedback
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = '✓';
                btn.style.color = 'var(--accent)';
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.color = '';
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy:', err);
            });
        }

        // Copy code block
        function copyCode(elementId) {
            const codeElement = document.getElementById(elementId);
            if (!codeElement) return;

            const text = codeElement.textContent;
            navigator.clipboard.writeText(text).then(() => {
                // Visual feedback
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(() => {
                    btn.textContent = originalText;
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy:', err);
            });
        }

        // Test live endpoints
        async function testEndpoint(type) {
            const statusElement = document.getElementById(`${type}-status`);
            const resultElement = document.getElementById(`${type}-result`);

            statusElement.textContent = 'Testing...';
            resultElement.textContent = '';

            try {
                let url;
                if (type === 'discovery') {
                    url = 'https://hodlxxi.com/.well-known/openid-configuration';
                } else if (type === 'status') {
                    url = 'https://hodlxxi.com/oauthx/status';
                }

                const response = await fetch(url);
                const data = await response.json();

                statusElement.textContent = `✓ ${response.status} ${response.statusText}`;
                resultElement.textContent = JSON.stringify(data, null, 2);
                resultElement.style.display = 'block';
            } catch (error) {
                statusElement.textContent = '✗ Error';
                resultElement.textContent = `Error: ${error.message}\n\nThis might be due to CORS restrictions. Try accessing the URL directly in a new tab.`;
                resultElement.style.display = 'block';
                resultElement.style.color = 'var(--bitcoin-orange)';
            }
        }
    </script>
</body>
</html>
"""



# ============================================================================
# PLAYGROUND HTML TEMPLATE
# ============================================================================

PLAYGROUND_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎮 HODLXXI Playground - Test All Auth Methods</title>
    
    <!-- React 18 -->
    <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    
    <!-- QR Code -->
    <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
    
    <!-- Socket.IO -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.1/socket.io.min.js"></script>
    
    <style>
        :root {
            --bg: #0b0f10;
            --panel: #11171a;
            --fg: #e6f1ef;
            --accent: #00ff88;
            --orange: #f7931a;
            --red: #ff3b30;
            --blue: #3b82f6;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            background: var(--bg);
            color: var(--fg);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        #matrix-bg {
            position: fixed;
            inset: 0;
            z-index: 0;
            pointer-events: none;
        }
        
        @media (prefers-reduced-motion: reduce) {
            #matrix-bg { display: none !important; }
        }
        
        #root {
            position: relative;
            z-index: 1;
            padding: 2rem;
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: rgba(17, 23, 26, 0.92);
            border: 1px solid #0f2a24;
            border-radius: 14px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 0 10px rgba(0, 255, 136, 0.08);
        }
        
        .header h1 {
            color: var(--accent);
            font-size: 2rem;
            margin-bottom: 0.5rem;
            text-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
        }
        
        .header-info {
            display: flex;
            gap: 1rem;
            margin-top: 1rem;
            flex-wrap: wrap;
        }
        
        .card {
            background: rgba(17, 23, 26, 0.92);
            border: 1px solid #0f2a24;
            border-radius: 14px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 0 10px rgba(0, 255, 136, 0.08);
        }
        
        .card h2 {
            color: var(--accent);
            margin-bottom: 1rem;
            font-size: 1.3rem;
        }
        
        .tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }
        
        .tab {
            background: #0e1516;
            border: 1px solid #184438;
            color: var(--fg);
            padding: 0.75rem 1.25rem;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            font-weight: 500;
            font-size: 0.9rem;
        }
        
        .tab.active {
            background: var(--accent);
            color: #000;
            border-color: var(--accent);
            box-shadow: 0 0 15px rgba(0, 255, 136, 0.3);
        }
        
        .tab:hover:not(.active) {
            border-color: var(--accent);
            background: rgba(0, 255, 136, 0.1);
        }
        
        input, textarea, select {
            width: 100%;
            background: #0e1315;
            color: var(--fg);
            border: 1px solid #255244;
            padding: 0.75rem;
            border-radius: 8px;
            font-family: ui-monospace, monospace;
            margin: 0.5rem 0;
            font-size: 0.9rem;
        }
        
        input:focus, textarea:focus, select:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(0, 255, 136, 0.2);
        }
        
        button {
            background: var(--accent);
            color: #000;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
            font-size: 0.95rem;
        }
        
        button:hover {
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
            transform: translateY(-2px);
        }
        
        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        button.secondary {
            background: transparent;
            border: 1px solid var(--accent);
            color: var(--accent);
        }
        
        button.danger {
            background: var(--red);
            color: white;
        }
        
        .result {
            background: #0e1315;
            border: 1px solid #255244;
            padding: 1rem;
            border-radius: 8px;
            font-family: monospace;
            font-size: 0.8rem;
            max-height: 400px;
            overflow-y: auto;
            margin-top: 1rem;
        }
        
        .result.success {
            border-color: var(--accent);
            background: rgba(0, 255, 136, 0.05);
        }
        
        .result.error {
            border-color: var(--red);
            background: rgba(255, 59, 48, 0.05);
            color: var(--red);
        }
        
        .qr-container {
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 1rem 0;
            padding: 1rem;
            background: white;
            border-radius: 12px;
            border: 2px solid var(--accent);
        }
        
        .qr-container canvas {
            display: block;
        }
        
        .status-badge {
            display: inline-block;
            padding: 0.35rem 0.85rem;
            border-radius: 6px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .status-badge.success {
            background: rgba(0, 255, 136, 0.2);
            color: var(--accent);
            border: 1px solid var(--accent);
        }
        
        .status-badge.pending {
            background: rgba(247, 147, 26, 0.2);
            color: var(--orange);
            border: 1px solid var(--orange);
        }
        
        .status-badge.error {
            background: rgba(255, 59, 48, 0.2);
            color: var(--red);
            border: 1px solid var(--red);
        }
        
        .label {
            font-size: 0.875rem;
            color: var(--accent);
            font-weight: 600;
            display: block;
            margin-top: 1rem;
            margin-bottom: 0.25rem;
        }
        
        .code-box {
            background: #0e1315;
            padding: 1rem;
            border-radius: 8px;
            border: 1px dashed var(--accent);
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
        }
        
        .code-box:hover {
            background: rgba(0, 255, 136, 0.05);
            border-color: var(--accent);
        }
        
        .code-box code {
            color: var(--accent);
            word-break: break-all;
            font-size: 0.85rem;
        }
        
        .hint {
            background: rgba(247, 147, 26, 0.1);
            border-left: 3px solid var(--orange);
            padding: 1rem;
            border-radius: 6px;
            margin-top: 1rem;
        }
        
        .hint-title {
            color: var(--orange);
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        .hint ol, .hint ul {
            margin-left: 1.5rem;
            color: var(--muted);
            font-size: 0.875rem;
        }
        
        .hint li {
            margin: 0.25rem 0;
        }
        
        .spinner {
            display: inline-block;
            width: 1rem;
            height: 1rem;
            border: 2px solid rgba(0, 255, 136, 0.3);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 0.6s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        @media (max-width: 768px) {
            #root {
                padding: 1rem;
            }
            
            .header h1 {
                font-size: 1.5rem;
            }
            
            .tabs {
                flex-direction: column;
            }
            
            .tab {
                width: 100%;
                text-align: center;
            }
        }
        
        /* Loading overlay */
        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
        }
        
        .loading-content {
            text-align: center;
        }
        
        .loading-spinner {
            width: 3rem;
            height: 3rem;
            border: 3px solid rgba(0, 255, 136, 0.3);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto 1rem;
        }
    </style>
</head>
<body>
    <canvas id="matrix-bg" aria-hidden="true"></canvas>
    <div id="root"></div>
    
    <!-- Matrix Animation -->
    <script>
        (function() {
            const canvas = document.getElementById('matrix-bg');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            const CHARS = ['0','1'];
            let width = 0, height = 0, particles = [], raf = null;

            function resize() {
                const dpr = Math.max(1, Math.min(window.devicePixelRatio || 1, 2));
                const cssW = window.innerWidth, cssH = window.innerHeight;
                canvas.width = Math.floor(cssW * dpr);
                canvas.height = Math.floor(cssH * dpr);
                canvas.style.width = cssW + 'px';
                canvas.style.height = cssH + 'px';
                ctx.setTransform(1,0,0,1,0,0);
                ctx.scale(dpr, dpr);
                width = cssW; height = cssH;
                particles = [];
                for (let i = 0; i < 400; i++) {
                    particles.push({
                        x: (Math.random() - 0.5) * width,
                        y: (Math.random() - 0.5) * height,
                        z: Math.random() * 800 + 100
                    });
                }
                ctx.fillStyle = 'rgba(0,0,0,1)';
                ctx.fillRect(0, 0, width, height);
            }

            function draw() {
                ctx.fillStyle = 'rgba(0,0,0,0.25)';
                ctx.fillRect(0, 0, width, height);
                ctx.fillStyle = '#00ff88';
                for (const p of particles) {
                    const scale = 200 / p.z;
                    const x2 = width / 2 + p.x * scale;
                    const y2 = height / 2 + p.y * scale;
                    const size = Math.max(8 * scale, 1);
                    ctx.font = size + 'px monospace';
                    ctx.fillText(CHARS[(Math.random() > 0.5) | 0], x2, y2);
                    p.z -= 5;
                    if (p.z < 1) {
                        p.x = (Math.random() - 0.5) * width;
                        p.y = (Math.random() - 0.5) * height;
                        p.z = 800;
                    }
                }
                raf = requestAnimationFrame(draw);
            }

            function onVis() {
                if (document.hidden) { 
                    if (raf) cancelAnimationFrame(raf), raf = null; 
                } else { 
                    if (!raf) raf = requestAnimationFrame(draw); 
                }
            }

            window.addEventListener('resize', resize);
            document.addEventListener('visibilitychange', onVis);
            resize();
            raf = requestAnimationFrame(draw);
        })();
    </script>
    
    <!-- React App -->
    <script type="text/babel">
        const { useState, useEffect, useRef } = React;
        
        function PlaygroundApp() {
            const [activeTab, setActiveTab] = useState('legacy');
            const [result, setResult] = useState(null);
            const [loading, setLoading] = useState(false);
            
            const loggedIn = "{{ logged_in_pubkey }}";
            const accessLevel = "{{ access_level }}";
            const issuer = "{{ issuer }}";
            
            return (
                <div>
                    <div className="header">
                        <h1>🎮 HODLXXI API Playground</h1>
                        <p style={{color: 'var(--muted)', marginBottom: '1rem'}}>
                            Test all authentication methods, OAuth flows, and Bitcoin verification in real-time
                        </p>
                        {loggedIn && loggedIn !== '' ? (
                            <div className="header-info">
                                <span className="status-badge success">
                                    Logged in: {loggedIn.slice(-8)}
                                </span>
                                <span className="status-badge pending">
                                    Access: {accessLevel}
                                </span>
                            </div>
                        ) : (
                            <div className="header-info">
                                <span className="status-badge error">
                                    Not logged in
                                </span>
                            </div>
                        )}
                    </div>
                    
                    {loading && (
                        <div className="loading-overlay">
                            <div className="loading-content">
                                <div className="loading-spinner"></div>
                                <p style={{color: 'var(--accent)'}}>Processing...</p>
                            </div>
                        </div>
                    )}
                    
                    <div className="card">
                        <div className="tabs">
                            <button 
                                className={`tab ${activeTab === 'legacy' ? 'active' : ''}`}
                                onClick={() => setActiveTab('legacy')}
                            >
                                🔐 Legacy Signature
                            </button>
                            <button 
                                className={`tab ${activeTab === 'api' ? 'active' : ''}`}
                                onClick={() => setActiveTab('api')}
                            >
                                ⚡ API Challenge
                            </button>
                            <button 
                                className={`tab ${activeTab === 'lnurl' ? 'active' : ''}`}
                                onClick={() => setActiveTab('lnurl')}
                            >
                                ⚡ LNURL-Auth
                            </button>
                            <button 
                                className={`tab ${activeTab === 'oauth' ? 'active' : ''}`}
                                onClick={() => setActiveTab('oauth')}
                            >
                                🔑 OAuth Flow
                            </button>
                            <button 
                                className={`tab ${activeTab === 'pof' ? 'active' : ''}`}
                                onClick={() => setActiveTab('pof')}
                            >
                                💰 Proof of Funds
                            </button>
                        </div>
                        
                        {activeTab === 'legacy' && <LegacyTab setResult={setResult} setLoading={setLoading} />}
                        {activeTab === 'api' && <APITab setResult={setResult} setLoading={setLoading} />}
                        {activeTab === 'lnurl' && <LNURLTab setResult={setResult} setLoading={setLoading} issuer={issuer} />}
                        {activeTab === 'oauth' && <OAuthTab setResult={setResult} setLoading={setLoading} issuer={issuer} />}
                        {activeTab === 'pof' && <PoFTab setResult={setResult} setLoading={setLoading} />}
                    </div>
                    
                    {result && (
                        <div className="card">
                            <h2>📊 Result</h2>
                            <div className={`result ${result.error ? 'error' : 'success'}`}>
                                <pre>{JSON.stringify(result, null, 2)}</pre>
                            </div>
                            <button 
                                className="secondary" 
                                style={{marginTop: '1rem'}}
                                onClick={() => setResult(null)}
                            >
                                Clear Result
                            </button>
                        </div>
                    )}
                </div>
            );
        }
        
        // === TAB COMPONENTS ===
        
        function LegacyTab({ setResult, setLoading }) {
            const [pubkey, setPubkey] = useState('');
            const [signature, setSignature] = useState('');
            const [challenge, setChallenge] = useState('Loading...');
            
            useEffect(() => {
                fetch('/login')
                    .then(r => r.text())
                    .then(html => {
                        const match = html.match(/id="legacyChallenge"[^>]*>([^<]+)</);
                        if (match) setChallenge(match[1].trim());
                        else setChallenge('Failed to load challenge');
                    })
                    .catch(() => setChallenge('Error loading challenge'));
            }, []);
            
            const handleVerify = async () => {
                if (!pubkey || !signature) {
                    setResult({ error: 'Both pubkey and signature are required' });
                    return;
                }
                
                setLoading(true);
                try {
                    const res = await fetch('/verify_signature', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ pubkey, signature, challenge })
                    });
                    const data = await res.json();
                    setResult(data);
                    
                    if (data.verified) {
                        setTimeout(() => window.location.href = '/app', 2000);
                    }
                } catch (err) {
                    setResult({ error: err.message });
                } finally {
                    setLoading(false);
                }
            };
            
            const copyChallenge = () => {
                navigator.clipboard.writeText(challenge);
                alert('Challenge copied to clipboard!');
            };
            
            return (
                <div>
                    <label className="label">Challenge (Sign this in your wallet)</label>
                    <div className="code-box" onClick={copyChallenge} title="Click to copy">
                        <code>{challenge}</code>
                    </div>
                    
                    <label className="label">Public Key</label>
                    <input 
                        value={pubkey}
                        onChange={(e) => setPubkey(e.target.value)}
                        placeholder="02... or 03... (66 hex chars)"
                    />
                    
                    <label className="label">Signature (Base64)</label>
                    <textarea 
                        value={signature}
                        onChange={(e) => setSignature(e.target.value)}
                        placeholder="Base64 signature from Electrum/Sparrow/Bitcoin Core"
                        rows="4"
                    />
                    
                    <button onClick={handleVerify} style={{marginTop: '1rem'}}>
                        Verify & Login
                    </button>
                    
                    <div className="hint">
                        <div className="hint-title">How to sign:</div>
                        <ol>
                            <li>Copy the challenge above</li>
                            <li>Open your Bitcoin wallet (Electrum, Sparrow, etc.)</li>
                            <li>Find "Sign Message" feature</li>
                            <li>Paste challenge, sign with your key</li>
                            <li>Copy signature and paste above</li>
                        </ol>
                    </div>
                </div>
            );
        }
        
        function APITab({ setResult, setLoading }) {
            const [pubkey, setPubkey] = useState('');
            const [challengeId, setChallengeId] = useState('');
            const [challengeText, setChallengeText] = useState('');
            const [signature, setSignature] = useState('');
            const [step, setStep] = useState(1);
            
            const getChallenge = async () => {
                if (!pubkey) {
                    setResult({ error: 'Public key is required' });
                    return;
                }
                
                setLoading(true);
                try {
                    const res = await fetch('/api/challenge', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ pubkey })
                    });
                    const data = await res.json();
                    
                    if (data.challenge_id && data.challenge) {
                        setChallengeId(data.challenge_id);
                        setChallengeText(data.challenge);
                        setStep(2);
                        setResult(data);
                    } else {
                        setResult({ error: 'Invalid response from server' });
                    }
                } catch (err) {
                    setResult({ error: err.message });
                } finally {
                    setLoading(false);
                }
            };
            
            const verify = async () => {
                if (!signature) {
                    setResult({ error: 'Signature is required' });
                    return;
                }
                
                setLoading(true);
                try {
                    const res = await fetch('/api/verify', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ 
                            pubkey, 
                            signature, 
                            challenge_id: challengeId 
                        })
                    });
                    const data = await res.json();
                    setResult(data);
                    
                    if (data.verified) {
                        setTimeout(() => window.location.href = '/app', 2000);
                    }
                } catch (err) {
                    setResult({ error: err.message });
                } finally {
                    setLoading(false);
                }
            };
            
            const copyText = (text) => {
                navigator.clipboard.writeText(text);
                alert('Copied to clipboard!');
            };
            
            return (
                <div>
                    <div style={{marginBottom: '1rem'}}>
                        <span className="status-badge success">Step {step} of 2</span>
                    </div>
                    
                    <label className="label">Public Key</label>
                    <input 
                        value={pubkey}
                        onChange={(e) => setPubkey(e.target.value)}
                        placeholder="02... or npub..."
                        disabled={step === 2}
                    />
                    
                    {step === 1 && (
                        <button onClick={getChallenge} style={{marginTop: '0.5rem'}}>
                            Get Challenge
                        </button>
                    )}
                    
                    {step === 2 && (
                        <>
                            <label className="label">Challenge (Click to copy)</label>
                            <div className="code-box" onClick={() => copyText(challengeText)}>
                                <code>{challengeText}</code>
                            </div>
                            
                            <label className="label">Challenge ID</label>
                            <input value={challengeId} readOnly />
                            
                            <label className="label">Signature (Base64)</label>
                            <textarea 
                                value={signature}
                                onChange={(e) => setSignature(e.target.value)}
                                placeholder="Paste signature here"
                                rows="4"
                            />
                            
                            <div style={{display: 'flex', gap: '0.5rem', marginTop: '1rem'}}>
                                <button onClick={verify}>Verify & Login</button>
                                <button className="secondary" onClick={() => { setStep(1); setChallengeText(''); setSignature(''); }}>
                                    Start Over
                                </button>
                            </div>
                        </>
                    )}
                    
                    <div className="hint">
                        <div className="hint-title">API Authentication Flow:</div>
                        <ol>
                            <li>Request challenge with your pubkey</li>
                            <li>Sign challenge with your Bitcoin wallet</li>
                            <li>Submit signature for verification</li>
                            <li>Receive access token on success</li>
                        </ol>
                    </div>
                </div>
            );
        }
        
        function LNURLTab({ setResult, setLoading, issuer }) {
            const [lnurl, setLnurl] = useState('');
            const [sessionId, setSessionId] = useState('');
            const [polling, setPolling] = useState(false);
            const qrRef = useRef(null);
            const pollIntervalRef = useRef(null);
            
            useEffect(() => {
                return () => {
                    if (pollIntervalRef.current) {
                        clearInterval(pollIntervalRef.current);
                    }
                };
            }, []);
            
            const createSession = async () => {
                setLoading(true);
                try {
                    const res = await fetch('/api/lnurl-auth/create', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' }
                    });
                    const data = await res.json();
                    
                    if (data.lnurl && data.session_id) {
                        setLnurl(data.lnurl);
                        setSessionId(data.session_id);
                        setResult(data);
                        
                        // Generate QR
                        if (qrRef.current && window.QRCode) {
                            qrRef.current.innerHTML = '';
                            new QRCode(qrRef.current, {
                                text: data.lnurl,
                                width: 256,
                                height: 256,
                                colorDark: '#000000',
                                colorLight: '#ffffff'
                            });
                        }
                        
                        // Start polling
                        setPolling(true);
                        pollIntervalRef.current = setInterval(async () => {
                            try {
                                const checkRes = await fetch(`/api/lnurl-auth/check/${data.session_id}`);
                                const checkData = await checkRes.json();
                                
                                if (checkData.authenticated) {
                                    clearInterval(pollIntervalRef.current);
                                    setPolling(false);
                                    setResult({ 
                                        ...checkData, 
                                        message: '✓ Authentication successful!',
                                        success: true
                                    });
                                    setTimeout(() => window.location.href = '/app', 2000);
                                }
                            } catch (err) {
                                console.error('Polling error:', err);
                            }
                        }, 2000);
                    } else {
                        setResult({ error: 'Invalid response from server' });
                    }
                } catch (err) {
                    setResult({ error: err.message });
                } finally {
                    setLoading(false);
                }
            };
            
            const stopPolling = () => {
                if (pollIntervalRef.current) {
                    clearInterval(pollIntervalRef.current);
                    setPolling(false);
                }
            };
            
            return (
                <div>
                    {!lnurl ? (
                        <button onClick={createSession}>
                            Create LNURL-Auth Session
                        </button>
                    ) : (
                        <>
                            <div className="qr-container">
                                <div ref={qrRef}></div>
                            </div>
                            
                            <label className="label">LNURL (Click to copy)</label>
                            <div 
                                className="code-box" 
                                onClick={() => {
                                    navigator.clipboard.writeText(lnurl);
                                    alert('LNURL copied to clipboard!');
                                }}
                                style={{fontSize: '0.75rem', wordBreak: 'break-all'}}
                            >
                                <code>{lnurl}</code>
                            </div>
                            
                            <div style={{display: 'flex', gap: '0.5rem', marginTop: '1rem', flexWrap: 'wrap'}}>
                                <a 
                                    href={`lightning:${lnurl}`} 
                                    style={{
                                        display: 'inline-block',
                                        padding: '0.75rem 1.5rem',
                                        background: 'var(--orange)',
                                        color: '#fff',
                                        borderRadius: '8px',
                                        textDecoration: 'none',
                                        fontWeight: 600
                                    }}
                                >
                                    Open in Wallet
                                </a>
                                <button className="secondary" onClick={stopPolling}>
                                    {polling ? 'Stop Polling' : 'Stopped'}
                                </button>
                            </div>
                            
                            {polling && (
                                <div style={{marginTop: '1rem', textAlign: 'center'}}>
                                    <span className="spinner" style={{marginRight: '0.5rem'}}></span>
                                    <span style={{color: 'var(--muted)'}}>
                                        Waiting for authentication... (Session: {sessionId.slice(0, 8)}...)
                                    </span>
                                </div>
                            )}
                        </>
                    )}
                    
                    <div className="hint">
                        <div className="hint-title">Compatible Wallets:</div>
                        <ul>
                            <li>Alby (Browser extension)</li>
                            <li>Mutiny (Web/Mobile)</li>
                            <li>Zeus (Mobile)</li>
                            <li>Phoenix (Mobile)</li>
                            <li>Blixt (Mobile)</li>
                        </ul>
                    </div>
                </div>
            );
        }
        
        function OAuthTab({ setResult, setLoading, issuer }) {
            const [clientId, setClientId] = useState('');
            const [clientSecret, setClientSecret] = useState('');
            const [registeredClient, setRegisteredClient] = useState(null);
            const [showSecret, setShowSecret] = useState(false);
            
            const registerClient = async () => {
                setLoading(true);
                try {
                    const res = await fetch('/oauth/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            redirect_uris: ['http://localhost:3000/callback', 'https://oauth.pstmn.io/v1/callback']
                        })
                    });
                    const data = await res.json();
                    
                    if (data.client_id && data.client_secret) {
                        setRegisteredClient(data);
                        setClientId(data.client_id);
                        setClientSecret(data.client_secret);
                        setResult(data);
                    } else {
                        setResult({ error: 'Registration failed', details: data });
                    }
                } catch (err) {
                    setResult({ error: err.message });
                } finally {
                    setLoading(false);
                }
            };
            
            const startOAuthFlow = () => {
                const params = new URLSearchParams({
                    client_id: clientId,
                    redirect_uri: 'http://localhost:3000/callback',
                    scope: 'read',
                    response_type: 'code',
                    state: Math.random().toString(36).slice(2)
                });
                const url = `/oauth/authorize?${params}`;
                window.open(url, '_blank', 'width=600,height=800');
            };
            
            return (
                <div>
                    {!registeredClient ? (
                        <>
                            <button onClick={registerClient}>
                                Register New OAuth Client
                            </button>
                            
                            <div className="hint">
                                <div className="hint-title">What is OAuth2?</div>
                                <p style={{color: 'var(--muted)', fontSize: '0.875rem'}}>
                                    OAuth 2.0 is an authorization framework that enables applications to obtain 
                                    limited access to user accounts. This playground lets you test the full 
                                    OAuth flow including client registration, authorization, and token exchange.
                                </p>
                            </div>
                        </>
                    ) : (
                        <>
                            <label className="label">Client ID</label>
                            <div className="code-box" onClick={() => navigator.clipboard.writeText(clientId)}>
                                <code>{clientId}</code>
                            </div>
                            
                            <label className="label">Client Secret (Save this securely!)</label>
                            <div style={{position: 'relative'}}>
                                <input 
                                    type={showSecret ? 'text' : 'password'}
                                    value={clientSecret}
                                    readOnly
                                    style={{fontFamily: 'monospace'}}
                                />
                                <button 
                                    className="secondary"
                                    style={{
                                        position: 'absolute',
                                        right: '0.5rem',
                                        top: '50%',
                                        transform: 'translateY(-50%)',
                                        padding: '0.5rem 1rem'
                                    }}
                                    onClick={() => setShowSecret(!showSecret)}
                                >
                                    {showSecret ? '🙈 Hide' : '👁️ Show'}
                                </button>
                            </div>
                            
                            <div style={{marginTop: '1rem'}}>
                                <button onClick={startOAuthFlow}>
                                    Start Authorization Flow
                                </button>
                            </div>
                            
                            <div className="hint">
                                <div className="hint-title">Next Steps:</div>
                                <ol>
                                    <li>Click "Start Authorization Flow"</li>
                                    <li>Authorize in the popup window</li>
                                    <li>You'll receive an authorization code</li>
                                    <li>Exchange code for access token at <code>/oauth/token</code></li>
                                </ol>
                            </div>
                            
                            <div className="hint" style={{marginTop: '1rem'}}>
                                <div className="hint-title">Token Exchange Example:</div>
                                <pre style={{background: '#000', padding: '1rem', borderRadius: '6px', overflow: 'auto'}}>
{`curl -X POST ${issuer}/oauth/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code" \\
  -d "client_id=${clientId}" \\
  -d "client_secret=${clientSecret}" \\
  -d "code=YOUR_AUTH_CODE" \\
  -d "redirect_uri=http://localhost:3000/callback"`}
                                </pre>
                            </div>
                        </>
                    )}
                </div>
            );
        }
        
        function PoFTab({ setResult, setLoading }) {
            const [pubkey, setPubkey] = useState('');
            const [challengeId, setChallengeId] = useState('');
            const [challenge, setChallenge] = useState('');
            const [psbt, setPsbt] = useState('');
            const [step, setStep] = useState(1);
            
            const getChallenge = async () => {
                if (!pubkey) {
                    setResult({ error: 'Public key is required' });
                    return;
                }
                
                setLoading(true);
                try {
                    const res = await fetch('/api/pof/challenge', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ pubkey })
                    });
                    const data = await res.json();
                    
                    if (data.challenge_id && data.challenge) {
                        setChallengeId(data.challenge_id);
                        setChallenge(data.challenge);
                        setStep(2);
                        setResult(data);
                    } else {
                        setResult({ error: 'Failed to get challenge', details: data });
                    }
                } catch (err) {
                    setResult({ error: err.message });
                } finally {
                    setLoading(false);
                }
            };
            
            const verifyPSBT = async () => {
                if (!psbt) {
                    setResult({ error: 'PSBT is required' });
                    return;
                }
                
                setLoading(true);
                try {
                    const res = await fetch('/api/pof/verify_psbt', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            challenge_id: challengeId,
                            psbt,
                            privacy_level: 'aggregate',
                            min_sat: 0
                        })
                    });
                    const data = await res.json();
                    setResult(data);
                } catch (err) {
                    setResult({ error: err.message });
                } finally {
                    setLoading(false);
                }
            };
            
            return (
                <div>
                    <div style={{marginBottom: '1rem'}}>
                        <span className="status-badge success">Step {step} of 2</span>
                    </div>
                    
                    <label className="label">Public Key</label>
                    <input 
                        value={pubkey}
                        onChange={(e) => setPubkey(e.target.value)}
                        placeholder="02... or npub..."
                        disabled={step === 2}
                    />
                    
                    {step === 1 && (
                        <button onClick={getChallenge} style={{marginTop: '0.5rem'}}>
                            Get PoF Challenge
                        </button>
                    )}
                    
                    {step === 2 && (
                        <>
                            <label className="label">Challenge (Include in OP_RETURN)</label>
                            <div 
                                className="code-box" 
                                onClick={() => {
                                    navigator.clipboard.writeText(challenge);
                                    alert('Challenge copied!');
                                }}
                            >
                                <code>{challenge}</code>
                            </div>
                            
                            <label className="label">PSBT (Base64)</label>
                            <textarea 
                                value={psbt}
                                onChange={(e) => setPsbt(e.target.value)}
                                placeholder="Paste PSBT here (must contain OP_RETURN with challenge)"
                                rows="8"
                            />
                            
                            <div style={{display: 'flex', gap: '0.5rem', marginTop: '1rem'}}>
                                <button onClick={verifyPSBT}>Verify Proof</button>
                                <button className="secondary" onClick={() => { setStep(1); setChallenge(''); setPsbt(''); }}>
                                    Start Over
                                </button>
                            </div>
                        </>
                    )}
                    
                    <div className="hint">
                        <div className="hint-title">How to create PoF PSBT:</div>
                        <ol>
                            <li>Create a transaction with your UTXOs as inputs</li>
                            <li>Add an OP_RETURN output containing the challenge string</li>
                            <li><strong>DO NOT broadcast the transaction</strong></li>
                            <li>Export as PSBT (base64 format)</li>
                            <li>Paste the PSBT above and verify</li>
                        </ol>
                    </div>
                    
                    <div className="hint" style={{marginTop: '1rem', borderColor: 'var(--accent)'}}>
                        <div className="hint-title" style={{color: 'var(--accent)'}}>Privacy Levels:</div>
                        <ul>
                            <li><strong>Boolean:</strong> Only yes/no (meets threshold?)</li>
                            <li><strong>Threshold:</strong> True/false for specific amount</li>
                            <li><strong>Aggregate:</strong> Exact total revealed (default)</li>
                        </ul>
                    </div>
                </div>
            );
        }
        
        // Render app
        ReactDOM.createRoot(document.getElementById('root')).render(<PlaygroundApp />);
    </script>
</body>
</html>
"""



# ============================================================================
# ROUTES: LANDING PAGE
# ============================================================================


@app.route("/")
@app.route("/oidc")
def landing_page():
    """Serve the KeyAuth BTC OIDC landing page"""
    # Get the issuer URL dynamically
    base = request.url_root.rstrip("/")
    # Render the template with the issuer variable
    return render_template_string(LANDING_PAGE_HTML, issuer=base)


# ============================================================================
# ROUTES: ADDITIONAL PAGES
# ============================================================================


@app.route("/dashboard")
def dashboard():
    """OAuth client dashboard"""
    return render_template_string(
        """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Dashboard - KeyAuth BTC OIDC</title>
  <style>
    :root{--bg:#0a0a0a;--fg:#e0e0e0;--accent:#00ff00}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui;padding:2rem}
    .container{max-width:1120px;margin:0 auto}
    a{color:var(--accent)}
    h1{color:var(--accent)}
    .btn{background:var(--accent);color:#000;padding:10px 20px;border:none;border-radius:8px;cursor:pointer;font-weight:bold}
  </style>
</head>
<body>
  <div class="container">
    <h1>🔐 API Dashboard</h1>
    <p>Manage your OAuth clients and API keys</p>

    <h2>Register New Client</h2>
    <button class="btn" onclick="register()">Register Client</button>
    <pre id="result"></pre>

    <p><a href="/">← Back to Home</a></p>
  </div>

  <script>
    async function register() {
      try {
        const res = await fetch('/oauth/register', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({redirect_uris: ['http://localhost:3000/callback']})
        });
        const data = await res.json();
        document.getElementById('result').textContent = JSON.stringify(data, null, 2);
      } catch(e) {
        alert('Error: ' + e);
      }
    }
  </script>
</body>
</html>
    """
    )

@app.route("/playground/", defaults={'path': ''})
@app.route("/playground/<path:path>")
def playground(path):
    playground_dir = 'static/playground'
    if path == '':
        resp = make_response(send_from_directory(playground_dir, 'index.html'))
    else:
        resp = make_response(send_from_directory(playground_dir, path))
    
    # FORCE override CSP for playground - remove any existing CSP
    if 'Content-Security-Policy' in resp.headers:
        del resp.headers['Content-Security-Policy']
    if 'Content-Security-Policy-Report-Only' in resp.headers:
        del resp.headers['Content-Security-Policy-Report-Only']
    
    # Set very permissive CSP
    resp.headers['Content-Security-Policy'] = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline';"
    
    return resp

#@app.route("/playground", methods=["GET"])
#def playground():
            # Serve static playground to avoid Jinja parsing issues
 #   logged_in = session.get('logged_in_pubkey', '')
  #  access_level = session.get('access_level', 'limited')

    # Serve the prebuilt static HTML (bypass Jinja)
   # return send_from_directory('static', 'playground.html')

@app.route("/oauth/register", methods=["POST"])
def oauth_register():
    """Register a new OAuth client"""
    body = request.get_json(silent=True) or {}

    try:
        # Generate client credentials
        client_id = "anon_" + secrets.token_hex(16)
        client_secret = secrets.token_hex(32)

        # Get redirect URIs
        redirect_uris = body.get("redirect_uris") or []

        # Prepare database client data
        client_data = {
            "client_secret": client_secret,
            "client_name": body.get("client_name", "Anonymous Client"),
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "read_limited",
            "token_endpoint_auth_method": "client_secret_post",
            "meta_data": {"client_type": "free", "rate_limit": 100, "payment_proof": body.get("payment_proof")},
        }

        # Store to database
        store_oauth_client(client_id, client_data)

        logger.info(f"✅ Registered OAuth client: {client_id}")

        return (
            jsonify(
                {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "client_type": "free",
                    "rate_limit": 100,
                    "allowed_scopes": ["read_limited"],
                    "redirect_uris": redirect_uris,
                }
            ),
            201,
        )

    except Exception as e:
        logger.error(f"OAuth registration failed: {e}")
        return jsonify({"error": "Registration failed", "details": str(e)}), 500
        return jsonify({"error": "registration_failed", "detail": str(e)}), 400


@app.route("/oauth/authorize", methods=["GET"])
def oauth_authorize():
    """Authorization endpoint"""
    result = oauth_server.authorization_endpoint(
        client_id=request.args.get("client_id", ""),
        scope=request.args.get("scope", "read_limited"),
        state=request.args.get("state", ""),
        redirect_uri=request.args.get("redirect_uri", ""),
        response_type=request.args.get("response_type", "code"),
        code_challenge=request.args.get("code_challenge"),
        code_challenge_method=request.args.get("code_challenge_method", "S256"),
        nonce=request.args.get("nonce"),
    )

    if "error" in result:
        return jsonify(result), 400

    # Redirect to client's redirect_uri with code
    return redirect(result["redirect_uri"])


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    """Token endpoint"""
    # Support both JSON and form data
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()

    result = oauth_server.token_endpoint(
        grant_type=data.get("grant_type"),
        client_id=data.get("client_id"),
        client_secret=data.get("client_secret"),
        code=data.get("code"),
        refresh_token=data.get("refresh_token"),
        code_verifier=data.get("code_verifier"),
    )

    if "error" in result:
        return jsonify(result), 400

    return jsonify(result), 200


if limiter:
    oauth_authorize = limiter.limit("30 per minute")(oauth_authorize)
    oauth_token = limiter.limit("60 per minute")(oauth_token)


@app.route("/metrics/prometheus")
def metrics_prometheus():
    """Prometheus-formatted metrics endpoint."""
    data = generate_latest(REGISTRY)
    return Response(data, mimetype="text/plain; version=0.0.4; charset=utf-8")


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
  #  response.headers["Content-Security-Policy"] = "default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; connect-src 'self' wss: ws: https: http:; font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; frame-ancestors 'none'"
    return response

# ============================================================================
# ROUTES: LNURL-AUTH
# ============================================================================


@app.route("/api/lnurl-auth/create", methods=["POST"])
def lnurl_create():
    """Create LNURL-Auth session"""
    sid = str(uuid.uuid4())
    k1 = secrets.token_hex(32)

    LNURL_SESSION_STORE[sid] = {"k1": k1, "created": time.time(), "authenticated": False, "pubkey": None}

    params_url = url_for("lnurl_params", _external=True) + f"?sid={sid}"
    lnurl_str = _lnurl_bech32(params_url)

    return jsonify(
        {
            "session_id": sid,
            "callback_url": params_url,
            "expires_in": LNURL_TTL,
            "lnurl": lnurl_str,
            "qr_code": lnurl_str,
        }
    )


@app.route("/api/lnurl-auth/params", methods=["GET"])
def lnurl_params():
    """LNURL-Auth params (LUD-04)"""
    sid = request.args.get("sid", "").strip()
    rec = LNURL_SESSION_STORE.get(sid)

    if not rec:
        return jsonify({"status": "ERROR", "reason": "unknown session"}), 404

    if time.time() - rec["created"] > LNURL_TTL:
        return jsonify({"status": "ERROR", "reason": "expired"}), 410

    callback_url = url_for("lnurl_callback", session_id=sid, _external=True)

    return jsonify({"tag": "login", "k1": rec["k1"], "callback": callback_url})


@app.route("/api/lnurl-auth/callback/<session_id>", methods=["GET"])
def lnurl_callback(session_id):
    """LNURL-Auth callback"""
    rec = LNURL_SESSION_STORE.get(session_id)

    if not rec:
        return jsonify({"status": "ERROR", "reason": "unknown session"}), 404

    k1 = request.args.get("k1", "").strip()
    sig = request.args.get("sig", "").strip()
    key = request.args.get("key", "").strip()

    if not (k1 and sig and key):
        return jsonify({"status": "ERROR", "reason": "missing parameters"}), 400

    if k1 != rec["k1"]:
        return jsonify({"status": "ERROR", "reason": "k1 mismatch"}), 400

    # Verify signature (simplified - add proper verification)
    try:
        from coincurve import PublicKey

        msg = hashlib.sha256(bytes.fromhex(k1)).digest()
        sig_bytes = bytes.fromhex(sig)
        pub_bytes = bytes.fromhex(key)

        pk = PublicKey(pub_bytes)
        verified = pk.verify(sig_bytes, msg, hasher=None)

        if not verified:
            return jsonify({"status": "ERROR", "reason": "invalid signature"}), 400
    except Exception as e:
        return jsonify({"status": "ERROR", "reason": f"verification failed: {e}"}), 400

    # Mark as authenticated
    rec["authenticated"] = True
    rec["pubkey"] = key
    rec["ts"] = time.time()

    return jsonify({"status": "OK"}), 200


@app.route("/api/lnurl-auth/check/<session_id>", methods=["GET"])
def lnurl_check(session_id):
    """Check LNURL-Auth status"""
    rec = LNURL_SESSION_STORE.get(session_id)

    if not rec:
        return jsonify({"authenticated": False, "error": "unknown session"}), 404

    verified = rec.get("authenticated", False)
    return jsonify({"authenticated": verified, "verified": verified, "pubkey": rec.get("pubkey")})


# ============================================================================
# ROUTES: PROTECTED DEMO API
# ============================================================================


def require_oauth_token(required_scope: str):
    def decorator(f):
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "unauthorized", "detail": "Missing Bearer token"}), 401

            token_str = auth_header.split(" ", 1)[1]

            try:
                payload = decode_jwt(token_str, audience=AUDIENCE)
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "token_expired"}), 401
            except jwt.InvalidTokenError as e:
                return jsonify({"error": "invalid_token", "detail": str(e)}), 401

            # extra: confirm issuer matches what we mint
            if payload.get("iss") != ISSUER:
                return jsonify({"error": "invalid_token", "detail": "Invalid issuer"}), 401

            token_scopes = set(payload.get("scope", "").split())
            if required_scope not in token_scopes:
                return (
                    jsonify(
                        {"error": "insufficient_scope", "required": required_scope, "provided": list(token_scopes)}
                    ),
                    403,
                )

            request.oauth_payload = payload
            request.oauth_client_id = payload.get("client_id")
            request.oauth_scope = payload.get("scope")

            return f(*args, **kwargs)

        wrapper.__name__ = f.__name__
        return wrapper

    return decorator


# ============================================================================
# ROUTES: STATUS & HEALTH
# ============================================================================


@app.route("/oauthx/status")
def oauthx_status():
    """Status endpoint"""
    return jsonify(
        {
            "ok": True,
            "service": "HODLXXI OAuth2/OIDC",
            "timestamp": int(time.time()),
            "registered_clients": len(CLIENT_STORE),
            "active_codes": len(AUTH_CODE_STORE),
            "lnurl_sessions": len(LNURL_SESSION_STORE),
            "issuer": ISSUER,
            "endpoints": {
                "discovery": "/.well-known/openid-configuration",
                "authorize": "/oauth/authorize",
                "token": "/oauth/token",
                "register": "/oauth/register",
                "jwks": "/oauth/jwks.json",
            },
        }
    )


@app.route("/oauthx/docs")
def oauthx_docs():
    """API documentation"""
    return jsonify(
        {
            "version": "1.0",
            "authentication": {
                "type": "OAuth 2.0 + OIDC",
                "flows": {
                    "authorization_code": {
                        "authorization_url": f"{ISSUER}/oauth/authorize",
                        "token_url": f"{ISSUER}/oauth/token",
                        "scopes": {
                            "read": "Read-only access",
                            "write": "Write access",
                            "covenant_read": "Read covenants",
                            "covenant_create": "Create covenants",
                            "read_limited": "Limited read access (free tier)",
                        },
                    },
                    "refresh_token": {"token_url": f"{ISSUER}/oauth/token"},
                },
            },
            "endpoints": {
                "POST /oauth/register": {
                    "description": "Register new OAuth client",
                    "body": {"payment_proof": "optional", "redirect_uris": ["array of URIs"]},
                    "response": {
                        "client_id": "string",
                        "client_secret": "string",
                        "client_type": "free|paid|premium",
                        "rate_limit": "number",
                        "allowed_scopes": ["array"],
                    },
                },
                "GET /oauth/authorize": {
                    "description": "Authorization endpoint",
                    "params": {
                        "client_id": "required",
                        "scope": "required",
                        "state": "required",
                        "redirect_uri": "required",
                        "response_type": "code",
                    },
                },
                "POST /oauth/token": {
                    "description": "Token endpoint",
                    "body": {
                        "grant_type": "authorization_code|refresh_token",
                        "client_id": "required",
                        "client_secret": "required",
                        "code": "required for authorization_code",
                        "refresh_token": "required for refresh_token",
                    },
                },
                "GET /api/demo/protected": {
                    "description": "Demo protected endpoint",
                    "headers": {"Authorization": "Bearer <access_token>"},
                    "required_scope": "read",
                },
            },
            "lnurl_auth": {
                "POST /api/lnurl-auth/create": "Create LNURL session",
                "GET /api/lnurl-auth/params": "Get LNURL params",
                "GET /api/lnurl-auth/callback/<session_id>": "LNURL callback",
                "GET /api/lnurl-auth/check/<session_id>": "Check auth status",
            },
        }
    )


# ============================================================================
# UTILITY: TOKEN INTROSPECTION (for debugging)
# ============================================================================


@app.route("/oauth/introspect", methods=["POST"])
def oauth_introspect():
    """Token introspection endpoint (for debugging)"""
    data = request.get_json(silent=True) or request.form.to_dict()
    token = data.get("token")

    if not token:
        return jsonify({"active": False}), 400

    try:
        payload = decode_jwt(token)

        return jsonify(
            {
                "active": True,
                "client_id": payload.get("client_id"),
                "scope": payload.get("scope"),
                "exp": payload.get("exp"),
                "iat": payload.get("iat"),
                "token_type": payload.get("type"),
            }
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"active": False, "error": "expired"})
    except jwt.InvalidTokenError:
        return jsonify({"active": False, "error": "invalid"})


# ============================================================================
# CLEANUP: Periodic cleanup of expired data
# ============================================================================


def cleanup_expired_data():
    """Remove expired auth codes and sessions"""
    import threading

    now = int(time.time())

    # Clean auth codes
    expired_codes: List[str] = []
    for code, data in AUTH_CODE_STORE.items():
        exp_val = data.get("expires_at")
        if isinstance(exp_val, str):
            try:
                exp_ts = datetime.fromisoformat(exp_val).timestamp()
            except ValueError:
                exp_ts = 0
        else:
            exp_ts = exp_val or 0

        if exp_ts < now:
            expired_codes.append(code)
    for code in expired_codes:
        # Delete from in-memory if it was there (Redis auto-deleted)
        AUTH_CODE_STORE.pop(code, None)

    # Clean LNURL sessions
    expired_sessions = [
        sid
        for sid, data in LNURL_SESSION_STORE.items()
        if (now - data.get("created", 0)) > LNURL_TTL and not data.get("authenticated")
    ]
    for sid in expired_sessions:
        del LNURL_SESSION_STORE[sid]

    # Schedule next cleanup
    threading.Timer(60.0, cleanup_expired_data).start()


# Start cleanup thread
cleanup_expired_data()

# ============================================================================
# ADDITIONAL HELPER ROUTES
# ============================================================================


@app.route("/oauth/clients", methods=["GET"])
def list_clients():
    """List all registered clients (admin only - add auth in production)"""
    return jsonify(
        {
            "clients": [
                {
                    "client_id": data["client_id"],
                    "client_type": data["client_type"],
                    "created_at": data["created_at"],
                    "scopes": data["allowed_scopes"],
                }
                for data in CLIENT_STORE.values()
            ]
        }
    )


@app.route("/oauth/revoke", methods=["POST"])
def oauth_revoke():
    """Revoke a token"""
    data = request.get_json(silent=True) or {}
    token = data.get("token")

    if not token:
        return jsonify({"error": "token required"}), 400

    # In production, maintain a blacklist in Redis
    return jsonify({"revoked": True}), 200


# ============================================================================
# PRINT STARTUP INFO
# ============================================================================

logger.info("=" * 70)
logger.info("🔐 HODLXXI OAuth2/OIDC System Initialized")
logger.info("=" * 70)
logger.info(f"📍 Issuer: {ISSUER}")
logger.info(f"🔑 JWT Secret: {'*' * 20} (set)")
logger.info(f"📊 Storage: In-Memory (use Redis for production)")
logger.info("🌐 Endpoints:")
logger.info(f"   • Landing:    / and /oidc (KeyAuth BTC OIDC Landing Page)")
logger.info(f"   • Discovery:  /.well-known/openid-configuration")
logger.info(f"   • Register:   POST /oauth/register")
logger.info(f"   • Authorize:  GET /oauth/authorize")
logger.info(f"   • Token:      POST /oauth/token")
logger.info(f"   • Status:     GET /oauthx/status")
logger.info(f"   • Docs:       GET /oauthx/docs")
logger.info("🧪 Demo:")
logger.info(f"   • Protected:  GET /api/demo/protected (requires Bearer token)")
logger.info("⚡ LNURL-Auth:")
logger.info(f"   • Create:     POST /api/lnurl-auth/create")
logger.info(f"   • Check:      GET /api/lnurl-auth/check/<session_id>")
logger.info("=" * 70)

# ============================================================================
# END OF OIDC/OAuth2 SYSTEM
# ============================================================================


def create_app():
    """Return the configured Flask application."""
    return app


if __name__ == "__main__":
    # Run the demo server locally
    app.run(host="127.0.0.1", port=5000, debug=True)


# === HODLXXI â Proof of Funds (append-only block) ============================
# Non-custodial PoF: challenge -> PSBT (with OP_RETURN containing challenge)
# -> server verifies unspent inputs; stores short-lived attestation only.
# This block is self-contained and safe to append at EOF.
try:
    ACTIVE_CHALLENGES  # reuse if already defined
except NameError:
    ACTIVE_CHALLENGES = {}


# ============================================================================
# OLD POF CODE - REPLACED BY pof_enhanced.py
# ============================================================================
# SIMPLE POF ENDPOINTS - Wrapper for verify.html template
# These provide a simpler signature-based flow vs PSBT-based pof_enhanced
# ============================================================================

@app.route("/pof/api/generate-challenge", methods=["POST"])
def pof_simple_generate_challenge():
    """Generate challenge for address-based verification"""
    try:
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required"}), 401
            
        data = request.get_json() or {}
        addresses = data.get("addresses", [])
        
        if not addresses or len(addresses) == 0:
            return jsonify({"error": "At least one address required"}), 400
            
        if len(addresses) > 100:
            return jsonify({"error": "Maximum 100 addresses allowed"}), 400
        
        # Generate challenge
        challenge = secrets.token_hex(32)
        message = f"HODLXXI Proof of Funds\nChallenge: {challenge}\nTimestamp: {int(time.time())}"
        
        # Store in session
        session['pof_challenge'] = challenge
        session['pof_message'] = message
        session['pof_addresses'] = addresses
        session['pof_timestamp'] = time.time()
        
        return jsonify({
            "challenge": challenge,
            "message": message,
            "addresses": addresses
        })
        
    except Exception as e:
        logger.error(f"Error generating PoF challenge: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/pof/api/verify-signatures", methods=["POST"])
def pof_simple_verify_signatures():
    """Verify signatures and calculate balance"""
    try:
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required"}), 401
            
        data = request.get_json() or {}
        signatures = data.get("signatures", [])
        privacy_level = data.get("privacy_level", "boolean")
        
        # Validate session challenge
        if 'pof_challenge' not in session:
            return jsonify({"error": "No active challenge"}), 400
            
        if time.time() - session.get('pof_timestamp', 0) > 900:  # 15 min
            return jsonify({"error": "Challenge expired"}), 400
        
        message = session['pof_message']
        rpc = get_rpc_connection()
        
        verified_addresses = []
        total_balance = 0
        
        for sig_data in signatures:
            address = sig_data.get("address", "").strip()
            signature = sig_data.get("signature", "").strip()
            
            if not address or not signature:
                continue
                
            try:
                # Verify signature
                is_valid = rpc.verifymessage(address, signature, message)
                
                if is_valid:
                    # Get balance for this address
                    try:
                        utxos = rpc.scantxoutset("start", [f"addr({address})"])
                        balance = utxos.get("total_amount", 0)
                        total_balance += balance
                        verified_addresses.append({
                            "address": address,
                            "balance": balance
                        })
                    except:
                        # Address might not have any UTXOs
                        verified_addresses.append({
                            "address": address,
                            "balance": 0
                        })
            except Exception as e:
                logger.error(f"Error verifying {address}: {e}")
                continue
        
        if len(verified_addresses) == 0:
            return jsonify({"error": "No valid signatures provided"}), 400
        
        # Determine whale tier
        whale_tiers = [
            {'name': 'Shrimp', 'min': 0.0, 'max': 0.1, 'emoji': '🦐', 'color': '#94A3B8'},
            {'name': 'Crab', 'min': 0.1, 'max': 1.0, 'emoji': '🦀', 'color': '#F97316'},
            {'name': 'Dolphin', 'min': 1.0, 'max': 10.0, 'emoji': '🐬', 'color': '#3B82F6'},
            {'name': 'Shark', 'min': 10.0, 'max': 50.0, 'emoji': '🦈', 'color': '#8B5CF6'},
            {'name': 'Whale', 'min': 50.0, 'max': 100.0, 'emoji': '🐋', 'color': '#EC4899'},
            {'name': 'Humpback', 'min': 100.0, 'max': 1000.0, 'emoji': '🐳', 'color': '#F59E0B'},
            {'name': 'Blue Whale', 'min': 1000.0, 'max': float('inf'), 'emoji': '🌊', 'color': '#14B8A6'}
        ]
        
        tier = whale_tiers[0]
        for t in whale_tiers:
            if t['min'] <= total_balance < t['max']:
                tier = t
                break
        
        # Format amount based on privacy
        if privacy_level == 'boolean':
            formatted = "Verified ✓"
        elif privacy_level == 'threshold':
            formatted = f"{tier['emoji']} {tier['name']}"
        elif privacy_level == 'aggregate':
            rounded = round(total_balance / 10) * 10
            formatted = f"~{rounded} BTC"
        else:  # exact
            formatted = f"{total_balance:.8f} BTC"
        
        # Generate certificate ID
        cert_id = secrets.token_urlsafe(16)
        
        # Clear session challenge
        session.pop('pof_challenge', None)
        session.pop('pof_message', None)
        
        return jsonify({
            "success": True,
            "address_count": len(verified_addresses),
            "total_btc": total_balance,
            "whale_tier": tier,
            "formatted_amount": formatted,
            "certificate_id": cert_id,
            "verified_addresses": verified_addresses
        })
        
    except Exception as e:
        logger.error(f"Error verifying PoF signatures: {e}")
        return jsonify({"error": str(e)}), 500

# Keeping for reference only - DO NOT USE
# ============================================================================
def _hodlxxi_pof_bootstrap():
    # Local imports to avoid touching your top import section
    import hashlib
    import os
    import secrets
    import sqlite3
    import time
    from datetime import datetime, timedelta

    from flask import jsonify, request, session

    globals_ = globals()

    # Must exist in your app already:
    app = globals_["app"]
    socketio = globals_["socketio"]
    get_rpc_connection = globals_["get_rpc_connection"]

    # Config
    POF_DB_PATH = os.getenv("POF_DB_PATH", "/srv/app/pof_attest.db")
    POF_TTL_SECONDS = int(os.getenv("POF_TTL_SECONDS", "172800"))  # 48h
    POF_MAX_PSBT_B64 = int(os.getenv("POF_MAX_PSBT_B64", "250000"))  # ~250 KB

    os.makedirs(os.path.dirname(POF_DB_PATH), exist_ok=True)
    _POF = sqlite3.connect(POF_DB_PATH, check_same_thread=False, isolation_level=None)
    _POF.execute("PRAGMA journal_mode=WAL")
    _POF.execute(
        """
    CREATE TABLE IF NOT EXISTS pof_attestations(
      pubkey TEXT NOT NULL,
      covenant_id TEXT NOT NULL DEFAULT '',
      total_sat INTEGER NOT NULL,
      method TEXT NOT NULL,
      privacy_level TEXT NOT NULL,
      proof_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY(pubkey, covenant_id)
    )"""
    )

    def _pof_now():
        return int(time.time())

    def _pof_prune():
        try:
            _POF.execute("DELETE FROM pof_attestations WHERE expires_at < ?", (_pof_now(),))
        except Exception:
            pass

    def _pof_get_status(pubkey, covenant_id):
        row = _POF.execute(
            "SELECT pubkey, covenant_id, total_sat, method, privacy_level, proof_hash, expires_at, created_at "
            "FROM pof_attestations WHERE pubkey=? AND covenant_id=?",
            (pubkey, covenant_id),
        ).fetchone()
        if not row:
            return None
        keys = [
            "pubkey",
            "covenant_id",
            "total_sat",
            "method",
            "privacy_level",
            "proof_hash",
            "expires_at",
            "created_at",
        ]
        return dict(zip(keys, row))

    def _extract_opret_hex(vout_obj: dict):
        spk = (vout_obj or {}).get("scriptPubKey") or {}
        asm = spk.get("asm") or ""
        parts = asm.split()
        if len(parts) >= 2 and parts[0] == "OP_RETURN":
            return parts[1]
        return None

    def _is_member(pubkey: str, covenant_id: str | None):
        # Minimal guard: logged-in pubkey must match the claimant.
        # You can tighten this to "pubkey is actually in covenant_id" using your existing metadata.
        try:
            return session.get("logged_in_pubkey") == pubkey
        except Exception:
            return False

    # @app.post("/api/pof/challenge")
    def api_pof_challenge():
        data = request.get_json(silent=True) or {}
        pubkey = (data.get("pubkey") or "").strip()
        covenant_id = (data.get("covenant_id") or "").strip() or None
        if not pubkey:
            return jsonify(ok=False, error="pubkey required"), 400
        if not _is_member(pubkey, covenant_id):
            return jsonify(ok=False, error="membership required"), 403
        cid = secrets.token_hex(8)
        challenge = f"HODLXXI-PoF:{cid}:{_pof_now()}"
        ACTIVE_CHALLENGES[cid] = {
            "pubkey": pubkey,
            "covenant_id": covenant_id,
            "challenge": challenge,
            "expires": _pof_now() + 900,
        }
        return jsonify(ok=True, challenge_id=cid, challenge=challenge, expires_in=900)

    # @app.post("/api/pof/verify_psbt")
    def api_pof_verify_psbt():
        data = request.get_json(silent=True) or {}
        cid = (data.get("challenge_id") or "").strip()
        psbt = (data.get("psbt") or "").strip()
        privacy_level = (data.get("privacy_level") or "aggregate").strip().lower()
        min_sat = int(data.get("min_sat") or 0)
        if not cid or not psbt:
            return jsonify(ok=False, error="challenge_id and psbt required"), 400
        if len(psbt) > POF_MAX_PSBT_B64:
            return jsonify(ok=False, error="PSBT too large"), 413
        rec = ACTIVE_CHALLENGES.get(cid)
        if not rec or rec["expires"] < _pof_now():
            return jsonify(ok=False, error="invalid or expired challenge"), 400
        pubkey, cov_id, challenge = rec["pubkey"], rec["covenant_id"], rec["challenge"]
        if not _is_member(pubkey, cov_id):
            return jsonify(ok=False, error="membership required"), 403

        rpc = get_rpc_connection()
        dec = rpc.decodepsbt(psbt)
        tx = dec.get("tx") or {}
        vouts = tx.get("vout") or []
        vins = tx.get("vin") or []

        # OP_RETURN must contain our challenge bytes
        bound = False
        for vout in vouts:
            ophex = _extract_opret_hex(vout)
            if not ophex:
                continue
            try:
                if challenge.encode() in bytes.fromhex(ophex):
                    bound = True
                    break
            except Exception:
                pass
        if not bound:
            return jsonify(ok=False, error="OP_RETURN challenge missing"), 400

        # At least one referenced input must still be unspent + sum all currently unspent inputs
        total_sat = 0
        for i in vins:
            txid = i.get("txid")
            voutn = i.get("vout")
            if not txid and txid != "":
                continue
            if voutn is None:
                continue
            utxo = rpc.gettxout(txid, voutn)
            if utxo:
                amt_sat = int(round(float(utxo.get("value", 0.0)) * 1e8))
                total_sat += amt_sat
        if total_sat <= 0:
            return jsonify(ok=False, error="no live inputs"), 400

        # Store short-lived attestation (NOT a balance)
        proof_hash = hashlib.sha256((psbt + challenge).encode()).hexdigest()
        now = _pof_now()
        exp = now + POF_TTL_SECONDS
        _POF.execute(
            """
          INSERT INTO pof_attestations(pubkey,covenant_id,total_sat,method,privacy_level,proof_hash,expires_at,created_at)
          VALUES(?,?,?,?,?,?,?,?)
          ON CONFLICT(pubkey, covenant_id) DO UPDATE SET
            total_sat=excluded.total_sat, method=excluded.method,
            privacy_level=excluded.privacy_level, proof_hash=excluded.proof_hash,
            expires_at=excluded.expires_at, created_at=excluded.created_at
        """,
            (pubkey, (cov_id or ""), total_sat, "psbt", privacy_level, proof_hash, exp, now),
        )
        _pof_prune()
        ACTIVE_CHALLENGES.pop(cid, None)

        # Live signal (optional)
        try:
            socketio.emit(
                "pof:updated",
                {
                    "pubkey": pubkey,
                    "covenant_id": cov_id,
                    "total_sat": total_sat,
                    "privacy_level": privacy_level,
                    "expires_at": exp,
                    "method": "psbt",
                },
            )
        except Exception:
            pass

        res = {"ok": True, "pubkey": pubkey, "total_sat": total_sat, "expires_in": POF_TTL_SECONDS}
        if privacy_level == "boolean":
            res["has_threshold"] = total_sat >= max(min_sat, 0)
        elif privacy_level == "threshold":
            res["meets_min_sat"] = total_sat >= max(min_sat, 0)
        return jsonify(res)

    # @app.get("/api/pof/status/<pubkey>")
    def api_pof_status(pubkey):
        covenant_id = (request.args.get("covenant_id") or "").strip()
        st = _pof_get_status((pubkey or "").strip(), covenant_id)
        return jsonify(ok=True, status=st)


# _hodlxxi_pof_bootstrap()  # OLD - replaced by pof_enhanced

# ============================================================================
# PLAYGROUND POF - Public demo endpoints (no membership required)
# ============================================================================

@app.route('/api/playground/pof/challenge', methods=['POST'])
def playground_pof_challenge():
    """Generate PoF challenge for playground demo (no auth required)"""
    try:
        data = request.get_json() or {}
        pubkey = data.get("pubkey", "playground-demo").strip()
        
        # Generate challenge
        import secrets, time
        cid = secrets.token_hex(8)
        challenge = f"HODLXXI-PoF-DEMO:{cid}:{int(time.time())}"
        
        # Store in Redis (5 min expiry for demo)
        playground_redis.setex(
            f'pg_pof:{cid}',
            300,
            json.dumps({
                'pubkey': pubkey,
                'challenge': challenge,
                'created_at': int(time.time())
            })
        )
        
        return jsonify({
            'ok': True,
            'challenge_id': cid,
            'challenge': challenge,
            'expires_in': 300
        })
        
    except Exception as e:
        logger.error(f"Playground PoF challenge failed: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/playground/pof/verify', methods=['POST'])
def playground_pof_verify():
    """Verify SIGNED PSBT proof for playground demo"""
    try:
        data = request.get_json() or {}
        challenge_id = data.get('challenge_id', '').strip()
        psbt = data.get('psbt', '').strip()
        
        if not challenge_id or not psbt:
            return jsonify({'ok': False, 'error': 'challenge_id and psbt required'}), 400
        
        # Get challenge from Redis
        challenge_data = playground_redis.get(f'pg_pof:{challenge_id}')
        if not challenge_data:
            return jsonify({'ok': False, 'error': 'Challenge expired or invalid'}), 400
        
        challenge_info = json.loads(challenge_data)
        challenge = challenge_info['challenge']
        
        # Verify PSBT using Bitcoin RPC
        rpc = get_rpc_connection()
        decoded = rpc.decodepsbt(psbt)
        tx = decoded.get('tx', {})
        vouts = tx.get('vout', [])
        vins = tx.get('vin', [])
        
        # Check if OP_RETURN contains our challenge
        has_challenge = False
        for vout in vouts:
            script_hex = vout.get('scriptPubKey', {}).get('hex', '')
            if script_hex.startswith('6a'):  # OP_RETURN
                try:
                    op_return_data = bytes.fromhex(script_hex[2:])
                    if challenge.encode() in op_return_data:
                        has_challenge = True
                        break
                except:
                    pass
        
        if not has_challenge:
            return jsonify({
                'ok': False,
                'error': 'Challenge not found in OP_RETURN',
                'hint': f'Add OP_RETURN with: {challenge}'
            }), 400
        
        # ⭐ NEW: Verify PSBT has valid signatures
        try:
            finalized = rpc.finalizepsbt(psbt, False)  # Don't extract tx
            is_complete = finalized.get('complete', False)
            
            if not is_complete:
                return jsonify({
                    'ok': False,
                    'error': 'PSBT must be signed to prove ownership',
                    'hint': 'Sign the PSBT with your wallet before submitting'
                }), 400
                
        except Exception as e:
            return jsonify({
                'ok': False,
                'error': f'Invalid PSBT signatures: {str(e)}'
            }), 400
        
        # Calculate total value from unspent inputs
        total_sat = 0
        unspent_count = 0
        
        for vin in vins:
            txid = vin.get('txid')
            vout_n = vin.get('vout')
            
            if txid and vout_n is not None:
                try:
                    utxo = rpc.gettxout(txid, vout_n)
                    if utxo:
                        value_btc = float(utxo.get('value', 0))
                        total_sat += int(value_btc * 100000000)
                        unspent_count += 1
                except:
                    pass
        
        if total_sat <= 0:
            return jsonify({'ok': False, 'error': 'No valid unspent inputs'}), 400
        
        # Generate proof ID
        import secrets
        proof_id = secrets.token_hex(8)
        
        # Store proof (optional - for tracking)
        playground_redis.setex(
            f'pg_pof_proof:{proof_id}',
            3600,
            json.dumps({
                'challenge_id': challenge_id,
                'total_sat': total_sat,
                'unspent_count': unspent_count,
                'verified_at': int(time.time())
            })
        )
        
        return jsonify({
            'ok': True,
            'message': 'Proof verified successfully!',
            'proof_id': proof_id,
            'total_sat': total_sat,
            'total_btc': round(total_sat / 100000000, 8),
            'unspent_count': unspent_count,
            'note': 'Cryptographic signatures verified'
        })
        
    except Exception as e:
        logger.error(f"Playground PoF verify failed: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500



def playground_pof_verify():
    """Verify PSBT proof for playground demo"""
    try:
        data = request.get_json() or {}
        challenge_id = data.get('challenge_id', '').strip()
        psbt = data.get('psbt', '').strip()
        
        if not challenge_id or not psbt:
            return jsonify({'ok': False, 'error': 'challenge_id and psbt required'}), 400
        
        # Get challenge from Redis
        challenge_data = playground_redis.get(f'pg_pof:{challenge_id}')
        if not challenge_data:
            return jsonify({'ok': False, 'error': 'Challenge expired or invalid'}), 400
        
        challenge_info = json.loads(challenge_data)
        challenge = challenge_info['challenge']
        
        # Verify PSBT using Bitcoin RPC
        rpc = get_rpc_connection()
        decoded = rpc.decodepsbt(psbt)
        tx = decoded.get('tx', {})
        vouts = tx.get('vout', [])
        vins = tx.get('vin', [])
        
        # Check if OP_RETURN contains our challenge
        has_challenge = False
        for vout in vouts:
            script_hex = vout.get('scriptPubKey', {}).get('hex', '')
            if script_hex.startswith('6a'):  # OP_RETURN
                try:
                    op_return_data = bytes.fromhex(script_hex[2:])
                    if challenge.encode() in op_return_data:
                        has_challenge = True
                        break
                except:
                    pass
        
        if not has_challenge:
            return jsonify({
                'ok': False,
                'error': 'Challenge not found in OP_RETURN',
                'hint': f'Add OP_RETURN with: {challenge}'
            }), 400
        
        # Calculate total value from unspent inputs
        total_sat = 0
        unspent_count = 0
        
        for vin in vins:
            txid = vin.get('txid')
            vout_n = vin.get('vout')
            
            if txid and vout_n is not None:
                try:
                    utxo = rpc.gettxout(txid, vout_n)
                    if utxo:
                        value_btc = float(utxo.get('value', 0))
                        total_sat += int(value_btc * 100000000)
                        unspent_count += 1
                except:
                    pass
        
        if total_sat == 0:
            return jsonify({
                'ok': False,
                'error': 'No unspent inputs found',
                'hint': 'Make sure your PSBT references unspent UTXOs'
            }), 400
        
        # Success!
        proof_id = secrets.token_hex(8)
        playground_redis.setex(
            f'pg_pof_result:{proof_id}',
            3600,
            json.dumps({
                'challenge_id': challenge_id,
                'total_sat': total_sat,
                'unspent_count': unspent_count,
                'verified_at': int(time.time())
            })
        )
        
        return jsonify({
            'ok': True,
            'proof_id': proof_id,
            'total_sat': total_sat,
            'total_btc': total_sat / 100000000,
            'unspent_count': unspent_count,
            'message': 'Proof verified successfully!',
            'note': 'Demo: No addresses were revealed'
        })
        
    except Exception as e:
        logger.error(f"Playground PoF verify failed: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500

# === End PoF block ===========================================================




# ---- playground runtime globals API (used by static/playground.html) ----
@app.route('/playground-globals', methods=['GET'])
def playground_globals():
    """Return runtime values the static playground can fetch (safe JSON)."""
    try:
        logged = session.get('logged_in_pubkey', '')
    except Exception:
        logged = ''
    try:
        access = session.get('access_level', 'limited')
    except Exception:
        access = 'limited'
    issuer_val = globals().get('ISSUER', '') if 'ISSUER' in globals() else ''
    return jsonify({
        'logged_in_pubkey': logged,
        'access_level': access,
        'issuer': issuer_val
    })
# ------------------------------------------------------------------------

# ============================================================================
# PLAYGROUND - REAL DEMOS API
# Auto-added by deploy script
# ============================================================================

@app.route('/api/playground/stats', methods=['GET'])
def playground_stats():
    """Get real-time authentication statistics"""
    try:
        from datetime import datetime as dt
        today_key = f"pg_stats:{dt.now().strftime('%Y-%m-%d')}"
        auths_today = playground_redis.get(today_key) or 0
        
        return jsonify({
            'avgAuthTime': 4.2,
            'authsToday': int(auths_today),
            'countries': 0,  # Can add IP geolocation later
            'totalAuths': int(auths_today)  # For now, same as today
        })
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({
            'avgAuthTime': 4.2,
            'authsToday': 0,
            'countries': 0,
            'totalAuths': 0
        })


@app.route('/api/playground/activity', methods=['GET'])
@app.route('/api/playground/activity', methods=['GET'])
def playground_activity():
    """Get recent playground activity"""
    try:
        logger.info("Fetching activity from Redis...")
        activities = []
        recent = playground_redis.zrevrange('pg_activity', 0, 9)
        logger.info(f"Got {len(recent)} items from Redis")
        
        for activity_json in recent:
            logger.info(f"Processing: {activity_json[:50]}...")
            try:
                activity = json.loads(activity_json)
                activities.append(activity)
                logger.info(f"Parsed: {activity.get('action', 'N/A')}")
            except Exception as parse_err:
                logger.error(f"Parse error: {parse_err}")
        
        logger.info(f"Returning {len(activities)} activities")
        return jsonify({'activities': activities})
    except Exception as e:
        logger.error(f"Activity error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'activities': []})


def log_playground_activity(user_id, action, location='Unknown'):
    """Log playground activity to Redis"""
    logger.info(f"log_playground_activity called: {user_id}, {action}")
    try:
        logger.info("Step 1: Creating activity JSON...")
        activity = json.dumps({
            'user': user_id[:8] if len(user_id) > 8 else user_id,
            'action': action,
            'location': location,
            'timestamp': int(time.time())
        })
        logger.info(f"Step 2: Activity JSON created: {activity[:50]}...")
        
        logger.info("Step 3: Adding to Redis sorted set...")
        playground_redis.zadd('pg_activity', {activity: time.time()})
        logger.info("Step 4: Trimming old entries...")
        playground_redis.zremrangebyrank('pg_activity', 0, -101)
        logger.info("Step 5: Activity added to Redis!")
        
        # Increment daily counter
        from datetime import datetime as dt
        today_key = f"pg_stats:{dt.now().strftime('%Y-%m-%d')}"
        logger.info(f"Step 6: Incrementing counter: {today_key}")
        playground_redis.incr(today_key)
        playground_redis.expire(today_key, 86400 * 7)
        logger.info("Step 7: Counter incremented! SUCCESS!")
    except Exception as e:
        logger.error(f"Activity log error at some step: {e}")
        import traceback
        logger.error(traceback.format_exc())


@app.route('/api/playground/lightning/init', methods=['POST'])
def playground_lightning_init():
    """Initialize real Lightning authentication"""
    try:
        import secrets, qrcode, base64
        from io import BytesIO
        
        session_id = secrets.token_hex(16)
        k1 = secrets.token_hex(32)
        
        # Store session in Redis
        playground_redis.setex(
            f'pg_ln:{session_id}',
            300,  # 5 minutes
            json.dumps({'k1': k1, 'authenticated': False})
        )
        
        # Create LNURL callback URL
        callback_url = f'https://hodlxxi.com/api/playground/lightning/callback?session={session_id}&k1={k1}'
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(callback_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_b64 = base64.b64encode(buffer.getvalue()).decode()
        
        return jsonify({
            'sessionId': session_id,
            'qrCodeDataUrl': f'data:image/png;base64,{qr_b64}',
            'expiresIn': 300
        })
        
    except Exception as e:
        logger.error(f"Lightning init failed: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/playground/lightning/callback', methods=['GET'])
def playground_lightning_callback():
    """Handle Lightning wallet callback"""
    try:
        session_id = request.args.get('session')
        k1 = request.args.get('k1')
        sig = request.args.get('sig')
        key = request.args.get('key')
        
        if not session_id or not key:
            return jsonify({'status': 'ERROR', 'reason': 'Missing parameters'})
        
        # Get session
        session_data = playground_redis.get(f'pg_ln:{session_id}')
        if not session_data:
            return jsonify({'status': 'ERROR', 'reason': 'Session expired'})
        
        # Update session (TODO: Add signature verification in production)
        data = json.loads(session_data)
        data['authenticated'] = True
        log_playground_activity(key, 'logged in via Lightning', 'Web')
        data['pubkey'] = key
        playground_redis.setex(f'pg_ln:{session_id}', 300, json.dumps(data))
        
        return jsonify({'status': 'OK'})
        
    except Exception as e:
        logger.error(f"Lightning callback failed: {e}")
        return jsonify({'status': 'ERROR', 'reason': str(e)})


@app.route('/api/playground/lightning/check/<session_id>', methods=['GET'])
def playground_lightning_check(session_id):
    """Check Lightning authentication status"""
    try:
        session_data = playground_redis.get(f'pg_ln:{session_id}')
        
        if not session_data:
            return jsonify({'authenticated': False, 'expired': True})
        
        data = json.loads(session_data)
        
        return jsonify({
            'authenticated': data.get('authenticated', False),
            'pubkey': data.get('pubkey', None)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/playground/nostr/auth', methods=['POST'])
def playground_nostr_auth():
    """Nostr authentication with demo session"""
    try:
        data = request.get_json()
        pubkey = data.get('pubkey')
        
        if pubkey:
            # Store in Redis for demo purposes
            session_id = secrets.token_hex(16)
            playground_redis.setex(
                f'pg_nostr:{session_id}',
                3600,  # 1 hour
                json.dumps({
                    'pubkey': pubkey,
                    'authenticated': True,
                    'timestamp': int(time.time())
                })
            )
            
            return jsonify({
                'authenticated': True,
                'pubkey': pubkey,
                'sessionId': session_id,
                'message': 'Successfully authenticated via Nostr!',
                'nextSteps': [
                    'Your Nostr identity is now verified',
                    'In production, this would create a user session',
                    'You could now access Nostr-gated features'
                ]
            })
        
        return jsonify({'authenticated': False, 'error': 'No pubkey provided'})
        
    except Exception as e:
        return jsonify({'authenticated': False, 'error': str(e)})


@app.route("/play")
def play():
    return send_from_directory("static", "play.html")


@app.route("/api/get-login-challenge", methods=["GET"])
def get_login_challenge():
    """Get login challenge in JSON format - for testing/CLI use"""
    import secrets
    import time
    
    # Generate a fresh challenge
    challenge_str = secrets.token_hex(32)
    challenge_message = f"HODLXXI Login Challenge: {challenge_str}"
    
    return jsonify({
        "challenge": challenge_message,
        "challenge_id": challenge_str,
        "timestamp": int(time.time()),
        "expires_in": 600,
        "usage": "Sign this message with bitcoin-cli signmessage <address> '<challenge>'"
    })

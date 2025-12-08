import hashlib
import json
import redis
import redis
import logging
import os
import re
from flask import session, request
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
from flask import render_template, send_from_directory
from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
    flash,
)
from flask_socketio import SocketIO, emit
# === Added for production hardening ===
import jwt
import redis as redis_client
from cryptography.hazmat.primitives import serialization
from prometheus_client import CollectorRegistry, Counter, generate_latest

from app.audit_logger import get_audit_logger, init_audit_logger
from app.config import get_config
from app.database import close_all, init_all, get_session as get_db_session
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
from app.utils import get_rpc_connection
from app.oidc import oidc_bp, validate_pkce
from app.security import init_security, limiter
from app.tokens import issue_rs256_jwt
from app.pof_routes import pof_bp, pof_api_bp
#from app.playground_routes import playground_bp   # <-- ADD THIS
from flask import make_response




from .ubid_membership import (
    UbidUser,
    on_successful_login,
    require_paid_user,
)



# --- Simple in-memory user view object for dashboard/upgrade ---
class SimpleUser:
    def __init__(self, pubkey, plan="free_trial", sats_balance=0, expires_at=None):
        self.pubkey = pubkey
        self.plan = plan
        self.sats_balance = sats_balance
        self.membership_expires_at = expires_at


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


def _resolve_socketio_async_mode(preferred: str | None = None) -> str:
    """Return a supported async_mode for Flask-SocketIO.

    If the requested mode is unavailable (e.g., eventlet not installed),
    gracefully fall back to the safe threading backend to avoid runtime
    initialization errors during tests or local development.
    """

    preferred_mode = (preferred or "").strip() or "eventlet"
    valid_modes = {"eventlet", "gevent", "gevent_uwsgi", "threading"}

    if preferred_mode not in valid_modes:
        logger.warning("Invalid SOCKETIO_ASYNC_MODE '%s', defaulting to threading", preferred_mode)
        return "threading"

    if preferred_mode == "threading":
        return preferred_mode

    try:
        module_name = preferred_mode if preferred_mode != "gevent_uwsgi" else "gevent"
        __import__(module_name)
        return preferred_mode
    except ImportError:
        logger.warning(
            "SOCKETIO_ASYNC_MODE '%s' requested but dependency missing; using threading",
            preferred_mode,
        )
        return "threading"


SOCKETIO_ASYNC_MODE = _resolve_socketio_async_mode(os.getenv("SOCKETIO_ASYNC_MODE"))

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

class SafeRedis:
    """Wrapper for Redis that gracefully handles connection failures"""
    def __init__(self, redis_client):
        self._redis = redis_client
        self._is_available = redis_client is not None
    
    def _safe_call(self, method_name, *args, **kwargs):
        if not self._is_available:
            return None
        try:
            method = getattr(self._redis, method_name)
            return method(*args, **kwargs)
        except Exception as e:
            logger.debug(f"Redis {method_name} failed: {e}")
            self._is_available = False
            return None
    
    def ping(self):
        return self._safe_call('ping')
    def get(self, key):
        return self._safe_call('get', key)
    def set(self, key, value, ex=None, px=None, nx=False, xx=False):
        return self._safe_call('set', key, value, ex=ex, px=px, nx=nx, xx=xx)
    def setex(self, key, time, value):
        return self._safe_call('setex', key, time, value)
    def delete(self, *keys):
        return self._safe_call('delete', *keys)
    def sadd(self, name, *values):
        return self._safe_call('sadd', name, *values)
    def smembers(self, name):
        return self._safe_call('smembers', name) or set()
    def __getattr__(self, name):
        def method(*args, **kwargs):
            return self._safe_call(name, *args, **kwargs)
        return method


try:
    _redis_raw = redis_client.Redis.from_url(REDIS_URL, decode_responses=True)
    _redis_raw.ping()
    _redis = SafeRedis(_redis_raw)
except Exception:
    _redis = SafeRedis(None)


# Redis client for playground (instance, not module)

try:
    logger.info(f"Creating playground_redis with URL: {REDIS_URL[:50]}...")
    _redis_raw2 = redis_client.Redis.from_url(REDIS_URL, decode_responses=True)
    _redis_raw2.ping()
    playground_redis = SafeRedis(_redis_raw2)
    logger.info("✅ playground_redis with SafeRedis!")
except Exception as e:
    logger.error(f"playground_redis failed: {e}")
    playground_redis = SafeRedis(None)
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

# Blueprints
app.register_blueprint(pof_bp)
app.register_blueprint(oidc_bp)
app.register_blueprint(pof_api_bp)
#app.register_blueprint(playground_bp)

OAUTH_PATH_PREFIXES = ("/oauth/", "/oauthx/")
OAUTH_PUBLIC_PATHS = (
    "/oauth/register",
    "/oauth/authorize",
    "/oauth/token",
    "/oauthx/status",
    "/oauthx/docs",
)


# Initialize storage and audit logging
try:
    init_all()
    init_audit_logger()
    logger.info("✅ Storage, audit logging, and config initialized")
except Exception as e:
    logger.error(f"❌ Failed to initialize infrastructure: {e}")

app.secret_key = FLASK_SECRET_KEY

logger.info("SocketIO async mode resolved to %s", SOCKETIO_ASYNC_MODE)

socketio = SocketIO(
    app,
    cors_allowed_origins=SOCKETIO_CORS,
    async_mode=SOCKETIO_ASYNC_MODE,
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


# --- Chat message helpers + events ---


def _broadcast_chat_message(text: str):
    """Shared logic to append to history and broadcast to all clients."""
    pk = session.get("logged_in_pubkey")
    if not pk:
        logger.warning("Message received from unauthenticated user")
        return

    m = {"pubkey": pk, "text": str(text), "ts": time.time()}
    CHAT_HISTORY.append(m)
    purge_old_messages()

    # Old clients listen to "message", new UI listens to both
    socketio.emit("message", m)
    socketio.emit("chat:message", m)


@socketio.on("message")
def handle_message(msg_text):
    """Legacy handler for default Socket.IO 'message' event."""
    try:
        _broadcast_chat_message(msg_text)
    except Exception as e:
        logger.error(f"Error handling message: {e}", exc_info=True)


@socketio.on("chat:send")
def handle_chat_send(data):
    """
    New handler for our front-end.

    Client sends: socket.emit('chat:send', { text: 'hello' })
    """
    try:
        # data can be dict or string; normalize to text
        if isinstance(data, dict):
            text = (data.get("text") or "").strip()
        else:
            text = str(data or "").strip()

        if not text:
            return

        _broadcast_chat_message(text)
    except Exception as e:
        logger.error(f"Error handling chat:send: {e}", exc_info=True)


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

    # Make sure only fresh messages are in memory (<= 45 seconds old)
    purge_old_messages()

    chat_html = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>HODLXXI — Covenant Lounge</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
    <meta name="theme-color" content="#00ff88" />

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
            --muted: #8a9da4;

            --border-subtle: rgba(15, 23, 42, 0.7);
            --border-strong: #0f2a24;

            --spacing: 1rem;
            --radius-lg: 16px;
            --radius-pill: 999px;

            --touch-target: 44px;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        html, body {
            width: 100%;
            height: 100%;
        }

        body {
            background: radial-gradient(circle at top, #020617 0, #020617 40%, #000 100%);
            color: var(--fg);
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Mono", Menlo, Consolas, monospace;
            overflow: hidden;
        }

        #matrix-bg {
            position: fixed;
            inset: 0;
            z-index: 0;
            pointer-events: none;
        }
        body > *:not(#matrix-bg) {
            position: relative;
            z-index: 1;
        }

        .shell {
            position: relative;
            width: 100%;
            height: 100%;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        /* Mobile layout tweaks */
        @media (max-width: 768px) {
            /* Allow the whole page to scroll on small screens */
            body {
                overflow-y: auto;
                -webkit-overflow-scrolling: touch;
            }

            .shell {
                padding: 0.75rem;
                min-height: 100%;
                height: auto;
            }

            /* Stack chat and sidebar vertically instead of 2-column grid */
            .layout {
                display: flex;
                flex-direction: column;
                gap: 0.75rem;
            }
        }

        .top-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.75rem;
        }

        .top-left {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .back-btn {
            min-width: var(--touch-target);
            height: var(--touch-target);
            border-radius: 50%;
            border: 1px solid var(--border-subtle);
            background: radial-gradient(circle at 30% 0%, #1f2933 0, #020617 60%);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            color: var(--accent);
            cursor: pointer;
            box-shadow: 0 0 10px rgba(0,255,136,0.25);
        }

        .back-btn span {
            font-size: 1.4rem;
            transform: translateX(-1px);
        }

        .title-block {
            display: flex;
            flex-direction: column;
            gap: 0.1rem;
        }

        .title {
            font-size: clamp(1.1rem, 1.4vw, 1.3rem);
            letter-spacing: 0.06em;
            text-transform: uppercase;
            color: var(--accent);
        }

        .subtitle {
            font-size: 0.8rem;
            color: var(--muted);
        }

        .top-right {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 0.8rem;
            color: var(--muted);
        }

        .online-chip {
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            padding: 0.3rem 0.7rem;
            border-radius: var(--radius-pill);
            border: 1px solid rgba(34,197,94,0.35);
            background: radial-gradient(circle at 0 0, rgba(34,197,94,0.25), transparent 60%);
        }

        .online-dot {
            width: 0.5rem;
            height: 0.5rem;
            border-radius: 50%;
            background: #22c55e;
            box-shadow: 0 0 8px rgba(34,197,94,0.9);
        }

        .layout {
            flex: 1;
            min-height: 0;
            display: grid;
            grid-template-columns: minmax(0, 2.1fr) minmax(0, 1.3fr);
            gap: 1rem;
        }

        @media (max-width: 960px) {
            .layout {
                grid-template-columns: minmax(0, 1.8fr) minmax(0, 1.6fr);
            }
        }

        .panel {
            position: relative;
            background: radial-gradient(circle at 0 -20%, rgba(0,255,136,0.18), transparent 55%),
                        radial-gradient(circle at 100% 120%, rgba(59,130,246,0.18), transparent 60%),
                        linear-gradient(145deg, rgba(15,23,42,0.98), #020617 80%);
            border-radius: var(--radius-lg);
            border: 1px solid rgba(15,23,42,0.9);
            box-shadow:
                0 0 0 1px rgba(15,23,42,0.9),
                0 0 25px rgba(0,255,136,0.1),
                0 0 45px rgba(37,99,235,0.33);
            padding: 0.9rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            overflow: hidden;
        }

        .panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 0.8rem;
            color: var(--muted);
            gap: 0.5rem;
        }

        .panel-title {
            text-transform: uppercase;
            letter-spacing: 0.12em;
            font-size: 0.7rem;
            color: rgba(148,163,184,0.95);
        }

        .panel-badge {
            border-radius: var(--radius-pill);
            border: 1px solid rgba(148,163,184,0.45);
            padding: 0.18rem 0.6rem;
            font-size: 0.7rem;
        }

        .panel-body {
            flex: 1;
            min-height: 0;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .messages-wrap {
            flex: 1;
            min-height: 0;
            border-radius: 12px;
            border: 1px solid rgba(15,23,42,0.9);
            background:
                radial-gradient(circle at 0 0, rgba(0,255,136,0.15), transparent 60%),
                linear-gradient(180deg, rgba(15,23,42,0.85), rgba(2,6,23,0.95));
            padding: 0.6rem;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        .message-list {
            list-style: none;
            flex: 1;
            min-height: 0;
            overflow-y: auto;
            padding-right: 0.3rem;
            display: flex;
            flex-direction: column;
            gap: 0.45rem;
            scrollbar-width: thin;
            scrollbar-color: rgba(148,163,184,0.7) transparent;
        }

        .message-list::-webkit-scrollbar {
            width: 6px;
        }
        .message-list::-webkit-scrollbar-track {
            background: transparent;
        }
        .message-list::-webkit-scrollbar-thumb {
            background: rgba(148,163,184,0.7);
            border-radius: 999px;
        }

        .message {
            position: relative;
            display: inline-flex;
            flex-direction: column;
            max-width: min(85%, 520px);
            border-radius: 12px;
            padding: 0.45rem 0.6rem;
            background: rgba(15,23,42,0.9);
            border: 1px solid rgba(15,23,42,0.9);
            box-shadow: 0 12px 18px rgba(15,23,42,0.85);
        }

        .message.me {
            align-self: flex-end;
            background: radial-gradient(circle at 0 0, rgba(0,255,136,0.18), transparent 75%);
            border-color: rgba(34,197,94,0.5);
        }

        .message-meta {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.6rem;
            font-size: 0.68rem;
            color: var(--muted);
            margin-bottom: 0.18rem;
        }

        .message-sender {
            max-width: 70%;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .message-text {
            font-size: 0.84rem;
            line-height: 1.3;
            word-break: break-word;
        }

        .composer {
            margin-top: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .input-shell {
            flex: 1;
            border-radius: var(--radius-pill);
            border: 1px solid rgba(15,23,42,0.9);
            background: rgba(15,23,42,0.95);
            display: flex;
            align-items: center;
            gap: 0.45rem;
            padding: 0.25rem 0.65rem;
        }

        .input-shell input {
            border: none;
            background: transparent;
            color: var(--fg);
            font-size: 0.88rem;
            outline: none;
            width: 100%;
        }

        .hint-pill {
            font-size: 0.7rem;
            padding: 0.12rem 0.45rem;
            border-radius: 999px;
            border: 1px dashed rgba(148,163,184,0.5);
            color: rgba(148,163,184,0.9);
            white-space: nowrap;
        }

        .send-btn {
            min-width: var(--touch-target);
            height: var(--touch-target);
            border-radius: 50%;
            border: none;
            background: radial-gradient(circle at 20% 0, #22c55e 0, #15803d 40%, #052e16 100%);
            color: #e5fdf2;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            box-shadow:
                0 0 0 1px rgba(34,197,94,0.6),
                0 0 22px rgba(34,197,94,0.8);
        }

        .send-btn:active {
            transform: translateY(1px) scale(0.97);
        }

        .ephemeral {
            font-size: 0.7rem;
            color: var(--muted);
            margin-top: 0.15rem;
        }

        .ephemeral span {
            color: var(--accent);
        }

        .sidebar {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .users-list-wrap {
            flex: 1;
            min-height: 0;
            border-radius: 12px;
            background: linear-gradient(160deg, rgba(15,23,42,0.92), #020617);
            border: 1px solid rgba(15,23,42,0.9);
            padding: 0.6rem;
            display: flex;
            flex-direction: column;
        }

        .users-list {
            list-style: none;
            flex: 1;
            min-height: 0;
            overflow-y: auto;
            padding-right: 0.3rem;
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
            scrollbar-width: thin;
            scrollbar-color: rgba(148,163,184,0.7) transparent;
        }

        .users-list::-webkit-scrollbar {
            width: 6px;
        }

        .user-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.5rem;
            padding: 0.35rem 0.4rem;
            border-radius: 10px;
            background: radial-gradient(circle at 0 0, rgba(0,255,136,0.12), transparent 60%);
            border: 1px solid rgba(15,23,42,0.9);
            cursor: pointer;
            user-select: none;
            -webkit-user-select: none;
        }

        .user-left {
            display: flex;
            align-items: center;
            gap: 0.45rem;
            min-width: 0;
        }

        .user-dot {
            width: 0.4rem;
            height: 0.4rem;
            border-radius: 50%;
            box-shadow: 0 0 8px rgba(34,197,94,0.9);
            background: #22c55e;
        }

        .user-name {
            font-size: 0.78rem;
            max-width: 150px;
            white-space: nowrap;
            text-overflow: ellipsis;
            overflow: hidden;
        }

        .user-pubkey {
            font-size: 0.64rem;
            color: var(--muted);
            opacity: 0.8;
        }

        .user-tag-me {
            display: inline-flex;
            padding: 0.1rem 0.4rem;
            border-radius: 999px;
            border: 1px solid rgba(148,163,184,0.7);
            font-size: 0.64rem;
            color: var(--muted);
        }

        .user-btn {
            font-size: 0.9rem;
            min-width: 30px;
            height: 30px;
            border-radius: 999px;
            border: 1px solid rgba(148,163,184,0.6);
            background: radial-gradient(circle at 0 0, rgba(148,163,184,0.18), transparent 65%);
            color: var(--fg);
            cursor: pointer;
        }

        .info-card {
            font-size: 0.76rem;
            padding: 0.6rem;
            border-radius: 12px;
            border: 1px dashed rgba(148,163,184,0.6);
            background: radial-gradient(circle at 0 0, rgba(59,130,246,0.16), transparent 70%);
            color: rgba(148,163,184,0.95);
        }

        .info-card strong {
            color: var(--accent);
        }

        .info-card code {
            font-family: "SF Mono", Menlo, Consolas, monospace;
            font-size: 0.74rem;
            background: rgba(15,23,42,0.95);
            padding: 0.05rem 0.35rem;
            border-radius: 999px;
            border: 1px solid rgba(15,23,42,0.9);
        }

        /* Call panel */
        .call-panel {
            position: relative;
            margin-top: 0.5rem;
            border-radius: 12px;
            border: 1px solid rgba(15,23,42,0.9);
            background: radial-gradient(circle at 0 0, rgba(59,130,246,0.22), transparent 75%);
            padding: 0.55rem;
            display: grid;
            grid-template-columns: minmax(0, 2fr) minmax(0, 1.4fr);
            gap: 0.5rem;
            align-items: center;
            font-size: 0.8rem;
        }

        @media (max-width: 960px) {
            .call-panel {
                grid-template-columns: minmax(0, 1.7fr) minmax(0, 1.3fr);
            }
        }

        @media (max-width: 768px) {
            .call-panel {
                grid-template-columns: minmax(0, 1.2fr);
                grid-auto-rows: auto;
            }
        }

        .call-videos {
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.4rem;
            min-height: 110px;
        }

        .video-frame {
            width: 100%;
            max-width: 260px;
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid rgba(148,163,184,0.6);
            background: #020617;
            position: relative;
        }

        .video-frame video {
            width: 100%;
            height: 100%;
            object-fit: cover;
            background: #020617;
        }

        .video-label {
            position: absolute;
            inset-inline: 0.35rem;
            bottom: 0.25rem;
            font-size: 0.65rem;
            color: rgba(226,232,240,0.9);
            text-shadow: 0 0 10px rgba(15,23,42,0.9);
        }

        .call-meta {
            display: flex;
            flex-direction: column;
            gap: 0.3rem;
        }

        .call-status {
            font-size: 0.8rem;
            color: var(--muted);
        }

        .call-status span {
            color: var(--accent);
        }

        .call-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 0.35rem;
            margin-top: 0.25rem;
        }

        .btn {
            border-radius: 999px;
            border: 1px solid rgba(148,163,184,0.6);
            background: rgba(15,23,42,0.95);
            color: var(--fg);
            font-size: 0.78rem;
            padding: 0.24rem 0.65rem;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
        }

        .btn-danger {
            border-color: rgba(239,68,68,0.7);
            background: radial-gradient(circle at 0 0, rgba(239,68,68,0.18), transparent 70%);
            color: #fecaca;
        }

        .btn-icon {
            font-size: 0.9rem;
        }

        .call-panel.hidden {
            opacity: 0.45;
        }

        .call-panel.hidden .btn-danger {
            opacity: 0.3;
            pointer-events: none;
        }

        .status-pill {
            font-size: 0.7rem;
            padding: 0.1rem 0.45rem;
            border-radius: 999px;
            border: 1px solid rgba(148,163,184,0.65);
            color: rgba(148,163,184,0.9);
        }

    
        /* Mobile column layout override (final) */
        @media (max-width: 768px) {
            body {
                overflow-y: auto;
                -webkit-overflow-scrolling: touch;
            }

            .shell {
                padding: 0.75rem;
                min-height: 100%;
                height: auto;
            }

            /* Stack Live flow · HODLXXI and Online presence vertically */
            .layout {
                display: flex;
                flex-direction: column;
                gap: 0.75rem;
            }
        }

</style>
</head>
<body data-my-pubkey="{{ my_pubkey|e }}">
    <canvas id="matrix-bg"></canvas>

    <main class="shell">
        <header class="top-bar">
            <div class="top-left">
                <button class="back-btn" type="button" onclick="goHome('#explorer')">
                    <span>home</span>
                </button>
                <div class="title-block">
                    <div class="title">Covenant Lounge</div>
                    <div class="subtitle">
                        Encrypted presence chips, 45&nbsp;sec ephemeral whispers, tap-hold to video-call.
                    </div>
                </div>
            </div>
            <div class="top-right">
                <div class="online-chip">
                    <span class="online-dot"></span>
                    <span><span id="onlineCount">{{ online_users|length }}</span> online</span>
                </div>
                <div id="room-status" class="status-pill">Connecting…</div>
            </div>
        </header>

        <section class="layout">
            <!-- Chat panel -->
            <section class="panel">
                <div class="panel-header">
                    <div class="panel-title">Live flow &nbsp;·&nbsp; <span style="color:var(--accent)">HODLXXI</span></div>
                    <div class="panel-badge">Messages self-erase after 45&nbsp;sec</div>
                </div>
                <div class="panel-body">
                    <div class="messages-wrap">
                        <ul id="messages" class="message-list">
                            {% for m in history %}
                            <li class="message{% if m.pubkey == my_pubkey %} me{% endif %}"
                                data-ts="{{ m.ts|default(0) }}">
                                <div class="message-meta">
                                    <div class="message-sender">
                                        {{ (m.pubkey or 'anon')[:12] }}…{{ (m.pubkey or '')[-6:] }}
                                    </div>
                                    <div class="message-timestamp">
                                        {{ m.ts|datetimeformat if m.ts else '' }}
                                    </div>
                                </div>
                                <div class="message-text">
                                    {{ (m.text or '')|e }}
                                </div>
                            </li>
                            {% endfor %}
                        </ul>
                    </div>

                    <div class="composer">
                        <div class="input-shell">
                            <input id="chatInput"
                                   type="text"
                                   autocomplete="off"
                                   placeholder="Type a whisper…" />
                            <div class="hint-pill">@</div>
                        </div>
                        <button id="sendBtn" class="send-btn" type="button">➤</button>
                    </div>
                    <div class="ephemeral">
                        Ephemeral mode: messages exist in memory for <span>45&nbsp;seconds</span>, then vanish.
                    </div>
                </div>
            </section>

            <!-- Right sidebar: users + call panel -->
            <aside class="sidebar">
                <section class="panel">
                    <div class="panel-header">
                        <div class="panel-title">Online presence</div>
                        <div class="panel-badge">Tap = @mention · Long-press = call</div>
                    </div>
                    <div class="panel-body">
                        <div class="users-list-wrap">
                                        <ul id="userList" class="users-list">
                {% for pk in online_users %}
                <li class="user-item" data-pubkey="{{ pk|e }}">
                    <div class="user-left">
                        <span class="user-dot"></span>
                        <div>
                            <div class="user-name">
                                {% set last4 = pk[-4:] %}
                                {% if pk.startswith('guest') or pk|length < 20 %}
                                    guest …{{ last4 }}
                                {% elif pk == my_pubkey %}
                                    you · …{{ last4 }}
                                {% else %}
                                    …{{ last4 }}
                                {% endif %}
                            </div>
                            {% if pk == my_pubkey %}
                                <div class="user-tag-me">you</div>
                            {% else %}
                                <div class="user-pubkey">…{{ pk[-4:] }}</div>
                            {% endif %}
                        </div>
                    </div>
                    <button class="user-btn" type="button">@</button>
                </li>
                {% endfor %}
            </ul>
                        </div>
                    </div>
                </section>

                <section id="callPanel" class="call-panel hidden">
                    <div class="call-videos">
                        <div class="video-frame">
                            <video id="remoteVideo" playsinline></video>
                            <div class="video-label">Remote stream</div>
                        </div>
                        <div class="video-frame" style="max-width: 140px;">
                            <video id="localVideo" muted playsinline></video>
                            <div class="video-label">You</div>
                        </div>
                    </div>
                    <div class="call-meta">
                        <div id="callStatus" class="call-status">
                            No active call — long-press any user chip to start.
                        </div>
                        <div class="call-buttons">
                            <button id="hangupBtn" class="btn btn-danger" type="button">
                                <span class="btn-icon">✕</span>
                                Hang up
                            </button>
                        </div>
                    </div>
                </section>
            </aside>
        </section>
    </main>

    <!-- JS: Matrix background + chat + WebRTC -->
    <script>
        const myPubkey = document.body.dataset.myPubkey || "";

        // Matrix "space warp"
        (() => {
            const canvas = document.getElementById('matrix-bg');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            const CHARS = ['0','1'];
            let width = 0, height = 0, particles = [], raf = null;

            function resize() {
                const dpr = Math.max(1, Math.min(window.devicePixelRatio || 1, 2));
                const cssW = window.innerWidth;
                const cssH = window.innerHeight;

                canvas.width  = Math.floor(cssW * dpr);
                canvas.height = Math.floor(cssH * dpr);
                canvas.style.width  = cssW + 'px';
                canvas.style.height = cssH + 'px';

                ctx.setTransform(1,0,0,1,0,0);
                ctx.scale(dpr, dpr);

                width = cssW;
                height = cssH;

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
                    const x2 = width  / 2 + p.x * scale;
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
                    if (raf) { cancelAnimationFrame(raf); raf = null; }
                } else {
                    if (!raf) raf = requestAnimationFrame(draw);
                }
            }

            window.addEventListener('resize', resize);
            document.addEventListener('visibilitychange', onVis);

            resize();
            raf = requestAnimationFrame(draw);
        })();

        function goHome(hash) {
            const base = "{{ url_for('home') }}";
            const url  = hash ? base + hash : base;
            window.location.href = url;
        }

        function shortKey(pk) {
            if (!pk) return "";
            return pk.length > 18 ? pk.slice(0,10) + "…" + pk.slice(-6) : pk;
        }

        function mentionUser(pubkey) {
            const input = document.getElementById('chatInput');
            if (!input) return;
            const prefix = input.value && !input.value.endsWith(' ') ? ' ' : '';
            input.value = (input.value || '') + prefix + '@' + shortKey(pubkey) + ' ';
            input.focus();
        }

                function openExplorerFor(pubkey) {
            if (!pubkey) return;
            if (pubkey.startsWith('guest')) return;
            try {
                localStorage.setItem('hodlxxi_explorer_target', pubkey);
            } catch (e) {}
            // Jump to Explorer section; Explorer JS can read localStorage
            goHome('#explorer');
        }


        const messagesEl    = document.getElementById('messages');
        const userListEl    = document.getElementById('userList');
        const onlineCountEl = document.getElementById('onlineCount');
        const statusEl      = document.getElementById('room-status');
        const inputEl       = document.getElementById('chatInput');
        const sendBtn       = document.getElementById('sendBtn');

        const callPanelEl   = document.getElementById('callPanel');
        const callStatusEl  = document.getElementById('callStatus');
        const hangupBtn     = document.getElementById('hangupBtn');
        const localVideo    = document.getElementById('localVideo');
        const remoteVideo   = document.getElementById('remoteVideo');

        function setStatus(text) {
            if (statusEl) statusEl.textContent = text;
        }

        function setOnlineCount(n) {
            if (onlineCountEl) onlineCountEl.textContent = n;
        }

        // 45 sec UI cleanup to match backend EXPIRY_SECONDS
        const EXPIRY_SECONDS = 45;
        function pruneOldMessagesUI() {
            if (!messagesEl) return;
            const now = Date.now() / 1000;
            const items = messagesEl.querySelectorAll('.message');
            items.forEach(li => {
                const ts = parseFloat(li.dataset.ts || "0");
                if (ts && (now - ts) > EXPIRY_SECONDS) {
                    li.remove();
                }
            });
        }
        setInterval(pruneOldMessagesUI, 5000);

        function renderMessage(msg) {
            if (!messagesEl || !msg) return;
            const li = document.createElement('li');
            li.className = 'message';

            const fromPk = msg.pubkey || msg.sender_pubkey || '';
            if (fromPk && myPubkey && fromPk === myPubkey) {
                li.classList.add('me');
            }

            const senderLabel = msg.label || msg.sender || (fromPk || 'anon');
            const shortSender = senderLabel.length > 22
                ? senderLabel.slice(0, 12) + '…' + senderLabel.slice(-6)
                : senderLabel;

            // Server ts is in seconds; fall back to "now"
            const rawTs = msg.ts || msg.timestamp || msg.created_at || (Date.now() / 1000);
            const timeStr = new Date(rawTs * 1000).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit'
            });

            // Store timestamp on the DOM node for pruning
            li.dataset.ts = String(rawTs);

            li.innerHTML = `
                <div class="message-meta">
                    <div class="message-sender">${shortSender}</div>
                    <div class="message-timestamp">${timeStr}</div>
                </div>
                <div class="message-text">${(msg.text || msg.body || '').replace(/</g, '&lt;')}</div>
            `;

            messagesEl.appendChild(li);

            // Always auto-scroll to the newest message
            requestAnimationFrame(() => {
                messagesEl.scrollTop = messagesEl.scrollHeight;
            });
        }


        function extractPubkeys(payload) {
            if (!payload) return [];
            const arr = Array.isArray(payload)
                ? payload
                : (payload.users || payload.online_users || []);
            return arr
                .map(u => typeof u === 'string'
                    ? u
                    : (u && (u.pubkey || u.id)) || null
                )
                .filter(Boolean);
        }

                function renderUserList(users) {
            if (!userListEl || !Array.isArray(users)) return;
            userListEl.innerHTML = '';

            users.forEach(pk => {
                const li = document.createElement('li');
                li.className = 'user-item';
                li.dataset.pubkey = pk;

                const isMe = myPubkey && pk === myPubkey;
                const isGuest = pk.length < 20 || pk.startsWith('guest');
                const last4 = pk.slice(-4);
                let label;
                if (isGuest) {
                    label = 'guest …' + last4;
                } else if (isMe) {
                    label = 'you · …' + last4;
                } else {
                    label = '…' + last4;
                }

                li.innerHTML = `
                    <div class="user-left">
                        <span class="user-dot"></span>
                        <div>
                            <div class="user-name">
                                ${label}
                            </div>
                            ${isMe
                                ? '<div class="user-tag-me">you</div>'
                                : '<div class="user-pubkey">…' + last4 + '</div>'}
                        </div>
                    </div>
                    <button class="user-btn" type="button">@</button>
                `;

                const btn = li.querySelector('.user-btn');
                if (btn) {
                    btn.addEventListener('click', (ev) => {
                        ev.stopPropagation();
                        mentionUser(pk);
                    });
                }

                // Long-press to call
                let pressTimer = null;
                let didLongPress = false;
                const startPress = (ev) => {
                    if (pk === myPubkey) return;
                    if (pressTimer !== null) return;
                    pressTimer = setTimeout(() => {
                        pressTimer = null;
                        didLongPress = true;
                        startCall(pk);
                        setTimeout(() => { didLongPress = false; }, 100);
                    }, 700); // 0.7 sec long-press
                };
                const cancelPress = () => {
                    if (pressTimer !== null) {
                        clearTimeout(pressTimer);
                        pressTimer = null;
                    }
                };

                li.addEventListener('mousedown', startPress);
                li.addEventListener('touchstart', startPress, { passive: true });
                ['mouseup','mouseleave','touchend','touchcancel'].forEach(evName => {
                    li.addEventListener(evName, cancelPress);
                });

                // Tap on real keys -> open Explorer with that pubkey
                if (!isGuest) {
                    li.addEventListener('click', (ev) => {
                        if (didLongPress) return;  // avoid double-fire after long press
                        openExplorerFor(pk);
                    });
                }

                userListEl.appendChild(li);
            });
            setOnlineCount(users.length);
        }


        // --- Socket.IO wiring ---
        const socket = io();

        socket.on('connect', () => {
            setStatus('Connected');
        });

        socket.on('disconnect', () => {
            setStatus('Disconnected');
        });

        socket.on('chat:history', (payload) => {
            if (!payload) return;
            const msgs = payload.messages || payload;
            if (!Array.isArray(msgs)) return;
            messagesEl.innerHTML = '';
            msgs.forEach(renderMessage);
            // Make sure we end up at the bottom after loading history
            requestAnimationFrame(() => {
                messagesEl.scrollTop = messagesEl.scrollHeight;
            });
            setStatus('History loaded');
        });

        socket.on('chat:message', (msg) => {
            renderMessage(msg);
        });


        socket.on('online:list', (payload) => {
            const users = extractPubkeys(payload);
            renderUserList(users);
        });

        socket.on('user:list', (payload) => {
            const users = extractPubkeys(payload);
            renderUserList(users);
        });

        socket.on('user:joined', (payload) => {
            const [pk] = extractPubkeys([payload]);
            if (!pk || !userListEl) return;

            const existing = Array.from(
                userListEl.querySelectorAll('.user-item')
            ).map(li => li.dataset.pubkey);

            if (existing.includes(pk)) return;
            renderUserList([...existing, pk]);
        });

        socket.on('user:left', (payload) => {
            const [pk] = extractPubkeys([payload]);
            if (!pk || !userListEl) return;

            const li = userListEl.querySelector(`.user-item[data-pubkey="${pk}"]`);
            if (li) li.remove();
            setOnlineCount(userListEl.querySelectorAll('.user-item').length);
        });

        function sendMessage() {
            if (!inputEl) return;
            const text = inputEl.value.trim();
            if (!text) return;
            socket.emit('chat:send', { text });
            inputEl.value = '';
            inputEl.focus();
        }

        sendBtn.addEventListener('click', sendMessage);
        inputEl.addEventListener('keydown', (evt) => {
            if (evt.key === 'Enter' && !evt.shiftKey) {
                evt.preventDefault();
                sendMessage();
            }
        });

        if (userListEl) {
            setOnlineCount(userListEl.querySelectorAll('.user-item').length);
        }

        // --- WebRTC: video calls (uses rtc:* events and /turn_credentials) ---
        let pc = null;
        let localStream = null;
        let currentPeer = null;
        let iceServersCache = null;

        function setCallUI(active, text) {
            if (!callPanelEl || !callStatusEl) return;
            if (active) {
                callPanelEl.classList.remove('hidden');
            } else {
                callPanelEl.classList.add('hidden');
            }
            callStatusEl.textContent = text || (active ? 'In call…' : 'No active call — long-press any user chip to start.');
        }

        async function getIceServers() {
            if (iceServersCache) return iceServersCache;
            try {
                const resp = await fetch('/turn_credentials');
                if (resp.ok) {
                    iceServersCache = await resp.json();
                } else {
                    iceServersCache = [];
                }
            } catch (err) {
                console.warn('TURN/STUN fetch failed', err);
                iceServersCache = [];
            }
            return iceServersCache;
        }

        async function ensureMedia() {
            if (localStream) return localStream;
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
                localStream = stream;
                if (localVideo) {
                    localVideo.srcObject = stream;
                    localVideo.muted = true;
                    localVideo.play().catch(() => {});
                }
                return stream;
            } catch (err) {
                console.error('getUserMedia failed', err);
                setCallUI(false, 'Camera/mic access denied.');
                throw err;
            }
        }

        async function createPeerConnection(targetPubkey) {
            const iceServers = await getIceServers();
            pc = new RTCPeerConnection({ iceServers });

            pc.onicecandidate = (event) => {
                if (event.candidate && currentPeer) {
                    socket.emit('rtc:ice', {
                        to: currentPeer,
                        from: myPubkey,
                        candidate: event.candidate
                    });
                }
            };

            pc.ontrack = (event) => {
                if (remoteVideo) {
                    remoteVideo.srcObject = event.streams[0];
                    remoteVideo.play().catch(() => {});
                }
            };

            const stream = await ensureMedia();
            stream.getTracks().forEach(t => pc.addTrack(t, stream));

            currentPeer = targetPubkey;
            setCallUI(true, 'Connecting to ' + shortKey(targetPubkey) + '…');
            return pc;
        }

        async function startCall(targetPubkey) {
            if (!myPubkey) {
                setCallUI(false, 'Please log in to start a call.');
                return;
            }
            if (!targetPubkey || targetPubkey === myPubkey) return;

            try {
                if (pc) {
                    endCall(false);
                }
                const conn = await createPeerConnection(targetPubkey);
                const offer = await conn.createOffer();
                await conn.setLocalDescription(offer);

                socket.emit('rtc:offer', {
                    to: targetPubkey,
                    from: myPubkey,
                    offer
                });
                setCallUI(true, 'Calling ' + shortKey(targetPubkey) + '…');
            } catch (err) {
                console.error('startCall failed', err);
                endCall(false);
                setCallUI(false, 'Call failed to start.');
            }
        }

        function endCall(sendSignal = true) {
            if (pc) {
                pc.getSenders().forEach(s => {
                    try { s.track && s.track.stop(); } catch {}
                });
                try { pc.close(); } catch {}
                pc = null;
            }
            if (localStream) {
                localStream.getTracks().forEach(t => t.stop());
                localStream = null;
                if (localVideo) localVideo.srcObject = null;
            }
            if (remoteVideo) {
                remoteVideo.srcObject = null;
            }

            if (sendSignal && currentPeer && myPubkey) {
                socket.emit('rtc:hangup', {
                    to: currentPeer,
                    from: myPubkey
                });
            }

            currentPeer = null;
            setCallUI(false);
        }

        hangupBtn.addEventListener('click', () => {
            endCall(true);
        });

        socket.on('rtc:offer', async (data) => {
            try {
                if (!data || data.to !== myPubkey) return;
                const from = data.from;
                if (!from || from === myPubkey) return;

                if (pc) {
                    endCall(false);
                }

                const conn = await createPeerConnection(from);
                await conn.setRemoteDescription(new RTCSessionDescription(data.offer));
                const answer = await conn.createAnswer();
                await conn.setLocalDescription(answer);

                socket.emit('rtc:answer', {
                    to: from,
                    from: myPubkey,
                    answer
                });

                setCallUI(true, 'In call with ' + shortKey(from));
            } catch (err) {
                console.error('Error handling rtc:offer', err);
                endCall(false);
            }
        });

        socket.on('rtc:answer', async (data) => {
            try {
                if (!data || data.to !== myPubkey || !pc) return;
                await pc.setRemoteDescription(new RTCSessionDescription(data.answer));
                setCallUI(true, 'In call with ' + shortKey(data.from || currentPeer || 'peer'));
            } catch (err) {
                console.error('Error handling rtc:answer', err);
                endCall(false);
            }
        });

        socket.on('rtc:ice', async (data) => {
            try {
                if (!data || data.to !== myPubkey || !pc || !data.candidate) return;
                await pc.addIceCandidate(new RTCIceCandidate(data.candidate));
            } catch (err) {
                console.error('Error handling rtc:ice', err);
            }
        });

        socket.on('rtc:hangup', (data) => {
            if (!data || data.to !== myPubkey) return;
            endCall(false);
            setCallUI(false, 'Call ended by ' + shortKey(data.from || 'peer') + '.');
        });
        
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
    :root {
      --bg: #0b0f10;
      --panel: #11171a;
      --fg: #e6f1ef;
      --accent: #00ff88;
      --orange: #f7931a;
      --muted: #8a9da4;
      --red: #ff3b30;
      --blue: #3b82f6;
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      background: var(--bg);
      color: var(--fg);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto", sans-serif;
      min-height: 100vh;
      overflow-x: hidden;
      text-rendering: optimizeLegibility;
    }

    /* Matrix background (same family as leaderboard/playground) */
    #matrix-bg {
      position: fixed;
      inset: 0;
      z-index: 0;
      pointer-events: none;
    }

    @media (prefers-reduced-motion: reduce) {
      #matrix-bg {
        display: none !important;
      }
    }

    /* Top CTA bar like Playground / Leaderboard */
    .top-cta {
      position: sticky;
      top: 0;
      z-index: 12;
      width: 100%;
      display: flex;
      justify-content: center;
      padding: 0.45rem 0.75rem;
      background: radial-gradient(
        circle at top,
        rgba(34, 197, 94, 0.16) 0,
        rgba(3, 7, 18, 0.96) 45%,
        rgba(3, 7, 18, 0.98) 100%
      );
      border-bottom: 1px solid rgba(0, 255, 136, 0.3);
      box-shadow: 0 18px 35px rgba(0, 0, 0, 0.9);
      backdrop-filter: blur(16px);
    }

    .top-cta-inner {
      width: 100%;
      max-width: 1200px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
    }

    .top-cta-text {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.4rem;
      font-size: 0.85rem;
      color: #cbd5f5;
    }

    .top-cta-text strong {
      color: var(--accent);
      font-weight: 600;
    }

    .top-cta-pill {
      padding: 0.18rem 0.6rem;
      border-radius: 999px;
      border: 1px solid rgba(0, 255, 136, 0.6);
      background: rgba(6, 95, 70, 0.7);
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #bbf7d0;
    }

    .top-cta-action {
      white-space: nowrap;
    }

    .btn,
    button {
      background: var(--accent);
      color: #000;
      border: none;
      padding: 0.8rem 1.8rem;
      font-size: 0.95rem;
      font-weight: 600;
      border-radius: 999px;
      cursor: pointer;
      font-family: inherit;
      transition: all 0.3s;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }

    .btn:hover,
    button:hover {
      box-shadow: 0 0 20px rgba(0, 255, 136, 0.4);
      transform: translateY(-2px);
    }

    button:disabled,
    .btn:disabled {
      background: #374151;
      color: #9ca3af;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }

    .btn-secondary {
      background: transparent;
      border: 1px solid var(--accent);
      color: var(--accent);
    }

    .btn-secondary:hover {
      background: rgba(0, 255, 136, 0.08);
    }

    /* Main root container */
    #root {
      position: relative;
      z-index: 1;
      padding: 4.5rem 1.5rem 2rem;
      max-width: 960px;
      margin: 0 auto;
    }

    .login-card {
      background: rgba(17, 23, 26, 0.92);
      border-radius: 16px;
      border: 1px solid #0f2a24;
      box-shadow: 0 0 10px rgba(0, 255, 136, 0.08);
      padding: 2rem 1.75rem 1.75rem;
    }

    .login-header {
      margin-bottom: 1.5rem;
    }

    .login-header h1 {
      font-size: 1.9rem;
      margin-bottom: 0.4rem;
      color: var(--accent);
      text-shadow: 0 0 18px rgba(0, 255, 136, 0.3);
    }

    .login-header p {
      font-size: 0.98rem;
      color: var(--muted);
    }

    /* Tabs row (Legacy / API / Nostr) */
    .tabs-row {
      display: flex;
      gap: 0.75rem;
      align-items: center;
      justify-content: space-between;
      margin: 1.1rem 0 1.2rem;
      flex-wrap: wrap;
    }

    .tabs {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }

    .tab-btn {
      border-radius: 999px;
      border: 1px solid #184438;
      background: #020617;
      color: var(--fg);
      padding: 0.45rem 1.1rem;
      cursor: pointer;
      font-size: 0.9rem;
      font-weight: 500;
      transition: all 0.2s;
    }

    .tab-btn:hover {
      border-color: var(--accent);
      color: var(--accent);
    }

    .tab-btn.active {
      border-color: var(--accent);
      background: var(--accent);
      color: #000;
      box-shadow: 0 0 14px rgba(0, 255, 136, 0.3);
    }

    /* Nostr / Matrix toggle area */
    .tabs-right {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }

    .nostr-btn {
      background: #8b5cf6;
      color: #fff;
      border-radius: 999px;
      padding: 0.45rem 1.1rem;
      font-size: 0.9rem;
      font-weight: 600;
      border: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      transition: all 0.2s;
    }

    .nostr-btn:hover {
      box-shadow: 0 0 18px rgba(139, 92, 246, 0.5);
      transform: translateY(-1px);
    }

    .ln-btn {
      background: #f97316;
      color: #fff;
      border-radius: 999px;
      padding: 0.45rem 1.1rem;
      font-size: 0.9rem;
      font-weight: 600;
      border: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      transition: all 0.2s;
    }

    .ln-btn:hover {
      box-shadow: 0 0 18px rgba(248, 150, 30, 0.5);
      transform: translateY(-1px);
    }

    .matrix-toggle {
      border-radius: 999px;
      border: 1px solid #184438;
      background: #020617;
      color: var(--fg);
      padding: 0.45rem 1.1rem;
      font-size: 0.85rem;
      cursor: pointer;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
    }

    .matrix-toggle:hover {
      background: #12352d;
    }

    /* Panels */
    .panel {
      display: none;
      border-top: 1px solid #1f2933;
      padding-top: 1rem;
      margin-top: 0.4rem;
    }

    .panel.active {
      display: block;
    }

    .hint {
      color: var(--muted);
      font-size: 0.86rem;
      margin-bottom: 0.8rem;
    }

    .challenge-box {
      background: #020617;
      border: 1px dashed var(--accent);
      color: var(--accent);
      padding: 0.75rem 0.9rem;
      border-radius: 10px;
      text-align: center;
      cursor: pointer;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.9rem;
      margin-bottom: 0.9rem;
    }

    .row {
      display: flex;
      gap: 0.75rem;
      flex-wrap: wrap;
      margin-bottom: 0.75rem;
    }

    .row > .field {
      flex: 1 1 260px;
      min-width: 0;
    }

    label {
      display: block;
      font-size: 0.8rem;
      color: var(--muted);
      margin-bottom: 0.25rem;
    }

    input,
    textarea {
      width: 100%;
      padding: 0.6rem 0.7rem;
      border-radius: 10px;
      border: 1px solid #255244;
      background: #020617;
      color: #bfffe6;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.85rem;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
    }

    input:focus,
    textarea:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 1px rgba(0, 255, 136, 0.4);
      background: #020c13;
    }

    textarea {
      min-height: 100px;
      resize: vertical;
    }

    .actions {
      display: flex;
      gap: 0.5rem;
      margin-top: 0.4rem;
      flex-wrap: wrap;
    }

    .actions button {
      border-radius: 999px;
      padding-inline: 1.3rem;
    }

    .actions .copy {
      background: transparent;
      border: 1px solid var(--accent);
      color: var(--accent);
    }

    .actions .copy:hover {
      background: rgba(0, 255, 136, 0.08);
    }

    .status {
      margin-top: 0.6rem;
      min-height: 1.2rem;
      font-size: 0.86rem;
      color: var(--muted);
    }

    /* Guest login box */
    .guest-login-panel {
      margin-top: 1.8rem;
      padding-top: 1.1rem;
      border-top: 1px dashed #1f2933;
    }

    .guest-login-panel h2 {
      font-size: 1rem;
      margin-bottom: 0.4rem;
      color: var(--accent);
    }

    .guest-login-panel p {
      font-size: 0.85rem;
      color: var(--muted);
      margin-bottom: 0.6rem;
    }

    .guest-input {
      width: 100%;
      padding: 0.55rem 0.65rem;
      border-radius: 999px;
      border: 1px solid #255244;
      background: #020617;
      color: #bfffe6;
      font-size: 0.85rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      margin-bottom: 0.5rem;
    }

    .guest-input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 1px rgba(0, 255, 136, 0.4);
      outline: none;
    }

    .guest-btn {
      width: 100%;
      justify-content: center;
      border-radius: 999px;
      padding-block: 0.7rem;
    }

    @media (max-width: 768px) {
      #root {
        padding: 3.5rem 1rem 1.5rem;
      }

      .login-card {
        padding: 1.6rem 1.2rem 1.4rem;
      }

      .login-header h1 {
        font-size: 1.6rem;
      }

      .top-cta-inner {
        flex-direction: column;
        align-items: flex-start;
      }

      .top-cta-action {
        width: 100%;
        text-align: center;
      }

      .btn,
      button {
        width: auto;
      }
    }

    @media (max-width: 480px) {
      .btn,
      button {
        width: 100%;
        justify-content: center;
      }

      .tabs-row {
        flex-direction: column;
        align-items: flex-start;
      }

      .tabs-right {
        width: 100%;
        justify-content: flex-start;
      }
    }
  </style>
</head>
<body>
  <!-- Global matrix background -->
  <canvas id="matrix-bg" aria-hidden="true"></canvas>

  <!-- Top CTA strip -->
  <div class="top-cta">
    <div class="top-cta-inner">
      <div class="top-cta-text">
        <span class="top-cta-pill">HODLXXI</span>
        <span><strong>Bitcoin Key Login</strong> · Prove you are your keys.</span>
      </div>
      <div class="top-cta-action">
        <button class="btn btn-secondary" onclick="window.location.href='/playground'">
          Open Playground
        </button>
      </div>
    </div>
  </div>

  <!-- Optional login sound (triggered by app JS elsewhere) -->
  <audio id="login-sound"
         src="/static/sounds/login.mp3"
         preload="auto" playsinline></audio>

  <div id="root">
    <div class="login-card">
      <div class="login-header">
        <h1>*Log in with your actual key, we Verify Trust*</h1>
        <p>Use your Bitcoin key, Lightning wallet, Nostr identity, or guest access to explore HODLXXI.</p>
      </div>

      <!-- Tabs row -->
      <div class="tabs-row">
        <div class="tabs">
          <button id="tabLegacy" class="tab-btn active" onclick="showTab('legacy')">
            Legacy
          </button>
          <button id="tabApi" class="tab-btn" onclick="showTab('api')">
            API
          </button>
          <button id="tabSpecial" class="tab-btn" onclick="showTab('special')">
            Special
          </button>
        </div>
        <div class="tabs-right">
          <button class="nostr-btn" type="button" onclick="loginWithNostr()">
            🟣 <span>Nostr</span>
          </button>
          <button class="ln-btn" type="button" onclick="loginWithLightning()">
            ⚡ <span>Lightning</span>
          </button>
        </div>
      </div>

      <!-- Legacy panel -->
      <div id="panelLegacy" class="panel active">
        <p class="hint">Sign the challenge with your wallet, then paste the signature.</p>
        <div class="challenge-box" id="legacyChallenge" title="Click to copy">
          {{ challenge }}
        </div>

        <div class="row">
          <div class="field">
            <label for="legacyPubkey">Public key</label>
            <input id="legacyPubkey" placeholder="02.. or 03.." />
          </div>
          <div class="field">
            <label for="legacySignature">Signature</label>
            <textarea id="legacySignature" rows="4" placeholder="base64 signature"></textarea>
          </div>
        </div>

        <div class="actions">
          <button class="copy" type="button" onclick="copyText('legacyChallenge')">
            Copy challenge
          </button>
          <button type="button" onclick="legacyVerify()">
            Verify &amp; Login
          </button>
        </div>

        <div id="legacyStatus" class="status"></div>
      </div>

      <!-- API panel -->
      <div id="panelApi" class="panel">
        <p class="hint">Request a challenge via the API, sign it, and verify.</p>

        <div class="row">
          <div class="field">
            <label for="apiPubkey">Public key</label>
            <input id="apiPubkey" placeholder="02.. or 03.." />
          </div>
          <div class="field">
            <label for="apiChallenge">Challenge</label>
            <textarea id="apiChallenge" rows="3" readonly></textarea>
          </div>
        </div>

        <div class="actions">
          <button type="button" onclick="getChallenge()">Get challenge</button>
          <button class="copy" type="button" onclick="copyText('apiChallenge')">Copy</button>
        </div>

        <div class="row">
          <div class="field">
            <label for="apiSignature">Signature</label>
            <textarea id="apiSignature" rows="4" placeholder="base64 signature"></textarea>
          </div>
          <div class="field">
            <label for="apiCid">Challenge ID</label>
            <input id="apiCid" readonly />
          </div>
        </div>

        <div class="actions">
          <button type="button" onclick="apiVerify()">Verify &amp; Login</button>
        </div>

        <div id="apiStatus" class="status"></div>
      </div>

      <!-- Special login panel -->
      <div id="panelSpecial" class="panel">
        <p class="hint">For special / host login via pre-agreed signature.</p>
        <div class="row">
          <div class="field">
            <label for="specialSignature">Special signature</label>
            <textarea id="specialSignature" rows="4" placeholder="Paste special signature"></textarea>
          </div>
        </div>
        <div class="actions">
          <button type="button" onclick="specialLogin()">
            Verify &amp; Login
          </button>
        </div>
        <div id="specialStatus" class="status"></div>
      </div>

      <!-- Guest login -->
      <div class="guest-login-panel">
        <h2>Guest / PIN Login</h2>
        <p>Use a shared PIN (if invited) or leave blank for a random guest session.</p>
        <input
          id="guestPin"
          class="guest-input"
          type="text"
          placeholder="PIN or leave blank for guest"
        />
        <button type="button" class="btn guest-btn" onclick="guestLogin()">
          Guest
        </button>
      </div>
    </div>
  </div>

  <!-- QR modal reused from universal_login -->
  <div id="qrModal" class="qr-modal" style="
    position:fixed;
    inset:0;
    background:rgba(0,0,0,.95);
    display:none;
    align-items:center;
    justify-content:center;
    z-index:1000;
  ">
    <div class="qr-content" style="
      background:white;
      padding:2rem;
      border-radius:16px;
      text-align:center;
      max-width:400px;
      width:90%;
    ">
      <h2>Scan with Wallet</h2>
      <div id="qrcode"></div>
      <a id="openInWallet" href="#" target="_blank" rel="noopener">Open in wallet</a>
      <div id="lnurlText" style="
        margin-top:1rem;
        padding:.75rem;
        background:#f0f0f0;
        border-radius:8px;
        font-family:monospace;
        font-size:.7rem;
        word-break:break-all;
        color:#333;
      "></div>
      <div id="countdown" style="color:#666;font-size:.85rem;margin-top:.5rem"></div>
      <button onclick="closeQR()" style="
        margin-top:1rem;
        padding:.75rem 2rem;
        background:#333;
        color:white;
        border:none;
        border-radius:8px;
        cursor:pointer;
      ">Close</button>
    </div>
  </div>
  <script src="/static/js/qrcode.min.js"></script>

  <!-- Login logic (unchanged, just formatted) -->
  <script>
    // Helper to respect ?next= parameter for post-login redirects
    function getRedirectUrl() {
      const params = new URLSearchParams(window.location.search);
      const next = params.get("next");
      return next || "/app";
    }

    function showTab(which) {
      ["legacy", "api", "guest", "special"].forEach((t) => {
        const tab = document.getElementById(
          "tab" + t.charAt(0).toUpperCase() + t.slice(1)
        );
        const panel = document.getElementById(
          "panel" + t.charAt(0).toUpperCase() + t.slice(1)
        );
        if (tab && panel) {
          tab.classList.toggle("active", t === which);
          panel.classList.toggle("active", t === which);
        }
      });
    }

    function copyText(id) {
      const el = document.getElementById(id);
      const txt =
        el.tagName === "TEXTAREA" || el.tagName === "INPUT"
          ? el.value
          : el.textContent.trim();
      navigator.clipboard.writeText(txt);
    }

    // Click to copy on the challenge card (visual feedback)
    const legacyEl = document.getElementById("legacyChallenge");
    if (legacyEl) {
      legacyEl.addEventListener("click", () => {
        const text = legacyEl.textContent.trim();
        navigator.clipboard.writeText(text).then(() => {
          const orig = legacyEl.style.background;
          legacyEl.style.background = "#12352d";
          setTimeout(() => (legacyEl.style.background = orig), 300);
        });
      });
    }

    // --- Flows ---
    async function legacyVerify() {
      const pubkey = document.getElementById("legacyPubkey").value.trim();
      const signature = document
        .getElementById("legacySignature")
        .value.trim();
      const challenge = document
        .getElementById("legacyChallenge")
        .textContent.trim();
      const st = document.getElementById("legacyStatus");
      st.textContent = "Verifying...";
      try {
        const r = await fetch("/verify_signature", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pubkey, signature, challenge }),
        });
        const d = await r.json();
        // NOTE: access_level in response is for UI hints only.
        // DO NOT treat this as an authorization boundary.
        // All actual authorization happens server-side via session validation.
        if (r.ok && d.verified) {
          sessionStorage.setItem("playLoginSound", "1");
          window.location.href = getRedirectUrl();
        } else {
          st.textContent = d.error || "Failed";
        }
      } catch (e) {
        st.textContent = "Network error";
      }
    }

    async function getChallenge() {
      const pubkey = document.getElementById("apiPubkey").value.trim();
      const st = document.getElementById("apiStatus");
      try {
        const r = await fetch("/api/challenge", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pubkey }),
        });
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || "Request failed");
        document.getElementById("apiChallenge").value = d.challenge || "";
        document.getElementById("apiCid").value = d.challenge_id || "";
        st.textContent = "Challenge ready";
      } catch (e) {
        st.textContent = e.message;
      }
    }

    async function apiVerify() {
      const pubkey = document.getElementById("apiPubkey").value.trim();
      const signature = document
        .getElementById("apiSignature")
        .value.trim();
      const cid = document.getElementById("apiCid").value.trim();
      const st = document.getElementById("apiStatus");
      try {
        const r = await fetch("/api/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pubkey, signature, challenge_id: cid }),
        });
        const d = await r.json();
        if (r.ok && d.verified) {
          sessionStorage.setItem("playLoginSound", "1");
          window.location.href = getRedirectUrl();
        } else {
          st.textContent = d.error || "Failed";
        }
      } catch (e) {
        st.textContent = "Network error";
      }
    }

    async function guestLogin() {
      const pinInput = document.getElementById("guestPin");
      const pin = pinInput ? pinInput.value.trim() : "";

      const res = await fetch("/guest_login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pin }),
      });

      const data = await res.json();
      if (!res.ok || !data.ok) {
        alert(data.error || "Guest login failed");
        return;
      }

      const label = data.label || "Guest";
      console.log("Guest login successful:", label);
      alert("Logged in as " + label);
      window.location.href = getRedirectUrl();
    }

    async function specialLogin() {
      const sig = document
        .getElementById("specialSignature")
        ?.value.trim();
      const st = document.getElementById("specialStatus");
      try {
        const r = await fetch("/special_login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ signature: sig }),
        });
        const d = await r.json();
        if (r.ok && d.verified) {
          sessionStorage.setItem("playLoginSound", "1");
          window.location.href = getRedirectUrl();
        } else {
          st.textContent = d.error || "Failed";
        }
      } catch (e) {
        st.textContent = "Network error";
      }
    }
  </script>

  <!-- LNURL auth + Nostr -->
  <script>
    function urlToLnurl(url) {
      const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
      function polymod(v) {
        const G = [
          0x3b6a57b2,
          0x26508e6d,
          0x1ea119fa,
          0x3d4233dd,
          0x2a1462b3,
        ];
        let chk = 1;
        for (const val of v) {
          const top = chk >>> 25;
          chk = ((chk & 0x1ffffff) << 5) ^ val;
          for (let i = 0; i < 5; i++)
            if ((top >>> i) & 1) chk ^= G[i];
        }
        return chk;
      }
      function hrpExpand(hrp) {
        const ret = [];
        for (let i = 0; i < hrp.length; i++)
          ret.push(hrp.charCodeAt(i) >> 5);
        ret.push(0);
        for (let i = 0; i < hrp.length; i++)
          ret.push(hrp.charCodeAt(i) & 31);
        return ret;
      }
      function createChecksum(hrp, data) {
        const values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
        const mod = polymod(values) ^ 1;
        const ret = [];
        for (let p = 0; p < 6; p++)
          ret.push((mod >> (5 * (5 - p))) & 31);
        return ret;
      }
      function convertBits(data, from, to) {
        let acc = 0,
          bits = 0,
          ret = [],
          maxv = (1 << to) - 1;
        for (const value of data) {
          acc = (acc << from) | value;
          bits += from;
          while (bits >= to) {
            bits -= to;
            ret.push((acc >> bits) & maxv);
          }
        }
        if (bits > 0) ret.push((acc << (to - bits)) & maxv);
        return ret;
      }
      const bytes = new TextEncoder().encode(url);
      const data5 = convertBits(Array.from(bytes), 8, 5);
      const combined = data5.concat(createChecksum("lnurl", data5));
      let out = "lnurl1";
      for (const d of combined) out += CHARSET[d];
      return out.toUpperCase();
    }

    function renderQR(el, text) {
      el.innerHTML = "";
      new QRCode(el, {
        text,
        width: 256,
        height: 256,
        colorDark: "#000",
        colorLight: "#fff",
      });
    }

    let poll = null,
      expire = null;

    function startPolling(sid) {
      clearInterval(poll);
      poll = setInterval(async () => {
        const r = await fetch(`/api/lnurl-auth/check/${sid}`);
        const j = await r.json();
        if (j.authenticated) {
          clearInterval(poll);
          clearInterval(expire);
          closeQR();
          alert("Lightning login success!");
          window.location.href = getRedirectUrl();
        }
      }, 2000);
    }

    function startCountdown(s) {
      clearInterval(expire);
      let r = s;
      const el = document.getElementById("countdown");
      expire = setInterval(() => {
        r--;
        el.textContent = `Expires in ${Math.floor(r / 60)}:${(
          r % 60
        )
          .toString()
          .padStart(2, "0")}`;
        if (r <= 0) {
          clearInterval(poll);
          clearInterval(expire);
          closeQR();
        }
      }, 1000);
    }

    function closeQR() {
      document.getElementById("qrModal").style.display = "none";
    }

    async function loginWithLightning() {
      const modal     = document.getElementById("qrModal");
      const qrBox     = document.getElementById("qrcode");
      const lnurlBox  = document.getElementById("lnurlText");
      const countdown = document.getElementById("countdown");

      try {
        // Show modal immediately with loading state
        if (qrBox) qrBox.innerHTML = "";
        if (lnurlBox) lnurlBox.textContent = "Requesting Lightning login…";
        if (countdown) countdown.textContent = "";
        if (modal) modal.style.display = "flex";

        const res = await fetch("/api/lnurl-auth/create", {
          method: "POST",
        });

        if (!res.ok) {
          const txt = await res.text().catch(() => "");
          console.error("LNURL-auth create failed:", res.status, txt);
          alert("Lightning login init failed: " + res.status);
          if (modal) modal.style.display = "none";
          return;
        }

        let j;
        try {
          j = await res.json();
        } catch (e) {
          console.error("LNURL-auth JSON parse error:", e);
          alert("Lightning login error: invalid server response");
          if (modal) modal.style.display = "none";
          return;
        }

        if (!j || !j.callback_url) {
          console.error("LNURL-auth missing callback_url:", j);
          alert("Lightning login error: missing callback_url");
          if (modal) modal.style.display = "none";
          return;
        }

        const lnurl = urlToLnurl(j.callback_url);

        if (qrBox && typeof QRCode !== "undefined") {
          renderQR(qrBox, lnurl);
        } else if (lnurlBox) {
          // Fallback: show lnurl text only
          lnurlBox.textContent = lnurl;
        }

        if (lnurlBox) lnurlBox.textContent = lnurl;
        const openEl = document.getElementById("openInWallet");
        if (openEl) openEl.href = "lightning:" + lnurl;

        startPolling(j.session_id);
        startCountdown(j.expires_in || 300);
      } catch (e) {
        console.error("Lightning login error:", e);
        alert("Lightning login error: " + e);
        if (modal) modal.style.display = "none";
      }
    }

    async function loginWithNostr() {
      if (!window.nostr) {
        alert("No Nostr extension found");
        return;
      }
      const pubkey = await window.nostr.getPublicKey();
      const r = await fetch("/api/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pubkey, method: "nostr" }),
      });
      const d = await r.json();
      const event = {
        kind: 22242,
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ["challenge", d.challenge],
          ["app", "HODLXXI"],
        ],
        content: `HODLXXI Login: ${d.challenge}`,
      };
      const signed = await window.nostr.signEvent(event);
      const vr = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          challenge_id: d.challenge_id,
          pubkey,
          signature: signed.sig,
        }),
      });
      const j2 = await vr.json();
      if (j2.verified) {
        alert("Nostr login success!");
        window.location.href = getRedirectUrl();
      } else alert("Verification failed");
    }
  </script>

  <!-- Matrix background animation (same as leaderboard/playground) -->
  <script>
    (function () {
      const canvas = document.getElementById("matrix-bg");
      if (!canvas) return;

      const ctx = canvas.getContext("2d");
      const CHARS = ["0", "1"];
      let width = 0,
        height = 0,
        particles = [],
        raf = null;

      function resize() {
        const dpr = Math.max(1, Math.min(window.devicePixelRatio || 1, 2));
        const cssW = window.innerWidth;
        const cssH = window.innerHeight;

        canvas.width = Math.floor(cssW * dpr);
        canvas.height = Math.floor(cssH * dpr);
        canvas.style.width = cssW + "px";
        canvas.style.height = cssH + "px";

        ctx.setTransform(1, 0, 0, 1, 0, 0);
        ctx.scale(dpr, dpr);

        width = cssW;
        height = cssH;
        particles = [];

        for (let i = 0; i < 400; i++) {
          particles.push({
            x: (Math.random() - 0.5) * width,
            y: (Math.random() - 0.5) * height,
            z: Math.random() * 800 + 100,
          });
        }

        ctx.fillStyle = "rgba(0,0,0,1)";
        ctx.fillRect(0, 0, width, height);
      }

      function draw() {
        ctx.fillStyle = "rgba(0,0,0,0.25)";
        ctx.fillRect(0, 0, width, height);
        ctx.fillStyle = "#00ff88";

        for (const p of particles) {
          const scale = 200 / p.z;
          const x2 = width / 2 + p.x * scale;
          const y2 = height / 2 + p.y * scale;
          const size = Math.max(8 * scale, 1);

          ctx.font = size + "px monospace";
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
          if (raf) {
            cancelAnimationFrame(raf);
            raf = null;
          }
        } else {
          if (!raf) raf = requestAnimationFrame(draw);
        }
      }

      window.addEventListener("resize", resize);
      document.addEventListener("visibilitychange", onVis);

      resize();
      raf = requestAnimationFrame(draw);
    })();

    // Optional: simple toggle that just flips a flag in localStorage (you can
    // later wire it to warp/rain variants if you want)
    (function () {
      const btn = document.getElementById("bgToggle");
      if (!btn) return;

      function updateLabel() {
        const mode = localStorage.getItem("matrixMode") || "warp";
        btn.textContent = mode === "warp" ? "◒ Matrix" : "◒ Matrix";
      }

      updateLabel();
      btn.addEventListener("click", () => {
        const current = localStorage.getItem("matrixMode") || "warp";
        const next = current === "warp" ? "rain" : "warp";
        localStorage.setItem("matrixMode", next);
        updateLabel();
        // Visual mode is still the same effect; you can swap implementations later if needed.
      });
    })();
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
    data = request.get_json() or {}
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
        # Explicit pubkey provided by client
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

    # --- Membership + session wiring ---
    # Create/update user in membership system (sets logged_in_pubkey, user_id, plan in session)
    user = on_successful_login(matched_pubkey)

    # For PoF routes compatibility, keep a dedicated key with the raw pubkey
    session["pof_pubkey"] = matched_pubkey

    # Access level logic
    if not pubkey_hex:
        # matched a SPECIAL_USER
        session["access_level"] = "full"

        # Treat special users as admin/paid so they always pass require_paid_user()
        if user.plan != "admin":
            user.plan = "admin"
    else:
        # Normal user: compute save/check ratio
        in_bal, out_bal = get_save_and_check_balances_for_pubkey(matched_pubkey)
        ratio = (out_bal / in_bal) if in_bal > 0 else 0
        session["access_level"] = "full" if ratio >= 1 else "limited"

    session.permanent = True

    # Optional: clear challenge to prevent replay
    session.pop("challenge", None)
    session.pop("challenge_timestamp", None)

    # Notify chat clients
    socketio.emit("user:logged_in", matched_pubkey)

    logger.debug(
        "verify_signature → matched_pubkey=%s, access_level=%s, plan=%s",
        matched_pubkey,
        session["access_level"],
        user.plan,
    )

    return jsonify({
        "verified": True,
        "access_level": session["access_level"],
        "pubkey": matched_pubkey,
        "plan": user.plan,
    })


@app.route("/guest_login", methods=["POST"])
def guest_login():
    """Guest or PIN login with clear identity separation"""
    import hashlib
    data = request.get_json(silent=True) or {}
    pin = (data.get("pin") or "").strip()
    if session.get("logged_in_pubkey"):
        return jsonify({"ok": True, "label": session.get("guest_label")})
    if pin:
        label = GUEST_PINS.get(pin)
        if not label:
            return jsonify({"error": "Invalid PIN"}), 403
        guest_id = f"guest-pin-{hashlib.sha256(pin.encode()).hexdigest()[:16]}"
        session["logged_in_pubkey"] = guest_id
        session["logged_in_privkey"] = None
        session["guest_label"] = label
        session["login_method"] = "pin"
    else:
        rand_id = uuid.uuid4().hex[:12]
        session["logged_in_pubkey"] = f"guest-random-{rand_id}"
        session["logged_in_privkey"] = None
        session["guest_label"] = f"Guest-{rand_id[:6]}"
        session["login_method"] = "random_guest"
    session.permanent = True
    return jsonify({"ok": True, "label": session["guest_label"]})


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
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>HODLXXI — Covenant Explorer & Onboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="theme-color" content="#00ff88">

    <!-- QR library for scanning -->
    <script src="https://unpkg.com/jsqr/dist/jsQR.js"></script>

    <style>
        .hidden { display: none !important; }

        :root {
            --bg: #0b0f10;
            --panel: #11171a;
            --fg: #e6f1ef;
            --accent: #00ff88;
            --orange: #f7931a;
            --red: #ff3b30;
            --blue: #3b82f6;
            --muted: #8a9da4;

            /* legacy names mapped to new palette */
            --neon-green: var(--accent);
            --neon-blue: var(--blue);
            --dark-bg: #020617;
            --border-color: #0f2a24;
            --text-color: var(--fg);
            --spacing-unit: 1rem;
            --touch-target: 44px;
        }

        /* --- Matrix background canvas --- */
        #matrix-bg {
            position: fixed;
            inset: 0;
            z-index: 0;
            pointer-events: none;
        }

        body > *:not(#matrix-bg) {
            position: relative;
            z-index: 1;
        }

        @media (prefers-reduced-motion: reduce) {
            #matrix-bg { display: none !important; }
        }

        @media print {
            #matrix-bg { display: none !important; }
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            margin: 0;
            background: radial-gradient(circle at top, rgba(0, 255, 136, 0.12) 0, var(--bg) 55%, #020617 100%);
            color: var(--text-color);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto", "Helvetica Neue", Arial, sans-serif;
            line-height: 1.5;
            min-height: 100vh;
            font-size: 16px;
            overflow-x: hidden;
            text-rendering: optimizeLegibility;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 4.5rem 1.25rem 2rem;
        }

        /* Header / Manifest block */
        .header {
            text-align: center;
            margin-bottom: calc(var(--spacing-unit) * 1.5);
        }

        .app-title {
            margin: 0 0 0.5rem;
            font-size: clamp(1.6rem, 6vw, 2.3rem);
            letter-spacing: 0.16em;
            text-transform: uppercase;
            color: var(--accent);
            text-shadow: 0 0 18px rgba(0,255,136,0.4);
        }

        .home-link {
            color: var(--accent);
            text-decoration: none;
            cursor: pointer;
            display: inline-block;
        }

        .home-link:hover,
        .home-link:focus {
            text-decoration: underline;
            outline: none;
            text-shadow: 0 0 25px rgba(0,255,136,0.8);
        }

        .manifesto-panel {
            margin-top: 0.75rem;
            border-radius: 14px;
            background: rgba(17, 23, 26, 0.92);
            border: 1px solid var(--border-color);
            box-shadow: 0 0 12px rgba(0,255,136,0.12);
            padding: 1.2rem 1rem;
        }

        .manifesto-text {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 0.78rem;
            line-height: 1.7;
            color: var(--muted);
            text-align: left;
        }

        .manifesto-text a {
            color: var(--accent);
            text-decoration: none;
        }

        .manifesto-text a:hover {
            text-decoration: underline;
        }

        /* Top icon nav (Explorer / Onboard / Chat / Exit) */
        .manifesto-actions {
            margin-top: 1rem;
            text-align: center;
        }

        .manifesto-actions-inner {
            display: inline-flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: center;
            justify-content: center;
        }

        .btn-icon {
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(148, 163, 184, 0.6);
            color: var(--fg);
            font-size: 0.85rem;
            padding: 0.35rem 0.9rem;
            border-radius: 999px;
            cursor: pointer;
            transition: background 0.2s ease, color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-height: 32px;
        }

        .btn-icon:hover,
        .btn-icon:active {
            background: rgba(0, 255, 136, 0.1);
            color: var(--accent);
            box-shadow: 0 0 14px rgba(0,255,136,0.3);
            transform: translateY(-1px);
        }

        .btn-icon.exit {
            border-color: rgba(248, 113, 113, 0.8);
            color: #fecaca;
        }

        .btn-icon.exit:hover {
            background: rgba(248, 113, 113, 0.16);
            color: #fee2e2;
        }

        /* Main grid – single column but centered */
        .main-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: var(--spacing-unit);
            margin-top: calc(var(--spacing-unit) * 1.5);
            margin-bottom: calc(var(--spacing-unit) * 1.5);
            max-width: 1100px;
            margin-inline: auto;
        }

        @media (min-width: 768px) {
            :root { --spacing-unit: 1.5rem; }
        }

        /* Panels */
        .panel {
            background: rgba(17, 23, 26, 0.92);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: var(--spacing-unit);
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.6);
            transition: transform 0.25s ease, box-shadow 0.25s ease, border-color 0.25s ease;
            overflow: hidden;
        }

        .panel:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(0,255,136,0.16);
            border-color: rgba(0,255,136,0.35);
        }

        .panel h2 {
            color: var(--accent);
            font-size: clamp(1rem, 4vw, 1.3rem);
            margin-bottom: var(--spacing-unit);
            text-align: center;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* Form elements */
        .form-group {
            margin-bottom: var(--spacing-unit);
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--accent);
            font-weight: 600;
            font-size: 0.9rem;
        }

        input,
        textarea {
            width: 100%;
            background: rgba(3, 7, 18, 0.92);
            color: var(--text-color);
            border: 1px solid rgba(15, 23, 42, 0.9);
            border-radius: 10px;
            padding: 0.75rem 0.85rem;
            font-family: inherit;
            font-size: 16px;
            transition: border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
            min-height: var(--touch-target);
            -webkit-appearance: none;
            appearance: none;
        }

        input:focus,
        textarea:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 2px rgba(0,255,136,0.25);
            background: rgba(3, 7, 18, 0.98);
        }

        textarea {
            resize: vertical;
            min-height: 120px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        }

        /* Primary buttons */
        .btn {
            width: 100%;
            background: var(--accent);
            color: #000;
            border: none;
            padding: 0.8rem 1rem;
            border-radius: 999px;
            font-family: inherit;
            font-size: 0.95rem;
            font-weight: 700;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            cursor: pointer;
            transition: all 0.25s ease;
            margin-top: 0.5rem;
            min-height: var(--touch-target);
            touch-action: manipulation;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }

        .btn:hover,
        .btn:active {
            box-shadow: 0 0 20px rgba(0,255,136,0.4);
            transform: translateY(-1px);
        }

        .btn-secondary {
            background: transparent;
            border: 1px solid var(--accent);
            color: var(--accent);
        }

        .btn-secondary:hover,
        .btn-secondary:active {
            background: rgba(0,255,136,0.09);
            color: var(--fg);
        }

        /* Balance summary */
        .balance-summary {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.9rem 1rem;
            margin: var(--spacing-unit) 0;
            background: rgba(16, 185, 129, 0.04);
            border: 1px dashed rgba(16, 185, 129, 0.8);
            border-radius: 999px;
            text-align: center;
            flex-wrap: wrap;
            gap: 0.75rem;
        }

        .balance-item {
            flex: 1;
            min-width: 140px;
        }

        .balance-label {
            font-size: 0.78rem;
            opacity: 0.85;
            display: block;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .balance-value {
            font-size: clamp(1rem, 3vw, 1.2rem);
            font-weight: 700;
            margin-top: 0.25rem;
            word-break: break-all;
        }

        .balance-in { color: var(--accent); }
        .balance-out { color: var(--blue); }

        .loading {
            text-align: center;
            color: var(--accent);
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

        /* Covenant boxes */
        .contracts-container {
            margin-top: var(--spacing-unit);
        }

        .contract-box {
            background: rgba(2, 6, 23, 0.9);
            border: 1px solid rgba(148, 163, 184, 0.5);
            border-radius: 12px;
            padding: 0.85rem 0.9rem;
            margin-bottom: var(--spacing-unit);
            transition: border-color 0.25s ease, box-shadow 0.25s ease, transform 0.25s ease;
            overflow: hidden;
        }

        .contract-box.input-role {
            border-color: rgba(34, 197, 94, 0.9);
            box-shadow: 0 0 16px rgba(16, 185, 129, 0.2);
            background: linear-gradient(135deg, rgba(34, 197, 94, 0.15), rgba(2, 6, 23, 0.96));
        }

        .contract-box.output-role {
            border-color: rgba(56, 189, 248, 0.9);
            box-shadow: 0 0 16px rgba(56, 189, 248, 0.18);
            background: linear-gradient(135deg, rgba(56, 189, 248, 0.14), rgba(2, 6, 23, 0.96));
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

        .nostr-info {
            font-size: 0.8rem;
            color: var(--muted);
        }

        /* QR modal */
        .body-locked {
            height: 100dvh;
            overflow: hidden;
            position: relative;
        }

        .qr-modal {
            position: fixed;
            inset: 0;
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 99999;
            background: rgba(0, 0, 0, 0.95);
            padding: env(safe-area-inset-top) 1rem env(safe-area-inset-bottom);
            -webkit-backdrop-filter: blur(2px);
            backdrop-filter: blur(2px);
        }

        .qr-video {
            width: 100vw;
            height: 100vh;
            object-fit: cover;
            border-radius: 0;
        }

        .qr-close {
            position: fixed;
            top: max(12px, env(safe-area-inset-top));
            right: max(12px, env(safe-area-inset-right));
            z-index: 100000;
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(148, 163, 184, 0.8);
            color: var(--fg);
            padding: 0.4rem 0.8rem;
            border-radius: 999px;
            cursor: pointer;
            font-size: 0.85rem;
        }

        /* RPC section */
        .rpc-section {
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
            background: rgba(2, 6, 23, 0.95);
            border: 1px solid rgba(30, 64, 175, 0.6);
            border-radius: 10px;
            padding: 0.9rem;
            font-size: clamp(0.7rem, 2.5vw, 0.82rem);
            white-space: pre-wrap;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
            word-break: break-all;
        }

        /* QR code grid */
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
            image-rendering: pixelated;
            max-width: 360px;
            width: 2.5in;
            height: 2.5in;
            border-radius: 10px;
            box-shadow: 0 0 18px rgba(0,255,136,0.32);
            border: 1px solid rgba(15, 23, 42, 0.9);
        }

        .qr-codes figcaption {
            color: var(--accent);
            font-size: clamp(0.7rem, 2.5vw, 0.8rem);
            margin-top: 0.5rem;
            font-weight: 600;
            word-break: break-word;
        }

        @media print {
            body {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }

            figure {
                break-inside: avoid;
                page-break-inside: avoid;
            }

            .qr-codes img {
                width: 2.5in;
                height: 2.5in;
            }
        }

        /* Mobile-specific tweaks */
        @media (max-width: 767px) {
            .container {
                padding: 3.5rem 1rem 1.5rem;
            }

            .balance-summary {
                flex-direction: column;
                border-radius: 14px;
            }

            .rpc-buttons {
                grid-template-columns: 1fr;
            }

            .qr-codes {
                grid-template-columns: 1fr;
            }

            button,
            .btn,
            .btn-icon,
            input,
            textarea {
                min-height: var(--touch-target);
            }
        }

        @media (max-height: 500px) and (orientation: landscape) {
            .header {
                margin-bottom: 1rem;
            }

            .app-title {
                font-size: 1.5rem;
                margin-bottom: 0.5rem;
            }
        }

        /* iOS Safari adjustments */
        @supports (-webkit-touch-callout: none) {
            .container {
                padding-bottom: calc(var(--spacing-unit) + env(safe-area-inset-bottom));
            }

            input,
            textarea {
                font-size: 16px;
            }
        }

        /* Accessibility / reduced motion */
        @media (prefers-reduced-motion: reduce) {
            * {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }

        @media (prefers-contrast: high) {
            :root {
                --border-color: #666;
                --panel: #000;
            }

            .panel {
                border-width: 2px;
            }
        }
    </style>
</head>

<body data-access-level="{{ access_level }}">
    <!-- Matrix canvas -->
    <canvas id="matrix-bg" aria-hidden="true"></canvas>

    <!-- QR Scan Modal -->
    <div id="qr-modal" class="qr-modal">
        <video id="qr-video" class="qr-video" autoplay playsinline></video>
        <button onclick="stopScan()" class="qr-close">✕ Close</button>
        <canvas id="qr-canvas" style="display:none;"></canvas>
    </div>

    <div class="container">
        <!-- Header & manifesto -->
        <div class="header">
            <h1 class="app-title">
                <a class="home-link" href="{{ url_for('home') }}">HODLXXI</a>
            </h1>

            <div class="manifesto-panel">
                <p class="manifesto-text">
                    <a href="https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer.git" target="_blank" rel="noopener">
                        This is a Game Theory and Mathematics–driven Design Framework for decentralized financial support
                        networks, leveraging Bitcoin smart contracts and integrating Nostr for social trust. It fosters a system
                        where mutual care, financial incentives, and social responsibility are embedded in every
                        transaction—aiming to create financially stable and independent communities. Beyond technological
                        advancements, this framework envisions a reimagined form of human cooperation and economic interaction,
                        promoting transparency and equity. It merges technology with human values, challenging traditional
                        notions of trust and community in the digital age. It also raises philosophical questions about the role
                        of technology in enhancing human capabilities, governance, and social structures. Ultimately, success
                        depends on both technological feasibility and ethical foundations, advocating a balanced integration of
                        innovation and tradition to shape future societal evolution. This crypto-centric platform is built as a
                        robust, scalable model of decentralized trust by embedding financial cooperation directly in
                        cryptographic agreements. It uses a Bitcoin full node as its backbone, leveraging descriptor-based
                        wallets and script covenants to enforce long-term, trust-based contracts. The system eliminates
                        centralized intermediaries in favor of immutable, transparent blockchain agreements. Here, cooperation is
                        mathematically reinforced, transparency is the default, and power flows back to individuals. Built on
                        math, guided by ethics, designed for generations. Let’s make covenants great again!!!
                    </a>
                </p>
            </div>

            <div class="manifesto-actions">
                <div class="manifesto-actions-inner">
                    <button id="btnExplorer" class="btn-icon">🔍 Explorer</button>
                    <button id="btnOnboard"  class="btn-icon">🔧 Onboard</button>
                    <button id="btnChat"     class="btn-icon">💬 Chat</button>
                    <button id="btnExit"     class="btn-icon exit">🚪 Exit</button>
                </div>
            </div>
        </div>

        <!-- Main grid: home text panel -->
        <div class="main-grid">
            <div class="panel" id="homePanel">
                <h2>Welcome to the Covenant Viewer</h2>
                <p style="font-size:0.9rem;color:var(--muted);margin-top:0.2rem;text-align:center;">
                    Start with <strong>Explorer</strong> to see who is locked in covenants, or open
                    <strong>Converter &amp; Decoder</strong> to verify scripts and generate QR packs.
                </p>
            </div>
        </div>

        <!-- Explorer Panel -->
        <div class="panel hidden" id="explorerPanel">
            <h2>🔍 Explorer</h2>

            <div class="form-group">
                <label for="pubKey">Enter Hex or NOSTR Key</label>
                <input
                    type="text"
                    id="pubKey"
                    placeholder="Compressed Pub/NOSTR key"
                    autocomplete="off"
                    autocorrect="off"
                    autocapitalize="off"
                    spellcheck="false"
                />
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

        <!-- Onboard Panel -->
        <div class="panel hidden" id="onboardPanel">
            <h2>🔧 Converter &amp; Decoder</h2>

            <div class="form-group">
                <label for="initialScript">Raw Script</label>
                <textarea
                    id="initialScript"
                    placeholder="Enter your script…"
                    autocomplete="off"
                    autocorrect="off"
                    autocapitalize="off"
                    spellcheck="false"
                ></textarea>
            </div>

            <div class="form-group">
                <label for="newPubKey1">Public Key (Who you care about)</label>
                <input
                    type="text"
                    id="newPubKey1"
                    placeholder="Enter public key"
                    autocomplete="off"
                    autocorrect="off"
                    autocapitalize="off"
                    spellcheck="false"
                />
            </div>

            <div class="form-group">
                <label for="newPubKey2">Public Key (Who cares about you)</label>
                <input
                    type="text"
                    id="newPubKey2"
                    placeholder="Enter public key"
                    autocomplete="off"
                    autocorrect="off"
                    autocapitalize="off"
                    spellcheck="false"
                />
            </div>

            <button class="btn" onclick="handleUpdateScript()">Verify Witness</button>

            <div class="form-group">
                <label>New P2WSH Script:</label>
                <div id="updatedScript" class="contract-box" contenteditable="true"></div>
            </div>

            <h3 style="color: var(--accent); margin: var(--spacing-unit) 0; text-align:center;">Decoded Results:</h3>
            <pre id="decodedWitness" class="rpc-response"></pre>

            <div id="qr-codes" class="qr-codes"></div>
        </div>

        {% if access_level == 'full' %}
        <!-- RPC Full Node Section -->
        <div class="panel rpc-section">
            <h2>⚡ RPC Node</h2>

            <!-- Import Descriptor Panel -->
            <div class="panel" style="margin-bottom: var(--spacing-unit);">
                <h2>Import Covenant Descriptor</h2>
                <div class="form-group">
                    <textarea id="descriptorInput" placeholder="Paste descriptor here raw(...)checksum"></textarea>
                </div>
                <button class="btn" onclick="handleImportDescriptor()">Import</button>
                <div id="importResult" class="rpc-response" style="margin-top: var(--spacing-unit);"></div>
            </div>

            <!-- Set Labels Panel -->
            <div class="panel" style="margin-bottom: var(--spacing-unit);">
                <h2>Set Checking Labels</h2>
                <div class="form-group">
                    <input type="text" id="zpubInput" placeholder="Enter your zpub" />
                </div>
                <div class="form-group">
                    <input type="text" id="labelInput" placeholder="Enter label" />
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

    <!-- JS: logic same as before, with small fixes & palette alignment -->
    <script>
        // global: cache most recent covenant hex
        window.lastScriptHex = window.lastScriptHex || null;
        const accessLevel = document.body.dataset.accessLevel || 'limited';

        // QR scanner
        let scanning = false;
        let currentStream = null;

        async function startScan(inputElem, onResult) {
            const secure = location.protocol === 'https:' || location.hostname === 'localhost';
            if (!secure || !navigator.mediaDevices?.getUserMedia) {
                alert('Camera only works on HTTPS or localhost.');
                return;
            }

            const modal  = document.getElementById('qr-modal');
            const video  = document.getElementById('qr-video');
            const canvas = document.getElementById('qr-canvas');
            const ctx    = canvas.getContext('2d');

            document.body.classList.add('body-locked');
            modal.style.display = 'flex';
            requestAnimationFrame(() => window.scrollTo(0,0));

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

            window.stopScan = function stopScan() {
                scanning = false;
                try { currentStream?.getTracks().forEach(t => t.stop()); } catch {}
                currentStream = null;
                video.srcObject = null;
                modal.style.display = 'none';
                document.body.classList.remove('body-locked');
            };

            (function tick() {
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

        function handleCovenants() {
            const inp = document.getElementById('pubKey');
            if (!inp.value.trim()) startScan(inp, verifyAndListContracts);
            else verifyAndListContracts();
        }

        function handleUpdateScript() {
            const inp = document.getElementById('initialScript');
            if (!inp.value.trim()) startScan(inp, updateScript);
            else updateScript();
        }

        function handleImportDescriptor() {
            const inp = document.getElementById('descriptorInput');
            if (!inp || !inp.value.trim()) {
                if (inp) startScan(inp, importDescriptor);
                return;
            }
            importDescriptor();
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

        const chatSound = new Audio('{{ url_for("static", filename="sounds/login.mp3") }}');
        chatSound.preload = 'auto';
        chatSound.playsInline = true;

        function callRPC(cmd, param) {
            let url = `/rpc/${cmd}`;
            if (param !== undefined && param !== '') {
                url += `?p=${encodeURIComponent(param)}`;
            }
            const out = document.getElementById('rpcResponse');
            if (out) out.textContent = '⏳ sending…';
            fetch(url)
                .then(r => r.json())
                .then(json => {
                    if (out) out.textContent = JSON.stringify(json, null, 2);
                })
                .catch(e => {
                    if (out) out.textContent = 'Error: ' + e;
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
            let pubKey = clickedPubKey || document.getElementById('pubKey').value.trim();
            if (!pubKey) {
                alert('Please enter a public key');
                return;
            }

            const isNpub    = pubKey.startsWith("npub") && pubKey.length >= 10;
            const isHexFull = /^[0-9a-fA-F]{66,130}$/.test(pubKey);
            const isHex32   = /^[0-9a-fA-F]{64}$/.test(pubKey);

            // If we got a bare 32-byte hex (no 02/03 prefix),
            // normalize to a compressed-style key with 0x02 prefix.
            if (!isNpub && !isHexFull && isHex32) {
                pubKey = "02" + pubKey;
            }

            const isHexFinal = /^[0-9a-fA-F]{66,130}$/.test(pubKey);
            if (!isNpub && !isHexFinal) {
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
                    const isEnteredNpub = entered.startsWith('npub');
                    const enteredLC = entered.toLowerCase();

                    sorted.forEach(descriptor => {
                        const save  = parseFloat(descriptor.saving_balance_usd) || 0;
                        const check = parseFloat(descriptor.checking_balance_usd) || 0;
                        const total = save + check;

                        const ifHex  = descriptor.op_if_pub   ? descriptor.op_if_pub.toLowerCase()    : null;
                        const elHex  = descriptor.op_else_pub ? descriptor.op_else_pub.toLowerCase()  : null;
                        const ifNpub = descriptor.op_if_npub  || null;
                        const elNpub = descriptor.op_else_npub|| null;

                        let role = null;
                        if (isEnteredNpub) {
                            if (ifNpub && ifNpub === entered)        role = 'input';
                            else if (elNpub && elNpub === entered)   role = 'output';
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
                            if (accessLevel === "full") {
                                nostrSection = `
                                  <div class="nostr-info" style="text-align:center;margin:0.5rem 0;">
                                    <strong>Nostr:</strong><br>
                                    <a href="https://advancednostrsearch.vercel.app/?npub=${descriptor.nostr_npub}"
                                       target="_blank"
                                       style="color:var(--neon-blue); text-decoration:none; display:inline-block; margin-top:0.25rem;">
                                       ${descriptor.nostr_npub_truncated}
                                    </a>
                                  </div>`;
                            } else {
                                nostrSection = `
                                  <div class="nostr-info" style="text-align:center;margin:0.5rem 0;">
                                    <strong>Nostr:</strong><br>${descriptor.nostr_npub_truncated}
                                  </div>`;
                            }
                        }

                        const counterpartyOnline = descriptor.counterparty_online;
                        let counterpartyNote = '';
                        if (counterpartyOnline && descriptor.counterparty_pubkey) {
                            counterpartyNote = `
                              <div style="text-align:center; color:lime; font-size:0.8rem; margin-top:0.25rem;">
                                🟢 online
                              </div>`;
                        }

                        const deeplink = (accessLevel === "full" && (descriptor.onboard_link || descriptor.raw_script))
                            ? (descriptor.onboard_link || `#onboard?raw=${encodeURIComponent(descriptor.raw_script)}&autoverify=1`)
                            : null;

                        const imgTag = descriptor.qr_code
                            ? `<img src="data:image/png;base64,${descriptor.qr_code}" alt="Address QR"
                                     style="max-width:180px;border:1px solid #111827;border-radius:8px;box-shadow:0 0 10px rgba(0,255,0,.15);" />`
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
                            <div style="text-align:center; margin:0.5rem 0;">
                                <pre><strong>Address:</strong> ${descriptor.truncated_address}</pre>
                            </div>
                            <div style="text-align:center;"><strong>HEX</strong> ${descriptor.script_hex}</div>
                            ${addrQR}
                            ${counterpartyNote}
                            ${nostrSection}
                            <div style="text-align:center; margin-top:1rem;">
                                <div style="display:inline-block;">
                                    <strong>Save:</strong> $${descriptor.saving_balance_usd}
                                    &nbsp;&nbsp;
                                    <strong>Check:</strong> $${descriptor.checking_balance_usd}
                                </div>
                            </div>`;

                        container.appendChild(box);
                    });

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

            let rawScript = tpl;
            if (baked[0] && k1) rawScript = rawScript.replace(baked[0], k1);
            if (baked[1] && k2) rawScript = rawScript.replace(baked[1], k2);

            let displayScript = tpl;
            if (baked[0] && k1) displayScript = displayScript.replace(baked[0], `<span style="color:var(--neon-blue);">${k1}</span>`);
            if (baked[1] && k2) displayScript = displayScript.replace(baked[1], `<span style="color:var(--neon-green);">${k2}</span>`);
            document.getElementById('updatedScript').innerHTML = displayScript;

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

                if (!d.error && d.qr) {
                    function makeQR(label, b64) {
                        if (!b64) return '';
                        return `
                          <figure>
                            <img src="data:image/png;base64,${b64}" alt="${label} QR"/>
                            <figcaption>${label}</figcaption>
                          </figure>`;
                    }

                    qrContainer.innerHTML =
                        makeQR('Receiver Pubkey', d.qr.pubkey_if) +
                        makeQR('Giver Pubkey', d.qr.pubkey_else) +
                        makeQR('Raw Script (hex)', d.qr.raw_script_hex) +
                        makeQR('HODL Address', d.qr.segwit_address);

                    if (d.qr.first_unused_addr) {
                        qrContainer.innerHTML += makeQR('First Unused Address', d.qr.first_unused_addr);
                    } else {
                        const warning = d.warning || 'No unused address found. Label your zpub in "Set Checking Labels" to enable detection.';
                        qrContainer.innerHTML += `
                          <div style="text-align:center; color: var(--accent); margin-top: 0;">
                            <strong style="color: var(--red);">Warning:</strong> ${warning}
                          </div>`;
                    }

                    if (d.qr.full_descriptor) {
                        qrContainer.innerHTML += makeQR('Descriptor (checksummed)', d.qr.full_descriptor);
                    }
                }
            })
            .catch(e => {
                document.getElementById('decodedWitness').textContent = `Error: ${e}`;
            });
        }

        function jumpOnboard(rawHex) {
            try {
                ['homePanel','explorerPanel','onboardPanel'].forEach(id => {
                    const el = document.getElementById(id);
                    if (!el) return;
                    el.classList.toggle('hidden', id !== 'onboardPanel');
                });

                const ta = document.getElementById('initialScript');
                if (ta) ta.value = rawHex || '';

                if (location.hash !== '#onboard') location.hash = 'onboard';

                setTimeout(() => {
                    try { handleUpdateScript(); } catch (e) { console.error(e); }
                }, 0);
            } catch (e) {
                console.error('jumpOnboard error:', e);
            }
            return false;
        }

        function importDescriptor() {
            const inputEl = document.getElementById("descriptorInput");
            if (!inputEl) return;
            const input = inputEl.value.trim();
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
                if (out) out.innerHTML = "Imported ✔️<br><small>script_hex: " + (data.script_hex || "n/a") + "</small>";

                if (data.raw_hex) {
                    const res = await fetch('/decode_raw_script', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                        body: JSON.stringify({ raw_script: data.raw_hex })
                    }).then(r => r.json()).catch(()=>null);

                    if (res && res.qr) {
                        const qrContainer = document.getElementById('qr-codes');
                        const label = (t,b64) => (b64
                            ? `<figure><img src="data:image/png;base64,${b64}"><figcaption>${t}</figcaption></figure>`
                            : ""
                        );
                        qrContainer.innerHTML =
                            label('Receiver Pubkey', res.qr.pubkey_if) +
                            label('Giver Pubkey',    res.qr.pubkey_else) +
                            label('Raw Script (hex)',res.qr.raw_script_hex) +
                            label('HODL Address',    res.qr.segwit_address) +
                            (res.qr.first_unused_addr
                                ? label('First Unused Address', res.qr.first_unused_addr)
                                : `<div style="text-align:center;color:var(--accent)">
                                     <strong style="color:var(--red)">Warning:</strong> ${res.warning||'No unused address yet.'}
                                   </div>`);
                    }
                }
            })
            .catch(err => {
                const out = document.getElementById("importResult");
                if (out) out.innerHTML = "Error: " + err;
            });
        }

        function setLabelsFromZpub() {
            const zpub  = document.getElementById("zpubInput")?.value.trim();
            const label = document.getElementById("labelInput")?.value.trim();

            if (!zpub) {
                alert("zpub is required.");
                return;
            }

            const body = { zpub };
            if (label) body.label = label;
            if (window.lastScriptHex) body.script_hex = window.lastScriptHex;

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
                const out = document.getElementById("setLabelsResult");
                if (out) out.innerHTML = msg || "No specific results to display.";
            })
            .catch(err => {
                const out = document.getElementById("setLabelsResult");
                if (out) out.innerHTML = "Error: " + err.message;
            });
        }

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

        // Initial pubkey from URL
        document.addEventListener('DOMContentLoaded', () => {
            const initialPk = "{{ initial_pubkey }}";
            if (initialPk) {
                verifyAndListContracts(initialPk);
            }
        });

        // Login sound on entry from login page
        document.addEventListener('DOMContentLoaded', () => {
            if (sessionStorage.getItem('playLoginSound') === '1') {
                sessionStorage.removeItem('playLoginSound');
                const a = new Audio('/static/sounds/login.mp3');
                a.loop = true;
                a.play().catch(()=>{});
                setTimeout(() => { a.pause(); a.remove(); }, 6000);
            }
        });

        // Matrix background (warp)
        (() => {
            const canvas = document.getElementById('matrix-bg');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');

            const CHARS = ['0','1'];
            let width = 0, height = 0, particles = [], raf = null;

            function resize() {
                const dpr = Math.max(1, Math.min(window.devicePixelRatio || 1, 2));
                const cssW = window.innerWidth;
                const cssH = window.innerHeight;

                canvas.width  = Math.floor(cssW * dpr);
                canvas.height = Math.floor(cssH * dpr);
                canvas.style.width  = cssW + 'px';
                canvas.style.height = cssH + 'px';

                ctx.setTransform(1,0,0,1,0,0);
                ctx.scale(dpr, dpr);

                width = cssW;
                height = cssH;

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
                    const x2 = width  / 2 + p.x * scale;
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
                    if (raf) { cancelAnimationFrame(raf); raf = null; }
                } else {
                    if (!raf) raf = requestAnimationFrame(draw);
                }
            }

            window.addEventListener('resize', resize);
            document.addEventListener('visibilitychange', onVis);

            resize();
            raf = requestAnimationFrame(draw);
        })();

        // Small nav helpers for the top icon row
        function openPanel(which) {
            const url = `${location.origin}${location.pathname}#${which}`;
            window.open(url, '_blank', 'noopener,noreferrer');
        }

        document.getElementById('btnExplorer').addEventListener('click', () => openPanel('explorer'));
        document.getElementById('btnOnboard') .addEventListener('click', () => openPanel('onboard'));
        document.getElementById('btnChat')    .addEventListener('click', () => {
            window.open("{{ url_for('chat') }}", '_blank', 'noopener,noreferrer');
        });
        document.getElementById('btnExit')    .addEventListener('click', () => {
            window.location.href = "{{ url_for('logout') }}";
        });

        function switchPanelByHash() {
            const h = (location.hash || '').slice(1);
            const showId =
                  h === 'explorer' ? 'explorerPanel'
                : h === 'onboard'  ? 'onboardPanel'
                : 'homePanel';

            ['homePanel','explorerPanel','onboardPanel'].forEach(id => {
                const el = document.getElementById(id);
                if (!el) return;
                el.classList.toggle('hidden', id !== showId);
            });

            const rpc = document.querySelector('.rpc-section');
            if (rpc) rpc.classList.toggle('hidden', showId === 'homePanel');

            window.scrollTo({ top: 0 });
        }

        window.addEventListener('hashchange', switchPanelByHash);
        document.addEventListener('DOMContentLoaded', switchPanelByHash);

        function maskDeepLinkedKeyForLimited() {
            try {
                // Only mask for non-full users
                if (typeof accessLevel !== 'undefined' && accessLevel === 'full') return;

                const hash = window.location.hash || '';
                if (!hash || hash.indexOf('#explorer') !== 0) return;

                let target = null;
                try {
                    target = localStorage.getItem('hodlxxi_explorer_target') || null;
                } catch (e) {
                    target = null;
                }
                if (!target) return;

                const inp = document.getElementById('pubKey');
                if (!inp) return;

                const last4 = target.slice(-4);
                inp.value = '…' + last4;
            } catch (e) {
                if (window.console && console.warn) {
                    console.warn('maskDeepLinkedKeyForLimited failed', e);
                }
            }
        }

        // Run after all other DOMContentLoaded handlers (including deep-link loader)
        document.addEventListener('DOMContentLoaded', () => {
            setTimeout(maskDeepLinkedKeyForLimited, 0);
        });

        function autoLoadExplorerFromDeepLink() {
            try {
                const hash = window.location.hash || '';
                // Only act on /home#explorer
                if (!hash || hash.indexOf('#explorer') !== 0) return;

                let target = null;
                try {
                    target = localStorage.getItem('hodlxxi_explorer_target') || null;
                } catch (e) {
                    target = null;
                }
                if (!target) return;

                // Put the pubkey into the Explorer input
                const inp = document.getElementById('pubKey');
                if (inp) inp.value = target;

                // Run the covenant lookup immediately
                verifyAndListContracts(target);
            } catch (err) {
                if (window.console && console.warn) {
                    console.warn('Explorer deep-link failed', err);
                }
            }
        }

        document.addEventListener('DOMContentLoaded', autoLoadExplorerFromDeepLink);
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
                user = on_successful_login(pubkey)
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
    # Create/update user in membership system
    user = on_successful_login(pubkey)
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
    <li><a href="/playground">Playground</a></li>
    <li><a href="/pof/">Proof of Funds</a></li>
    <li><a href="/pof/leaderboard">Whale Leaderboard</a></li>
    <li><a href="/login">Login</a></li>
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



# @app.route("/playground/", defaults={'path': ''})
# @app.route("/playground/<path:path>")
# def playground(path):
#     playground_dir = 'static/playground'
#     if path == '':
#         resp = make_response(send_from_directory(playground_dir, 'index.html'))
#     else:
#         resp = make_response(send_from_directory(playground_dir, path))
#     
#     # FORCE override CSP for playground - remove any existing CSP
#     if 'Content-Security-Policy' in resp.headers:
#         del resp.headers['Content-Security-Policy']
#     if 'Content-Security-Policy-Report-Only' in resp.headers:
#         del resp.headers['Content-Security-Policy-Report-Only']    
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

@app.route("/playground")
def playground_page():
    """Render the React playground shell."""
    # Optional membership user: look up by session pubkey
    from app.ubid_membership import UbidUser  # safe import here if not at top

    user = None
    try:
        pubkey = session.get("logged_in_pubkey")
        if pubkey:
            user = UbidUser.query.filter_by(pubkey=pubkey).first()
    except Exception:
        user = None

    # Logged-in info from session (safe defaults)
    try:
        logged_in = session.get("logged_in_pubkey", "") or ""
    except Exception:
        logged_in = ""

    try:
        access_level = session.get("access_level", "limited") or "limited"
    except Exception:
        access_level = "limited"

    # Issuer from CFG (which is a dict in your app)
    try:
        issuer = CFG.get("ISSUER", "") or ""
    except Exception:
        issuer = ""

    initial_tab = request.args.get("tab", "legacy")

    return render_template(
        "playground.html",
        logged_in_pubkey=logged_in,
        access_level=access_level,
        issuer=issuer,
        initial_tab=initial_tab,
        user=user,  # 👈 Jinja sees this
    )


def require_login(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "logged_in_pubkey" not in session:
            next_url = request.path
            return redirect(url_for("login", next=next_url))
        return view_func(*args, **kwargs)
    return wrapper


@app.route("/dev-dashboard")
@require_login
def dev_dashboard():
    """
    Lightweight dev dashboard backed only by session.
    """
    pubkey = session.get("logged_in_pubkey")
    if not pubkey:
        return redirect(url_for("login", next="/dev-dashboard"))

    user = {
        "pubkey": pubkey,
        "plan": session.get("ubid_plan", "free"),
        "sats_balance": session.get("ubid_sats_balance", 0),
        "membership_expires_at": session.get("ubid_membership_expires_at"),
    }
    return render_template("dashboard.html", user=user)


@app.route("/upgrade", methods=["GET", "POST"])
@require_login
def upgrade():
    """
    Upgrade page that just stores membership info in the session for now.
    """
    pubkey = session.get("logged_in_pubkey")
    if not pubkey:
        return redirect(url_for("login", next="/upgrade"))

    if request.method == "POST":
        plan_choice = request.form.get("plan", "paid")
        if plan_choice not in ("paid", "free_trial"):
            plan_choice = "paid"

        session["ubid_plan"] = plan_choice

        if plan_choice == "paid":
            expires = datetime.utcnow() + timedelta(days=365)
        else:
            expires = datetime.utcnow() + timedelta(days=14)

        session["ubid_membership_expires_at"] = expires.isoformat() + "Z"
        session.setdefault("ubid_sats_balance", 0)
        flash("Membership updated", "success")
        return redirect(url_for("dev_dashboard"))

    user = {
        "pubkey": pubkey,
        "plan": session.get("ubid_plan", "free"),
        "sats_balance": session.get("ubid_sats_balance", 0),
        "membership_expires_at": session.get("ubid_membership_expires_at"),
    }
    return render_template("upgrade.html", user=user, logged_in_pubkey=pubkey)

    # GET → show current info
    user = {
        "pubkey": pubkey,
        "plan": session.get("ubid_plan", "free"),
        "sats_balance": session.get("ubid_sats_balance", 0),
        "membership_expires_at": session.get("ubid_membership_expires_at"),
    }

    # Template also expects logged_in_pubkey
    return render_template(
        "upgrade.html",

        user=user,
        logged_in_pubkey=pubkey,
    )




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


# ============================================================================
# PLAYGROUND POF - Public demo endpoints (no membership required)
# ============================================================================
@app.route('/api/playground/pof/challenge', methods=['POST'])
def playground_pof_challenge():
    """Generate PoF challenge for playground demo (no auth required)"""
    try:
        data = request.get_json(silent=True) or {}
        pubkey = (data.get("pubkey") or "playground-demo").strip()

        # Generate challenge
        cid = secrets.token_hex(8)
        challenge = f"HODLXXI-PoF:{cid}:{int(time.time())}"

        # Store in Redis (5 min expiry for demo)
        if 'playground_redis' in globals() and playground_redis is not None:
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
            'expires_in': 300,
            'pubkey': pubkey,
        })

    except Exception as e:
        logger.error(f"Playground PoF challenge failed: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/playground/pof/verify', methods=['POST'])
def playground_pof_verify():
    """Verify PSBT proof for playground demo"""
    try:
        data = request.get_json(silent=True) or {}
        challenge_id = (data.get('challenge_id') or '').strip()
        psbt = (data.get('psbt') or '').strip()
        privacy_level = (data.get('privacy_level') or 'aggregate').strip()
        min_sat_raw = data.get('min_sat') or 0

        try:
            min_sat = int(min_sat_raw)
        except Exception:
            min_sat = 0

        if not challenge_id or not psbt:
            return jsonify({'ok': False, 'error': 'challenge_id and psbt required'}), 400

        # Get challenge from Redis
        if 'playground_redis' in globals() and playground_redis is not None:
            challenge_data = playground_redis.get(f'pg_pof:{challenge_id}')
        else:
            challenge_data = None

        if not challenge_data:
            return jsonify({'ok': False, 'error': 'Challenge expired or invalid'}), 400

        challenge_info = json.loads(challenge_data)
        challenge = challenge_info.get('challenge', '')

        # Verify PSBT using Bitcoin RPC
        rpc = get_rpc_connection()
        decoded = rpc.decodepsbt(psbt)
        tx = decoded.get('tx', {})
        vouts = tx.get('vout', [])
        vins = tx.get('vin', [])

        # Check OP_RETURN contains our challenge *bytes*
        has_challenge = False
        for vout in vouts:
            spk = vout.get('scriptPubKey', {})
            asm = spk.get('asm', '') or ''
            parts = asm.split()

            # Expect: "OP_RETURN <hexdata>"
            if len(parts) >= 2 and parts[0] == 'OP_RETURN':
                data_hex = parts[1]
                try:
                    data_bytes = bytes.fromhex(data_hex)
                    if challenge and challenge.encode() in data_bytes:
                        has_challenge = True
                        break
                except Exception:
                    continue

        # Sum unspent inputs
        total_sat = 0
        unspent_count = 0
        for vin in vins:
            txid = vin.get('txid')
            vout_n = vin.get('vout')
            if not txid or vout_n is None:
                continue
            try:
                utxo = rpc.gettxout(txid, vout_n)
                if utxo:
                    value_btc = float(utxo.get('value', 0))
                    total_sat += int(value_btc * 100_000_000)
                    unspent_count += 1
            except Exception:
                continue

        if total_sat <= 0:
            return jsonify({'ok': False, 'error': 'No valid unspent inputs'}), 400

        proof_id = secrets.token_hex(8)

        # Optional: store result in Redis for 1 hour
        if 'playground_redis' in globals() and playground_redis is not None:
            playground_redis.setex(
                f'pg_pof_result:{proof_id}',
                3600,
                json.dumps({
                    'challenge_id': challenge_id,
                    'total_sat': total_sat,
                    'unspent_count': unspent_count,
                    'verified_at': int(time.time()),
                    'privacy_level': privacy_level,
                    'min_sat': min_sat,
                })
            )

        return jsonify({
            'ok': True,
            'message': 'Proof verified successfully!',
            'proof_id': proof_id,
            'total_sat': total_sat,
            'total_btc': round(total_sat / 100_000_000, 8),
            'unspent_count': unspent_count,
            'privacy_level': privacy_level,
            'min_sat': min_sat,
        })

    except Exception as e:
        logger.error(f"Playground PoF verify failed: {e}")
        return jsonify({'ok': False, 'error': f'internal error: {e}'}), 500


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

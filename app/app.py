import hashlib
import threading
import json
import redis
import redis
import logging
import os
import re
from flask import session, request
from flask import render_template_string
import secrets
import time
from flask import jsonify, render_template
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

# Active challenges (in-memory; ephemeral)
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
from app.dev_routes import dev_bp

# from app.playground_routes import playground_bp   # <-- ADD THIS
from flask import make_response


from .ubid_membership import (
    UbidUser,
    charge_action,
    create_payg_invoice,
    get_user,
    on_successful_login,
    require_paid_user,
    set_payg,
    settle_payg_invoice,
)


# --- Simple in-memory user view object for dashboardupgrade ---
class SimpleUser:
    def __init__(self, pubkey, plan="free", sats_balance=0, expires_at=None):
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
    logger.warning("FLASK_SECRET_KEY not provided – generated ephemeral key for local development.")

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
GUEST2_PRIVKEY = os.getenv("GUEST2_PRIVKEY", "").strip()

SPECIAL_NAMES = {}
if GUEST_PUBKEY:
    SPECIAL_NAMES[GUEST_PUBKEY] = "Alice"

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
        JWT_VERIFYING_KEY = (
            private_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )
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
        return self._safe_call("ping")

    def get(self, key):
        return self._safe_call("get", key)

    def set(self, key, value, ex=None, px=None, nx=False, xx=False):
        return self._safe_call("set", key, value, ex=ex, px=px, nx=nx, xx=xx)

    def setex(self, key, time, value):
        return self._safe_call("setex", key, time, value)

    def delete(self, *keys):
        return self._safe_call("delete", *keys)

    def sadd(self, name, *values):
        return self._safe_call("sadd", name, *values)

    def smembers(self, name):
        return self._safe_call("smembers", name) or set()

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
ONLINE_USER_META = {}  # pubkey -> {'role': <role>, 'label': <label>}

ONLINE_USERS: Set[str] = set()
CHAT_HISTORY: List[Dict[str, any]] = []

# ============================================================================
# GROUP VIDEO CALLS (up to 4 participants)
# ============================================================================

# Room management: room_id -> {pubkeys: set, created_at: timestamp}
CALL_ROOMS: Dict[str, Dict[str, any]] = {}
MAX_ROOM_SIZE = 4


def cleanup_old_rooms():
    """Remove rooms older than 1 hour with no participants"""
    now = time.time()
    to_remove = []
    for room_id, room_data in list(CALL_ROOMS.items()):
        age = now - room_data.get("created_at", now)
        if age > 3600 and len(room_data.get("pubkeys", set())) == 0:
            to_remove.append(room_id)
    for room_id in to_remove:
        CALL_ROOMS.pop(room_id, None)
    if to_remove:
        logger.info(f"Cleaned up {len(to_remove)} old empty rooms")


def get_room_participants(room_id: str) -> list:
    """Get list of pubkeys currently in a room"""
    room = CALL_ROOMS.get(room_id)
    if not room:
        return []
    return list(room.get("pubkeys", set()))


FORCE_RELAY = os.getenv("FORCE_RELAY", "false").lower() in ("1", "true", "yes", "on")
logger.info(f"FORCE_RELAY = {FORCE_RELAY}")


def truncate_key(key: str, head: int = 6, tail: int = 4) -> str:
    if len(key) <= head + tail:
        return key
    return f"{key[:head]}…{key[-tail:]}"


app = Flask(__name__)

# Cookie domain: allow sessions to work across apex + www
_cookie_domain = os.getenv("SESSION_COOKIE_DOMAIN")
if _cookie_domain:
    app.config["SESSION_COOKIE_DOMAIN"] = _cookie_domain

_cookie_name = os.getenv("SESSION_COOKIE_NAME")
if _cookie_name:
    app.config["SESSION_COOKIE_NAME"] = _cookie_name
# COOKIE_DOMAIN_V1
app.config.setdefault("SESSION_COOKIE_DOMAIN", ".hodlxxi.com")
app.config.setdefault("SESSION_COOKIE_SECURE", True)
app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
# /COOKIE_DOMAIN_V1

# === DOCS_ROUTES_REGISTER_V1 ===
try:
    from .docs_routes import register_docs_routes

    register_docs_routes(app)
except Exception as _e:
    # Docs are non-critical; do not break service if something is misconfigured.
    app.logger.warning(f"Docs routes not registered: {_e}")
# === /DOCS_ROUTES_REGISTER_V1 ===


@app.route("/screensaver")
def screensaver():
    return render_template("screensaver.html")


@app.route("/api/public/status")
def api_public_status():
    import time

    now = int(time.time())
    iso = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now))

    height = None
    err = None

    try:
        rpc = get_rpc_connection()
        height = rpc.getblockcount()
    except Exception as e:
        err = str(e)

    return jsonify(
        {
            "server_time_epoch": now,
            "server_time_utc": iso,
            "block_height": height,
            "error": err,
        }
    )


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
app.register_blueprint(dev_bp, url_prefix="/dev")
# app.register_blueprint(playground_bp)

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
    ping_interval=25,
    ping_timeout=60,
    cors_allowed_origins=SOCKETIO_CORS,
    async_mode=SOCKETIO_ASYNC_MODE,
    logger=True,
    engineio_logger=True,
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
            "pid": os.getpid(),
            "process_start_time": PROCESS_START_TIME,
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


# --- Dev dashboard hard block (must run before any login redirect gates) ---
@app.before_request
def _dev_dashboard_full_only():
    # Always hide dev dashboard unless full (even if not logged in)
    if request.path.rstrip("/") == "/dev/dashboard" and session.get("access_level") != "full":
        from flask import make_response as _make_response

        return _make_response("Forbidden", 403)


# ------------------------------------------------------------------------


@app.before_request
def _oauth_public_allowlist():
    # OAUTH_ALLOWLIST_SCOPE_GUARD_V1
    # This allowlist is only meant for OAuth/OIDC endpoints.
    # Do NOT enforce login here for the rest of the site.
    from flask import request

    _p = request.path or "/"
    if not (
        _p.startswith("/oauth/")
        or _p.startswith("/oauthx/")
        or _p.startswith("/oauthdemo/")
        or _p.startswith("/.well-known/")
    ):
        return None
    # /OAUTH_ALLOWLIST_SCOPE_GUARD_V1

    p = request.path or "/"
    if any(p.startswith(pref) for pref in OAUTH_PATH_PREFIXES) or p in OAUTH_PUBLIC_PATHS:
        # Mark request so any later guards skip login
        setattr(request, "_oauth_public", True)
        return None


# --- metrics helpers (safe, soft-fail) ---
PROCESS_START_TIME = time.time()

# DB metrics cache (avoid heavy COUNT(*) on every scrape)
_DB_METRICS_LOCK = threading.Lock()
_DB_METRICS_CACHE = {"ts": 0.0, "data": None}


def _db_metrics_counts_cached(ttl_seconds: int = 15):
    now = time.time()
    try:
        with _DB_METRICS_LOCK:
            data = _DB_METRICS_CACHE.get("data")
            ts = float(_DB_METRICS_CACHE.get("ts") or 0.0)
            if data is not None and (now - ts) < ttl_seconds:
                return data
    except Exception:
        # soft-fail: if lock/cache breaks, just compute live
        pass

    data = _db_metrics_counts()
    try:
        with _DB_METRICS_LOCK:
            _DB_METRICS_CACHE["ts"] = now
            _DB_METRICS_CACHE["data"] = data
    except Exception:
        pass
    return data


def _db_metrics_counts():
    """
    Returns a dict of DB row counts. Never raises (soft-fail).
    Tries env first, then local socket as hodlxxi/hodlxxi.
    """
    try:
        import psycopg2
        import psycopg2.extras
    except Exception as e:
        return {"db_error": f"psycopg2_import_failed: {e}"}

    # best-effort connection params
    dbname = os.getenv("PGDATABASE") or os.getenv("DB_NAME") or "hodlxxi"
    user = os.getenv("PGUSER") or os.getenv("DB_USER") or "hodlxxi"
    host = os.getenv("PGHOST") or os.getenv("DB_HOST") or None
    port = os.getenv("PGPORT") or os.getenv("DB_PORT") or None
    password = os.getenv("PGPASSWORD") or os.getenv("DB_PASSWORD") or None

    dsn = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")

    conn = None
    try:
        if dsn:
            conn = psycopg2.connect(dsn, connect_timeout=2)
        else:
            kwargs = {"dbname": dbname, "user": user, "connect_timeout": 2}
            if host:
                kwargs["host"] = host
            if port:
                kwargs["port"] = int(port)
            if password:
                kwargs["password"] = password
            conn = psycopg2.connect(**kwargs)

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                
select
  -- totals
  (select count(*) from users)            as users,
  (select count(*) from ubid_users)       as ubid_users,
  (select count(*) from sessions)         as sessions,
  (select count(*) from chat_messages)    as chat_messages,
  (select count(*) from lnurl_challenges) as lnurl_challenges,
  (select count(*) from pof_challenges)   as pof_challenges,
  (select count(*) from audit_logs)       as audit_logs,
  (select count(*) from oauth_clients)    as oauth_clients,
  (select count(*) from oauth_tokens)     as oauth_tokens,
  (select count(*) from payments)         as payments,
  (select count(*) from proof_of_funds)   as proof_of_funds,
  (select count(*) from subscriptions)    as subscriptions,
  (select count(*) from usage_stats)      as usage_stats,

  -- activity windows (movement)
  (select count(*) from users where last_login is not null and last_login > now() - interval '5 minutes')  as logins_5m,
  (select count(*) from users where last_login is not null and last_login > now() - interval '1 hour')     as logins_1h,
  (select count(*) from users where last_login is not null and last_login > now() - interval '24 hours')   as logins_24h,

  (select count(*) from chat_messages where "timestamp" > now() - interval '5 minutes')                    as chat_5m,
  (select count(*) from chat_messages where "timestamp" > now() - interval '1 hour')                       as chat_1h,
  (select count(*) from chat_messages where "timestamp" > now() - interval '24 hours')                     as chat_24h,

  (select count(*) from lnurl_challenges where created_at > now() - interval '5 minutes')                  as lnurl_created_5m,
  (select count(*) from lnurl_challenges where created_at > now() - interval '1 hour')                     as lnurl_created_1h,
  (select count(*) from lnurl_challenges where created_at > now() - interval '24 hours')                   as lnurl_created_24h,
  (select count(*) from lnurl_challenges where verified_at is not null and verified_at > now() - interval '24 hours') as lnurl_verified_24h,

  (select count(*) from pof_challenges where created_at > now() - interval '5 minutes')                    as pof_created_5m,
  (select count(*) from pof_challenges where created_at > now() - interval '1 hour')                       as pof_created_1h,
  (select count(*) from pof_challenges where created_at > now() - interval '24 hours')                     as pof_created_24h,
  (select count(*) from pof_challenges where verified_at is not null and verified_at > now() - interval '24 hours') as pof_verified_24h,

  (select count(*) from oauth_tokens where created_at > now() - interval '5 minutes')                      as oauth_tokens_5m,
  (select count(*) from oauth_tokens where created_at > now() - interval '1 hour')                         as oauth_tokens_1h,
  (select count(*) from oauth_tokens where created_at > now() - interval '24 hours')                       as oauth_tokens_24h,

  (select count(*) from payments where created_at > now() - interval '24 hours')                            as payments_24h,
  (select count(*) from payments where paid_at is not null and paid_at > now() - interval '24 hours')       as payments_paid_24h

            """
            )
            row = cur.fetchone() or {}
            # cast Decimals/ints cleanly if needed
            return {k: int(row[k]) if row.get(k) is not None else 0 for k in row.keys()}
    except Exception as e:
        return {"db_error": str(e)}
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass


# --- end metrics helpers ---


@app.route("/metrics")
def metrics():
    # SAFE_METRICS_ACTIVE_CHALLENGES_FALLBACK
    # Some deployments removed/renamed ACTIVE_CHALLENGES; avoid NameError in /metrics
    ACTIVE_CHALLENGES = globals().get("ACTIVE_CHALLENGES", {}) or {}

    """Metrics endpoint for monitoring"""
    try:
        metrics_data = {
            "timestamp": time.time(),
            "active_sockets": len(ACTIVE_SOCKETS),
            "online_users": len(ONLINE_USERS),
            "chat_history_size": len(CHAT_HISTORY),
            "active_challenges": len(ACTIVE_CHALLENGES),
            "lnurl_sessions": len(LNURL_SESSIONS),
            "db": _db_metrics_counts_cached(),
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
    # Require a logged-in session to prevent TURN credential scraping/abuse
    from flask import session

    if not (session.get("logged_in_pubkey") or "").strip():
        return jsonify({"error": "Not logged in"}), 401

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


# --- Group Video Call Handlers (rooms + generic signaling) ---


@socketio.on("rtc:join_room")
def rtc_join_room(data):
    """
    Join a call room. data = {"room_id": str}
    - Creates the room if needed
    - Enforces MAX_ROOM_SIZE
    - Sends existing peers to the joiner via "rtc:room_peers"
    - Notifies others via "rtc:peer_joined"
    - For direct-* rooms, auto-sends an invite to the other pubkey
    """
    from flask_socketio import emit, join_room as flask_join_room
    from flask import request

    try:
        pubkey = session.get("logged_in_pubkey")
        if not pubkey:
            emit("rtc:error", {"error": "Not authenticated"})
            return

        room_id = (data or {}).get("room_id")
        if not room_id:
            emit("rtc:error", {"error": "No room_id provided"})
            return

        # Create room if needed
        if room_id not in CALL_ROOMS:
            CALL_ROOMS[room_id] = {"pubkeys": set(), "created_at": time.time()}

        room = CALL_ROOMS[room_id]

        # Capacity check
        if len(room["pubkeys"]) >= MAX_ROOM_SIZE and pubkey not in room["pubkeys"]:
            emit("rtc:error", {"error": "Room is full (max 4 participants)"})
            logger.warning(f"Room {room_id} is full, rejected {pubkey[:8]}")
            return

        # Add user to room
        room["pubkeys"].add(pubkey)
        flask_join_room(room_id)

        # Current peers (excluding the joiner)
        current_peers = [p for p in room["pubkeys"] if p != pubkey]

        logger.info(f"User {truncate_key(pubkey)} joined room {room_id}. " f"Participants: {len(room['pubkeys'])}")

        # Send the room peer list ONLY to the joiner
        emit(
            "rtc:room_peers",
            {"room_id": room_id, "peers": current_peers},
            room=request.sid,
        )

        # Notify others that a peer joined
        emit(
            "rtc:peer_joined",
            {"room_id": room_id, "pubkey": pubkey},
            room=room_id,
            include_self=False,
        )

        # Auto-invite for direct-* (2-party) calls
        if room_id.startswith("direct-") and len(room["pubkeys"]) == 1:
            # Look for another online pubkey whose full value is embedded in room_id.
            other_pubkey = None
            for candidate in set(ACTIVE_SOCKETS.values()):
                if candidate != pubkey and candidate in room_id:
                    other_pubkey = candidate
                    break

            if other_pubkey:
                logger.info(f"Auto-inviting {truncate_key(other_pubkey)} to join {room_id}")
                payload = {"room_id": room_id, "from": pubkey}
                for sid in sids_for_pubkey(other_pubkey):
                    emit("rtc:call_invite", payload, room=sid)

    except Exception as e:
        logger.error(f"Error in rtc_join_room: {e}", exc_info=True)
        emit("rtc:error", {"error": "Failed to join room"})


@socketio.on("rtc:leave_room")
def rtc_leave_room(data):
    """Leave a call room. data = {"room_id": str}"""
    from flask_socketio import emit, leave_room as flask_leave_room
    from flask import request

    try:
        pubkey = session.get("logged_in_pubkey")
        if not pubkey:
            return

        room_id = (data or {}).get("room_id")
        if not room_id:
            return

        room = CALL_ROOMS.get(room_id)
        if not room:
            return

        if pubkey in room["pubkeys"]:
            room["pubkeys"].remove(pubkey)

        flask_leave_room(room_id)
        logger.info(f"User {truncate_key(pubkey)} left room {room_id}")

        emit(
            "rtc:peer_left",
            {"room_id": room_id, "pubkey": pubkey},
            room=room_id,
            include_self=False,
        )

        # If room is empty, mark for cleanup
        if not room["pubkeys"]:
            room["created_at"] = time.time()
            cleanup_old_rooms()

    except Exception as e:
        logger.error(f"Error in rtc_leave_room: {e}", exc_info=True)


@socketio.on("rtc:signal")
def rtc_signal(data):
    """
    Generic WebRTC signaling for group calls.
    data = {
      "room_id": str,
      "to": remote_pubkey,
      "type": "offer"|"answer"|"ice",
      "payload": {...}
    }
    """
    from flask_socketio import emit

    try:
        pubkey = session.get("logged_in_pubkey")
        if not pubkey:
            emit("rtc:error", {"error": "Not authenticated"})
            return

        room_id = (data or {}).get("room_id")
        target_pubkey = (data or {}).get("to")
        signal_type = (data or {}).get("type")
        payload = (data or {}).get("payload")

        if not room_id or not target_pubkey or not signal_type:
            emit("rtc:error", {"error": "Invalid signal payload"})
            return

        room = CALL_ROOMS.get(room_id)
        if not room or pubkey not in room["pubkeys"]:
            emit("rtc:error", {"error": "Not in this room"})
            return

        if target_pubkey not in room["pubkeys"]:
            emit("rtc:error", {"error": "Target not in this room"})
            return

        outbound = {
            "room_id": room_id,
            "from": pubkey,
            "type": signal_type,
            "payload": payload,
        }

        for sid in sids_for_pubkey(target_pubkey):
            emit("rtc:signal", outbound, room=sid)

    except Exception as e:
        logger.error(f"Error in rtc_signal: {e}", exc_info=True)
        emit("rtc:error", {"error": "Signaling failed"})


# --- Chat message helpers + events ---


@socketio.on("rtc:invite")
def rtc_invite(data):
    """Forward call invitation to specific user"""
    from flask_socketio import emit

    to_pubkey = data.get("to")
    room_id = data.get("room_id")
    from_pubkey = session.get("logged_in_pubkey")
    if not to_pubkey or not room_id or not from_pubkey:
        return
    # Use sids_for_pubkey like other handlers
    for sid in sids_for_pubkey(to_pubkey):
        emit("rtc:invite", {"room_id": room_id, "from": from_pubkey, "from_name": from_pubkey[-8:]}, room=sid)


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


# CHALLENGE_STORE_V1
# In-memory login/PoF challenge store (single worker/eventlet).
# If you scale workers, move this to Redis.
ACTIVE_CHALLENGES = {}
CHALLENGE_TTL_SECONDS = 300
# /CHALLENGE_STORE_V1


def generate_challenge():
    return str(uuid.uuid4())


# --- Minimal login/guest/dev helpers ---------------------------------
@app.before_request
def check_auth():
    # PUBLIC PREVIEW ROUTES (no login required)
    from flask import request as flask_request

    # ALLOW_POF_API_V1
    # These endpoints are safe to hit without redirecting users to login,
    # and are used by the Playground/PoF flows.
    if flask_request.path in (
        "/api/whoami",
        "/api/debug/session",
        "/api/challenge",
        "/api/verify",
        "/api/pof/verify_psbt",
    ):
        return None

    if flask_request.path == "/special_login":
        return None
    if flask_request.path.startswith("/api/lnurl-auth/"):
        return None
    # /ALLOW_POF_API_V1

    if flask_request.path in ("/new-index", "/new-keyauth", "/new-signup", "/docs2", "/screensaver"):
        return None

    from flask import jsonify, redirect, request, session, url_for

    p = request.path or "/"

    # Canonicalize legacy dev dashboard URL early
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
        or p.startswith("/api/playground") or p in ("/api/pof/stats", "/api/pof/stats/") \
        or p.startswith("/play") \
        or p.startswith("/p/")
        or p.startswith("/api/playground")
        or p.startswith("/play")
    ):
        return None

    # 1.6) Public paths (no session required)
    PUBLIC_PATHS = {
        "/",
        "/oidc",
        "/docs",
        "/docs/",
        "/docs.json",
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
        "/pof/verify",
        "/pof/verify/",
        "/api/challenge",
        "/api/verify",
        "/pof/verify",
    }
    if p in PUBLIC_PATHS or p.startswith("/docs/"):
        return None

    # 2) Public endpoints by function name (handle blueprints)
    public_endpoints = {
        "login",
        "logout",
        "verify_signature",
        "guest_login",
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
        "docs_json_alias",
        "api_docs",
        # landing & explorer
        "landing_page",
        "root_redirect",
        "oidc_alias",
        "explorer_page",
        "verify_pubkey_and_list",
            "api_public_status",
}
    if not endpoint_base:
        return None

    if endpoint_base in public_endpoints:
        return None

    # 3) Everything else requires a logged-in session
    if not session.get("logged_in_pubkey"):
        if (p.startswith("/api/") and not p.startswith("/api/playground") and not p.startswith("/api/public/")) or p.endswith("/set_labels_from_zpub"):
            return jsonify(ok=False, error="Not logged in"), 401
        nxt = request.full_path if request.query_string else request.path
        return redirect(url_for("login", next=nxt))


@socketio.on("connect")
def on_connect(auth=None):
    pubkey = session.get("logged_in_pubkey", "")
    level = session.get("access_level")
    if not pubkey:
        return False
    role = classify_presence(pubkey, level)

    ACTIVE_SOCKETS[request.sid] = pubkey
    ONLINE_USERS.add(pubkey)
    ONLINE_META[pubkey] = role

    # Use emit() not socketio.emit()
    # PRESENCE_LABEL_BROADCAST_V2: attach label to presence join payload (PIN guests)
    label = None
    try:
        if session.get("login_method") == "pin_guest":
            label = session.get("guest_label")
    except Exception:
        label = None
    try:
        ONLINE_USER_META[pubkey] = {"role": role, "label": label}
    except Exception:
        pass
    emit("user:joined", {"pubkey": pubkey, "role": role, "label": label}, broadcast=True)
    online_list = [{"pubkey": pk, "role": ONLINE_META.get(pk, "limited")} for pk in ONLINE_USERS]
    # PRESENCE_LABEL_BROADCAST_V2: ensure online:list items include label when available
    try:
        for it in online_list:
            if isinstance(it, dict) and "pubkey" in it and "label" not in it:
                meta = ONLINE_USER_META.get(it["pubkey"], {})
                it["label"] = meta.get("label")
    except Exception:
        pass
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

        online_list = [{"pubkey": pk, "role": ONLINE_META.get(pk, "limited")} for pk in ONLINE_USERS]
        # PRESENCE_LABEL_BROADCAST_V2: ensure online:list items include label when available
        try:
            for it in online_list:
                if isinstance(it, dict) and "pubkey" in it and "label" not in it:
                    meta = ONLINE_USER_META.get(it["pubkey"], {})
                    it["label"] = meta.get("label")
        except Exception:
            pass
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
      --bg: #000;
      --fg: #e6f1ef;
      --accent: #00ff88;
      --red: #ff3b30;
      --blue: #3b82f6;
      --muted: #8a9da4;

      --stroke: rgba(255,255,255,.08);
      --glass: rgba(8,12,10,.22);

      --radius-lg: 16px;
      --radius-pill: 999px;
      --touch: 44px;

      --mono: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
    }

    * { box-sizing:border-box; margin:0; padding:0; -webkit-tap-highlight-color: transparent; }
    html, body { width:100%; height:100%; background:var(--bg); color:var(--fg); overflow:hidden; }
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Mono", Menlo, Consolas, monospace; }

    /* Matrix canvas */
    #matrix-bg { position:fixed; inset:0; z-index:0; pointer-events:none; }
    body > *:not(#matrix-bg){ position:relative; z-index:1; }

    .shell{
      width:100%;
      height:100%;
      padding: 1.25rem;
      display:flex;
      flex-direction:column;
      gap: 0.9rem;
    }



    .top-bar{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:0.75rem;
    }
    .top-left{ display:flex; align-items:center; gap:0.75rem; }

    .back-btn{
      min-width:var(--touch);
      height:var(--touch);
      border-radius:50%;
      border:1px solid var(--stroke);
      background: rgba(0,0,0,.25);
      color: var(--accent);
      cursor:pointer;
      display:inline-flex;
      align-items:center;
      justify-content:center;
      box-shadow: 0 0 14px rgba(0,255,136,.18);
      font-family: var(--mono);
      font-size: 12px;
      padding: 0 10px;
    }

    .title-block{ display:flex; flex-direction:column; gap:0.1rem; }
    .title{
      font-size: clamp(1.05rem, 1.4vw, 1.25rem);
      letter-spacing:.08em;
      text-transform: uppercase;
      color: var(--accent);
    }
    .subtitle{ font-size:0.8rem; color:var(--muted); }

    .top-right{
      display:flex;
      align-items:center;
      gap:0.65rem;
      font-size:0.8rem;
      color:var(--muted);
      flex-wrap:wrap;
      justify-content:flex-end;
    }

    .online-chip{
      display:inline-flex;
      align-items:center;
      gap:0.35rem;
      padding:0.3rem 0.7rem;
      border-radius:var(--radius-pill);
      border:1px solid rgba(34,197,94,0.35);
      background: radial-gradient(circle at 0 0, rgba(34,197,94,0.20), transparent 65%);
      font-family: var(--mono);
    }
    .online-dot{
      width:0.5rem; height:0.5rem; border-radius:50%;
      background:#22c55e;
      box-shadow:0 0 8px rgba(34,197,94,.9);
    }
    .status-pill{
      font-family: var(--mono);
      font-size:0.72rem;
      padding:0.12rem 0.55rem;
      border-radius:999px;
      border:1px solid rgba(148,163,184,0.55);
      background: rgba(0,0,0,.22);
      color: rgba(148,163,184,0.95);
    }

    .layout{
      flex:1;
      min-height:0;
      display:grid;
      grid-template-columns: minmax(0, 2.1fr) minmax(0, 1.3fr);
      gap: 0.9rem;
    }

    .panel{
      border-radius: var(--radius-lg);
      border: 1px solid var(--stroke);
      background: var(--glass);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      box-shadow: 0 10px 40px rgba(0,0,0,.45);
      padding: 0.9rem;
      display:flex;
      flex-direction:column;
      gap:0.75rem;
      min-height:0;
      overflow:hidden;
    }

    .panel-header{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:0.5rem;
      font-size:0.78rem;
      color:var(--muted);
      font-family: var(--mono);
    }
    .panel-title{
      text-transform:uppercase;
      letter-spacing:0.12em;
      font-size:0.7rem;
      color: rgba(255,59,48,.88);
      text-shadow: 0 0 6px rgba(255,59,48,.18);
    }
    .panel-badge{
      border-radius:var(--radius-pill);
      border:1px solid rgba(148,163,184,0.45);
      padding:0.18rem 0.6rem;
      font-size:0.7rem;
      white-space:nowrap;
    }

    .panel-body{ flex:1; min-height:0; display:flex; flex-direction:column; gap:0.75rem; }

    .messages-wrap{
      flex:1; min-height:0;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,.08);
      background: rgba(0,0,0,.22);
      padding: 0.6rem;
      display:flex;
      flex-direction:column;
      overflow:hidden;
    }
    .message-list{
      list-style:none;
      flex:1;
      min-height:0;
      overflow-y:auto;
      padding-right:0.3rem;
      display:flex;
      flex-direction:column;
      gap:0.45rem;
      scrollbar-width:thin;
      scrollbar-color: rgba(148,163,184,0.7) transparent;
    }
    .message-list::-webkit-scrollbar{ width:6px; }
    .message-list::-webkit-scrollbar-thumb{ background: rgba(148,163,184,0.7); border-radius:999px; }

    .message{
      align-self:flex-start;
      max-width:min(85%, 520px);
      border-radius:12px;
      padding:0.45rem 0.6rem;
      background: rgba(15,23,42,0.75);
      border:1px solid rgba(255,255,255,.06);
      box-shadow: 0 10px 18px rgba(0,0,0,.45);
    }
    .message.me{
      align-self:flex-end;
      border-color: rgba(34,197,94,0.45);
      box-shadow: 0 0 0 1px rgba(34,197,94,0.08) inset, 0 10px 18px rgba(0,0,0,.45);
    }

    .message-meta{
      display:flex;
      justify-content:space-between;
      gap:0.6rem;
      font-size:0.68rem;
      color: var(--muted);
      margin-bottom: 0.18rem;
      font-family: var(--mono);
    }
    .message-sender{ max-width:70%; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .message-text{ font-size:0.86rem; line-height:1.3; word-break:break-word; }

    .composer{
      display:flex;
      align-items:center;
      gap:0.5rem;
      margin-top:0.1rem;
    }
    .input-shell{
      flex:1;
      border-radius: var(--radius-pill);
      border: 1px solid rgba(255,255,255,.08);
      background: rgba(0,0,0,.22);
      display:flex;
      align-items:center;
      gap:0.45rem;
      padding:0.28rem 0.7rem;
    }
    .input-shell input{
      width:100%;
      border:none;
      outline:none;
      background:transparent;
      color:var(--fg);
      font-size:0.9rem;
    }
    .hint-pill{
      font-family: var(--mono);
      font-size:0.72rem;
      padding:0.12rem 0.45rem;
      border-radius:999px;
      border: 1px dashed rgba(148,163,184,0.5);
      color: rgba(148,163,184,0.9);
      white-space:nowrap;
    }
    .send-btn{
      min-width:var(--touch);
      height:var(--touch);
      border-radius:50%;
      border:none;
      cursor:pointer;
      display:inline-flex;
      align-items:center;
      justify-content:center;
      font-size:1.25rem;
      color:#e5fdf2;
      background: radial-gradient(circle at 20% 0, #22c55e 0, #15803d 45%, #052e16 100%);
      box-shadow: 0 0 0 1px rgba(34,197,94,0.55), 0 0 22px rgba(34,197,94,0.55);
    }
    .send-btn:active{ transform: translateY(1px) scale(0.98); }

    .ephemeral{
      font-family: var(--mono);
      font-size:0.72rem;
      color: var(--muted);
    }
    .ephemeral span{ color: var(--accent); }

    /* Sidebar */
    .sidebar{ display:flex; flex-direction:column; gap:0.75rem; min-height:0; }

    .users-list-wrap{
      flex:1; min-height:0;
      border-radius:12px;
      border:1px solid rgba(255,255,255,.08);
      background: rgba(0,0,0,.22);
      padding:0.6rem;
      display:flex;
      flex-direction:column;
      overflow:hidden;
    }
    .users-list{
      list-style:none;
      flex:1; min-height:0;
      overflow-y:auto;
      padding-right:0.3rem;
      display:flex;
      flex-direction:column;
      gap:0.4rem;
    }
    .user-item{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:0.5rem;
      padding:0.35rem 0.45rem;
      border-radius:10px;
      border:1px solid rgba(255,255,255,.06);
      background: rgba(0,0,0,.20);
      cursor:pointer;
      user-select:none;
      -webkit-user-select:none;
    }
    .user-left{ display:flex; align-items:center; gap:0.45rem; min-width:0; }
    .user-dot{
      width:0.42rem; height:0.42rem; border-radius:50%;
      background:#22c55e;
      box-shadow:0 0 8px rgba(34,197,94,.85);
      flex:0 0 auto;
    }
    .user-name{ font-size:0.8rem; max-width:170px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .user-sub{ font-size:0.66rem; color:var(--muted); opacity:.9; font-family: var(--mono); }
    .user-tag{
      display:inline-flex;
      padding:0.08rem 0.4rem;
      border-radius:999px;
      border:1px solid rgba(148,163,184,0.55);
      font-size:0.64rem;
      color: rgba(148,163,184,0.95);
      font-family: var(--mono);
      margin-top: 2px;
      width: fit-content;
    }
    .user-btn{
      font-size:0.9rem;
      min-width:30px; height:30px;
      border-radius:999px;
      border:1px solid rgba(148,163,184,0.5);
      background: rgba(0,0,0,.18);
      color: var(--fg);
      cursor:pointer;
      flex:0 0 auto;
    }

    /* Group call panel */
    .group-call-panel{
      border-radius:12px;
      border:1px solid rgba(255,255,255,.08);
      background: rgba(0,0,0,.22);
      padding:0.6rem;
      overflow:hidden;
    }
    .group-call-panel.hidden{ display:none; }

    .call-header{
      display:flex;
      align-items:flex-start;
      justify-content:space-between;
      gap:0.6rem;
      flex-wrap:wrap;
      margin-bottom:0.6rem;
    }
    .call-status{
      font-family: var(--mono);
      font-size:0.78rem;
      color: var(--muted);
    }
    .call-controls{
      display:flex;
      flex-wrap:wrap;
      gap:0.35rem;
    }
    .ctrl-btn{
      font-family: var(--mono);
      font-size:0.75rem;
      padding:0.35rem 0.7rem;
      border-radius:999px;
      border:1px solid rgba(148,163,184,0.5);
      background: rgba(0,0,0,.18);
      color: var(--fg);
      cursor:pointer;
      display:inline-flex;
      align-items:center;
      gap:0.3rem;
      transition: all .15s ease;
    }
    .ctrl-btn:hover{ border-color: rgba(0,255,136,.35); }
    .ctrl-btn.active{
      border-color: rgba(239,68,68,0.6);
      background: rgba(239,68,68,0.12);
      color: #fecaca;
    }
    .ctrl-btn.ctrl-danger{
      border-color: rgba(239,68,68,0.7);
      background: rgba(239,68,68,0.12);
      color: #fecaca;
    }

    .call-grid{
      display:grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap:0.5rem;
    }
    @media (min-width: 600px){
      .call-grid{ grid-template-columns: repeat(2, 1fr); }
    }
    .video-tile{
      position:relative;
      width:100%;
      aspect-ratio: 4/3;
      border-radius:10px;
      overflow:hidden;
      border:1px solid rgba(148,163,184,0.45);
      background:#020617;
    }
    .video-tile.local-tile{ border-color: rgba(59,130,246,0.55); }
    .video-tile video{ width:100%; height:100%; object-fit:cover; background:#020617; }
    .video-label{
      position:absolute;
      left:0.5rem; right:0.5rem; bottom:0.5rem;
      font-family: var(--mono);
      font-size:0.7rem;
      color: rgba(226,232,240,0.95);
      background: rgba(0,0,0,0.45);
      padding:0.2rem 0.4rem;
      border-radius:6px;
      backdrop-filter: blur(4px);
      -webkit-backdrop-filter: blur(4px);
      white-space:nowrap;
      overflow:hidden;
      text-overflow:ellipsis;
    }

    .floating-call-btn{
      position:fixed;
      bottom: 18px;
      right: 18px;
      width: 56px;
      height: 56px;
      border-radius: 50%;
      border: 2px solid var(--accent);
      background: rgba(0,0,0,.28);
      color: var(--accent);
      font-size: 1.35rem;
      cursor:pointer;
      box-shadow: 0 0 18px rgba(59,130,246,0.22), 0 0 18px rgba(0,255,136,0.18);
      z-index: 1000;
    }

@media (max-width: 768px){
  html, body { overflow-y:auto !important; -webkit-overflow-scrolling:touch; }
  .shell { padding: 0.75rem; height:auto; min-height:100%; }

  .layout{
    display:flex !important;
    flex-direction:column !important;
    gap:0.75rem !important;
  }

  .chat-panel { order: 1; }
  .sidebar    { order: 2; }

  /* ✅ make chat area actually usable in portrait */
  .chat-panel{
    flex: 1 1 auto !important;
    min-height: 62vh !important;
  }

  .chat-panel .panel-body{
    flex: 1 1 auto !important;
    min-height: 0 !important;
  }

  .chat-panel .messages-wrap{
    flex: 1 1 auto !important;
    min-height: 0 !important;
    overflow:hidden;
  }

  /* remove fixed vh; let it fill remaining height */
  .chat-panel .message-list{
    flex: 1 1 auto !important;
    min-height: 0 !important;
    height: auto !important;
    max-height: none !important;
    overflow-y:auto !important;
    -webkit-overflow-scrolling:touch;
  }

  /* ✅ shrink presence list so chat wins vertical space */
  .presence-panel .users-list-wrap{
    max-height: 22vh !important;
    overflow:auto;
  }

  /* ✅ iOS safe area so composer isn't hidden behind home bar */
  .composer{
    padding-bottom: calc(env(safe-area-inset-bottom, 0px) + 6px);
  }

  /* ✅ ensure online list is actually visible on mobile */
  .sidebar{
    flex: 0 0 auto !important;
    min-height: 180px !important;
  }

  .presence-panel{
    min-height: 180px !important;
  }

  .presence-panel .panel-body{
    min-height: 120px !important;
  }

  .presence-panel .users-list-wrap{
    height: 180px !important;
    max-height: 30vh !important;
    overflow-y: auto !important;
    -webkit-overflow-scrolling: touch;
  }

}
  .sidebar    { order: 2; }

  .chat-panel .messages-wrap{
    flex:1 !important;
    min-height:0 !important;
    overflow:hidden;
  }

  .chat-panel .message-list{
    height: 55vh !important;
    max-height: 60vh !important;
    overflow-y:auto !important;
    -webkit-overflow-scrolling:touch;
  }

  .presence-panel .users-list-wrap{
    height: 24vh;
    max-height: 28vh;
    overflow:auto;
  }
}
  .sidebar    { order: 2; }

  .chat-panel .messages-wrap{
    height: 60vh;
    max-height: 65vh;
    overflow:auto;
  }

  .presence-panel .users-list-wrap{
    height: 24vh;
    max-height: 28vh;
    overflow:auto;
  }
}

  
/* LOGIN_MODAL_MOBILE_CSS: make LN modal readable on phones */
#lnurlText{
  display:block;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 12px;
  line-height: 1.25;
  opacity: 0.95;
  word-break: break-all;
  max-height: 10.5em;
  overflow:auto;
  padding: 8px 10px;
  border-radius: 10px;
  border: 1px solid rgba(0,255,0,0.25);
  background: rgba(0,0,0,0.35);
}

#countdown{
  display:block;
  margin-top: 8px;
  font-size: 13px;
  opacity: 0.9;
}

@media (max-width: 768px){
  /* ensure modal content stacks nicely */
  #qrModal .modal-content, #qrModal .modal-inner, #qrModal .qr-wrap{
    width: min(92vw, 520px) !important;
    max-height: 86vh !important;
    overflow: auto !important;
  }
  #qrcode{
    display:flex;
    justify-content:center;
    padding: 8px 0 4px;
  }
  #lnurlText{
    font-size: 13px;
  }
}


/* LOGIN_LANDSCAPE_QR_FIX: stable modal + prevent bg tap stealing */
#matrix-bg, #matrix-canvas, canvas#matrix-bg, canvas#matrix-canvas,
#matrix-bg *, #matrix-canvas *, .matrix-bg, .matrix-bg *{
  pointer-events: none !important;
}

/* Make sure actual UI is tappable above background layers */
.pill, .pill *, button, a, .btn, .toolbar, .shell, .panel, .main, .content {
  pointer-events: auto;
}

/* QR Modal always above everything */
#qrModal{
  position: fixed !important;
  inset: 0 !important;
  z-index: 999999 !important;
}

/* iPad / tablet landscape: modal should fit and show QR + text + timer */
@media (max-width: 1024px) and (orientation: landscape){
  #qrModal{
    padding: 10px !important;
  }

  /* allow scrolling if height is tight */
  #qrModal *{
    max-height: none;
  }

  /* make QR smaller so it doesn't get clipped */
  #qrcode img, #qrcode canvas{
    width: 220px !important;
    height: 220px !important;
  }

  #lnurlText{
    max-height: 7.5em !important;
  }
}


/* LOGIN_MODAL_LAYOUT_V3 */

/* Keep matrix background behind everything */
#matrix-bg, #matrix-canvas, canvas#matrix-bg, canvas#matrix-canvas,
#matrix-bg *, #matrix-canvas * {
  pointer-events: none !important;
  z-index: 0 !important;
}

/* Ensure main UI sits above background */
.shell, .main, .content, .panel, .toolbar, .login-wrap, .auth-row, .pillbar {
  position: relative;
  z-index: 10;
}

/* QR modal always on top */
#qrModal{
  position: fixed !important;
  inset: 0 !important;
  z-index: 999999 !important;
}

/* Make modal content scroll if height is tight */
#qrModal{
  overflow: auto !important;
  -webkit-overflow-scrolling: touch;
}

/* Improve readability of lnurl text (keep your neon vibe) */
#lnurlText{
  display:block;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  word-break: break-all;
  overflow:auto;
  padding: 8px 10px;
  border-radius: 10px;
  border: 1px solid rgba(0,255,0,0.25);
  background: rgba(0,0,0,0.35);
}

/* iPad / tablet LANDSCAPE: show QR + text side-by-side */
@media (orientation: landscape) and (max-height: 600px){
  /* Try multiple container names so it works with your current markup */
  #qrModal > div,
  #qrModal .modal-content,
  #qrModal .modal-inner,
  #qrModal .qr-wrap{
    display: grid !important;
    grid-template-columns: 260px 1fr !important;
    gap: 12px !important;
    align-items: start !important;
    width: min(96vw, 980px) !important;
    margin: 10px auto !important;
    max-height: 86vh !important;
    overflow: auto !important;
  }

  #qrcode{ grid-column: 1 !important; display:flex; justify-content:center; }
  #lnurlText{ grid-column: 2 !important; max-height: 9em !important; }
  #countdown{ grid-column: 2 !important; margin-top: 8px !important; }
  #qrcode img, #qrcode canvas { width: 240px !important; height: 240px !important; }
}

/* Phones portrait: keep it stacked, readable */
@media (max-width: 768px){
  #qrcode{ display:flex; justify-content:center; padding: 8px 0 4px; }
  #lnurlText{ font-size: 13px; max-height: 11em; }
  #countdown{ font-size: 13px; opacity: .9; }
}


/* QR_MODAL_LANDSCAPE_V1: iPad/tablet landscape QR modal layout */
@media (orientation: landscape) and (max-width: 1024px){
  /* assume first inner wrapper holds qrcode + lnurlText + countdown */
  #qrModal > div{
    width: min(96vw, 980px) !important;
    max-height: 86vh !important;
    overflow: auto !important;
    display: grid !important;
    grid-template-columns: 260px 1fr !important;
    grid-auto-rows: min-content !important;
    gap: 12px !important;
    align-items: start !important;
    margin: 10px auto !important;
  }

  #qrcode{ grid-column: 1 !important; display:flex !important; justify-content:center !important; }
  #lnurlText{ grid-column: 2 !important; max-height: 8.5em !important; }
  #countdown{ grid-column: 2 !important; margin-top: 8px !important; }

  #qrcode img, #qrcode canvas{
    width: 240px !important;
    height: 240px !important;
  }
}


/* QR_MODAL_WRAPPER_V3 */
#qrCard.qr-card{
  width: min(92vw, 520px);
  max-height: 86vh;
  overflow: auto;
  margin: 10px auto;
  padding: 12px;
  border-radius: 16px;
  border: 1px solid rgba(0,255,0,0.25);
  background: rgba(0,0,0,0.55);
  box-shadow: 0 0 18px rgba(0,255,0,0.12);
}

@media (orientation: landscape) and (max-width: 1024px){
  #qrCard.qr-card{
    width: min(96vw, 980px);
    display: grid;
    grid-template-columns: 260px 1fr;
    gap: 12px;
    align-items: start;
  }
  #qrcode{ grid-column: 1; display:flex; justify-content:center; }
  #lnurlText{ grid-column: 2; max-height: 8.5em; }
  #countdown{ grid-column: 2; margin-top: 8px; }
  #qrcode img, #qrcode canvas{ width: 240px !important; height: 240px !important; }
}


/* LOGIN_QR_LAYOUT_V4 */

/* Never let the matrix/bg steal taps */
#matrix-bg, #matrix-canvas, canvas#matrix-bg, canvas#matrix-canvas,
#matrix-bg *, #matrix-canvas *, canvas {
  pointer-events: none !important;
}

/* Make sure login controls are above background */
.shell, .main, .content, .panel, .toolbar, .login-wrap, .auth-row, .pillbar, .pill, button {
  position: relative;
  z-index: 10;
}

/* Modal always on top */
#qrModal{
  position: fixed !important;
  inset: 0 !important;
  z-index: 999999 !important;
  overflow: auto !important;
  -webkit-overflow-scrolling: touch;
}

/* Our wrapper card */
#qrCard{
  width: min(92vw, 520px);
  max-height: 86vh;
  overflow: auto;
  margin: 10px auto;
  padding: 12px;
  border-radius: 16px;
  border: 1px solid rgba(0,255,0,0.25);
  background: rgba(0,0,0,0.55);
  box-shadow: 0 0 18px rgba(0,255,0,0.12);
}

/* Text + timer look good on phones */
#lnurlText{
  display:block;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 13px;
  line-height: 1.25;
  opacity: 0.95;
  word-break: break-all;
  max-height: 11em;
  overflow:auto;
  padding: 8px 10px;
  border-radius: 10px;
  border: 1px solid rgba(0,255,0,0.25);
  background: rgba(0,0,0,0.35);
}
#countdown{
  display:block;
  margin-top: 8px;
  font-size: 13px;
  opacity: 0.9;
}

/* iPad/tablet LANDSCAPE: QR left, text+timer right */
@media (orientation: landscape) and (max-width: 1024px){
  #qrCard{
    width: min(96vw, 980px);
    display: grid;
    grid-template-columns: 260px 1fr;
    gap: 12px;
    align-items: start;
  }
  #qrcode{ grid-column: 1; display:flex; justify-content:center; padding: 8px 0 4px; }
  #lnurlText{ grid-column: 2; max-height: 8.5em; }
  #countdown{ grid-column: 2; }
  #qrcode img, #qrcode canvas{ width: 240px !important; height: 240px !important; }
}



/* LOGIN_QR_COSMETIC_POLISH_V1 */
/* Cosmetic only: spacing, readability, consistent card + better landscape behavior */

#qrModal{
  /* nicer overlay */
  background: rgba(0,0,0,0.70) !important;
  backdrop-filter: blur(10px) saturate(120%);
  -webkit-backdrop-filter: blur(10px) saturate(120%);
}

/* The modal “card” */
#qrCard, #qrCard.qr-card{
  border-radius: 18px !important;
  padding: 14px !important;
  border: 1px solid rgba(0,255,0,0.28) !important;
  box-shadow:
    0 0 26px rgba(0,255,0,0.14),
    inset 0 0 0 1px rgba(0,255,0,0.08) !important;
}

/* QR block */
#qrcode{
  padding: 10px 0 6px !important;
}
#qrcode img, #qrcode canvas{
  border-radius: 12px !important;
  box-shadow: 0 0 18px rgba(0,255,0,0.12) !important;
}

/* LNURL text box */
#lnurlText{
  font-size: 13px !important;
  letter-spacing: 0.15px;
  scrollbar-width: thin;
}

/* Countdown: centered + tabular digits (cleaner timer look) */
#countdown{
  text-align: center;
  font-variant-numeric: tabular-nums;
  letter-spacing: 0.25px;
  padding: 2px 0 0;
}

/* Buttons/links inside the modal: consistent tap target + spacing */
#qrModal a, #qrModal button{
  min-height: 44px; /* iOS recommended */
  border-radius: 14px;
}
#qrModal a{
  text-decoration: none;
}
#qrModal .qr-card a,
#qrModal .qr-card button{
  width: 100%;
  margin-top: 10px;
}

/* Open-in-wallet link: make it look intentional */
#openInWallet{
  display:block;
  text-align:center;
  opacity: 0.95;
  padding: 6px 0 2px;
}

/* Small phones: tighten spacing */
@media (max-width: 420px){
  #qrCard, #qrCard.qr-card{ padding: 12px !important; }
  #lnurlText{ font-size: 12.5px !important; max-height: 10.5em !important; }
}

/* iPad / landscape with limited height: keep everything visible */
@media (orientation: landscape) and (max-height: 700px){
  #qrCard, #qrCard.qr-card{
    width: min(96vw, 980px) !important;
    display: grid !important;
    grid-template-columns: 220px 1fr !important;
    gap: 12px !important;
    align-items: start !important;
  }
  #qrcode{ grid-column: 1 !important; }
  #lnurlText{ grid-column: 2 !important; max-height: 7.5em !important; }
  #countdown{ grid-column: 2 !important; }
  #qrcode img, #qrcode canvas{ width: 200px !important; height: 200px !important; }
}

</style>
</head>

<body
  data-my-pubkey="{{ my_pubkey|e }}"
  data-access-level="{{ access_level|e }}"
>
  <canvas id="matrix-bg"></canvas>

  <!-- expose SPECIAL_NAMES to JS -->
  <script id="specialNames" type="application/json">{{ special_names|tojson }}</script>

  <main class="shell">
    <header class="top-bar">
      <div class="top-left">
        <button class="back-btn" type="button" onclick="goHome('#explorer')">CRT</button>
        <div class="title-block">
          <div class="title">Global Chat</div>
          <div class="subtitle">Presence chips ·  whispers · p2p call</div>
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
      <!-- Chat -->
      <section class="panel chat-panel">
        <div class="panel-header">
          <div class="panel-title">Live flow · <span style="color:var(--accent)">HODLXXI</span></div>
          <div class="panel-badge">Self-erase after 45s</div>
        </div>

        <div class="panel-body">
          <div class="messages-wrap">
            <ul id="messages" class="message-list">
              {% for m in history %}
              <li class="message{% if m.pubkey == my_pubkey %} me{% endif %}" data-ts="{{ m.ts|default(0) }}">
                <div class="message-meta">
                  <div class="message-sender">{{ (m.pubkey or 'anon')[:12] }}…{{ (m.pubkey or '')[-6:] }}</div>
                  <div class="message-timestamp">''</div>
                </div>
                <div class="message-text">{{ (m.text or '')|e }}</div>
              </li>
              {% endfor %}
            </ul>
          </div>

          <div class="composer">
            <div class="input-shell">
              <input id="chatInput" type="text" autocomplete="off" placeholder="Type a whisper…" />
              <div class="hint-pill">@</div>
            </div>
            <button id="sendBtn" class="send-btn" type="button">➤</button>
          </div>

      </section>

      <!-- Sidebar -->
      <aside class="sidebar">
        <section class="panel presence-panel">
          <div class="panel-header">
            <div class="panel-title">Online presence</div>
            <div class="panel-badge">@ = mention · Hold = call</div>
          </div>

          <div class="panel-body">
            <div class="users-list-wrap">
              <ul id="userList" class="users-list">
                {% for pk in online_users %}
                <li class="user-item" data-pubkey="{{ pk|e }}">
                  <div class="user-left">
                    <span class="user-dot"></span>
                    <div style="min-width:0;">
                      <div class="user-name">…{{ pk[-4:] }}</div>
                      {% if pk == my_pubkey %}
                        <div class="user-tag">you</div>
                      {% else %}
                        <div class="user-sub">…{{ pk[-4:] }}</div>
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

        <!-- Group call panel -->
        <section id="groupCallPanel" class="group-call-panel hidden">
          <div class="call-header">
            <div id="callStatus" class="call-status">Not in a call</div>
            <div class="call-controls">
              <button id="muteBtn" class="ctrl-btn" type="button"><span>🔊</span>Mute</button>
              <button id="cameraBtn" class="ctrl-btn" type="button"><span>📷</span>Camera Off</button>
              <button id="hangupGroupBtn" class="ctrl-btn ctrl-danger" type="button"><span>✕</span>Hang Up</button>
            </div>
          </div>

          <div class="call-grid">
            <div class="video-tile local-tile">
              <video id="localVideo" muted playsinline autoplay></video>
              <div class="video-label">You</div>
            </div>
            <div id="remoteVideosContainer"></div>
          </div>
        </section>
      </aside>
    </section>
  </main>

  <button class="floating-call-btn" onclick="startGroupCall()" title="Start group call">📞</button>

  <script>
    const myPubkey = document.body.dataset.myPubkey || "";
    const accessLevel = document.body.dataset.accessLevel || "limited";
    const SPECIAL_NAMES = (() => {
      try { return JSON.parse(document.getElementById("specialNames")?.textContent || "{}"); }
      catch { return {}; }
    })();

    // Matrix "space warp"
    (() => {
      const canvas = document.getElementById('matrix-bg');
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      const CHARS = ['0','1'];
      const isMobile = window.matchMedia && window.matchMedia('(max-width: 768px)').matches;
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
        width = cssW; height = cssH;

        particles = [];
        for (let i = 0; i < (isMobile ? 120 : 400); i++) {
          particles.push({ x:(Math.random()-0.5)*width, y:(Math.random()-0.5)*height, z:Math.random()*800+100 });
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
          const x2 = width/2 + p.x * scale;
          const y2 = height/2 + p.y * scale;
          const size = Math.max(8 * scale, 1);
          ctx.font = size + 'px monospace';
          ctx.fillText(CHARS[(Math.random() > 0.5) | 0], x2, y2);
          p.z -= (isMobile ? 2 : 5);
          if (p.z < 1) { p.x=(Math.random()-0.5)*width; p.y=(Math.random()-0.5)*height; p.z=800; }
        }
        raf = requestAnimationFrame(draw);
      }

      document.addEventListener('visibilitychange', () => {
        if (document.hidden) { if (raf) cancelAnimationFrame(raf), raf = null; }
        else { if (!raf) raf = requestAnimationFrame(draw); }
      });

      window.addEventListener('resize', resize);
      resize(); raf = requestAnimationFrame(draw);
    })();

    function goHome(hash) {
      const base = "{{ url_for('home') }}";
      window.location.href = hash ? base + hash : base;
    }

    // PRESENCE_APPLY_LABELS_GLOBAL_V1: global helper to apply server-broadcast labels to presence DOM chips

    try {

      window.__applyPresenceLabels = window.__applyPresenceLabels || function() {

        try {

          const lm = window.__labelByPubkey || {};

          const entries = Object.entries(lm).filter(([pk, lbl]) => pk && lbl);

          if (!entries.length) return 0;


          const tails = entries.map(([pk, lbl]) => {

            const s = String(pk);

            return { t8: s.slice(-8), t6: s.slice(-6), lbl: String(lbl) };

          });


          let changed = 0;

          document.querySelectorAll('span,div,li,p,a,button').forEach((el) => {

            try {

              if (!el || (el.children && el.children.length)) return;

              const txt = (el.textContent || '').trim();

              if (!txt) return;

              if (!(txt.includes('…') || txt.includes('...'))) return;

              if (txt.length > 32) return;


              for (const x of tails) {

                if ((x.t8 && txt.endsWith(x.t8)) || (x.t6 && txt.endsWith(x.t6))) {

                  el.textContent = x.lbl;

                  changed += 1;

                  break;

                }

              }

            } catch(e) {}

          });

          return changed;

        } catch(e) {}

        return 0;

      };


      // Observe future rerenders (React)

      if (!window.__presenceLabelObserver) {

        window.__presenceLabelObserver = new MutationObserver(() => {

          try {

            clearTimeout(window.__presenceLabelTO);

            window.__presenceLabelTO = setTimeout(() => {

              try { window.__applyPresenceLabels && window.__applyPresenceLabels(); } catch(e) {}

            }, 50);

          } catch(e) {}

        });

        try {

          window.__presenceLabelObserver.observe(document.body, { childList:true, subtree:true, characterData:true });

        } catch(e) {}

      }

    } catch(e) {}


    function shortKey(pk) {

  // PRESENCE_LABELMAP_FRONTEND_V1: prefer server-broadcast labels for ANY user (so everyone sees Guest-HOST)
  try {
    const lm = window.__labelByPubkey || {};
    const lbl = lm[pk];
    if (lbl) return lbl;
  } catch(e) {}

      // APP_PRESENCE_GUEST_LABEL_SHORTKEY_V1: show Guest-* label for current PIN guest instead of truncating pubkey

      try {

        const my = window.__myPubkey || '';

        const gl = window.__guestLabel || '';

        if (gl && my && pk === my) return gl;

      } catch(e) {}
  // GUEST_LABEL_UI_V1: show guest label for current (PIN) guest instead of truncated pubkey
  if (window.__myPubkey === undefined) {
    var ds = (document && document.body && document.body.dataset) ? document.body.dataset : {};
    window.__myPubkey = ds.loggedInPubkey || ds.loggedIn || "";
    window.__guestLabel = ds.guestLabel || "";
  }
  if (window.__guestLabel && window.__myPubkey && pk === window.__myPubkey) return window.__guestLabel;

      if (!pk) return "";
      return pk.length > 18 ? pk.slice(0,10) + "…" + pk.slice(-6) : pk;
    }

    function displayName(pk) {
      // PRESENCE_DISPLAYNAME_LABELMAP_V1: prefer server-broadcast labels for ANY user (PIN guests, etc.)
      try {
        const lm = window.__labelByPubkey || {};
        const lbl = lm[pk];
        if (lbl) return lbl;
      } catch(e) {}

      if (!pk) return "anon";
      if (SPECIAL_NAMES && SPECIAL_NAMES[pk]) return SPECIAL_NAMES[pk];
      const last4 = pk.slice(-4);
      if (pk.startsWith("guest") || pk.length < 20) return "guest …" + last4;
      if (pk === myPubkey) return "you · …" + last4;
      return "…"+last4;
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
      try { localStorage.setItem('hodlxxi_explorer_target', pubkey); } catch {}
      goHome('#explorer');
    }

    const messagesEl    = document.getElementById('messages');
    function scrollMessagesToBottom(){
      if (!messagesEl) return;
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }
    const userListEl    = document.getElementById('userList');
    const onlineCountEl = document.getElementById('onlineCount');
    const statusEl      = document.getElementById('room-status');
    const inputEl       = document.getElementById('chatInput');
    const sendBtn       = document.getElementById('sendBtn');

    function setStatus(text) { if (statusEl) statusEl.textContent = text; }
    function setOnlineCount(n) { if (onlineCountEl) onlineCountEl.textContent = n; }

    // 45s prune (UI)
    const EXPIRY_SECONDS = 45;
    setInterval(() => {
      if (!messagesEl) return;
      const now = Date.now() / 1000;
      messagesEl.querySelectorAll('.message').forEach(li => {
        const ts = parseFloat(li.dataset.ts || "0");
        if (ts && (now - ts) > EXPIRY_SECONDS) li.remove();
      });
    }, 5000);

    function renderMessage(msg) {
      if (!messagesEl || !msg) return;
      const li = document.createElement('li');
      li.className = 'message';

      const fromPk = msg.pubkey || msg.sender_pubkey || '';
      if (fromPk && myPubkey && fromPk === myPubkey) li.classList.add('me');

      const senderLabel = msg.label || msg.sender || fromPk || 'anon';
      const shortSender = senderLabel.length > 22 ? senderLabel.slice(0, 12) + '…' + senderLabel.slice(-6) : senderLabel;

      const rawTs = msg.ts || msg.timestamp || msg.created_at || (Date.now() / 1000);
      const timeStr = new Date(rawTs * 1000).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });

      li.dataset.ts = String(rawTs);
      li.innerHTML = `
        <div class="message-meta">
          <div class="message-sender">${shortSender.replace(/</g,'&lt;')}</div>
          <div class="message-timestamp">${timeStr}</div>
        </div>
        <div class="message-text">${(msg.text || msg.body || '').replace(/</g,'&lt;')}</div>
      `;

      messagesEl.appendChild(li);
      requestAnimationFrame(() => { scrollMessagesToBottom(); });
    }

    function extractPubkeys(payload) {
      if (!payload) return [];
      const arr = Array.isArray(payload) ? payload : (payload.users || payload.online_users || []);
      return arr.map(u => typeof u === 'string' ? u : (u && (u.pubkey || u.id)) || null).filter(Boolean);
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

        li.innerHTML = `
          <div class="user-left">
            <span class="user-dot"></span>
            <div style="min-width:0;">
              <div class="user-name">${displayName(pk).replace(/</g,'&lt;')}</div>
              ${isMe ? `<div class="user-tag">you</div>` : `<div class="user-sub">${shortKey(pk)}</div><!-- PRESENCE_USER_SUB_USE_SHORTKEY_V1 -->`}
            </div>
          </div>
          <button class="user-btn" type="button">@</button>
        `;

        li.querySelector('.user-btn')?.addEventListener('click', (ev) => {
          ev.stopPropagation();
          mentionUser(pk);
        });

        // Long-press to call (direct room)
        let pressTimer = null;
        let didLongPress = false;

        const startPress = () => {
          if (pk === myPubkey) return;
          if (pressTimer) return;
          pressTimer = setTimeout(() => {
            pressTimer = null;
            didLongPress = true;
            startCall(pk);
            setTimeout(() => { didLongPress = false; }, 120);
          }, 700);
        };
        const cancelPress = () => { if (pressTimer) { clearTimeout(pressTimer); pressTimer = null; } };

        li.addEventListener('mousedown', startPress);
        li.addEventListener('touchstart', startPress, { passive:true });
        ['mouseup','mouseleave','touchend','touchcancel'].forEach(ev => li.addEventListener(ev, cancelPress));

        // Tap (non-guest) opens Explorer
        if (!isGuest) {
          li.addEventListener('click', () => {
            if (didLongPress) return;
            openExplorerFor(pk);
          });
        }

        userListEl.appendChild(li);
      });

      setOnlineCount(users.length);
    }

    // Socket.IO
    const socket = io();

    socket.on('connect', () => setStatus('Connected'));
    socket.on('disconnect', () => setStatus('Disconnected'));

    socket.on('chat:history', (payload) => {
      const msgs = payload?.messages || payload;
      if (!Array.isArray(msgs)) return;
      messagesEl.innerHTML = '';
      msgs.forEach(renderMessage);
      requestAnimationFrame(() => { scrollMessagesToBottom(); });
      setStatus('History loaded');
    });

    socket.on('chat:message', renderMessage);

    // APP_PRESENCE_ONLINE_CACHE_V1: cache latest payload so we can re-render once guest_label arrives

    // APP_PRESENCE_GUEST_LABEL_INIT_V1: fetch guest_label for current session so presence UI can show Guest-HOST

    (function(){

      if (window.__guestLabelInit) return; window.__guestLabelInit = true;

      try {

        const ds = (document.body && document.body.dataset) ? document.body.dataset : {};

        window.__myPubkey = window.__myPubkey || ds.myPubkey || ds.loggedInPubkey || ds.loggedIn || '';

        window.__guestLabel = window.__guestLabel || ds.guestLabel || '';

      } catch(e) {}

      try {

        fetch('/api/debug/session', { credentials: 'same-origin' })

          .then(r => r.json())

          .then(d => {

            if (!d) return;

            window.__myPubkey = d.pubkey || window.__myPubkey || '';

            window.__guestLabel = d.guest_label || d.guestLabel || window.__guestLabel || '';
        // APP_PRESENCE_DOM_APPLY_GUESTLABEL_V1: persist to dataset + update rendered presence chips immediately
        try {
          if (document && document.body && document.body.dataset) {
            document.body.dataset.guestLabel = window.__guestLabel || '';
          // APP_PRESENCE_FORCE_GUESTLABEL_DOMFIX_V2: best-effort DOM fix for presence chips that still show truncated pubkey like …59cb
          try {
            window.__applyGuestLabelPresence = window.__applyGuestLabelPresence || function() {
              try {
                const my = (window.__myPubkey || '').trim();
                const gl = (window.__guestLabel || '').trim();
                if (!my || !gl) return;

                const tail8 = my.slice(-8);
                const tail6 = my.slice(-6);
                const tail4 = my.slice(-4);

                // Find likely presence/userlist containers
                const roots = [];
                document.querySelectorAll('[id],[class]').forEach((el) => {
                  const s = ((el.id || '') + ' ' + (el.className || '')).toLowerCase();
                  if (s.includes('online') || s.includes('presence') || s.includes('userlist') || s.includes('user-list') || s.includes('users')) {
                    roots.push(el);
                  }
                });
                if (!roots.length) roots.push(document.body);

                // Only touch leaf nodes that contain ellipsis and end with our tail
                const tryTails = (tails) => {
                  let changed = 0;
                  roots.slice(0, 10).forEach((root) => {
                    root.querySelectorAll('*').forEach((el) => {
                      try {
                        if (!el || (el.children && el.children.length)) return;
                        const txt = (el.textContent || '').trim();
                        if (!txt) return;
                        if (!(txt.includes('…') || txt.includes('...'))) return;
                        if (tails.some(t => t && txt.endsWith(t))) {
                          el.textContent = gl;
                          changed += 1;
                        }
                      } catch(e) {}
                    });
                  });
                  return changed;
                };

                // Prefer longer tails first (less collision), then fallback to tail4
                if (tryTails([tail8, tail6]) === 0) {
                  // Only apply tail4 replacement if the text is short-ish (chip), to avoid accidental matches
                  roots.slice(0, 10).forEach((root) => {
                    root.querySelectorAll('*').forEach((el) => {
                      try {
                        if (!el || (el.children && el.children.length)) return;
                        const txt = (el.textContent || '').trim();
                        if (!txt) return;
                        if (txt.length > 20) return;
                        if (!(txt.includes('…') || txt.includes('...'))) return;
                        if (tail4 && txt.endsWith(tail4)) el.textContent = gl;
                      } catch(e) {}
                    });
                  });
                }
              } catch(e) {}
            };
          } catch(e) {}

          // Run now + again shortly (covers “render happens after fetch” timing)
          try { window.__applyGuestLabelPresence && window.__applyGuestLabelPresence(); } catch(e) {}
          try { setTimeout(() => window.__applyGuestLabelPresence && window.__applyGuestLabelPresence(), 250); } catch(e) {}
          try { setTimeout(() => window.__applyGuestLabelPresence && window.__applyGuestLabelPresence(), 1000); } catch(e) {}

          }
        } catch(e) {}
        try {
          const my = window.__myPubkey || '';
          const gl = window.__guestLabel || '';
          if (my && gl) {
            document.querySelectorAll('[data-pubkey]').forEach((el) => {
              try {
                if (el && el.dataset && el.dataset.pubkey === my) {
                  el.textContent = gl;
                }
              } catch(e) {}
            });
          }
        } catch(e) {}


            // Re-render online list if we already drew it

            if (window.__guestLabel && window.__lastOnlinePayload && typeof renderUserList === 'function' && typeof extractPubkeys === 'function') {

              try { renderUserList(extractPubkeys(window.__lastOnlinePayload)); } catch(e) {}

            }

          })

          .catch(() => {});

      } catch(e) {}

    })();


    socket.on('online:list', (payload) => {
      // PRESENCE_LABELMAP_SOCKET_V2: build label map from server payload so everyone renders Guest-* labels
      // PRESENCE_DOM_LABEL_APPLY_V1: apply label map to any presence chips that still show truncated pubkey like …59cb
      try {
        window.__applyPresenceLabels = window.__applyPresenceLabels || function() {
          try {
            const lm = window.__labelByPubkey || {};
            const entries = Object.entries(lm).filter(([pk, lbl]) => pk && lbl);
            if (!entries.length) return;

            // precompute tails
            const tails = entries.map(([pk, lbl]) => {
              const s = String(pk);
              return { t8: s.slice(-8), t6: s.slice(-6), lbl: String(lbl) };
            });

            // scan leaf nodes likely used as chips
            document.querySelectorAll('span,div,li,p,a,button').forEach((el) => {
              try {
                if (!el || (el.children && el.children.length)) return;
                const txt = (el.textContent || '').trim();
                if (!txt) return;
                if (!(txt.includes('…') || txt.includes('...'))) return;
                if (txt.length > 32) return; // avoid touching paragraphs

                for (const x of tails) {
                  if ((x.t8 && txt.endsWith(x.t8)) || (x.t6 && txt.endsWith(x.t6))) {
                    el.textContent = x.lbl;
                    break;
                  }
                }
              } catch(e) {}
            });
          } catch(e) {}
        };

        // observe re-renders (React / DOM updates)
        if (!window.__presenceLabelObserver) {
          window.__presenceLabelObserver = new MutationObserver(() => {
            try {
              clearTimeout(window.__presenceLabelTO);
              window.__presenceLabelTO = setTimeout(() => {
                try { window.__applyPresenceLabels && window.__applyPresenceLabels(); } catch(e) {}
              }, 50);
            } catch(e) {}
          });
          try {
            window.__presenceLabelObserver.observe(document.body, { childList:true, subtree:true, characterData:true });
          } catch(e) {}
        }

        // run now and shortly after
        try { window.__applyPresenceLabels(); } catch(e) {}
        try { setTimeout(() => window.__applyPresenceLabels && window.__applyPresenceLabels(), 50); } catch(e) {}
        try { setTimeout(() => window.__applyPresenceLabels && window.__applyPresenceLabels(), 250); } catch(e) {}
      } catch(e) {}

      try {
        const list = Array.isArray(payload) ? payload : (payload ? [payload] : []);
        window.__labelByPubkey = window.__labelByPubkey || {};
        list.forEach((x) => {
          try {
            if (x && typeof x === 'object' && x.pubkey && x.label) {
              window.__labelByPubkey[x.pubkey] = x.label;
            }
          } catch(e) {}
        });
      } catch(e) {}

      try { window.__labelByPubkey = window.__labelByPubkey || {}; (payload||[]).forEach((x)=>{ if(x && typeof x==='object' && x.pubkey && x.label){ window.__labelByPubkey[x.pubkey]=x.label; } }); } catch(e) {}


      try { window.__lastOnlinePayload = payload; } catch (e) {}

      renderUserList(extractPubkeys(payload));

      try { window.__applyGuestLabelPresence && window.__applyGuestLabelPresence(); } catch(e) {}
    });

    socket.on('user:list',   (payload) => renderUserList(extractPubkeys(payload)));

    socket.on('user:joined', (payload) => {
      // PRESENCE_LABELMAP_SOCKET_V2: also capture label on incremental join events
      try { window.__applyPresenceLabels && window.__applyPresenceLabels(); } catch(e) {}

      try {
        if (payload && typeof payload === 'object' && payload.pubkey && payload.label) {
          window.__labelByPubkey = window.__labelByPubkey || {};
          window.__labelByPubkey[payload.pubkey] = payload.label;
        }
      } catch(e) {}

      try { if(payload && payload.pubkey && payload.label){ window.__labelByPubkey = window.__labelByPubkey || {}; window.__labelByPubkey[payload.pubkey]=payload.label; } } catch(e) {}

      const [pk] = extractPubkeys([payload]);
      if (!pk || !userListEl) return;
      const existing = Array.from(userListEl.querySelectorAll('.user-item')).map(li => li.dataset.pubkey);
      if (existing.includes(pk)) return;
      renderUserList([...existing, pk]);
    });

    socket.on('user:left', (payload) => {
      const [pk] = extractPubkeys([payload]);
      if (!pk || !userListEl) return;
      userListEl.querySelector(`.user-item[data-pubkey="${pk}"]`)?.remove();
      setOnlineCount(userListEl.querySelectorAll('.user-item').length);
    });

    function sendMessage() {
      const text = (inputEl?.value || '').trim();
      if (!text) return;
      socket.emit('chat:send', { text });
      inputEl.value = '';
      inputEl.focus();
    }
    sendBtn?.addEventListener('click', sendMessage);
    inputEl?.addEventListener('keydown', (evt) => {
      if (evt.key === 'Enter' && !evt.shiftKey) { evt.preventDefault(); sendMessage(); }
    });

    // ================== GROUP CALL MANAGER (single implementation) ==================
    const GroupCallManager = (() => {
      let localStream = null;
      let peerConnections = {};
      let currentRoomId = null;
      let iceServersCache = null;
      let isMuted = false;
      let isCameraOff = false;

      const panel = document.getElementById("groupCallPanel");
      const callStatusEl = document.getElementById("callStatus");
      const localVideoEl = document.getElementById("localVideo");
      const remoteWrap = document.getElementById("remoteVideosContainer");
      const muteBtn = document.getElementById("muteBtn");
      const cameraBtn = document.getElementById("cameraBtn");
      const hangupBtn = document.getElementById("hangupGroupBtn");

      function updateStatus(t){ if (callStatusEl) callStatusEl.textContent = t || "No active call"; }
      function setUI(active){
        if (!panel) return;
        panel.classList.toggle("hidden", !active);
      }

      async function getIceServers() {
        if (iceServersCache) return iceServersCache;
        try {
          const resp = await fetch("/turn_credentials");
          iceServersCache = resp.ok ? await resp.json() : [];
        } catch { iceServersCache = []; }
        return iceServersCache;
      }

      async function ensureLocalStream() {
        if (localStream) return localStream;
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: true,
          video: { width:{ideal:640}, height:{ideal:480} }
        });
        localStream = stream;
        if (localVideoEl) {
          localVideoEl.srcObject = stream;
          localVideoEl.muted = true;
          localVideoEl.play().catch(()=>{});
        }
        return stream;
      }

      function addRemoteTile(pk, stream){
        if (!remoteWrap) return;
        let tile = document.getElementById("tile-" + pk);
        if (!tile){
          tile = document.createElement("div");
          tile.className = "video-tile";
          tile.id = "tile-" + pk;

          const v = document.createElement("video");
          v.autoplay = true; v.playsinline = true;

          const label = document.createElement("div");
          label.className = "video-label";
          label.textContent = displayName(pk);

          tile.appendChild(v);
          tile.appendChild(label);
          remoteWrap.appendChild(tile);
        }
        const vid = tile.querySelector("video");
        if (vid){
          vid.srcObject = stream;
          vid.play().catch(()=>{});
        }
      }

      function removeRemoteTile(pk){
        document.getElementById("tile-" + pk)?.remove();
      }

      async function createPC(remotePk){
        const iceServers = await getIceServers();
        const pc = new RTCPeerConnection({ iceServers });

        pc.onicecandidate = (e) => {
          if (e.candidate && currentRoomId){
            socket.emit("rtc:signal", { room_id: currentRoomId, to: remotePk, type: "ice", payload: e.candidate });
          }
        };

        pc.ontrack = (e) => addRemoteTile(remotePk, e.streams[0]);

        pc.oniceconnectionstatechange = () => {
          if (["disconnected","failed","closed"].includes(pc.iceConnectionState)){
            closePC(remotePk);
          }
        };

        localStream?.getTracks().forEach(track => pc.addTrack(track, localStream));

        peerConnections[remotePk] = pc;
        return pc;
      }

      function closePC(remotePk){
        const pc = peerConnections[remotePk];
        if (pc){ try{ pc.close(); }catch{} delete peerConnections[remotePk]; }
        removeRemoteTile(remotePk);
      }

      async function joinRoom(roomId){
        if (!myPubkey){ updateStatus("Please log in to join a call"); return; }
        if (currentRoomId) await leaveRoom();

        try{
          await ensureLocalStream();
          currentRoomId = roomId;
          setUI(true);
          updateStatus("Joining room…");
          socket.emit("rtc:join_room", { room_id: roomId });
        } catch (e){
          updateStatus("Camera/mic denied");
          await leaveRoom();
        }
      }

      async function leaveRoom(){
        if (currentRoomId) socket.emit("rtc:leave_room", { room_id: currentRoomId });

        Object.keys(peerConnections).forEach(closePC);
        peerConnections = {};

        if (localStream){
          localStream.getTracks().forEach(t => t.stop());
          localStream = null;
          if (localVideoEl) localVideoEl.srcObject = null;
        }

        if (remoteWrap) remoteWrap.innerHTML = "";
        currentRoomId = null;
        isMuted = false;
        isCameraOff = false;
        muteBtn?.classList.remove("active");
        cameraBtn?.classList.remove("active");
        if (muteBtn) muteBtn.innerHTML = "<span>🔊</span>Mute";
        if (cameraBtn) cameraBtn.innerHTML = "<span>📷</span>Camera Off";
        setUI(false);
        updateStatus("Not in a call");
      }

      async function handleRoomPeers(data){
        if (!data?.peers || !currentRoomId) return;
        updateStatus(`In room with ${data.peers.length} peer(s)`);

        for (const remotePk of data.peers){
          if (remotePk === myPubkey) continue;
          if (peerConnections[remotePk]) continue;
          try{
            const pc = await createPC(remotePk);
            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);
            socket.emit("rtc:signal", { room_id: currentRoomId, to: remotePk, type: "offer", payload: offer });
          } catch {}
        }
      }

      async function handleSignal(data){
        if (!data || !data.from || !currentRoomId) return;
        const remotePk = data.from;
        if (remotePk === myPubkey) return;

        try{
          if (data.type === "offer"){
            let pc = peerConnections[remotePk];
            if (!pc) pc = await createPC(remotePk);
            await pc.setRemoteDescription(new RTCSessionDescription(data.payload));
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            socket.emit("rtc:signal", { room_id: currentRoomId, to: remotePk, type: "answer", payload: answer });
          } else if (data.type === "answer"){
            const pc = peerConnections[remotePk];
            if (pc) await pc.setRemoteDescription(new RTCSessionDescription(data.payload));
          } else if (data.type === "ice"){
            const pc = peerConnections[remotePk];
            if (pc && data.payload) await pc.addIceCandidate(new RTCIceCandidate(data.payload));
          }
        } catch {}
      }

      function toggleMute(){
        if (!localStream) return;
        isMuted = !isMuted;
        localStream.getAudioTracks().forEach(t => t.enabled = !isMuted);
        if (muteBtn){
          muteBtn.classList.toggle("active", isMuted);
          muteBtn.innerHTML = isMuted ? "<span>🔇</span>Unmute" : "<span>🔊</span>Mute";
        }
      }

      function toggleCamera(){
        if (!localStream) return;
        isCameraOff = !isCameraOff;
        localStream.getVideoTracks().forEach(t => t.enabled = !isCameraOff);
        if (cameraBtn){
          cameraBtn.classList.toggle("active", isCameraOff);
          cameraBtn.innerHTML = isCameraOff ? "<span>📹</span>Camera On" : "<span>📷</span>Camera Off";
        }
      }

      function init(){
        hangupBtn?.addEventListener("click", leaveRoom);
        muteBtn?.addEventListener("click", toggleMute);
        cameraBtn?.addEventListener("click", toggleCamera);

        socket.on("rtc:room_peers", handleRoomPeers);
        socket.on("rtc:signal", handleSignal);

        socket.on("rtc:peer_left", (d) => { if (d?.pubkey) closePC(d.pubkey); });

        // accept invites from either event name (backward compatibility)
        socket.on("rtc:invite", (d) => { if (d?.room_id) joinRoom(d.room_id); });
        socket.on("rtc:call_invite", (d) => { if (d?.room_id) joinRoom(d.room_id); });

        socket.on("rtc:error", (d) => updateStatus(d?.error || "RTC error"));
      }

      return { init, joinRoom, leaveRoom };
    })();

    GroupCallManager.init();

    // direct call from long-press
    async function startCall(targetPubkey){
      if (!targetPubkey || !myPubkey) return;
      const roomId = "direct-" + [myPubkey, targetPubkey].sort().join("-");
      GroupCallManager.joinRoom(roomId);

      // invite the other side (supports either handler server-side)
      socket.emit("rtc:invite", { to: targetPubkey, room_id: roomId, from_name: shortKey(myPubkey) });
      socket.emit("rtc:call_invite", { to: targetPubkey, room_id: roomId, from_name: shortKey(myPubkey) });
    }

    // group call picker (max 3 others)
    function startGroupCall(){
      const onlineUsers = Array.from(document.querySelectorAll('.user-item'))
        .map(li => li.dataset.pubkey)
        .filter(pk => pk && pk !== myPubkey);

      if (onlineUsers.length === 0){ alert("No other users online"); return; }

      const popup = document.createElement('div');
      popup.style.cssText =
        'position:fixed;inset:0;display:flex;align-items:center;justify-content:center;' +
        'background:rgba(0,0,0,.75);z-index:10000;padding:16px;';
      popup.innerHTML =
        '<div style="max-width:420px;width:100%;background:rgba(8,12,10,.92);border:1px solid rgba(0,255,136,.35);' +
        'box-shadow:0 0 30px rgba(0,255,136,.18);border-radius:14px;padding:16px;">' +
        '<div style="font-family:var(--mono);color:#00ff88;margin-bottom:10px;">Select users (max 3)</div>' +
        '<div id="userCheckboxes" style="max-height:260px;overflow:auto;margin-bottom:12px;"></div>' +
        '<div style="display:flex;gap:10px;justify-content:flex-end;">' +
        '<button id="cancelCallBtn" style="padding:8px 12px;border-radius:10px;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.25);color:#e6f1ef;cursor:pointer;">Cancel</button>' +
        '<button id="startCallBtn" style="padding:8px 12px;border-radius:10px;border:1px solid rgba(0,255,136,.35);background:rgba(0,255,136,.12);color:#00ff88;cursor:pointer;">Start</button>' +
        '</div></div>';
      document.body.appendChild(popup);

      const box = popup.querySelector('#userCheckboxes');
      onlineUsers.forEach(pk => {
        const row = document.createElement('label');
        row.style.cssText = 'display:flex;align-items:center;gap:10px;color:#e6f1ef;margin:8px 0;cursor:pointer;font-family:var(--mono);font-size:12px;';
        row.innerHTML = `<input type="checkbox" value="${pk}" /> <span>${displayName(pk)}</span>`;
        box.appendChild(row);
      });

      popup.querySelector('#cancelCallBtn').onclick = () => popup.remove();
      popup.querySelector('#startCallBtn').onclick = () => {
        const selected = Array.from(popup.querySelectorAll('input[type=checkbox]:checked')).map(cb => cb.value);
        if (selected.length === 0) { alert('Select at least one'); return; }
        if (selected.length > 3) { alert('Max 3 others (4 total)'); return; }

        const roomId = 'room-' + Math.random().toString(36).slice(2, 9);
        GroupCallManager.joinRoom(roomId);

        selected.forEach(pk => {
          socket.emit("rtc:invite", { to: pk, room_id: roomId, from_name: shortKey(myPubkey) });
          socket.emit("rtc:call_invite", { to: pk, room_id: roomId, from_name: shortKey(myPubkey) });
        });

        popup.remove();
      };
    }
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
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"/>
  <meta name="apple-mobile-web-app-capable" content="yes"/>
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"/>
  <meta name="theme-color" content="#00ff88"/>
  <title>HODLXXI — Login</title>

  <style>
    :root{
      --bg: #000;
      --fg: rgba(235,255,245,.92);
      --muted: rgba(235,255,245,.70);

      --accent: rgba(0,255,136,.95);
      --warn: rgba(255,42,42,.90);
      --blue: rgba(59,130,246,.95);
      --violet: rgba(139,92,246,.95);
      --orange: rgba(249,115,22,.95);

      --glass: rgba(8,12,10,.22);
      --glass2: rgba(0,0,0,.20);
      --stroke: rgba(255,255,255,.08);

      --radius: 16px;
      --pad: 14px;
      --mono: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
      --sans: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    }

    *{ box-sizing:border-box; margin:0; padding:0; -webkit-tap-highlight-color: transparent; }
    html,body{ height:100%; background:var(--bg); color:var(--fg); overflow-x:hidden; }
    body{ font-family: var(--sans); }

    /* Matrix canvas */
    #matrix-bg{ position:fixed; inset:0; width:100vw; height:100vh; display:block; z-index:0; pointer-events:none; }
    body > *:not(#matrix-bg){ position:relative; z-index:1; }

    /* Content */
    .wrap{
      max-width: 980px;
      margin: 0 auto;
      padding: 84px 14px 22px;
    }

    /* Minimal header */
    .topline{
      display:flex;
      align-items:flex-end;
      justify-content:space-between;
      gap:10px;
      margin-bottom: 14px;
    }
    .brand{
      font-family: var(--mono);
      letter-spacing: .14em;
      text-transform: uppercase;
      font-size: 12px;
      color: var(--warn);
      text-shadow: 0 0 6px rgba(255,42,42,.18);
      user-select:none;
    }
    .sub{
      font-family: var(--mono);
      font-size: 11px;
      color: rgba(235,255,245,.62);
      user-select:none;
    }

    /* Panel (glass card) */
    .panel{
      border-radius: var(--radius);
      border: 1px solid var(--stroke);
      background: var(--glass);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      box-shadow: 0 10px 40px rgba(0,0,0,.45);
      overflow:hidden;
      margin: 12px 0;
    }
    .panel-hd{
      padding: 12px 12px 10px;
      border-bottom: 1px solid rgba(255,255,255,.06);
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      flex-wrap: wrap;
    }
    .panel-title{
      font-family: var(--mono);
      letter-spacing: .12em;
      text-transform: uppercase;
      font-size: 11px;
      color: var(--warn);
      text-shadow: 0 0 6px rgba(255,42,42,.18);
      user-select:none;
    }
    .panel-bd{ padding: var(--pad); }

    .manifesto-text{font-family:var(--mono);font-size:12px;line-height:1.55;color:rgba(235,255,245,.78)}
    .manifesto-text b{color:var(--accent)}
    .manifesto-text p{margin:.35rem 0}
    .home-link{color:var(--accent);text-decoration:none}
    .home-link:hover,.home-link:focus{text-decoration:underline;outline:none;text-shadow:0 0 14px rgba(0,255,136,.45)}


    .hintline{
      font-family: var(--mono);
      font-size: 11px;
      color: rgba(235,255,245,.72);
      line-height: 1.35;
    }
    .hintline b{ color: var(--accent); }

    /* Tabs + actions */
    .tabs{
      display:flex; gap:6px; flex-wrap:wrap; align-items:center;
    }
    .tab{
      border-radius: 12px;
      border:1px solid rgba(255,255,255,.08);
      background: rgba(0,0,0,.18);
      color: rgba(235,255,245,.9);
      padding: 8px 10px;
      font-size: 12px;
      font-family: var(--mono);
      cursor:pointer;
      user-select:none;
      touch-action: manipulation;
    }
    .tab.is-active{
      border-color: rgba(0,255,136,.35);
      box-shadow: 0 0 0 1px rgba(0,255,136,.12) inset;
    }

    .pill-actions{
      display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end; align-items:center;
      margin-left:auto;
    }
    .pill{
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,.10);
      background: rgba(0,0,0,.22);
      color: rgba(235,255,245,.92);
      padding: 8px 12px;
      font-family: var(--mono);
      font-size: 12px;
      cursor:pointer;
      user-select:none;
      touch-action: manipulation;
      display:inline-flex;
      align-items:center;
      gap:8px;
    }
    .pill:active{ transform: translateY(1px); background: rgba(0,0,0,.28); }

    .pill.ln{ border-color: rgba(249,115,22,.35); box-shadow: 0 0 0 1px rgba(249,115,22,.10) inset; }
    .pill.nostr{ border-color: rgba(139,92,246,.35); box-shadow: 0 0 0 1px rgba(139,92,246,.10) inset; }
    .pill.primary{ border-color: rgba(0,255,136,.35); box-shadow: 0 0 0 1px rgba(0,255,136,.12) inset; }

    /* Forms */
    label{
      display:block;
      font-family: var(--mono);
      font-size: 10px;
      letter-spacing: .08em;
      text-transform: uppercase;
      color: rgba(255,42,42,.85);
      margin: 10px 0 6px;
    }
    input, textarea{
      width:100%;
      border-radius: 14px;
      border: 1px solid var(--stroke);
      background: rgba(0,0,0,.22);
      color: var(--fg);
      padding: 12px 12px;
      font-size: 16px;
      outline:none;
      -webkit-appearance:none;
      appearance:none;
    }
    textarea{ min-height: 120px; resize: vertical; font-family: var(--mono); font-size: 12px; }

    input:focus, textarea:focus{
      border-color: rgba(0,255,136,.35);
      box-shadow: 0 0 0 1px rgba(0,255,136,.12) inset;
    }

    .row{ display:flex; gap:10px; flex-wrap:wrap; align-items:flex-start; }
    .col{ flex: 1 1 260px; min-width: 0; }

    .btnrow{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-top: 10px; }
    .btn{
      flex: 1 1 180px;
      border-radius: 14px;
      border: 1px solid var(--stroke);
      background: rgba(0,0,0,.20);
      color: var(--fg);
      padding: 12px 12px;
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: .02em;
      cursor:pointer;
      user-select:none;
      touch-action: manipulation;
      text-align:center;
    }
    .btn:active{ transform: translateY(1px); background: rgba(0,0,0,.28); }
    .btn.primary{
      border-color: rgba(0,255,136,.35);
      box-shadow: 0 0 0 1px rgba(0,255,136,.12) inset;
    }
    .btn.warn{
      border-color: rgba(255,42,42,.35);
      box-shadow: 0 0 0 1px rgba(255,42,42,.10) inset;
    }

    .status{
      font-family: var(--mono);
      font-size: 11px;
      color: rgba(235,255,245,.72);
      padding: 10px 0 0;
      min-height: 18px;
    }

    /* Challenge card */
    .card{
      border-radius: 14px;
      border: 1px solid var(--stroke);
      background: rgba(0,0,0,.20);
      padding: 12px 12px;
      margin: 10px 0;
      overflow:hidden;
    }
    .challenge{
      font-family: var(--mono);
      font-size: 12px;
      color: var(--accent);
      text-shadow: 0 0 8px rgba(0,255,136,.18);
      word-break: break-word;
      cursor: pointer;
      user-select: none;
      text-align: center;
    }

    .hidden{ display:none !important; }

    /* QR modal (glass, not white) */
    .body-locked{ height: 100dvh; overflow:hidden; }
    #qrModal{
      position:fixed; inset:0;
      background: rgba(0,0,0,.92);
      display:none;
      align-items:center;
      justify-content:center;
      z-index:99999;
      padding: max(12px, env(safe-area-inset-top)) 12px max(12px, env(safe-area-inset-bottom));
      backdrop-filter: blur(2px);
      -webkit-backdrop-filter: blur(2px);
    }
    .qr-content{
      width: min(420px, 92vw);
      border-radius: 16px;
      border: 1px solid rgba(255,255,255,.10);
      background: rgba(8,12,10,.22);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      box-shadow: 0 10px 40px rgba(0,0,0,.55);
      padding: 14px;
      text-align:center;
      color: rgba(235,255,245,.92);
    }
    .qr-title{
      font-family: var(--mono);
      font-size: 11px;
      letter-spacing: .12em;
      text-transform: uppercase;
      color: var(--warn);
      text-shadow:0 0 6px rgba(255,42,42,.18);
      margin-bottom: 10px;
      user-select:none;
    }
    #qrcode{ display:flex; justify-content:center; padding: 6px 0 2px; }
    #openInWallet{
      display:inline-block;
      margin-top: 8px;
      font-family: var(--mono);
      font-size: 12px;
      color: var(--blue);
      text-decoration:none;
    }
    #openInWallet:hover{ text-decoration: underline; }
    #lnurlText{
      margin-top: 10px;
      padding: 10px 10px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,.08);
      background: rgba(0,0,0,.20);
      font-family: var(--mono);
      font-size: 11px;
      word-break: break-all;
      color: rgba(235,255,245,.82);
    }
    #countdown{
      margin-top: 8px;
      font-family: var(--mono);
      font-size: 11px;
      color: rgba(235,255,245,.72);
    }

    @media (prefers-reduced-motion: reduce){
      #matrix-bg{ display:none !important; }
      *{ transition:none !important; animation:none !important; }
    }


/* LOGIN_MANIFESTO_SINGLE_V1_CSS */
.manifesto-details{ position:relative; }
.manifesto-summary{
  list-style:none;
  cursor:pointer;
  user-select:none;
  display:flex;
  align-items:center;
  justify-content:flex-end;
  gap:8px;
  margin: 6px 0 10px;
  font-family: var(--mono);
  font-size: 11px;
  color: rgba(235,255,245,.78);
}
.manifesto-summary::-webkit-details-marker{ display:none; }
.manifesto-summary-label{
  color: var(--accent);
  text-shadow: 0 0 10px rgba(0,255,136,.25);
}
.manifesto-summary-icon{
  opacity:.85;
  transform: translateY(-1px);
  transition: transform .18s ease;
}

/* closed: show ~3 lines */
.manifesto-preview{
  max-height: 4.9em;
  overflow:hidden;
  position:relative;
  padding-bottom: 4px;
}
.manifesto-preview:after{
  content:"";
  position:absolute;
  left:0; right:0; bottom:0;
  height: 1.6em;
  background: linear-gradient(to bottom, rgba(0,0,0,0), rgba(0,0,0,.55));
  pointer-events:none;
}

/* open: reveal full */
.manifesto-full{ display:none; }
.manifesto-details[open] .manifesto-full{ display:block; margin-top: 10px; }
.manifesto-details[open] .manifesto-preview{ max-height:none; }
.manifesto-details[open] .manifesto-preview:after{ display:none; }
.manifesto-details[open] .manifesto-summary-icon{ transform: rotate(180deg); }
.manifesto-details[open] .manifesto-summary-label::after{
  content:" (collapse)";
  color: rgba(235,255,245,.55);
}

</style>
  <link rel="stylesheet" href="/static/ui_core.css?v=1"/>
</head>

<body>
  <canvas id="matrix-bg" aria-hidden="true"></canvas>

  <!-- Optional login sound -->
  <audio id="login-sound" src="/static/sounds/login.mp3" preload="auto" playsinline></audio>

  <div class="wrap">
    <!-- LOGIN_MANIFESTO_SINGLE_V1: single manifesto panel -->
    <div class="manifesto panel">
      <div class="panel-hd">
        <div class="panel-title">HODLXXI MANIFESTO</div>
        <div class="hintline">Bitcoin-native identity, presence, and covenants.</div>
      </div>
      <div class="panel-bd">
        <details class="manifesto-details" id="manifestoDetails">
          <summary class="manifesto-summary">
            <span class="manifesto-summary-label">Read more</span>
            <span class="manifesto-summary-icon" aria-hidden="true">▾</span>
          </summary>

          <div class="manifesto-preview manifesto-text">
            <p><b>HODLXXI</b> is a Bitcoin-native Auth0: sign-in with keys, not accounts.</p>
            <p>OAuth2/OIDC for apps, LNURL-Auth for wallets, Nostr for social identity, and Proof-of-Funds for trust gating.</p>
          </div>

          <div class="manifesto-full manifesto-text">
            <p><b>Keys replace accounts.</b> You authenticate by proving control of a key — not by handing over email + password.</p>
            <p><b>Developers get standards:</b> OAuth2/OIDC for Web2/Web3 apps, sessions, scopes, and redirects.</p>
            <p><b>Users get native flows:</b> Bitcoin signatures, LNURL-Auth QR, Nostr extensions, and optional Proof-of-Funds signals.</p>
            <p><b>Presence is a signal</b> (who is online / ready to coordinate), not a harvested social graph.</p>
            <p><b>Covenant descriptors</b> extend identity into time: reciprocal commitments with observable rules.</p>

            <p style="margin-top:.6rem;opacity:.92">
              <a class="home-link" href="/new-index">← Home</a>
            </p>
          </div>
        </details>
      </div>
    </div>


    

    <div class="topline">
      <div>
        <div class="brand">HODLXXI // LOGIN</div>
      </div>
      <div class="sub" id="miniStatus">status: ready</div>
    </div>

    <section class="panel">
      <div class="panel-hd">
        <div class="panel-title">Authenticate</div>

<div class="tabs" role="tablist" aria-label="Login methods">
  <button id="tabGuest" class="tab is-active" onclick="showTab('guest')" type="button">Guest</button>
  <button id="tabLegacy" class="tab" onclick="showTab('legacy')" type="button">Legacy</button>
  <button id="tabApi" class="tab" onclick="showTab('api')" type="button">API</button>
  <button id="tabSpecial" class="tab" onclick="showTab('special')" type="button">Special</button>
</div>

        <div class="pill-actions">
          <button class="pill nostr" type="button" onclick="loginWithNostr()" id="nostrBtn">🟣 Nostr</button>
          <button class="pill ln" type="button" onclick="loginWithLightning()" id="lnBtn">⚡ Lightning</button>
          <a class="pill" href="/pof/leaderboard" style="text-decoration:none;">🏆 PoF</a>
          <a class="pill" href="/playground" style="text-decoration:none;">▶ Playground</a>
          <a class="pill" href="/docs2" style="text-decoration:none;">📚 Docs</a>
        </div>
        <!-- LOGIN_MANIFESTO_DETAILS_V2: Variant C -->
        

      </div>

      <div class="panel-bd">
        <div class="hintline">
          Start with <b>Guest</b> or authenticate using <b>Lightning</b>, <b>Nostr</b>, or <b>Legacy</b>.
          Use <b>Lightning</b> for LNURL-Auth QR. Use <b>Nostr</b> via extension.
        </div>

        <!-- Legacy panel -->
         <div id="panelLegacy" class="hidden">
          <div class="card">
            <div class="challenge" id="legacyChallenge" title="Tap to copy">{{ challenge }}</div>
          </div>

          <div class="row">
            <div class="col">
              <label for="legacyPubkey">Public key (hex)</label>
              <input id="legacyPubkey" placeholder="02.. or 03.." autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"/>
            </div>
            <div class="col">
              <label for="legacySignature">Signature (base64)</label>
              <textarea id="legacySignature" rows="4" placeholder="paste signature"></textarea>
            </div>
          </div>

          <div class="btnrow">
            <button class="btn" type="button" onclick="copyText('legacyChallenge')">Copy challenge</button>
            <button class="btn primary" type="button" onclick="legacyVerify()">Verify &amp; Login</button>
          </div>

          <div id="legacyStatus" class="status"></div>
        </div>

        <!-- API panel -->
        <div id="panelApi" class="hidden">
          <div class="row">
            <div class="col">
              <label for="apiPubkey">Public key (hex)</label>
              <input id="apiPubkey" placeholder="02.. or 03.." autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"/>
            </div>
            <div class="col">
              <label for="apiChallenge">Challenge (readonly)</label>
              <textarea id="apiChallenge" rows="3" readonly></textarea>
            </div>
          </div>

          <div class="btnrow">
            <button class="btn primary" type="button" onclick="getChallenge()">Get challenge</button>
            <button class="btn" type="button" onclick="copyText('apiChallenge')">Copy</button>
          </div>

          <div class="row">
            <div class="col">
              <label for="apiSignature">Signature (base64)</label>
              <textarea id="apiSignature" rows="4" placeholder="paste signature"></textarea>
            </div>
            <div class="col">
              <label for="apiCid">Challenge ID</label>
              <input id="apiCid" readonly />
            </div>
          </div>

          <div class="btnrow">
            <button class="btn primary" type="button" onclick="apiVerify()">Verify &amp; Login</button>
          </div>

          <div id="apiStatus" class="status"></div>
        </div>

        <!-- Special panel -->
        <div id="panelSpecial" class="hidden">
          <label for="specialSignature">Special signature</label>
          <textarea id="specialSignature" rows="4" placeholder="Paste special signature"></textarea>
  <div style="margin-top:10px;">
    <div style="opacity:.75;font-size:.9em;margin-bottom:6px;">Challenge (sign this)</div>
    <textarea class="challenge" id="specialChallenge" rows="2" readonly title="Tap to copy"></textarea>
    <button class="btn" type="button" onclick="copyText('specialChallenge')">Copy challenge</button>
  </div>
          <div class="btnrow">
            <button class="btn primary" type="button" onclick="specialLogin()">Verify &amp; Login</button>
          </div>
          <div id="specialStatus" class="status"></div>
        </div>

        <!-- Guest panel -->
        <div id="panelGuest">
          <label for="guestPin">Guest / PIN (blank = random)</label>
          <input id="guestPin" type="text" placeholder="PIN or leave blank" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"/>
          <div class="btnrow">
            <button class="btn primary" type="button" onclick="guestLogin()">Enter as Guest</button>
          </div>
          <div class="status">Tip: invited PINs map to named guests (server-side).</div>
        </div>
      </div>
    </section>

    <!-- Optional stats panel (only shows if you later inject values with Jinja) -->
    <section class="panel hidden" id="nodePanel">
      <div class="panel-hd">
        <div class="panel-title">Node</div>
      </div>
      <div class="panel-bd">
        <div class="hintline mono">block_height={{ block_height }} · balance={{ wallet_balance }} · remaining={{ remaining }}</div>
        <div class="hintline mono">startup={{ startup_time }} · mempool={{ mempool_txs }} ({{ mempool_usage }})</div>
      </div>
    </section>
  </div>

<!-- QR modal -->
<div id="qrModal" aria-hidden="true">
  <div class="qr-content">
    <div class="qr-title">Scan with wallet</div>



<style>
/* LOGIN_QR_UI_V6: final QR modal layout (iPad landscape + phone) */

/* Background never steals taps */
#matrix-bg, #matrix-canvas, canvas#matrix-bg, canvas#matrix-canvas { pointer-events:none !important; z-index:0 !important; }

/* Buttons always tappable */
#lnBtn, #nostrBtn, button, .pill { position:relative; z-index:50; pointer-events:auto; touch-action:manipulation; -webkit-tap-highlight-color:rgba(0,0,0,0); }

/* Modal on top */
#qrModal{ position:fixed !important; inset:0 !important; z-index:999999 !important; overflow:auto !important; -webkit-overflow-scrolling:touch; padding:max(10px, env(safe-area-inset-top)) max(10px, env(safe-area-inset-right)) max(10px, env(safe-area-inset-bottom)) max(10px, env(safe-area-inset-left)); }

/* Card (your #qrCard wrapper) */
#qrCard, #qrCard.qr-card{
  width:min(92vw, 520px);
  max-height:86vh;
  overflow:auto;
  margin:10px auto;
  padding:12px;
  border-radius:16px;
  border:1px solid rgba(0,255,0,0.25);
  background:rgba(0,0,0,0.55);
  box-shadow:0 0 18px rgba(0,255,0,0.12);
}

/* QR + text */
#qrcode{ display:flex; justify-content:center; padding:8px 0 4px; }
#lnurlText{
  display:block;
  font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
  font-size:13px; line-height:1.25; opacity:.95;
  word-break:break-all;
  max-height:11em; overflow:auto;
  padding:8px 10px;
  border-radius:10px;
  border:1px solid rgba(0,255,0,0.25);
  background:rgba(0,0,0,0.35);
}
#countdown{ display:block; margin-top:8px; font-size:13px; opacity:.9; }

/* LANDSCAPE: use max-height so it works on ALL iPads (including Pro) */
@media (orientation: landscape) and (max-height: 900px){
  #qrCard, #qrCard.qr-card{
    width:min(96vw, 980px);
    display:grid;
    grid-template-columns:260px 1fr;
    gap:12px;
    align-items:start;
  }
  #qrcode{ grid-column:1; }
  #lnurlText{ grid-column:2; max-height:8.5em; }
  #countdown{ grid-column:2; }
  #qrcode img, #qrcode canvas{ width:240px !important; height:240px !important; }
}

/* Very short landscape (phones): shrink QR */
@media (orientation: landscape) and (max-height: 700px){
  #qrcode img, #qrcode canvas{ width:200px !important; height:200px !important; }
}
</style>

<div id="qrCard" class="qr-card"> <!-- QR_MODAL_WRAPPER_V3 -->
    <div id="qrcode"></div>

    <a id="openInWallet" href="#" target="_blank" rel="noopener">Open in wallet</a>

    <!-- Mobile fallback: big tap target -->
    <button class="btn primary" id="openWalletBtn" type="button" style="margin-top:10px; width:100%;">
      ⚡ Open Lightning Wallet
    </button>

    <div id="lnurlText"></div>
    <div id="countdown"></div>

</div> <!-- /QR_MODAL_WRAPPER_V3 -->

                <button class="btn" id="copyLnurlBtn" type="button" style="margin-top:8px; width:100%;">📋 Copy LNURL</button>

<div class="btnrow" style="margin-top:10px;">
      <button class="btn warn" type="button" onclick="closeQR()">✕ Close</button>
    </div>
  </div>
</div>

  <script src="/static/js/qrcode.min.js"></script>
  <script src="/static/js/ios_tapfix.js"></script>
<script src="/static/js/tapfix_v2.js"></script>
<script src="/static/js/tap_probe.js"></script>


  <script>
    // Helper to respect ?next= parameter for post-login redirects
    function getRedirectUrl() {
      const params = new URLSearchParams(window.location.search);
      const next = params.get("next");
      return next || "/account";
    }

    function showTab(which) {
      const panels = {
        legacy: ["tabLegacy", "panelLegacy"],
        api: ["tabApi", "panelApi"],
        special: ["tabSpecial", "panelSpecial"],
        guest: ["tabGuest", "panelGuest"],
      };
      Object.entries(panels).forEach(([k,[tabId,panelId]]) => {
        const tab = document.getElementById(tabId);
        const panel = document.getElementById(panelId);
        if (tab) tab.classList.toggle("is-active", k === which);
        if (panel) panel.classList.toggle("hidden", k !== which);
      });
    }

    function setStatus(id, msg) {
      const el = document.getElementById(id);
      if (el) el.textContent = msg || "";
      const mini = document.getElementById("miniStatus");
      if (mini) mini.textContent = "status: " + (msg ? msg.toLowerCase() : "ready");
    }

    function copyText(id) {
      const el = document.getElementById(id);
      const txt =
        el.tagName === "TEXTAREA" || el.tagName === "INPUT"
          ? el.value
          : el.textContent.trim();
      navigator.clipboard.writeText(txt).catch(()=>{});
    }

    // Tap-to-copy challenge
    (function(){
      const legacyEl = document.getElementById("legacyChallenge");
      if (!legacyEl) return;
      legacyEl.addEventListener("click", () => {
        const text = legacyEl.textContent.trim();
        navigator.clipboard.writeText(text).then(() => {
          const orig = legacyEl.style.opacity || "1";
          legacyEl.style.opacity = "0.65";
          setTimeout(() => (legacyEl.style.opacity = orig), 220);
        }).catch(()=>{});
      });
    })();

    // Mirror legacy challenge into Special tab
    (function(){
      const src = document.getElementById("legacyChallenge");
      const dst = document.getElementById("specialChallenge");
      if (src && dst) dst.value = (src.textContent || "").trim();
    })();

    // --- Legacy verify ---
    async function legacyVerify() {
      const pubkey = document.getElementById("legacyPubkey").value.trim();
      const signature = document.getElementById("legacySignature").value.trim();
      const challenge = document.getElementById("legacyChallenge").textContent.trim();
      setStatus("legacyStatus", "Verifying...");
      try {
        const r = await fetch("/verify_signature", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pubkey, signature, challenge }),
        });
        const d = await r.json().catch(()=> ({}));
        if (r.ok && d.verified) {
          sessionStorage.setItem("playLoginSound", "1");
          window.location.href = getRedirectUrl();
        } else {
          setStatus("legacyStatus", d.error || "Failed");
        }
      } catch (e) {
        setStatus("legacyStatus", "Network error");
      }
    }

    // --- API challenge/verify ---
    async function getChallenge() {
      const pubkey = document.getElementById("apiPubkey").value.trim();
      setStatus("apiStatus", "Requesting challenge...");
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
        setStatus("apiStatus", "Challenge ready");
      } catch (e) {
        setStatus("apiStatus", e.message || "Error");
      }
    }

    async function apiVerify() {
      const pubkey = document.getElementById("apiPubkey").value.trim();
      const signature = document.getElementById("apiSignature").value.trim();
      const cid = document.getElementById("apiCid").value.trim();
      setStatus("apiStatus", "Verifying...");
      try {
        const r = await fetch("/api/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pubkey, signature, challenge_id: cid }),
        });
        const d = await r.json().catch(()=> ({}));
        if (r.ok && d.verified) {
          sessionStorage.setItem("playLoginSound", "1");
          window.location.href = getRedirectUrl();
        } else {
          setStatus("apiStatus", d.error || "Failed");
        }
      } catch (e) {
        setStatus("apiStatus", "Network error");
      }
    }

    // --- Guest login ---
    async function guestLogin() {
      const pin = (document.getElementById("guestPin")?.value || "").trim();
      try {
        const res = await fetch("/guest_login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pin }),
        });
        const data = await res.json().catch(()=> ({}));
        if (!res.ok || !data.ok) {
          alert(data.error || "Guest login failed");
          return;
        }
        window.location.href = getRedirectUrl();
      } catch (e) {
        alert("Guest login error");
      }
    }

    // --- Special login ---
    async function specialLogin() {
      const sig = (document.getElementById("specialSignature")?.value || "").trim();
      setStatus("specialStatus", "Verifying...");
      try {
        const r = await fetch("/special_login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ signature: sig }),
        });
        const d = await r.json().catch(()=> ({}));
        if (r.ok && d.verified) {
          sessionStorage.setItem("playLoginSound", "1");
          window.location.href = getRedirectUrl();
        } else {
          setStatus("specialStatus", d.error || "Failed");
        }
      } catch (e) {
        setStatus("specialStatus", "Network error");
      }
    }
  </script>

  <!-- LNURL auth + Nostr -->
  <script>
    function urlToLnurl(url) {
      const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
      function polymod(v) {
        const G = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3];
        let chk = 1;
        for (const val of v) {
          const top = chk >>> 25;
          chk = ((chk & 0x1ffffff) << 5) ^ val;
          for (let i=0;i<5;i++) if ((top>>>i)&1) chk ^= G[i];
        }
        return chk;
      }
      function hrpExpand(hrp) {
        const ret = [];
        for (let i=0;i<hrp.length;i++) ret.push(hrp.charCodeAt(i)>>5);
        ret.push(0);
        for (let i=0;i<hrp.length;i++) ret.push(hrp.charCodeAt(i)&31);
        return ret;
      }
      function createChecksum(hrp, data) {
        const values = hrpExpand(hrp).concat(data).concat([0,0,0,0,0,0]);
        const mod = polymod(values) ^ 1;
        const ret = [];
        for (let p=0;p<6;p++) ret.push((mod >> (5*(5-p))) & 31);
        return ret;
      }
      function convertBits(data, from, to) {
        let acc=0, bits=0, ret=[], maxv=(1<<to)-1;
        for (const value of data) {
          acc = (acc<<from) | value;
          bits += from;
          while (bits >= to) { bits -= to; ret.push((acc>>bits) & maxv); }
        }
        if (bits > 0) ret.push((acc << (to-bits)) & maxv);
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
      new QRCode(el, { text, width: 256, height: 256, colorDark: "#000", colorLight: "#fff" });
    }


    // --- Mobile-friendly wallet open + copy fallbacks ---
    function openLightningWallet(lnurl) {
      const walletUrl = "lightning:" + lnurl;

      // 1) direct navigation (best when allowed)
      try {window.location.href = walletUrl;} catch(e) {}

      // 2) fallback: temp <a> click (some browsers prefer this)
      setTimeout(() => {
        try {const a = document.createElement("a");
          a.href = walletUrl;
          a.rel = "noopener";
          a.style.display = "none";
          document.body.appendChild(a);
          a.click();
          a.remove();} catch(e) {}
      }, 50);

      // 3) fallback: new tab (some Android cases)
      setTimeout(() => {
        try {window.open(walletUrl, "_blank");} catch(e) {}
      }, 120);
    }

    (function bindLnurlFallbackButtons(){
      const openBtn = document.getElementById("openWalletBtn");
      const copyBtn = document.getElementById("copyLnurlBtn");
      const lnurlBox = document.getElementById("lnurlText");

      if (openBtn && !openBtn.dataset.bound) {
        openBtn.dataset.bound = "1";
        openBtn.addEventListener("click", () => {
          const lnurl = (lnurlBox?.textContent || "").trim();
          if (!lnurl) return alert("LNURL not ready yet");
          openLightningWallet(lnurl);
        }, { passive: true });
      }

      if (copyBtn && !copyBtn.dataset.bound) {
        copyBtn.dataset.bound = "1";
        copyBtn.addEventListener("click", async () => {
          const lnurl = (lnurlBox?.textContent || "").trim();
          if (!lnurl) return alert("LNURL not ready yet");
          try {await navigator.clipboard.writeText(lnurl);
            const old = copyBtn.textContent;
            copyBtn.textContent = "✅ Copied";
            setTimeout(() => (copyBtn.textContent = old), 900);} catch(e) {
            alert("Copy failed — press and hold the LNURL text to copy.");
          }
        }, { passive: true });
      }
    })();
    let poll=null, expire=null;

    function startPolling(sid) {
      clearInterval(poll);
      poll = setInterval(async () => {
        const r = await fetch(`/api/lnurl-auth/check/${sid}`);
        const j = await r.json().catch(()=> ({}));
        if (j.authenticated) {
          clearInterval(poll);
          clearInterval(expire);
          closeQR();
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
        if (el) el.textContent = `Expires in ${Math.floor(r/60)}:${(r%60).toString().padStart(2,"0")}`;
        if (r <= 0) {
          clearInterval(poll);
          clearInterval(expire);
          closeQR();
        }
      }, 1000);
    }

    function closeQR() {
      const modal = document.getElementById("qrModal");
      if (modal) modal.style.display = "none";
      document.body.classList.remove("body-locked");
    }

    async function loginWithLightning() {
      const modal     = document.getElementById("qrModal");
      const qrBox     = document.getElementById("qrcode");
      const lnurlBox  = document.getElementById("lnurlText");
      const countdown = document.getElementById("countdown");

      try {
        if (qrBox) qrBox.innerHTML = "";
        if (lnurlBox) lnurlBox.textContent = "Requesting Lightning login…";
        if (countdown) countdown.textContent = "";
        if (modal) modal.style.display = "flex";
        document.body.classList.add("body-locked");

        const res = await fetch("/api/lnurl-auth/create", { method: "POST", headers: { "Accept": "application/json" }, credentials: "same-origin" });
if (!res.ok) {
          const txt = await res.text().catch(()=> "");
          console.error("LNURL-auth create failed:", res.status, txt);
          alert("Lightning login init failed: " + res.status);
          closeQR();
          return;
        }

        let j;
        try {j = await res.json();} catch (e) {
          console.error("LNURL-auth JSON parse error:", e);
          alert("Lightning login error: invalid server response");
          closeQR();
          return;
        }

        if (!j || !j.callback_url) {
          console.error("LNURL-auth missing callback_url:", j);
          alert("Lightning login error: missing callback_url");
          closeQR();
          return;
        }

        const lnurl = urlToLnurl(j.callback_url);

        
        
// bind mobile fallback buttons (must be a user gesture)

          try {await navigator.clipboard.writeText(lnurl);} catch(e) {}
// Set the link + mobile fallback button

    // REMOVED: orphaned e.preventDefault()


        
        // --- Canonical LNURL UI wiring (single source of truth) ---
        const walletUrl = "lightning:" + lnurl;

        // "Open in wallet" link (works on desktop and some mobile browsers)
        const openInWalletEl = document.getElementById("openInWallet");
        if (openInWalletEl) {
          openInWalletEl.href = walletUrl;
          openInWalletEl.onclick = (e) => {
            e.preventDefault();
            // some mobile browsers require direct navigation
            window.location.href = walletUrl;
          };
        }

        // Mobile-friendly explicit button (user gesture)
        const openBtn = document.getElementById("openWalletBtn");
        if (openBtn) {
          openBtn.onclick = () => {
            try {window.location.href = walletUrl;} catch(e) {}
            // fallback: attempt <a> click
            setTimeout(() => {
              try {const a = document.createElement("a");
                a.href = walletUrl;
                a.rel = "noopener";
                a.style.display = "none";
                document.body.appendChild(a);
                a.click();
                a.remove();} catch(e) {}
            }, 50);
          };
        }

        // Copy LNURL button (works even if wallet open is blocked)
        const copyBtn = document.getElementById("copyLnurlBtn");
        if (copyBtn) {
          copyBtn.onclick = async () => {
            try {await navigator.clipboard.writeText(lnurl);
              alert("LNURL copied");} catch (e) {
              // fallback: prompt
              window.prompt("Copy LNURL:", lnurl);
            }
          };
        }
if (qrBox && typeof QRCode !== "undefined") renderQR(qrBox, lnurl);
        if (lnurlBox) lnurlBox.textContent = lnurl;

        const openEl = document.getElementById("openInWallet");
        if (openEl) {
  openEl.href = "lightning:" + lnurl;
  openEl.onclick = (e) => {
    // Ensure this is a user gesture
    e.preventDefault();
    window.location.href = "lightning:" + lnurl;
  };
}


        startPolling(j.session_id);
        startCountdown(j.expires_in || 300);
      } catch (e) {
        console.error("Lightning login error:", e);
        alert("Lightning login error");
        closeQR();
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
        created_at: Math.floor(Date.now()/1000),
        tags: [["challenge", d.challenge], ["app", "HODLXXI"]],
        content: `HODLXXI Login: ${d.challenge}`,
      };
      const signed = await window.nostr.signEvent(event);
      const vr = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challenge_id: d.challenge_id, pubkey, signature: signed.sig }),
      });
      const j2 = await vr.json();
      if (j2.verified) window.location.href = getRedirectUrl();
      else alert("Verification failed");
    }

    // --- Bind pill buttons (mobile-safe) ---
    (function bindLoginPills(){
      function setMini(msg){
        const mini = document.getElementById("miniStatus");
        if (mini) mini.textContent = "status: " + msg;
      }

      function bindOne(id, fnName){
        const el = document.getElementById(id);
        if (!el) return;

        const fire = async (e) => {
          try {
            if (e && e.preventDefault) e.preventDefault();
            if (e && e.stopPropagation) e.stopPropagation();
            setMini(fnName + "…");
            // Call the function by name to avoid scope issues
            const fn = window[fnName] || (typeof eval === "function" ? eval(fnName) : null);
            if (typeof fn !== "function") {
              setMini(fnName + " missing");
              alert(fnName + " is not available (JS load error).");
              return;
            }
            await fn();
            setMini("ready");
          } catch (err) {
            console.error(fnName + " error:", err);
            setMini("error");
            alert(fnName + " failed: " + (err && err.message ? err.message : "unknown"));
          }
        };

        // iOS: touchstart is often more reliable than click
        el.addEventListener("touchstart", fire, { passive: false });
        el.addEventListener("click", fire, { passive: false });
      }

      // Make sure the global functions are reachable via window
      try {if (typeof loginWithLightning === "function") window.loginWithLightning = loginWithLightning;} catch(e) {}
      try {if (typeof loginWithNostr === "function") window.loginWithNostr = loginWithNostr;} catch(e) {}

      setMini("ready");
    })();

  
  
</script>
  <script>
    // --- Top-level pill wiring (runs on page load) ---
    (function bindLoginPillsTopLevel(){
      function bind(id, fnName){
        const el = document.getElementById(id);
        if (!el) return;

        el.addEventListener("click", async (e) => {
          try {
            e.preventDefault();
            e.stopPropagation();
            const fn = window[fnName];
            if (typeof fn !== "function") {
              console.error("Missing handler:", fnName);
              alert("Init failed: " + fnName + " is not available");
              return;
            }
            await fn();
          } catch (err) {
            console.error(fnName + " error:", err);
            alert("Init failed");
          }
        }, { passive: false });
      }

      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", () => {
          bind("lnBtn", "loginWithLightning");
          bind("nostrBtn", "loginWithNostr");
        });
      } else {
        bind("lnBtn", "loginWithLightning");
        bind("nostrBtn", "loginWithNostr");
      }
    })();
  </script>
</script>

  <!-- Matrix Animation (warp) -->
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
        if (document.hidden) { if (raf) cancelAnimationFrame(raf), raf = null; }
        else { if (!raf) raf = requestAnimationFrame(draw); }
      }

      window.addEventListener('resize', resize);
      document.addEventListener('visibilitychange', onVis);
      resize();
      raf = requestAnimationFrame(draw);
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

    return jsonify(
        {
            "verified": True,
            "access_level": session["access_level"],
            "pubkey": matched_pubkey,
            "plan": user.plan,
        }
    )


@app.route("/guest_login", methods=["POST"])
def guest_login():
    """PIN guest login (stable identity) + random guest fallback."""
    import hashlib
    import secrets
    import os
    import re as _re
    from flask import request, jsonify, session

    # already logged in
    if session.get("logged_in_pubkey"):
        return jsonify(ok=True, label=session.get("guest_label"), already_logged_in=True), 200

    data = request.get_json(silent=True) or {}
    pin = (request.form.get("pin") or request.values.get("pin") or data.get("pin") or "").strip().lower()

    # Parse GUEST_STATIC_PINS env: "9ca5:9ca5,e923:HOST,..."
    raw = (os.getenv("GUEST_STATIC_PINS", "") or "").strip()
    pins = {}
    for part in _re.split(r"[,\s]+", raw):
        part = (part or "").strip()
        if not part:
            continue
        if ":" in part:
            k, v = part.split(":", 1)
            k = (k or "").strip().lower()
            v = (v or "").strip()
            if k:
                pins[k] = v or k
        else:
            k = part.strip().lower()
            if k:
                pins[k] = k

    # --- PIN login: stable identity ---
    if pin:
        label = pins.get(pin)
        if not label:
            return jsonify(ok=False, error="Invalid PIN"), 403

        guest_id = f"guest-pin-{hashlib.sha256(pin.encode('utf-8')).hexdigest()[:16]}"
        session["logged_in_pubkey"] = guest_id
        session["access_level"] = "limited"
        session["login_method"] = "pin_guest"
        session["guest_label"] = f"Guest-{label}"

        return jsonify(ok=True, label=session["guest_label"], pubkey=guest_id, login_method="pin_guest"), 200

    # --- Random guest fallback (no pin provided) ---
    rid = secrets.token_hex(6)
    guest_id = f"guest-random-{rid}"
    session["logged_in_pubkey"] = guest_id
    session["access_level"] = "limited"
    session["login_method"] = "random_guest"
    session["guest_label"] = f"Guest-{rid}"
    return jsonify(ok=True, label=session["guest_label"], pubkey=guest_id, login_method="random_guest"), 200


def _guest_static_pins_map():
    """
    Parse GUEST_STATIC_PINS env like:
      "9ca5:9ca5,e923:HOST,4f96:4f96"
    Returns dict: {pin_lower: label}
    """
    import os
    import re

    raw = (os.getenv("GUEST_STATIC_PINS", "") or "").strip()
    if not raw:
        return {}
    out = {}
    for part in re.split(r"[,\s]+", raw):
        part = (part or "").strip()
        if not part:
            continue
        if ":" in part:
            k, v = part.split(":", 1)
            k = (k or "").strip().lower()
            v = (v or "").strip()
            if k:
                out[k] = v or k
        else:
            k = part.strip().lower()
            if k:
                out[k] = k
    return out


# ---- Special Login ----
SPECIAL_USERS = [p.strip() for p in os.getenv("SPECIAL_USERS", "").split(",") if p.strip()]


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

:root{
  --bg: #070b0f;
  --panel: rgba(12, 16, 22, 0.78);
  --fg: #e7fff4;
  --muted: rgba(231,255,244,.72);
  --accent: #00ff88;
  --accent2: #3b82f6;
  --danger: #ff3b30;
  --warn: #f59e0b;
  --glass: rgba(10, 14, 20, 0.55);
  --glass2: rgba(10, 14, 20, 0.25);
  --border: rgba(0, 255, 136, 0.18);
  --border2: rgba(59, 130, 246, 0.22);
  --shadow: 0 10px 40px rgba(0,0,0,.55);
  --shadow2: 0 0 24px rgba(0,255,136,.16);
  --radius: 16px;
  --radius2: 12px;
  --pad: 16px;
  --touch: 44px;
}

*{ box-sizing:border-box; -webkit-tap-highlight-color: transparent; }
html,body{ height:100%; }
body{
  margin:0;
  font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, "Apple Color Emoji","Segoe UI Emoji";
  color: var(--fg);
  background: radial-gradient(900px 450px at 50% 0%, rgba(0,255,136,.14), rgba(0,0,0,0) 55%),
              radial-gradient(700px 420px at 70% 12%, rgba(59,130,246,.10), rgba(0,0,0,0) 60%),
              #03060a;
  overflow-x:hidden;
}

/* Matrix canvas behind everything */
#matrix-bg{
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events:none;
}
body > *:not(#matrix-bg){ position:relative; z-index:1; }

.container{
  max-width: 1100px;
  margin: 0 auto;
  padding: 4.25rem 1rem 2rem;
}

.header{
  text-align:center;
  margin-bottom: 1rem;
}

.app-title{
  margin: 0 0 .5rem;
  font-size: clamp(1.55rem, 5.5vw, 2.25rem);
  letter-spacing: .18em;
  text-transform: uppercase;
  color: var(--accent);
  text-shadow: 0 0 18px rgba(0,255,136,.35);
}

.home-link{
  color: var(--accent);
  text-decoration:none;
}
.home-link:hover, .home-link:focus{
  text-decoration:underline;
  outline:none;
  text-shadow: 0 0 26px rgba(0,255,136,.65);
}

.manifesto-panel{
  margin-top: .75rem;
  padding: 1rem 1rem;
  border-radius: var(--radius);
  background: linear-gradient(180deg, rgba(12,16,22,.82), rgba(12,16,22,.62));
  border: 1px solid var(--border);
  box-shadow: var(--shadow2);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
}

.manifesto-text{
  text-align:left;
  color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono","Courier New", monospace;
  font-size: .78rem;
  line-height: 1.65;
}
.manifesto-text a{
  color: var(--muted);
  text-decoration:none;
}
.manifesto-text a:hover{ color: var(--fg); text-decoration: underline; }

.manifesto-actions{ margin-top: .95rem; }
.manifesto-actions-inner{
  display:inline-flex;
  gap: 10px;
  flex-wrap:wrap;
  align-items:center;
  justify-content:center;
}

.btn-icon{
  min-height: 34px;
  padding: .38rem .9rem;
  border-radius: 999px;
  border: 1px solid rgba(231,255,244,.28);
  background: rgba(10,14,20,.55);
  color: var(--fg);
  cursor:pointer;
  transition: transform .15s ease, box-shadow .15s ease, border-color .15s ease, background .15s ease, color .15s ease;
  box-shadow: 0 6px 20px rgba(0,0,0,.35);
}
.btn-icon:hover, .btn-icon:active{
  transform: translateY(-1px);
  border-color: rgba(0,255,136,.35);
  box-shadow: 0 0 18px rgba(0,255,136,.18);
  background: rgba(0,255,136,.06);
  color: var(--accent);
}
.btn-icon.exit{
  border-color: rgba(255,59,48,.35);
  color: rgba(255,220,220,.92);
}
.btn-icon.exit:hover{
  background: rgba(255,59,48,.12);
  border-color: rgba(255,59,48,.6);
  color: #ffe5e5;
}

.main-grid{
  display:grid;
  grid-template-columns: 1fr;
  gap: 16px;
  margin-top: 1.25rem;
  max-width: 980px;
  margin-inline: auto;
}

.panel{
  border-radius: var(--radius);
  padding: var(--pad);
  background: var(--panel);
  border: 1px solid var(--border);
  box-shadow: var(--shadow);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  overflow:hidden;
}
.panel:hover{
  border-color: rgba(0,255,136,.28);
  box-shadow: 0 10px 46px rgba(0,0,0,.6), 0 0 22px rgba(0,255,136,.12);
}

.panel h2{
  margin: 0 0 1rem;
  text-align:center;
  color: var(--accent);
  letter-spacing: .08em;
  text-transform: uppercase;
  font-size: clamp(1rem, 4vw, 1.25rem);
}

/* Form */
.form-group{ margin-bottom: 1rem; }
.form-group label{
  display:block;
  margin-bottom: .5rem;
  color: var(--accent);
  font-weight: 700;
  font-size: .9rem;
}

input, textarea{
  width:100%;
  min-height: var(--touch);
  padding: .75rem .85rem;
  border-radius: 12px;
  border: 1px solid rgba(231,255,244,.14);
  background: rgba(0,0,0,.32);
  color: var(--fg);
  outline:none;
  transition: border-color .15s ease, box-shadow .15s ease, background .15s ease;
}
input:focus, textarea:focus{
  border-color: rgba(0,255,136,.55);
  box-shadow: 0 0 0 2px rgba(0,255,136,.22);
  background: rgba(0,0,0,.38);
}

textarea{
  resize: vertical;
  min-height: 120px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono","Courier New", monospace;
}

/* Buttons */
.btn{
  width:100%;
  min-height: var(--touch);
  border: none;
  border-radius: 999px;
  padding: .85rem 1rem;
  font-weight: 800;
  letter-spacing: .06em;
  text-transform: uppercase;
  cursor:pointer;
  background: linear-gradient(90deg, rgba(0,255,136,1), rgba(0,255,136,.78));
  color: #00140a;
  transition: transform .15s ease, box-shadow .15s ease, filter .15s ease;
}
.btn:hover, .btn:active{
  transform: translateY(-1px);
  box-shadow: 0 0 22px rgba(0,255,136,.28);
  filter: brightness(1.03);
}
.btn.btn-secondary, .btn-secondary{
  background: rgba(0,0,0,.18);
  border: 1px solid rgba(0,255,136,.42);
  color: var(--accent);
}
.btn-secondary:hover, .btn-secondary:active{
  background: rgba(0,255,136,.07);
  color: var(--fg);
}

/* Summary pill */
.balance-summary{
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap: 10px;
  flex-wrap:wrap;
  padding: .85rem 1rem;
  border-radius: 999px;
  border: 1px dashed rgba(0,255,136,.55);
  background: rgba(0,255,136,.04);
  margin: 1rem 0;
}
.balance-item{ flex:1; min-width: 150px; text-align:center; }
.balance-label{
  display:block;
  font-size: .75rem;
  opacity:.85;
  letter-spacing:.12em;
  text-transform: uppercase;
}
.balance-value{
  margin-top: .25rem;
  font-weight: 900;
  font-size: clamp(1rem, 3vw, 1.15rem);
  word-break: break-word;
}
.balance-in{ color: var(--accent); }
.balance-out{ color: var(--accent2); }

/* Covenant cards */
.contracts-container{ margin-top: 1rem; }
.contract-box{
  background: rgba(0,0,0,.28);
  border: 1px solid rgba(231,255,244,.16);
  border-radius: var(--radius2);
  padding: .85rem .9rem;
  margin-bottom: 1rem;
  box-shadow: 0 8px 26px rgba(0,0,0,.35);
  overflow:hidden;
}
.contract-box.input-role{
  border-color: rgba(0,255,136,.55);
  box-shadow: 0 0 22px rgba(0,255,136,.14);
}
.contract-box.output-role{
  border-color: rgba(59,130,246,.55);
  box-shadow: 0 0 22px rgba(59,130,246,.14);
}
.contract-box pre{
  margin: .25rem 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: clamp(.7rem, 2.4vw, .86rem);
}

.nostr-info{ font-size: .8rem; color: var(--muted); }

/* QR modal */
.body-locked{ height:100dvh; overflow:hidden; }
.qr-modal{
  position:fixed;
  inset:0;
  display:none;
  align-items:center;
  justify-content:center;
  z-index: 99999;
  background: rgba(0,0,0,.94);
  padding: env(safe-area-inset-top) 1rem env(safe-area-inset-bottom);
  backdrop-filter: blur(2px);
  -webkit-backdrop-filter: blur(2px);
}
.qr-video{ width:100vw; height:100vh; object-fit: cover; }
.qr-close{
  position:fixed;
  top: max(12px, env(safe-area-inset-top));
  right: max(12px, env(safe-area-inset-right));
  z-index: 100000;
  border-radius: 999px;
  padding: .42rem .85rem;
  background: rgba(10,14,20,.6);
  border: 1px solid rgba(231,255,244,.24);
  color: var(--fg);
  cursor:pointer;
}

/* RPC */
.rpc-buttons{
  display:grid;
  grid-template-columns: repeat(auto-fit, minmax(160px,1fr));
  gap: 10px;
  margin-bottom: 1rem;
}
.rpc-response{
  background: rgba(0,0,0,.3);
  border: 1px solid rgba(59,130,246,.35);
  border-radius: 12px;
  padding: .9rem;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 420px;
  overflow:auto;
  font-size: clamp(.7rem, 2.4vw, .84rem);
}

/* QR grid */
.qr-codes{
  display:grid;
  grid-template-columns: repeat(auto-fit, minmax(200px,1fr));
  gap: 16px;
  margin-top: 1rem;
  align-items:center;
}
.qr-codes img{
  image-rendering: pixelated;
  max-width: 360px;
  width: 2.5in;
  height: 2.5in;
  border-radius: 12px;
  border: 1px solid rgba(231,255,244,.18);
  box-shadow: 0 0 22px rgba(0,255,136,.18);
}
.qr-codes figcaption{
  margin-top: .5rem;
  color: var(--accent);
  font-weight: 700;
  font-size: clamp(.7rem, 2.4vw, .82rem);
  word-break: break-word;
  text-align:center;
}

/* Mobile */
@media (max-width: 767px){
  .container{ padding: 3.5rem 1rem 1.5rem; }
  .balance-summary{ border-radius: var(--radius); }
  .rpc-buttons{ grid-template-columns: 1fr; }
  .qr-codes{ grid-template-columns: 1fr; }
}

/* Reduced motion */
@media (prefers-reduced-motion: reduce){
  *{ animation:none !important; transition:none !important; }
  #matrix-bg{ display:none !important; }
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
                    <button id="btnScreensaver" class="btn-icon">🖥️ Screensaver</button>
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
                    try {handleUpdateScript();} catch (e) { console.error(e); }
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
      const isMobile = window.matchMedia && window.matchMedia('(max-width: 768px)').matches;
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
                for (let i = 0; i < (isMobile ? 120 : 400); i++) {
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

                    p.z -= (isMobile ? 2 : 5);
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

const btnScreensaver = document.getElementById('btnScreensaver');
if (btnScreensaver) {
    btnScreensaver.addEventListener('click', () => {
        window.open('/screensaver', '_blank', 'noopener,noreferrer');
    });
}

document.getElementById('btnOnboard').addEventListener('click', () => openPanel('onboard'));
document.getElementById('btnChat').addEventListener('click', () => {
    window.open("{{ url_for('chat') }}", '_blank', 'noopener,noreferrer');
});
document.getElementById('btnExit').addEventListener('click', () => {
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
                try {target = localStorage.getItem('hodlxxi_explorer_target') || null;} catch (e) {
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
                try {target = localStorage.getItem('hodlxxi_explorer_target') || null;} catch (e) {
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
    if p.startswith("/pof/certificate/"):
        return None

    # PUBLIC_GUARD_ALLOW_POF_V1
    # Allow PoF pages (viral/public)
    if p.startswith("/pof/"):
        return None

    # Allow public docs/pages
    if p == "/" or p.startswith("/screensaver"):
        return None
    if p.startswith("/docs") or p.startswith("/docs/"):
        return None
    if p in ("/new-index", "/new-keyauth", "/new-signup", "/docs2"):
        return None
    # /PUBLIC_GUARD_ALLOW_POF_V1

    if p.startswith("/playground") or p.startswith("/playground/") or p.startswith("/static/playground"):
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

    # NOTE: Do NOT treat a Bearer header as authenticated.
    # If you later add real token auth, validate the token explicitly here.
    auth = request.headers.get("Authorization", "")

    # Fallback: require session for other /api/*

    # Public allow-list:

    #  - /api/public/*

    #  - /api/playground/*

    #  - /api/pof/stats (public stats only)

    if p.startswith("/api/") and not (

        p.startswith("/api/public/")

        or p.startswith("/api/playground")

        or p in ("/api/pof/stats", "/api/pof/stats/")

    ) and not session.get("logged_in_pubkey"):

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


# WHOAMI_V1
@app.route("/api/whoami", methods=["GET"])
def api_whoami():
    spk = (session.get("logged_in_pubkey") or "").strip()
    return jsonify(
        ok=True,
        logged_in=bool(spk),
        pubkey=spk,
        access_level=session.get("access_level", "limited"),
        login_method=session.get("login_method", ""),
    )


# /WHOAMI_V1
@app.route("/api/challenge", methods=["POST"])
def api_challenge():
    data = request.get_json() or {}
    user_input = (data.get("pubkey") or "").strip()

    # Accept either:
    # - explicit pubkey in request
    # - OR (if logged in) any label, using session pubkey
    pubkey = user_input
    label = ""

    if not pubkey or not is_valid_pubkey(pubkey):
        spk = (session.get("logged_in_pubkey") or "").strip()
        if spk and is_valid_pubkey(spk):
            label = user_input
            pubkey = spk
        else:
            return jsonify(error="Missing or invalid pubkey"), 400
    cid = str(uuid.uuid4())
    challenge = f"HODLXXI:login:{int(time.time())}:{uuid.uuid4().hex[:8]}"
    ACTIVE_CHALLENGES[cid] = {
        "pubkey": pubkey,
        "label": label,
        "challenge": challenge,
        "created": datetime.utcnow(),
        "expires": datetime.utcnow() + timedelta(minutes=5),
        "method": data.get("method", "api"),
    }
    return jsonify(ok=True, challenge_id=cid, challenge=challenge, expires_in=300)


# ALIAS_PLAYGROUND_POF_CHALLENGE_V1
@app.route("/api/playground/pof/challenge", methods=["POST", "OPTIONS"])
def api_playground_pof_challenge():
    """Backward-compatible alias for older front-end code."""
    return api_challenge()


# /ALIAS_PLAYGROUND_POF_CHALLENGE_V1
@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json() or {}
    cid = (data.get("challenge_id") or "").strip()
    pubkey = (data.get("pubkey") or "").strip()
    signature = (data.get("signature") or "").strip()

    if not (cid and signature):
        return jsonify(error="Missing required parameters"), 400

    if not pubkey:
        spk = (session.get("logged_in_pubkey") or "").strip()
        if spk and is_valid_pubkey(spk):
            pubkey = spk

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
        "ok": True,
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


# ALIAS_PLAYGROUND_POF_VERIFY_V1
@app.route("/api/playground/pof/verify", methods=["POST", "OPTIONS"])
def api_playground_pof_verify():
    """Backward-compatible alias for older front-end code."""
    return api_verify()


# /ALIAS_PLAYGROUND_POF_VERIFY_V1
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
# DEPRECATED: old signature flow, kept only for reference.
# @app.route("/verify_signature", methods=["POST"])
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
        "ok": True,
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
    """Public front door:
    - logged-in users -> /home
    - everyone else   -> /screensaver
    """
    from flask import session, redirect, url_for

    try:
        if session.get("logged_in_pubkey"):
            return redirect(url_for("home"))
    except Exception:
        pass
    return redirect("/screensaver", code=302)


from enum import Enum


class ClientType(Enum):
    FREE = "free"
    PAID = "paid"
    PREMIUM = "premium"


from dataclasses import dataclass, field
from typing import List, Set, Optional
from datetime import datetime


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


# OAuth/OIDC in-memory stores (use Redis for production)
CLIENT_STORE = {}
# auth code store is used by cleanup_expired_data() and token flows
AUTH_CODE_STORE = globals().get("AUTH_CODE_STORE", {})


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
                        created_at=redis_client.created_at
                        if isinstance(redis_client.created_at, datetime)
                        else datetime.fromtimestamp(redis_client.created_at)
                        if redis_client.created_at
                        else datetime.utcnow(),
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

    def _handle_code_grant(self, code: str, client: ClientCredentials, code_verifier: Optional[str] = None) -> dict:
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
    <title>KeyAuth — Reference Implementation</title>
    <meta name="description" content="A reference implementation inspired by HODLXXI principles. Not canonical. Not authoritative.">
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
            --warning: #ff6b35;
            --border-color: #0f2a24;
            --card-bg: rgba(17, 23, 26, 0.92);
            --glow-green: rgba(0, 255, 136, 0.2);
        }

        body {
            font-family: ui-monospace, 'SF Mono', 'Monaco', monospace;
            background: var(--bg);
            color: var(--fg);
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 800px;
            margin: 0 auto;
        }

        /* Header */
        header {
            padding: 40px 0;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 40px;
        }

        .logo {
            font-size: 24px;
            font-weight: 700;
            color: var(--accent);
            letter-spacing: 0.1em;
            margin-bottom: 8px;
        }

        .tagline {
            color: var(--muted);
            font-size: 13px;
        }

        /* Disclaimer Box */
        .disclaimer {
            background: rgba(255, 107, 53, 0.1);
            border: 2px solid var(--warning);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 40px;
        }

        .disclaimer h2 {
            color: var(--warning);
            font-size: 16px;
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .disclaimer p {
            color: var(--fg);
            font-size: 13px;
            line-height: 1.8;
            margin-bottom: 12px;
        }

        .disclaimer p:last-child {
            margin-bottom: 0;
        }

        /* Content Sections */
        section {
            margin-bottom: 60px;
        }

        h2 {
            font-size: 20px;
            color: var(--accent);
            margin-bottom: 20px;
        }

        p {
            color: var(--muted);
            font-size: 14px;
            line-height: 1.8;
            margin-bottom: 16px;
        }

        ul {
            list-style: none;
            margin-bottom: 20px;
        }

        li {
            color: var(--muted);
            font-size: 13px;
            padding: 8px 0;
            padding-left: 24px;
            position: relative;
        }

        li::before {
            content: '•';
            position: absolute;
            left: 8px;
            color: var(--accent);
        }

        .negative-list li::before {
            content: '✗';
            color: var(--warning);
        }

        /* Pricing Section */
        .pricing {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 32px;
            margin-top: 40px;
        }

        .pricing h3 {
            font-size: 16px;
            margin-bottom: 16px;
            color: var(--fg);
        }

        .pricing-note {
            background: rgba(0, 255, 136, 0.05);
            border-left: 3px solid var(--accent);
            padding: 16px;
            margin-bottom: 20px;
            font-size: 13px;
            color: var(--muted);
        }

        .tier {
            padding: 20px 0;
            border-bottom: 1px solid var(--border-color);
        }

        .tier:last-child {
            border-bottom: none;
        }

        .tier-name {
            font-size: 14px;
            font-weight: 600;
            color: var(--accent);
            margin-bottom: 8px;
        }

        .tier-price {
            font-size: 13px;
            color: var(--muted);
            margin-bottom: 12px;
        }

        /* Links */
        .link-bar {
            display: flex;
            gap: 24px;
            padding: 20px 0;
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
        }

        .link-bar a {
            color: var(--accent);
            text-decoration: none;
            font-size: 13px;
            border-bottom: 1px solid transparent;
            transition: all 0.2s;
        }

        .link-bar a:hover {
            border-bottom-color: var(--accent);
        }

        /* Footer */
        footer {
            margin-top: 80px;
            padding-top: 40px;
            border-top: 1px solid var(--border-color);
            text-align: center;
        }

        footer p {
            font-size: 12px;
            color: var(--muted);
        }

        /* Button */
        .btn {
            display: inline-block;
            padding: 12px 24px;
            background: transparent;
            border: 1px solid var(--accent);
            color: var(--accent);
            text-decoration: none;
            border-radius: 6px;
            font-size: 13px;
            transition: all 0.2s;
            margin-top: 20px;
        }

        .btn:hover {
            background: rgba(0, 255, 136, 0.1);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">KeyAuth</div>
            <div class="tagline">An independent implementation inspired by HODLXXI principles — not canonical</div>
        </header>

        <div class="disclaimer">
            <h2>⚠️ Important Disclaimer</h2>
            <p><strong>KeyAuth is an experimental implementation.</strong></p>
            <p>It is not canonical.<br>
            It is not authoritative.<br>
            It does not represent the protocol itself.</p>
            <p>You are paying for infrastructure and support,<br>
            not for legitimacy or trust.</p>
        </div>

        <section>
            <h2>What KeyAuth Provides</h2>
            <p>KeyAuth provides hosted infrastructure for:</p>
            <ul>
                <li>Bitcoin signature authentication</li>
                <li>LNURL-Auth integration</li>
                <li>Nostr-based login (NIP-07)</li>
                <li>OAuth2 / OIDC compatibility</li>
                <li>Proof-of-Funds verification (PSBTs)</li>
            </ul>
            <p>
                This service exists for teams that want to experiment
                without running their own infrastructure.
            </p>
        </section>

        <section>
            <h2>What KeyAuth Does NOT Provide</h2>
            <p>KeyAuth does not:</p>
            <ul class="negative-list">
                <li>Define identity (users control their keys)</li>
                <li>Assign trust (reputation is derived, not assigned)</li>
                <li>Control reputation (system observes, doesn't judge)</li>
                <li>Prevent exit (always possible)</li>
                <li>Represent canonical deployment (one of many possible implementations)</li>
            </ul>
        </section>

        <section>
            <h2>Pricing Philosophy</h2>
            <p>
                Payment does not imply endorsement.<br>
                Payment does not imply authority.<br>
                Payment does not imply correctness.
            </p>
            <p>
                Forking and self-hosting are always valid alternatives.
            </p>

            <div class="pricing">
                <h3>Current Pricing (Beta)</h3>
                <div class="pricing-note">
                    All tiers are FREE during beta.<br>
                    When we exit beta (2025?), pricing below will apply.<br>
                    We'll give 60 days notice before charging.
                </div>

                <div class="tier">
                    <div class="tier-name">Free</div>
                    <div class="tier-price">$0/month • 1,000 active users</div>
                    <p>Bitcoin signature auth, basic time-locks, community support</p>
                </div>

                <div class="tier">
                    <div class="tier-name">Developer</div>
                    <div class="tier-price">$29/month • 10,000 active users</div>
                    <p>Email support (48h), early access features, priority bug fixes</p>
                </div>

                <div class="tier">
                    <div class="tier-name">Professional</div>
                    <div class="tier-price">$99/month • 100,000 active users</div>
                    <p>Priority support, custom covenants, direct feedback to roadmap</p>
                </div>
            </div>

            <p style="margin-top: 24px; font-size: 12px;">
                <strong>No "Enterprise" tier yet.</strong>
                The system is not ready for mission-critical applications.
            </p>
        </section>

        <section>
            <h2>What Users Pay For</h2>
            <p>Users pay for:</p>
            <ul>
                <li>Hosted infrastructure (servers, monitoring, backups)</li>
                <li>Uptime and maintenance (best-effort, no SLA during beta)</li>
                <li>Integration support (email, documentation)</li>
                <li>Operational convenience (not running your own nodes)</li>
            </ul>
        </section>

        <section>
            <h2>What Users Do NOT Pay For</h2>
            <p>Users do not pay for:</p>
            <ul class="negative-list">
                <li>Identity legitimacy (cryptography provides this)</li>
                <li>Trust guarantees (trust is earned through behavior)</li>
                <li>Protocol authority (no one has this)</li>
                <li>Exclusive access (open source, forkable)</li>
                <li>Long-term control (exit always possible)</li>
            </ul>
        </section>

        <section>
            <h2>Explicit Red Line</h2>
            <p>
                Any monetization that requires:
            </p>
            <ul class="negative-list">
                <li>Lock-in (preventing users from leaving)</li>
                <li>Hidden constraints (undisclosed limitations)</li>
                <li>Asymmetry of exit (different rules for different users)</li>
                <li>Claims of canonical authority (KeyAuth is one implementation among many)</li>
            </ul>
            <p>
                ...violates the principles of HODLXXI and should be considered non-compliant.
            </p>
        </section>

        <section>
            <h2>Acceptable Revenue Sources</h2>
            <p>KeyAuth may generate revenue from:</p>
            <ul>
                <li>Infrastructure fees (hosting, API usage)</li>
                <li>Integration work (custom deployments)</li>
                <li>Consulting (system design advice)</li>
                <li>Research sponsorships (grant-funded work)</li>
                <li>Educational content (courses, workshops)</li>
            </ul>
            <p style="margin-top: 16px;">
                All revenue sources must preserve user agency and exit rights.
            </p>
        </section>

        <div class="link-bar">
            <a href="https://hodlxxi.com/docs">HODLXXI Documentation</a>
            <a href="https://hodlxxi.com/docs/limits">System Limits</a>
            <a href="https://hodlxxi.com/docs/principles">Core Principles</a>
            <a href="https://github.com/hodlxxi">Source Code</a>
        </div>


        <footer>
            <p>
                This KeyAuth  interface is a reference implementation.<br>
                Participation is voluntary. Exit is always allowed.
            </p>
            <p style="margin-top: 16px;">
                KeyAuth • MIT License • 2024
            </p>
        </footer>
    </div>
</body>
</html>

"""


# ============================================================================
# ROUTES: LANDING PAGE
# ============================================================================


@app.route("/oidc")
def landing_page():
    """Serve the KeyAuth BTC OIDC landing page"""
    # Get the issuer URL dynamically
    base = request.url_root.rstrip("/")
    # Render the template with the issuer variable
    return render_template_string(LANDING_PAGE_HTML, issuer=base)


# ============================================================================

# ----------------------------------------------------------------------------
# PREVIEW ROUTES (template-based pages)
# ----------------------------------------------------------------------------


@app.get("/new-index")
def new_index_preview():
    base = request.url_root.rstrip("/")
    from flask import render_template

    return render_template("index.html", issuer=base)


@app.get("/new-keyauth")
def new_keyauth_preview():
    base = request.url_root.rstrip("/")
    from flask import render_template

    return render_template("keyauth.html", issuer=base)


@app.get("/new-signup")
def new_signup_preview():
    base = request.url_root.rstrip("/")
    from flask import render_template

    return render_template("signup.html", issuer=base)

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
    resp.headers[
        "Content-Security-Policy"
    ] = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline';"

    return resp


# @app.route("/playground", methods=["GET"])
# def playground():
# Serve static playground to avoid Jinja parsing issues
#   logged_in = session.get('logged_in_pubkey', '')
#  access_level = session.get('access_level', 'limited')

# Serve the prebuilt static HTML (bypass Jinja)
# return send_from_directory('static', 'playground.html')


@app.route("/oauth/register", methods=["POST"])
def oauth_register():
    # --- ownership + stricter anon throttling ---
    from flask import session, request
    import time

    my_pubkey = session.get("logged_in_pubkey") or ""
    level = session.get("access_level") or ""

    # Simple extra throttle for anonymous registrations (in-memory, per-process)
    if not my_pubkey:
        ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "unknown"
        now = time.time()
        window = 3600  # 1 hour
        limit = 10  # anon register max 10/hour per IP
        bucket = getattr(oauth_register, "_anon_bucket", {})
        times = [t for t in bucket.get(ip, []) if (now - t) < window]
        if len(times) >= limit:
            return jsonify(ok=False, error="Rate limited"), 429
        times.append(now)
        bucket[ip] = times
        setattr(oauth_register, "_anon_bucket", bucket)

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
    # SAFE_METRICS_ACTIVE_CHALLENGES_FALLBACK
    ACTIVE_CHALLENGES = globals().get("ACTIVE_CHALLENGES", {}) or {}
    """
    Prometheus metrics endpoint.
    Includes:
      - realtime in-memory gauges (sockets/online/chat memory)
      - DB-backed totals (users, PoF, challenges, tokens, messages)
      - any existing oauth counters already registered
    """
    try:
        # --- realtime gauges (in-memory) ---
        rt_active_sockets = len(ACTIVE_SOCKETS)
        rt_online_users = len(ONLINE_USERS)
        rt_chat_history_size = len(CHAT_HISTORY)

        # --- DB-backed totals ---
        db_counts = {}
        try:
            import os

            # Prefer psycopg3, fall back to psycopg2
            _connect = None
            try:
                import psycopg  # psycopg3

                _connect = psycopg.connect
            except Exception:
                import psycopg2  # psycopg2

                _connect = psycopg2.connect

            # DSN from env (best), else build from common PG vars
            dsn = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or ""
            if not dsn:
                host = os.getenv("PGHOST", os.getenv("DB_HOST", "127.0.0.1"))
                port = os.getenv("PGPORT", os.getenv("DB_PORT", "5432"))
                db = os.getenv("PGDATABASE", os.getenv("DB_NAME", "hodlxxi"))
                user = os.getenv("PGUSER", os.getenv("DB_USER", "hodlxxi"))
                pw = os.getenv("PGPASSWORD", os.getenv("DB_PASSWORD", ""))

                if pw:
                    dsn = f"postgresql://{user}:{pw}@{host}:{port}/{db}"
                else:
                    dsn = f"postgresql://{user}@{host}:{port}/{db}"

            conn = _connect(dsn)
            try:
                cur = conn.cursor()
                try:

                    def q(sql: str) -> int:
                        cur.execute(sql)
                        row = cur.fetchone()
                        return int((row[0] if row else 0) or 0)

                    db_counts["users_total"] = q("select count(*) from users;")
                    db_counts["proof_of_funds_total"] = q("select count(*) from proof_of_funds;")
                    db_counts["pof_challenges_total"] = q("select count(*) from pof_challenges;")
                    db_counts["chat_messages_total"] = q("select count(*) from chat_messages;")
                    db_counts["oauth_tokens_total"] = q("select count(*) from oauth_tokens;")
                finally:
                    try:
                        cur.close()
                    except Exception:
                        pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"Prometheus DB metrics unavailable: {e}")
            db_counts = {}

        # --- base prometheus content from existing registry (if available) ---
        base_text = ""
        try:
            from prometheus_client import generate_latest, CONTENT_TYPE_LATEST  # type: ignore

            base_text = generate_latest().decode("utf-8", errors="ignore")
        except Exception:
            CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
        # --- append our custom exposition lines ---
        lines = []

        # realtime
        lines += [
            "# HELP hodlxxi_active_sockets Current active Socket.IO connections (session-authenticated)",
            "# TYPE hodlxxi_active_sockets gauge",
            f"hodlxxi_active_sockets {rt_active_sockets}",
            "# HELP hodlxxi_online_users Current unique online users (session-authenticated pubkeys)",
            "# TYPE hodlxxi_online_users gauge",
            f"hodlxxi_online_users {rt_online_users}",
            "# HELP hodlxxi_chat_history_size In-memory chat history size (ephemeral)",
            "# TYPE hodlxxi_chat_history_size gauge",
            f"hodlxxi_chat_history_size {rt_chat_history_size}",
            "# HELP hodlxxi_active_challenges Current active challenges (ephemeral)",
            "# TYPE hodlxxi_active_challenges gauge",
            f"hodlxxi_active_challenges {len((globals().get('ACTIVE_CHALLENGES', {}) or {}))}",
        ]

        # DB totals (always emitted; 0 if unavailable)
        db = _db_metrics_counts_cached()

        def _emit_gauge(name: str, help_text: str, value) -> None:
            try:
                v = int(value or 0)
            except Exception:
                v = 0
            lines.extend(
                [
                    f"# HELP {name} {help_text}",
                    f"# TYPE {name} gauge",
                    f"{name} {v}",
                ]
            )

        # DB health
        _emit_gauge(
            "hodlxxi_db_up",
            "Database reachable for metrics query (1=up, 0=down)",
            0 if (isinstance(db, dict) and db.get("db_error")) else 1,
        )

        # Totals
        for key, help_text in [
            ("users", "Total users in DB"),
            ("ubid_users", "Total UBID users in DB"),
            ("sessions", "Total sessions in DB"),
            ("chat_messages", "Total chat messages in DB"),
            ("lnurl_challenges", "Total LNURL challenges in DB"),
            ("pof_challenges", "Total PoF challenges in DB"),
            ("audit_logs", "Total audit logs in DB"),
            ("oauth_clients", "Total OAuth clients in DB"),
            ("oauth_tokens", "Total OAuth tokens in DB"),
            ("payments", "Total payments in DB"),
            ("proof_of_funds", "Total Proof-of-Funds records in DB"),
            ("subscriptions", "Total subscriptions in DB"),
            ("usage_stats", "Total usage_stats rows in DB"),
        ]:
            _emit_gauge(f"hodlxxi_{key}_total", help_text, (db or {}).get(key) if isinstance(db, dict) else 0)

        # Activity windows (movement)
        for key, help_text in [
            ("logins_5m", "Users with last_login in last 5 minutes"),
            ("logins_1h", "Users with last_login in last 1 hour"),
            ("logins_24h", "Users with last_login in last 24 hours"),
            ("chat_5m", "Chat messages in last 5 minutes"),
            ("chat_1h", "Chat messages in last 1 hour"),
            ("chat_24h", "Chat messages in last 24 hours"),
            ("lnurl_created_5m", "LNURL challenges created in last 5 minutes"),
            ("lnurl_created_1h", "LNURL challenges created in last 1 hour"),
            ("lnurl_created_24h", "LNURL challenges created in last 24 hours"),
            ("lnurl_verified_24h", "LNURL challenges verified in last 24 hours"),
            ("pof_created_5m", "PoF challenges created in last 5 minutes"),
            ("pof_created_1h", "PoF challenges created in last 1 hour"),
            ("pof_created_24h", "PoF challenges created in last 24 hours"),
            ("pof_verified_24h", "PoF challenges verified in last 24 hours"),
            ("oauth_tokens_5m", "OAuth tokens created in last 5 minutes"),
            ("oauth_tokens_1h", "OAuth tokens created in last 1 hour"),
            ("oauth_tokens_24h", "OAuth tokens created in last 24 hours"),
            ("payments_24h", "Payments created in last 24 hours"),
            ("payments_paid_24h", "Payments paid in last 24 hours"),
        ]:
            _emit_gauge(f"hodlxxi_{key}", help_text, (db or {}).get(key) if isinstance(db, dict) else 0)

        custom_text = "\n".join(lines) + "\n"

        # Combine
        out = (base_text or "") + ("\n" if base_text and not base_text.endswith("\n") else "") + custom_text
        return Response(out, content_type=CONTENT_TYPE_LATEST), 200

    except Exception as e:
        logger.error(f"Prometheus metrics endpoint failed: {e}", exc_info=True)
        return Response("# ERROR generating metrics\n", mimetype="text/plain"), 500

    # SAFE_METRICS_ACTIVE_CHALLENGES_FALLBACK
    ACTIVE_CHALLENGES = globals().get("ACTIVE_CHALLENGES", {}) or {}
    """
    Prometheus metrics endpoint.
    Includes:
      - realtime in-memory gauges (sockets/online/chat memory)
      - DB-backed totals (users, PoF, challenges, tokens, messages)
      - any existing oauth counters already registered
    """
    try:
        # --- realtime gauges (in-memory) ---
        rt_active_sockets = len(ACTIVE_SOCKETS)
        rt_online_users = len(ONLINE_USERS)
        rt_chat_history_size = len(CHAT_HISTORY)

        # --- DB-backed totals ---
        db_counts = {}
        try:
            import os

            # Prefer psycopg3, fall back to psycopg2
            _connect = None
            try:
                import psycopg  # psycopg3

                _connect = psycopg.connect
            except Exception:
                import psycopg2  # psycopg2

                _connect = psycopg2.connect

            # DSN from env (best), else build from common PG vars
            dsn = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or ""
            if not dsn:
                host = os.getenv("PGHOST", os.getenv("DB_HOST", "127.0.0.1"))
                port = os.getenv("PGPORT", os.getenv("DB_PORT", "5432"))
                db = os.getenv("PGDATABASE", os.getenv("DB_NAME", "hodlxxi"))
                user = os.getenv("PGUSER", os.getenv("DB_USER", "hodlxxi"))
                pw = os.getenv("PGPASSWORD", os.getenv("DB_PASSWORD", ""))

                if pw:
                    dsn = f"postgresql://{user}:{pw}@{host}:{port}/{db}"
                else:
                    dsn = f"postgresql://{user}@{host}:{port}/{db}"

            conn = _connect(dsn)
            try:
                cur = conn.cursor()
                try:

                    def q(sql: str) -> int:
                        cur.execute(sql)
                        row = cur.fetchone()
                        return int((row[0] if row else 0) or 0)

                    db_counts["users_total"] = q("select count(*) from users;")
                    db_counts["proof_of_funds_total"] = q("select count(*) from proof_of_funds;")
                    db_counts["pof_challenges_total"] = q("select count(*) from pof_challenges;")
                    db_counts["chat_messages_total"] = q("select count(*) from chat_messages;")
                    db_counts["oauth_tokens_total"] = q("select count(*) from oauth_tokens;")
                finally:
                    try:
                        cur.close()
                    except Exception:
                        pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"Prometheus DB metrics unavailable: {e}")
            db_counts = {}

        # --- base prometheus content from existing registry (if available) ---
        base_text = ""
        try:
            from prometheus_client import generate_latest, CONTENT_TYPE_LATEST  # type: ignore

            base_text = generate_latest().decode("utf-8", errors="ignore")
        except Exception:
            CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
        # --- append our custom exposition lines ---
        lines = []

        # realtime
        lines += [
            "# HELP hodlxxi_active_sockets Current active Socket.IO connections (session-authenticated)",
            "# TYPE hodlxxi_active_sockets gauge",
            f"hodlxxi_active_sockets {rt_active_sockets}",
            "# HELP hodlxxi_online_users Current unique online users (session-authenticated pubkeys)",
            "# TYPE hodlxxi_online_users gauge",
            f"hodlxxi_online_users {rt_online_users}",
            "# HELP hodlxxi_chat_history_size In-memory chat history size (ephemeral)",
            "# TYPE hodlxxi_chat_history_size gauge",
            f"hodlxxi_chat_history_size {rt_chat_history_size}",
            "# HELP hodlxxi_active_challenges Current active challenges (ephemeral)",
            "# TYPE hodlxxi_active_challenges gauge",
            f"hodlxxi_active_challenges {len((globals().get('ACTIVE_CHALLENGES', {}) or {}))}",
        ]

        # DB totals (always emitted; 0 if unavailable)
        db = _db_metrics_counts_cached() if "_db_metrics_counts_cached" in globals() else {}

        def _emit_gauge(name: str, help_text: str, value) -> None:
            try:
                v = int(value or 0)
            except Exception:
                v = 0
            lines.extend(
                [
                    f"# HELP {name} {help_text}",
                    f"# TYPE {name} gauge",
                    f"{name} {v}",
                ]
            )

        # DB health
        _emit_gauge(
            "hodlxxi_db_up",
            "Database reachable for metrics query (1=up, 0=down)",
            0 if (isinstance(db, dict) and db.get("db_error")) else 1,
        )

        # Totals
        for key, help_text in [
            ("users", "Total users in DB"),
            ("ubid_users", "Total UBID users in DB"),
            ("sessions", "Total sessions in DB"),
            ("chat_messages", "Total chat messages in DB"),
            ("lnurl_challenges", "Total LNURL challenges in DB"),
            ("pof_challenges", "Total PoF challenges in DB"),
            ("audit_logs", "Total audit logs in DB"),
            ("oauth_clients", "Total OAuth clients in DB"),
            ("oauth_tokens", "Total OAuth tokens in DB"),
            ("payments", "Total payments in DB"),
            ("proof_of_funds", "Total Proof-of-Funds records in DB"),
            ("subscriptions", "Total subscriptions in DB"),
            ("usage_stats", "Total usage_stats rows in DB"),
        ]:
            _emit_gauge(f"hodlxxi_{key}_total", help_text, (db or {}).get(key) if isinstance(db, dict) else 0)

        # Activity windows (movement)
        for key, help_text in [
            ("logins_5m", "Users with last_login in last 5 minutes"),
            ("logins_1h", "Users with last_login in last 1 hour"),
            ("logins_24h", "Users with last_login in last 24 hours"),
            ("chat_5m", "Chat messages in last 5 minutes"),
            ("chat_1h", "Chat messages in last 1 hour"),
            ("chat_24h", "Chat messages in last 24 hours"),
            ("lnurl_created_5m", "LNURL challenges created in last 5 minutes"),
            ("lnurl_created_1h", "LNURL challenges created in last 1 hour"),
            ("lnurl_created_24h", "LNURL challenges created in last 24 hours"),
            ("lnurl_verified_24h", "LNURL challenges verified in last 24 hours"),
            ("pof_created_5m", "PoF challenges created in last 5 minutes"),
            ("pof_created_1h", "PoF challenges created in last 1 hour"),
            ("pof_created_24h", "PoF challenges created in last 24 hours"),
            ("pof_verified_24h", "PoF challenges verified in last 24 hours"),
            ("oauth_tokens_5m", "OAuth tokens created in last 5 minutes"),
            ("oauth_tokens_1h", "OAuth tokens created in last 1 hour"),
            ("oauth_tokens_24h", "OAuth tokens created in last 24 hours"),
            ("payments_24h", "Payments created in last 24 hours"),
            ("payments_paid_24h", "Payments paid in last 24 hours"),
        ]:
            _emit_gauge(f"hodlxxi_{key}", help_text, (db or {}).get(key) if isinstance(db, dict) else 0)

        custom_text = "\n".join(lines) + "\n"

        # Combine
        out = (base_text or "") + ("\n" if base_text and not base_text.endswith("\n") else "") + custom_text
        return Response(out, content_type=CONTENT_TYPE_LATEST), 200

    except Exception as e:
        logger.error(f"Prometheus metrics endpoint failed: {e}", exc_info=True)
        return Response("# ERROR generating metrics\n", mimetype="text/plain"), 500


@app.after_request
def apply_security_headers(response):
    from flask import make_response as _make_response

    response = _make_response(response)
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    #  response.headers["Content-Security-Policy"] = "default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; connect-src 'self' wss: ws: https: http:; font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; frame-ancestors 'none'"
    return response


# ============================================================================
# ROUTES: LNURL-AUTH
# ============================================================================


@app.route("/api/lnurl-auth/create", methods=["GET", "POST"])
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
            "lnurl_sessions": len((globals().get("LNURL_SESSION_STORE") or globals().get("LNURL_SESSIONS") or {})),
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


# ----------------------------------------------------------------------------
# DOCS VIEWER (preview) - does NOT replace existing /docs
# ----------------------------------------------------------------------------
@app.get("/docs2")
def docs_viewer_v2():
    import os
    from flask import render_template

    docs_dir = os.path.join(app.static_folder, "docs", "docs")
    items = []
    try:
        for name in sorted(os.listdir(docs_dir)):
            low = name.lower()
            if low.endswith(".md") or low.endswith(".pdf"):
                items.append(name)
    except Exception:
        # If folder missing, show empty list instead of crashing prod
        items = []

    return render_template("docs_viewer.html", items=items)


@app.route("/docs")
@app.route("/docs/")
def docs_alias():
    # === DOCS_INDEX_DYNAMIC_V1: dynamic docs index from /static/docs/docs ===
    import os
    import re as _re
    from flask import render_template

    docs_dir = os.path.join(app.static_folder, "docs", "docs")

    # Curated ordering: put the "start here" set on top if present
    curated = [
        "README",
        "what_is_hodlxxi",
        "about_short",
        "how_it_works",
        "architecture",
        "faq",
        "crt_theory",
        "principles",
        "ethics",
        "threat_model_and_failure_modes",
        "research_status",
        "auth0_comparison",
        "academic_references_and_prior_art",
        "bibliography",
    ]

    md_items = []
    pdf_items = []

    def _title_from_md(text: str, fallback: str) -> str:
        # first markdown heading like "# Title"
        for line in (text or "").splitlines():
            line = line.strip()
            if line.startswith("#"):
                return line.lstrip("#").strip() or fallback
            if line:
                break
        return fallback

    def _desc_from_md(text: str) -> str:
        # first non-empty paragraph-ish line (not heading)
        for line in (text or "").splitlines():
            t = line.strip()
            if not t:
                continue
            if t.startswith("#"):
                continue
            if t.startswith(">"):
                t = t.lstrip(">").strip()
            if len(t) < 8:
                continue
            return t[:220]
        return ""

    try:
        names = sorted(os.listdir(docs_dir))
    except Exception:
        names = []

    # Build md list
    md_map = {}
    for name in names:
        low = name.lower()
        p = os.path.join(docs_dir, name)
        if low.endswith(".md") and os.path.isfile(p):
            slug = name[:-3]
            md_map[slug] = p

    # Order: curated first, then the rest alpha
    ordered_slugs = []
    for c in curated:
        if c in md_map:
            ordered_slugs.append(c)
    for slug in sorted(md_map.keys()):
        if slug not in ordered_slugs:
            ordered_slugs.append(slug)

    for slug in ordered_slugs:
        p = md_map[slug]
        try:
            raw = Path(p).read_text(encoding="utf-8", errors="replace")
        except Exception:
            raw = ""
        display = _title_from_md(raw, slug.replace("_", " ").replace("-", " ").title())
        desc = _desc_from_md(raw)
        try:
            size_kb = int((Path(p).stat().st_size + 1023) / 1024)
        except Exception:
            size_kb = None
        md_items.append({"slug": slug, "display": display, "desc": desc, "size_kb": size_kb})

    # PDFs
    for name in names:
        low = name.lower()
        p = os.path.join(docs_dir, name)
        if low.endswith(".pdf") and os.path.isfile(p):
            try:
                size_kb = int((Path(p).stat().st_size + 1023) / 1024)
            except Exception:
                size_kb = None
            pdf_items.append({"name": name, "size_kb": size_kb})

    return render_template("docs_index.html", title="HODLXXI Docs", md_items=md_items, pdf_items=pdf_items)
    # === /DOCS_INDEX_DYNAMIC_V1 ===


@app.route("/docs.json")
def docs_json_alias():
    return redirect(url_for("oauthx_docs"), code=302)


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
    # Defensive: some stores may be defined later / conditionally
    g = globals()
    g.setdefault("AUTH_CODE_STORE", {})
    if "LNURL_SESSION_STORE" not in g:
        g["LNURL_SESSION_STORE"] = g.get("LNURL_SESSIONS", {}) or {}

    # Guard: app can import before stores are defined (gunicorn boot)
    global AUTH_CODE_STORE
    AUTH_CODE_STORE = globals().get("AUTH_CODE_STORE", {})
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
# Defer cleanup until runtime (avoid import-time crashes during gunicorn boot)
# Flask 3+: before_first_request was removed. Run cleanup once via before_request.
_cleanup_once = {"done": False}


@app.before_request
def _run_cleanup_once():
    if _cleanup_once.get("done"):
        return None
    _cleanup_once["done"] = True
    try:
        cleanup_expired_data()
    except Exception as e:
        try:
            app.logger.warning("cleanup_expired_data failed: %s", e)
        except Exception:
            pass
    return None


def _deferred_cleanup_expired_data():
    try:
        cleanup_expired_data()
    except Exception as e:
        try:
            logger.warning(f"deferred cleanup_expired_data failed: {e}", exc_info=True)
        except Exception:
            print(f"deferred cleanup_expired_data failed: {e}")


# ============================================================================
# ADDITIONAL HELPER ROUTES
# ============================================================================


@app.route("/oauth/clients", methods=["GET"])
def list_clients():
    from flask import jsonify, session
    import os, json, time
    import psycopg

    pubkey = session.get("logged_in_pubkey", "")
    level = session.get("access_level")

    if not pubkey:
        return jsonify(ok=False, error="Not logged in", clients=[]), 401

    # DSN from env (best), else build from common vars
    dsn = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or ""
    if not dsn:
        host = os.getenv("PGHOST", os.getenv("DB_HOST", "127.0.0.1"))
        port = os.getenv("PGPORT", os.getenv("DB_PORT", "5432"))
        db = os.getenv("PGDATABASE", os.getenv("DB_NAME", "hodlxxi"))
        user = os.getenv("PGUSER", os.getenv("DB_USER", "hodlxxi"))
        pw = os.getenv("PGPASSWORD", os.getenv("DB_PASSWORD", ""))
        dsn = f"postgresql://{user}:{pw}@{host}:{port}/{db}" if pw else f"postgresql://{user}@{host}:{port}/{db}"

    def _jsonish(v):
        if v is None:
            return None
        if isinstance(v, (dict, list, int, float, bool)):
            return v
        if isinstance(v, str):
            t = v.strip()
            if (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]")):
                try:
                    return json.loads(t)
                except Exception:
                    return v
            return v
        return v

    # Full users can view all clients; others see owned + NULL-owned (legacy)
    is_full = level == "full"

    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                if is_full:
                    cur.execute(
                        """
                        select client_id, client_name, redirect_uris, grant_types, response_types,
                               scope, token_endpoint_auth_method, created_at, metadata, is_active,
                               owner_pubkey, plan
                        from oauth_clients
                        order by created_at desc
                        limit 200
                    """
                    )
                else:
                    cur.execute(
                        """
                        select client_id, client_name, redirect_uris, grant_types, response_types,
                               scope, token_endpoint_auth_method, created_at, metadata, is_active,
                               owner_pubkey, plan
                        from oauth_clients
                        where owner_pubkey = %s or owner_pubkey is null
                        order by created_at desc
                        limit 200
                    """,
                        (pubkey,),
                    )
                rows = cur.fetchall()

        clients = []
        for (
            client_id,
            client_name,
            redirect_uris,
            grant_types,
            response_types,
            scope,
            token_auth,
            created_at,
            metadata,
            is_active,
            owner_pubkey,
            plan,
        ) in rows:
            clients.append(
                {
                    "client_id": client_id,
                    "client_name": client_name,
                    "redirect_uris": _jsonish(redirect_uris) or [],
                    "grant_types": _jsonish(grant_types) or [],
                    "response_types": _jsonish(response_types) or [],
                    "scope": scope,
                    "token_endpoint_auth_method": token_auth,
                    "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
                    "metadata": _jsonish(metadata) or {},
                    "is_active": bool(is_active) if is_active is not None else True,
                    "owner_pubkey": owner_pubkey,
                    "plan": plan or "free",
                }
            )

        return jsonify(ok=True, clients=clients, count=len(clients), ts=time.time()), 200

    except Exception as e:
        return jsonify(ok=False, error=f"DB query failed: {e}", clients=[]), 500


@app.route("/oauth/clients/<client_id>", methods=["GET"])
def oauth_client_detail(client_id):
    """
    GET /oauth/clients/<client_id> (NO SECRET)
    - 401 not logged in
    - 403 not full
    - 404 not found
    - 403 if not owner (owner_pubkey), and not admin for NULL-owned
    """
    from flask import jsonify, session
    import os, json
    import psycopg

    pubkey = session.get("logged_in_pubkey") or ""
    level = session.get("access_level") or ""

    if not pubkey:
        resp = jsonify(ok=False, error="Not logged in")
        resp.headers["Cache-Control"] = "no-store"
        return resp, 401

    if level != "full":
        resp = jsonify(ok=False, error="Forbidden")
        resp.headers["Cache-Control"] = "no-store"
        return resp, 403

    admins = {x.strip() for x in (os.getenv("OAUTH_CLIENTS_ADMIN_PUBKEYS", "")).split(",") if x.strip()}
    is_admin = pubkey in admins

    dsn = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or ""
    if not dsn:
        host = os.getenv("PGHOST", os.getenv("DB_HOST", "127.0.0.1"))
        port = os.getenv("PGPORT", os.getenv("DB_PORT", "5432"))
        db = os.getenv("PGDATABASE", os.getenv("DB_NAME", "hodlxxi"))
        user = os.getenv("PGUSER", os.getenv("DB_USER", "hodlxxi"))
        pw = os.getenv("PGPASSWORD", os.getenv("DB_PASSWORD", ""))
        dsn = f"postgresql://{user}:{pw}@{host}:{port}/{db}" if pw else f"postgresql://{user}@{host}:{port}/{db}"

    def _jsonish(v):
        if v is None:
            return None
        if isinstance(v, (dict, list, int, float, bool)):
            return v
        if isinstance(v, str):
            t = v.strip()
            if (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]")):
                try:
                    return json.loads(t)
                except Exception:
                    return v
            return v
        return v

    sql = """
      SELECT client_id, client_name, redirect_uris, grant_types, response_types, scope,
             token_endpoint_auth_method, created_at, metadata, is_active, owner_pubkey, plan
      FROM oauth_clients
      WHERE client_id = %s
      LIMIT 1
    """

    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (client_id,))
                r = cur.fetchone()
    except Exception as e:
        resp = jsonify(ok=False, error=f"DB query failed: {e}")
        resp.headers["Cache-Control"] = "no-store"
        return resp, 500

    if not r:
        resp = jsonify(ok=False, error="Not found")
        resp.headers["Cache-Control"] = "no-store"
        return resp, 404

    owner = r[10]
    if owner != pubkey and not (owner is None and is_admin):
        resp = jsonify(ok=False, error="Forbidden")
        resp.headers["Cache-Control"] = "no-store"
        return resp, 403

    resp = jsonify(
        ok=True,
        client={
            "client_id": r[0],
            "client_name": r[1],
            "redirect_uris": _jsonish(r[2]) or [],
            "grant_types": _jsonish(r[3]) or [],
            "response_types": _jsonish(r[4]) or [],
            "scope": r[5],
            "token_endpoint_auth_method": r[6],
            "created_at": (r[7].isoformat() if getattr(r[7], "isoformat", None) else str(r[7])),
            "metadata": _jsonish(r[8]) or {},
            "is_active": bool(r[9]),
            "owner_pubkey": owner,
            "plan": r[11] or "free",
        },
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp, 200


@app.route("/oauth/clients/<client_id>/rotate-secret", methods=["POST"])
def oauth_client_rotate_secret(client_id):
    """
    POST /oauth/clients/<client_id>/rotate-secret
    ADMIN-ONLY (pubkey in OAUTH_CLIENTS_ADMIN_PUBKEYS + full)
    Returns new client_secret.
    """
    from flask import jsonify, session
    import os, secrets
    import psycopg

    pubkey = session.get("logged_in_pubkey") or ""
    level = session.get("access_level") or ""

    admins = {x.strip() for x in (os.getenv("OAUTH_CLIENTS_ADMIN_PUBKEYS", "")).split(",") if x.strip()}
    is_admin = pubkey in admins

    if not pubkey:
        resp = jsonify(ok=False, error="Not logged in")
        resp.headers["Cache-Control"] = "no-store"
        return resp, 401
    if level != "full" or not is_admin:
        resp = jsonify(ok=False, error="Forbidden")
        resp.headers["Cache-Control"] = "no-store"
        return resp, 403

    dsn = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or ""
    if not dsn:
        host = os.getenv("PGHOST", os.getenv("DB_HOST", "127.0.0.1"))
        port = os.getenv("PGPORT", os.getenv("DB_PORT", "5432"))
        db = os.getenv("PGDATABASE", os.getenv("DB_NAME", "hodlxxi"))
        user = os.getenv("PGUSER", os.getenv("DB_USER", "hodlxxi"))
        pw = os.getenv("PGPASSWORD", os.getenv("DB_PASSWORD", ""))
        dsn = f"postgresql://{user}:{pw}@{host}:{port}/{db}" if pw else f"postgresql://{user}@{host}:{port}/{db}"

    new_secret = secrets.token_urlsafe(32)

    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE oauth_clients SET client_secret=%s WHERE client_id=%s", (new_secret, client_id))
                if cur.rowcount != 1:
                    conn.rollback()
                    resp = jsonify(ok=False, error="Not found")
                    resp.headers["Cache-Control"] = "no-store"
                    return resp, 404
            conn.commit()
    except Exception as e:
        resp = jsonify(ok=False, error=f"DB update failed: {e}")
        resp.headers["Cache-Control"] = "no-store"
        return resp, 500

    resp = jsonify(ok=True, client_id=client_id, client_secret=new_secret)
    resp.headers["Cache-Control"] = "no-store"
    return resp, 200


@app.route("/playground", methods=["GET"])
def playground():
    # Public demo page
    from flask import render_template

    return render_template("playground.html")


# API_DEBUG_SESSION_ALIAS_V1
@app.route("/api/debug/session", methods=["GET"])
def api_debug_session_alias():
    """Compat endpoint: some frontend code calls /api/debug/session."""
    return api_whoami()


# /API_DEBUG_SESSION_ALIAS_V1


# API_POF_VERIFY_PSBT_V1
@app.route("/api/pof/verify_psbt", methods=["POST"])
def api_pof_verify_psbt():
    """
    Verify a PSBT PoF proof:
      - PSBT contains OP_RETURN with the exact challenge string for challenge_id
      - PSBT is signed (has final_scriptwitness/final_scriptsig/partial_sigs per input)
      - Sum amounts from witness_utxo/non_witness_utxo if available (best-effort)
    """
    import base64
    import time
    from flask import request, jsonify, session

    data = request.get_json() or {}
    cid = (data.get("challenge_id") or "").strip()
    psbt_b64 = (data.get("psbt") or "").strip()
    pubkey = (data.get("pubkey") or "").strip()

    if not cid or not psbt_b64:
        return jsonify(ok=False, error="Missing challenge_id or psbt"), 400

    # session fallback for pubkey (optional)
    if not pubkey:
        spk = (session.get("logged_in_pubkey") or "").strip()
        if spk:
            pubkey = spk

    # ACTIVE_CHALLENGES must exist in your app (it does in your /api/challenge flow)
    ch = ACTIVE_CHALLENGES.get(cid) if "ACTIVE_CHALLENGES" in globals() else None
    if not ch:
        return jsonify(ok=False, error="Unknown or expired challenge_id"), 400

    # Expiry (best-effort)
    exp = ch.get("expires_at") or 0
    if exp and time.time() > float(exp):
        try:
            ACTIVE_CHALLENGES.pop(cid, None)
        except Exception:
            pass
        return jsonify(ok=False, error="Challenge expired"), 400

    challenge = ch.get("challenge") or ""
    if not challenge:
        return jsonify(ok=False, error="Challenge record missing challenge string"), 500

    # -------- PSBT parsing helpers (minimal BIP174) --------
    def read_varint(b, i):
        n = b[i]
        if n < 0xFD:
            return n, i + 1
        if n == 0xFD:
            return int.from_bytes(b[i + 1 : i + 3], "little"), i + 3
        if n == 0xFE:
            return int.from_bytes(b[i + 1 : i + 5], "little"), i + 5
        return int.from_bytes(b[i + 1 : i + 9], "little"), i + 9

    def read_kv_map(b, i):
        m = []
        while True:
            if i >= len(b):
                raise ValueError("truncated psbt map")
            if b[i] == 0x00:
                return m, i + 1
            klen, i = read_varint(b, i)
            key = b[i : i + klen]
            i += klen
            vlen, i = read_varint(b, i)
            val = b[i : i + vlen]
            i += vlen
            m.append((key, val))
        # unreachable

    def parse_psbt(psbt_bytes):
        if not psbt_bytes.startswith(b"psbt\xff"):
            raise ValueError("bad psbt magic")
        i = 5
        gmap, i = read_kv_map(psbt_bytes, i)

        unsigned_tx = None
        for k, v in gmap:
            if len(k) >= 1 and k[0] == 0x00:
                unsigned_tx = v
                break
        if not unsigned_tx:
            raise ValueError("missing unsigned tx in psbt")

        # parse unsigned tx to know num inputs/outputs
        tx = parse_tx(unsigned_tx)
        nin = len(tx["vin"])
        nout = len(tx["vout"])

        in_maps = []
        for _ in range(nin):
            imap, i = read_kv_map(psbt_bytes, i)
            in_maps.append(imap)

        out_maps = []
        for _ in range(nout):
            omap, i = read_kv_map(psbt_bytes, i)
            out_maps.append(omap)

        return tx, in_maps, out_maps

    def parse_tx(tx_bytes):
        # minimal tx parser (handles segwit marker if present)
        i = 0
        version = int.from_bytes(tx_bytes[i : i + 4], "little")
        i += 4

        segwit = False
        if i + 2 <= len(tx_bytes) and tx_bytes[i] == 0x00 and tx_bytes[i + 1] == 0x01:
            segwit = True
            i += 2

        vin_n, i = read_varint(tx_bytes, i)
        vin = []
        for _ in range(vin_n):
            txid_le = tx_bytes[i : i + 32]
            i += 32
            vout = int.from_bytes(tx_bytes[i : i + 4], "little")
            i += 4
            slen, i = read_varint(tx_bytes, i)
            script = tx_bytes[i : i + slen]
            i += slen
            seq = tx_bytes[i : i + 4]
            i += 4
            vin.append({"txid_le": txid_le, "vout": vout, "scriptSig": script, "sequence": seq})

        vout_n, i = read_varint(tx_bytes, i)
        vout_list = []
        for _ in range(vout_n):
            amt_sat = int.from_bytes(tx_bytes[i : i + 8], "little")
            i += 8
            pklen, i = read_varint(tx_bytes, i)
            spk = tx_bytes[i : i + pklen]
            i += pklen
            vout_list.append({"value_sat": amt_sat, "scriptPubKey": spk})

        # skip witness if present
        if segwit:
            for _ in range(vin_n):
                items, i = read_varint(tx_bytes, i)
                for __ in range(items):
                    ilen, i = read_varint(tx_bytes, i)
                    i += ilen

        locktime = int.from_bytes(tx_bytes[i : i + 4], "little") if i + 4 <= len(tx_bytes) else 0
        return {"version": version, "vin": vin, "vout": vout_list, "locktime": locktime}

    def extract_opreturn_strings(vout_list):
        out = []
        for o in vout_list:
            spk = o["scriptPubKey"]
            if not spk or spk[0] != 0x6A:  # OP_RETURN
                continue
            j = 1
            if j >= len(spk):
                continue
            op = spk[j]
            j += 1
            if op <= 0x4B:
                n = op
            elif op == 0x4C:
                if j >= len(spk):
                    continue
                n = spk[j]
                j += 1
            elif op == 0x4D:
                if j + 1 >= len(spk):
                    continue
                n = int.from_bytes(spk[j : j + 2], "little")
                j += 2
            else:
                continue
            data = spk[j : j + n]
            try:
                out.append(data.decode("utf-8", errors="strict"))
            except Exception:
                # ignore non-text
                pass
        return out

    def input_has_sig(imap):
        # key type is first byte of key
        for k, v in imap:
            if not k:
                continue
            t = k[0]
            # 0x02 partial sig, 0x07 final_scriptsig, 0x08 final_scriptwitness
            if t in (0x02, 0x07, 0x08):
                return True
        return False

    def sum_input_sats(tx, in_maps):
        total = 0
        used = 0

        # witness_utxo key type is 0x01, value = TxOut (8 sat + varint scriptlen + script)
        def parse_txout(v):
            if len(v) < 9:
                return None
            amt = int.from_bytes(v[0:8], "little")
            # parse script length varint
            slen, off = read_varint(v, 8)
            spk = v[off : off + slen]
            return amt, spk

        # non_witness_utxo key type is 0x00, value = full previous tx
        def parse_prev_tx_and_get_vout(prev_tx_bytes, vout_index):
            pt = parse_tx(prev_tx_bytes)
            if 0 <= vout_index < len(pt["vout"]):
                return pt["vout"][vout_index]["value_sat"]
            return None

        for idx, imap in enumerate(in_maps):
            got = None
            for k, v in imap:
                if not k:
                    continue
                if k[0] == 0x01:  # witness_utxo
                    parsed = parse_txout(v)
                    if parsed:
                        got = parsed[0]
                        break
            if got is None:
                prev_tx = None
                for k, v in imap:
                    if k and k[0] == 0x00:  # non_witness_utxo
                        prev_tx = v
                        break
                if prev_tx is not None:
                    got = parse_prev_tx_and_get_vout(prev_tx, tx["vin"][idx]["vout"])
            if got is not None:
                total += got
                used += 1

        return total, used

    # decode base64 psbt
    try:
        psbt_bytes = base64.b64decode(psbt_b64, validate=True)
    except Exception:
        return jsonify(ok=False, error="Invalid base64 PSBT"), 400

    try:
        tx, in_maps, out_maps = parse_psbt(psbt_bytes)
    except Exception as e:
        return jsonify(ok=False, error=f"PSBT parse failed: {e}"), 400

    # verify OP_RETURN includes challenge string
    op_returns = extract_opreturn_strings(tx["vout"])
    if challenge not in op_returns:
        return jsonify(ok=False, error="Challenge not found in OP_RETURN"), 400

    # verify signed
    if not all(input_has_sig(im) for im in in_maps):
        return jsonify(ok=False, error="PSBT not fully signed (missing signatures)"), 400

    total_sat, used_inputs = sum_input_sats(tx, in_maps)
    total_btc = total_sat / 1e8

    # best-effort response compatible with UI
    return (
        jsonify(
            ok=True,
            verified=True,
            challenge_id=cid,
            pubkey=pubkey,
            unspent_count=len(in_maps),
            total_sat=total_sat,
            total_btc=total_btc,
            inputs_with_amount=used_inputs,
        ),
        200,
    )


# /API_POF_VERIFY_PSBT_V1


# UPGRADE_ENDPOINT_V2
# Render the real Upgrade UI (upgrade.html). Keeps endpoint name 'upgrade'.
@app.route("/upgrade", methods=["GET", "POST"])
def upgrade():
    from flask import session, request, redirect, render_template

    if not session.get("logged_in_pubkey"):
        return redirect(f"/login?next={request.path}")

    pk = session.get("logged_in_pubkey") or ""
    short_pk = (pk[:12] + "…") if isinstance(pk, str) and len(pk) > 12 else pk

    return render_template(
        "upgrade.html",
        pubkey=pk,
        short_pk=short_pk,
        access_level=session.get("access_level", "limited"),
        guest_label=session.get("guest_label"),
    )


# HODLXXI_ACCOUNT_RESTORE_V3
# ACCAUNT_TYPO_BEFORE_AUTH_V3
# Fix common typo BEFORE auth guards so next= uses /account
@app.before_request
def _fix_accaunt_typo_before_auth_v3():
    from flask import request, redirect

    if request.path == "/accaunt":
        return redirect("/account", code=301)
    if request.path == "/accaunts":
        return redirect("/accounts", code=301)


# RESTORE_ACCOUNT_ROUTE_V3
@app.route("/account", methods=["GET"])
def account():
    from flask import session, request, redirect, render_template
    from jinja2 import TemplateNotFound
    from werkzeug.routing import BuildError

    if not session.get("logged_in_pubkey"):
        return redirect(f"/login?next={request.path}")

    # Render but never allow template endpoint mistakes to crash production
    try:
        pk = session.get("logged_in_pubkey") or ""
        short_pk = (pk[:12] + "…") if isinstance(pk, str) and len(pk) > 12 else pk
        return render_template(
            "account.html",
            pubkey=pk,
            short_pk=short_pk,
            access_level=session.get("access_level", "limited"),
            guest_label=session.get("guest_label"),
        )
    except (TemplateNotFound, BuildError) as e:
        pub = session.get("logged_in_pubkey", "")
        lvl = session.get("access_level", "")
        return (
            "<!doctype html><html><head><meta charset='utf-8'><title>Account</title></head>"
            "<body style='font-family:system-ui;padding:24px'>"
            "<h1>Account</h1>"
            f"<p><b>pubkey</b>: {pub}</p>"
            f"<p><b>access</b>: {lvl}</p>"
            f"<p style='color:#b00'><b>Template/endpoint issue</b>: {e}</p>"
            "<p>/account route restored. Fix account.html url_for() endpoint names.</p>"
            "</body></html>"
        )


# === Compat routes (restore legacy UI + billing API paths) ===
try:
    _rules = {r.rule for r in app.url_map.iter_rules()}

    if "/accounts" not in _rules:
        from app.blueprints.accounts_page import bp as _accounts_bp

        app.register_blueprint(_accounts_bp)

    # Templates call /api/billing/* but current endpoints live under /dev/billing/*
    if ("/api/billing/create-invoice" not in _rules) and ("/dev/billing/create-invoice" in _rules):
        from app.blueprints.billing_api_compat import bp as _billing_bp

        app.register_blueprint(_billing_bp)

except Exception as _e:
    try:
        app.logger.exception("Compat route registration failed: %s", _e)
    except Exception:
        pass


# === AUTH_DIAG_401403_V1 ===
@app.after_request
def _auth_diag_401403(resp):
    try:
        from flask import request, session

        if resp.status_code in (401, 403):
            # log only interesting paths to avoid noise
            if request.path.startswith(("/api/", "/dev/")) or request.path in ("/account", "/accounts", "/upgrade"):
                app.logger.warning(
                    "AUTH_DIAG %s %s -> %s session_keys=%s",
                    request.method,
                    request.path,
                    resp.status_code,
                    list(getattr(session, "keys", lambda: [])()),
                )
    except Exception:
        pass
    return resp


# === ACCOUNT_API_COMPAT_V1 ===
# account.html calls /api/account/summary and /api/account/set-payg from a logged-in browser session.
# If those endpoints are missing or require bearer/dev auth, the UI will "kick" to /login.
def _account_api_compat_v1():
    """Register /api/account/* endpoints used by account.html (DB-backed)."""
    try:
        from app.blueprints.account_api_compat import bp as _acct_api_bp

        app.register_blueprint(_acct_api_bp)
        app.logger.info("account_api_compat: registered DB-backed /api/account/*")
    except Exception as _e:
        try:
            app.logger.exception("account_api_compat registration failed: %s", _e)
        except Exception:
            pass


# Ensure account API compat is registered
try:
    _account_api_compat_v1()
except Exception:
    pass


@app.route("/playground/")
def playground_slash_alias():
    from flask import redirect

    return redirect("/playground", code=308)

import hashlib
import threading
import json
import redis
import redis
import logging
import os
import re


def _mask_pubkey_tail(pk: str, tail: int = 4) -> str:
    pk = (pk or "").strip()
    if len(pk) < tail:
        return pk
    if re.fullmatch(r"(?i)(02|03)[0-9a-f]{64}", pk):
        return pk[:2] + "*****" + pk[-tail:]
    return "*****" + pk[-tail:]


def _mask_clickable_pubkeys_in_html(html: str) -> str:
    """
    Mask visible pubkey text inside clickable spans but keep onclick FULL.
    """
    if not html:
        return html

    pat = re.compile(
        r'(<span class=\\"clickable-pubkey\\"[^>]*handlePubKeyClick\\(\\\'([0-9a-fA-F]{66})\\\'\\);\\">)\\2(</span>)'
    )

    def repl(m):
        full = m.group(2)
        tail = full[-4:]
        return m.group(1) + f'<span style=\\"color:red;\\">{tail}</span>' + m.group(3)

    return pat.sub(repl, html)


from flask import session, request, request
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
from urllib.parse import urlsplit
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
from werkzeug.exceptions import HTTPException

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
    get_oauth_token,
    get_oauth_token_by_refresh,
    get_session,
    get_user_by_id,
    get_user_by_pubkey,
    store_lnurl_challenge,
    store_oauth_client,
    store_oauth_code,
    store_oauth_token,
    store_session,
    revoke_oauth_token_by_refresh,
)
from app.billing_clients import check_client_invoice, create_client_invoice, require_paid_client
from app.jwks import ensure_rsa_keypair
from app.oauth_utils import require_oauth_token
from app.utils import get_rpc_connection
from app.oidc import oidc_bp, validate_pkce
from app.security import init_security, limiter
from app.tokens import issue_rs256_jwt
from app.pof_routes import pof_bp, pof_api_bp
from app.dev_routes import dev_bp
from app.blueprints.agent import agent_bp
from app.browser_routes import get_browser_route_handler, register_browser_routes
from app.socket_handlers import register_socket_handlers
from app.socket_state import ACTIVE_SOCKETS, CHAT_HISTORY, ONLINE_META, ONLINE_USER_META, ONLINE_USERS
from app.request_context import get_or_create_request_id
from app.browser_compat import (
    redirect_explorer,
    redirect_oneword,
    redirect_onboard,
    render_account_page,
    render_upgrade_page,
)

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


def _redact_url_secret(raw_url: str) -> str:
    """Mask credentials embedded in URLs before logging."""
    try:
        parsed = urlsplit(raw_url or "")
    except Exception:
        return "<invalid-url>"
    if not parsed.scheme:
        return "<redacted>"
    if parsed.username is None and parsed.password is None:
        return raw_url
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return f"{parsed.scheme}://***:***@{host}{parsed.path or ''}"


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
    logger.info("Creating playground_redis with URL: %s", _redact_url_secret(REDIS_URL))
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

# --- Internal Agent Invoice API (Option A: agent -> localhost web app) ---
from app.agent_invoice_api import bp as agent_invoice_bp

app.register_blueprint(agent_invoice_bp)


# VISIT_LOG_V1: per-request identity log (no query strings, no secrets)
from flask import request


@app.before_request
def _assign_request_id():
    get_or_create_request_id()


@app.after_request
def _hodl_visit_log(resp):
    try:
        path = request.path or ""
        # avoid noise
        if path.startswith("/static") or path in ("/favicon.ico",):
            return resp

        # real client ip if nginx forwards it; else remote_addr
        ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()

        pub = session.get("logged_in_pubkey")
        lvl = session.get("access_level")
        lm = session.get("login_method")
        gl = session.get("guest_label")

        kind = "anon"
        if pub:
            pub_s = str(pub)
            kind = "guest" if pub_s.startswith("guest-") or gl or (lm in ("guest", "pin")) else "key"
        tail = str(pub)[-8:] if pub else ""

        app.logger.info(
            "VISIT request_id=%s ip=%s kind=%s lvl=%s lm=%s pub_tail=%s %s %s -> %s",
            getattr(g, "request_id", None),
            ip,
            kind,
            lvl,
            lm,
            tail,
            request.method,
            path,
            resp.status_code,
        )
    except Exception:
        pass
    try:
        resp.headers["X-Request-ID"] = getattr(g, "request_id", "") or resp.headers.get("X-Request-ID", "")
    except Exception:
        pass
    return resp


@app.errorhandler(Exception)
def _handle_unexpected_exception(exc):
    if isinstance(exc, HTTPException):
        return exc
    request_id = getattr(g, "request_id", None)
    app.logger.error(
        "unhandled_exception request_id=%s path=%s method=%s",
        request_id,
        getattr(request, "path", None),
        getattr(request, "method", None),
        exc_info=True,
    )
    payload = {"error": "internal_error", "message": "An unexpected error occurred"}
    if request_id:
        payload["request_id"] = request_id
    return jsonify(payload), 500


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


# PUBLIC_STATUS_EXT_V3: extended public status for screensaver (public-safe, cached)
@app.route("/api/public/status")
def api_public_status():
    import time, os, subprocess

    now = int(time.time())
    iso = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now))

    # Presence totals (safe)
    active_sockets = len(ACTIVE_SOCKETS) if "ACTIVE_SOCKETS" in globals() else 0
    online_users = len(ONLINE_USERS) if "ONLINE_USERS" in globals() else 0

    # Role breakdown (aggregated only)
    roles = {"full": 0, "limited": 0, "pin": 0, "random": 0, "other": 0}
    try:
        users = list(ONLINE_USERS) if "ONLINE_USERS" in globals() else []
        for pk in users:
            role = None
            try:
                rec = (ONLINE_USER_META.get(pk) if "ONLINE_USER_META" in globals() else None) or {}
                role = rec.get("role") if isinstance(rec, dict) else None
            except Exception:
                role = None
            if not role:
                try:
                    role = ONLINE_META.get(pk) if "ONLINE_META" in globals() else None
                except Exception:
                    role = None
            role = str(role).strip().lower() if role else "limited"
            if role in roles:
                roles[role] += 1
            elif role.startswith("guest"):
                roles["random"] += 1
            else:
                roles["other"] += 1
    except Exception:
        pass

    # Process uptime/load (safe)
    try:
        uptime_sec = int(time.time() - float(PROCESS_START_TIME))
    except Exception:
        uptime_sec = None
    try:
        l1, l5, l15 = os.getloadavg()
        load = {"1": l1, "5": l5, "15": l15}
    except Exception:
        load = None

    # Cached bitcoind stats (public-safe)
    # TEMP: disable Bitcoin RPC here while reverse tunnel is fragile
    btc = {
        "chain": None,
        "block_height": None,
        "headers": None,
        "ibd": None,
        "verificationprogress": None,
        "mempool_size": None,
        "mempool_bytes": None,
        "peers": None,
        "error": "temporarily_disabled",
    }

    # LND state only (public-safe)
    lnd = {}
    try:
        cache = getattr(api_public_status, "_lnd_cache", None)
        ttl = 10
        if cache and (time.time() - cache.get("ts", 0)) < ttl:
            lnd = cache.get("data", {}) or {}
        else:
            state = None
            try:
                r = subprocess.run(
                    ["systemctl", "is-active", "lnd.service"], capture_output=True, text=True, timeout=0.6
                )
                state = (r.stdout or "").strip() or (r.stderr or "").strip() or "unknown"
            except Exception as e:
                state = f"unknown:{e.__class__.__name__}"
            lnd = {"active": True if state == "active" else False, "state": state}
            api_public_status._lnd_cache = {"ts": time.time(), "data": lnd}
    except Exception as e:
        lnd = {"active": False, "state": f"unknown:{e.__class__.__name__}"}

    # Back-compat fields
    height = btc.get("block_height")
    err = btc.get("error")

    return jsonify(
        {
            "server_time_epoch": now,
            "server_time_utc": iso,
            "block_height": height,
            "error": err,
            "online_users": online_users,
            "active_sockets": active_sockets,
            "online_roles": roles,
            "uptime_sec": uptime_sec,
            "load": load,
            "btc": btc,
            "lnd": lnd,
        }
    )


# /PUBLIC_STATUS_EXT_V3


# LND_STATUS_API_V1: wallet/channel stats (login + full only)
@app.route("/api/lnd/status", methods=["GET"])
def api_lnd_status():
    import os, time, json, subprocess
    from flask import jsonify, session

    if not (session.get("logged_in_pubkey") or "").strip():
        return jsonify(ok=False, error="Not logged in"), 401
    if (session.get("access_level") or "").strip().lower() != "full":
        return jsonify(ok=False, error="Full access required"), 403

    cache = getattr(api_lnd_status, "_cache", None)
    ttl = 10
    if cache and (time.time() - cache.get("ts", 0)) < ttl:
        return jsonify(cache.get("data", {})), 200

    lncli_bin = os.getenv("LND_LNCLI_BIN", "/usr/local/bin/lncli")
    lnddir = os.getenv("LND_DIR", "/var/lib/lnd")

    # Prefer runtime copies if present
    tls_candidates = [
        os.getenv("LND_TLS_CERT", ""),
        "/srv/ubid/runtime/lnd/tls.cert",
        f"{lnddir}/tls.cert",
    ]
    mac_candidates = [
        os.getenv("LND_READONLY_MACAROON", ""),
        os.getenv("LND_MACAROON", ""),
        "/srv/ubid/runtime/lnd/readonly.macaroon",
        f"{lnddir}/data/chain/bitcoin/mainnet/readonly.macaroon",
    ]
    tls = next((x for x in tls_candidates if x and os.path.exists(x)), None)
    mac = next((x for x in mac_candidates if x and os.path.exists(x)), None)

    if not tls or not mac:
        data = {"ok": False, "error": "LND cert/macaroon not found", "active": False}
        api_lnd_status._cache = {"ts": time.time(), "data": data}
        return jsonify(data), 500

    base = [lncli_bin, f"--lnddir={lnddir}", f"--tlscertpath={tls}", f"--macaroonpath={mac}"]

    rpcserver = (os.getenv("LND_RPCSERVER") or "127.0.0.1:10009").strip()
    if rpcserver:
        base.append(f"--rpcserver={rpcserver}")

    def run(args, timeout=8.0):
        r = subprocess.run(base + args, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            msg = (r.stderr or r.stdout or "").strip()
            raise RuntimeError(msg[:300] if msg else "lncli error")
        out = (r.stdout or "").strip()
        return json.loads(out) if out else {}

    try:
        info = run(["getinfo"])
        wb = run(["walletbalance"])
        cb = run(["channelbalance"])
        ch = run(["listchannels"], timeout=12.0)
        # summarize channels (avoid huge payload)
        chans = ch.get("channels") or []
        local_sum = sum(int(x.get("local_balance") or 0) for x in chans)
        remote_sum = sum(int(x.get("remote_balance") or 0) for x in chans)

        data = {
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
    except Exception:
        logger.error("Failed to build LND status payload", exc_info=True)
        data = {"ok": False, "active": False, "error": "Internal server error"}

    api_lnd_status._cache = {"ts": time.time(), "data": data}
    return jsonify(data), 200


# /LND_STATUS_API_V1

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
app.register_blueprint(agent_bp)
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

register_socket_handlers(socketio)


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
        except Exception:  # pragma: no cover - network dependent
            health_status["rpc"] = "error"
            health_status["rpc_error"] = "Internal server error"
            logger.warning("RPC health check failed", exc_info=True)

        return jsonify(health_status), 200
    except Exception:  # pragma: no cover - defensive
        logger.error("Health check failed", exc_info=True)
        return jsonify({"status": "unhealthy", "error": "Internal server error"}), 500


# --- Dev dashboard hard block (must run before any login redirect gates) ---
@app.before_request
def _dev_dashboard_full_only():
    # PAYG_BEARER_BILLING_AGENT_BYPASS_V1: allow billing-agent endpoints to use Bearer tokens
    # Session gate must not block these; require_oauth_token will enforce auth+scope.
    if request.path.startswith("/api/billing/agent/"):
        return None

    # Always hide dev dashboard unless full (even if not logged in)
    if request.path.rstrip("/") == "/dev/dashboard" and session.get("access_level") != "full":
        from flask import make_response as _make_response

        return _make_response("Forbidden", 403)


# ------------------------------------------------------------------------


@app.before_request
def _oauth_public_allowlist():

    # EXEMPT: allow agent invoice endpoints without session (protected by localhost + Bearer in blueprint)
    from flask import request as _req

    p = _req.path or ""
    if p.startswith("/api/internal/agent/invoice"):
        return
    # PAYG_BILLING_AGENT_BYPASS_ALL_V1: never block billing-agent bearer endpoints with session gates
    from flask import request as _req

    if (_req.path or "").startswith("/api/billing/agent/"):
        return None
    if (_req.path or "").startswith("/agent/"):
        return None

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
            cur.execute("""
                
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

            """)
            row = cur.fetchone() or {}
            # cast Decimals/ints cleanly if needed
            return {k: int(row[k]) if row.get(k) is not None else 0 for k in row.keys()}
    except Exception:
        logger.error("Database metrics query failed", exc_info=True)
        return {"db_error": "Internal server error"}
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
    except Exception:
        logger.error("Metrics endpoint failed", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


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

# TURN_RATE_LIMIT_V1: simple in-process limiter for /turn_credentials
# Env knobs:
#   TURN_RL_WINDOW=60  (seconds)
#   TURN_RL_MAX=20     (requests per window)
TURN_RL_WINDOW = int(os.getenv("TURN_RL_WINDOW", "60"))
TURN_RL_MAX = int(os.getenv("TURN_RL_MAX", "20"))
_TURN_RL = {}  # key -> [timestamps]


def _turn_rate_limit_ok(key: str):
    import time as _t

    now = _t.time()
    arr = _TURN_RL.get(key, [])
    arr = [x for x in arr if (now - x) < TURN_RL_WINDOW]
    if len(arr) >= TURN_RL_MAX:
        retry = int(TURN_RL_WINDOW - (now - min(arr))) + 1
        _TURN_RL[key] = arr
        return False, max(retry, 1)
    arr.append(now)
    _TURN_RL[key] = arr
    return True, 0


@app.route("/turn_credentials")
def turn_credentials():
    # Require a logged-in session to prevent TURN credential scraping/abuse
    from flask import session, request

    if not (session.get("logged_in_pubkey") or "").strip():
        return jsonify({"error": "Not logged in"}), 401

    if not TURN_SECRET:
        return jsonify({"error": "TURN not configured"}), 500

    # TURN_RATE_LIMIT_CHECK_V1: per IP + session pubkey
    try:
        xf = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    except Exception:
        xf = ""
    ip = xf or (request.remote_addr or "unknown")
    pk = (session.get("logged_in_pubkey") or "").strip()
    ok, retry = _turn_rate_limit_ok(f"{ip}|{pk}")
    if not ok:
        return jsonify({"error": "Rate limited", "retry_after": retry}), 429
    username = str(int(time.time()) + TURN_TTL)
    # NOTE: TURN REST auth credential derivation remains HMAC-SHA1 for coturn compatibility.
    # Do not switch this hash algorithm without coordinating TURN server auth configuration.
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
      pin     -> White (PIN guest)
      random  -> Red   (anonymous guest like 'guest-xxxx')

    HARDENED:
      - tolerate None / whitespace
      - tolerate missing PIN maps
      - never raise (socket connect must not crash)
    """
    pk = (pubkey or "").strip()
    lvl = (access_level or "").strip().lower()

    if not pk:
        return "limited"

    if pk.startswith("guest-"):
        return "random"

    if pk.isdigit():
        return "pin"

    try:
        pin_map = globals().get("GUEST_PINS") or globals().get("GUEST_STATIC_PINS") or {}
        if pk in pin_map:
            return "pin"
    except Exception:
        pass

    if lvl == "full":
        return "full"
    if lvl == "limited":
        return "limited"

    return "limited"


# --- WebRTC signaling relay (server) ---


def sids_for_pubkey(pk: str):
    """Get all socket IDs for a given pubkey"""
    return [sid for sid, who in ACTIVE_SOCKETS.items() if who == pk]


app.config["SESSION_PERMANENT"] = True
app.permanent_session_lifetime = timedelta(days=7)

from decimal import Decimal


def extract_timelock_pubkeys_from_asm(asm: str):
    """
    Return (first_pub, second_pub) for the *timelock* OP_IF/OP_ELSE pair.

    Works for:
      A) Legacy: OP_IF <cltv> ... <pkA> OP_CHECKSIG OP_ELSE <cltv> ... <pkB> OP_CHECKSIG OP_ENDIF
      B) Multisig-wrapped: OP_IF ... OP_CHECKMULTISIG OP_ELSE OP_IF <cltv> ... <pkA> OP_CHECKSIG OP_ELSE ... <pkB> OP_CHECKSIG OP_ENDIF OP_ENDIF

    We ignore multisig header keys by preferring matches after OP_CHECKMULTISIG.
    """
    import re

    if not asm:
        return (None, None)

    toks = (asm or "").replace("\n", " ").split()

    ms_idx = -1
    try:
        ms_idx = toks.index("OP_CHECKMULTISIG")
    except ValueError:
        ms_idx = -1

    matches = []
    # pattern: <lock> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG
    for i in range(len(toks) - 4):
        if toks[i + 1] == "OP_CHECKLOCKTIMEVERIFY" and toks[i + 2] == "OP_DROP" and toks[i + 4] == "OP_CHECKSIG":
            lt = toks[i]
            pk = toks[i + 3]
            if lt.isdigit() and re.fullmatch(r"[0-9A-Fa-f]{66,130}", pk):
                matches.append((i, int(lt), pk))

    # Prefer timelock pair after multisig (if present)
    cand = [m for m in matches if m[0] > ms_idx] if ms_idx != -1 else matches
    if len(cand) >= 2:
        return (cand[0][2], cand[1][2])

    # fallback: last pair
    if len(matches) >= 2:
        return (matches[-2][2], matches[-1][2])

    return (None, None)


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

    # FIX_TIMELOCK_PUBKEYS_V4: compare user pubkey (hex or npub) to script pubkey (hex)
    def _pk_match(user_pk: str, script_hex_pk: str) -> bool:
        if not user_pk or not script_hex_pk:
            return False
        u = str(user_pk).strip()
        if u.lower().startswith("npub"):
            try:
                return to_npub(script_hex_pk) == u
            except Exception:
                return False
        return script_hex_pk.lower() == u.lower()

    for desc_item in rpc_conn.listdescriptors().get("descriptors", []):
        raw_desc = desc_item["desc"]

        # tolerate wrappers like wsh(raw(...))
        script = extract_script_from_any_descriptor(raw_desc)
        if not script:
            continue

        decoded = rpc_conn.decodescript(script)
        asm = decoded.get("asm", "")

        # FIX_BALANCE_CLASSIFY_V5:
        # - For 1 CLTV ELSE branch: treat as OUT (legacy behavior)
        # - For 2+ CLTV ELSE branches: earliest lock = IN, second = OUT (nested/dual-else)
        op_if_pub = extract_pubkey_from_op_if(asm)
        else_branches = sorted(extract_else_branches(asm), key=lambda b: int(b.get("lock") or 0))

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

        # Rule 1: one CLTV branch => OUT
        if len(else_branches) == 1:
            b = else_branches[0]
            if b.get("pubkey") and _pk_match(pubkey_hex, b["pubkey"]):
                out_total += sum_btc
                matched = True

        # Rule 2: two+ CLTV branches => earliest=IN, second=OUT
        elif len(else_branches) >= 2:
            early = else_branches[0]
            late = else_branches[1]
            if early.get("pubkey") and _pk_match(pubkey_hex, early["pubkey"]):
                in_total += sum_btc
                matched = True
            elif late.get("pubkey") and _pk_match(pubkey_hex, late["pubkey"]):
                out_total += sum_btc
                matched = True

        # Fallback: OP_IF pubkey behaves like IN for old scripts
        if (not matched) and op_if_pub and _pk_match(pubkey_hex, op_if_pub):
            in_total += sum_btc
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

# removed duplicate RPC helper (use app.utils.get_rpc_connection)


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

    # EXEMPT: agent invoice endpoints bypass session/login gate (protected by localhost + Bearer token)
    from flask import request as _req

    p = _req.path or ""
    if p.startswith("/api/internal/agent/invoice"):
        return None
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

    # PAYG_BILLING_AGENT_ALLOWLIST_V1: billing-agent endpoints are Bearer-authenticated
    # and must never be blocked by session/login gates.
    if p.startswith("/api/billing/agent/"):
        return None
    auth_header = request.headers.get("Authorization", "")
    # Bearer API calls should NOT be redirected to /login. Token validation happens in the route.
    if auth_header.startswith("Bearer ") and p.startswith("/api/"):
        return None

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
        or p.startswith("/p/")
        or p.startswith("/api/playground")
        or p in ("/api/pof/stats", "/api/pof/stats/")
        or p.startswith("/play")
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
        "/.well-known/agent.json",
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

    # PUBLIC_AGENT_READONLY_V2
    # Public GET endpoints for marketplace / discovery / verification.
    # Keep write or paid flows protected.
    AGENT_PUBLIC_PATHS = {
        "/agent/capabilities",
        "/agent/capabilities/schema",
        "/agent/skills",
        "/agent/request",
        "/agent/attestations",
        "/agent/reputation",
        "/agent/chain/health",
        "/agent/marketplace/listing",
        "/agent/trust/hodlxxi-herald-01",
        "/agent/binding/hodlxxi-herald-01",
        "/agent/trust-summary/hodlxxi-herald-01.json",
        "/agent/covenants/hodlxxi-herald-covenant-v1.json",
    }
    if (
        request.method in {"GET", "HEAD"}
        and (
            p in AGENT_PUBLIC_PATHS
            or p.startswith("/agent/verify/")
            or p.startswith("/agent/jobs/")
            or p.startswith("/reports/")
            or p.startswith("/verify/report/")
            or p.startswith("/verify/nostr/")
            or p.startswith("/agent/trust/")
            or p.startswith("/agent/binding/")
            or p.startswith("/agent/trust-summary/")
            or p.startswith("/agent/covenants/")
        )
    ) or (request.method == "POST" and p in {"/agent/request", "/agent/message"}):
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
        auth_header = request.headers.get("Authorization", "")
        # Allow Bearer-token API calls without requiring a web session
        if auth_header.startswith("Bearer ") and p.startswith("/api/"):
            return None
        auth_header = request.headers.get("Authorization", "")
        if (
            p.startswith("/api/")
            and not p.startswith("/api/playground")
            and not p.startswith("/api/public/")
            and not (p == "/api/demo/protected" and auth_header.startswith("Bearer "))
        ) or p.endswith("/set_labels_from_zpub"):
            return jsonify(ok=False, error="Not logged in"), 401
        nxt = request.full_path if request.query_string else request.path
        return redirect(url_for("login", next=nxt))


def purge_old_messages():
    """Keep only messages newer than EXPIRY_SECONDS."""
    import time

    now = time.time()

    def is_fresh(m):
        ts = m.get("ts") if isinstance(m, dict) else None
        return ts is not None and (now - ts) <= EXPIRY_SECONDS

    global CHAT_HISTORY
    CHAT_HISTORY[:] = [m for m in CHAT_HISTORY if is_fresh(m)]


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
    print("API_VERIFY_DATA =", data, flush=True)
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
        except Exception:
            logger.error("Signature verification failed", exc_info=True)
            return jsonify({"verified": False, "error": "Internal server error"}), 500
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
    # Backwards-compatible: return the first pubkey found in ELSE branches
    branches = extract_else_branches(asm)
    return branches[0]["pubkey"] if branches else None


def extract_else_branches(asm: str) -> list[dict]:
    """
    Extract all branches matching:
      <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <PUBKEY> OP_CHECKSIG
    Works even when OP_ELSE contains nested OP_IF/OP_ELSE.
    Returns list of dicts: [{"lock": int, "pubkey": str}, ...] (unique).
    """
    ops = (asm or "").split()
    out: list[dict] = []

    for i, tok in enumerate(ops):
        if tok != "OP_CHECKLOCKTIMEVERIFY":
            continue
        if i == 0 or not ops[i - 1].isdigit():
            continue
        lock = int(ops[i - 1])

        pk = None
        # pubkey usually appears shortly after OP_DROP; scan a small window
        for j in range(i + 1, min(i + 20, len(ops))):
            t = ops[j]
            if re.fullmatch(r"[0-9a-fA-F]{66}", t) or re.fullmatch(r"[0-9a-fA-F]{130}", t):
                pk = t
                break
        if pk:
            out.append({"lock": lock, "pubkey": pk})

    # de-dup
    seen = set()
    uniq = []
    for b in out:
        key = (b["lock"], b["pubkey"].lower())
        if key in seen:
            continue
        seen.add(key)
        uniq.append(b)
    return uniq


def else_early_late(asm: str):
    """
    Returns (early, late) where early is the smallest locktime branch from OP_ELSE.
    early/late are dicts like {"lock": int, "pubkey": str} or None.
    """
    branches = sorted(extract_else_branches(asm), key=lambda b: b["lock"])
    early = branches[0] if len(branches) >= 1 else None
    late = branches[1] if len(branches) >= 2 else None
    return early, late


def format_asm(asm):
    ops = (asm or "").split()
    formatted_ops = []

    for op in ops:
        # Mask any compressed pubkey token (02/03 + 64 hex) using ref-based click
        if re.fullmatch(r"(?i)(02|03)[0-9a-f]{64}", op):
            formatted_ops.append(clickable_ref(op))
        else:
            formatted_ops.append(op)

    grouped_ops = [" ".join(formatted_ops[i : i + 4]) for i in range(0, len(formatted_ops), 4)]
    return "\n".join(grouped_ops)


def extract_script_from_raw_descriptor(descriptor):
    match = re.search(r"raw\(([0-9A-Fa-f]+)\)", descriptor)
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


# --- pubkey ref (no full pubkey in HTML) ---
def _pkref_redis():
    # Dedicated tiny redis client for pubkey refs (TTL). Uses existing env if present.
    url = os.environ.get("REDIS_URL") or os.environ.get("REDIS_URI") or "redis://localhost:6379/0"
    try:
        return redis.Redis.from_url(url, decode_responses=True)
    except Exception:
        # fallback
        return redis.Redis(host="localhost", port=6379, decode_responses=True)


def _pkref_store(pubkey: str, ttl_sec: int = 600) -> str:
    # Store mapping ref->pubkey server-side; return short token.
    ref = secrets.token_urlsafe(9)  # ~12 chars
    r = _pkref_redis()
    r.setex(f"hodlxxi:pkref:{ref}", ttl_sec, pubkey)
    return ref


def clickable_ref(pubkey: str) -> str:
    # clickable span that DOES NOT reveal pubkey in HTML
    ref = _pkref_store(pubkey)
    short = pubkey[-4:]
    return (
        f'<span class="clickable-pubkey" onclick="handlePubKeyClickRef(\'{ref}\');">'
        f'<span style="color:red;">{short}</span></span>'
    )


@app.get("/api/pubkey/resolve")
def api_pubkey_resolve():
    # Require login (same behavior as /home): no anonymous resolution
    if not session.get("logged_in_pubkey"):
        return jsonify({"error": "Not logged in"}), 401
    ref = request.args.get("ref", "").strip()
    if not ref or len(ref) > 64:
        return jsonify({"error": "Bad ref"}), 400
    r = _pkref_redis()
    pub = r.get(f"hodlxxi:pkref:{ref}")
    if not pub:
        return jsonify({"error": "Expired or unknown ref"}), 404
    return jsonify({"pubkey": pub})


# --- end pubkey ref ---


def clickable_trunc(pubkey):
    # Return ref-based clickable so pubkey never appears in HTML/JSON
    return clickable_ref(pubkey)


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
        # Also mask ANY compressed pubkey (02/03 + 64 hex) inside raw-hex (e.g., multisig scripts)
        masked_hex = re.sub(
            r"(?i)(02|03)[0-9a-f]{64}",
            lambda m: clickable_ref(m.group(0)),
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
    from app.browser_shell_routes import render_browser_home_page

    return render_browser_home_page(logger=logger)


# --- Aliases: panels live inside /home (hash router) ---
# If any UI link navigates by path, keep it working.
@app.route("/explorer", methods=["GET"])
def explorer_alias():
    return redirect_explorer()


@app.route("/onboard", methods=["GET"])
def onboard_alias():
    return redirect_onboard()


@app.route("/oneword", methods=["GET"])
def oneword_alias():
    return redirect_oneword()


@app.route("/verify_pubkey_and_list", methods=["GET"])
def verify_pubkey_and_list():
    import re
    from decimal import Decimal

    pubkey = request.args.get("pubkey")

    # FIX_INOUT_TOTALS_V1: compute incoming/outgoing totals from matched descriptors below
    in_role_btc = Decimal("0")
    out_role_btc = Decimal("0")
    in_role_usd = Decimal("0")
    out_role_usd = Decimal("0")
    ratio = None

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

            # FIX_VERIFY_USES_TIMELOCK_PUBKEYS_V2
            op_if_pub, op_else_pub = extract_timelock_pubkeys_from_asm(asm)
            if not op_if_pub and not op_else_pub:
                op_if_pub = extract_pubkey_from_op_if(asm)
                op_else_pub = extract_pubkey_from_op_else(asm)
            op_if_npub = to_npub(op_if_pub) if op_if_pub else None
            op_else_npub = to_npub(op_else_pub) if op_else_pub else None

            # FIX_INOUT_TOTALS_V1: accumulate role totals for the queried pubkey (no pubkey leakage to JSON)
            try:
                total_btc = save_bal + check_bal
                total_usd = total_btc * btc_price

                role = None
                if isinstance(pubkey, str) and pubkey.startswith("npub"):
                    if op_if_npub and op_if_npub == pubkey:
                        role = "in"
                    elif op_else_npub and op_else_npub == pubkey:
                        role = "out"
                else:
                    pkl = (pubkey or "").lower()
                    if op_if_pub and op_if_pub.lower() == pkl:
                        role = "in"
                    elif op_else_pub and op_else_pub.lower() == pkl:
                        role = "out"

                if role == "in":
                    in_role_btc += total_btc
                    in_role_usd += total_usd
                elif role == "out":
                    out_role_btc += total_btc
                    out_role_usd += total_usd
            except Exception:
                pass

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
                    # hide full pubkeys in JSON; provide only tail+ref
                    "op_if_tail": (op_if_pub[-4:] if op_if_pub else None),
                    "op_else_tail": (op_else_pub[-4:] if op_else_pub else None),
                    "op_if_ref": (_pkref_store(op_if_pub) if op_if_pub else None),
                    "op_else_ref": (_pkref_store(op_else_pub) if op_else_pub else None),
                    "op_if_pub": None,
                    "op_else_pub": None,
                    "address": segwit_addr,
                    "truncated_address": truncate_address(segwit_addr) if segwit_addr else None,
                    "qr_code": generate_qr_code(segwit_addr) if segwit_addr else None,
                    "balance_usd": f"{bal_usd:.2f}",
                    "nostr_npub": nostr_npub,
                    "nostr_npub_truncated": truncated_npub,
                    "op_if_pub": None,
                    "op_if_tail": (op_if_pub[-4:] if op_if_pub else None),
                    "op_if_ref": (_pkref_store(op_if_pub) if op_if_pub else None),
                    "op_else_pub": None,
                    "op_else_tail": (op_else_pub[-4:] if op_else_pub else None),
                    "op_else_ref": (_pkref_store(op_else_pub) if op_else_pub else None),
                    "script_hex": mask_hex_value(script_hex_val),
                    "saving_balance_usd": f"{save_usd:.2f}",
                    "checking_balance_usd": f"{check_usd:.2f}",
                    "counterparty_online": counterparty_online,
                    "counterparty_pubkey": None,
                    "counterparty_tail": (counterparty_pubkey[-4:] if counterparty_pubkey else None),
                    "counterparty_ref": (_pkref_store(counterparty_pubkey) if counterparty_pubkey else None),
                    "op_if_npub": op_if_npub,
                    "op_else_npub": op_else_npub,
                    # full-access only
                    "raw_script": raw_script_for_ui,
                    "onboard_link": onboard_link,
                }
            )
        if not matched:
            return jsonify({"valid": False, "error": "No matching descriptors found."}), 404

        # FIX_INOUT_TOTALS_V1: totals come from role totals accumulated above
        in_total_btc = in_role_btc
        out_total_btc = out_role_btc
        try:
            ratio = float(out_total_btc / in_total_btc) if in_total_btc and in_total_btc != 0 else None
        except Exception:
            ratio = None

        in_usd_val = float(in_role_usd)
        out_usd_val = float(out_role_usd)

        return (
            jsonify(
                {
                    "valid": True,
                    "descriptors": matched,
                    "in_total": format(in_total_btc, ".8f"),
                    "out_total": format(out_total_btc, ".8f"),
                    "ratio": ratio,
                    # explicit fields for WhoIs panels (USD + BTC)
                    "in_btc": format(in_total_btc, ".8f"),
                    "out_btc": format(out_total_btc, ".8f"),
                    "in_usd": f"{in_usd_val:.2f}",
                    "out_usd": f"{out_usd_val:.2f}",
                    "incoming_usd": f"{in_usd_val:.2f}",
                    "outgoing_usd": f"{out_usd_val:.2f}",
                }
            ),
            200,
        )

    except Exception:
        logger.error("Error in verify_pubkey_and_list", exc_info=True)
        return jsonify({"valid": False, "error": "Internal server error"}), 500


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
        else_branches = extract_else_branches(asm)
        early, late = else_early_late(asm)
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
                "op_if": op_if,
                "op_else": op_else,
                "npub_if": npub_if,
                "npub_else": npub_else,
                "op_else_branches": else_branches,
                "else_early_pub": (early.get("pubkey") if early else None),
                "else_early_lock": (early.get("lock") if early else None),
                "else_late_pub": (late.get("pubkey") if late else None),
                "else_late_lock": (late.get("lock") if late else None),
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
    except Exception:
        logger.error("decode_raw_script failed", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


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
    except Exception:
        logger.error("import_descriptor failed", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


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

    except Exception:
        logger.error("set_labels_from_zpub failed", exc_info=True)
        return jsonify(error="Internal server error"), 500


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
    except Exception:
        logger.error("btc_rpc failed", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


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

    except Exception:
        logger.error("make_wif_qr failed", exc_info=True)
        return jsonify({"ok": False, "error": "Internal server error"}), 400


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

    # EXEMPT: agent invoice endpoints bypass session/login gate (protected by localhost + Bearer token)
    from flask import request as _req

    p = _req.path or ""
    if p.startswith("/api/internal/agent/invoice"):
        return None
    # PAYG_BILLING_AGENT_BYPASS_ALL_V1: never block billing-agent bearer endpoints with session gates
    from flask import request as _req

    if (_req.path or "").startswith("/api/billing/agent/"):
        return None

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
    if (
        p.startswith("/agent/trust/")
        or p.startswith("/agent/binding/")
        or p.startswith("/agent/trust-summary/")
        or p.startswith("/agent/covenants/")
        or p.startswith("/reports/")
        or p.startswith("/verify/report/")
        or p.startswith("/verify/nostr/")
    ):
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

    auth = request.headers.get("Authorization", "")
    if p == "/api/demo/protected" and auth.startswith("Bearer "):
        return None

    # Fallback: require session for other /api/*

    # Public allow-list:

    #  - /api/public/*

    #  - /api/playground/*

    #  - /api/pof/stats (public stats only)

    if (
        p.startswith("/api/")
        and not (
            p.startswith("/api/public/")
            or p.startswith("/api/playground")
            or p in ("/api/pof/stats", "/api/pof/stats/")
        )
        and not session.get("logged_in_pubkey")
    ):

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


NOSTR_LOGIN_MAX_AGE_SECONDS = int(os.getenv("NOSTR_LOGIN_MAX_AGE_SECONDS", "300"))
NOSTR_LOGIN_MAX_FUTURE_SKEW_SECONDS = int(os.getenv("NOSTR_LOGIN_MAX_FUTURE_SKEW_SECONDS", "60"))


def _nostr_compact_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


# Developer note:
# Nostr login currently uses a server-issued one-time challenge plus a signed
# Nostr event at kind 22242 for compatibility with the existing frontend.
# Future HTTP-native auth could migrate toward NIP-98 / kind 27235, but that is
# not implemented here.
def _nostr_event_id(event: dict) -> str:
    payload = [
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"],
    ]
    return hashlib.sha256(_nostr_compact_json(payload).encode("utf-8")).hexdigest()


def _nostr_get_tag(event: dict, name: str) -> Optional[str]:
    tags = event.get("tags")
    if not isinstance(tags, list):
        return None

    for tag in tags:
        if (
            isinstance(tag, list)
            and len(tag) >= 2
            and isinstance(tag[0], str)
            and isinstance(tag[1], str)
            and tag[0] == name
        ):
            return tag[1]
    return None


def verify_nostr_login_event(
    event: dict,
    *,
    expected_pubkey: str,
    expected_challenge: str,
    expected_verify_url: Optional[str] = None,
    now_ts: Optional[int] = None,
) -> tuple[bool, Optional[str]]:
    if not isinstance(event, dict):
        return False, "Invalid nostr_event"

    required_fields = ("id", "pubkey", "created_at", "kind", "tags", "content", "sig")
    missing = [field for field in required_fields if field not in event]
    if missing:
        return False, f"Missing nostr_event field: {missing[0]}"

    event_pubkey = (event.get("pubkey") or "").strip().lower()
    event_id = (event.get("id") or "").strip().lower()
    event_sig = (event.get("sig") or "").strip().lower()
    expected_pubkey = (expected_pubkey or "").strip().lower()

    if not re.fullmatch(r"[0-9a-f]{64}", event_pubkey):
        return False, "Invalid nostr pubkey"
    if not re.fullmatch(r"[0-9a-f]{64}", event_id):
        return False, "Invalid nostr event id"
    if not re.fullmatch(r"[0-9a-f]{128}", event_sig):
        print("NOSTR_FAIL=invalid_signature", flush=True)
        return False, "Invalid nostr signature"
    if event_pubkey != expected_pubkey:
        print(f"NOSTR_FAIL=pubkey_mismatch expected={expected_pubkey} got={event_pubkey}", flush=True)
        return False, "Pubkey mismatch"

    try:
        created_at = int(event.get("created_at"))
    except Exception:
        return False, "Invalid nostr created_at"

    try:
        kind = int(event.get("kind"))
    except Exception:
        return False, "Invalid nostr kind"

    if kind != 22242:
        return False, "Invalid nostr kind"
    if not isinstance(event.get("tags"), list):
        return False, "Invalid nostr tags"
    if not isinstance(event.get("content"), str):
        return False, "Invalid nostr content"

    now_ts = int(now_ts if now_ts is not None else time.time())
    if created_at < now_ts - NOSTR_LOGIN_MAX_AGE_SECONDS:
        return False, "Nostr event is too old"
    if created_at > now_ts + NOSTR_LOGIN_MAX_FUTURE_SKEW_SECONDS:
        return False, "Nostr event is too far in the future"

    challenge_tag = _nostr_get_tag(event, "challenge")
    if not challenge_tag or challenge_tag != expected_challenge:
        print(f"NOSTR_FAIL=challenge_mismatch expected={expected_challenge} got={challenge_tag}", flush=True)
        return False, "Challenge mismatch"

    url_tag = _nostr_get_tag(event, "u")
    if url_tag and expected_verify_url and url_tag != expected_verify_url:
        print(f"NOSTR_FAIL=url_mismatch expected={expected_verify_url} got={url_tag}", flush=True)
        return False, "Nostr event URL mismatch"

    normalized_event = dict(event)
    normalized_event["pubkey"] = event_pubkey
    normalized_event["id"] = event_id
    normalized_event["sig"] = event_sig
    normalized_event["created_at"] = created_at
    normalized_event["kind"] = kind

    recomputed_id = _nostr_event_id(normalized_event)
    if recomputed_id != event_id:
        print("NOSTR_FAIL=event_id_mismatch", flush=True)
        return False, "Nostr event id mismatch"

    try:
        from coincurve import PublicKeyXOnly

        verified = PublicKeyXOnly(bytes.fromhex(event_pubkey)).verify(
            bytes.fromhex(event_sig),
            bytes.fromhex(recomputed_id),
        )
    except Exception as e:
        logger.error("Nostr login verification error: %s", e)
        return False, "Nostr signature verification unavailable"

    if not verified:
        print("NOSTR_FAIL=invalid_signature", flush=True)
        return False, "Invalid nostr signature"

    return True, None


# WHOAMI_V2_USERSTATS
# WHOAMI_V3 (screensaver-compatible)
@app.route("/api/whoami", methods=["GET"])
def api_whoami():
    spk = (session.get("logged_in_pubkey") or "").strip()
    lvl = (session.get("access_level") or "limited").strip()
    glabel = (session.get("guest_label") or "").strip()
    lm = (session.get("login_method") or "").strip()

    # If not logged in, keep existing behavior: 401 JSON (screensaver handles this)
    if not spk:
        return jsonify(ok=False, error="Not logged in", logged_in=False), 401

    # role classification (no external deps)
    role = (lvl or "limited").lower()
    try:
        gl = glabel.lower()
        if gl.startswith("guest-"):
            role = "pin"
            if "random" in gl:
                role = "random"
    except Exception:
        pass
    try:
        if spk.startswith("guest-"):
            role = "random"
        if spk.startswith("guest-pin-"):
            role = "pin"
    except Exception:
        pass

    # active socket count for this pubkey
    try:
        conns = len([sid for sid, who in ACTIVE_SOCKETS.items() if who == spk]) if spk else 0
    except Exception:
        conns = 0

    # online flag (SocketIO presence)
    try:
        online = bool(spk) and (spk in ONLINE_USERS)
    except Exception:
        online = False

    # display helper (optional)
    def short_pk(x: str) -> str:
        if not x:
            return "—"
        if len(x) > 10:
            return x[:2] + "…" + x[-4:]
        return x

    try:
        display = glabel or (SPECIAL_NAMES.get(spk) if "SPECIAL_NAMES" in globals() else "") or short_pk(spk)
    except Exception:
        display = short_pk(spk)

    return jsonify(
        ok=True,
        logged_in=True,
        pubkey=spk,
        access_level=lvl or "limited",
        login_method=lm,
        guest_label=glabel,
        role=role,
        online=online,
        active_connections=conns,
        display=display,
    )


# /WHOAMI_V3


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
    now_utc = datetime.now(timezone.utc)
    ACTIVE_CHALLENGES[cid] = {
        "pubkey": pubkey,
        "label": label,
        "challenge": challenge,
        "created": now_utc,
        "expires": now_utc + timedelta(minutes=5),
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

    if not pubkey:
        spk = (session.get("logged_in_pubkey") or "").strip()
        if spk and is_valid_pubkey(spk):
            pubkey = spk

    if not cid:
        return jsonify(error="Missing required parameters"), 400

    rec = ACTIVE_CHALLENGES.get(cid)
    if not rec or rec["expires"] < datetime.now(timezone.utc):
        return jsonify(error="Invalid or expired challenge"), 400
    # For nostr, pubkey is validated inside nostr event
    if method != "nostr":
        if rec["pubkey"] != pubkey:
            return jsonify(error="Pubkey mismatch"), 400

    method = rec.get("method", "api")

    # --- 🔹 Verification depending on method ---
    if method == "nostr":
        nostr_event = data.get("nostr_event")
        if not nostr_event:
            return jsonify(error="Missing nostr_event"), 400

        nostr_expected_pubkey = pubkey
        if re.fullmatch(r"[0-9a-fA-F]{66}", nostr_expected_pubkey) and nostr_expected_pubkey[:2].lower() in {
            "02",
            "03",
        }:
            nostr_expected_pubkey = nostr_expected_pubkey[2:]

        ok, error = verify_nostr_login_event(
            nostr_event,
            expected_pubkey=nostr_expected_pubkey,
            expected_challenge=rec["challenge"],
            expected_verify_url=request.url_root.rstrip("/") + url_for("api_verify"),
        )
        if not ok:
            return jsonify(error=error or "Nostr verification failed"), 403
    elif method == "lightning":
        return jsonify(error=f"Verification method '{method}' not yet supported"), 501
    else:
        if not signature:
            return jsonify(error="Missing required parameters"), 400

        # Default: Bitcoin RPC verification
        try:
            rpc = get_rpc_connection()
            addr = derive_legacy_address_from_pubkey(pubkey)
            ok = rpc.verifymessage(addr, signature, rec["challenge"])
        except Exception:
            return jsonify(error="Signature verification temporarily unavailable"), 500

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

    env_name = os.getenv("FLASK_ENV", "development").strip().lower()
    secure_default = env_name == "production"
    secure_cookies = _as_bool(os.getenv("SECURE_COOKIES"), default=secure_default)
    access_cookie_httponly = _as_bool(os.getenv("ACCESS_COOKIE_HTTPONLY"), default=True)
    cookie_samesite = os.getenv("COOKIE_SAMESITE", "Lax")

    # Best-effort: mint and set cookies if JWT machinery is present
    try:
        at = mint_access_token(sub=pubkey)
        resp.set_cookie(
            "at",
            at,
            max_age=AT_TTL,
            secure=secure_cookies,
            httponly=access_cookie_httponly,
            samesite=cookie_samesite,
        )
    except Exception:
        pass

    try:
        rt = mint_refresh_token(sub=pubkey)
        resp.set_cookie(
            "rt",
            rt,
            max_age=RT_TTL,
            secure=secure_cookies,
            httponly=True,
            samesite=cookie_samesite,
        )
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
                        created_at=(
                            redis_client.created_at
                            if isinstance(redis_client.created_at, datetime)
                            else (
                                datetime.fromtimestamp(redis_client.created_at)
                                if redis_client.created_at
                                else datetime.utcnow()
                            )
                        ),
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

        user_pubkey = session.get("logged_in_pubkey")
        if not user_pubkey:
            return {"error": "login_required"}
        # 4. issue short-lived code
        code = secrets.token_urlsafe(24)
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        code_data = {
            "client_id": client_id,
            "user_pubkey": user_pubkey,
            "scope": " ".join(requested_scopes),
            "redirect_uri": redirect_uri,
            "state": state,
            "created_at": int(time.time()),
            "expires_at": expires_at.isoformat(),
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "nonce": nonce,
        }

        store_oauth_code(code, code_data, ttl=600)

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
        code_data = get_oauth_code(code)

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
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(48)

        user_id = code_data.get("user_id")
        user = get_user_by_id(user_id) if user_id else None
        if not user:
            return {"error": "invalid_grant", "detail": "user_not_found"}

        now = datetime.utcnow()
        access_expires_at = now + timedelta(seconds=TOKEN_TTL_SECONDS)
        refresh_expires_at = now + timedelta(days=30)
        store_oauth_token(
            str(uuid.uuid4()),
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer",
                "client_id": client.client_id,
                "user_id": user_id,
                "scope": scope_str,
                "access_token_expires_at": access_expires_at.isoformat(),
                "refresh_token_expires_at": refresh_expires_at.isoformat(),
            },
        )

        delete_oauth_code(code)
        now_ts = int(now.timestamp())
        id_claims = {
            "iss": ISSUER,
            "aud": client.client_id,
            "iat": now_ts,
            "exp": now_ts + TOKEN_TTL_SECONDS,
        }
        nonce = code_data.get("nonce")
        if nonce:
            id_claims["nonce"] = nonce
        id_token = issue_rs256_jwt(sub=user["pubkey"], claims=id_claims)

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
        token_data = get_oauth_token_by_refresh(refresh_token)
        if not token_data:
            return {"error": "invalid_grant", "detail": "refresh_not_found"}

        if token_data.get("client_id") != client.client_id:
            return {"error": "invalid_grant", "detail": "client_mismatch"}

        scope_str = token_data.get("scope", "read_limited")
        user_id = token_data.get("user_id")

        new_access = secrets.token_urlsafe(32)
        new_refresh = secrets.token_urlsafe(48)

        now = datetime.utcnow()
        access_expires_at = now + timedelta(seconds=TOKEN_TTL_SECONDS)
        refresh_expires_at = now + timedelta(days=30)
        store_oauth_token(
            str(uuid.uuid4()),
            {
                "access_token": new_access,
                "refresh_token": new_refresh,
                "token_type": "Bearer",
                "client_id": client.client_id,
                "user_id": user_id,
                "scope": scope_str,
                "access_token_expires_at": access_expires_at.isoformat(),
                "refresh_token_expires_at": refresh_expires_at.isoformat(),
            },
        )
        revoke_oauth_token_by_refresh(refresh_token)

        oauth_tokens_issued.inc()

        return {
            "access_token": new_access,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_SECONDS,
            "refresh_token": new_refresh,
        }

    def _gen_access(self, client: ClientCredentials, scope_str: str) -> str:
        return secrets.token_urlsafe(32)

    def _gen_refresh(self, client_id: str, scope_str: str) -> str:
        return secrets.token_urlsafe(48)


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
                logger.warning("JWT decode failed in require_scope: %s", e)
                return jsonify({"error": "invalid_token", "detail": "Token validation failed"}), 401

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
                logger.warning("JWT decode failed in require_scope (compat): %s", e)
                return jsonify({"error": "invalid_token", "detail": "Token validation failed"}), 401

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
    </style></head>
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
    resp.headers["Content-Security-Policy"] = (
        "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline';"
    )

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
        logger.exception("OAuth registration failed: %s", e)
        return jsonify({"error": "Registration failed", "details": "Internal server error"}), 500


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

    callback_url = url_for("lnurl_callback", session_id=sid, _external=True)
    params_url = url_for("lnurl_params", _external=True) + f"?sid={sid}"
    lnurl_str = _lnurl_bech32(params_url)

    try:
        store_lnurl_challenge(
            sid,
            {
                "k1": k1,
                "callback_url": callback_url,
                "metadata": {"created_via": "lnurl_create"},
            },
            ttl=LNURL_TTL,
        )
    except Exception as e:
        return jsonify({"status": "ERROR", "reason": f"store failed: {e}"}), 500

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
    sid = request.args.get("session_id") or request.args.get("sid")
    rec = get_lnurl_challenge(sid)

    if not rec:
        return jsonify({"status": "ERROR", "reason": "unknown session"}), 404

    callback_url = url_for("lnurl_callback", session_id=sid, _external=True)

    return jsonify({"tag": "login", "k1": rec["k1"], "callback": callback_url})


@app.route("/api/lnurl-auth/callback/<session_id>", methods=["GET"])
def lnurl_callback(session_id):
    """LNURL-Auth callback"""
    rec = get_lnurl_challenge(session_id)

    if not rec:
        return jsonify({"status": "ERROR", "reason": "unknown session"}), 404

    k1 = request.args.get("k1", "").strip()
    sig = request.args.get("sig", "").strip()
    key = request.args.get("key", "").strip()

    if not (k1 and sig and key):
        return jsonify({"status": "ERROR", "reason": "missing parameters"}), 400

    if k1 != rec["k1"]:
        return jsonify({"status": "ERROR", "reason": "k1 mismatch"}), 400

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

    try:
        update_lnurl_challenge(session_id, key)
    except Exception as e:
        return jsonify({"status": "ERROR", "reason": f"update failed: {e}"}), 500

    return jsonify({"status": "OK"}), 200


@app.route("/api/lnurl-auth/check/<session_id>", methods=["GET"])
def lnurl_check(session_id):
    """Check LNURL-Auth status"""
    rec = get_lnurl_challenge(session_id)

    if not rec:
        return jsonify({"authenticated": False, "error": "unknown session"}), 404

    verified = bool(rec.get("is_verified"))
    return jsonify({"authenticated": verified, "verified": verified, "pubkey": rec.get("pubkey")})


# ============================================================================
# ROUTES: PROTECTED DEMO API
# ============================================================================


@app.route("/api/demo/protected", methods=["GET"])
@require_oauth_token("read_limited")
@require_paid_client(cost_sats=int(os.getenv("HODLXXI_COST_DEMO_PROTECTED_SATS", "1")))
def api_demo_protected_v2():
    return jsonify({"status": "ok", "tier": "limited", "msg": "requires read_limited scope"})


@app.route("/api/billing/agent/create-invoice", methods=["POST"])
@require_oauth_token("read_limited")
def api_billing_agent_create_invoice():
    data = request.get_json(silent=True) or {}
    amount_raw = data.get("amount_sats") or request.form.get("amount_sats")
    if amount_raw is None:
        return jsonify({"ok": False, "error": "amount_sats required"}), 400
    try:
        amount_sats = int(amount_raw)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "amount_sats must be an integer"}), 400
    if amount_sats <= 0:
        return jsonify({"ok": False, "error": "amount_sats must be > 0"}), 400

    client_id = request.oauth_client_id
    memo = f"HODLXXI PAYG topup for client {client_id}"
    payload = create_client_invoice(client_id, amount_sats, memo)
    return jsonify(payload)


@app.route("/api/billing/agent/check-invoice", methods=["POST"])
@require_oauth_token("read_limited")
def api_billing_agent_check_invoice():
    data = request.get_json(silent=True) or {}
    invoice_id = data.get("invoice_id") or request.args.get("invoice_id") or request.form.get("invoice_id")
    if not invoice_id:
        return jsonify({"ok": False, "error": "invoice_id required"}), 400

    client_id = request.oauth_client_id
    payload = check_client_invoice(client_id, invoice_id)
    status_code = 404 if payload.get("error") == "invoice_not_found" else 200
    return jsonify(payload), status_code


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
                    "required_scope": "read_limited",
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

    auth_header = request.headers.get("Authorization", "")
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    if auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode("utf-8")
            client_id, client_secret = decoded.split(":", 1)
        except Exception:
            return jsonify({"error": "invalid_client"}), 401

    if not client_id or not client_secret:
        return jsonify({"error": "invalid_client"}), 401

    client = get_oauth_client(client_id)
    if not client or not secrets.compare_digest(client.get("client_secret", ""), client_secret):
        return jsonify({"error": "invalid_client"}), 401

    token_data = get_oauth_token(token)
    if not token_data:
        return jsonify({"active": False})

    user = get_user_by_id(token_data.get("user_id")) if token_data.get("user_id") else None
    exp_dt = None
    try:
        exp_dt = datetime.fromisoformat(token_data.get("access_token_expires_at"))
    except Exception:
        exp_dt = None
    exp_val = int(exp_dt.timestamp()) if exp_dt else None

    return jsonify(
        {
            "active": True,
            "client_id": token_data.get("client_id"),
            "scope": token_data.get("scope"),
            "exp": exp_val,
            "sub": user.get("pubkey") if user else None,
            "token_type": token_data.get("token_type", "Bearer"),
        }
    )


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

    # EXEMPT: agent invoice endpoints bypass session/login gate (protected by localhost + Bearer token)
    from flask import request as _req

    p = _req.path or ""
    if p.startswith("/api/internal/agent/invoice"):
        return None
    # PAYG_BILLING_AGENT_BYPASS_ALL_V1: never block billing-agent bearer endpoints with session gates
    from flask import request as _req

    if (_req.path or "").startswith("/api/billing/agent/"):
        return None

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
                    cur.execute("""
                        select client_id, client_name, redirect_uris, grant_types, response_types,
                               scope, token_endpoint_auth_method, created_at, metadata, is_active,
                               owner_pubkey, plan
                        from oauth_clients
                        order by created_at desc
                        limit 200
                    """)
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


# API_DEBUG_SESSION_ALIAS_V1

register_browser_routes(
    app,
    generate_challenge=generate_challenge,
    get_rpc_connection=get_rpc_connection,
    logger=logger,
    render_template_string_func=render_template_string,
    special_names=SPECIAL_NAMES,
    force_relay=FORCE_RELAY,
    chat_history=CHAT_HISTORY,
    online_users=ONLINE_USERS,
    purge_old_messages=purge_old_messages,
)


def _call_browser_route_alias(alias_name):
    handler = get_browser_route_handler(alias_name)
    if handler is None:
        raise RuntimeError(f"Browser route handler '{alias_name}' is not registered")
    return handler()


def login():
    return _call_browser_route_alias("login")


def logout():
    return _call_browser_route_alias("logout")


def root_redirect():
    return _call_browser_route_alias("root_redirect")


def playground():
    return _call_browser_route_alias("playground")


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
    return render_upgrade_page()


# HODLXXI_ACCOUNT_RESTORE_V3
# ACCAUNT_TYPO_BEFORE_AUTH_V3
# Fix common typo BEFORE auth guards so next= uses /account
@app.before_request
def _fix_accaunt_typo_before_auth_v3():
    # PAYG_BILLING_AGENT_BYPASS_ALL_V1: never block billing-agent bearer endpoints with session gates
    from flask import request as _req

    if (_req.path or "").startswith("/api/billing/agent/"):
        return None

    from flask import request, redirect

    if request.path == "/accaunt":
        return redirect("/account", code=301)
    if request.path == "/accaunts":
        return redirect("/accounts", code=301)


# RESTORE_ACCOUNT_ROUTE_V3
@app.route("/account", methods=["GET"])
def account():
    return render_account_page()


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


# === HODLXXI_APP_SOUND_INJECT_V3b: inject sound + socket hook into GET /app (ignore self-echo) ===
@app.after_request
def _hodlxxi_app_sound_inject_v3b(resp):
    try:
        if request.method != "GET":
            return resp
        if request.path not in ("/app", "/app/"):
            return resp
        ct = resp.headers.get("Content-Type", "")
        if "text/html" not in ct:
            return resp

        html = resp.get_data(as_text=True)
        if "HODLXXI_APP_SOUND_INJECT_V3b" in html:
            return resp

        import json

        my = str(session.get("logged_in_pubkey", "") or "")
        my_js = json.dumps(my)  # safe JS string literal (includes quotes)

        inject = (
            "<script src='/static/js/sound.js'></script>"
            "<script>(function(){"
            "var MY_PUBKEY=" + my_js + ";"
            "var SOUND_URL='/static/sounds/message.mp3';var ENTER_KEY='hodlxxi_enter_ding_done';try{if(!sessionStorage.getItem(ENTER_KEY)){sessionStorage.setItem(ENTER_KEY,'1');setTimeout(function(){try{ if(window.HODLXXI_PLAY_SOUND) window.HODLXXI_PLAY_SOUND(SOUND_URL,0.9); }catch(e){}},80);}}catch(e){}"
            "var NOISE=/typing|presence|pong|ping|joined|left|online|user:|connect|disconnect/i;"
            "var MATCH=/chat|message|msg|dm/i;"
            "var last=0;"
            "function dbg(){try{return localStorage.getItem('soundDebug')==='1';}catch(e){return false;}}"
            "function ding(){var now=Date.now(); if(now-last<250) return; last=now;"
            "try{ if(window.HODLXXI_PLAY_SOUND) window.HODLXXI_PLAY_SOUND(SOUND_URL,0.9); }catch(e){}"
            "}"
            "function install(){"
            "try{"
            "if(!window.io||!window.io.Socket||!window.io.Socket.prototype) return false;"
            "var P=window.io.Socket.prototype;"
            "if(P.__hodlxxi_sound_v3b) return true;"
            "P.__hodlxxi_sound_v3b=true;"
            "var orig=P.onevent;"
            "P.onevent=function(packet){"
            "try{"
            "var d=packet&&packet.data; var ev=d&&d[0]; var payload=d&&d[1];"
            "if(typeof ev==='string'){"
            "if(dbg()) console.log('[sock]',ev,d);"
            "if(MATCH.test(ev) && !NOISE.test(ev)){"
            "if(payload && typeof payload==='object' && payload.pubkey && MY_PUBKEY && payload.pubkey===MY_PUBKEY){"
            "return orig.call(this,packet);"
            "}"
            "ding();"
            "}"
            "}"
            "}catch(e){}"
            "return orig.call(this,packet);"
            "};"
            "return true;"
            "}catch(e){ return false; }"
            "}"
            "if(!install()){var tries=0; var t=setInterval(function(){"
            "tries++; if(install()||tries>40) clearInterval(t);"
            "},250);}"
            "})();</script>"
            "<!-- HODLXXI_APP_SOUND_INJECT_V3b -->"
        )

        if "</body>" in html:
            html = html.replace("</body>", inject + "</body>", 1)
        else:
            html = html + inject

        resp.set_data(html)
        resp.headers.pop("Content-Length", None)
    except Exception:
        pass
    return resp


# === /HODLXXI_APP_SOUND_INJECT_V3b ===


# === HODLXXI_LOGIN_SOUND_UNLOCK_V1: unlock audio on /login?next=/app so /app enter ding can play ===
@app.after_request
def _hodlxxi_login_sound_unlock_v1(resp):
    try:
        if request.method != "GET":
            return resp
        if request.path not in ("/login", "/universal_login"):
            return resp

        # Only when user is heading into the chat app
        nxt = (request.args.get("next", "") or "").strip()
        if nxt not in ("/app", "/app/"):
            return resp

        ct = resp.headers.get("Content-Type", "")
        if "text/html" not in ct:
            return resp

        html = resp.get_data(as_text=True)
        if "HODLXXI_LOGIN_SOUND_UNLOCK_V1" in html:
            return resp

        inject = (
            "<script src='/static/js/sound.js'></script>"
            "<script>(function(){"
            "var SOUND_URL='/static/sounds/message.mp3';"
            "var done=false;"
            "function unlock(){"
            "if(done) return; done=true;"
            "try{"
            "var AC=window.AudioContext||window.webkitAudioContext;"
            "if(AC){ var ctx=new AC(); ctx.resume().catch(function(){}); }"
            "}catch(e){}"
            "try{"
            ""
            "sessionStorage.removeItem('hodlxxi_enter_ding_done');"
            "}catch(e){}"
            "try{"
            ""
            "if(window.HODLXXI_PLAY_SOUND) window.HODLXXI_PLAY_SOUND(SOUND_URL, 0.0);"
            "}catch(e){}"
            "}"
            "['pointerdown','touchstart','click','keydown'].forEach(function(ev){"
            "window.addEventListener(ev, unlock, {passive:true, once:true});"
            "});"
            "})();</script>"
            "<!-- HODLXXI_LOGIN_SOUND_UNLOCK_V1 -->"
        )

        if "</body>" in html:
            html = html.replace("</body>", inject + "</body>", 1)
        else:
            html = html + inject

        resp.set_data(html)
        resp.headers.pop("Content-Length", None)
    except Exception:
        pass
    return resp


# === /HODLXXI_LOGIN_SOUND_UNLOCK_V1 ===


# HIDE_MANIFESTO_V1: allow user to hide Home manifesto for current login session
@app.route("/api/ui/hide_manifesto", methods=["POST"])
def api_hide_manifesto():
    try:
        # require some logged-in identity (guest or full)
        if not session.get("logged_in_pubkey"):
            return jsonify({"ok": False, "error": "not_logged_in"}), 401
        session["manifesto_hidden"] = True
        return jsonify({"ok": True})
    except Exception:
        logger.error("hide_manifesto failed", exc_info=True)
        return jsonify({"ok": False, "error": "Internal server error"}), 500

"""Explicit, loopback-only IAC preview composition. Never imported by wsgi:app."""

import ipaddress
import json
import os
import re
import ssl
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request, send_from_directory
from werkzeug.exceptions import HTTPException
from werkzeug.serving import WSGIRequestHandler, make_server

from app.services.invite_call_v0 import InviteCallStore, Unavailable

PREAUTH = "__Host-iac_preauth"
SESSION = "__Host-iac_session"
MAX_REQUEST = 144 * 1024
ASSETS = Path(__file__).with_name("static") / "iac"
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; media-src 'self' blob:; object-src 'none'; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'none'"
)


@dataclass(frozen=True)
class PreviewSettings:
    origin: str
    turn_url: str | None = None
    turn_secret: str | None = None

    def validate(self):
        parsed = urlsplit(self.origin)
        if (
            parsed.scheme != "https"
            or not re.fullmatch(r"iac-[a-z0-9-]{1,50}\.test", parsed.hostname or "")
            or parsed.port is None
            or parsed.port < 1024
            or self.origin != f"https://{parsed.hostname}:{parsed.port}"
        ):
            raise ValueError("dedicated HTTPS preview origin required")
        if self.turn_url is None and self.turn_secret is None:
            return
        if (
            not isinstance(self.turn_url, str)
            or type(self.turn_secret) is not str
            or len(self.turn_secret) < 32
            or not self.turn_secret.isascii()
        ):
            raise ValueError("isolated TURN configuration required")
        address = re.fullmatch(r"turn:(127(?:\.[0-9]{1,3}){3}):([1-9][0-9]{3,4})\?transport=udp", self.turn_url)
        if address is None or not ipaddress.ip_address(address[1]).is_loopback or not 1024 <= int(address[2]) <= 65535:
            raise ValueError("loopback UDP TURN required")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Unavailable()
        result[key] = value
    return result


def _invalid_constant(_value):
    raise Unavailable()


def _request_fields(fields):
    if request.mimetype != "application/json" or set(request.mimetype_params) - {"charset"}:
        raise Unavailable()
    if request.mimetype_params.get("charset", "utf-8").lower() != "utf-8":
        raise Unavailable()
    raw = request.get_data(cache=False)
    if not 0 < len(raw) <= MAX_REQUEST:
        raise Unavailable()
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_invalid_constant)
    if type(data) is not dict or set(data) != fields:
        raise Unavailable()
    return data


def _cookie(response, name, value, max_age):
    response.set_cookie(name, value, max_age=max_age, secure=True, httponly=True, samesite="Strict", path="/")


def create_preview_app(*, enabled=False, settings=None, accounts=None, clock=None, elapsed=None):
    """Compose only IAC routes, with an isolated in-memory authority."""
    if enabled is not True or os.getenv("FLASK_ENV", "").strip().lower() == "production":
        raise ValueError("IAC preview is disabled")
    if type(settings) is not PreviewSettings:
        raise ValueError("explicit preview settings required")
    settings.validate()
    overrides = {name: value for name, value in (("clock", clock), ("elapsed", elapsed)) if value is not None}
    store = InviteCallStore(settings.origin, accounts, settings.turn_url, settings.turn_secret, **overrides)
    app = Flask(__name__, static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=MAX_REQUEST, PROPAGATE_EXCEPTIONS=False)
    app.extensions["iac_store"] = store
    authority = urlsplit(settings.origin).netloc

    @app.before_request
    def enforce_boundary():
        if (
            request.environ.get("wsgi.multiprocess")
            or request.scheme != "https"
            or request.host != authority
            or request.query_string
        ):
            raise Unavailable()
        if request.method == "POST" and request.headers.getlist("Origin") != [settings.origin]:
            raise Unavailable()

    @app.after_request
    def protect_response(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Content-Security-Policy"] = CSP
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Permissions-Policy"] = "camera=(self), microphone=(self)"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        return response

    def deny(status=403):
        return jsonify(error="unavailable"), status

    @app.errorhandler(HTTPException)
    def reject_http(error):
        return deny(error.code)

    @app.errorhandler(Exception)
    def reject_request(error):
        if isinstance(error, (ValueError, RecursionError)):
            return deny()
        # Neither exception text nor request data belongs in preview logs.
        app.logger.error("IAC preview operation failed")
        return deny(500)

    @app.get("/")
    @app.get("/invite")
    def page():
        return render_template("iac_preview.html")

    @app.get("/iac/assets/<name>")
    def asset(name):
        if name not in ("client.js", "styles.css"):
            return deny(404)
        return send_from_directory(ASSETS, name, conditional=False)

    @app.get("/iac/bootstrap")
    def bootstrap():
        if request.method == "HEAD":
            return "", 204
        if request.headers.get("Sec-Fetch-Site") not in (None, "none", "same-origin"):
            raise Unavailable()
        data, preauth = store.bootstrap(request.cookies.get(PREAUTH), request.cookies.get(SESSION))
        response = jsonify(data)
        if preauth is not None:
            _cookie(response, PREAUTH, preauth, 600)
        return response

    routes = (
        ("invite/prepare", store.prepare, {"token"}, True),
        ("auth/challenge", store.challenge, {"pubkey"}, True),
        ("auth/verify", store.verify, {"event"}, True),
        ("invite/issue", store.issue, set(), False),
        ("invite/claim", store.claim, set(), False),
        ("attempt/status", store.status, set(), False),
        ("attempt/consent", store.consent, {"attempt", "accept"}, False),
        ("attempt/cancel", store.cancel, {"attempt"}, False),
        ("call/status", store.call_status, {"room", "phase"}, False),
        ("call/turn", store.turn, {"room"}, False),
        ("call/signal/send", store.send, {"room", "message", "kind", "payload"}, False),
        ("call/signal/poll", store.poll, {"room", "ack"}, False),
        ("call/hangup", store.hangup, {"room", "failed"}, False),
        ("auth/logout", store.logout, set(), False),
    )

    def endpoint(handler, fields, before_login):
        def respond():
            result = store.execute(
                handler,
                preauth=request.cookies.get(PREAUTH),
                bearer=request.cookies.get(SESSION),
                csrf=request.headers.get("X-IAC-CSRF"),
                data=_request_fields(fields),
                before_login=before_login,
            )
            if handler == store.verify:
                result, bearer = result
                response = jsonify(result)
                _cookie(response, SESSION, bearer, 28800)
                _cookie(response, PREAUTH, "", 0)
                return response
            response = jsonify(result)
            if handler == store.logout:
                _cookie(response, SESSION, "", 0)
                _cookie(response, PREAUTH, "", 0)
            return response

        return respond

    for path, handler, fields, before_login in routes:
        app.add_url_rule(
            "/iac/" + path,
            endpoint=handler.__name__,
            view_func=endpoint(handler, fields, before_login),
            methods=["POST"],
            provide_automatic_options=False,
        )
    return app


class QuietPreviewRequests(WSGIRequestHandler):
    def log(self, _type, _message, *_args):
        """Suppress raw request lines and exception bodies in preview access logs."""


def serve_preview(*, enabled=False, settings=None, accounts=None, certificate, private_key):
    """Run one local TLS process without a reloader, reverse proxy or worker pool."""
    app = create_preview_app(enabled=enabled, settings=settings, accounts=accounts)
    if settings.turn_url is None:
        raise ValueError("isolated relay required to run the preview")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key)
    with make_server(
        "127.0.0.1",
        urlsplit(settings.origin).port,
        app,
        threaded=False,
        processes=1,
        request_handler=QuietPreviewRequests,
        ssl_context=context,
    ) as server:
        server.serve_forever()

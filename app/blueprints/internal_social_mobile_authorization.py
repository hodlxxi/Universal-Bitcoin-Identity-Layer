"""Dormant closed POST routes for the confidential Social backend."""

from flask import Blueprint, current_app, request

from app.services.bearer_credentials import BearerHeaderError, parse_bearer_authorization_header
from app.services.confidential_service_credentials import GRANT_TYPE, MAX_LIFETIME_SECONDS, CredentialDenied
from app.services.social_messaging_mobile_authorization import canonical
from app.services.social_mobile_authorization_ingress import EXTENSION, MobileAuthorizationIngress
from app.services.social_mobile_authorization_ingress_schema import (
    COMMANDS,
    MAX_BODY_BYTES,
    PREFIX,
    TOKEN_PATH,
    VIEWER_HEADER,
    InvalidMobileRequest,
    command_body,
)

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
internal_social_mobile_authorization_bp = Blueprint("internal_social_mobile_authorization", __name__)


def _response(value, status=200):
    response = current_app.response_class(canonical(value), content_type="application/json")
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _error(name="mobile_authorization_unavailable", status=503):
    return _response(dict(error=name), status)


def _runtime():
    value = current_app.extensions.get(EXTENSION)
    return value if type(value) is MobileAuthorizationIngress else None


def _body(content_type):
    if (
        request.content_type != content_type
        or request.query_string
        or request.headers.get("Content-Encoding")
        or request.headers.get("Transfer-Encoding")
        or request.content_length is None
        or not 0 < request.content_length <= MAX_BODY_BYTES
    ):
        raise InvalidMobileRequest()
    raw = request.get_data(cache=True)
    if len(raw) != request.content_length or len(raw) > MAX_BODY_BYTES:
        raise InvalidMobileRequest()
    return raw


@internal_social_mobile_authorization_bp.post(TOKEN_PATH, provide_automatic_options=False)
def issue_mobile_service_token():
    runtime = _runtime()
    if runtime is None:
        return _error("not_found", 404)
    try:
        _body("application/x-www-form-urlencoded")
        required = {"grant_type", "client_id", "client_assertion_type", "client_assertion", "scope"}
        if set(request.form) != required or any(len(request.form.getlist(k)) != 1 for k in required):
            raise InvalidMobileRequest()
        if (
            request.form["grant_type"] != GRANT_TYPE
            or request.form["client_id"] != runtime.service_configs[0].client_id
            or request.form["client_assertion_type"] != ASSERTION_TYPE
        ):
            raise CredentialDenied("credential denied")
        token = runtime.issue(request.form["client_assertion"], request.form["scope"])
        return _response(
            dict(
                access_token=token,
                token_type="Bearer",
                expires_in=MAX_LIFETIME_SECONDS,
                scope=request.form["scope"],
            )
        )
    except InvalidMobileRequest:
        return _error("invalid_request", 400)
    except CredentialDenied:
        return _error("invalid_credential", 401)
    except Exception:
        return _error()


def _command(command):
    runtime = _runtime()
    if runtime is None:
        return _error("not_found", 404)
    try:
        data = command_body(command, _body("application/json"))
        service_token = parse_bearer_authorization_header(request.headers.get("Authorization", ""))
        viewer_token = None
        if COMMANDS[command][0] in {"desktop", "invalidate"}:
            viewer_token = parse_bearer_authorization_header(request.headers.get(VIEWER_HEADER, ""))
        elif VIEWER_HEADER in request.headers:
            raise InvalidMobileRequest()
        return _response(runtime.execute(command, data, service_token=service_token, viewer_token=viewer_token))
    except InvalidMobileRequest:
        return _error("invalid_request", 400)
    except (BearerHeaderError, CredentialDenied):
        return _error("invalid_credential", 401)
    except Exception:
        # Includes viewer, proof, ownership, unavailable composition/storage.
        # Never expose which operation, participant or receipt exists.
        return _error()


def _command_view(command):
    def view():
        return _command(command)

    suffix = command.replace("/", "_").replace("-", "_")
    view.__name__ = f"_command_{suffix}"
    view.__qualname__ = view.__name__
    return view


for _name in COMMANDS:
    internal_social_mobile_authorization_bp.add_url_rule(
        PREFIX + "/" + _name,
        endpoint=_name.replace("/", "_"),
        view_func=_command_view(_name),
        methods=["POST"],
        provide_automatic_options=False,
    )


@internal_social_mobile_authorization_bp.record_once
def _install_error_policy(state):
    @state.app.after_request
    def protect_mobile_responses(response):
        if request.path == PREFIX or request.path.startswith(PREFIX + "/"):
            if response.status_code in {404, 405, 413} or 300 <= response.status_code < 400:
                response = _error("invalid_request", 404 if response.status_code < 400 else response.status_code)
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

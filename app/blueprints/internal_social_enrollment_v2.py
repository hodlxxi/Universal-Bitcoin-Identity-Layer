"""Dormant POST-only confidential ingress; no SQL, environment or key lookup."""

from flask import Blueprint, current_app, request

from app.services.bearer_credentials import BearerHeaderError, parse_bearer_authorization_header
from app.services.confidential_service_credentials import GRANT_TYPE, MAX_LIFETIME_SECONDS, CredentialDenied
from app.services.social_enrollment_v2_ingress import EXTENSION, EnrollmentV2Ingress
from app.services.social_enrollment_v2_ingress_schema import (
    ASSERTION_TYPE,
    COMMANDS,
    MAX_BODY_BYTES,
    PREFIX,
    TOKEN_PATH,
    VIEWER_HEADER,
    InvalidMobileRequest,
    command_body,
    token_form,
)
from app.services.social_messaging_mobile_authorization import canonical

internal_social_enrollment_v2_bp = Blueprint("internal_social_enrollment_v2", __name__)


def _response(value, status=200):
    response = current_app.response_class(canonical(value), status=status, content_type="application/json")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _error(name="social_enrollment_v2_unavailable", status=503):
    return _response(dict(error=name), status)


def _runtime():
    runtime = current_app.extensions.get(EXTENSION)
    return runtime if type(runtime) is EnrollmentV2Ingress else None


def _body(media):
    if (
        request.content_type != media
        or request.query_string
        or "Content-Encoding" in request.headers
        or "Transfer-Encoding" in request.headers
        or request.content_length is None
        or not 0 < request.content_length <= MAX_BODY_BYTES
    ):
        raise InvalidMobileRequest()
    raw = request.get_data(cache=False)
    if len(raw) != request.content_length or len(raw) > MAX_BODY_BYTES:
        raise InvalidMobileRequest()
    return raw


@internal_social_enrollment_v2_bp.post(TOKEN_PATH, provide_automatic_options=False)
def service_token():
    runtime = _runtime()
    if runtime is None:
        return _error("not_found", 404)
    try:
        data = token_form(_body("application/x-www-form-urlencoded"))
        if VIEWER_HEADER in request.headers or "Authorization" in request.headers:
            raise InvalidMobileRequest()
        if (
            data["grant_type"] != GRANT_TYPE
            or data["client_id"] != runtime.challenge.config.backend_id
            or data["client_assertion_type"] != ASSERTION_TYPE
        ):
            raise CredentialDenied("credential denied")
        encoded = runtime.issue(data["client_assertion"], data["scope"])
        return _response(
            dict(access_token=encoded, token_type="Bearer", expires_in=MAX_LIFETIME_SECONDS, scope=data["scope"])
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
        service = parse_bearer_authorization_header(request.headers.get("Authorization", ""))
        viewer = parse_bearer_authorization_header(request.headers.get(VIEWER_HEADER, ""))
        return _response(runtime.execute(command, data, service_token=service, viewer_token=viewer))
    except InvalidMobileRequest:
        return _error("invalid_request", 400)
    except (CredentialDenied, BearerHeaderError):
        return _error("invalid_credential", 401)
    except Exception:
        return _error()


def _view(command):
    def view():
        return _command(command)

    view.__name__ = "_enrollment_" + command
    return view


for _command_name in COMMANDS:
    internal_social_enrollment_v2_bp.add_url_rule(
        PREFIX + "/" + _command_name,
        endpoint=_command_name,
        view_func=_view(_command_name),
        methods=["POST"],
        provide_automatic_options=False,
    )


@internal_social_enrollment_v2_bp.record_once
def _error_policy(state):
    @state.app.after_request
    def protect(response):
        if request.path == PREFIX or request.path.startswith(PREFIX + "/"):
            if response.status_code in {404, 405, 413} or 300 <= response.status_code < 400:
                response = _error("invalid_request", 404 if response.status_code < 400 else response.status_code)
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

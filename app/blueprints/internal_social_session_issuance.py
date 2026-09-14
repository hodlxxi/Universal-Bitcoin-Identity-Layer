"""Confidential POSTs backed by the durable owner; no SQL in HTTP handlers."""

from functools import partial

from flask import Blueprint, current_app, request

from app.blueprints.internal_social_mobile_authorization import ASSERTION_TYPE, _body, _response
from app.services.bearer_credentials import BearerHeaderError, parse_bearer_authorization_header
from app.services.confidential_service_credentials import GRANT_TYPE, MAX_LIFETIME_SECONDS, CredentialDenied
from app.services.social_mobile_authorization_ingress_schema import VIEWER_HEADER, InvalidMobileRequest
from app.services.social_session_issuance_ingress import EXTENSION, SocialSessionIssuanceIngress
from app.services.social_session_issuance_schema import COMMANDS, PREFIX, TOKEN_PATH, command_body

internal_social_session_issuance_bp = Blueprint("internal_social_session_issuance", __name__)


def _error(name="session_issuance_unavailable", status=503):
    return _response(dict(error=name), status)


def _runtime():
    runtime = current_app.extensions.get(EXTENSION)
    return runtime if type(runtime) is SocialSessionIssuanceIngress else None


@internal_social_session_issuance_bp.post(TOKEN_PATH, provide_automatic_options=False)
def service_token():
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
            or request.form["client_id"] != runtime.config.client_id
            or request.form["client_assertion_type"] != ASSERTION_TYPE
            or VIEWER_HEADER in request.headers
        ):
            raise CredentialDenied("credential denied")
        token = runtime.issue_service_token(request.form["client_assertion"], request.form["scope"])
        return _response(
            dict(access_token=token, token_type="Bearer", expires_in=MAX_LIFETIME_SECONDS, scope=request.form["scope"])
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
        viewer = None
        if command in {"resolve", "revoke"}:
            viewer = parse_bearer_authorization_header(request.headers.get(VIEWER_HEADER, ""))
        elif VIEWER_HEADER in request.headers:
            raise InvalidMobileRequest()
        return _response(runtime.execute(command, data, service_token=service, viewer_token=viewer))
    except InvalidMobileRequest:
        return _error("invalid_request", 400)
    except (CredentialDenied, BearerHeaderError):
        return _error("invalid_credential", 401)
    except Exception:
        return _error()


for _name in COMMANDS:
    internal_social_session_issuance_bp.add_url_rule(
        PREFIX + "/" + _name,
        endpoint=_name,
        view_func=partial(_command, _name),
        methods=["POST"],
        provide_automatic_options=False,
    )


@internal_social_session_issuance_bp.record_once
def _error_policy(state):
    @state.app.after_request
    def protect_issuance_responses(response):
        if request.path == PREFIX or request.path.startswith(PREFIX + "/"):
            if response.status_code in {404, 405, 413} or 300 <= response.status_code < 400:
                response = _error("invalid_request", max(404, response.status_code))
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

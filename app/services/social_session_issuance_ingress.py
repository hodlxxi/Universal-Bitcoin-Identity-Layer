"""Explicit confidential composition; never installed by the default factory."""

from dataclasses import dataclass

from app.services.confidential_service_assertion_replay_storage import PostgresConfidentialServiceAssertionReplayStore
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    CredentialDenied,
    issue_service_access_token,
    validate_confidential_service_config,
    verify_service_access_token,
)
from app.services.social_session_issuance import SessionIssuanceUnavailable, SqlAlchemySocialSessionIssuance
from app.services.social_session_issuance_schema import PREFIX, PURPOSE, SCOPE, TOKEN_PATH

EXTENSION = "social_session_issuance_v1"


@dataclass(frozen=True, repr=False)
class SocialSessionIssuanceIngress:
    config: ConfidentialServiceConfig
    service_signing_key: object
    service_signing_kid: str
    service: SqlAlchemySocialSessionIssuance
    replay: PostgresConfidentialServiceAssertionReplayStore

    def __post_init__(self):
        try:
            validate_confidential_service_config(self.config)
            cfg = self.config
            if (
                type(self.service) is not SqlAlchemySocialSessionIssuance
                or type(self.replay) is not PostgresConfidentialServiceAssertionReplayStore
                or self.service._factory is not self.replay._session_factory
                or cfg.issuer != self.service.lifecycle.browser_origin
                or cfg.issuer != self.service.lifecycle._validation.issuer
                or cfg.client_id != self.service.backend_id
                or cfg.service_principal != self.service.service_principal
                or cfg.token_endpoint_audience != cfg.issuer + TOKEN_PATH
                or cfg.service_resource_audience != cfg.issuer + PREFIX
                or cfg.service_scope != SCOPE
                or cfg.service_purpose != PURPOSE
                or type(self.service_signing_kid) is not str
                or not self.service_signing_kid
            ):
                raise ValueError
        except Exception:
            raise SessionIssuanceUnavailable() from None

    def issue_service_token(self, assertion, scope):
        if scope != SCOPE:
            raise CredentialDenied("credential denied")
        return issue_service_access_token(
            assertion,
            config=self.config,
            replay_consumer=self.replay,
            signing_key=self.service_signing_key,
            signing_kid=self.service_signing_kid,
        )

    def execute(self, command, data, *, service_token, viewer_token=None):
        verify_service_access_token(service_token, config=self.config)
        if command == "issue":
            return self.service.issue(data)
        if command == "recover":
            return self.service.recover(data)
        if command == "resolve":
            return self.service.resolve(data["issuanceId"], viewer_token)
        if command == "revoke":
            return self.service.revoke(data["issuanceId"], viewer_token)
        raise SessionIssuanceUnavailable()


def install_session_issuance(app, runtime, *, enabled=False):
    if enabled is False:
        return False
    if enabled is not True or type(runtime) is not SocialSessionIssuanceIngress or EXTENSION in app.extensions:
        raise SessionIssuanceUnavailable()
    from app.blueprints.internal_social_session_issuance import internal_social_session_issuance_bp

    app.register_blueprint(internal_social_session_issuance_bp)
    app.extensions[EXTENSION] = runtime
    return True

"""Opt-in service-authenticated native V2 session bridge; no default installation."""

import time
from dataclasses import dataclass
from types import MappingProxyType

from app.services.confidential_service_assertion_replay_storage import PostgresConfidentialServiceAssertionReplayStore
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    CredentialDenied,
    issue_service_access_token,
    validate_confidential_service_config,
    verify_service_access_token,
)
from app.services.oauth_session_lifecycle import SqlAlchemyOAuthSessionLifecycle
from app.services.social_session_issuance_v2 import NativeV2SessionIssuer
from app.services.social_session_issuance_v2_contract import V2IssuanceUnavailable
from app.services.social_session_issuance_v2_schema import (
    COMMANDS,
    PREFIX,
    PURPOSES,
    SCOPES,
    TOKEN_PATH,
    VIEWER_COMMANDS,
)

EXTENSION = "social_session_issuance_v2_ingress_v1"
RUNTIME_ENABLED = False


@dataclass(frozen=True, repr=False)
class NativeV2SessionIngress:
    service_configs: tuple[ConfidentialServiceConfig, ...]
    service_signing_key: object
    service_signing_kid: str
    owner: NativeV2SessionIssuer
    replay: PostgresConfidentialServiceAssertionReplayStore

    def _binding(self):
        owner = self.owner
        lifecycle = owner.lifecycle
        return (
            owner,
            lifecycle,
            lifecycle._factory,
            lifecycle.client_id,
            owner.backend_id,
            owner.principal,
            lifecycle._validation.issuer,
            lifecycle.browser_origin,
        )

    def __post_init__(self):
        try:
            if (
                type(self.service_configs) is not tuple
                or len(self.service_configs) != len(COMMANDS)
                or type(self.owner) is not NativeV2SessionIssuer
                or type(self.owner.lifecycle) is not SqlAlchemyOAuthSessionLifecycle
                or type(self.replay) is not PostgresConfidentialServiceAssertionReplayStore
                or self.replay._session_factory is not self.owner.lifecycle._factory
                or type(self.service_signing_kid) is not str
                or not self.service_signing_kid
            ):
                raise ValueError
            binding = self._binding()
            if binding[-1] != binding[-2]:
                raise ValueError
            configs = {}
            for supplied in self.service_configs:
                if type(supplied) is not ConfidentialServiceConfig:
                    raise ValueError
                cfg = ConfidentialServiceConfig(
                    **{name: getattr(supplied, name) for name in supplied.__dataclass_fields__}
                )
                validate_confidential_service_config(cfg)
                command = next(name for name in COMMANDS if cfg.service_scope == SCOPES[name])
                if (
                    command in configs
                    or cfg.clock_skew_seconds != 0
                    or (cfg.client_id, cfg.service_principal, cfg.issuer) != binding[4:7]
                    or cfg.token_endpoint_audience != cfg.issuer + TOKEN_PATH
                    or cfg.service_resource_audience != cfg.issuer + PREFIX + "/" + command
                    or cfg.service_purpose != PURPOSES[command]
                ):
                    raise ValueError
                configs[command] = cfg
            object.__setattr__(self, "_configs", MappingProxyType(configs))
            object.__setattr__(self, "_owner_binding", binding)
        except Exception:
            raise V2IssuanceUnavailable() from None

    def _check_owner(self):
        try:
            if self._binding() != self._owner_binding or self.replay._session_factory is not self._owner_binding[2]:
                raise ValueError
        except Exception:
            raise V2IssuanceUnavailable() from None

    def issue(self, assertion, scope):
        self._check_owner()
        command = next((name for name in COMMANDS if SCOPES[name] == scope), None)
        if command is None:
            raise CredentialDenied("credential denied")
        return issue_service_access_token(
            assertion,
            config=self._configs[command],
            replay_consumer=self.replay,
            signing_key=self.service_signing_key,
            signing_kid=self.service_signing_kid,
        )

    def authenticate(self, command, service_token):
        self._check_owner()
        if type(command) is not str or command not in COMMANDS:
            raise CredentialDenied("credential denied")
        at = int(time.time())
        value = verify_service_access_token(service_token, config=self._configs[command], now=at)
        if not value.issued_at <= at < value.expires_at:
            raise CredentialDenied("credential denied")

    def execute(self, command, data, *, service_token, viewer_token):
        self.authenticate(command, service_token)
        if command in VIEWER_COMMANDS:
            if type(viewer_token) is not str or not viewer_token:
                raise CredentialDenied("credential denied")
        elif viewer_token is not None:
            raise CredentialDenied("credential denied")
        if command == "offer":
            result = dict(
                authorizationWire=self.owner.create_offer(data["authorizationWire"], desktop_bearer=viewer_token)
            )
        elif command in {"issue", "recover"}:
            proofs = dict(
                approval_wire=data["approvalWire"],
                secret=data["secret"],
                possession_proof=data["possessionProof"],
                verifier=data["verifier"],
                delivery_key=data["deliveryKey"],
            )
            if command == "issue":
                result = self.owner.issue(data["operationId"], approver_bearer=viewer_token, **proofs)
            else:
                result = self.owner.recover(data["operationId"], **proofs)
        elif command == "resolve":
            result = self.owner.resolve(data["issuanceId"], viewer_bearer=viewer_token)
        else:
            result = self.owner.revoke(data["issuanceId"], viewer_bearer=viewer_token)
        self.authenticate(command, service_token)
        return result


def install_native_v2_session_ingress(app, runtime, *, enabled=False):
    if enabled is False:
        return False
    if enabled is not True or type(runtime) is not NativeV2SessionIngress or EXTENSION in app.extensions:
        raise V2IssuanceUnavailable()
    runtime._check_owner()
    from app.blueprints.internal_social_session_issuance_v2 import internal_social_session_issuance_v2_bp

    app.register_blueprint(internal_social_session_issuance_v2_bp)
    app.extensions[EXTENSION] = runtime
    return True

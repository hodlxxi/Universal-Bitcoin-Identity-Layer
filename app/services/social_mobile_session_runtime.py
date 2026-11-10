"""Trusted, explicit mobile/session composition. No environment or DB fallback."""

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.jwks import load_jwks_document
from app.services import social_session_issuance_schema as issuance
from app.services.confidential_service_assertion_replay_storage import PostgresConfidentialServiceAssertionReplayStore
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    validate_confidential_service_config,
)
from app.services.oauth_session_lifecycle import EXTENSION as LIFECYCLE_EXTENSION, SqlAlchemyOAuthSessionLifecycle
from app.services.social_messaging_mobile_authorization_storage import SqlAlchemyMobileAuthorizationService
from app.services.social_mobile_authorization_ingress import (
    EXTENSION as MOBILE_EXTENSION,
    MobileAuthorizationIngress,
    install_mobile_ingress,
)
from app.services.social_mobile_authorization_ingress_schema import GROUPS, PREFIX, PURPOSES, SCOPES, TOKEN_PATH
from app.services.social_session_issuance import SqlAlchemySocialSessionIssuance
from app.services.social_session_issuance_ingress import (
    EXTENSION as ISSUANCE_EXTENSION,
    SocialSessionIssuanceIngress,
    install_session_issuance,
)

ENABLE_FLAGS = ("SOCIAL_MOBILE_AUTHORIZATION_ENABLED", "SOCIAL_SESSION_ISSUANCE_ENABLED")


class MobileSessionConfigurationError(ValueError):
    def __init__(self):
        super().__init__("mobile session configuration invalid")


def _required(config, name):
    value = config.get(name)
    if type(value) is not str or not value or value.strip() != value:
        raise MobileSessionConfigurationError()
    return value


def _identity(config, name):
    value = _required(config, name)
    if re.fullmatch(r"[A-Za-z0-9._:-]{1,255}", value) is None:
        raise MobileSessionConfigurationError()
    return value


def _fixed(config, name, expected):
    if config.get(name, expected) != expected:
        raise MobileSessionConfigurationError()
    return expected


def _path(config, name, *, directory=False):
    value = _required(config, name)
    if not os.path.isabs(value) or os.path.normpath(value) != value:
        raise MobileSessionConfigurationError()
    if directory:
        info = os.lstat(value)
        if not stat.S_ISDIR(info.st_mode):
            raise MobileSessionConfigurationError()
    return value


def _read_signing_key(path):
    # Exact existing infrastructure file only; never discover or create keys.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or not 0 < info.st_size <= 16384:
            raise MobileSessionConfigurationError()
        material = source.read(16385)
        if len(material) > 16384:
            raise MobileSessionConfigurationError()
        return serialization.load_pem_private_key(material, password=None)


def _public_keys(directory):
    document = load_jwks_document(directory)
    keys = document["keys"]
    kids = set()
    for key in keys:
        kid = key.get("kid")
        if type(kid) is not str or re.fullmatch(r"[A-Za-z0-9._:-]{1,255}", kid) is None or kid in kids:
            raise MobileSessionConfigurationError()
        kids.add(kid)
        public = RSAAlgorithm.from_jwk(key)
        if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 2048:
            raise MobileSessionConfigurationError()
    return tuple(keys)


def _credentials(config, prefix, *, backend, principal, issuer, token_path, resources):
    client_dir = _path(config, prefix + "_CLIENT_JWKS_DIR", directory=True)
    service_dir = _path(config, prefix + "_SERVICE_JWKS_DIR", directory=True)
    if list(Path(client_dir).glob("private_key*.pem")):
        raise MobileSessionConfigurationError()
    client_keys = _public_keys(client_dir)
    service_keys = _public_keys(service_dir)
    configs = tuple(
        ConfidentialServiceConfig(
            enabled=True,
            client_id=backend,
            service_principal=principal,
            issuer=issuer,
            token_endpoint_audience=issuer + token_path,
            service_resource_audience=issuer + resource,
            client_jwks=client_keys,
            service_jwks=service_keys,
            service_scope=scope,
            service_purpose=purpose,
        )
        for resource, scope, purpose in resources
    )
    for cfg in configs:
        validate_confidential_service_config(cfg)
    kid = _required(config, prefix + "_SERVICE_SIGNING_KEY_ID")
    matches = [key for key in service_keys if key["kid"] == kid]
    if len(matches) != 1:
        raise MobileSessionConfigurationError()
    key = _read_signing_key(_path(config, prefix + "_SERVICE_SIGNING_KEY_PATH"))
    if (
        not isinstance(key, rsa.RSAPrivateKey)
        or key.key_size < 2048
        or key.public_key().public_numbers() != RSAAlgorithm.from_jwk(matches[0]).public_numbers()
    ):
        raise MobileSessionConfigurationError()
    return configs, kid, key


@dataclass(frozen=True, repr=False)
class SocialMobileSessionRuntime:
    lifecycle: SqlAlchemyOAuthSessionLifecycle
    mobile: MobileAuthorizationIngress
    issuance: SocialSessionIssuanceIngress


def build_social_mobile_session_runtime(config, *, session_factory=None):
    """Both exact enable flags and all dependencies are required before install."""
    flags = tuple(config.get(name, False) for name in ENABLE_FLAGS)
    if all(value is False for value in flags):
        return None
    try:
        if any(value is not True for value in flags) or not callable(session_factory):
            raise ValueError
        client_id = _identity(config, "SOCIAL_MOBILE_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID")
        backend = _identity(config, "SOCIAL_SESSION_ISSUANCE_BACKEND_ID")
        principal = _identity(config, "SOCIAL_SESSION_ISSUANCE_SERVICE_PRINCIPAL")
        if (
            _required(config, "SOCIAL_SESSION_ISSUANCE_SCOPE") != issuance.SCOPE
            or _required(config, "SOCIAL_SESSION_ISSUANCE_PURPOSE") != issuance.PURPOSE
            or config.get("JWT_ALGORITHM", "RS256") != "RS256"
        ):
            raise ValueError
        issuer = _required(config, "JWT_ISSUER")
        # Copy only the existing token signer's non-secret configuration vocabulary.
        token_config = {name: config[name] for name in ("JWT_ISSUER", "JWT_AUDIENCE", "TOKEN_TTL") if name in config}
        token_config["JWKS_DIR"] = _path(config, "JWKS_DIR", directory=True)
        lifecycle = SqlAlchemyOAuthSessionLifecycle(session_factory, client_id=client_id, token_config=token_config)
        if issuer != lifecycle.browser_origin or issuer != lifecycle._validation.issuer:
            raise ValueError
        _fixed(config, "SOCIAL_SESSION_ISSUANCE_ISSUER", issuer)
        _fixed(config, "SOCIAL_SESSION_ISSUANCE_TOKEN_ENDPOINT_AUDIENCE", issuer + issuance.TOKEN_PATH)
        _fixed(config, "SOCIAL_SESSION_ISSUANCE_RESOURCE_AUDIENCE", issuer + issuance.PREFIX)
        mobile = SqlAlchemyMobileAuthorizationService(session_factory, issuance_client_id=client_id)
        replay = PostgresConfidentialServiceAssertionReplayStore(session_factory)
        service = SqlAlchemySocialSessionIssuance(
            mobile=mobile, lifecycle=lifecycle, backend_id=backend, service_principal=principal
        )
        configs, kid, key = _credentials(
            config,
            "SOCIAL_SESSION_ISSUANCE",
            backend=backend,
            principal=principal,
            issuer=issuer,
            token_path=issuance.TOKEN_PATH,
            resources=((issuance.PREFIX, issuance.SCOPE, issuance.PURPOSE),),
        )
        issuance_ingress = SocialSessionIssuanceIngress(configs[0], key, kid, service, replay)
        configs, kid, key = _credentials(
            config,
            "SOCIAL_MOBILE_AUTHORIZATION",
            backend=_identity(config, "SOCIAL_MOBILE_AUTHORIZATION_BACKEND_ID"),
            principal=_identity(config, "SOCIAL_MOBILE_AUTHORIZATION_SERVICE_PRINCIPAL"),
            issuer=issuer,
            token_path=TOKEN_PATH,
            resources=tuple((PREFIX + "/" + group, SCOPES[group], PURPOSES[group]) for group in GROUPS),
        )
        mobile_ingress = MobileAuthorizationIngress(configs, key, kid, client_id, lifecycle, mobile, replay)
        return SocialMobileSessionRuntime(lifecycle, mobile_ingress, issuance_ingress)
    except Exception:
        raise MobileSessionConfigurationError() from None


def configure_social_mobile_session(app, config, *, session_factory=None):
    """Compose completely before registering either existing dormant ingress."""
    if any(name in app.extensions for name in (LIFECYCLE_EXTENSION, MOBILE_EXTENSION, ISSUANCE_EXTENSION)):
        raise MobileSessionConfigurationError()
    runtime = build_social_mobile_session_runtime(config, session_factory=session_factory)
    if runtime is None:
        return False
    # Preflight both blueprint names before either installer mutates the app.
    from app.blueprints.internal_social_mobile_authorization import internal_social_mobile_authorization_bp
    from app.blueprints.internal_social_session_issuance import internal_social_session_issuance_bp

    if app._got_first_request or any(
        bp.name in app.blueprints
        for bp in (internal_social_mobile_authorization_bp, internal_social_session_issuance_bp)
    ):
        raise MobileSessionConfigurationError()
    install_mobile_ingress(app, runtime.mobile, enabled=True)
    install_session_issuance(app, runtime.issuance, enabled=True)
    app.extensions[LIFECYCLE_EXTENSION] = runtime.lifecycle
    return True

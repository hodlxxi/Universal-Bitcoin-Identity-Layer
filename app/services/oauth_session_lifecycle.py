"""Opt-in canonical OAuth generation owner. No default factory or routes.

The registered application extension is a trusted composition input, never
request data. All commands use PostgreSQL and commit before returning. No
Redis, cached principal, or browser-selected session identity is consulted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import jwt
from sqlalchemy import select, text, update

from app.auth_api_core import canonical_xonly_pubkey
from app.jwks import get_key_by_kid
from app.models import (
    OAuthBrowserGeneration,
    OAuthClient,
    OAuthCode,
    OAuthSessionCodeBinding,
    OAuthSessionGeneration,
    OAuthToken,
    Session,
    User,
)
from app.services.bearer_credentials import DEFAULT_MAX_BEARER_LENGTH, has_compact_jwt_shape
from app.services.oauth_bearer_validation import (
    TOKEN_CONTRACT,
    BearerValidationConfig,
    validate_canonical_access_token_with_config,
)
from app.services.oauth_scope_policy import (
    RESERVED_SCOPES,
    SCOPE_POLICY_VERSION,
    client_allowed_scopes,
    parse_scopes,
    serialize_scopes,
    validate_client_scopes,
)
from app.tokens import _resolve_ttl, issue_rs256_jwt

EXTENSION = "oauth_session_lifecycle_v1"
_TRIGGERS = (
    ("oauth_browser_generations", "trg_oauth_browser_generation_guard"),
    ("oauth_session_generations", "trg_oauth_generation_guard"),
    ("oauth_session_code_bindings", "trg_oauth_code_binding_guard"),
    ("oauth_codes", "trg_oauth_bound_code_guard"),
    ("sessions", "trg_oauth_mapped_session_guard"),
    ("oauth_tokens", "trg_oauth_token_session_invalidation"),
    ("users", "trg_oauth_user_session_invalidation"),
    ("oauth_clients", "trg_oauth_client_session_invalidation"),
)


class OAuthSessionUnavailable(ValueError):
    def __init__(self):
        super().__init__("OAuth session lifecycle unavailable")


@dataclass(frozen=True, slots=True, repr=False)
class OAuthSessionAuthority:
    """Internal identity only; never serialize into an OAuth/browser response."""

    session_id: str
    subject: str


def _subject(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise OAuthSessionUnavailable()
    if canonical_xonly_pubkey(value) != value:
        raise OAuthSessionUnavailable()
    return value


def _utc(value):
    if type(value) is not datetime:
        raise OAuthSessionUnavailable()
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class SqlAlchemyOAuthSessionLifecycle:
    """One current generation per exact user/client; each exchange replaces it.

    token_config supplies existing RS256 issuer/key configuration. It grants no
    client eligibility by itself: the active persisted client is reread. Only
    this exact client opts in; existing unmapped credentials cannot be adopted.
    """

    def __init__(self, session_factory, *, client_id, token_config, clock=None, browser_ttl_seconds=3600):
        if (
            not callable(session_factory)
            or type(client_id) is not str
            or not 1 <= len(client_id) <= 255
            or client_id.strip() != client_id
            or type(token_config) is not dict
            or clock is not None
            and not callable(clock)
        ):
            raise OAuthSessionUnavailable()
        if type(browser_ttl_seconds) is not int or not 1 <= browser_ttl_seconds <= 86400:
            raise OAuthSessionUnavailable()
        self._browser_ttl = browser_ttl_seconds
        origin = urlsplit(str(token_config.get("JWT_ISSUER") or ""))
        if (
            origin.scheme != "https"
            or not origin.hostname
            or origin.username
            or origin.password
            or origin.query
            or origin.fragment
            or origin.netloc != origin.netloc.lower()
        ):
            raise OAuthSessionUnavailable()
        self.browser_origin = origin.scheme + "://" + origin.netloc
        self.client_id = client_id
        self._factory = session_factory
        self._config = dict(token_config)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._validation = BearerValidationConfig(
            issuer=str(token_config.get("JWT_ISSUER") or ""),
            jwks_dir=str(token_config.get("JWKS_DIR") or ""),
            leeway_seconds=0,
        )
        if not self._validation.issuer or not self._validation.jwks_dir:
            raise OAuthSessionUnavailable()

    def _now(self):
        now = self._clock()
        if type(now) is not datetime or now.tzinfo is None:
            raise OAuthSessionUnavailable()
        return now.astimezone(timezone.utc)

    def _run(self, command):
        try:
            with self._factory() as db:
                with db.begin():
                    if db.get_bind().dialect.name != "postgresql":
                        raise OAuthSessionUnavailable()
                    if db.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed":
                        raise OAuthSessionUnavailable()
                    pairs = ",".join(f"(to_regclass('{table}'), '{name}')" for table, name in _TRIGGERS)
                    count = db.execute(
                        text(
                            "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O' "
                            "AND (tgrelid, tgname) IN (" + pairs + ")"
                        )
                    ).scalar_one()
                    if count != len(_TRIGGERS):
                        raise OAuthSessionUnavailable()
                    result = command(db)
                    db.flush()
                return result
        except Exception:
            raise OAuthSessionUnavailable() from None

    def _owner(self, db, user_id):
        # Same User-before-Session order as the unchanged mobile _auth. Client
        # and token lifecycle triggers invalidate Sessions in their own commit.
        user = db.get(User, user_id, with_for_update=True, populate_existing=True)
        client = db.get(OAuthClient, self.client_id, with_for_update=True, populate_existing=True)
        if user is None or client is None or user.is_active is not True or client.is_active is not True:
            raise OAuthSessionUnavailable()
        _subject(user.pubkey)
        return user, client

    def _close_owner(self, db, user_id):
        # The token update's migration trigger deactivates its exact Session.
        db.execute(
            update(OAuthToken)
            .where(
                OAuthToken.id.in_(
                    select(OAuthSessionGeneration.token_id).where(
                        OAuthSessionGeneration.user_id == user_id,
                        OAuthSessionGeneration.client_id == self.client_id,
                    )
                )
            )
            .values(is_revoked=True)
        )
        db.execute(
            update(OAuthCode)
            .where(
                OAuthCode.user_id == user_id,
                OAuthCode.client_id == self.client_id,
                OAuthCode.code.in_(select(OAuthSessionCodeBinding.code)),
            )
            .values(is_used=True)
        )

    def _browser(self, db, generation_id, user, *, active=True):
        if type(generation_id) is not str or re.fullmatch(r"[0-9a-f]{64}", generation_id) is None:
            raise OAuthSessionUnavailable()
        browser = db.get(OAuthBrowserGeneration, generation_id, with_for_update=True, populate_existing=True)
        if (
            browser is None
            or browser.user_id != user.id
            or browser.client_id != self.client_id
            or browser.subject != user.pubkey
        ):
            raise OAuthSessionUnavailable()
        if active and (
            browser.is_active is not True or not _utc(browser.created_at) <= self._now() < _utc(browser.expires_at)
        ):
            raise OAuthSessionUnavailable()
        return browser

    def _browser_owner(self, db, generation_id):
        browser = db.get(OAuthBrowserGeneration, generation_id)
        if browser is None or browser.client_id != self.client_id:
            raise OAuthSessionUnavailable()
        user, client = self._owner(db, browser.user_id)
        return user, client

    def complete_verified_login(
        self,
        *,
        subject: str,
        challenge: str,
        challenge_created: datetime,
        challenge_expires: datetime,
        previous_generation: str | None = None,
    ) -> str:
        """Only the just-successful signature-verification branch may call this.

        The server challenge is read from admitted authentication state, never
        inferred from an old authenticated subject. Its retained digest is a
        global consume-once fence across clients, subjects and login methods.
        """
        _subject(subject)
        if type(challenge) is not str or not 1 <= len(challenge) <= 4096:
            raise OAuthSessionUnavailable()
        proof_id = hashlib.sha256(("HODLXXI_BROWSER_LOGIN_PROOF_V1\0" + challenge).encode()).hexdigest()

        def command(db):
            user_id = db.execute(select(User.id).where(User.pubkey == subject)).scalar_one()
            previous = None if previous_generation is None else db.get(OAuthBrowserGeneration, previous_generation)
            if previous_generation is not None and (previous is None or previous.client_id != self.client_id):
                raise OAuthSessionUnavailable()
            # Cross-subject replacement locks all Users in a deterministic order,
            # then the exact client, browser generation(s), tokens and Sessions.
            owners = {user_id} | ({previous.user_id} if previous is not None else set())
            for owner in sorted(owners):
                db.get(User, owner, with_for_update=True, populate_existing=True)
            user, _client = self._owner(db, user_id)
            now = self._now()
            if user.pubkey != subject or not _utc(challenge_created) <= now < _utc(challenge_expires):
                raise OAuthSessionUnavailable()
            if (
                db.execute(
                    select(OAuthBrowserGeneration.generation_id).where(OAuthBrowserGeneration.proof_id == proof_id)
                ).first()
                is not None
            ):
                raise OAuthSessionUnavailable()
            if previous is not None:
                db.execute(
                    update(OAuthBrowserGeneration)
                    .where(OAuthBrowserGeneration.generation_id == previous.generation_id)
                    .values(is_active=False)
                )
            db.execute(
                update(OAuthBrowserGeneration)
                .where(OAuthBrowserGeneration.user_id == user_id, OAuthBrowserGeneration.client_id == self.client_id)
                .values(is_active=False)
            )
            self._close_owner(db, user_id)
            generation_id = secrets.token_hex(32)
            db.add(
                OAuthBrowserGeneration(
                    generation_id=generation_id,
                    user_id=user_id,
                    client_id=self.client_id,
                    subject=subject,
                    proof_id=proof_id,
                    created_at=now.replace(tzinfo=None),
                    expires_at=(now + timedelta(seconds=self._browser_ttl)).replace(tzinfo=None),
                    is_active=True,
                )
            )
            db.flush()
            if not _utc(challenge_created) <= self._now() < _utc(challenge_expires):
                raise OAuthSessionUnavailable()
            return generation_id

        return self._run(command)

    def browser_subject(self, generation_id: str) -> str:
        """Resolve only an authenticated server-session reference, without renewal."""

        def command(db):
            user, _client = self._browser_owner(db, generation_id)
            return self._browser(db, generation_id, user).subject

        return self._run(command)

    def invalidate_browser(self, generation_id: str) -> None:
        """Exact generation only; an equal old retry never closes its replacement."""

        def command(db):
            browser = db.get(OAuthBrowserGeneration, generation_id)
            if browser is None or browser.client_id != self.client_id:
                raise OAuthSessionUnavailable()
            # Unlike admission, revocation remains possible for inactive owners.
            db.get(User, browser.user_id, with_for_update=True, populate_existing=True)
            db.get(OAuthClient, self.client_id, with_for_update=True, populate_existing=True)
            db.execute(
                update(OAuthBrowserGeneration)
                .where(OAuthBrowserGeneration.generation_id == generation_id)
                .values(is_active=False)
            )

        return self._run(command)

    def authorize(self, *, subject, browser_generation, redirect_uri, scope, code_challenge):
        """Called only after existing verified-browser admission; no JSON identity."""
        _subject(subject)

        def command(db):
            user_id = db.execute(select(User.id).where(User.pubkey == subject)).scalar_one()
            user, client = self._owner(db, user_id)
            browser = self._browser(db, browser_generation, user)
            if user.pubkey != subject or redirect_uri not in client.redirect_uris:
                raise OAuthSessionUnavailable()
            scopes = parse_scopes(scope)
            validate_client_scopes(
                scopes,
                client_allowed_scopes(
                    {
                        "scope": client.scope,
                        "metadata": client.metadata_json,
                    }
                ),
            )
            if "openid" not in scopes or re.fullmatch(r"[A-Za-z0-9_-]{43}", code_challenge) is None:
                raise OAuthSessionUnavailable()
            now = self._now().replace(tzinfo=None)
            code = secrets.token_urlsafe(32)
            db.add(
                OAuthCode(
                    code=code,
                    user_id=user.id,
                    client_id=client.client_id,
                    redirect_uri=redirect_uri,
                    scope=serialize_scopes(scopes),
                    code_challenge=code_challenge,
                    code_challenge_method="S256",
                    created_at=now,
                    expires_at=min(now + timedelta(minutes=10), browser.expires_at),
                    is_used=False,
                )
            )
            db.flush()
            db.add(OAuthSessionCodeBinding(code=code, subject=subject, browser_generation_id=browser.generation_id))
            db.flush()
            self._browser(db, browser_generation, user)
            return code

        return self._run(command)

    def exchange(self, *, code, redirect_uri, code_verifier):
        """After confidential OAuth client authentication, atomically issue both records.

        Token strings exist only in this transient response and the existing
        signer. The Session and relation contain no bearer or signing material.
        """

        def command(db):
            if type(code) is not str or not 1 <= len(code) <= 255:
                raise OAuthSessionUnavailable()
            pending = db.get(OAuthCode, code)
            if pending is None or pending.client_id != self.client_id:
                raise OAuthSessionUnavailable()
            user, client = self._owner(db, pending.user_id)
            pending = db.get(OAuthCode, code, with_for_update=True, populate_existing=True)
            bound = db.get(OAuthSessionCodeBinding, code)
            if bound is None:
                raise OAuthSessionUnavailable()
            browser = self._browser(db, bound.browser_generation_id, user)
            now = self._now()
            if (
                bound is None
                or bound.subject != user.pubkey
                or pending.user_id != user.id
                or pending.client_id != client.client_id
                or pending.is_used is not False
                or not _utc(pending.created_at) <= now < _utc(pending.expires_at)
                or redirect_uri != pending.redirect_uri
                or redirect_uri not in client.redirect_uris
                or pending.code_challenge_method != "S256"
                or type(code_verifier) is not str
                or re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", code_verifier) is None
            ):
                raise OAuthSessionUnavailable()
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode()
            )
            if not hmac.compare_digest(challenge, pending.code_challenge):
                raise OAuthSessionUnavailable()
            scopes = parse_scopes(pending.scope)
            validate_client_scopes(
                scopes, client_allowed_scopes({"scope": client.scope, "metadata": client.metadata_json})
            )
            if "openid" not in scopes:
                raise OAuthSessionUnavailable()
            ttl = _resolve_ttl(self._config)
            if type(ttl) is not int or not 1 <= ttl <= 86400:
                raise OAuthSessionUnavailable()
            scope = serialize_scopes(scopes)
            jti = secrets.token_hex(16)
            dates = {
                "iat": int(now.timestamp()),
                "exp": min(int(now.timestamp()) + ttl, int(_utc(browser.expires_at).timestamp())),
            }
            token = issue_rs256_jwt(
                user.pubkey,
                {
                    **dates,
                    "aud": self.client_id,
                    "jti": jti,
                    "scope": scope,
                    "token_use": "access",
                    "token_contract": TOKEN_CONTRACT,
                },
                cfg=self._config,
            )
            id_token = issue_rs256_jwt(user.pubkey, {**dates, "aud": self.client_id, "scope": scope}, cfg=self._config)
            header = jwt.get_unverified_header(token)
            expires = datetime.fromtimestamp(dates["exp"], timezone.utc).replace(tzinfo=None)
            created = now.replace(tzinfo=None)  # Never round creation earlier.
            if not created < expires:
                raise OAuthSessionUnavailable()
            self._close_owner(db, user.id)  # Also consumes every older outstanding code.
            db.add(
                OAuthToken(
                    id=jti,
                    access_token=hashlib.sha256(token.encode("ascii")).hexdigest(),
                    token_type="Bearer",
                    client_id=self.client_id,
                    user_id=user.id,
                    scope=scope,
                    created_at=created,
                    access_token_expires_at=expires,
                    is_revoked=False,
                    metadata_json={
                        "token_contract": TOKEN_CONTRACT,
                        "token_use": "access",
                        "issuer": self._validation.issuer.rstrip("/"),
                        "audience": self.client_id,
                        "kid": header["kid"],
                        "digest_algorithm": "sha256",
                        "scope_policy_version": SCOPE_POLICY_VERSION,
                    },
                )
            )
            session_id = secrets.token_hex(32)
            db.add(
                Session(
                    session_id=session_id,
                    user_id=user.id,
                    session_type="web",
                    created_at=created,
                    expires_at=expires,
                    is_active=True,
                )
            )
            db.flush()
            db.add(
                OAuthSessionGeneration(
                    token_id=jti,
                    browser_generation_id=browser.generation_id,
                    session_id=session_id,
                    user_id=user.id,
                    client_id=self.client_id,
                    subject=user.pubkey,
                )
            )
            # Flush the mapping too before the final fence/expiry checks; no
            # deferred relationship write may move admission past those checks.
            db.flush()
            # Validate the actual signed output against its just-persisted record.
            # A signer/configuration failure rolls back code, replacement and issuance.
            self._validate(db, token)
            self._browser(db, browser.generation_id, user)
            if self._now() >= _utc(expires):
                raise OAuthSessionUnavailable()
            return {
                "access_token": token,
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": dates["exp"] - dates["iat"],
                "scope": scope,
            }

        return self._run(command)

    def _validate(self, db, bearer):
        def record(jti):
            token = db.get(OAuthToken, jti, populate_existing=True)
            if token is None:
                return None
            user = db.get(User, token.user_id, populate_existing=True)
            return {
                "jti": token.id,
                "digest": token.access_token,
                "client_id": token.client_id,
                "user_id": token.user_id,
                "scope": token.scope,
                "expires_at": token.access_token_expires_at,
                "is_revoked": token.is_revoked,
                "metadata": token.metadata_json,
                "user": None if user is None else {"id": user.id, "pubkey": user.pubkey, "is_active": user.is_active},
            }

        return validate_canonical_access_token_with_config(
            bearer,
            config=self._validation,
            expected_client_id=self.client_id,
            record_loader=record,
        )

    def resolve(self, viewer_bearer: str) -> OAuthSessionAuthority:
        """Verify the existing canonical bearer and reread exact durable authority."""

        def command(db):
            viewer = self._validate(db, viewer_bearer)
            user, _client = self._owner(db, viewer.user_id)
            generation = db.get(OAuthSessionGeneration, viewer.jti)
            if generation is None or generation.client_id != self.client_id or generation.user_id != user.id:
                raise OAuthSessionUnavailable()
            self._browser(db, generation.browser_generation_id, user)
            auth = db.get(Session, generation.session_id, with_for_update=True, populate_existing=True)
            # Revalidate after acquiring locks; a principal cached before revoke is insufficient.
            viewer = self._validate(db, viewer_bearer)
            token = db.get(OAuthToken, viewer.jti)
            now = self._now()
            if (
                auth is None
                or auth.is_active is not True
                or auth.session_type != "web"
                or auth.user_id != user.id
                or generation.subject != user.pubkey
                or viewer.subject != user.pubkey
                or auth.created_at != token.created_at
                or auth.expires_at > token.access_token_expires_at
                or not _utc(auth.created_at) <= now < _utc(auth.expires_at)
                or not _utc(viewer.issued_at) <= now < _utc(viewer.expires_at)
                or "openid" not in viewer.scopes
            ):
                raise OAuthSessionUnavailable()
            return OAuthSessionAuthority(auth.session_id, user.pubkey)

        return self._run(command)

    def invalidate(self, viewer_bearer: str) -> None:
        """Invalidate this currently valid viewer's exact generation.

        Equal retry after revocation uses invalidate_generation with the trusted
        issuer's recorded token/user identity. It cannot revoke a replacement.
        """

        def command(db):
            viewer = self._validate(db, viewer_bearer)
            self._invalidate_token(db, viewer.jti, viewer.user_id)

        return self._run(command)

    def invalidate_original(self, viewer_bearer: str) -> None:
        """Revoke only this exact signed, durably recorded original generation.

        Expiry/revocation are deliberately tolerated ONLY by this command. It
        returns no identity or authentication evidence. The immutable generation
        supplies the original subject even after User deactivation/key change.
        Unknown signing keys fail closed, including after key retirement.
        """

        def command(db):
            if (
                type(viewer_bearer) is not str
                or len(viewer_bearer) > DEFAULT_MAX_BEARER_LENGTH
                or not has_compact_jwt_shape(viewer_bearer)
            ):
                raise OAuthSessionUnavailable()
            digest = hashlib.sha256(viewer_bearer.encode("ascii")).hexdigest()
            # The exact stored digest selects the record; unverified JWT claims
            # cannot select a User, Session or a generation to invalidate.
            token = db.execute(select(OAuthToken).where(OAuthToken.access_token == digest)).scalar_one_or_none()
            if token is None or token.client_id != self.client_id:
                raise OAuthSessionUnavailable()
            generation = db.get(OAuthSessionGeneration, token.id)
            if generation is None or generation.client_id != self.client_id or generation.user_id != token.user_id:
                raise OAuthSessionUnavailable()
            header = jwt.get_unverified_header(viewer_bearer)
            kid = header.get("kid")
            if header.get("alg") != "RS256" or type(kid) is not str or not 1 <= len(kid) <= 255:
                raise OAuthSessionUnavailable()
            key = get_key_by_kid(self._validation.jwks_dir, kid)
            if key is None:
                raise OAuthSessionUnavailable()
            issuer = self._validation.issuer.rstrip("/")
            claims = jwt.decode(
                viewer_bearer,
                key.public_key(),
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=issuer,
                leeway=0,
                options={
                    "require": ["iss", "aud", "sub", "iat", "exp", "jti", "scope", "token_use", "token_contract"],
                    "verify_exp": False,
                    "verify_iat": True,
                },
            )
            scopes = parse_scopes(claims.get("scope"))
            metadata = dict(
                token_contract=TOKEN_CONTRACT,
                token_use="access",
                issuer=issuer,
                audience=self.client_id,
                kid=kid,
                digest_algorithm="sha256",
                scope_policy_version=SCOPE_POLICY_VERSION,
            )
            if (
                claims.get("aud") != self.client_id
                or claims.get("sub") != _subject(generation.subject)
                or claims.get("jti") != token.id
                or claims.get("token_use") != "access"
                or claims.get("token_contract") != TOKEN_CONTRACT
                or claims.get("scope") != serialize_scopes(scopes)
                or token.scope != claims["scope"]
                or "openid" not in scopes
                or scopes & RESERVED_SCOPES
                or token.metadata_json != metadata
                or type(claims["iat"]) is not int
                or type(claims["exp"]) is not int
                or not 0 < claims["exp"] - claims["iat"] <= 86400
                or int(_utc(token.created_at).timestamp()) != claims["iat"]
                or _utc(token.access_token_expires_at).timestamp() > claims["exp"]
                or _utc(token.created_at) > self._now()
            ):
                raise OAuthSessionUnavailable()
            self._invalidate_token(db, token.id, token.user_id)

        return self._run(command)

    def _invalidate_token(self, db, token_id, user_id):
        generation = db.get(OAuthSessionGeneration, token_id)
        if generation is None or generation.user_id != user_id or generation.client_id != self.client_id:
            raise OAuthSessionUnavailable()
        db.execute(update(OAuthToken).where(OAuthToken.id == token_id).values(is_revoked=True))

    def invalidate_generation(self, *, token_id: str, user_id: str) -> None:
        """Trusted server-only recorded OAuth identity; idempotent, no new authority.

        Later ingress must derive BOTH values from its authenticated issuer work
        item. Neither value may be accepted from browser JSON or query parameters.
        """
        return self._run(lambda db: self._invalidate_token(db, token_id, user_id))

    def invalidate_subject(self, subject):
        """Trusted UBID browser logout/replacement; all generations for this client."""
        _subject(subject)

        def command(db):
            user = db.execute(select(User).where(User.pubkey == subject).with_for_update()).scalar_one_or_none()
            if user is not None:
                db.get(OAuthClient, self.client_id, with_for_update=True, populate_existing=True)
                db.execute(
                    update(OAuthBrowserGeneration)
                    .where(
                        OAuthBrowserGeneration.user_id == user.id, OAuthBrowserGeneration.client_id == self.client_id
                    )
                    .values(is_active=False)
                )
                self._close_owner(db, user.id)

        return self._run(command)


def configured_lifecycle(app):
    """Absent by default; no factory/environment activation in this change."""
    value = app.extensions.get(EXTENSION)
    if value is not None and type(value) is not SqlAlchemyOAuthSessionLifecycle:
        raise OAuthSessionUnavailable()
    return value

import importlib
import inspect
import json
import sys

import pytest

from app.services.action_authorization import (
    ACTION_REQUIREMENTS,
    POLICY_VERSION,
    ActionName,
    ActionRequest,
    EntitlementSnapshot,
    IdentityClass,
    ReasonCode,
    authorize_action,
)

ACTOR = "11" * 32
OTHER_ACTOR = "22" * 32
COMPRESSED_ACTOR = "02" + ACTOR


class Resolver:
    def __init__(self, identity=IdentityClass.LIMITED, relation=False, actor=ACTOR):
        self.identity = identity
        self.relation = relation
        self.actor = actor
        self.calls = 0

    def resolve(self, actor_pubkey):
        self.calls += 1
        return EntitlementSnapshot(
            actor_pubkey=self.actor,
            identity_class=self.identity,
            current_full_relation_satisfied=self.relation,
            evidence_source="unit-test:v1",
        )


def request(action, scope, **kwargs):
    return ActionRequest(
        actor_pubkey=kwargs.pop("actor_pubkey", ACTOR),
        action=action,
        granted_scopes=frozenset({scope}) if scope else frozenset(),
        **kwargs,
    )


def test_module_imports_without_flask_context():
    module = importlib.import_module("app.services.action_authorization")
    assert module.POLICY_VERSION == "hodlxxi.action-policy.v1"


def test_missing_and_malformed_actor_fail_closed():
    resolver = Resolver()
    missing = authorize_action(request(ActionName.SELF_READ, "self:read", actor_pubkey=None), resolver)
    malformed = authorize_action(request(ActionName.SELF_READ, "self:read", actor_pubkey="guest_123"), resolver)
    assert missing.reason_code is ReasonCode.MISSING_ACTOR
    assert malformed.reason_code is ReasonCode.INVALID_ACTOR
    assert not missing.allowed and not malformed.allowed


def test_anonymous_actor_denied():
    decision = authorize_action(request(ActionName.SELF_READ, "self:read"), Resolver(IdentityClass.ANONYMOUS))
    assert decision.reason_code is ReasonCode.ANONYMOUS_DENIED


@pytest.mark.parametrize("action", list(ActionName))
def test_guest_denied_for_every_action(action):
    requirement = ACTION_REQUIREMENTS[action]
    decision = authorize_action(request(action, requirement.required_scope), Resolver(IdentityClass.GUEST))
    assert decision.reason_code is ReasonCode.GUEST_DENIED


def test_limited_allowed_for_exact_action_and_scope():
    decision = authorize_action(request(ActionName.SELF_READ, "self:read"), Resolver())
    assert decision.allowed
    assert decision.reason_code is ReasonCode.ALLOWED


@pytest.mark.parametrize(
    "action,scope",
    [
        (ActionName.COVENANT_DRAFT_CREATE, "covenant:draft:create"),
        (ActionName.COVENANT_DRAFT_READ_SELF, "covenant:draft:read:self"),
    ],
)
def test_limited_denied_for_covenant_actions(action, scope):
    decision = authorize_action(request(action, scope, step_up_verified=True, resource_owner_pubkey=ACTOR), Resolver())
    assert decision.reason_code is ReasonCode.INSUFFICIENT_IDENTITY


def test_full_action_requires_current_satisfied_relation():
    denied = authorize_action(
        request(ActionName.COVENANT_DRAFT_CREATE, "covenant:draft:create", step_up_verified=True),
        Resolver(IdentityClass.FULL, relation=False),
    )
    allowed = authorize_action(
        request(ActionName.COVENANT_DRAFT_CREATE, "covenant:draft:create", step_up_verified=True),
        Resolver(IdentityClass.FULL, relation=True),
    )
    assert denied.reason_code is ReasonCode.CURRENT_FULL_RELATION_REQUIRED
    assert allowed.allowed


@pytest.mark.parametrize(
    "relation",
    [False, None, 0, 1, "true", "false", "", [], [True], {}, {"value": True}, object()],
)
def test_full_relation_requires_actual_bool_true(relation):
    decision = authorize_action(
        request(ActionName.COVENANT_DRAFT_CREATE, "covenant:draft:create", step_up_verified=True),
        Resolver(IdentityClass.FULL, relation=relation),
    )
    assert decision.reason_code is ReasonCode.CURRENT_FULL_RELATION_REQUIRED


def test_actual_bool_true_satisfies_full_relation_requirement():
    decision = authorize_action(
        request(ActionName.COVENANT_DRAFT_CREATE, "covenant:draft:create", step_up_verified=True),
        Resolver(IdentityClass.FULL, relation=True),
    )
    assert decision.allowed


def test_stale_previous_full_state_cannot_override_current_limited_result():
    req = request(ActionName.COVENANT_DRAFT_CREATE, "covenant:draft:create", step_up_verified=True)
    first = authorize_action(req, Resolver(IdentityClass.FULL, relation=True))
    second = authorize_action(req, Resolver(IdentityClass.LIMITED, relation=False))
    assert first.allowed
    assert second.reason_code is ReasonCode.INSUFFICIENT_IDENTITY


def test_resolver_is_called_for_every_decision():
    resolver = Resolver()
    req = request(ActionName.SELF_READ, "self:read")
    authorize_action(req, resolver)
    authorize_action(req, resolver)
    assert resolver.calls == 2


def test_resolver_unavailable_and_exception_fail_closed_without_leak():
    class BrokenResolver:
        def resolve(self, actor_pubkey):
            raise RuntimeError("secret resolver detail")

    req = request(ActionName.SELF_READ, "self:read")
    unavailable = authorize_action(req, None)
    broken = authorize_action(req, BrokenResolver())
    assert unavailable.reason_code is ReasonCode.ENTITLEMENT_UNAVAILABLE
    assert broken.reason_code is ReasonCode.ENTITLEMENT_UNAVAILABLE
    assert "secret" not in json.dumps(broken.to_dict())


def test_entitlement_actor_mismatch_denied():
    decision = authorize_action(request(ActionName.SELF_READ, "self:read"), Resolver(actor=OTHER_ACTOR))
    assert decision.reason_code is ReasonCode.ENTITLEMENT_ACTOR_MISMATCH


def test_missing_exact_scope_and_broad_scope_are_denied():
    missing = authorize_action(request(ActionName.JOB_CREATE, None), Resolver())
    broad = authorize_action(request(ActionName.JOB_CREATE, "write"), Resolver())
    assert missing.reason_code is ReasonCode.MISSING_SCOPE
    assert broad.reason_code is ReasonCode.MISSING_SCOPE


@pytest.mark.parametrize(
    "scopes",
    [
        "job:create",
        b"job:create",
        bytearray(b"job:create"),
        {"job:create": True},
        ["job:create", 1],
        ["job:create", ""],
        ["job:create", "   "],
    ],
)
def test_malformed_scope_collections_fail_closed(scopes):
    req = ActionRequest(actor_pubkey=ACTOR, action=ActionName.JOB_CREATE, granted_scopes=scopes)
    decision = authorize_action(req, Resolver())
    assert decision.reason_code is ReasonCode.INVALID_SCOPE_SET


def test_scope_iterable_that_raises_fails_closed():
    class BrokenIterable:
        def __iter__(self):
            raise RuntimeError("scope iteration secret")

    req = ActionRequest(
        actor_pubkey=ACTOR,
        action=ActionName.JOB_CREATE,
        granted_scopes=BrokenIterable(),
    )
    decision = authorize_action(req, Resolver())
    assert decision.reason_code is ReasonCode.INVALID_SCOPE_SET
    assert "secret" not in json.dumps(decision.to_dict())


@pytest.mark.parametrize("scopes", [frozenset(), set(), tuple(), list(), None])
def test_empty_or_none_scope_collection_is_missing_scope(scopes):
    req = ActionRequest(actor_pubkey=ACTOR, action=ActionName.JOB_CREATE, granted_scopes=scopes)
    decision = authorize_action(req, Resolver())
    assert decision.reason_code is ReasonCode.MISSING_SCOPE


@pytest.mark.parametrize(
    "scopes",
    [
        frozenset({"job:create"}),
        {"job:create"},
        ("job:create",),
        ["job:create"],
        ["unrelated:scope", "job:create"],
    ],
)
def test_valid_scope_collection_forms_preserve_exact_matching(scopes):
    req = ActionRequest(actor_pubkey=ACTOR, action=ActionName.JOB_CREATE, granted_scopes=scopes)
    assert authorize_action(req, Resolver()).allowed


def test_unknown_action_denied():
    decision = authorize_action(request("wallet_sweep", "write"), Resolver())
    assert decision.reason_code is ReasonCode.UNKNOWN_ACTION


@pytest.mark.parametrize(
    "raw_action",
    [
        "bearer-token-like-secret",
        "client-secret-like-value",
        "unknown\ncontrol\x00characters",
        "x" * 100_000,
    ],
)
def test_unknown_action_is_not_reflected_in_audit_decision(raw_action):
    decision = authorize_action(request(raw_action, "write"), Resolver())
    serialized = json.dumps(decision.to_dict())
    assert decision.reason_code is ReasonCode.UNKNOWN_ACTION
    assert decision.action == "unknown"
    assert decision.to_dict()["action"] == "unknown"
    assert raw_action not in serialized


@pytest.mark.parametrize("action", list(ActionName))
def test_known_actions_serialize_to_exact_canonical_names(action):
    requirement = ACTION_REQUIREMENTS[action]
    kwargs = {}
    resolver = Resolver()
    if requirement.ownership_required:
        kwargs["resource_owner_pubkey"] = ACTOR
    if requirement.step_up_required:
        kwargs["step_up_verified"] = True
    if requirement.current_full_relation_required:
        resolver = Resolver(IdentityClass.FULL, relation=True)
    decision = authorize_action(request(action, requirement.required_scope, **kwargs), resolver)
    assert decision.action == action.value
    assert decision.to_dict()["action"] == action.value


def test_self_owned_reads_require_matching_valid_owner():
    base = {"action": ActionName.JOB_READ_SELF, "scope": "job:read:self"}
    missing = authorize_action(request(**base), Resolver())
    malformed = authorize_action(request(**base, resource_owner_pubkey="bad"), Resolver())
    mismatch = authorize_action(request(**base, resource_owner_pubkey=OTHER_ACTOR), Resolver())
    same = authorize_action(request(**base, resource_owner_pubkey=COMPRESSED_ACTOR), Resolver())
    assert missing.reason_code is ReasonCode.OWNERSHIP_REQUIRED
    assert malformed.reason_code is ReasonCode.OWNERSHIP_REQUIRED
    assert mismatch.reason_code is ReasonCode.OWNERSHIP_MISMATCH
    assert same.allowed
    assert same.resource_owner_pubkey == ACTOR


def test_covenant_draft_creation_requires_verified_step_up():
    base = {"action": ActionName.COVENANT_DRAFT_CREATE, "scope": "covenant:draft:create"}
    missing = authorize_action(request(**base), Resolver(IdentityClass.FULL, relation=True))
    verified = authorize_action(request(**base, step_up_verified=True), Resolver(IdentityClass.FULL, relation=True))
    assert missing.reason_code is ReasonCode.STEP_UP_REQUIRED
    assert verified.allowed


def test_operator_has_no_implicit_bypass():
    decision = authorize_action(request(ActionName.SELF_READ, "self:read"), Resolver(IdentityClass.OPERATOR))
    assert decision.reason_code is ReasonCode.OPERATOR_CONTROL_PLANE_REQUIRED


def test_decision_version_and_serialization_are_exact_and_deterministic():
    decision = authorize_action(request(ActionName.SELF_READ, "self:read"), Resolver())
    assert decision.policy_version == POLICY_VERSION == "hodlxxi.action-policy.v1"
    assert decision.to_dict() == decision.to_dict()
    assert json.dumps(decision.to_dict(), sort_keys=True) == json.dumps(decision.to_dict(), sort_keys=True)


def test_denied_decision_contains_no_request_secrets_or_exception_material():
    class SecretFailure:
        def resolve(self, actor_pubkey):
            raise Exception("bearer-token private-key signature client-secret")

    decision = authorize_action(request(ActionName.SELF_READ, "self:read"), SecretFailure())
    serialized = json.dumps(decision.to_dict()).lower()
    for secret in ("bearer-token", "private-key", "signature", "client-secret"):
        assert secret not in serialized


def test_requirement_table_contains_only_approved_narrow_actions_and_scopes():
    assert set(ACTION_REQUIREMENTS) == set(ActionName)
    assert len(ACTION_REQUIREMENTS) == 7
    scopes = [requirement.required_scope for requirement in ACTION_REQUIREMENTS.values()]
    assert len(scopes) == 7
    assert all(isinstance(scope, str) and scope for scope in scopes)
    assert "write" not in scopes
    assert "read" not in scopes
    assert "covenant_create" not in scopes


def test_service_has_no_forbidden_runtime_imports():
    module = importlib.import_module("app.services.action_authorization")
    source = inspect.getsource(module)
    forbidden = ("flask.session", "app.app", "mcp", "wallet", "lnd")
    assert not any(name in source.lower() for name in forbidden)
    assert "flask" not in sys.modules or not source.startswith("from flask")

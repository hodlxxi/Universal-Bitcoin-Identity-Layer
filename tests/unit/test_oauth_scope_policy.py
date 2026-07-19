import pytest

from app.services.oauth_scope_policy import (
    ACTION_SCOPES,
    OPERATOR_MANAGED_SCOPES,
    PUBLIC_DYNAMIC_SCOPES,
    RESERVED_SCOPES,
    STANDARD_SCOPES,
    ScopePolicyError,
    allowed_scopes_for_trust_class,
    classify_scope,
    parse_scopes,
    serialize_scopes,
    validate_client_scopes,
)


def test_registry_classification_is_finite():
    assert {classify_scope(scope) for scope in STANDARD_SCOPES} == {"standard"}
    assert all(classify_scope(scope) in {"action", "reserved"} for scope in ACTION_SCOPES)
    assert RESERVED_SCOPES == {"covenant:draft:create", "covenant:draft:read:self"}


@pytest.mark.parametrize(
    "value",
    ["read", "write", "admin", "operator", "*", "covenant_create", "special", "admin:x", "operator:x"],
)
def test_unknown_broad_and_privileged_scopes_fail_closed(value):
    with pytest.raises(ScopePolicyError):
        parse_scopes(value)


def test_canonical_order_and_deduplication():
    assert serialize_scopes(parse_scopes("profile openid profile")) == "openid profile"


@pytest.mark.parametrize(
    "value", [None, "", " openid", "openid ", "openid  profile", "openid,profile", "openid\tprofile", "openid\nprofile"]
)
def test_malformed_values_rejected(value):
    with pytest.raises(ScopePolicyError):
        parse_scopes(value)


def test_oversized_values_rejected():
    with pytest.raises(ScopePolicyError):
        parse_scopes("openid" + "x" * 1024)


def test_trust_policies_are_exact_and_reserved_nonissuable():
    assert allowed_scopes_for_trust_class("public_dynamic") == PUBLIC_DYNAMIC_SCOPES
    assert allowed_scopes_for_trust_class("operator_managed") == OPERATOR_MANAGED_SCOPES
    assert OPERATOR_MANAGED_SCOPES - PUBLIC_DYNAMIC_SCOPES == {
        "job:create",
        "job:read:self",
        "job:receipt:read:self",
        "action:receipt:read:self",
    }
    for scope in RESERVED_SCOPES:
        with pytest.raises(ScopePolicyError):
            validate_client_scopes(frozenset({scope}), OPERATOR_MANAGED_SCOPES)

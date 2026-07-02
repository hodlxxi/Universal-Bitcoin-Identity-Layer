from app.contracts.qr_pointer_v0 import (
    FORBIDDEN_CLAIM_KEYS,
    SECRET_LIKE_QR_KEYS,
    is_local_bounded_target,
)


def test_qr_pointer_boundary_helper_forbids_authority_claim_keys():
    assert {
        "identity",
        "human_identity",
        "consent",
        "approval",
        "delegation",
        "authorization",
        "execution",
        "receipt_validity",
        "payment",
        "trust",
        "reputation",
        "human_presence",
        "operator_approval",
    }.issubset(FORBIDDEN_CLAIM_KEYS)


def test_qr_pointer_boundary_helper_forbids_secret_like_keys():
    assert {
        "token",
        "secret",
        "password",
        "private_key",
        "macaroon",
        "cookie",
        "bearer",
        "invoice",
        "preimage",
    }.issubset(SECRET_LIKE_QR_KEYS)


def test_qr_pointer_boundary_helper_rejects_write_delegation_policy_and_external_targets():
    assert is_local_bounded_target("/.well-known/agent.json")
    assert is_local_bounded_target("/.well-known/hodlxxi-operator.json")
    assert is_local_bounded_target("/agent/verify/job_123")

    for rejected in (
        "https://hodlxxi.com/agent/verify/job_123",
        "//hodlxxi.com/agent/verify/job_123",
        "/agent/request",
        "/agent/request/request_123",
        "/.well-known/agent-delegation.json",
        "/agent/delegations/delegation_123",
        "/agent/policy",
    ):
        assert not is_local_bounded_target(rejected)


def test_delegation_runtime_endpoints_are_not_registered(app):
    rules = {rule.rule for rule in app.url_map.iter_rules()}

    assert "/.well-known/agent-delegation.json" not in rules
    assert "/agent/delegations" not in rules
    assert "/agent/delegations/<delegation_id>" not in rules
    assert "/agent/policy" not in rules

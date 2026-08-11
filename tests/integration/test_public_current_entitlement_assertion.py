from __future__ import annotations

from pathlib import Path

import pytest

from app.services.action_authorization import IdentityClass
from app.services.current_entitlement import EntitlementDecision, EntitlementDenied, EntitlementUnavailable

SUBJECT = "a" * 64
ENDPOINT = f"/agent/authority/current/{SUBJECT}.json"
OBSERVED_AT = "2026-08-10T00:00:00+00:00"
SUCCESS_KEYS = {
    "schema",
    "subject",
    "valid",
    "identity_class",
    "current_full_relation_satisfied",
    "evidence_source",
    "observed_at",
}


def decision(
    identity_class=IdentityClass.LIMITED,
    relation=False,
    subject=SUBJECT,
    evidence_source="runtime_evidence",
    observed_at=OBSERVED_AT,
):
    return EntitlementDecision(subject, identity_class, relation, evidence_source, observed_at)


def assert_publication_fails_closed(client, monkeypatch, malformed_decision):
    calls = []

    def resolve(subject):
        calls.append(subject)
        return malformed_decision

    monkeypatch.setattr("app.blueprints.agent.resolve_runtime_current_entitlement", resolve)
    response = client.get(ENDPOINT)
    assert calls == [SUBJECT]
    assert response.status_code == 503
    assert response.get_json() == {"error": "entitlement_unavailable"}
    return response


@pytest.mark.parametrize(
    "subject",
    ["A" * 64, "z" * 64, "a" * 63, "02" + "a" * 64, "npub1invalid", "nsec1invalid", "alice", "a@b.test"],
)
def test_noncanonical_subject_is_rejected_before_resolver(client, monkeypatch, subject):
    def unexpected(_subject):
        pytest.fail("resolver called for noncanonical subject")

    monkeypatch.setattr("app.blueprints.agent.resolve_runtime_current_entitlement", unexpected)
    response = client.get(f"/agent/authority/current/{subject}.json")
    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid_subject"}


@pytest.mark.parametrize(
    ("identity_class", "relation", "expected_class"),
    [(IdentityClass.LIMITED, False, "limited"), (IdentityClass.FULL, True, "full")],
)
def test_canonical_runtime_decision_is_published_with_exact_allowlist(
    client, monkeypatch, identity_class, relation, expected_class
):
    calls = []

    def resolve(subject):
        calls.append(subject)
        return decision(identity_class, relation)

    monkeypatch.setattr("app.blueprints.agent.resolve_runtime_current_entitlement", resolve)
    response = client.get(ENDPOINT)
    assert response.status_code == 200
    body = response.get_json()
    assert calls == [SUBJECT]
    assert set(body) == SUCCESS_KEYS
    assert body == {
        "schema": "hodlxxi.current_entitlement_assertion.v1",
        "subject": SUBJECT,
        "valid": True,
        "identity_class": expected_class,
        "current_full_relation_satisfied": relation,
        "evidence_source": "runtime_evidence",
        "observed_at": OBSERVED_AT,
    }
    assert not ({"balance", "xpub", "descriptor", "email", "raw_evidence", "evidence_id"} & set(body))


@pytest.mark.parametrize(
    ("evidence_source", "private_marker"),
    [
        ({"email": "private-dict@example.test"}, "private-dict@example.test"),
        (["private-list-value"], "private-list-value"),
        (23, None),
        (object(), None),
        ("", None),
        ("private-oversized-" + ("x" * 128), "private-oversized"),
        ("runtime_evidence\nprivate-control-value", "private-control-value"),
    ],
    ids=("dict", "list", "non-string", "opaque-object", "empty", "oversized", "control-character"),
)
def test_malformed_evidence_source_fails_closed_without_leakage(
    client, monkeypatch, evidence_source, private_marker
):
    response = assert_publication_fails_closed(
        client,
        monkeypatch,
        decision(evidence_source=evidence_source),
    )
    if private_marker is not None:
        assert private_marker not in response.get_data(as_text=True)


@pytest.mark.parametrize(
    ("observed_at", "private_marker"),
    [
        ({"raw_evidence": "private-observed-structure"}, "private-observed-structure"),
        (23, None),
        ("bad-private-time", "private-time"),
        ("2" * 33, None),
        (object(), None),
    ],
    ids=("structured", "non-string", "malformed-timestamp", "oversized", "non-serializable"),
)
def test_malformed_observed_at_fails_closed_without_leakage(
    client, monkeypatch, observed_at, private_marker
):
    response = assert_publication_fails_closed(
        client,
        monkeypatch,
        decision(observed_at=observed_at),
    )
    if private_marker is not None:
        assert private_marker not in response.get_data(as_text=True)


@pytest.mark.parametrize(
    ("identity_class", "relation", "observed_at"),
    [
        (IdentityClass.LIMITED, False, None),
        (IdentityClass.FULL, True, "2026-08-10T00:00:00.123456+00:00"),
    ],
)
def test_canonical_observed_at_variants_remain_publishable(
    client, monkeypatch, identity_class, relation, observed_at
):
    calls = []

    def resolve(subject):
        calls.append(subject)
        return decision(identity_class, relation, observed_at=observed_at)

    monkeypatch.setattr("app.blueprints.agent.resolve_runtime_current_entitlement", resolve)
    response = client.get(ENDPOINT)
    assert calls == [SUBJECT]
    assert response.status_code == 200
    assert response.get_json()["observed_at"] == observed_at


@pytest.mark.parametrize(
    "invalid_decision",
    [
        decision(IdentityClass.FULL, False),
        decision(IdentityClass.LIMITED, True),
        decision(subject="b" * 64),
        object(),
    ],
)
def test_contradictory_or_unsupported_decision_fails_closed(client, monkeypatch, invalid_decision):
    monkeypatch.setattr(
        "app.blueprints.agent.resolve_runtime_current_entitlement", lambda _subject: invalid_decision
    )
    response = client.get(ENDPOINT)
    assert response.status_code == 503
    assert response.get_json() == {"error": "entitlement_unavailable"}


@pytest.mark.parametrize(
    ("failure", "status", "error"),
    [
        (EntitlementDenied("private denial detail"), 404, "entitlement_denied"),
        (EntitlementUnavailable("private storage detail"), 503, "entitlement_unavailable"),
        (RuntimeError("private infrastructure detail"), 503, "entitlement_unavailable"),
    ],
)
def test_resolver_failures_are_distinct_safe_and_fail_closed(client, monkeypatch, failure, status, error):
    def fail(_subject):
        raise failure

    monkeypatch.setattr("app.blueprints.agent.resolve_runtime_current_entitlement", fail)
    response = client.get(ENDPOINT)
    assert response.status_code == status
    assert response.get_json() == {"error": error}
    assert "private" not in response.get_data(as_text=True)


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_unsupported_write_methods_never_resolve(client, monkeypatch, method):
    monkeypatch.setattr(
        "app.blueprints.agent.resolve_runtime_current_entitlement",
        lambda _subject: pytest.fail("resolver called for write method"),
    )
    assert getattr(client, method)(ENDPOINT).status_code == 405


def test_standalone_request_does_not_wrap_resolver_in_session_scope(client, monkeypatch):
    monkeypatch.setattr(
        "app.blueprints.agent.session_scope",
        lambda: pytest.fail("route opened an ambient transaction"),
    )
    monkeypatch.setattr(
        "app.blueprints.agent.resolve_runtime_current_entitlement", lambda _subject: decision()
    )
    assert client.get(ENDPOINT).status_code == 200


def test_agent_publication_includes_assertion_without_mcp_expansion(client):
    capabilities = client.get("/agent/capabilities").get_json()
    schema = client.get("/agent/capabilities/schema").get_json()
    discovery = client.get("/agent/discovery").get_json()
    path = "/agent/authority/current/<subject>.json"

    assert capabilities["endpoints"]["current_entitlement_assertion"] == path
    assert schema["properties"]["endpoints"]["properties"]["current_entitlement_assertion"] == {
        "type": "string",
        "pattern": "^/",
    }
    assert discovery["discovery"]["current_entitlement_assertion"] == path
    assert capabilities["mcp"]["tool_count"] == discovery["mcp"]["tool_count"]


def test_blueprint_has_no_entitlement_storage_or_policy_coupling():
    source = (Path(__file__).parents[2] / "app" / "blueprints" / "agent.py").read_text()
    publication_source = source.split('def _canonical_current_entitlement_subject(subject: str)', 1)[1].split(
        '@agent_bp.get("/agent/capabilities/schema")', 1
    )[0]
    forbidden = (
        "SqlAlchemyCurrentEntitlementEvidenceRepository",
        "get_session",
        "resolve_current_entitlement(",
        "get_user_by_pubkey",
        "canonical_crt_membership",
        "canonical_sponsor_lineage",
        "covenant_entitlement_materializer",
        "get_rpc_connection",
        "session_scope(",
    )
    assert "resolve_runtime_current_entitlement(canonical_subject)" in publication_source
    assert not any(name in publication_source for name in forbidden)


def test_e923_is_only_a_participant_subject_and_operator_surface_is_unchanged(client, monkeypatch):
    e923_subject = "3d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
    monkeypatch.setattr(
        "app.blueprints.agent.resolve_runtime_current_entitlement",
        lambda subject: decision(subject=subject),
    )
    assertion = client.get(f"/agent/authority/current/{e923_subject}.json").get_json()
    operator = client.get("/.well-known/hodlxxi-operator.json").get_json()
    assert assertion["identity_class"] == "limited"
    assert "operator" not in assertion
    assert operator["operator_id"] == "E923"
    assert operator["operator_pubkey"].startswith("02")

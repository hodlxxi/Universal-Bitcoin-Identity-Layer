from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.services.canonical_controlling_registration as selector_module
from app.services.canonical_controlling_registration import (
    ControllingRegistrationSelectionSource as Source,
    ControllingRegistrationUnavailable,
    resolve_controlling_registration,
)
from app.services.canonical_genesis_record import GRAPH_ID
from app.services.trusted_covenant_registration import TrustedCovenantRegistrationLifecycle


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


genesis_fixtures = _module("genesis_fixtures_for_controlling", "tests/unit/test_canonical_genesis_record.py")
edge_fixtures = _module("edge_fixtures_for_controlling", "tests/unit/test_canonical_admission_edge.py")
root_fixtures = _module("root_fixtures_for_controlling", "tests/unit/test_canonical_root_registration_binding.py")
registration_fixtures = _module(
    "registration_fixtures_for_controlling", "tests/unit/test_trusted_covenant_registration.py"
)
NOW = datetime(2026, 8, 11, tzinfo=timezone.utc)


class Repository:
    def __init__(self, value=None, error=None):
        self.value = value
        self.error = error
        self.calls = []

    def _read(self, name, args):
        self.calls.append((name, args))
        if self.error:
            raise self.error
        return self.value

    def list_for_graph(self, *args):
        return self._read("list_for_graph", args)

    def get_effective_for_child(self, *args):
        return self._read("get_effective_for_child", args)

    def resolve_effective(self, *args, **kwargs):
        return self._read("resolve_effective", (args, kwargs))

    def get(self, *args):
        return self._read("get", args)


def _repositories(*, root=False):
    genesis_record = genesis_fixtures.record()
    if root:
        registration = registration_fixtures.registration()
        selector = root_fixtures.binding()
    else:
        registration = edge_fixtures.registration()
        selector = edge_fixtures.edge(registration)
    return (
        registration,
        Repository((genesis_record,)),
        Repository(selector if not root else None),
        Repository(selector if root else None),
        Repository(registration),
    )


def _resolve(subject, repositories, *, graph=GRAPH_ID, evaluated_at=NOW):
    _, genesis, edge, root, registration = repositories
    return resolve_controlling_registration(
        graph,
        subject,
        evaluated_at=evaluated_at,
        genesis_repository=genesis,
        admission_edge_repository=edge,
        root_registration_binding_repository=root,
        trusted_registration_repository=registration,
    )


def test_ordinary_subject_uses_only_exact_admission_edge_pointer():
    repositories = _repositories()
    registration = repositories[0]
    result = _resolve(registration.subject_xonly_pubkey, repositories)
    assert result.registration == registration
    assert result.selection_source is Source.CANONICAL_ADMISSION_EDGE
    assert repositories[2].calls == [
        ("get_effective_for_child", (GRAPH_ID, registration.subject_xonly_pubkey))
    ]
    assert repositories[3].calls == []
    assert repositories[4].calls == [("get", (registration.registration_id,))]


def test_root_uses_only_exact_binding_and_never_falls_back():
    repositories = _repositories(root=True)
    registration = repositories[0]
    result = _resolve(registration.subject_xonly_pubkey, repositories)
    assert result.selection_source is Source.CANONICAL_ROOT_REGISTRATION_BINDING
    assert repositories[2].calls == []
    assert repositories[3].calls[0][0] == "resolve_effective"
    repositories[3].value = None
    with pytest.raises(ControllingRegistrationUnavailable):
        _resolve(registration.subject_xonly_pubkey, repositories)
    assert repositories[2].calls == []


def test_unrelated_active_registration_is_not_enumerated_or_selected():
    repositories = _repositories()
    pointed = repositories[0]
    unrelated = replace(pointed, registration_id="00000000-0000-4000-8000-000000000012")
    repositories[4].value = pointed
    result = _resolve(pointed.subject_xonly_pubkey, repositories)
    assert result.registration == pointed
    assert unrelated.lifecycle_state is TrustedCovenantRegistrationLifecycle.ACTIVE
    assert repositories[4].calls == [("get", (pointed.registration_id,))]


@pytest.mark.parametrize("value", (None, object()))
def test_missing_or_malformed_pointer_fails_closed(value):
    repositories = _repositories()
    repositories[2].value = value
    with pytest.raises(ControllingRegistrationUnavailable, match="^controlling registration unavailable$"):
        _resolve(repositories[0].subject_xonly_pubkey, repositories)


def test_inactive_subject_digest_id_and_graph_mismatches_fail_closed():
    base = _repositories()
    subject = base[0].subject_xonly_pubkey
    cases = (
        replace(base[0], lifecycle_state=TrustedCovenantRegistrationLifecycle.REVOKED),
        registration_fixtures.registration(),
        replace(base[0], registration_id="00000000-0000-4000-8000-000000000012"),
    )
    for registration in cases:
        repositories = _repositories()
        repositories[4].value = registration
        with pytest.raises(ControllingRegistrationUnavailable):
            _resolve(subject, repositories)
    repositories = _repositories()
    repositories[2].value = replace(repositories[2].value, trusted_registration_sha256="0" * 64)
    with pytest.raises(ControllingRegistrationUnavailable):
        _resolve(subject, repositories)
    repositories = _repositories(root=True)
    repositories[3].value = replace(repositories[3].value, graph_or_protocol_id="other")
    with pytest.raises(ControllingRegistrationUnavailable):
        _resolve(repositories[0].subject_xonly_pubkey, repositories)


@pytest.mark.parametrize("graph,subject", (("", "0" * 64), (GRAPH_ID, "A" * 64), (GRAPH_ID, "0" * 63)))
def test_malformed_identity_fails_before_storage(graph, subject):
    repositories = _repositories()
    with pytest.raises(ControllingRegistrationUnavailable):
        _resolve(subject, repositories, graph=graph)
    assert repositories[1].calls == []


def test_genesis_and_storage_failures_are_sanitized():
    repositories = _repositories()
    repositories[1].value = ()
    with pytest.raises(ControllingRegistrationUnavailable):
        _resolve(repositories[0].subject_xonly_pubkey, repositories)
    repositories = _repositories()
    repositories[2].error = RuntimeError("private database detail")
    with pytest.raises(ControllingRegistrationUnavailable) as caught:
        _resolve(repositories[0].subject_xonly_pubkey, repositories)
    assert str(caught.value) == "controlling registration unavailable"
    assert caught.value.__cause__ is None


def test_ambiguous_and_malformed_genesis_fail_before_either_branch():
    for records in (
        (
            genesis_fixtures.record(),
            replace(
                genesis_fixtures.record(),
                record_id="20000000-0000-4000-8000-000000000002",
            ),
        ),
        (object(),),
    ):
        repositories = _repositories()
        repositories[1].value = records
        with pytest.raises(ControllingRegistrationUnavailable):
            _resolve(repositories[0].subject_xonly_pubkey, repositories)
        assert repositories[2].calls == []
        assert repositories[3].calls == []


def test_missing_or_malformed_registration_and_trusted_storage_failure_are_sanitized():
    for value, error in ((None, None), (object(), None), (None, RuntimeError("private row"))):
        repositories = _repositories()
        repositories[4].value = value
        repositories[4].error = error
        with pytest.raises(ControllingRegistrationUnavailable, match="^controlling registration unavailable$"):
            _resolve(repositories[0].subject_xonly_pubkey, repositories)
        assert repositories[3].calls == []


@pytest.mark.parametrize("evaluated_at", (None, "2026-08-11T00:00:00Z", NOW.replace(tzinfo=None)))
def test_invalid_evaluated_at_fails_before_selector_branches(evaluated_at):
    repositories = _repositories()
    with pytest.raises(ControllingRegistrationUnavailable):
        _resolve(repositories[0].subject_xonly_pubkey, repositories, evaluated_at=evaluated_at)
    assert repositories[2].calls == []
    assert repositories[3].calls == []


def test_admission_edge_graph_and_child_mismatches_fail_without_root_lookup(monkeypatch):
    for changes in (
        {"graph_or_protocol_id": "other"},
        {"child_x_only_public_key": "0" * 64},
    ):
        repositories = _repositories()
        canonical = repositories[2].value
        values = {
            field: getattr(canonical, field) for field in canonical.__dataclass_fields__
        }
        malformed = SimpleNamespace(**{**values, **changes})
        monkeypatch.setattr(selector_module, "parse_canonical_admission_edge", lambda _value, result=malformed: result)
        with pytest.raises(ControllingRegistrationUnavailable):
            _resolve(repositories[0].subject_xonly_pubkey, repositories)
        assert repositories[3].calls == []


@pytest.mark.parametrize(
    "changes",
    (
        {"graph_or_protocol_id": "other"},
        {"root_x_only_public_key": "0" * 64},
        {"trusted_registration_id": "20000000-0000-4000-8000-000000000003"},
        {"trusted_registration_sha256": "0" * 64},
    ),
)
def test_root_binding_graph_root_id_and_digest_mismatches_never_fall_back(changes):
    repositories = _repositories(root=True)
    repositories[3].value = replace(repositories[3].value, **changes)
    with pytest.raises(ControllingRegistrationUnavailable):
        _resolve(repositories[0].subject_xonly_pubkey, repositories)
    assert repositories[2].calls == []


def test_result_is_immutable_and_contains_no_authority_fields():
    repositories = _repositories()
    result = _resolve(repositories[0].subject_xonly_pubkey, repositories)
    with pytest.raises(FrozenInstanceError):
        result.graph_or_protocol_id = "other"
    assert set(result.__dataclass_fields__) == {
        "graph_or_protocol_id",
        "subject_xonly_pubkey",
        "selection_source",
        "selector_record_id",
        "selector_record_sha256",
        "registration",
    }


@pytest.mark.parametrize("exception", (KeyboardInterrupt, SystemExit))
def test_process_control_exceptions_are_preserved(exception):
    repositories = _repositories()
    repositories[1].error = exception()
    with pytest.raises(exception):
        _resolve(repositories[0].subject_xonly_pubkey, repositories)


@pytest.mark.parametrize("repository_index", (2, 4))
@pytest.mark.parametrize("exception", (KeyboardInterrupt, SystemExit))
def test_process_control_exceptions_after_genesis_are_preserved_for_ordinary_path(
    repository_index, exception
):
    repositories = _repositories()
    repositories[repository_index].error = exception()
    with pytest.raises(exception):
        _resolve(repositories[0].subject_xonly_pubkey, repositories)
    assert repositories[3].calls == []


@pytest.mark.parametrize("repository_index", (3, 4))
@pytest.mark.parametrize("exception", (KeyboardInterrupt, SystemExit))
def test_process_control_exceptions_after_genesis_are_preserved_for_root_path(
    repository_index, exception
):
    repositories = _repositories(root=True)
    repositories[repository_index].error = exception()
    with pytest.raises(exception):
        _resolve(repositories[0].subject_xonly_pubkey, repositories)
    assert repositories[2].calls == []

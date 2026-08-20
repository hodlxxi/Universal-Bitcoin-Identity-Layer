from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.services.canonical_crt_runtime_bootstrap import (
    AMBIGUOUS_MESSAGE,
    EXPECTED_MANIFEST_FILE_SHA256,
    BootstrapMode,
    BootstrapUnavailable,
    execute_bootstrap,
    load_bootstrap_bundle,
)
from app.services.canonical_crt_runtime_bootstrap_runner import (
    COMMIT_ACK,
    BootstrapRequest,
    execute_request,
    parse_bootstrap_argv,
)
from app.services.covenant_relation import CovenantDirection

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 20, 22, 5, tzinfo=timezone.utc)


class GenesisRepo:
    def __init__(self, value=None):
        self.value = value
        self.appends = 0

    def list_for_graph(self, graph):
        return () if self.value is None else (self.value,)

    def get(self, identifier):
        return self.value if self.value is not None and self.value.record_id == identifier else None

    def append(self, value):
        self.appends += 1
        self.value = value


class TrustedRepo:
    def __init__(self, value=None):
        self.value = value
        self.appends = 0

    def get(self, identifier):
        return self.value if self.value is not None and self.value.registration_id == identifier else None

    def append(self, value):
        self.appends += 1
        self.value = value


class BindingRepo:
    def __init__(self, value=None):
        self.value = value
        self.appends = 0
        self.evaluated_at = None

    def list_for_root(self, graph, subject):
        return () if self.value is None else (self.value,)

    def get(self, identifier):
        return self.value if self.value is not None and self.value.binding_id == identifier else None

    def append(self, value, *, evaluated_at):
        self.appends += 1
        self.evaluated_at = evaluated_at
        self.value = value


class FundingRepo:
    def __init__(self, value=None):
        self.value = value
        self.appends = 0

    def list_by_registration(self, identifier):
        return () if self.value is None else (self.value,)

    def get(self, identifier):
        return self.value if self.value is not None and self.value.funding_set_id == identifier else None

    def append(self, value):
        self.appends += 1
        self.value = value


def repos(bundle, *, genesis=False, trusted=False, binding=False, funding=False):
    values = {
        "genesis_repository": GenesisRepo(bundle.genesis if genesis else None),
        "trusted_registration_repository": TrustedRepo(bundle.trusted_registration if trusted else None),
        "root_registration_binding_repository": BindingRepo(bundle.root_registration_binding if binding else None),
        "funding_set_repository": FundingRepo(bundle.funding_set if funding else None),
    }
    return values


def test_manifest_rebuilds_exact_domain_chain():
    bundle = load_bootstrap_bundle(ROOT, evaluated_at=NOW)
    assert bundle.manifest_sha256 == EXPECTED_MANIFEST_FILE_SHA256
    assert bundle.graph_or_protocol_id == "hodlxxi.crt_membership_graph.v1"
    assert bundle.subject_xonly_pubkey == "3d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
    assert bundle.trusted_registration.delta_blocks == 777
    assert bundle.trusted_registration.delta_profile.value == "legacy_777"
    assert bundle.trusted_registration.pair_sha256 == "14d28942ffe57c022413f45d293d22f3500e5a2aaf8facac29fa823595430866"
    assert len(bundle.funding_set.recognized_outpoints) == 5
    assert (
        sum(x.amount_sats for x in bundle.funding_set.recognized_outpoints if x.direction is CovenantDirection.INCOMING)
        == 300000
    )
    assert (
        sum(x.amount_sats for x in bundle.funding_set.recognized_outpoints if x.direction is CovenantDirection.OUTGOING)
        == 300000
    )


def test_dry_run_is_zero_write_preview():
    bundle = load_bootstrap_bundle(ROOT, evaluated_at=NOW)
    stores = repos(bundle)
    result = execute_bootstrap(bundle, mode=BootstrapMode.DRY_RUN, evaluated_at=NOW, **stores)
    assert result["outcome"] == "preview"
    assert result["append_performed"] is False and result["appended_count"] == 0
    assert set(result["actions"].values()) == {"would_append"}
    assert sum(store.appends for store in stores.values()) == 0
    assert result["writes_entitlement_evidence"] is False
    assert result["performs_bitcoin_observation"] is False
    assert result["installs_scheduler"] is False


def test_commit_appends_in_order_and_exact_replay_is_unchanged():
    bundle = load_bootstrap_bundle(ROOT, evaluated_at=NOW)
    stores = repos(bundle)
    first = execute_bootstrap(bundle, mode=BootstrapMode.COMMIT, evaluated_at=NOW, **stores)
    assert first["outcome"] == "applied" and first["appended_count"] == 4
    assert list(first["actions"].values()) == ["appended", "appended", "appended", "appended"]
    assert stores["root_registration_binding_repository"].evaluated_at == NOW
    assert [store.appends for store in stores.values()] == [1, 1, 1, 1]

    replay = execute_bootstrap(bundle, mode=BootstrapMode.COMMIT, evaluated_at=NOW, **stores)
    assert replay["outcome"] == "unchanged" and replay["appended_count"] == 0
    assert set(replay["actions"].values()) == {"unchanged"}
    assert [store.appends for store in stores.values()] == [1, 1, 1, 1]


def test_partial_exact_state_resumes_without_rewriting_prior_steps():
    bundle = load_bootstrap_bundle(ROOT, evaluated_at=NOW)
    stores = repos(bundle, genesis=True, trusted=True)
    result = execute_bootstrap(bundle, mode=BootstrapMode.COMMIT, evaluated_at=NOW, **stores)
    assert result["actions"] == {
        "genesis": "unchanged",
        "trusted_registration": "unchanged",
        "root_registration_binding": "appended",
        "funding_set": "appended",
    }
    assert [store.appends for store in stores.values()] == [0, 0, 1, 1]


def test_conflicting_existing_identity_fails_closed_before_append():
    bundle = load_bootstrap_bundle(ROOT, evaluated_at=NOW)

    class ConflictGenesis(GenesisRepo):
        def list_for_graph(self, graph):
            return (bundle.genesis,)

        def get(self, identifier):
            return object()

    stores = repos(bundle)
    stores["genesis_repository"] = ConflictGenesis()
    with pytest.raises(BootstrapUnavailable) as error:
        execute_bootstrap(bundle, mode=BootstrapMode.COMMIT, evaluated_at=NOW, **stores)
    assert str(error.value) == AMBIGUOUS_MESSAGE
    assert sum(store.appends for store in stores.values()) == 0


def test_runner_argv_requires_explicit_commit_ack_and_absolute_lock():
    assert parse_bootstrap_argv(["--dry-run"]) == BootstrapRequest(BootstrapMode.DRY_RUN, None)
    commit = parse_bootstrap_argv(["--commit", "--lock-directory", "/private/lock", "--ack", COMMIT_ACK])
    assert commit == BootstrapRequest(BootstrapMode.COMMIT, "/private/lock")
    for argv in (
        ["--commit"],
        ["--commit", "--lock-directory", "relative", "--ack", COMMIT_ACK],
        ["--commit", "--lock-directory", "/private/lock", "--ack", "wrong"],
        ["--dry-run", "--ack", COMMIT_ACK],
        ["--dry-run", "--lock-directory", "/private/lock"],
        ["--dry-run", "--commit"],
    ):
        with pytest.raises(BootstrapUnavailable):
            parse_bootstrap_argv(argv)


def test_runner_commit_uses_subject_guard_and_normalizes_clock_precision():
    bundle = load_bootstrap_bundle(ROOT, evaluated_at=NOW)
    stores = repos(bundle)
    held = []
    closed = []

    class Guard:
        def __init__(self, directory):
            assert directory == "/private/lock"

        @contextmanager
        def hold(self, subject):
            held.append(subject)
            yield self

        def close(self):
            closed.append(True)

    result = execute_request(
        BootstrapRequest(BootstrapMode.COMMIT, "/private/lock"),
        dependency_factory=lambda: stores,
        repository_root=ROOT,
        clock=lambda: NOW.replace(microsecond=654321),
        guard_factory=Guard,
    )
    assert result["outcome"] == "applied"
    assert held == [bundle.subject_xonly_pubkey] and closed == [True]
    assert stores["root_registration_binding_repository"].evaluated_at == NOW

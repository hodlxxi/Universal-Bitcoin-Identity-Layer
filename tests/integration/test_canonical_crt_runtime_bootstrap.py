from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models import Base
from app.services.canonical_covenant_funding_set_storage import SqlAlchemyCanonicalCovenantFundingSetRepository
from app.services.canonical_crt_runtime_bootstrap import BootstrapMode, execute_bootstrap, load_bootstrap_bundle
from app.services.canonical_genesis_record_storage import SqlAlchemyCanonicalGenesisRecordRepository
from app.services.canonical_root_registration_binding_storage import (
    SqlAlchemyCanonicalRootRegistrationBindingRepository,
)
from app.services.trusted_covenant_registration_storage import SqlAlchemyTrustedCovenantRegistrationRepository

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 20, 22, 10, tzinfo=timezone.utc)


@pytest.fixture
def repositories(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'bootstrap.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    genesis = SqlAlchemyCanonicalGenesisRecordRepository(factory)
    trusted = SqlAlchemyTrustedCovenantRegistrationRepository(factory)
    binding = SqlAlchemyCanonicalRootRegistrationBindingRepository(
        factory,
        genesis_repository=genesis,
        trusted_registration_repository=trusted,
    )
    funding = SqlAlchemyCanonicalCovenantFundingSetRepository(
        factory,
        trusted_registration_repository=trusted,
    )
    return factory, {
        "genesis_repository": genesis,
        "trusted_registration_repository": trusted,
        "root_registration_binding_repository": binding,
        "funding_set_repository": funding,
    }


def test_sqlalchemy_bootstrap_commit_replay_and_no_entitlement_write(repositories):
    factory, repos = repositories
    bundle = load_bootstrap_bundle(ROOT, evaluated_at=NOW)

    preview = execute_bootstrap(bundle, mode=BootstrapMode.DRY_RUN, evaluated_at=NOW, **repos)
    assert preview["outcome"] == "preview"
    assert set(preview["actions"].values()) == {"would_append"}

    applied = execute_bootstrap(bundle, mode=BootstrapMode.COMMIT, evaluated_at=NOW, **repos)
    assert applied["outcome"] == "applied" and applied["appended_count"] == 4
    assert repos["genesis_repository"].get(bundle.genesis.record_id) == bundle.genesis
    stored_registration = repos["trusted_registration_repository"].get(bundle.trusted_registration.registration_id)
    assert stored_registration == bundle.trusted_registration
    assert (
        stored_registration.mirrored_pair.earlier_leg.raw_script_hex
        == bundle.trusted_registration.mirrored_pair.earlier_leg.raw_script_hex
    )
    assert (
        stored_registration.mirrored_pair.later_leg.raw_script_hex
        == bundle.trusted_registration.mirrored_pair.later_leg.raw_script_hex
    )
    assert (
        repos["root_registration_binding_repository"].get(bundle.root_registration_binding.binding_id)
        == bundle.root_registration_binding
    )
    assert repos["funding_set_repository"].get(bundle.funding_set.funding_set_id) == bundle.funding_set

    with factory() as session:
        assert session.execute(text("SELECT COUNT(*) FROM current_entitlement_evidence")).scalar_one() == 0

    replay = execute_bootstrap(bundle, mode=BootstrapMode.COMMIT, evaluated_at=NOW, **repos)
    assert replay["outcome"] == "unchanged" and replay["appended_count"] == 0
    assert set(replay["actions"].values()) == {"unchanged"}


def test_sqlalchemy_partial_resume_preserves_exact_prior_rows(repositories):
    _, repos = repositories
    bundle = load_bootstrap_bundle(ROOT, evaluated_at=NOW)
    repos["genesis_repository"].append(bundle.genesis)
    repos["trusted_registration_repository"].append(bundle.trusted_registration)

    result = execute_bootstrap(bundle, mode=BootstrapMode.COMMIT, evaluated_at=NOW, **repos)
    assert result["actions"] == {
        "genesis": "unchanged",
        "trusted_registration": "unchanged",
        "root_registration_binding": "appended",
        "funding_set": "appended",
    }
    assert repos["genesis_repository"].list_for_graph(bundle.graph_or_protocol_id) == (bundle.genesis,)
    assert (
        repos["trusted_registration_repository"].get(bundle.trusted_registration.registration_id)
        == bundle.trusted_registration
    )
    assert (
        repos["root_registration_binding_repository"].resolve_effective(
            bundle.graph_or_protocol_id,
            bundle.subject_xonly_pubkey,
            evaluated_at=NOW,
        )
        == bundle.root_registration_binding
    )
    assert (
        repos["funding_set_repository"].resolve_effective(bundle.trusted_registration.registration_id)
        == bundle.funding_set
    )

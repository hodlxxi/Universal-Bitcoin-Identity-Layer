from pathlib import Path


def test_domain_service_is_importable_and_absent_from_runtime_surfaces():
    import app.services.canonical_sponsor_lineage as service

    assert callable(service.evaluate_canonical_sponsor_lineage)
    forbidden = (
        Path("app/blueprints"),
        Path("packages/hodlxxi_mcp"),
        Path("migrations"),
    )
    for root in forbidden:
        for path in root.rglob("*.py"):
            assert "canonical_sponsor_lineage" not in path.read_text(errors="ignore")


def test_no_lineage_model_or_migration_is_published():
    assert "CanonicalSponsorLineage" not in Path("app/models.py").read_text()
    assert not any("lineage" in path.name.lower() for path in Path("migrations").rglob("*"))

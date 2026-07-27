from pathlib import Path

from app.services.canonical_admission_edge import EDGE_SCHEMA, EDGE_VERSION


def test_no_production_edge_is_published_or_seeded():
    assert EDGE_SCHEMA == "hodlxxi.canonical_admission_edge.v1"
    assert EDGE_VERSION == "hodlxxi.canonical_admission_edge_service.v1"
    assert not list(Path("docs/data").glob("*admission*edge*"))
    migration = Path("migrations/2026-07-26_canonical_admission_edge_registry_v1.sql").read_text()
    assert "INSERT INTO" not in migration.upper()

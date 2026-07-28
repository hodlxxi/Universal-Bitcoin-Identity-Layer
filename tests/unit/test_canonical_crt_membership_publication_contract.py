from pathlib import Path


def test_service_is_importable_and_domain_only():
    from app.services import canonical_crt_membership

    path = Path(canonical_crt_membership.__file__)
    text = path.read_text()
    assert path.name == "canonical_crt_membership.py"
    for forbidden in (
        "flask",
        "sqlalchemy",
        "requests",
        "subprocess",
        "bitcoinrpc",
        "app.models",
    ):
        assert forbidden not in text.lower()


def test_no_runtime_surface_imports_membership_service():
    roots = (
        Path("app/blueprints"),
        Path("packages/hodlxxi_mcp"),
    )
    for root in roots:
        if root.exists():
            for path in root.rglob("*.py"):
                assert "canonical_crt_membership" not in path.read_text(errors="ignore")


def test_no_model_migration_cli_or_scheduler_publication():
    service_name = "canonical_crt_membership"
    for root in (Path("migrations"), Path("app")):
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in {".py", ".sql"} and path.name != f"{service_name}.py":
                if any(part in {"services"} for part in path.parts):
                    continue
                assert service_name not in path.read_text(errors="ignore")

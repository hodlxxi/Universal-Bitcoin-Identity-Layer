from pathlib import Path


def test_service_is_importable_and_domain_only():
    from app.services import canonical_crt_authorization_policy

    path = Path(canonical_crt_authorization_policy.__file__)
    text = path.read_text()
    assert path.name == "canonical_crt_authorization_policy.py"
    for forbidden in (
        "from app.services.action_authorization import",
        "import identityclass", "entitlementsnapshot",
        "currententitlementevidencerecord", "actiondecision",
        "authorize_action(", ".materialize(", "repository.append",
        "flask", "sqlalchemy", "requests", "subprocess", "bitcoinrpc",
    ):
        assert forbidden not in text.lower()


def test_no_runtime_surface_consumes_policy():
    service_name = "canonical_crt_authorization_policy"
    for root in (
        Path("app/blueprints"),
        Path("packages/hodlxxi_mcp"),
        Path("app/services"),
    ):
        if root.exists():
            for path in root.rglob("*.py"):
                if path.name != f"{service_name}.py":
                    assert service_name not in path.read_text(errors="ignore")


def test_no_model_migration_cli_scheduler_or_runtime_publication():
    service_name = "canonical_crt_authorization_policy"
    for root in (Path("migrations"), Path("app")):
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if (
                path.is_file()
                and path.suffix in {".py", ".sql"}
                and path.name != f"{service_name}.py"
                and "tests" not in path.parts
            ):
                assert service_name not in path.read_text(errors="ignore")

import ast
from pathlib import Path


ROOT = Path(__file__).parents[2]
POLICY_MODULE = "app.services.canonical_crt_authorization_policy"
PROOF_MODULE = "app.services.canonical_crt_authorization_proof"
POLICY_SYMBOLS = {
    "CanonicalCrtAuthorizationClass",
    "CanonicalCrtAuthorizationEvaluation",
    "CanonicalCrtAuthorizationReason",
    "canonical_crt_authorization_evaluation_bytes",
    "canonical_crt_authorization_evaluation_sha256",
    "parse_canonical_crt_authorization_evaluation",
}
RESOLVER_PATH = ROOT / "app/services/canonical_crt_authorization_proof_resolver.py"
DYNAMIC_CALLS = {"import_module", "__import__", "exec", "eval"}


def _tree(path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _constant_string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_string(node.left)
        right = _constant_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _referenced_modules(path):
    modules = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.add(node.module or "")
            modules.update(
                f"{node.module}.{alias.name}"
                for alias in node.names
                if node.module
            )
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if POLICY_MODULE in node.value or PROOF_MODULE in node.value:
                modules.add(node.value)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            value = _constant_string(node)
            if isinstance(value, str):
                if POLICY_MODULE in value or PROOF_MODULE in value:
                    modules.add(value)
    return modules


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
    proof_path = ROOT / "app/services/canonical_crt_authorization_proof.py"
    policy_imports = [
        node for node in ast.walk(_tree(proof_path))
        if isinstance(node, ast.ImportFrom) and node.module == POLICY_MODULE
    ]
    assert len(policy_imports) == 1
    assert {alias.name for alias in policy_imports[0].names} == POLICY_SYMBOLS
    assert all(alias.name != "*" for alias in policy_imports[0].names)

    for node in ast.walk(_tree(proof_path)):
        if isinstance(node, ast.Import):
            assert all(alias.name != "importlib" for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module != "importlib"
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in DYNAMIC_CALLS

    services = ROOT / "app/services"
    allowed = {
        services / "canonical_crt_authorization_policy.py",
        proof_path,
        services / "canonical_crt_authorization_proof_publication.py",
        RESOLVER_PATH,
    }
    for path in services.rglob("*.py"):
        if path not in allowed:
            tree = _tree(path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    assert all(alias.name != "importlib" for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    assert node.module != "importlib"
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    assert node.func.id not in DYNAMIC_CALLS
            assert POLICY_MODULE not in _referenced_modules(path)

    for root in (ROOT / "app/blueprints", ROOT / "packages/hodlxxi_mcp"):
        for path in root.rglob("*.py"):
            references = _referenced_modules(path)
            assert POLICY_MODULE not in references
            assert PROOF_MODULE not in references


def test_no_model_migration_cli_scheduler_or_runtime_publication():
    allowed = {
        ROOT / "app/services/canonical_crt_authorization_policy.py",
        ROOT / "app/services/canonical_crt_authorization_proof.py",
        ROOT / "app/services/canonical_crt_authorization_proof_publication.py",
        RESOLVER_PATH,
    }
    for root in (ROOT / "migrations", ROOT / "app"):
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            if path not in allowed:
                references = _referenced_modules(path)
                assert POLICY_MODULE not in references
                assert PROOF_MODULE not in references
        for path in root.rglob("*.sql"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert "canonical_crt_authorization_policy" not in text
            assert "canonical_crt_authorization_proof" not in text

import ast
from pathlib import Path


ROOT = Path(__file__).parents[2]
PROOF_MODULE = "app.services.canonical_crt_authorization_proof"
PUBLICATION_MODULE = (
    "app.services.canonical_crt_authorization_proof_publication"
)
PUBLICATION_PATH = (
    ROOT / "app/services/canonical_crt_authorization_proof_publication.py"
)
BLUEPRINT_PATH = ROOT / "app/blueprints/crt_authorization_proof.py"
APPROVED_PROOF_CONSUMER = PUBLICATION_PATH
RESOLVER_PATH = ROOT / "app/services/canonical_crt_authorization_proof_resolver.py"
COMPOSER_PATH = ROOT / "app/services/hodlxxi_v1_snapshot_proof_composition.py"
APPROVED_PUBLICATION_CONSUMER = BLUEPRINT_PATH
FORBIDDEN_IMPORT_PARTS = {
    "flask", "sqlalchemy", "database", "models", "requests", "httpx",
    "subprocess", "payment", "payments", "billing", "entitlement",
    "entitlements", "session", "sessions", "bitcoin", "rpc", "lnd", "mcp",
    "scheduler", "schedulers", "cli",
}
FORBIDDEN_CALLS = {
    "session_scope", "get_rpc_connection", "requests.request",
    "requests.sessions.session.request", "session.request", "subprocess",
    "write_text", "write_bytes", "unlink", "rename", "mkdir",
}


def _runtime_python_files():
    roots = (
        ROOT / "app",
        ROOT / "packages",
        ROOT / "migrations",
        ROOT / "scripts",
    )
    for directory in roots:
        if directory.exists():
            yield from directory.rglob("*.py")


def _imports(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    result = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            result.append((node.module or "", tuple(a.name for a in node.names)))
        elif isinstance(node, ast.Import):
            result.extend((alias.name, ()) for alias in node.names)
    return result


def _dotted_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _module_parts(module):
    return {part.lower() for part in module.split(".")}


def test_exactly_two_static_proof_consumers_and_one_public_blueprint():
    proof_consumers = set()
    publication_consumers = set()
    for path in _runtime_python_files():
        for module, _ in _imports(path):
            if module == PROOF_MODULE:
                proof_consumers.add(path)
            if module == PUBLICATION_MODULE:
                publication_consumers.add(path)
    assert proof_consumers == {APPROVED_PROOF_CONSUMER, RESOLVER_PATH, COMPOSER_PATH}
    assert publication_consumers == {APPROVED_PUBLICATION_CONSUMER}


def test_approved_imports_are_explicit_and_complete():
    imports = dict(_imports(PUBLICATION_PATH))
    assert set(imports[PROOF_MODULE]) == {
        "CanonicalCrtAuthorizationProof",
        "InvalidCanonicalCrtAuthorizationProof",
        "SCHEMA",
        "VERIFICATION_RULE",
        "canonical_crt_authorization_proof_bytes",
        "canonical_crt_authorization_proof_sha256",
        "parse_canonical_crt_authorization_proof",
    }
    blueprint_imports = dict(_imports(BLUEPRINT_PATH))
    assert PUBLICATION_MODULE in blueprint_imports
    tree = ast.parse(PUBLICATION_PATH.read_text(), filename=str(PUBLICATION_PATH))
    proof_imports = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == PROOF_MODULE
    ]
    assert len(proof_imports) == 1
    assert all(alias.name != "*" for alias in proof_imports[0].names)


def test_no_wildcard_or_dynamic_import_and_no_code_execution():
    for path in (PUBLICATION_PATH, BLUEPRINT_PATH):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert all(alias.name != "*" for alias in node.names)
                assert node.module != "importlib"
            elif isinstance(node, ast.Import):
                assert all(alias.name != "importlib" for alias in node.names)
            elif isinstance(node, ast.Call):
                assert _dotted_name(node.func) not in {
                    "__import__", "eval", "exec", "importlib.import_module",
                    "import_module",
                }


def test_publication_service_has_no_forbidden_executable_dependency_or_call():
    tree = ast.parse(PUBLICATION_PATH.read_text(), filename=str(PUBLICATION_PATH))
    for module, _ in _imports(PUBLICATION_PATH):
        assert not (_module_parts(module) & FORBIDDEN_IMPORT_PARTS), module
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = _dotted_name(node.func).lower()
        assert called not in FORBIDDEN_CALLS
        assert not any(called.startswith(f"{name}.") for name in (
            "subprocess", "requests", "httpx",
        ))
        if isinstance(node.func, ast.Attribute) and node.func.attr == "replace":
            assert _dotted_name(node.func.value) not in {
                "path", "_artifact_directory",
            }


def test_agent_is_discovery_only():
    agent_path = ROOT / "app/blueprints/agent.py"
    imported = {module for module, _ in _imports(agent_path)}
    assert PROOF_MODULE not in imported
    assert PUBLICATION_MODULE not in imported


def test_no_second_blueprint_mcp_or_sensitive_runtime_consumer():
    for path in _runtime_python_files():
        if path in {
            APPROVED_PROOF_CONSUMER,
            APPROVED_PUBLICATION_CONSUMER,
            RESOLVER_PATH,
            COMPOSER_PATH,
        }:
            continue
        imported = {module for module, _ in _imports(path)}
        assert PROOF_MODULE not in imported, path
        assert PUBLICATION_MODULE not in imported, path

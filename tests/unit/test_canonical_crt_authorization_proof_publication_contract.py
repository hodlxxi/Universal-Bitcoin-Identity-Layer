import ast
from pathlib import Path


ROOT = Path(__file__).parents[2]
SERVICE_IMPORT = "canonical_crt_authorization_proof"
POLICY_MODULE = "app.services.canonical_crt_authorization_policy"
MEMBERSHIP_MODULE = "app.services.canonical_crt_membership"
POLICY_SYMBOLS = {
    "CanonicalCrtAuthorizationClass",
    "CanonicalCrtAuthorizationEvaluation",
    "CanonicalCrtAuthorizationReason",
    "canonical_crt_authorization_evaluation_bytes",
    "canonical_crt_authorization_evaluation_sha256",
    "parse_canonical_crt_authorization_evaluation",
}


def _constant_string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_string(node.left)
        right = _constant_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def test_no_public_or_runtime_consumer():
    forbidden_roots = (
        ROOT / "app/blueprints",
        ROOT / "packages/hodlxxi_mcp",
    )
    for directory in forbidden_roots:
        for path in directory.rglob("*.py"):
            assert SERVICE_IMPORT not in path.read_text(errors="ignore")


def test_no_model_migration_cli_or_scheduler_was_added():
    changed_service = ROOT / "app/services/canonical_crt_authorization_proof.py"
    text = changed_service.read_text()
    for forbidden in (
        "import sqlalchemy", "from sqlalchemy", "import flask", "from flask",
        "import subprocess", "from subprocess", "import requests",
        "from requests",
    ):
        assert forbidden not in text.lower()

    tree = ast.parse(text, filename=str(changed_service))
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imports.setdefault(node.module or "", []).extend(node.names)
        elif isinstance(node, ast.Import):
            assert all(alias.name != "importlib" for alias in node.names)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {
                "import_module", "__import__", "exec", "eval",
            }
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            value = _constant_string(node)
            assert not (
                isinstance(value, str)
                and value.startswith("app.services.canonical_crt_")
            )

    assert "importlib" not in imports
    assert MEMBERSHIP_MODULE in imports
    assert POLICY_MODULE in imports
    assert {alias.name for alias in imports[POLICY_MODULE]} == POLICY_SYMBOLS
    assert all(alias.name != "*" for alias in imports[POLICY_MODULE])

    import app.services.canonical_crt_authorization_policy as policy
    import app.services.canonical_crt_authorization_proof as proof

    for name in POLICY_SYMBOLS:
        assert getattr(proof, name) is getattr(policy, name)

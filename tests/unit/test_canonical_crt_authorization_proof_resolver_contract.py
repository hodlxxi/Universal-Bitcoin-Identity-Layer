import ast
from pathlib import Path

MODULE = Path("app/services/canonical_crt_authorization_proof_resolver.py")
APPROVED = {
    "app.services.canonical_genesis_record",
    "app.services.canonical_sponsor_lineage",
    "app.services.canonical_crt_membership",
    "app.services.canonical_crt_authorization_policy",
    "app.services.canonical_crt_authorization_proof",
}
SEQUENCE = (
    "evaluate_canonical_genesis",
    "evaluate_canonical_sponsor_lineage",
    "evaluate_canonical_crt_membership",
    "evaluate_canonical_crt_authorization",
    "build_canonical_crt_authorization_proof",
    "canonical_crt_authorization_proof_bytes",
    "parse_canonical_crt_authorization_proof",
)


def _tree():
    return ast.parse(MODULE.read_text(), filename=str(MODULE))


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def test_imports_are_only_standard_library_and_approved_domain_modules():
    for node in ast.walk(_tree()):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("app."):
            assert node.module in APPROVED
            assert all(alias.name != "*" for alias in node.names)
        elif isinstance(node, ast.Import):
            assert all(not alias.name.startswith("app.") for alias in node.names)


def test_authoritative_calls_are_structurally_present_in_order():
    resolver = next(
        node
        for node in _tree().body
        if isinstance(node, ast.FunctionDef) and node.name == "resolve_canonical_crt_authorization_proof_from_snapshot"
    )
    calls = [_dotted(node.func) for node in ast.walk(resolver) if isinstance(node, ast.Call)]
    for name in SEQUENCE:
        assert name in calls
    assert calls.index("evaluate_canonical_genesis") < calls.index("evaluate_canonical_crt_membership")
    assert calls.index("evaluate_canonical_crt_membership") < calls.index("evaluate_canonical_crt_authorization")
    assert calls.index("evaluate_canonical_crt_authorization") < calls.index("build_canonical_crt_authorization_proof")


def test_no_dynamic_import_write_publication_or_runtime_adapter_structure():
    forbidden_calls = {
        "__import__",
        "compile",
        "eval",
        "exec",
        "open",
        "setattr",
        "delattr",
        "write",
        "write_text",
        "write_bytes",
        "request",
        "urlopen",
        "connect",
        "commit",
        "flush",
        "add",
        "delete",
    }
    forbidden_nodes = (ast.AsyncFunctionDef, ast.Await, ast.Yield, ast.YieldFrom, ast.Delete, ast.Global, ast.Nonlocal)
    assert not any(isinstance(node, forbidden_nodes) for node in ast.walk(_tree()))
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Call):
            called = _dotted(node.func)
            assert called not in forbidden_calls
            assert called.split(".")[-1] not in {
                "write",
                "write_text",
                "write_bytes",
                "request",
                "urlopen",
                "connect",
                "commit",
                "flush",
                "add",
                "delete",
            }

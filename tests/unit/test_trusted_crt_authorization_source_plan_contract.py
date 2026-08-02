import ast
from pathlib import Path


PATH = Path("app/services/trusted_crt_authorization_source_plan.py")


def test_static_dependency_and_read_only_contract():
    tree = ast.parse(PATH.read_text())
    imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imports |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    forbidden = ("flask", "sqlalchemy", "app.models", "app.db_storage", "subprocess", "socket", "requests", "urllib", "http", "canonical_crt_authorization_proof_resolver", "current_entitlement")
    assert not any(name == item or name.startswith(item + ".") for name in imports for item in forbidden)
    assert not any("_storage" in name for name in imports)
    service_imports = {name for name in imports if name.startswith("app.services.")}
    assert service_imports == {
        "app.services.canonical_admission_edge",
        "app.services.canonical_genesis_record",
        "app.services.trusted_covenant_registration",
    }
    repository_calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr.endswith("_repository")
    }
    assert repository_calls == {"get", "list_for_graph"}
    assert repository_calls.isdisjoint({"append", "add", "delete", "update", "commit", "flush", "rollback"})
    assert not any(isinstance(node, (ast.Import, ast.ImportFrom)) and any(alias.name == "importlib" for alias in node.names) for node in ast.walk(tree))
    called_names = {
        node.func.id for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert {"eval", "exec", "__import__"}.isdisjoint(called_names)
    assert not any("observer" in name.lower() or "rpc" in name.lower() for name in called_names)

import ast
from pathlib import Path

from app.services.trusted_crt_bitcoin_observation_snapshot import EXPLICIT_NON_CLAIMS, STATUS

PATH = Path("app/services/trusted_crt_bitcoin_observation_snapshot.py")


def test_static_dependency_rpc_and_surface_contract():
    tree = ast.parse(PATH.read_text())
    imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imports |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    allowed_services = {
        "app.services.trusted_crt_authorization_source_plan",
        "app.services.trusted_covenant_registration",
        "app.services.trusted_covenant_observation",
        "app.services.covenant_relation",
    }
    assert {x for x in imports if x.startswith("app.services.")} == allowed_services
    forbidden = ("flask", "sqlalchemy", "app.models", "app.db_storage", "subprocess", "socket",
                 "requests", "urllib", "http", "current_entitlement", "action_authorization",
                 "canonical_crt_authorization_proof_resolver")
    assert not any(name == item or name.startswith(item + ".") for name in imports for item in forbidden)
    assert not any("storage" in name for name in imports)
    called_attrs = {node.func.attr for node in ast.walk(tree)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    rpc_like = {name for name in called_attrs if name.startswith(("getblock", "getbestblock", "gettxout"))}
    assert rpc_like == {"getblockcount", "getbestblockhash", "getblockhash", "gettxout"}
    forbidden_calls = {"listunspent", "scantxoutset", "importdescriptor", "importmulti",
                       "sendrawtransaction", "signrawtransaction", "getrawtransaction",
                       "eval", "exec", "__import__"}
    called_names = {node.func.id for node in ast.walk(tree)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert forbidden_calls.isdisjoint(called_attrs | called_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "app.services.trusted_covenant_observation":
            assert all(not alias.name.startswith("_") for alias in node.names)
    source = PATH.read_text().lower()
    assert not any(token in source for token in ("@app.route", "mcp.tool", "argparse", "click.command", "scheduler.add"))


def test_documentation_exact_status_and_nonclaims():
    text = Path("docs/TRUSTED_CRT_BITCOIN_OBSERVATION_SNAPSHOT_V1.md").read_text()
    assert all(value in text for value in STATUS)
    assert all(value in text for value in EXPLICIT_NON_CLAIMS)
    assert len(EXPLICIT_NON_CLAIMS) == 36

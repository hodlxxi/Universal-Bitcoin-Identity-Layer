import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_INIT_PATH = PROJECT_ROOT / "scripts" / "db_init.py"


def test_db_init_does_not_load_dotenv_implicitly():
    source = DB_INIT_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    dotenv_imports = []
    dotenv_calls = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == "dotenv":
                dotenv_imports.append(node.lineno)

        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "dotenv":
                    dotenv_imports.append(node.lineno)

        elif isinstance(node, ast.Call):
            function = node.func

            if isinstance(function, ast.Name) and function.id in {
                "load_dotenv",
                "find_dotenv",
                "dotenv_values",
            }:
                dotenv_calls.append(node.lineno)

            elif isinstance(function, ast.Attribute) and function.attr in {
                "load_dotenv",
                "find_dotenv",
                "dotenv_values",
            }:
                dotenv_calls.append(node.lineno)

    assert dotenv_imports == []
    assert dotenv_calls == []

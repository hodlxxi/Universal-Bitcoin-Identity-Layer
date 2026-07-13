import json
from pathlib import Path

from app.services.mcp_discovery import (
    MCP_ENDPOINT_PATH,
    MCP_SERVER_NAME,
    MCP_SERVER_VERSION,
    MCP_TRANSPORT_TYPE,
)


ROOT = Path(__file__).resolve().parents[2]
SERVER_JSON = ROOT / "server.json"


def _metadata() -> dict[str, object]:
    return json.loads(SERVER_JSON.read_text(encoding="utf-8"))


def test_registry_metadata_matches_public_mcp_contract() -> None:
    metadata = _metadata()

    assert metadata["$schema"] == (
        "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
    )
    assert metadata["name"] == "io.github.hodlxxi/hodlxxi-readonly"
    assert metadata["title"] == MCP_SERVER_NAME
    assert metadata["version"] == MCP_SERVER_VERSION
    assert metadata["websiteUrl"] == "https://hodlxxi.com"
    assert metadata["remotes"] == [
        {
            "type": MCP_TRANSPORT_TYPE.replace("_", "-"),
            "url": f"https://hodlxxi.com{MCP_ENDPOINT_PATH}",
        }
    ]


def test_registry_metadata_points_to_canonical_repository() -> None:
    repository = _metadata()["repository"]

    assert repository == {
        "url": "https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer",
        "source": "github",
        "subfolder": "packages/hodlxxi_mcp",
    }


def test_registry_metadata_advertises_remote_only() -> None:
    metadata = _metadata()

    assert "packages" not in metadata
    assert "environmentVariables" not in json.dumps(metadata)
    assert "headers" not in json.dumps(metadata)

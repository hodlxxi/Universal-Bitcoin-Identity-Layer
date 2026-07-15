from __future__ import annotations

import json
import ssl
from pathlib import Path

import pytest

from scripts import mcp_remote_verify as verifier


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b"", lines=None):
        self.status = status
        self.headers = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
        self.body = body
        self.lines = list(lines or [])
        self.read_calls = 0
        self.readline_calls = 0
        self.closed = False

    def read(self, size=-1):
        self.read_calls += 1
        if size >= 0:
            return self.body[:size]
        return self.body

    def readline(self, size=-1):
        self.readline_calls += 1
        if not self.lines:
            return b""
        return self.lines.pop(0)

    def close(self):
        self.closed = True


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, *, method, url, headers, body, timeout):
        self.requests.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout,
            }
        )
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def rpc_result(request_id, result):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def rpc_error(request_id, code=-32000, message="boom"):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def json_response(payload, *, headers=None, status=200):
    response_headers = {"content-type": "application/json"}
    response_headers.update(headers or {})
    return FakeResponse(status=status, headers=response_headers, body=json.dumps(payload).encode("utf-8"))


def sse_response(*payloads, status=200):
    lines = []
    for payload in payloads:
        if isinstance(payload, str):
            text = payload
        else:
            text = json.dumps(payload)
        for part in text.splitlines() or [""]:
            lines.append(f"data: {part}\n".encode("utf-8"))
        lines.append(b"\n")
    return FakeResponse(status=status, headers={"content-type": "text/event-stream"}, lines=lines)


def build_tool_entries(*, replacement=None, duplicate=None, stale_name=None):
    contract = verifier.load_canonical_contract()
    names = list(contract.tool_names)
    if replacement:
        names[-1] = replacement
    if duplicate:
        names[-1] = duplicate
    entries = []
    for name in names:
        description = f"{name} description"
        if name == stale_name:
            description = "disabled production stub"
        entries.append({"name": name, "description": description})
    return entries


def build_success_transport(
    *,
    get_probe=None,
    tool_pages=None,
    prompts=None,
    resources=None,
    safe_call_overrides=None,
    session_id="session-123",
    initialize_payload=None,
):
    contract = verifier.load_canonical_contract()
    init_result = initialize_payload or {
        "protocolVersion": contract.protocol_version,
        "serverInfo": {"name": contract.server_name, "version": contract.server_version},
        "capabilities": {"tools": {"listChanged": False}},
    }
    pages = tool_pages or [build_tool_entries()]
    responses = [
        get_probe or FakeResponse(status=405, headers={"content-type": "text/plain"}),
        json_response(rpc_result(1, init_result), headers={"MCP-Session-Id": session_id}),
        FakeResponse(status=202, headers={"content-type": "application/json"}),
    ]
    request_id = 10
    for index, page in enumerate(pages):
        result = {"tools": page}
        if index < len(pages) - 1:
            result["nextCursor"] = f"cursor-{index + 1}"
        responses.append(json_response(rpc_result(request_id, result)))
        request_id += 1
    responses.append(json_response(rpc_result(1001, {"prompts": prompts or []})))
    responses.append(json_response(rpc_result(1002, {"resources": resources or []})))
    overrides = safe_call_overrides or {}
    for offset, name in enumerate(verifier.SAFE_REQUIRED_TOOLS, start=2000):
        tool_result = overrides.get(
            name,
            {"content": [{"type": "text", "text": "{}"}], "structuredContent": {"ok": True}, "isError": False},
        )
        responses.append(json_response(rpc_result(offset, tool_result)))
    responses.append(FakeResponse(status=204, headers={"content-type": "application/json"}))
    return FakeTransport(responses)


def mismatch_report():
    report = verifier.verify_remote_mcp(transport=build_success_transport())
    report.status = "MISMATCH"
    report.failures = [verifier.FailureRecord(category="mismatch", message="forced mismatch")]
    return report


def test_successful_exact_verification():
    transport = build_success_transport()
    report = verifier.verify_remote_mcp(transport=transport)

    contract = verifier.load_canonical_contract()
    assert report.status == "VERIFIED"
    assert report.initialize["negotiated_protocol_version"] == contract.protocol_version
    assert report.initialize["server_name"] == contract.server_name
    assert report.initialize["server_version"] == contract.server_version
    assert report.protocol_header_used is True
    assert report.session_header_used is True
    assert report.tool_count == contract.tool_count
    assert report.unique_tool_count == contract.tool_count
    assert set(report.tool_names) == set(contract.tool_names)
    assert report.missing_tools == []
    assert report.unexpected_tools == []

    for request in transport.requests[2:]:
        if request["method"] != "POST":
            continue
        assert request["headers"]["MCP-Protocol-Version"] == contract.protocol_version
        assert request["headers"]["MCP-Session-Id"] == "session-123"


def test_canonical_inventory_synchronization():
    contract = verifier.load_canonical_contract()

    assert len(contract.tool_names) == contract.tool_count
    assert len(set(contract.tool_names)) == contract.tool_count
    assert "hodlxxi_get_mcp_server_card" in contract.tool_names


def test_get_probe_accepts_sse_without_reading_to_eof():
    get_probe = FakeResponse(
        status=200,
        headers={"content-type": "text/event-stream"},
        lines=[b"data: this should never be consumed\n", b"\n"],
    )
    transport = build_success_transport(get_probe=get_probe)

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "VERIFIED"
    assert get_probe.read_calls == 0
    assert get_probe.readline_calls == 0


def test_tools_list_pagination():
    page_a = build_tool_entries()[:13]
    page_b = build_tool_entries()[13:]
    transport = build_success_transport(tool_pages=[page_a, page_b])

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "VERIFIED"
    assert report.page_count == 2
    assert report.tool_count == 26


def test_cursor_loop_fails_verification():
    contract = verifier.load_canonical_contract()
    transport = FakeTransport(
        [
            FakeResponse(status=405, headers={"content-type": "text/plain"}),
            json_response(
                rpc_result(
                    1,
                    {
                        "protocolVersion": contract.protocol_version,
                        "serverInfo": {"name": contract.server_name, "version": contract.server_version},
                        "capabilities": {"tools": {"listChanged": False}},
                    },
                ),
                headers={"MCP-Session-Id": "loop"},
            ),
            FakeResponse(status=202, headers={"content-type": "application/json"}),
            json_response(rpc_result(10, {"tools": build_tool_entries()[:13], "nextCursor": "same"})),
            json_response(rpc_result(11, {"tools": build_tool_entries()[13:], "nextCursor": "same"})),
        ]
    )

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "MISMATCH"
    assert report.failures[0].category == "protocol"
    assert "cursor loop" in report.failures[0].message


def test_maximum_page_protection():
    transport = build_success_transport(tool_pages=[build_tool_entries()])
    transport.responses[3] = json_response(rpc_result(10, {"tools": build_tool_entries()[:13], "nextCursor": "next"}))

    report = verifier.verify_remote_mcp(transport=transport, max_pages=1)

    assert report.status == "MISMATCH"
    assert "maximum page count" in report.failures[0].message


def test_duplicate_tools_fail():
    duplicate_name = verifier.load_canonical_contract().tool_names[0]
    transport = build_success_transport(tool_pages=[build_tool_entries(duplicate=duplicate_name)])

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "MISMATCH"
    assert duplicate_name in report.duplicate_tool_names
    assert report.unique_tool_count == 25


def test_missing_tools_fail():
    transport = build_success_transport(tool_pages=[build_tool_entries(replacement="hodlxxi_post_request")])

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "MISMATCH"
    assert report.tool_count == 26
    assert "hodlxxi_post_request" in report.unexpected_tools
    assert report.missing_tools


def test_prompts_exposure_fails():
    transport = build_success_transport(prompts=[{"name": "unsafe"}])

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "MISMATCH"
    assert report.prompts_exposed is True
    assert report.prompt_count == 1


def test_resources_exposure_fails():
    transport = build_success_transport(resources=[{"name": "secret"}])

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "MISMATCH"
    assert report.resources_exposed is True
    assert report.resource_count == 1


def test_stale_descriptions_fail():
    transport = build_success_transport(tool_pages=[build_tool_entries(stale_name="hodlxxi_get_chain_health")])

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "MISMATCH"
    assert report.stale_description_tools == ["hodlxxi_get_chain_health"]


def test_required_tool_is_error_fails():
    overrides = {
        "hodlxxi_get_chain_health": {
            "content": [{"type": "text", "text": "{}"}],
            "structuredContent": {"ok": False},
            "isError": True,
        }
    }
    transport = build_success_transport(safe_call_overrides=overrides)

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "MISMATCH"
    assert report.failures[0].category == "protocol"
    assert "isError=true" in report.failures[0].message


def test_jsonrpc_error_fails():
    transport = build_success_transport()
    transport.responses[3] = json_response(rpc_error(10))

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "MISMATCH"
    assert report.failures[0].category == "jsonrpc"


def test_mismatched_response_id_fails():
    contract = verifier.load_canonical_contract()
    transport = FakeTransport(
        [
            FakeResponse(status=405, headers={"content-type": "text/plain"}),
            json_response(
                {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "result": {
                        "protocolVersion": contract.protocol_version,
                        "serverInfo": {"name": contract.server_name, "version": contract.server_version},
                        "capabilities": {"tools": {"listChanged": False}},
                    },
                },
                headers={"MCP-Session-Id": "bad"},
            ),
        ]
    )

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "MISMATCH"
    assert report.failures[0].category == "protocol"
    assert "response id" in report.failures[0].message


def test_malformed_json_fails():
    transport = FakeTransport(
        [
            FakeResponse(status=405, headers={"content-type": "text/plain"}),
            FakeResponse(
                status=200,
                headers={"content-type": "application/json", "MCP-Session-Id": "bad"},
                body=b"{",
            ),
        ]
    )

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "MISMATCH"
    assert report.failures[0].category == "malformed_json"


def test_malformed_sse_fails():
    contract = verifier.load_canonical_contract()
    transport = FakeTransport(
        [
            FakeResponse(status=405, headers={"content-type": "text/plain"}),
            json_response(
                rpc_result(
                    1,
                    {
                        "protocolVersion": contract.protocol_version,
                        "serverInfo": {"name": contract.server_name, "version": contract.server_version},
                        "capabilities": {"tools": {"listChanged": False}},
                    },
                ),
                headers={"MCP-Session-Id": "sse"},
            ),
            FakeResponse(status=202, headers={"content-type": "application/json"}),
            FakeResponse(status=200, headers={"content-type": "text/event-stream"}, lines=[b"bad-line\n", b"\n"]),
        ]
    )

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "MISMATCH"
    assert report.failures[0].category == "malformed_sse"


@pytest.mark.parametrize(
    ("error", "category"),
    [
        (verifier.VerificationError("timeout", "timed out"), "timeout"),
        (verifier.VerificationError("dns", "lookup failed"), "dns"),
        (verifier.VerificationError("tls", "tls failed"), "tls"),
        (verifier.VerificationError("network", "connection failed"), "network"),
    ],
)
def test_transport_failure_classification(error, category):
    transport = FakeTransport([error])

    report = verifier.verify_remote_mcp(transport=transport)

    assert report.status == "BLOCKED"
    assert report.failures[0].category == category


def test_json_and_markdown_report_generation(tmp_path, monkeypatch):
    report = verifier.verify_remote_mcp(transport=build_success_transport())
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"
    monkeypatch.setattr(verifier, "verify_remote_mcp", lambda **_: report)

    exit_code = verifier.main(["--json-output", str(json_path), "--markdown-output", str(markdown_path)])

    assert exit_code == 0
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["status"] == "VERIFIED"
    assert markdown_path.read_text(encoding="utf-8").startswith("# MCP Remote Verification")


def test_cli_returns_nonzero_for_mismatch(monkeypatch):
    report = mismatch_report()
    monkeypatch.setattr(verifier, "verify_remote_mcp", lambda **_: report)

    exit_code = verifier.main([])

    assert exit_code == 1

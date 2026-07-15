from __future__ import annotations

import argparse
import ast
import json
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol

DEFAULT_ENDPOINT = "https://hodlxxi.com/agent/mcp"
DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_PAGES = 50
MAX_BODY_BYTES = 2_000_000
MAX_DESCRIPTION_CHARS = 240
MAX_SUMMARY_CHARS = 240
USER_AGENT = "hodlxxi-production-truth-verifier/1.0"
SAFE_REQUIRED_TOOLS = (
    "hodlxxi_get_mcp_server_card",
    "hodlxxi_get_capabilities",
    "hodlxxi_get_chain_health",
    "hodlxxi_get_reputation",
)
STALE_DESCRIPTION_PHRASES = (
    "disabled production stub",
    "public transport is disabled",
    "no live /agent/mcp integration",
)
SUSPICIOUS_TOOL_PATTERNS = (
    "wallet",
    "lnd",
    "invoice",
    "payment",
    "publish",
    "write",
    "create",
    "update",
    "delete",
    "shell",
    "filesystem",
    "database",
    "mutate",
    "post_request",
)
SUSPICIOUS_TOOL_EXCEPTIONS = {
    "hodlxxi_get_receipt",
    "hodlxxi_verify_receipt",
}


@dataclass(frozen=True)
class CanonicalContract:
    server_name: str
    server_version: str
    protocol_version: str
    tool_count: int
    tool_names: tuple[str, ...]


@dataclass
class FailureRecord:
    category: str
    message: str


@dataclass
class VerificationReport:
    endpoint: str
    expected_server_name: str
    expected_server_version: str
    expected_protocol_version: str
    canonical_tool_count: int
    canonical_tool_names: list[str]
    status: str = "BLOCKED"
    get_probe: dict[str, Any] = field(default_factory=dict)
    initialize: dict[str, Any] = field(default_factory=dict)
    protocol_header_used: bool = False
    session_header_used: bool = False
    page_count: int = 0
    tool_count: int = 0
    unique_tool_count: int = 0
    duplicate_tool_names: list[str] = field(default_factory=list)
    missing_tools: list[str] = field(default_factory=list)
    unexpected_tools: list[str] = field(default_factory=list)
    suspicious_tools: list[str] = field(default_factory=list)
    stale_description_tools: list[str] = field(default_factory=list)
    tool_names: list[str] = field(default_factory=list)
    live_tool_descriptions: dict[str, str] = field(default_factory=dict)
    prompts_exposed: bool = False
    prompts_capability_advertised: bool = False
    prompt_count: int = 0
    resources_exposed: bool = False
    resources_capability_advertised: bool = False
    resource_count: int = 0
    required_calls: dict[str, dict[str, Any]] = field(default_factory=dict)
    failures: list[FailureRecord] = field(default_factory=list)
    cleanup: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["failures"] = [asdict(item) for item in self.failures]
        return data


class VerificationError(Exception):
    def __init__(self, category: str, message: str, *, http_status: int | None = None) -> None:
        super().__init__(message)
        self.category = category
        self.message = message
        self.http_status = http_status


class ResponseHandle(Protocol):
    status: int
    headers: Mapping[str, str]

    def read(self, size: int = -1) -> bytes: ...

    def readline(self, size: int = -1) -> bytes: ...

    def close(self) -> None: ...


class HTTPTransport(Protocol):
    def open(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> ResponseHandle: ...


class URLLibResponseHandle:
    def __init__(self, response: Any) -> None:
        self._response = response
        self.status = int(getattr(response, "status", getattr(response, "code")))
        self.headers = {str(key).lower(): str(value) for key, value in response.headers.items()}

    def read(self, size: int = -1) -> bytes:
        return self._response.read(size)

    def readline(self, size: int = -1) -> bytes:
        return self._response.readline(size)

    def close(self) -> None:
        self._response.close()


class StdlibHTTPTransport:
    def __init__(self) -> None:
        self._opener = urllib.request.build_opener()

    def open(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> ResponseHandle:
        request = urllib.request.Request(url=url, data=body, headers=dict(headers), method=method)
        try:
            response = self._opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            return URLLibResponseHandle(exc)
        except urllib.error.URLError as exc:
            raise _classify_url_error(exc) from exc
        except ssl.SSLError as exc:
            raise VerificationError("tls", _exc_message(exc)) from exc
        except socket.timeout as exc:
            raise VerificationError("timeout", _exc_message(exc)) from exc
        except TimeoutError as exc:
            raise VerificationError("timeout", _exc_message(exc)) from exc
        except OSError as exc:
            raise _classify_os_error(exc) from exc
        return URLLibResponseHandle(response)


def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_canonical_contract(root: Path | None = None) -> CanonicalContract:
    repo_root = root or repository_root()
    tools_path = repo_root / "packages" / "hodlxxi_mcp" / "src" / "hodlxxi_mcp" / "tools.py"
    init_path = repo_root / "packages" / "hodlxxi_mcp" / "src" / "hodlxxi_mcp" / "__init__.py"
    discovery_path = repo_root / "app" / "services" / "mcp_discovery.py"

    tool_names_value = _load_assignment_literal(tools_path, "TOOL_NAMES")
    init_version = _load_assignment_literal(init_path, "__version__")
    discovery_values = _load_assignment_literals(
        discovery_path,
        {"MCP_SERVER_NAME", "MCP_SERVER_VERSION", "MCP_PROTOCOL_VERSION", "MCP_TOOL_COUNT"},
    )

    if not isinstance(tool_names_value, tuple) or not all(isinstance(item, str) for item in tool_names_value):
        raise ValueError(f"{tools_path} TOOL_NAMES must be a tuple of strings")
    if not isinstance(init_version, str):
        raise ValueError(f"{init_path} __version__ must be a string literal")

    server_name = discovery_values["MCP_SERVER_NAME"]
    discovery_version = discovery_values["MCP_SERVER_VERSION"]
    protocol_version = discovery_values["MCP_PROTOCOL_VERSION"]
    tool_count = discovery_values["MCP_TOOL_COUNT"]

    if not isinstance(server_name, str):
        raise ValueError("MCP_SERVER_NAME must be a string literal")
    if not isinstance(discovery_version, str):
        raise ValueError("MCP_SERVER_VERSION must be a string literal")
    if not isinstance(protocol_version, str):
        raise ValueError("MCP_PROTOCOL_VERSION must be a string literal")
    if not isinstance(tool_count, int):
        raise ValueError("MCP_TOOL_COUNT must be an integer literal")
    if init_version != discovery_version:
        raise ValueError(
            f"Version mismatch between __init__.py ({init_version}) and mcp_discovery.py ({discovery_version})"
        )
    if len(tool_names_value) != tool_count:
        raise ValueError(f"TOOL_NAMES count {len(tool_names_value)} does not match MCP_TOOL_COUNT {tool_count}")

    return CanonicalContract(
        server_name=server_name,
        server_version=init_version,
        protocol_version=protocol_version,
        tool_count=tool_count,
        tool_names=tuple(tool_names_value),
    )


def verify_remote_mcp(
    *,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: float = DEFAULT_TIMEOUT,
    transport: HTTPTransport | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    root: Path | None = None,
) -> VerificationReport:
    contract = load_canonical_contract(root)
    report = VerificationReport(
        endpoint=endpoint,
        expected_server_name=contract.server_name,
        expected_server_version=contract.server_version,
        expected_protocol_version=contract.protocol_version,
        canonical_tool_count=contract.tool_count,
        canonical_tool_names=list(contract.tool_names),
    )
    http = transport or StdlibHTTPTransport()
    session_id: str | None = None
    negotiated_protocol = contract.protocol_version

    try:
        _perform_get_probe(report, http=http, endpoint=endpoint, timeout=timeout)

        init_response, init_headers = _jsonrpc_request(
            http=http,
            endpoint=endpoint,
            timeout=timeout,
            request_id=1,
            method="initialize",
            params={
                "protocolVersion": contract.protocol_version,
                "capabilities": {},
                "clientInfo": {
                    "name": "hodlxxi-production-truth-verifier",
                    "version": "1.0.0",
                },
            },
            protocol_version=None,
            session_id=None,
        )
        init_result = _require_jsonrpc_result(init_response, method="initialize")
        negotiated_protocol = _expect_string(
            init_result.get("protocolVersion"),
            label="initialize.result.protocolVersion",
        )
        server_info = _expect_mapping(init_result.get("serverInfo"), label="initialize.result.serverInfo")
        capabilities = _expect_mapping(init_result.get("capabilities"), label="initialize.result.capabilities")
        session_id = init_headers.get("mcp-session-id")
        report.prompts_capability_advertised = "prompts" in capabilities
        report.resources_capability_advertised = "resources" in capabilities
        report.initialize = {
            "negotiated_protocol_version": negotiated_protocol,
            "server_name": _expect_string(server_info.get("name"), label="initialize.result.serverInfo.name"),
            "server_version": _expect_string(server_info.get("version"), label="initialize.result.serverInfo.version"),
            "capabilities": _truncate_object(capabilities),
            "session_id_present": bool(session_id),
        }

        report.protocol_header_used = True
        report.session_header_used = bool(session_id)
        _post_notification(
            http=http,
            endpoint=endpoint,
            timeout=timeout,
            method="notifications/initialized",
            params={},
            protocol_version=negotiated_protocol,
            session_id=session_id,
        )

        tool_result = _collect_tools(
            report=report,
            http=http,
            endpoint=endpoint,
            timeout=timeout,
            protocol_version=negotiated_protocol,
            session_id=session_id,
            max_pages=max_pages,
            canonical_tool_names=set(contract.tool_names),
        )
        report.page_count = tool_result["page_count"]
        report.tool_names = tool_result["tool_names"]
        report.tool_count = len(report.tool_names)
        report.unique_tool_count = len(set(report.tool_names))
        report.duplicate_tool_names = sorted(tool_result["duplicate_tool_names"])
        report.missing_tools = sorted(set(contract.tool_names) - set(report.tool_names))
        report.unexpected_tools = sorted(set(report.tool_names) - set(contract.tool_names))
        report.live_tool_descriptions = tool_result["descriptions"]
        report.suspicious_tools = sorted(_find_suspicious_tools(report.tool_names))
        report.stale_description_tools = sorted(
            name
            for name, description in report.live_tool_descriptions.items()
            if any(phrase in description.lower() for phrase in STALE_DESCRIPTION_PHRASES)
        )

        prompt_info = _collect_optional_listing(
            http=http,
            endpoint=endpoint,
            timeout=timeout,
            method="prompts/list",
            result_key="prompts",
            request_id=1001,
            protocol_version=negotiated_protocol,
            session_id=session_id,
        )
        resource_info = _collect_optional_listing(
            http=http,
            endpoint=endpoint,
            timeout=timeout,
            method="resources/list",
            result_key="resources",
            request_id=1002,
            protocol_version=negotiated_protocol,
            session_id=session_id,
        )
        report.prompts_exposed = report.prompts_capability_advertised or prompt_info["count"] > 0
        report.prompt_count = prompt_info["count"]
        report.resources_exposed = report.resources_capability_advertised or resource_info["count"] > 0
        report.resource_count = resource_info["count"]

        for offset, tool_name in enumerate(SAFE_REQUIRED_TOOLS, start=2000):
            report.required_calls[tool_name] = _call_required_tool(
                http=http,
                endpoint=endpoint,
                timeout=timeout,
                tool_name=tool_name,
                request_id=offset,
                protocol_version=negotiated_protocol,
                session_id=session_id,
            )

        cleanup = _cleanup_session(
            http=http,
            endpoint=endpoint,
            timeout=timeout,
            protocol_version=negotiated_protocol,
            session_id=session_id,
        )
        report.cleanup = cleanup

        mismatches = _collect_mismatches(report=report, contract=contract)
        if mismatches:
            report.failures.extend(FailureRecord(category="mismatch", message=item) for item in mismatches)
            report.status = "MISMATCH"
        else:
            report.status = "VERIFIED"
    except VerificationError as exc:
        report.failures.append(FailureRecord(category=exc.category, message=exc.message))
        report.status = _status_for_error(exc)
    except Exception as exc:
        report.failures.append(FailureRecord(category="exception", message=_exc_message(exc)))
        report.status = "BLOCKED"
    return report


def _perform_get_probe(
    report: VerificationReport,
    *,
    http: HTTPTransport,
    endpoint: str,
    timeout: float,
) -> None:
    response = http.open(
        method="GET",
        url=endpoint,
        headers={"Accept": "text/event-stream", "User-Agent": USER_AGENT},
        body=None,
        timeout=timeout,
    )
    try:
        content_type = _content_type(response.headers)
        accepted = response.status == 405 or (200 <= response.status < 300 and content_type == "text/event-stream")
        report.get_probe = {
            "status_code": response.status,
            "content_type": content_type,
            "accepted": accepted,
            "body_read_to_eof": False,
        }
        if not accepted:
            raise VerificationError(
                "http",
                f"GET capability probe returned unexpected status/content-type: {response.status} {content_type or 'missing'}",
                http_status=response.status,
            )
    finally:
        response.close()


def _collect_tools(
    *,
    report: VerificationReport,
    http: HTTPTransport,
    endpoint: str,
    timeout: float,
    protocol_version: str,
    session_id: str | None,
    max_pages: int,
    canonical_tool_names: set[str],
) -> dict[str, Any]:
    cursor: str | None = None
    seen_cursors: set[str] = set()
    tool_names: list[str] = []
    descriptions: dict[str, str] = {}
    duplicate_tool_names: set[str] = set()
    page_count = 0

    for request_id in range(10, 10 + max_pages):
        params: dict[str, Any] = {}
        if cursor is not None:
            params["cursor"] = cursor
        response_obj, _ = _jsonrpc_request(
            http=http,
            endpoint=endpoint,
            timeout=timeout,
            request_id=request_id,
            method="tools/list",
            params=params,
            protocol_version=protocol_version,
            session_id=session_id,
        )
        result = _require_jsonrpc_result(response_obj, method="tools/list")
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise VerificationError("protocol", "tools/list result.tools must be a list")
        page_count += 1

        for item in tools:
            tool = _expect_mapping(item, label="tools/list.result.tools[]")
            name = _expect_string(tool.get("name"), label="tools/list.result.tools[].name")
            description = _expect_string(tool.get("description"), label=f"{name}.description")
            if name in descriptions:
                duplicate_tool_names.add(name)
            tool_names.append(name)
            descriptions[name] = _bounded_text(description, MAX_DESCRIPTION_CHARS)

        next_cursor = result.get("nextCursor")
        if next_cursor is None:
            break
        if not isinstance(next_cursor, str) or not next_cursor:
            raise VerificationError("protocol", "tools/list nextCursor must be a non-empty string when present")
        if next_cursor in seen_cursors:
            raise VerificationError("protocol", f"tools/list cursor loop detected at {next_cursor}")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    else:
        raise VerificationError("protocol", f"tools/list exceeded maximum page count of {max_pages}")

    missing = sorted(canonical_tool_names - set(tool_names))
    unexpected = sorted(set(tool_names) - canonical_tool_names)
    return {
        "page_count": page_count,
        "tool_names": tool_names,
        "duplicate_tool_names": duplicate_tool_names,
        "descriptions": descriptions,
        "missing": missing,
        "unexpected": unexpected,
    }


def _collect_optional_listing(
    *,
    http: HTTPTransport,
    endpoint: str,
    timeout: float,
    method: str,
    result_key: str,
    request_id: int,
    protocol_version: str,
    session_id: str | None,
) -> dict[str, Any]:
    response_obj, _ = _jsonrpc_request(
        http=http,
        endpoint=endpoint,
        timeout=timeout,
        request_id=request_id,
        method=method,
        params={},
        protocol_version=protocol_version,
        session_id=session_id,
    )
    error = response_obj.get("error")
    if isinstance(error, dict):
        code = error.get("code")
        message = str(error.get("message") or "")
        if code == -32601 or "method not found" in message.lower():
            return {"supported": False, "count": 0}
        raise VerificationError("jsonrpc", f"{method} returned JSON-RPC error {code}: {message}")
    result = _require_jsonrpc_result(response_obj, method=method)
    entries = result.get(result_key, [])
    if not isinstance(entries, list):
        raise VerificationError("protocol", f"{method} result.{result_key} must be a list")
    return {"supported": True, "count": len(entries)}


def _call_required_tool(
    *,
    http: HTTPTransport,
    endpoint: str,
    timeout: float,
    tool_name: str,
    request_id: int,
    protocol_version: str,
    session_id: str | None,
) -> dict[str, Any]:
    response_obj, _ = _jsonrpc_request(
        http=http,
        endpoint=endpoint,
        timeout=timeout,
        request_id=request_id,
        method="tools/call",
        params={"name": tool_name, "arguments": {}},
        protocol_version=protocol_version,
        session_id=session_id,
    )
    result = _require_jsonrpc_result(response_obj, method=f"tools/call:{tool_name}")
    if not isinstance(result, dict):
        raise VerificationError("protocol", f"tools/call result for {tool_name} must be an object")
    is_error = bool(result.get("isError") is True)
    if is_error:
        raise VerificationError("protocol", f"tools/call for {tool_name} returned isError=true")
    return {
        "ok": True,
        "isError": False,
        "summary": _summarize_tool_result(result),
    }


def _cleanup_session(
    *,
    http: HTTPTransport,
    endpoint: str,
    timeout: float,
    protocol_version: str,
    session_id: str | None,
) -> dict[str, Any]:
    if not session_id:
        return {"attempted": False}
    headers = {
        "MCP-Protocol-Version": protocol_version,
        "MCP-Session-Id": session_id,
        "User-Agent": USER_AGENT,
    }
    try:
        response = http.open(
            method="DELETE",
            url=endpoint,
            headers=headers,
            body=None,
            timeout=timeout,
        )
    except Exception as exc:
        return {
            "attempted": True,
            "ok": False,
            "error": _bounded_text(_exc_message(exc), MAX_SUMMARY_CHARS),
        }

    try:
        return {
            "attempted": True,
            "ok": 200 <= response.status < 300,
            "status_code": response.status,
        }
    finally:
        response.close()


def _collect_mismatches(report: VerificationReport, contract: CanonicalContract) -> list[str]:
    mismatches: list[str] = []
    initialize = report.initialize
    if initialize.get("negotiated_protocol_version") != contract.protocol_version:
        mismatches.append(
            f"Negotiated protocol {initialize.get('negotiated_protocol_version')} != expected {contract.protocol_version}"
        )
    if initialize.get("server_name") != contract.server_name:
        mismatches.append(f"Server name {initialize.get('server_name')} != expected {contract.server_name}")
    if initialize.get("server_version") != contract.server_version:
        mismatches.append(f"Server version {initialize.get('server_version')} != expected {contract.server_version}")
    if report.tool_count != contract.tool_count:
        mismatches.append(f"tools/list count {report.tool_count} != expected {contract.tool_count}")
    if report.unique_tool_count != contract.tool_count:
        mismatches.append(f"unique tool count {report.unique_tool_count} != expected {contract.tool_count}")
    if report.duplicate_tool_names:
        mismatches.append(f"Duplicate tool names present: {', '.join(report.duplicate_tool_names)}")
    if report.missing_tools:
        mismatches.append(f"Missing expected tools: {', '.join(report.missing_tools)}")
    if report.unexpected_tools:
        mismatches.append(f"Unexpected live tools: {', '.join(report.unexpected_tools)}")
    if report.prompts_capability_advertised:
        mismatches.append("initialize advertised prompts capability")
    if report.prompt_count > 0:
        mismatches.append(f"prompts exposed: count={report.prompt_count}")
    if report.resources_capability_advertised:
        mismatches.append("initialize advertised resources capability")
    if report.resource_count > 0:
        mismatches.append(f"resources exposed: count={report.resource_count}")
    if report.stale_description_tools:
        mismatches.append(f"Stale live tool descriptions: {', '.join(report.stale_description_tools)}")
    if report.suspicious_tools:
        mismatches.append(f"Suspicious live tools present: {', '.join(report.suspicious_tools)}")
    if not report.protocol_header_used:
        mismatches.append("MCP-Protocol-Version header was not reused after initialize")
    if report.initialize.get("session_id_present") and not report.session_header_used:
        mismatches.append("MCP-Session-Id header was not reused after initialize")
    for tool_name in SAFE_REQUIRED_TOOLS:
        if tool_name not in report.tool_names:
            mismatches.append(f"Required safe tool missing from live inventory: {tool_name}")
            continue
        call_result = report.required_calls.get(tool_name)
        if not call_result or not call_result.get("ok"):
            mismatches.append(f"Required safe call failed: {tool_name}")
    return mismatches


def _jsonrpc_request(
    *,
    http: HTTPTransport,
    endpoint: str,
    timeout: float,
    request_id: int,
    method: str,
    params: Mapping[str, Any],
    protocol_version: str | None,
    session_id: str | None,
) -> tuple[dict[str, Any], dict[str, str]]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    if protocol_version:
        headers["MCP-Protocol-Version"] = protocol_version
    if session_id:
        headers["MCP-Session-Id"] = session_id
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": dict(params),
        }
    ).encode("utf-8")
    response = http.open(method="POST", url=endpoint, headers=headers, body=body, timeout=timeout)
    try:
        if response.status < 200 or response.status >= 300:
            raise VerificationError(
                "http",
                f"{method} returned unexpected HTTP status {response.status}",
                http_status=response.status,
            )
        response_obj = _read_jsonrpc_response(response, request_id=request_id)
        return response_obj, dict(response.headers)
    finally:
        response.close()


def _post_notification(
    *,
    http: HTTPTransport,
    endpoint: str,
    timeout: float,
    method: str,
    params: Mapping[str, Any],
    protocol_version: str,
    session_id: str | None,
) -> None:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": protocol_version,
        "User-Agent": USER_AGENT,
    }
    if session_id:
        headers["MCP-Session-Id"] = session_id
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": method,
            "params": dict(params),
        }
    ).encode("utf-8")
    response = http.open(method="POST", url=endpoint, headers=headers, body=body, timeout=timeout)
    try:
        if response.status < 200 or response.status >= 300:
            raise VerificationError(
                "http",
                f"{method} returned unexpected HTTP status {response.status}",
                http_status=response.status,
            )
    finally:
        response.close()


def _read_jsonrpc_response(response: ResponseHandle, *, request_id: int) -> dict[str, Any]:
    content_type = _content_type(response.headers)
    if content_type == "text/event-stream":
        return _read_jsonrpc_from_sse(response, request_id=request_id)
    if content_type != "application/json":
        raise VerificationError("http", f"unexpected response content type: {content_type or 'missing'}")
    payload = _load_json_from_bytes(_read_limited(response), label="JSON-RPC response body")
    return _validate_jsonrpc_envelope(payload, request_id=request_id)


def _read_jsonrpc_from_sse(response: ResponseHandle, *, request_id: int) -> dict[str, Any]:
    for event_data in _iter_sse_data(response):
        if event_data == "[DONE]":
            continue
        payload = _load_json_from_text(event_data, label="SSE event data")
        if not isinstance(payload, dict):
            raise VerificationError("protocol", "SSE event JSON must be an object")
        if payload.get("id") != request_id:
            continue
        return _validate_jsonrpc_envelope(payload, request_id=request_id)
    raise VerificationError("malformed_sse", f"no JSON-RPC response matching request id {request_id}")


def _iter_sse_data(response: ResponseHandle) -> list[str]:
    events: list[str] = []
    data_lines: list[str] = []
    bytes_read = 0
    while True:
        chunk = response.readline()
        if chunk == b"":
            break
        bytes_read += len(chunk)
        if bytes_read > MAX_BODY_BYTES:
            raise VerificationError("http", f"SSE response exceeded {MAX_BODY_BYTES} bytes")
        try:
            line = chunk.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError("malformed_sse", "SSE response was not valid UTF-8") from exc
        line = line.rstrip("\r\n")
        if not line:
            if data_lines:
                events.append("\n".join(data_lines))
                data_lines = []
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if not separator:
            if field == "data":
                data_lines.append("")
                continue
            raise VerificationError("malformed_sse", f"malformed SSE line: {line}")
        if value.startswith(" "):
            value = value[1:]
        if field == "data":
            data_lines.append(value)
    if data_lines:
        events.append("\n".join(data_lines))
    return events


def _require_jsonrpc_result(payload: dict[str, Any], *, method: str) -> dict[str, Any]:
    error = payload.get("error")
    if error is not None:
        error_mapping = _expect_mapping(error, label=f"{method}.error")
        raise VerificationError(
            "jsonrpc",
            f"{method} returned JSON-RPC error {error_mapping.get('code')}: {error_mapping.get('message')}",
        )
    if "result" not in payload:
        raise VerificationError("protocol", f"{method} response did not include a result")
    result = payload["result"]
    return _expect_mapping(result, label=f"{method}.result")


def _validate_jsonrpc_envelope(payload: Any, *, request_id: int) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise VerificationError("protocol", "JSON-RPC payload must be an object")
    if payload.get("jsonrpc") != "2.0":
        raise VerificationError("protocol", f"jsonrpc field must be '2.0', got {payload.get('jsonrpc')!r}")
    if payload.get("id") != request_id:
        raise VerificationError("protocol", f"JSON-RPC response id {payload.get('id')!r} != request id {request_id!r}")
    if "error" not in payload and "result" not in payload:
        raise VerificationError("protocol", "JSON-RPC response must contain result or error")
    return payload


def _load_json_from_bytes(data: bytes, *, label: str) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("malformed_json", f"{label} was not valid UTF-8") from exc
    return _load_json_from_text(text, label=label)


def _load_json_from_text(text: str, *, label: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise VerificationError("malformed_json", f"{label} was not valid JSON") from exc


def _read_limited(response: ResponseHandle) -> bytes:
    payload = response.read(MAX_BODY_BYTES + 1)
    if len(payload) > MAX_BODY_BYTES:
        raise VerificationError("http", f"response exceeded {MAX_BODY_BYTES} bytes")
    return payload


def _content_type(headers: Mapping[str, str]) -> str:
    return str(headers.get("content-type", "")).split(";", 1)[0].strip().lower()


def _load_assignment_literal(path: Path, name: str) -> Any:
    values = _load_assignment_literals(path, {name})
    return values[name]


def _load_assignment_literals(path: Path, names: set[str]) -> dict[str, Any]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            value = ast.literal_eval(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in names:
                    found[target.id] = value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in names:
            found[node.target.id] = ast.literal_eval(node.value)
    missing = names - set(found)
    if missing:
        raise ValueError(f"Missing literal assignments {sorted(missing)} in {path}")
    return found


def _expect_mapping(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError("protocol", f"{label} must be an object")
    return value


def _expect_string(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationError("protocol", f"{label} must be a non-empty string")
    return value


def _summarize_tool_result(result: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {"keys": sorted(result)}
    if "structuredContent" in result and isinstance(result["structuredContent"], dict):
        summary["structured_content_keys"] = sorted(result["structuredContent"])[:12]
    if "content" in result and isinstance(result["content"], list):
        summary["content_items"] = len(result["content"])
        summary["content_types"] = sorted(
            {
                item.get("type")
                for item in result["content"]
                if isinstance(item, dict) and isinstance(item.get("type"), str)
            }
        )
    if "isError" in result:
        summary["isError"] = bool(result["isError"])
    return _truncate_object(summary)


def _truncate_object(value: Any, *, max_chars: int = MAX_SUMMARY_CHARS) -> Any:
    if isinstance(value, dict):
        return {str(key): _truncate_object(item, max_chars=max_chars) for key, item in value.items()}
    if isinstance(value, list):
        return [_truncate_object(item, max_chars=max_chars) for item in value[:20]]
    if isinstance(value, str):
        return _bounded_text(value, max_chars)
    return value


def _bounded_text(value: str, max_chars: int) -> str:
    text = value.replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _find_suspicious_tools(tool_names: list[str]) -> set[str]:
    suspicious: set[str] = set()
    for name in tool_names:
        lowered = name.lower()
        if name in SUSPICIOUS_TOOL_EXCEPTIONS:
            continue
        if any(pattern in lowered for pattern in SUSPICIOUS_TOOL_PATTERNS):
            suspicious.add(name)
    return suspicious


def _status_for_error(exc: VerificationError) -> str:
    if exc.category in {"timeout", "dns", "tls", "network"}:
        return "BLOCKED"
    if exc.category == "http" and exc.http_status is not None and exc.http_status >= 500:
        return "BLOCKED"
    return "MISMATCH"


def _classify_url_error(exc: urllib.error.URLError) -> VerificationError:
    reason = exc.reason
    if isinstance(reason, socket.gaierror):
        return VerificationError("dns", _exc_message(reason))
    if isinstance(reason, ssl.SSLError):
        return VerificationError("tls", _exc_message(reason))
    if isinstance(reason, socket.timeout):
        return VerificationError("timeout", _exc_message(reason))
    if isinstance(reason, TimeoutError):
        return VerificationError("timeout", _exc_message(reason))
    if isinstance(reason, OSError):
        return _classify_os_error(reason)
    return VerificationError("network", _exc_message(exc))


def _classify_os_error(exc: OSError) -> VerificationError:
    if isinstance(exc, socket.gaierror):
        return VerificationError("dns", _exc_message(exc))
    if exc.errno in {60, 110}:
        return VerificationError("timeout", _exc_message(exc))
    return VerificationError("network", _exc_message(exc))


def _exc_message(exc: Exception) -> str:
    message = str(exc).strip()
    return message or exc.__class__.__name__


def render_terminal_report(report: VerificationReport) -> str:
    required_summary = ", ".join(
        f"{name}=ok" if details.get("ok") else f"{name}=fail" for name, details in sorted(report.required_calls.items())
    )
    failures = "; ".join(f"{item.category}:{item.message}" for item in report.failures[:6]) or "none"
    return "\n".join(
        [
            f"status={report.status}",
            f"endpoint={report.endpoint}",
            (
                "server="
                f"{report.initialize.get('server_name') or '?'}"
                f"/{report.initialize.get('server_version') or '?'} "
                f"protocol={report.initialize.get('negotiated_protocol_version') or '?'}"
            ),
            (
                "tools="
                f"{report.tool_count} total, {report.unique_tool_count} unique, "
                f"pages={report.page_count}, "
                f"prompts={report.prompt_count}/{report.prompts_capability_advertised}, "
                f"resources={report.resource_count}/{report.resources_capability_advertised}"
            ),
            (
                "mismatches="
                f"missing={report.missing_tools or []} "
                f"unexpected={report.unexpected_tools or []} "
                f"duplicates={report.duplicate_tool_names or []}"
            ),
            f"required_calls={required_summary or 'none'}",
            f"failures={failures}",
        ]
    )


def render_markdown_report(report: VerificationReport) -> str:
    failure_lines = "\n".join(f"- `{item.category}` {item.message}" for item in report.failures) or "- none"
    required_lines = (
        "\n".join(
            f"- `{name}` ok={details.get('ok')} summary={json.dumps(details.get('summary', {}), sort_keys=True)}"
            for name, details in sorted(report.required_calls.items())
        )
        or "- none"
    )
    return "\n".join(
        [
            "# MCP Remote Verification",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| Status | `{report.status}` |",
            f"| Endpoint | `{report.endpoint}` |",
            f"| Expected protocol | `{report.expected_protocol_version}` |",
            f"| Negotiated protocol | `{report.initialize.get('negotiated_protocol_version')}` |",
            f"| Expected server | `{report.expected_server_name}` `{report.expected_server_version}` |",
            f"| Live server | `{report.initialize.get('server_name')}` `{report.initialize.get('server_version')}` |",
            f"| Tool count | `{report.tool_count}` total / `{report.unique_tool_count}` unique |",
            f"| Page count | `{report.page_count}` |",
            (
                "| Prompts exposed | "
                f"`{report.prompts_exposed}` (`{report.prompt_count}` listed / "
                f"`{report.prompts_capability_advertised}` advertised) |"
            ),
            (
                "| Resources exposed | "
                f"`{report.resources_exposed}` (`{report.resource_count}` listed / "
                f"`{report.resources_capability_advertised}` advertised) |"
            ),
            f"| Protocol header reused | `{report.protocol_header_used}` |",
            f"| Session header reused | `{report.session_header_used}` |",
            "",
            "## Tool Set",
            "",
            f"- Missing tools: `{report.missing_tools}`",
            f"- Unexpected tools: `{report.unexpected_tools}`",
            f"- Duplicate tools: `{report.duplicate_tool_names}`",
            f"- Suspicious tools: `{report.suspicious_tools}`",
            f"- Stale descriptions: `{report.stale_description_tools}`",
            "",
            "## Required Safe Calls",
            "",
            required_lines,
            "",
            "## Failures",
            "",
            failure_lines,
        ]
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify the live HODLXXI public MCP endpoint.")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--json-output")
    parser.add_argument("--markdown-output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = verify_remote_mcp(endpoint=args.endpoint, timeout=args.timeout)
    if args.json_output:
        path = Path(args.json_output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown_output:
        path = Path(args.markdown_output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_markdown_report(report) + "\n", encoding="utf-8")
    print(render_terminal_report(report))
    return 0 if report.status == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

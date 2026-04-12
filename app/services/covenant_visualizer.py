"""Covenant/script visualization helpers for paid agent jobs.

This module intentionally separates observed script evidence from inferred and
heuristic interpretations to avoid overstating covenant semantics.
"""

from __future__ import annotations

import re
from typing import Any

OPCODES = {
    0x63: "OP_IF",
    0x67: "OP_ELSE",
    0x68: "OP_ENDIF",
    0x75: "OP_DROP",
    0x76: "OP_DUP",
    0x87: "OP_EQUAL",
    0x88: "OP_EQUALVERIFY",
    0xA9: "OP_HASH160",
    0xAC: "OP_CHECKSIG",
    0xAE: "OP_CHECKMULTISIG",
    0xB1: "OP_CHECKLOCKTIMEVERIFY",
    0xB2: "OP_CHECKSEQUENCEVERIFY",
    0x6A: "OP_RETURN",
}

KEY_RE = re.compile(r"^(02|03)[0-9a-fA-F]{64}$")
XONLY_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
INT_RE = re.compile(r"^[0-9]+$")


class CovenantInputError(ValueError):
    """Validation error for covenant visualizer input."""


def visualize_covenant(input_dict: dict[str, Any]) -> dict[str, Any]:
    normalized, notes = _normalize_input(input_dict)
    parse_result = _parse_source(normalized)

    machine = _machine_explanation(normalized, parse_result, notes)
    human = _human_explanation(machine)
    graph = _branch_graph(machine)
    timeline = _timeline(machine)
    mermaid = _mermaid(graph)

    result = {
        "summary": human["summary"],
        "human_explanation": human,
        "machine_explanation": machine,
        "mermaid": mermaid,
        "timeline": timeline,
        "graph": graph,
        "spend_paths": machine.get("spend_paths", []),
        "warnings": _warnings(machine, parse_result, notes),
        "source_type": normalized["source_type"],
        "source": normalized,
    }
    dot = _graphviz_dot(graph)
    if dot:
        result["graphviz_dot"] = dot
    return result


def _normalize_input(input_dict: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    if not isinstance(input_dict, dict):
        raise CovenantInputError("input must be an object")

    descriptor = str(input_dict.get("descriptor") or "").strip()
    script_asm = re.sub(r"\s+", " ", str(input_dict.get("script_asm") or "").strip())
    script_hex = re.sub(r"\s+", "", str(input_dict.get("script_hex") or "").strip())
    network = str(input_dict.get("network") or "bitcoin").strip() or "bitcoin"

    if not any([descriptor, script_asm, script_hex]):
        raise CovenantInputError("one of descriptor, script_asm, script_hex is required")

    source_type = "descriptor" if descriptor else ("script_asm" if script_asm else "script_hex")
    return {
        "source_type": source_type,
        "network": network,
        "descriptor": descriptor or None,
        "script_asm": script_asm or None,
        "script_hex": script_hex.lower() or None,
        "original_input": input_dict,
    }, []


def _parse_source(normalized: dict[str, Any]) -> dict[str, Any]:
    source_type = normalized["source_type"]
    warnings: list[str] = []

    if source_type == "descriptor":
        descriptor = normalized.get("descriptor") or ""
        raw_script = _extract_raw_script(descriptor)
        if raw_script:
            tokens, decode_warnings = _decode_script_hex_to_tokens(raw_script)
            warnings.extend(decode_warnings)
            asm = " ".join(tokens)
            return {"tokens": tokens, "asm": asm, "raw_script_hex": raw_script, "warnings": warnings}

        warnings.append("descriptor parsing currently supports raw(<hex>) extraction only")
        return {"tokens": descriptor.split(), "asm": descriptor, "raw_script_hex": None, "warnings": warnings}

    if source_type == "script_asm":
        asm = normalized.get("script_asm") or ""
        return {"tokens": asm.split(), "asm": asm, "raw_script_hex": None, "warnings": warnings}

    script_hex = normalized.get("script_hex") or ""
    tokens, decode_warnings = _decode_script_hex_to_tokens(script_hex)
    warnings.extend(decode_warnings)
    return {"tokens": tokens, "asm": " ".join(tokens), "raw_script_hex": script_hex, "warnings": warnings}


def _extract_raw_script(descriptor: str) -> str | None:
    match = re.search(r"raw\(([0-9A-Fa-f]+)\)", descriptor)
    if not match:
        return None
    return match.group(1).lower()


def _decode_script_hex_to_tokens(script_hex: str) -> tuple[list[str], list[str]]:
    if not script_hex:
        return [], ["empty script_hex"]
    if len(script_hex) % 2 != 0 or re.search(r"[^0-9a-fA-F]", script_hex):
        return ["UNSUPPORTED_HEX"], ["script_hex is not valid even-length hex"]

    data = bytes.fromhex(script_hex)
    i = 0
    tokens: list[str] = []
    warnings: list[str] = []

    while i < len(data):
        opcode = data[i]
        i += 1

        if opcode in OPCODES:
            tokens.append(OPCODES[opcode])
            continue

        if 1 <= opcode <= 75:
            if i + opcode > len(data):
                tokens.append("PUSHDATA_TRUNCATED")
                warnings.append("pushdata length exceeds remaining bytes")
                break
            chunk = data[i : i + opcode]
            i += opcode
            tokens.append(chunk.hex())
            continue

        if opcode == 0x51:
            tokens.append("1")
            continue
        if opcode == 0x52:
            tokens.append("2")
            continue
        if opcode == 0x53:
            tokens.append("3")
            continue

        tokens.append(f"OP_UNKNOWN_{opcode:02x}")
        warnings.append(f"unsupported opcode 0x{opcode:02x}")

    return tokens, warnings


def _machine_explanation(normalized: dict[str, Any], parse_result: dict[str, Any], notes: list[str]) -> dict[str, Any]:
    tokens = parse_result.get("tokens", [])
    observed_ops = [t for t in tokens if t.startswith("OP_")]
    keys = [t for t in tokens if KEY_RE.match(t)]
    xonly_keys = [t for t in tokens if XONLY_KEY_RE.match(t) and not KEY_RE.match(t)]
    timelocks = _timelocks(tokens)
    has_if = "OP_IF" in tokens and "OP_ELSE" in tokens

    branches = []
    if has_if:
        branches.append({"branch": "cooperative", "selector": "OP_IF", "evidence": "OP_IF branch present"})
        branches.append({"branch": "alternative", "selector": "OP_ELSE", "evidence": "OP_ELSE branch present"})
    else:
        branches.append({"branch": "single_path", "selector": "none", "evidence": "no OP_IF/OP_ELSE pair observed"})

    spend_paths = []
    if has_if:
        spend_paths.append(
            {
                "path_id": "cooperative_path",
                "appears_to": "cooperative spend path",
                "observed_conditions": ["OP_IF branch"],
                "inferred_conditions": [],
            }
        )
        spend_paths.append(
            {
                "path_id": "alternative_path",
                "appears_to": "alternative/unilateral path",
                "observed_conditions": ["OP_ELSE branch"],
                "inferred_conditions": [
                    "may represent delayed exit when paired with CLTV/CSV; based on provided script"
                ],
            }
        )
    else:
        spend_paths.append(
            {
                "path_id": "single_path",
                "appears_to": "single-path spend",
                "observed_conditions": ["no conditional control-flow markers observed"],
                "inferred_conditions": [],
            }
        )

    if timelocks and spend_paths:
        spend_paths[-1].setdefault("observed_conditions", []).append("timelock opcode present")

    inferred_type = "conditional_multisig_timelock" if has_if and timelocks else "script_policy_partial"

    return {
        "type": inferred_type,
        "source_type": normalized["source_type"],
        "network": normalized.get("network"),
        "observed": {
            "asm": parse_result.get("asm", ""),
            "ops": observed_ops,
            "keys": keys,
            "xonly_keys": xonly_keys,
            "timelocks": timelocks,
            "branches_present": has_if,
            "raw_script_hex": parse_result.get("raw_script_hex"),
        },
        "inferred": {
            "branches": branches,
            "spend_paths": spend_paths,
            "role_hints": _role_hints(keys),
        },
        "heuristic_notes": notes,
        "spend_paths": spend_paths,
        "branches": branches,
        "timelocks": timelocks,
        "keys": keys,
    }


def _timelocks(tokens: list[str]) -> list[dict[str, Any]]:
    out = []
    for i, tok in enumerate(tokens):
        if tok not in {"OP_CHECKLOCKTIMEVERIFY", "OP_CLTV"}:
            continue
        raw_value = tokens[i - 1] if i > 0 else None
        if not raw_value:
            out.append({"raw": None, "type": "unknown", "note": "timelock opcode without prior push"})
            continue
        if INT_RE.match(raw_value):
            value = int(raw_value)
            out.append(
                {
                    "raw": raw_value,
                    "value": value,
                    "type": "timestamp" if value >= 500_000_000 else "block_height",
                }
            )
        else:
            out.append({"raw": raw_value, "type": "unknown", "note": "non-integer locktime operand"})
    return out


def _role_hints(keys: list[str]) -> list[dict[str, str]]:
    hints = []
    for idx, key in enumerate(keys, start=1):
        hints.append({"key": key, "label": f"Key {idx}", "note": "role assignment is heuristic"})
    return hints


def _human_explanation(machine: dict[str, Any]) -> dict[str, Any]:
    observed = machine["observed"]
    timelocks = observed["timelocks"]
    key_count = len(observed["keys"])

    summary = (
        "Based on the provided script material, this appears to encode a conditional spend structure "
        "with explicit branch markers."
        if observed["branches_present"]
        else "Based on the provided script material, this appears to encode a single-path spend structure."
    )

    cooperative = (
        "An OP_IF branch is present and appears to represent a cooperative path, but policy intent cannot be proven "
        "from opcodes alone."
        if observed["branches_present"]
        else "No explicit cooperative OP_IF branch was observed."
    )

    unilateral = (
        "An OP_ELSE branch appears to provide an alternate path that may be unilateral, especially when timelocks are "
        "present."
        if observed["branches_present"]
        else "No OP_ELSE branch was observed."
    )

    if timelocks:
        timelock_text = "Observed timelocks: " + ", ".join(
            f"{t.get('value', t.get('raw'))} ({t.get('type', 'unknown')})" for t in timelocks
        )
    else:
        timelock_text = "No explicit CLTV opcode with a parseable integer operand was observed."

    key_roles = (
        f"Detected {key_count} compressed pubkey-like tokens in the script evidence; roles are labeled heuristically."
        if key_count
        else "No compressed pubkey tokens were confidently detected from the provided input."
    )

    risks = [
        "Script evidence does not by itself prove legal intent, ownership, or economic policy guarantees.",
        "Role labels are heuristic and may not match signer identities.",
        "If script_hex decoding hits unsupported opcodes, interpretation is partial.",
    ]

    return {
        "summary": summary,
        "cooperative_path": cooperative,
        "unilateral_exit_paths": unilateral,
        "timelock_interpretation": timelock_text,
        "key_roles": key_roles,
        "risks_ambiguities": risks,
    }


def _branch_graph(machine: dict[str, Any]) -> dict[str, Any]:
    nodes = [
        {"id": "start", "label": "Start"},
    ]
    edges = []

    if machine["observed"]["branches_present"]:
        nodes.extend(
            [
                {"id": "cooperative", "label": "Cooperative"},
                {"id": "alternative", "label": "Alternative"},
            ]
        )
        edges.extend(
            [
                {"from": "start", "to": "cooperative", "label": "OP_IF"},
                {"from": "start", "to": "alternative", "label": "OP_ELSE"},
            ]
        )
    else:
        nodes.append({"id": "single", "label": "SinglePath"})
        edges.append({"from": "start", "to": "single", "label": "linear"})

    for idx, tl in enumerate(machine.get("timelocks", []), start=1):
        node_id = f"timelock_{idx}"
        nodes.append({"id": node_id, "label": f"Timelock {tl.get('value', tl.get('raw'))}"})
        attach_to = "alternative" if machine["observed"]["branches_present"] else "single"
        edges.append({"from": attach_to, "to": node_id, "label": tl.get("type", "unknown")})

    return {"nodes": nodes, "edges": edges}


def _timeline(machine: dict[str, Any]) -> list[dict[str, Any]]:
    points = [{"order": 0, "event": "script_evaluated", "detail": "input parsed"}]
    for idx, tl in enumerate(machine.get("timelocks", []), start=1):
        points.append(
            {
                "order": idx,
                "event": "timelock_gate",
                "value": tl.get("value", tl.get("raw")),
                "classification": tl.get("type", "unknown"),
            }
        )
    return points


def _mermaid(graph: dict[str, Any]) -> str:
    lines = ["flowchart TD"]
    for edge in graph.get("edges", []):
        src = edge["from"].replace("-", "_")
        dst = edge["to"].replace("-", "_")
        label = edge.get("label", "")
        if label:
            lines.append(f"  {src} -->|{label}| {dst}")
        else:
            lines.append(f"  {src} --> {dst}")
    return "\n".join(lines)


def _graphviz_dot(graph: dict[str, Any]) -> str:
    if not graph.get("nodes"):
        return ""
    lines = ["digraph CovenantFlow {"]
    for node in graph.get("nodes", []):
        lines.append(f'  {node["id"]} [label="{node.get("label", node["id"])}"];')
    for edge in graph.get("edges", []):
        label = edge.get("label")
        if label:
            lines.append(f'  {edge["from"]} -> {edge["to"]} [label="{label}"];')
        else:
            lines.append(f'  {edge["from"]} -> {edge["to"]};')
    lines.append("}")
    return "\n".join(lines)


def _warnings(machine: dict[str, Any], parse_result: dict[str, Any], notes: list[str]) -> list[str]:
    warnings = list(parse_result.get("warnings", []))
    warnings.extend(notes)

    if not machine["observed"].get("keys"):
        warnings.append("no compressed key tokens detected; key-role assignment may be incomplete")
    if machine["observed"].get("xonly_keys"):
        warnings.append("x-only key-like tokens detected; prefix/compression ambiguity remains")
    if not machine["observed"].get("timelocks"):
        warnings.append("no explicit CLTV operand detected; timeline is minimal")

    warnings.append("policy intent cannot be proven from script alone")
    return warnings

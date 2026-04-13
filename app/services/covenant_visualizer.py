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
    pattern = _pattern_match(parse_result)
    simplified_visualization, simplification_reasons = _is_simplified_visualization(parse_result, normalized)
    notes.extend(simplification_reasons)

    machine = _machine_explanation(normalized, parse_result, notes, pattern)
    human = _human_explanation(machine)
    graph = _branch_graph(machine)
    timeline = _timeline(machine)
    mermaid = _mermaid(graph)
    confidence, confidence_inputs = _confidence_score(machine, parse_result, simplified_visualization, pattern)
    trust_score, trust_factors = _trust_score(
        machine=machine,
        parse_result=parse_result,
        confidence=confidence,
        pattern_match=pattern,
        simplified_visualization=simplified_visualization,
    )
    machine["confidence_inputs"] = confidence_inputs
    machine["trust_factors"] = trust_factors

    result = {
        "summary": human["summary"],
        "confidence": confidence,
        "trust_score": trust_score,
        "pattern_match": pattern,
        "simplified_visualization": simplified_visualization,
        "human_explanation": human,
        "machine_explanation": machine,
        "mermaid": mermaid,
        "timeline": timeline,
        "graph": graph,
        "spend_paths": machine.get("spend_paths", []),
        "warnings": _warnings(machine, parse_result, notes, simplified_visualization),
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


def _machine_explanation(
    normalized: dict[str, Any], parse_result: dict[str, Any], notes: list[str], pattern_match: dict[str, Any]
) -> dict[str, Any]:
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
        "heuristic": {
            "notes": notes,
        },
        "pattern_match": pattern_match,
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

    for idx, tl in enumerate(machine.get("observed", {}).get("timelocks", []), start=1):
        node_id = f"timelock_{idx}"
        nodes.append({"id": node_id, "label": f"Timelock {tl.get('value', tl.get('raw'))}"})
        attach_to = "alternative" if machine["observed"]["branches_present"] else "single"
        edges.append({"from": attach_to, "to": node_id, "label": tl.get("type", "unknown")})

    return {"nodes": nodes, "edges": edges}


def _timeline(machine: dict[str, Any]) -> list[dict[str, Any]]:
    points = [{"order": 0, "event": "script_evaluated", "detail": "input parsed"}]
    for idx, tl in enumerate(machine.get("observed", {}).get("timelocks", []), start=1):
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


def _warnings(
    machine: dict[str, Any], parse_result: dict[str, Any], notes: list[str], simplified_visualization: bool
) -> list[str]:
    warnings = list(parse_result.get("warnings", []))
    warnings.extend(notes)

    if not machine["observed"].get("keys"):
        warnings.append("no compressed key tokens detected; key-role assignment may be incomplete")
    if machine["observed"].get("xonly_keys"):
        warnings.append("x-only key-like tokens detected; prefix/compression ambiguity remains")
    if not machine["observed"].get("timelocks"):
        warnings.append("no explicit CLTV operand detected; timeline is minimal")
    if simplified_visualization:
        warnings.append("nested branch logic detected; visualization is simplified")
    if any("unsupported opcode" in w for w in parse_result.get("warnings", [])):
        warnings.append("unsupported opcode(s) detected; graph is approximate")
    if machine.get("source_type") == "descriptor" and parse_result.get("raw_script_hex") is None:
        warnings.append("descriptor parsing is partial; only raw(...) is fully interpreted")

    warnings.append("policy intent cannot be proven from script alone")
    return list(dict.fromkeys(warnings))


def _pattern_match(parse_result: dict[str, Any]) -> dict[str, Any]:
    tokens = parse_result.get("tokens", [])
    if_count = tokens.count("OP_IF")
    else_count = tokens.count("OP_ELSE")
    endif_count = tokens.count("OP_ENDIF")
    cltv_count = tokens.count("OP_CHECKLOCKTIMEVERIFY")
    key_count = sum(1 for t in tokens if KEY_RE.match(t))
    unique_key_count = len({t for t in tokens if KEY_RE.match(t)})
    checksig_count = tokens.count("OP_CHECKSIG")

    signals: list[str] = []
    if if_count:
        signals.append("OP_IF")
    if else_count:
        signals.append("OP_ELSE")
    if cltv_count:
        signals.append("OP_CHECKLOCKTIMEVERIFY")
    if key_count:
        signals.append(f"{key_count} compressed key{'s' if key_count != 1 else ''}")
    if checksig_count:
        signals.append(f"{checksig_count} OP_CHECKSIG")

    family = "generic_script"
    variant = "unclassified"

    if if_count >= 1 and else_count >= 1 and cltv_count >= 1:
        family = "hodlxxi_covenant"
        variant = "generic_conditional_timelock"
    if if_count == 1 and else_count == 1 and cltv_count >= 1 and key_count >= 2:
        variant = "cooperative_plus_delayed_exit"
    if if_count >= 2 and else_count >= 2 and cltv_count >= 2:
        variant = "nested_cltv_ladder"
    if if_count >= 2 and else_count >= 2 and cltv_count >= 2 and unique_key_count == 2 and checksig_count >= 2:
        variant = "hodlxxi_two_party_ladder"

    return {
        "family": family,
        "variant": variant,
        "signals": signals,
        "note": "Pattern match is heuristic and based on opcode structure only.",
    }


def _is_simplified_visualization(parse_result: dict[str, Any], normalized: dict[str, Any]) -> tuple[bool, list[str]]:
    tokens = parse_result.get("tokens", [])
    if_count = tokens.count("OP_IF")
    else_count = tokens.count("OP_ELSE")
    endif_count = tokens.count("OP_ENDIF")
    reasons: list[str] = []

    has_unsupported = any("unsupported opcode" in warning for warning in parse_result.get("warnings", []))
    if has_unsupported:
        reasons.append("unsupported opcode(s) detected; graph is approximate")
    if if_count > 1:
        reasons.append("nested branch logic detected; visualization is simplified")
    if if_count != else_count or if_count != endif_count:
        reasons.append("imbalanced branch markers detected; visualization is simplified")
    if normalized.get("source_type") == "descriptor" and parse_result.get("raw_script_hex") is None:
        reasons.append("descriptor parsing is partial; only raw(...) is fully interpreted")

    return bool(reasons), reasons


def _confidence_score(
    machine: dict[str, Any],
    parse_result: dict[str, Any],
    simplified_visualization: bool,
    pattern_match: dict[str, Any],
) -> tuple[float, dict[str, Any]]:
    observed = machine.get("observed", {})
    tokens = parse_result.get("tokens", [])
    if_count = tokens.count("OP_IF")
    else_count = tokens.count("OP_ELSE")
    endif_count = tokens.count("OP_ENDIF")
    has_balanced_branches = if_count == else_count == endif_count
    unsupported_opcode_count = sum(1 for warning in parse_result.get("warnings", []) if "unsupported opcode" in warning)
    descriptor_partial = machine.get("source_type") == "descriptor" and parse_result.get("raw_script_hex") is None

    score = 0.35
    if observed.get("branches_present") and has_balanced_branches:
        score += 0.2
    if observed.get("keys"):
        score += 0.15
    if observed.get("timelocks"):
        score += 0.15
    if pattern_match.get("variant") in {
        "cooperative_plus_delayed_exit",
        "nested_cltv_ladder",
        "hodlxxi_two_party_ladder",
    }:
        score += 0.1
    elif pattern_match.get("variant") == "generic_conditional_timelock":
        score += 0.05

    score -= min(0.2, unsupported_opcode_count * 0.05)
    if observed.get("xonly_keys"):
        score -= 0.1
    if simplified_visualization:
        score -= 0.1
    if descriptor_partial:
        score -= 0.1
    if (if_count or else_count or endif_count) and not has_balanced_branches:
        score -= 0.1

    score = max(0.0, min(1.0, round(score, 2)))
    confidence_inputs = {
        "balanced_control_flow": has_balanced_branches,
        "clear_keys_detected": bool(observed.get("keys")),
        "timelocks_parseable": bool(observed.get("timelocks")),
        "pattern_variant": pattern_match.get("variant"),
        "unsupported_opcode_count": unsupported_opcode_count,
        "xonly_key_count": len(observed.get("xonly_keys") or []),
        "simplified_visualization": simplified_visualization,
        "descriptor_partial": descriptor_partial,
    }
    return score, confidence_inputs


def _trust_score(
    machine: dict[str, Any],
    parse_result: dict[str, Any],
    confidence: float,
    pattern_match: dict[str, Any],
    simplified_visualization: bool,
) -> tuple[float, dict[str, list[str]]]:
    observed = machine.get("observed", {})
    tokens = parse_result.get("tokens", [])
    if_count = tokens.count("OP_IF")
    else_count = tokens.count("OP_ELSE")
    endif_count = tokens.count("OP_ENDIF")
    balanced_branches = if_count == else_count == endif_count and (if_count > 0 or else_count > 0 or endif_count > 0)
    has_timelock = bool(observed.get("timelocks"))
    has_keys = bool(observed.get("keys"))
    unsupported_opcode_count = sum(1 for warning in parse_result.get("warnings", []) if "unsupported opcode" in warning)
    descriptor_partial = machine.get("source_type") == "descriptor" and parse_result.get("raw_script_hex") is None
    xonly_ambiguity = bool(observed.get("xonly_keys"))
    unclassified_pattern = pattern_match.get("variant") == "unclassified"
    imbalanced_branches = (if_count or else_count or endif_count) and not (if_count == else_count == endif_count)

    positive: list[str] = []
    negative: list[str] = []

    score = 0.4
    if balanced_branches:
        score += 0.15
        positive.append("balanced control flow")
    if has_keys:
        score += 0.1
        positive.append("compressed keys detected clearly")
    if has_timelock:
        score += 0.12
        positive.append("clear timelock structure")
    if not unclassified_pattern:
        score += 0.08
        positive.append("recognized covenant pattern variant")
    if unsupported_opcode_count == 0:
        score += 0.05
        positive.append("no unsupported opcodes detected")
    if not xonly_ambiguity:
        score += 0.03
        positive.append("no x-only key ambiguity")
    if not descriptor_partial:
        score += 0.03
        positive.append("no partial descriptor parsing")

    if unsupported_opcode_count:
        score -= min(0.24, 0.08 * unsupported_opcode_count)
        negative.append("unsupported opcode(s) present")
    if any("script_hex is not valid even-length hex" in warning for warning in parse_result.get("warnings", [])):
        score -= 0.2
        negative.append("malformed hex input")
    if xonly_ambiguity:
        score -= 0.12
        negative.append("x-only key ambiguity")
    if simplified_visualization:
        score -= 0.08
        negative.append("simplified visualization indicates approximation")
    if descriptor_partial:
        score -= 0.1
        negative.append("partial descriptor parsing")
    if unclassified_pattern:
        score -= 0.08
        negative.append("unclassified pattern")
    if imbalanced_branches:
        score -= 0.12
        negative.append("imbalanced branches")

    score -= max(0.0, (0.6 - confidence) * 0.1)
    score = max(0.0, min(1.0, round(score, 2)))
    negative.append("policy intent cannot be proven from script alone")
    return score, {"positive": list(dict.fromkeys(positive)), "negative": list(dict.fromkeys(negative))}

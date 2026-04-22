from datetime import datetime, timezone

"""Minimal Agent UBID routes: capabilities, jobs, attestations, and discovery."""

import hashlib
import logging
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request

from app.audit_logger import get_audit_logger

from app.agent_signer import canonical_json_bytes, get_agent_pubkey_hex, sign_message, verify_message
from app.database import session_scope
from app.models import AgentEvent, AgentJob
from app.payments.ln import check_invoice_paid, create_invoice
from app.structured_logging import log_event
from app.services.covenant_visualizer import CovenantInputError, visualize_covenant
from app.services.trust_surface import (
    DEFAULT_AGENT_ID,
    DEFAULT_COVENANT_ID,
    build_trust_report,
    build_trust_summary,
    compute_report_hash,
    has_covenant_artifact,
    load_agent_binding,
    load_covenant,
    trust_page_context,
)

logger = logging.getLogger(__name__)
audit_logger = get_audit_logger()

agent_bp = Blueprint("agent", __name__)

PING_SATS = 21
ATTESTATION_SATS = 1
MAX_JOBS_PER_DAY = 100
CAPABILITIES_SCHEMA_VERSION = "1.0"
MARKETPLACE_LISTING_VERSION = "1.0"
RECEIPT_VERSION = "1.0"
SKILLS_ROOT = Path(__file__).resolve().parents[2] / "skills" / "public"
SKILLS_REPO_RAW_BASE = "https://raw.githubusercontent.com/hodlxxi/Universal-Bitcoin-Identity-Layer/main/skills/public"

IP_WINDOW_SECONDS = 60
IP_MAX_REQUESTS = 20
_ip_requests = defaultdict(list)


def _check_ip_rate_limit() -> bool:
    ip = request.remote_addr or "unknown"
    now = time.time()
    arr = _ip_requests[ip]
    arr[:] = [t for t in arr if now - t < IP_WINDOW_SECONDS]
    if len(arr) >= IP_MAX_REQUESTS:
        return False
    arr.append(now)
    return True


def _is_production_mode() -> bool:
    env = (os.getenv("FLASK_ENV") or "").lower()
    force_https = (os.getenv("FORCE_HTTPS") or "").lower() == "true"
    return env == "production" or force_https


def _require_dev_admin() -> None:
    """
    Dev-only admin guard for endpoints that simulate payment/settlement.
    Uses Authorization: Bearer <DEV_AGENT_ADMIN_TOKEN>.
    """
    if _is_production_mode():
        from flask import abort

        abort(404)

    expected = os.getenv("DEV_AGENT_ADMIN_TOKEN") or ""
    auth = request.headers.get("Authorization", "")
    token = ""
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
    if not expected or token != expected:
        from flask import abort

        abort(403)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_hex(payload: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _payment_hash(invoice_lookup_id: str) -> str:
    candidate = (invoice_lookup_id or "").lower()
    if len(candidate) == 64 and all(ch in "0123456789abcdef" for ch in candidate):
        return candidate
    return hashlib.sha256(invoice_lookup_id.encode("utf-8")).hexdigest()


def _agent_endpoints() -> dict:
    return {
        "well_known": "/.well-known/agent.json",
        "capabilities": "/agent/capabilities",
        "capabilities_schema": "/agent/capabilities/schema",
        "request": "/agent/request",
        "message": "/agent/message",
        "job": "/agent/jobs/<job_id>",
        "verify": "/agent/verify/<job_id>",
        "attestations": "/agent/attestations",
        "reputation": "/agent/reputation",
        "chain_health": "/agent/chain/health",
        "marketplace_listing": "/agent/marketplace/listing",
        "skills": "/agent/skills",
        "trust_page": "/agent/trust/<agent_id>",
        "trust_summary": "/agent/trust-summary/<agent_id>.json",
        "binding_page": "/agent/binding/<agent_id>",
        "report_page": "/reports/<report_id>",
        "report_json": "/reports/<report_id>.json",
        "verify_report": "/verify/report/<report_id>",
        "verify_nostr": "/verify/nostr/<event_id>",
    }


def _parse_front_matter_text(skill_path: Path) -> tuple[dict, str]:
    text = skill_path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}, text

    parts = text.split("\n---\n", 1)
    if len(parts) != 2:
        return {}, text

    header_text, body = parts
    header_lines = header_text.splitlines()[1:]
    metadata: dict[str, object] = {}
    current_list_key: str | None = None

    for raw_line in header_lines:
        line = raw_line.rstrip()
        if not line:
            continue
        stripped = line.strip()
        if stripped.startswith("- ") and current_list_key:
            metadata.setdefault(current_list_key, [])
            casted = metadata[current_list_key]
            if isinstance(casted, list):
                casted.append(stripped[2:].strip())
            continue

        current_list_key = None
        if ":" not in stripped:
            continue

        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not value:
            current_list_key = key
            metadata.setdefault(key, [])
            continue

        metadata[key] = value.strip("'\"")

    return metadata, body


def _skill_entry(skill_dir: Path) -> dict | None:
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return None

    metadata, body = _parse_front_matter_text(skill_md)
    skill_name = str(metadata.get("name") or skill_dir.name)
    description = str(metadata.get("description") or "").strip()
    body_lines = [line.strip() for line in body.splitlines() if line.strip()]

    return {
        "skill_id": skill_name,
        "name": skill_name,
        "version": str(metadata.get("version") or "0.0.0"),
        "description": description or (body_lines[0] if body_lines else ""),
        "homepage": str(metadata.get("homepage") or ""),
        "tags": metadata.get("tags", []),
        "files": {
            "skill_markdown": f"skills/public/{skill_dir.name}/SKILL.md",
            "heartbeat_markdown": (
                f"skills/public/{skill_dir.name}/HEARTBEAT.md" if (skill_dir / "HEARTBEAT.md").exists() else None
            ),
        },
        "install": {
            "raw_url": f"{SKILLS_REPO_RAW_BASE}/{skill_dir.name}/SKILL.md",
            "local_path": f"skills/public/{skill_dir.name}/SKILL.md",
        },
    }


def _skills_catalog() -> list[dict]:
    if not SKILLS_ROOT.exists():
        return []

    items = []
    for skill_dir in sorted(path for path in SKILLS_ROOT.iterdir() if path.is_dir()):
        entry = _skill_entry(skill_dir)
        if entry:
            items.append(entry)
    return items


def _public_document_base() -> str:
    return request.url_root.rstrip("/")


def _trust_model_document() -> dict:
    endpoints = _agent_endpoints()
    return {
        "principle": (
            "HODLXXI treats agent trust not as a social claim but as an economically verifiable " "commitment."
        ),
        "identity_model": {
            "public_key": {
                "status": "verified_runtime_surface",
                "description": "Stable cryptographic identity anchor exposed by the runtime.",
                "surfaces": [endpoints["well_known"], endpoints["capabilities"]],
            },
            "operator_binding": {
                "status": "declared_runtime_surface",
                "description": (
                    "Operator metadata is published by the runtime, but the current trust surface does not "
                    "independently prove legal or organizational control."
                ),
                "surfaces": [endpoints["well_known"], endpoints["capabilities"]],
            },
            "time_locked_capital": {
                "status": "optional_not_verified",
                "description": (
                    "Optional trust anchor and design goal. The current runtime does not expose concrete proof of "
                    "time-locked capital or long-horizon Bitcoin commitments for this agent surface."
                ),
                "possible_backing_model": "May be tied to long-horizon Bitcoin commitments when such proofs exist.",
            },
            "observable_behavior": {
                "status": "verified_runtime_surface",
                "description": "Operational history that can be inspected through signed receipts, reputation, and chain health.",
                "surfaces": [endpoints["attestations"], endpoints["reputation"], endpoints["chain_health"]],
            },
        },
        "trust_derivation": ["continuity", "accountability", "verifiability", "bounded_risk"],
        "verified_runtime_properties": {
            "signed_receipts": True,
            "public_attestations": True,
            "reputation_surface": True,
            "chain_health_surface": True,
            "payment_required_before_work": True,
        },
        "assurance_boundaries": {
            "economically_enforced_continuity": "Design principle with partial runtime support via paid jobs and public history.",
            "on_chain_proof_exposed": False,
            "time_locked_capital_proof_exposed": False,
        },
    }


def _capabilities_schema_document() -> dict:
    endpoints = _agent_endpoints()
    base = _public_document_base()
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{base}{endpoints['capabilities_schema']}",
        "title": "HODLXXI Agent Capabilities",
        "description": "Canonical machine-readable schema for the Agent UBID capabilities document.",
        "type": "object",
        "required": [
            "agent_pubkey",
            "version",
            "service_name",
            "service_description",
            "operator",
            "network",
            "supports_payment_settlement_check",
            "endpoints",
            "pricing",
            "job_types",
            "limits",
            "timestamp",
            "sig_scheme",
            "signature",
        ],
        "properties": {
            "agent_pubkey": {"type": "string"},
            "version": {"type": "string"},
            "service_name": {"type": "string"},
            "service_description": {"type": "string"},
            "operator": {"type": "string"},
            "network": {"type": "string"},
            "supports_payment_settlement_check": {"type": "boolean"},
            "capability_schema": {
                "type": "object",
                "required": ["version", "uri"],
                "properties": {
                    "version": {"type": "string"},
                    "uri": {"type": "string", "pattern": "^/"},
                },
            },
            "endpoints": {
                "type": "object",
                "required": list(endpoints.keys()),
                "properties": {key: {"type": "string", "pattern": "^/"} for key in endpoints},
                "additionalProperties": False,
            },
            "pricing": {"type": "object"},
            "job_types": {"type": "object"},
            "limits": {"type": "object"},
            "skills": {
                "type": "object",
                "required": ["count", "endpoint", "items"],
                "properties": {
                    "count": {"type": "integer", "minimum": 0},
                    "endpoint": {"type": "string", "pattern": "^/"},
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["skill_id", "name", "version", "description", "install"],
                            "properties": {
                                "skill_id": {"type": "string"},
                                "name": {"type": "string"},
                                "version": {"type": "string"},
                                "description": {"type": "string"},
                                "homepage": {"type": "string"},
                                "tags": {"type": "array", "items": {"type": "string"}},
                                "files": {"type": "object"},
                                "install": {"type": "object"},
                            },
                        },
                    },
                },
            },
            "timestamp": {"type": "string", "format": "date-time"},
            "sig_scheme": {"type": "string"},
            "signature": {"type": "string"},
        },
        "additionalProperties": False,
    }


def _capabilities_payload() -> dict:
    skills = _skills_catalog()
    endpoints = _agent_endpoints()
    payload = {
        "agent_pubkey": get_agent_pubkey_hex(),
        "version": "0.1",
        "service_name": "HODLXXI Agent UBID",
        "service_description": "Lightning-paid agent with signed receipts, attestations, and reputation",
        "operator": "HODLXXI",
        "network": "bitcoin",
        "supports_payment_settlement_check": True,
        "capability_schema": {
            "version": CAPABILITIES_SCHEMA_VERSION,
            "uri": endpoints["capabilities_schema"],
        },
        "endpoints": endpoints,
        "pricing": {"ping_sats": PING_SATS, "attestation_sats": ATTESTATION_SATS},
        "job_types": JOB_REGISTRY,
        "limits": {"max_jobs_per_day": MAX_JOBS_PER_DAY},
        "skills": {
            "count": len(skills),
            "endpoint": endpoints["skills"],
            "items": skills,
        },
        "timestamp": _iso_now(),
        "sig_scheme": "secp256k1",
    }
    payload["signature"] = sign_message(canonical_json_bytes(payload))
    return payload


def _agent_identity_document() -> dict:
    capabilities = _capabilities_payload()
    skills = capabilities["skills"]
    endpoints = capabilities["endpoints"]
    return {
        "name": capabilities["service_name"],
        "version": capabilities["version"],
        "operator": capabilities["operator"],
        "network": capabilities["network"],
        "description": capabilities["service_description"],
        "agent_pubkey": capabilities["agent_pubkey"],
        "signature_scheme": capabilities["sig_scheme"],
        "capability_schema": capabilities["capability_schema"],
        "capabilities": {
            "supports_payment_settlement_check": capabilities["supports_payment_settlement_check"],
            "job_types": capabilities["job_types"],
        },
        "pricing": capabilities["pricing"],
        "limits": capabilities["limits"],
        "endpoints": endpoints,
        "skills": skills,
        "trust_model": _trust_model_document(),
        "discovery": {
            "well_known_agent": endpoints["well_known"],
            "capabilities": endpoints["capabilities"],
            "capabilities_schema": endpoints["capabilities_schema"],
            "skills": endpoints["skills"],
            "marketplace_listing": endpoints["marketplace_listing"],
        },
        "timestamp": capabilities["timestamp"],
    }


JOB_REGISTRY = {
    "ping": {
        "price_sats": PING_SATS,
        "memo": "Agent UBID ping job",
        "input_schema": {"payload": "object"},
        "output_schema": {"ok": "boolean", "job_type": "string", "echo": "object"},
    },
    "verify_signature": {
        "price_sats": PING_SATS,
        "memo": "Agent UBID verify_signature job",
        "input_schema": {"message": "string", "signature": "hex", "pubkey": "compressed secp256k1 hex"},
        "output_schema": {"ok": "boolean", "job_type": "string", "valid": "boolean"},
    },
    "covenant_decode": {
        "price_sats": PING_SATS,
        "memo": "Agent UBID covenant_decode job",
        "input_schema": {"script_hex": "hex"},
        "output_schema": {"ok": "boolean", "job_type": "string", "decoded": "string", "has_cltv": "boolean"},
    },
    "covenant_visualize": {
        "price_sats": PING_SATS,
        "memo": "Explain and visualize covenant/script/descriptor flows",
        "input_schema": {
            "descriptor": "string (optional)",
            "script_asm": "string (optional)",
            "script_hex": "hex (optional)",
            "network": "string (optional, default=bitcoin)",
        },
        "output_schema": {
            "ok": "boolean",
            "job_type": "string",
            "summary": "string",
            "confidence": "number (0.0-1.0 interpreter confidence; not cryptographic certainty)",
            "trust_score": "number (0.0-1.0 structural reliability / interpretability score)",
            "pattern_match": "object (heuristic family/variant/signals)",
            "simplified_visualization": "boolean",
            "machine_explanation": "object",
            "human_explanation": "object",
            "mermaid": "string",
            "timeline": "array",
            "graph": "object",
            "warnings": "array",
            "source_type": "string",
        },
    },
}


def _job_spec(job_type: str) -> dict | None:
    return JOB_REGISTRY.get(job_type)


def _job_result(job: AgentJob, payload: dict) -> dict:
    if job.job_type == "verify_signature":
        message = str(payload.get("message", ""))
        signature_hex = str(payload.get("signature", ""))
        pubkey_hex = str(payload.get("pubkey", ""))
        valid = verify_message(message.encode("utf-8"), signature_hex, pubkey_hex)
        return {
            "ok": True,
            "job_type": job.job_type,
            "valid": valid,
        }

    if job.job_type == "covenant_decode":
        script_hex = str(payload.get("script_hex", ""))
        return {
            "ok": True,
            "job_type": job.job_type,
            "script_hex": script_hex,
            "decoded": f"script({script_hex})",
            "has_cltv": "b1" in script_hex.lower(),
        }

    if job.job_type == "covenant_visualize":
        visualized = visualize_covenant(payload)
        return {
            "ok": True,
            "job_type": job.job_type,
            **visualized,
        }

    return {
        "ok": True,
        "job_type": job.job_type,
        "echo": payload,
    }


def _request_payload_from_data(data: dict) -> dict:
    payload = data.get("payload")
    if isinstance(payload, dict):
        result = dict(payload)
    else:
        input_payload = data.get("input")
        result = dict(input_payload) if isinstance(input_payload, dict) else {}

    nonce = data.get("nonce")
    if nonce is not None and "nonce" not in result:
        result["nonce"] = nonce

    return result


@agent_bp.get("/agent/capabilities")
def capabilities():
    return jsonify(_capabilities_payload())


@agent_bp.get("/agent/capabilities/schema")
def capabilities_schema():
    return jsonify(_capabilities_schema_document())


@agent_bp.get("/agent/skills")
def skills_listing():
    items = _skills_catalog()
    return jsonify(
        {
            "count": len(items),
            "items": items,
        }
    )


@agent_bp.get("/.well-known/agent.json")
def well_known_agent():
    return jsonify(_agent_identity_document())


def _signed_message_bytes(envelope: dict) -> bytes:
    """Canonical bytes used for signature verification/signing.

    Protocol rule: signature is computed over the canonical JSON envelope
    with the `signature` field omitted.
    """
    unsigned = dict(envelope)
    unsigned.pop("signature", None)
    return canonical_json_bytes(unsigned)


_AGENT_MESSAGE_IDEMPOTENCY_WINDOW_SECONDS = 600
_recent_agent_message_cache: dict[tuple[str, str], dict] = {}


def _prune_agent_message_cache(now: float) -> None:
    cutoff = now - _AGENT_MESSAGE_IDEMPOTENCY_WINDOW_SECONDS
    stale = [k for k, v in _recent_agent_message_cache.items() if float(v.get("ts", 0.0)) < cutoff]
    for key in stale:
        _recent_agent_message_cache.pop(key, None)


def _cached_agent_message_response(from_pubkey: str, message_id: str) -> dict | None:
    now = time.time()
    _prune_agent_message_cache(now)
    cached = _recent_agent_message_cache.get((from_pubkey, message_id))
    if not cached:
        return None
    response = cached.get("response")
    return response if isinstance(response, dict) else None


def _store_agent_message_response(from_pubkey: str, message_id: str, response: dict) -> None:
    now = time.time()
    _prune_agent_message_cache(now)
    _recent_agent_message_cache[(from_pubkey, message_id)] = {
        "response": response,
        "ts": now,
    }


def _validate_rfc3339_timestamp(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _validate_agent_message_envelope(envelope: dict) -> tuple[bool, str | None]:
    required = {
        "message_id",
        "conversation_id",
        "thread_id",
        "type",
        "from_pubkey",
        "to_pubkey",
        "created_at",
        "payload",
        "signature",
    }

    if required - set(envelope.keys()):
        return False, "invalid_envelope"

    for key in ("message_id", "conversation_id", "thread_id", "type", "from_pubkey", "to_pubkey", "created_at"):
        value = envelope.get(key)
        if not isinstance(value, str) or not value.strip():
            return False, "invalid_envelope"

    if not _validate_rfc3339_timestamp(envelope["created_at"]):
        return False, "invalid_envelope"

    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return False, "invalid_payload"

    signature = envelope.get("signature")
    if not isinstance(signature, str) or not signature:
        return False, "invalid_signature"

    try:
        signed_bytes = _signed_message_bytes(envelope)
    except (TypeError, ValueError):
        return False, "invalid_payload"

    if not verify_message(signed_bytes, signature, envelope["from_pubkey"]):
        return False, "invalid_signature"

    if envelope["type"] != "job_proposal":
        return False, "unsupported_type"

    if envelope["to_pubkey"] != get_agent_pubkey_hex():
        return False, "wrong_recipient"

    return True, None


def _sign_envelope(envelope: dict) -> str:
    return sign_message(_signed_message_bytes(envelope))


def _result_envelope_for_request(request_envelope: dict, payload: dict) -> dict:
    response = {
        "message_id": str(uuid.uuid4()),
        "conversation_id": request_envelope["conversation_id"],
        "thread_id": request_envelope["thread_id"],
        "type": "result",
        "from_pubkey": get_agent_pubkey_hex(),
        "to_pubkey": request_envelope["from_pubkey"],
        "created_at": _iso_now(),
        "payload": payload,
        "references": {"parent_message_id": request_envelope["message_id"]},
    }
    response["signature"] = _sign_envelope(response)
    return response


@agent_bp.post("/agent/message")
def post_agent_message():
    if not _check_ip_rate_limit():
        return jsonify({"error": "invalid_payload"}), 429

    envelope = request.get_json(silent=True)
    if not isinstance(envelope, dict):
        return jsonify({"error": "invalid_json"}), 400

    ok, error = _validate_agent_message_envelope(envelope)
    if not ok and error:
        return jsonify({"error": error}), 400

    from_pubkey = envelope["from_pubkey"]
    message_id = envelope["message_id"]

    cached_response = _cached_agent_message_response(from_pubkey, message_id)
    if cached_response:
        return jsonify(cached_response), 200

    payload = envelope["payload"]
    job_type = payload.get("job_type")
    job_payload = payload.get("payload")

    if not isinstance(job_type, str) or not isinstance(job_payload, dict):
        return jsonify({"error": "invalid_payload"}), 400

    spec = _job_spec(job_type)
    if not spec:
        log_event(logger, "agent.request_rejected", outcome="unsupported_job_type")
        return jsonify({"error": "unsupported_job_type"}), 400

    result_payload = _job_result(
        AgentJob(job_type=job_type, request_json={"payload": job_payload}),
        job_payload,
    )

    response_envelope = _result_envelope_for_request(
        envelope,
        payload={
            "job_type": job_type,
            "result": result_payload,
            "agent_pubkey": get_agent_pubkey_hex(),
            "attestation_ref": {
                "endpoint": "/agent/attestations",
                "note": "future-linkable; no receipt persisted by /agent/message MVP",
            },
        },
    )
    _store_agent_message_response(from_pubkey, message_id, response_envelope)
    return jsonify(response_envelope), 200


@agent_bp.post("/agent/request")
def create_job_request():
    log_event(logger, "agent.request_received", outcome="started")

    if not _check_ip_rate_limit():
        log_event(logger, "agent.request_rejected", outcome="ip_rate_limited")
        return jsonify({"error": "ip_rate_limited"}), 429

    data = request.get_json(silent=True) or {}
    job_type = data.get("job_type")
    payload = _request_payload_from_data(data)

    if len(str(payload)) > 10000:
        log_event(logger, "agent.request_rejected", outcome="payload_too_large")
        return jsonify({"error": "payload_too_large"}), 400

    spec = _job_spec(job_type)
    if not spec:
        return jsonify({"error": "unsupported_job_type"}), 400
    if job_type == "covenant_visualize":
        try:
            visualize_covenant(payload)
        except CovenantInputError as exc:
            return jsonify({"error": "invalid_input", "message": str(exc)}), 400

    with session_scope() as session:
        since = datetime.now(timezone.utc) - timedelta(days=1)
        jobs_last_day = session.query(AgentJob).filter(AgentJob.created_at >= since).count()
        if jobs_last_day >= MAX_JOBS_PER_DAY:
            log_event(logger, "agent.request_rejected", outcome="daily_rate_limited")
            return jsonify({"error": "rate_limited", "message": "daily job limit reached"}), 429

    request_payload = {"job_type": job_type, "payload": payload}
    req_hash = _sha256_hex(request_payload)

    with session_scope() as session:
        existing_job = (
            session.query(AgentJob)
            .filter(AgentJob.request_hash == req_hash)
            .order_by(AgentJob.created_at.desc())
            .first()
        )
        if existing_job:
            # if job already completed → safe to reuse
            if existing_job.status == "done":
                log_event(
                    logger,
                    "agent.request_deduplicated",
                    job_id=existing_job.id,
                    invoice_id=existing_job.payment_hash,
                    outcome="done",
                )
                existing_event = (
                    session.query(AgentEvent)
                    .filter_by(job_id=existing_job.id)
                    .order_by(AgentEvent.created_at.desc())
                    .first()
                )
                return (
                    jsonify(
                        {
                            "job_id": existing_job.id,
                            "invoice": existing_job.payment_request,
                            "payment_hash": existing_job.payment_hash,
                            "status": existing_job.status,
                            "receipt": existing_event.event_json if existing_event else None,
                            "deduplicated": True,
                        }
                    ),
                    200,
                )

            # if invoice is still pending → check freshness (1 hour TTL)
            if existing_job.status == "invoice_pending":
                created_at = existing_job.created_at
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)

                age = datetime.now(timezone.utc) - created_at

                # if invoice is still fresh → reuse
                if age.total_seconds() < 3600:
                    log_event(
                        logger,
                        "agent.request_deduplicated",
                        job_id=existing_job.id,
                        invoice_id=existing_job.payment_hash,
                        outcome="invoice_pending",
                    )
                    return (
                        jsonify(
                            {
                                "job_id": existing_job.id,
                                "invoice": existing_job.payment_request,
                                "payment_hash": existing_job.payment_hash,
                                "status": existing_job.status,
                                "deduplicated": True,
                            }
                        ),
                        200,
                    )

                # otherwise → expired → create new invoice
                log_event(
                    logger,
                    "agent.request_invoice_expired",
                    job_id=existing_job.id,
                    outcome="creating_new_invoice",
                )

    sats = int(spec["price_sats"])
    memo = str(spec["memo"])

    try:
        invoice, invoice_lookup_id = create_invoice(sats, memo, get_agent_pubkey_hex())
        log_event(logger, "agent.invoice_created", invoice_id=_payment_hash(invoice_lookup_id), outcome="created")
    except Exception:
        log_event(logger, "agent.invoice_create_failed", outcome="failure")
        logger.error("Agent invoice creation failed", exc_info=True)
        return (
            jsonify(
                {
                    "error": "invoice_create_failed",
                    "message": "Internal server error",
                }
            ),
            502,
        )

    with session_scope() as session:
        job = AgentJob(
            job_type=job_type,
            request_json=request_payload,
            request_hash=req_hash,
            sats=sats,
            payment_request=invoice,
            payment_lookup_id=invoice_lookup_id,
            payment_hash=_payment_hash(invoice_lookup_id),
            status="invoice_pending",
        )
        session.add(job)
        session.flush()
        job_id = job.id

    log_event(
        logger,
        "agent.execution_started",
        job_id=job_id,
        invoice_id=_payment_hash(invoice_lookup_id),
        outcome="invoice_pending",
    )
    audit_logger.log_event(
        "agent.job_created", job_id=job_id, invoice_id=_payment_hash(invoice_lookup_id), status="invoice_pending"
    )

    return (
        jsonify(
            {
                "job_id": job_id,
                "invoice": invoice,
                "payment_hash": _payment_hash(invoice_lookup_id),
                "status": "invoice_pending",
            }
        ),
        201,
    )


def _build_receipt(job: AgentJob, prev_event_hash: str | None) -> dict:
    payload = job.request_json.get("payload", {}) or {}
    result_payload = _job_result(job, payload)

    job.result_json = result_payload
    job.result_hash = _sha256_hex(result_payload)
    job.status = "done"

    receipt = {
        "event_type": "job_receipt",
        "job_id": job.id,
        "job_type": job.job_type,
        "request_hash": job.request_hash,
        "payment_hash": job.payment_hash,
        "result_hash": job.result_hash,
        "timestamp": _iso_now(),
        "agent_pubkey": get_agent_pubkey_hex(),
        "prev_event_hash": prev_event_hash,
        "version": RECEIPT_VERSION,
    }
    receipt["signature"] = sign_message(canonical_json_bytes(receipt))
    return receipt


def _event_attestation(event: AgentEvent, job: AgentJob | None) -> dict:
    raw = event.event_json or {}
    return {
        "version": raw.get("version", RECEIPT_VERSION),
        "event_type": raw.get("event_type", "job_receipt"),
        "job_id": raw.get("job_id", event.job_id),
        "job_type": raw.get("job_type") or (job.job_type if job else None),
        "request_hash": raw.get("request_hash") or (job.request_hash if job else None),
        "payment_hash": raw.get("payment_hash") or (job.payment_hash if job else None),
        "result_hash": raw.get("result_hash") or (job.result_hash if job else None),
        "timestamp": raw.get("timestamp") or event.created_at.isoformat(),
        "agent_pubkey": raw.get("agent_pubkey", get_agent_pubkey_hex()),
        "prev_event_hash": raw.get("prev_event_hash", event.prev_event_hash),
        "signature": raw.get("signature", event.signature),
        "event_hash": event.event_hash,
    }


@agent_bp.post("/agent/jobs/<job_id>/dev/mark_paid")
def dev_mark_paid(job_id: str):
    """
    Dev endpoint: simulate invoice payment and immediately issue a receipt.
    Protected by DEV_AGENT_ADMIN_TOKEN and disabled in production-like mode.
    """
    _require_dev_admin()

    with session_scope() as session:
        job = session.query(AgentJob).filter_by(id=job_id).first()
        if not job:
            log_event(logger, "agent.job_lookup", job_id=job_id, outcome="not_found")
            return jsonify({"error": "not_found"}), 404

        # If already has an event, return current status/receipt
        event = session.query(AgentEvent).filter_by(job_id=job_id).first()
        if event:
            log_event(logger, "agent.receipt_returned", job_id=job.id, outcome=job.status)
            return jsonify({"job_id": job.id, "status": job.status, "receipt": event.event_json})

        # Issue receipt now
        last_event = session.query(AgentEvent).order_by(AgentEvent.created_at.desc()).first()
        prev_event_hash = last_event.event_hash if last_event else None
        log_event(logger, "agent.payment_confirmed", job_id=job.id, invoice_id=job.payment_hash, outcome="paid")
        receipt = _build_receipt(job, prev_event_hash)
        event_hash = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
        session.add(
            AgentEvent(
                job_id=job.id,
                event_hash=event_hash,
                prev_event_hash=prev_event_hash,
                event_json=receipt,
                signature=receipt["signature"],
            )
        )
        log_event(logger, "agent.execution_completed", job_id=job.id, invoice_id=job.payment_hash, outcome=job.status)
        log_event(logger, "agent.receipt_returned", job_id=job.id, outcome=job.status)
        audit_logger.log_event("agent.job_completed", job_id=job.id, invoice_id=job.payment_hash, status=job.status)
        return jsonify({"job_id": job.id, "status": job.status, "receipt": receipt})


@agent_bp.get("/agent/jobs/<job_id>")
def get_job(job_id: str):
    with session_scope() as session:
        job = session.query(AgentJob).filter_by(id=job_id).first()
        if not job:
            log_event(logger, "agent.job_lookup", job_id=job_id, outcome="not_found")
            return jsonify({"error": "not_found"}), 404

        # Most recent event for THIS job (if any)
        existing_event = (
            session.query(AgentEvent).filter_by(job_id=job.id).order_by(AgentEvent.created_at.desc()).first()
        )

        # If no receipt yet, but invoice is paid -> mint receipt exactly once
        if not existing_event:
            paid = check_invoice_paid(job.payment_lookup_id)
            log_event(
                logger,
                "agent.payment_checked",
                job_id=job.id,
                invoice_id=job.payment_hash,
                outcome="paid" if paid else "pending",
            )
        else:
            paid = False

        if not existing_event and paid:
            # Chain head = latest event across all jobs
            last_event = session.query(AgentEvent).order_by(AgentEvent.created_at.desc()).first()
            chain_head = last_event.event_hash if last_event else None

            log_event(logger, "agent.execution_started", job_id=job.id, invoice_id=job.payment_hash, outcome="running")
            receipt = _build_receipt(job, chain_head)
            event_hash = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()

            session.add(
                AgentEvent(
                    job_id=job.id,
                    event_hash=event_hash,
                    prev_event_hash=chain_head,
                    event_json=receipt,
                    signature=receipt["signature"],
                )
            )

            # Persist job outcome (but do NOT store receipt in result_json)
            job.status = "done"
            session.flush()
            log_event(
                logger, "agent.execution_completed", job_id=job.id, invoice_id=job.payment_hash, outcome=job.status
            )
            audit_logger.log_event("agent.job_completed", job_id=job.id, invoice_id=job.payment_hash, status=job.status)

            existing_event = (
                session.query(AgentEvent).filter_by(job_id=job.id).order_by(AgentEvent.created_at.desc()).first()
            )

        log_event(logger, "agent.receipt_returned", job_id=job.id, invoice_id=job.payment_hash, outcome=job.status)
        return jsonify(
            {
                "job_id": job.id,
                "status": job.status,
                "result": job.result_json,
                "receipt": existing_event.event_json if existing_event else None,
            }
        )


@agent_bp.get("/agent/attestations")
def attestations():
    try:
        limit = min(max(int(request.args.get("limit", 20)), 1), 100)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return jsonify({"error": "invalid_pagination"}), 400

    with session_scope() as session:
        events = session.query(AgentEvent).order_by(AgentEvent.created_at.desc()).offset(offset).limit(limit).all()
        job_ids = {event.job_id for event in events}
        jobs = (
            {job.id: job for job in session.query(AgentJob).filter(AgentJob.id.in_(job_ids)).all()} if job_ids else {}
        )
        items = [_event_attestation(event, jobs.get(event.job_id)) for event in events]
    return jsonify({"items": items, "count": len(items), "limit": limit, "offset": offset})


@agent_bp.get("/agent/verify/<job_id>")
def verify_job_receipt(job_id: str):
    with session_scope() as session:
        job = session.query(AgentJob).filter_by(id=job_id).first()
        event = session.query(AgentEvent).filter_by(job_id=job_id).order_by(AgentEvent.created_at.desc()).first()
        if not event:
            return jsonify({"error": "not_found", "job_id": job_id, "verification": "unavailable"}), 404

        receipt = event.event_json
        payload = dict(receipt)
        signature = payload.pop("signature", None)

        if not signature:
            return jsonify({"error": "unavailable", "job_id": job_id, "reason": "missing_signature"}), 503

        agent_pubkey = payload.get("agent_pubkey", "")
        valid = verify_message(canonical_json_bytes(payload), signature, agent_pubkey)
        event_hash = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
        attestation = _event_attestation(event, job)
        verification_status = "verified" if valid else "invalid_signature"

        return jsonify(
            {
                "job_id": job_id,
                "status": verification_status,
                "valid": valid,
                "agent_pubkey": agent_pubkey,
                "event_hash": event_hash,
                "attestation": attestation,
                "receipt": receipt,
            }
        )


@agent_bp.get("/agent/chain/health")
def chain_health():
    with session_scope() as session:
        events = session.query(AgentEvent).order_by(AgentEvent.created_at.asc()).all()

        if not events:
            return jsonify(
                {
                    "agent_pubkey": get_agent_pubkey_hex(),
                    "count": 0,
                    "latest_event_hash": None,
                    "latest_prev_event_hash": None,
                    "chain_ok": True,
                }
            )

        chain_ok = True
        prev_hash = None
        for event in events:
            if event.prev_event_hash != prev_hash:
                chain_ok = False
                break
            prev_hash = event.event_hash

        latest = events[-1]
        return jsonify(
            {
                "agent_pubkey": get_agent_pubkey_hex(),
                "count": len(events),
                "latest_event_hash": latest.event_hash,
                "latest_prev_event_hash": latest.prev_event_hash,
                "latest_event_timestamp": latest.created_at.isoformat(),
                "chain_ok": chain_ok,
            }
        )


@agent_bp.get("/agent/marketplace/listing")
def marketplace_listing():
    endpoints = _agent_endpoints()
    capabilities = _capabilities_payload()
    skills = capabilities["skills"]
    with session_scope() as session:
        jobs = session.query(AgentJob).all()
        events = session.query(AgentEvent).order_by(AgentEvent.created_at.asc()).all()

        total_jobs = len(jobs)
        completed_jobs = sum(1 for j in jobs if j.status == "done")
        completed_job_ids = {event.job_id for event in events}
        counts_by_job_type: dict[str, int] = {}
        for job in jobs:
            if job.id in completed_job_ids:
                counts_by_job_type[job.job_type] = counts_by_job_type.get(job.job_type, 0) + 1

        latest_event_timestamp = events[-1].created_at.isoformat() if events else None

        chain_ok = True
        prev_hash = None
        for event in events:
            if event.prev_event_hash != prev_hash:
                chain_ok = False
                break
            prev_hash = event.event_hash

        latest_event_hash = events[-1].event_hash if events else None

        return jsonify(
            {
                "listing_version": MARKETPLACE_LISTING_VERSION,
                "service_name": "HODLXXI Agent UBID",
                "service_description": "Lightning-paid agent with signed receipts, attestations, and reputation",
                "operator": "HODLXXI",
                "agent_pubkey": get_agent_pubkey_hex(),
                "network": "bitcoin",
                "capability_schema": capabilities["capability_schema"],
                "discovery": {
                    "well_known_agent": endpoints["well_known"],
                    "capabilities": endpoints["capabilities"],
                    "capabilities_schema": endpoints["capabilities_schema"],
                    "skills": endpoints["skills"],
                },
                "job_types": JOB_REGISTRY,
                "pricing": {
                    "ping_sats": PING_SATS,
                    "attestation_sats": ATTESTATION_SATS,
                },
                "endpoints": endpoints,
                "skills": skills,
                "trust_model": _trust_model_document(),
                "reputation": {
                    "total_jobs": total_jobs,
                    "completed_jobs": completed_jobs,
                    "evidenced_completed_jobs": len(completed_job_ids),
                    "counts_by_job_type": counts_by_job_type,
                    "attestations_count": len(events),
                    "latest_event_timestamp": latest_event_timestamp,
                },
                "chain_health": {
                    "chain_ok": chain_ok,
                    "latest_event_hash": latest_event_hash,
                    "latest_event_timestamp": latest_event_timestamp,
                    "count": len(events),
                },
            }
        )


@agent_bp.get("/agent/reputation")
def reputation():
    with session_scope() as session:
        jobs = session.query(AgentJob).all()
        events = session.query(AgentEvent).order_by(AgentEvent.created_at.asc()).all()

        total_jobs = len(jobs)
        completed_jobs = sum(1 for j in jobs if j.status == "done")
        evidenced_job_ids = {event.job_id for event in events}

        counts_by_job_type: dict[str, int] = {}
        for j in jobs:
            if j.id in evidenced_job_ids:
                counts_by_job_type[j.job_type] = counts_by_job_type.get(j.job_type, 0) + 1

        latest_event_timestamp = events[-1].created_at.isoformat() if events else None
        trust_scores: list[float] = []
        confidences: list[float] = []
        pattern_distribution: dict[str, int] = {}
        for job in sorted(jobs, key=lambda item: item.created_at.timestamp() if item.created_at else 0.0):
            if job.status != "done" or not isinstance(job.result_json, dict):
                continue
            trust_score = job.result_json.get("trust_score")
            confidence = job.result_json.get("confidence")
            pattern_match = job.result_json.get("pattern_match")

            if isinstance(trust_score, (int, float)):
                trust_scores.append(float(trust_score))
            if isinstance(confidence, (int, float)):
                confidences.append(float(confidence))
            if isinstance(pattern_match, dict):
                variant = pattern_match.get("variant")
                if isinstance(variant, str) and variant:
                    pattern_distribution[variant] = pattern_distribution.get(variant, 0) + 1

        average_trust_score = round(sum(trust_scores) / len(trust_scores), 4) if trust_scores else None
        average_confidence = round(sum(confidences) / len(confidences), 4) if confidences else None

        trust_trend = None
        trust_window = trust_scores[-10:]
        if trust_window:
            trust_trend = {
                "window_size": len(trust_window),
                "rolling_average_trust_score": round(sum(trust_window) / len(trust_window), 4),
            }

        return jsonify(
            {
                "agent_pubkey": get_agent_pubkey_hex(),
                "total_jobs": total_jobs,
                "completed_jobs": completed_jobs,
                "evidenced_completed_jobs": len(evidenced_job_ids),
                "counts_by_job_type": counts_by_job_type,
                "job_types": counts_by_job_type,
                "attestations_count": len(events),
                "latest_event_timestamp": latest_event_timestamp,
                "average_trust_score": average_trust_score,
                "average_confidence": average_confidence,
                "pattern_distribution": pattern_distribution,
                "trust_trend": trust_trend,
            }
        )


@agent_bp.get("/agent/trust/<agent_id>")
def trust_page(agent_id: str):
    context = trust_page_context(agent_id)
    return render_template("agent/trust_page.html", **context)


@agent_bp.get("/agent/binding/<agent_id>")
def binding_page(agent_id: str):
    binding = load_agent_binding(agent_id)
    return render_template("agent/binding_page.html", agent_id=agent_id, binding=binding)


@agent_bp.get("/agent/trust-summary/<agent_id>.json")
def trust_summary_json(agent_id: str):
    return jsonify(build_trust_summary(agent_id))


@agent_bp.get("/agent/covenants/<covenant_id>.json")
def covenant_json(covenant_id: str):
    if not has_covenant_artifact(covenant_id):
        return jsonify({"error": "not_found"}), 404
    covenant = load_covenant(covenant_id)
    return jsonify(covenant)


@agent_bp.get("/reports/<report_id>.json")
def report_json(report_id: str):
    report = build_trust_report(DEFAULT_AGENT_ID, report_id=report_id)
    return jsonify(report)


@agent_bp.get("/reports/<report_id>")
def report_page(report_id: str):
    report = build_trust_report(DEFAULT_AGENT_ID, report_id=report_id)
    covenant = load_covenant(report["covenant"].get("covenant_id", DEFAULT_COVENANT_ID))
    return render_template("agent/report_page.html", report=report, covenant=covenant, agent_id=DEFAULT_AGENT_ID)


@agent_bp.get("/verify/report/<report_id>")
def verify_report_page(report_id: str):
    report = build_trust_report(DEFAULT_AGENT_ID, report_id=report_id)
    expected_hash = compute_report_hash(report)
    hash_matches = expected_hash == report.get("report_sha256")
    return render_template(
        "agent/verify_report.html",
        report=report,
        canonical_hash=expected_hash,
        hash_matches=hash_matches,
    )


@agent_bp.get("/verify/nostr/<event_id>")
def verify_nostr_page(event_id: str):
    return render_template(
        "agent/verify_nostr.html",
        event_id=event_id,
        trust_summary=build_trust_summary(DEFAULT_AGENT_ID),
    )

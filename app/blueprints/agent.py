"""Minimal Agent UBID routes: capabilities, jobs, and attestations."""

import hashlib
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from app.agent_signer import canonical_json_bytes, get_agent_pubkey_hex, sign_message
from app.database import session_scope
from app.models import AgentEvent, AgentJob
from app.payments.ln import check_invoice_paid, create_invoice

agent_bp = Blueprint("agent", __name__)

PING_SATS = 21
ATTESTATION_SATS = 1
MAX_JOBS_PER_DAY = 100


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_hex(payload: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _payment_hash(invoice_lookup_id: str) -> str:
    candidate = (invoice_lookup_id or "").lower()
    if len(candidate) == 64 and all(ch in "0123456789abcdef" for ch in candidate):
        return candidate
    return hashlib.sha256(invoice_lookup_id.encode("utf-8")).hexdigest()


@agent_bp.get("/agent/capabilities")
def capabilities():
    payload = {
        "agent_pubkey": get_agent_pubkey_hex(),
        "version": "0.1",
        "endpoints": {
            "request": "/agent/request",
            "job": "/agent/jobs/<job_id>",
            "attestations": "/agent/attestations",
        },
        "pricing": {"ping_sats": PING_SATS, "attestation_sats": ATTESTATION_SATS},
        "limits": {"max_jobs_per_day": MAX_JOBS_PER_DAY},
        "timestamp": _iso_now(),
        "sig_scheme": "secp256k1",
    }
    payload["signature"] = sign_message(canonical_json_bytes(payload))
    return jsonify(payload)


@agent_bp.post("/agent/request")
def create_job_request():
    data = request.get_json(silent=True) or {}
    if data.get("job_type") != "ping":
        return jsonify({"error": "unsupported_job_type"}), 400

    request_payload = {"job_type": "ping", "payload": data.get("payload") or {}}
    req_hash = _sha256_hex(request_payload)
    invoice, invoice_lookup_id = create_invoice(PING_SATS, "Agent UBID ping job", get_agent_pubkey_hex())

    with session_scope() as session:
        job = AgentJob(
            job_type="ping",
            request_json=request_payload,
            request_hash=req_hash,
            sats=PING_SATS,
            payment_request=invoice,
            payment_lookup_id=invoice_lookup_id,
            payment_hash=_payment_hash(invoice_lookup_id),
            status="invoice_pending",
        )
        session.add(job)
        session.flush()
        job_id = job.id

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
    result_payload = {"ok": True, "job_type": job.job_type, "echo": job.request_json.get("payload", {})}
    job.result_json = result_payload
    job.result_hash = _sha256_hex(result_payload)
    job.status = "done"

    receipt = {
        "event_type": "job_receipt",
        "job_id": job.id,
        "request_hash": job.request_hash,
        "payment_hash": job.payment_hash,
        "result_hash": job.result_hash,
        "timestamp": _iso_now(),
        "agent_pubkey": get_agent_pubkey_hex(),
        "prev_event_hash": prev_event_hash,
    }
    receipt["signature"] = sign_message(canonical_json_bytes(receipt))
    return receipt


@agent_bp.get("/agent/jobs/<job_id>")
def get_job(job_id: str):
    with session_scope() as session:
        job = session.query(AgentJob).filter_by(id=job_id).first()
        if not job:
            return jsonify({"error": "not_found"}), 404

        if job.status == "invoice_pending" and check_invoice_paid(job.payment_lookup_id):
            last_event = session.query(AgentEvent).order_by(AgentEvent.created_at.desc()).first()
            prev_event_hash = last_event.event_hash if last_event else None
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

        event = session.query(AgentEvent).filter_by(job_id=job_id).first()
        return jsonify({"job_id": job.id, "status": job.status, "receipt": event.event_json if event else None})


@agent_bp.get("/agent/attestations")
def attestations():
    try:
        limit = min(max(int(request.args.get("limit", 20)), 1), 100)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return jsonify({"error": "invalid_pagination"}), 400

    with session_scope() as session:
        events = (
            session.query(AgentEvent)
            .order_by(AgentEvent.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        items = [event.event_json for event in events]
    return jsonify({"items": items, "count": len(items)})

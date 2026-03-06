"""Minimal Agent UBID routes: capabilities, jobs, and attestations."""

import hashlib
import os
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from app.agent_signer import canonical_json_bytes, get_agent_pubkey_hex, sign_message, verify_message
from app.database import session_scope
from app.models import AgentEvent, AgentJob
from app.payments.ln import check_invoice_paid, create_invoice

agent_bp = Blueprint("agent", __name__)

PING_SATS = 21
ATTESTATION_SATS = 1
MAX_JOBS_PER_DAY = 100

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


@agent_bp.get("/agent/capabilities")
def capabilities():
    payload = {
        "agent_pubkey": get_agent_pubkey_hex(),
        "version": "0.1",
        "endpoints": {
            "request": "/agent/request",
            "job": "/agent/jobs/<job_id>",
            "verify": "/agent/verify/<job_id>",
            "attestations": "/agent/attestations",
            "reputation": "/agent/reputation",
        },
        "pricing": {"ping_sats": PING_SATS, "attestation_sats": ATTESTATION_SATS},
        "job_types": {
            "ping": {
                "price_sats": PING_SATS,
                "input_schema": {
                    "payload": "object"
                },
                "output_schema": {
                    "ok": "boolean",
                    "job_type": "string",
                    "echo": "object"
                }
            },
            "verify_signature": {
                "price_sats": PING_SATS,
                "input_schema": {
                    "message": "string",
                    "signature": "hex",
                    "pubkey": "compressed secp256k1 hex"
                },
                "output_schema": {
                    "ok": "boolean",
                    "job_type": "string",
                    "valid": "boolean"
                }
            },
            "covenant_decode": {
                "price_sats": PING_SATS,
                "input_schema": {
                    "script_hex": "hex"
                },
                "output_schema": {
                    "ok": "boolean",
                    "job_type": "string",
                    "decoded": "string",
                    "has_cltv": "boolean"
                }
            }
        },
        "limits": {"max_jobs_per_day": MAX_JOBS_PER_DAY},
        "timestamp": _iso_now(),
        "sig_scheme": "secp256k1",
    }
    payload["signature"] = sign_message(canonical_json_bytes(payload))
    return jsonify(payload)


@agent_bp.post("/agent/request")
def create_job_request():
    data = request.get_json(silent=True) or {}
    job_type = data.get("job_type")
    payload = data.get("payload") or {}

    if job_type not in {"ping", "verify_signature", "covenant_decode"}:
        return jsonify({"error": "unsupported_job_type"}), 400

    request_payload = {"job_type": job_type, "payload": payload}
    req_hash = _sha256_hex(request_payload)

    if job_type == "ping":
        sats = PING_SATS
        memo = "Agent UBID ping job"
    elif job_type == "verify_signature":
        sats = PING_SATS
        memo = "Agent UBID verify_signature job"
    else:
        sats = PING_SATS
        memo = "Agent UBID covenant_decode job"

    invoice, invoice_lookup_id = create_invoice(sats, memo, get_agent_pubkey_hex())

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

    if job.job_type == "verify_signature":
        message = str(payload.get("message", ""))
        signature_hex = str(payload.get("signature", ""))
        pubkey_hex = str(payload.get("pubkey", ""))
        valid = verify_message(message.encode("utf-8"), signature_hex, pubkey_hex)
        result_payload = {
            "ok": True,
            "job_type": job.job_type,
            "valid": valid,
        }
    elif job.job_type == "covenant_decode":
        script_hex = str(payload.get("script_hex", ""))
        result_payload = {
            "ok": True,
            "job_type": job.job_type,
            "script_hex": script_hex,
            "decoded": f"script({script_hex})",
            "has_cltv": "b1" in script_hex.lower(),
        }
    else:
        result_payload = {
            "ok": True,
            "job_type": job.job_type,
            "echo": payload,
        }

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
            return jsonify({"error": "not_found"}), 404

        # If already has an event, return current status/receipt
        event = session.query(AgentEvent).filter_by(job_id=job_id).first()
        if event:
            return jsonify({"job_id": job.id, "status": job.status, "receipt": event.event_json})

        # Issue receipt now
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
        return jsonify({"job_id": job.id, "status": job.status, "receipt": receipt})



@agent_bp.get("/agent/jobs/<job_id>")
def get_job(job_id: str):
    with session_scope() as session:
        job = session.query(AgentJob).filter_by(id=job_id).first()
        if not job:
            return jsonify({"error": "not_found"}), 404

        # Most recent event for THIS job (if any)
        existing_event = (
            session.query(AgentEvent)
            .filter_by(job_id=job.id)
            .order_by(AgentEvent.created_at.desc())
            .first()
        )

        # If no receipt yet, but invoice is paid -> mint receipt exactly once
        if not existing_event and check_invoice_paid(job.payment_lookup_id):
            # Chain head = latest event across all jobs
            last_event = session.query(AgentEvent).order_by(AgentEvent.created_at.desc()).first()
            chain_head = last_event.event_hash if last_event else None

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

            existing_event = (
                session.query(AgentEvent)
                .filter_by(job_id=job.id)
                .order_by(AgentEvent.created_at.desc())
                .first()
            )

        return jsonify(
            {
                "job_id": job.id,
                "status": job.status,
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
        events = (
            session.query(AgentEvent)
            .order_by(AgentEvent.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        items = [event.event_json for event in events]
    return jsonify({"items": items, "count": len(items)})


@agent_bp.get("/agent/verify/<job_id>")
def verify_job_receipt(job_id: str):
    with session_scope() as session:
        event = (
            session.query(AgentEvent)
            .filter_by(job_id=job_id)
            .order_by(AgentEvent.created_at.desc())
            .first()
        )
        if not event:
            return jsonify({"error": "not_found"}), 404

        receipt = event.event_json
        payload = dict(receipt)
        signature = payload.pop("signature", None)

        if not signature:
            return jsonify({"error": "missing_signature"}), 500

        agent_pubkey = payload.get("agent_pubkey", "")
        valid = verify_message(canonical_json_bytes(payload), signature, agent_pubkey)
        event_hash = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()

        return jsonify(
            {
                "job_id": job_id,
                "valid": valid,
                "agent_pubkey": agent_pubkey,
                "event_hash": event_hash,
                "receipt": receipt,
            }
        )


@agent_bp.get("/agent/reputation")
def reputation():
    with session_scope() as session:
        jobs = session.query(AgentJob).all()
        events = session.query(AgentEvent).all()

        total_jobs = len(jobs)
        completed_jobs = sum(1 for j in jobs if j.status == "done")

        job_types = {}
        for j in jobs:
            job_types[j.job_type] = job_types.get(j.job_type, 0) + 1

        return jsonify(
            {
                "agent_pubkey": get_agent_pubkey_hex(),
                "total_jobs": total_jobs,
                "completed_jobs": completed_jobs,
                "job_types": job_types,
                "attestations_count": len(events),
            }
        )

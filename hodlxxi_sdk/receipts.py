from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class ReceiptError(ValueError):
    """Raised when a HODLXXI receipt shape is invalid."""


@dataclass(frozen=True)
class AgentReceipt:
    job_id: str
    status: str
    payment_hash: str | None = None
    receipt_id: str | None = None
    signature: str | None = None
    raw: Mapping[str, Any] | None = None

    @classmethod
    def from_response(cls, payload: Mapping[str, Any]) -> "AgentReceipt":
        if not isinstance(payload, Mapping):
            raise ReceiptError("receipt payload must be a mapping")

        receipt = payload.get("receipt")
        source: Mapping[str, Any]
        if isinstance(receipt, Mapping):
            source = receipt
        else:
            source = payload

        job_id = source.get("job_id") or payload.get("job_id") or payload.get("id")
        status = source.get("status") or payload.get("status")
        payment_hash = source.get("payment_hash") or payload.get("payment_hash")
        receipt_id = source.get("receipt_id") or source.get("id") or payload.get("receipt_id")
        signature = source.get("signature") or payload.get("signature")

        if not job_id:
            raise ReceiptError("receipt missing job_id")
        if not status:
            raise ReceiptError("receipt missing status")

        return cls(
            job_id=str(job_id),
            status=str(status),
            payment_hash=str(payment_hash) if payment_hash else None,
            receipt_id=str(receipt_id) if receipt_id else None,
            signature=str(signature) if signature else None,
            raw=payload,
        )

    @property
    def is_done(self) -> bool:
        return self.status.lower() in {"done", "completed", "paid", "success"}

    @property
    def is_signed(self) -> bool:
        return bool(self.signature)

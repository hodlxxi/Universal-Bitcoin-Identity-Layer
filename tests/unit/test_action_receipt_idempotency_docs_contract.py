from pathlib import Path

from app.services.action_idempotency import IDEMPOTENCY_KEY_DOMAIN, OPERATION_CONTRACT_VERSION
from app.services.action_receipt import RECEIPT_SCHEMA, SIGNATURE_DOMAIN, SIGNATURE_SCHEME


def test_documentation_constants_boundaries_and_split():
    docs = Path("docs/ACTION_RECEIPT_IDEMPOTENCY_V1.md").read_text()
    for constant in (
        RECEIPT_SCHEMA,
        SIGNATURE_DOMAIN,
        SIGNATURE_SCHEME,
        IDEMPOTENCY_KEY_DOMAIN,
        OPERATION_CONTRACT_VERSION,
    ):
        assert constant in docs
    for phrase in (
        "PR5 owns",
        "PR6 owns",
        "no automatic deletion",
        "unsafe to expose directly",
        "client-supplied `step_up_verified` is never authoritative",
        "reconstructed `VerifiedStepUp` object is never authoritative",
    ):
        assert phrase in docs

from pathlib import Path
from datetime import datetime, timezone
from hashlib import sha256

from app.services.canonical_genesis_record import (
    canonical_genesis_record_sha256,
    parse_canonical_genesis_record,
)


def test_source_publication_is_exact_and_digest_pinned():
    path = Path("docs/data/e923_canonical_genesis_record_v1.json")
    item = parse_canonical_genesis_record(path.read_bytes())
    assert item.record_id == "e9230000-0000-4000-8000-000000000001"
    assert canonical_genesis_record_sha256(item) == ("df0445177ad8e913ef18dbf4670e8f8bc7a23f8adb14b9d87d4425dc3c5b1339")
    assert item.created_at == item.effective_at == item.lifecycle_changed_at
    assert item.created_at == datetime(2026, 7, 26, 7, 12, 51, tzinfo=timezone.utc)
    assert item.created_at >= datetime(2026, 7, 26, 6, 33, 21, tzinfo=timezone.utc)
    evidence = {value.reference_id: value for value in item.evidence_references}
    assert (
        evidence["e923_operator_continuity"].content_sha256
        == sha256(Path("docs/OPERATOR_CONTINUITY_E923.md").read_bytes()).hexdigest()
    )
    assert all(
        value.content_sha256
        not in (
            sha256(value.location.encode()).hexdigest(),
            sha256(Path(value.location).as_posix().encode()).hexdigest(),
        )
        for value in evidence.values()
        if value.content_sha256 is not None
    )
    forbidden = (
        "sponsor",
        "parent",
        "txid",
        "vout",
        "wallet",
        "descriptor",
        "amount_sats",
    )
    assert all(value not in path.read_text(encoding="utf-8") for value in forbidden)

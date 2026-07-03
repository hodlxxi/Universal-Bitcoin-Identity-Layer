from pathlib import Path

from app.auth_api_core import agent_requester_proof_storage_mode, requester_proof_storage_worker_warning


def test_requester_proof_storage_mode_memory_contract():
    mode = agent_requester_proof_storage_mode()

    assert mode["storage"] == "memory"
    assert mode["shared_across_workers"] is False
    assert mode["requires"] == "single_worker_or_session_affinity"
    assert mode["ttl_seconds"] == 300
    assert mode["multi_worker_safe"] is False
    assert "Redis" in mode["risk"] or "shared TTL" in mode["risk"]


def test_requester_proof_worker_warning_for_multi_worker_env():
    warning = requester_proof_storage_worker_warning({"WEB_CONCURRENCY": "2"})

    assert warning is not None
    assert "process-local memory" in warning
    assert "WEB_CONCURRENCY=2" in warning
    assert "Redis/shared TTL storage" in warning


def test_requester_proof_worker_warning_ignores_single_or_unparseable_env():
    assert requester_proof_storage_worker_warning({"WEB_CONCURRENCY": "1"}) is None
    assert requester_proof_storage_worker_warning({"WEB_CONCURRENCY": "many", "GUNICORN_WORKERS": "0"}) is None


def test_requester_proof_store_docs_cover_single_worker_shared_storage_contract():
    text = Path("docs/HUMAN_PROOF_REQUESTER_PROOF_STORE.md").read_text()

    for marker in [
        "process-local memory",
        "single worker",
        "session affinity",
        "Redis or another shared TTL storage layer",
        '"shared_across_workers": false',
        '"requires": "single_worker_or_session_affinity"',
        '"multi_worker_safe": false',
        "does not change what a receipt proves",
        "not make HODLXXI",
        "KYC",
        "legal identity",
        "custody",
        "token, investment",
    ]:
        assert marker in text

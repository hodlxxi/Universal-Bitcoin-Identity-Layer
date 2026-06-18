from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
STATUS_PHRASE = "Status:** Historical checkpoint"

HISTORICAL_CHECKPOINT_FILES = [
    "docs/ops/AGENT_LN_BACKEND_DROPIN_CLEANUP_2026-05-07.md",
    "docs/ops/ENV_DEDUPE_CHECKPOINT_2026-05-07.md",
    "docs/ops/GUNICORN_EVENTLET_SHUTDOWN_DIAGNOSIS_2026-05-09.md",
    "docs/ops/LND_DROPIN_CLEANUP_ROLLBACK_2026-05-07.md",
    "docs/ops/LND_RPCSERVER_DROPIN_CLEANUP_2026-05-07.md",
    "docs/ops/NATIVE_LND_STATUS_ROLLOUT_2026-05-09.md",
    "docs/ops/NATIVE_PUBLIC_STATUS_ROLLOUT_2026-05-07.md",
    "docs/ops/OVERRIDE_CONF_CLEANUP_CHECKPOINT_2026-05-07.md",
    "docs/ops/POST_RAM_RESTART_PROOF_2026-05-09.md",
    "docs/ops/REDIS_ENV_CLEANUP_CHECKPOINT_2026-05-07.md",
    "docs/ops/REMAINING_LND_HELPER_STATE_2026-05-07.md",
    "docs/ops/SECRETS_ROTATION_PLAN_2026-05-04.md",
    "docs/ops/SECRET_KEY_DROPIN_CLEANUP_2026-05-06.md",
    "docs/ops/STAGING_ENVLINE_CLEANUP_2026-05-07.md",
    "docs/ops/SYSTEMD_ENV_CLEANUP_CHECKPOINT_2026-05-05.md",
    "docs/ops/SYSTEMD_LIFECYCLE_TUNING_2026-05-07.md",
    "HARDENING_SPRINT_2026-05-04.md",
    "RED_TEAM_REMEDIATION_STATUS_2026-04-29.md",
    "RUNTIME_TRANSITION_STATUS.md",
    "STATE_OF_PRODUCT_AND_RUNTIME.md",
    "TODO_GRANT_GRADE_REMEDIATION.md",
    "docs/HODLXXI_AGENT_PROTOCOL_V0.2.md",
]

CURRENT_DOC_FILES = [
    "docs/ops/PUBLIC_AGENT_CONTRACT_SMOKE.md",
    "docs/READINESS_EVALUATION.md",
    "docs/DOCUMENTATION_MAP.md",
    "docs/AGENT_RECEIPT_V1.md",
    "docs/AGENT_RECEIPT_QUICKSTART.md",
    "AGENT_PROTOCOL.md",
    "README.md",
]


def read_doc(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_selected_historical_checkpoint_docs_have_status_notes_near_top():
    for relative_path in HISTORICAL_CHECKPOINT_FILES:
        path = REPO_ROOT / relative_path
        assert path.exists(), f"Missing historical checkpoint doc: {relative_path}"

        text = path.read_text(encoding="utf-8")
        first_lines = "\n".join(text.splitlines()[:8])

        assert STATUS_PHRASE in text
        assert STATUS_PHRASE in first_lines
        assert "Do not treat it as the current runbook" in first_lines
        assert "docs/DOCUMENTATION_MAP.md" in first_lines
        assert "docs/READINESS_EVALUATION.md" in first_lines


def test_current_docs_do_not_have_historical_checkpoint_status_notes():
    for relative_path in CURRENT_DOC_FILES:
        path = REPO_ROOT / relative_path
        assert path.exists(), f"Missing current doc: {relative_path}"
        assert STATUS_PHRASE not in path.read_text(encoding="utf-8")


def test_documentation_map_mentions_historical_status_note_scope():
    documentation_map = read_doc("docs/DOCUMENTATION_MAP.md")

    assert "standard status note" in documentation_map
    assert "current implementation truth" in documentation_map

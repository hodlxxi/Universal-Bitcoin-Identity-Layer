"""Docs contract for production readiness artifact storage."""

from pathlib import Path

ENV_VAR = "AGENT_READINESS_REPORT_DIR"
PROD_DIR = "/srv/ubid/runtime/agent_readiness_reports"
DEV_DIR = "data/agent_readiness_reports/"


def _read(path: str) -> str:
    return Path(path).read_text()


def test_readme_documents_production_readiness_artifact_env():
    text = _read("README.md")
    assert ENV_VAR in text
    assert PROD_DIR in text
    assert "hodlxxi.service" in text


def test_runtime_docs_document_systemd_readiness_artifact_storage():
    text = _read("docs/AGENT_RUNTIME.md")
    assert "Production readiness artifact storage" in text
    assert ENV_VAR in text
    assert PROD_DIR in text
    assert "ReadWritePaths=/srv/ubid/runtime" in text
    assert "[Service]" in text
    assert f"Environment={ENV_VAR}={PROD_DIR}" in text


def test_readiness_report_docs_document_artifact_urls_and_storage():
    text = _read("docs/AGENT_READINESS_REPORT_V1.md")
    assert "Production artifact storage" in text
    assert "/reports/<report_id>.json" in text
    assert "/verify/report/<report_id>" in text
    assert ENV_VAR in text
    assert PROD_DIR in text
    assert "install -d -m 0750 -o hodlxxi -g hodlxxi" in text
    assert DEV_DIR in text
    assert "should not be committed" in text


def test_gitignore_excludes_generated_default_readiness_artifacts():
    text = _read(".gitignore")
    assert DEV_DIR in text

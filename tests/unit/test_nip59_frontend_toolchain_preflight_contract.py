"""NIP-59 frontend toolchain preflight contract.

P23 documents that browser crypto dependencies must be built reproducibly and
must not be improvised on the production runtime host.
"""

from pathlib import Path

DOC = Path("docs/ops/NIP59_FRONTEND_TOOLCHAIN_PREFLIGHT.md")


def test_frontend_toolchain_preflight_doc_exists():
    text = DOC.read_text(encoding="utf-8")

    assert (
        "Do not install npm or mutate the frontend dependency toolchain directly on the production runtime host" in text
    )
    assert "controlled development, CI, or dedicated builder environment" in text
    assert "reproducible static artifact" in text


def test_frontend_toolchain_requires_lockfile_and_pinned_dependencies():
    text = DOC.read_text(encoding="utf-8")

    assert "`package.json`" in text
    assert "committed lockfile" in text
    assert "pinned dependency versions" in text
    assert "documented build command" in text
    assert "generated local static bundle" in text


def test_frontend_toolchain_keeps_runtime_safety_invariants():
    text = DOC.read_text(encoding="utf-8")

    assert "production `NIP17_MESSAGES_ENABLED` remains absent or false" in text
    assert "relay publishing remains disabled" in text
    assert "`Send sealed envelope` remains disabled" in text
    assert "plaintext is never sent to the server" in text
    assert "no production npm install is required" in text


def test_p23_does_not_add_frontend_package_files_yet():
    assert not Path("package.json").exists()
    assert not Path("package-lock.json").exists()
    assert not Path("pnpm-lock.yaml").exists()
    assert not Path("yarn.lock").exists()

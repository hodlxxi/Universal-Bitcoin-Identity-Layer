"""Unit safety regressions for the read-only paired-preview auditor."""

from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import audit_paired_preview_read_only as audit


def test_sha_and_source_fail_closed():
    commit = "a" * 40
    assert audit.sha(commit)
    assert not audit.sha("a" * 8)
    assert not audit.sha("../main")
    with patch.object(audit, "run", return_value=(0, commit)):
        assert audit.check_source(Path("/srv/repo"), commit) == "FAIL"


def test_source_requires_exact_head_and_clean_tracked_tree(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    commit = "a" * 40
    with patch.object(audit, "run", side_effect=[(0, commit), (0, "")]):
        assert audit.check_source(repo, commit) == "PASS"
    with patch.object(audit, "run", side_effect=[(0, commit), (0, " M app/factory.py")]):
        assert audit.check_source(repo, commit) == "FAIL"
    with patch.object(audit, "run", return_value=(0, "b" * 40)):
        assert audit.check_source(repo, commit) == "FAIL"


def test_probe_never_contacts_external_domain(tmp_path):
    root = tmp_path
    (root / "browser-proxy").mkdir()
    (root / "browser-proxy" / "ca.crt").write_text("test-only")
    seen = []

    def runner(args, **_kwargs):
        seen.append(args)
        return 0, "200"

    with patch.object(audit, "run", side_effect=runner):
        assert audit.check_probe(
            root, "social", "https://social-preview.hodlxxi.test:9544/auth/messages/config"
        ) == "PASS"
    assert "--unix-socket" in seen[0]
    assert "--cacert" in seen[0]
    assert "--output" in seen[0]
    assert "/dev/null" in seen[0]
    assert "https://social-preview.hodlxxi.test:9544/auth/messages/config" in seen[0]
    assert audit.check_probe(root, "production", "https://hodlxxi.com") == "FAIL"


@pytest.mark.parametrize("status,output,expected", [(0, "active", "PASS"), (0, "inactive", "FAIL"), (1, "", "FAIL")])
def test_unit_status(status, output, expected):
    with patch.object(audit, "run", return_value=(status, output)):
        assert audit.check_unit("hxxi-paired-browser-social-r2.service") == expected

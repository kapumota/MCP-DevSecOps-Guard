import json
from pathlib import Path

import pytest

from devsecops_agent.artifacts import (
    list_artifacts,
    read_artifact_text,
    read_named_artifact_text,
    summarize_security_findings,
)
from devsecops_agent.commands import run_make_target


def test_artifact_listing_and_summary(tmp_path: Path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (tmp_path / ".evidence").mkdir()
    (artifacts / "bandit.json").write_text(
        json.dumps({"results": [{"issue_severity": "HIGH", "issue_confidence": "MEDIUM"}]}),
        encoding="utf-8",
    )

    rows = list_artifacts(tmp_path)
    assert rows[0]["relative_path"] == "artifacts/bandit.json"

    summary = summarize_security_findings(tmp_path)
    assert summary["tools"]["bandit"]["finding_count"] == 1
    assert summary["tools"]["bandit"]["by_severity"]["high"] == 1


def test_read_artifact_blocks_path_traversal(tmp_path: Path):
    (tmp_path / "artifacts").mkdir()
    (tmp_path / ".evidence").mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("do not read", encoding="utf-8")

    with pytest.raises(ValueError):
        read_artifact_text("../secret.txt", root=tmp_path)


def test_named_artifact_resource_rejects_paths(tmp_path: Path):
    (tmp_path / "artifacts").mkdir()
    (tmp_path / ".evidence").mkdir()
    (tmp_path / ".evidence/local-security.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError):
        read_named_artifact_text("artifacts", "../.evidence/local-security.json", root=tmp_path)
    with pytest.raises(ValueError):
        read_named_artifact_text(".evidence", "subdir/file.json", root=tmp_path)


def test_run_make_target_rejects_unlisted_targets(tmp_path: Path):
    with pytest.raises(ValueError):
        run_make_target("shell", root=tmp_path)

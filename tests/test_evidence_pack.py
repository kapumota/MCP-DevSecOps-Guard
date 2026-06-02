import json
import tarfile
from pathlib import Path

from devsecops_agent.evidence_pack import create_evidence_pack


def test_evidence_pack_creates_manifest_and_archive(tmp_path: Path):
    artifacts = tmp_path / "artifacts"
    evidence = tmp_path / ".evidence"
    artifacts.mkdir()
    evidence.mkdir()
    (artifacts / "skill-scan-report.json").write_text('{"status":"PASS"}', encoding="utf-8")
    (evidence / "health.json").write_text('{"ok":true}', encoding="utf-8")

    manifest = create_evidence_pack(
        root=tmp_path, output_path=Path("artifacts/evidence-test.tar.gz")
    )

    pack_path = tmp_path / manifest["pack_path"]
    manifest_path = tmp_path / manifest["manifest_path"]
    assert pack_path.is_file()
    assert manifest_path.is_file()
    assert len(manifest["pack_sha256"]) == 64

    loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert loaded["included_file_count"] >= 2
    assert loaded["pack_sha256"] == manifest["pack_sha256"]
    assert loaded["files"] == manifest["files"]
    assert not any(
        entry["relative_path"] == "artifacts/evidence-manifest.json" for entry in loaded["files"]
    )

    with tarfile.open(pack_path, "r:gz") as archive:
        names = archive.getnames()
    assert "artifacts/skill-scan-report.json" in names
    assert ".evidence/health.json" in names
    assert "artifacts/evidence-manifest.json" not in names

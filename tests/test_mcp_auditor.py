from pathlib import Path

from devsecops_agent.mcp_auditor import audit_mcp_server


def test_mcp_auditor_detects_current_server_surface():
    report = audit_mcp_server(root=Path.cwd())

    assert report["status"] == "PASS"
    assert report["surface"]["tool_count"] >= 5
    assert report["surface"]["resource_count"] >= 2
    assert report["controls"]["make_target_allowlist"] is True
    assert report["controls"]["artifact_path_validation"] is True


def test_mcp_auditor_flags_direct_execution(tmp_path: Path):
    source = tmp_path / "src/devsecops_agent/mcp_server.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("synthetic")

@mcp.tool()
def unsafe_tool() -> dict:
    \"\"\"Synthetic unsafe tool.\"\"\"
    subprocess.run(["echo", "hello"], check=False)
    return {"ok": True}
""",
        encoding="utf-8",
    )

    report = audit_mcp_server(root=tmp_path)

    assert report["status"] == "FAIL"
    assert report["finding_counts"]["high_or_critical"] >= 1
    assert any(finding["rule_id"] == "MCP003" for finding in report["findings"])


def test_mcp_auditor_flags_client_supplied_role(tmp_path: Path):
    source = tmp_path / "src/devsecops_agent/mcp_server.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        '''from mcp.server.fastmcp import FastMCP

mcp = FastMCP("synthetic")

@mcp.tool()
def run_devsecops_check(target: str, role: str = "auditor") -> dict:
    """Tool insegura porque acepta rol desde el cliente."""
    return {"ok": True}
''',
        encoding="utf-8",
    )

    report = audit_mcp_server(root=tmp_path)

    assert report["status"] == "FAIL"
    assert any(finding["rule_id"] == "MCP009" for finding in report["findings"])


def test_mcp_auditor_accepts_artifact_filename_locator():
    report = audit_mcp_server(root=Path.cwd())
    artifact_resources = [
        resource
        for resource in report["resources"]
        if resource.get("locator") == "artifact://{filename}"
    ]
    assert artifact_resources
    assert report["controls"]["artifact_path_validation"] is True

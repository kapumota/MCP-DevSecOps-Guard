from pathlib import Path

import pytest

from devsecops_agent.rbac import RbacError, authorize_tool_invocation
from devsecops_agent.sandbox import require_sandbox_for_mode


def test_auditor_cannot_run_security_ci():
    with pytest.raises(RbacError):
        authorize_tool_invocation(role="auditor_readonly", tool_name="run_devsecops_check", target="security-ci", root=Path.cwd())



def test_readonly_auditor_cannot_create_evidence_archive():
    with pytest.raises(RbacError):
        authorize_tool_invocation(role="auditor_readonly", tool_name="create_evidence_archive", root=Path.cwd())


def test_operator_auditor_can_generate_dashboard():
    result = authorize_tool_invocation(role="auditor_operator", tool_name="generate_product_dashboard", root=Path.cwd())
    assert result["allowed"] is True
    assert result["role"] == "auditor_operator"


def test_default_role_is_readonly(monkeypatch):
    monkeypatch.delenv("SKILLCHAIN_MCP_ROLE", raising=False)
    result = authorize_tool_invocation(role=None, tool_name="summarize_findings", root=Path.cwd())
    assert result["role"] == "auditor_readonly"

def test_ci_runner_can_run_security_ci():
    result = authorize_tool_invocation(role="ci_runner", tool_name="run_devsecops_check", target="security-ci", root=Path.cwd())
    assert result["allowed"] is True
    assert result["role"] == "ci_runner"


def test_unknown_target_is_denied_by_rbac():
    with pytest.raises(RbacError):
        authorize_tool_invocation(role="ci_runner", tool_name="run_devsecops_check", target="shell", root=Path.cwd())


def test_strict_mode_requires_enabled_sandbox():
    with pytest.raises(RuntimeError):
        require_sandbox_for_mode(mode="strict", sandbox="disabled")


def test_demo_mode_allows_local_sandbox():
    require_sandbox_for_mode(mode="demo", sandbox="local")


def test_mcp_tool_does_not_accept_client_role_argument():
    import ast
    from pathlib import Path

    source = Path("src/devsecops_agent/mcp_server.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "run_devsecops_check"
    )
    assert "role" not in {arg.arg for arg in function.args.args}


def test_all_mcp_tools_use_common_authorization():
    import ast
    from pathlib import Path

    source = Path("src/devsecops_agent/mcp_server.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    tool_functions = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        is_tool = False
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Attribute) and target.attr == "tool":
                is_tool = True
        if is_tool:
            tool_functions.append(node)

    assert tool_functions
    for function in tool_functions:
        calls = {
            call.func.id
            for call in ast.walk(function)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        }
        assert "require_mcp_tool" in calls, function.name

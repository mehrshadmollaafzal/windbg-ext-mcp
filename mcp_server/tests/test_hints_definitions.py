from mcp_server.core.hints.definitions import get_tool_definitions


def test_runtime_control_help_metadata():
    tools = get_tool_definitions()

    assert "runtime_control" in tools
    runtime_control = tools["runtime_control"]

    assert "status" in runtime_control.actions
    assert "continue" in runtime_control.actions
    assert "break" in runtime_control.actions
    assert any(".breakin" in step for step in runtime_control.common_workflows)

import json

import httpx

from integrations.langchain_tools import BLOCKED_PREFIX, build_firewalled_tools


def _client_with_response(status_code: int, body: dict) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=body)

    return httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")


def _client_capturing_request(status_code: int, body: dict, captured: list) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        return httpx.Response(status_code, json=body)

    return httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")


def test_read_file_returns_result_when_allowed():
    client = _client_with_response(200, {"status": "allowed", "result": "file contents"})
    tools = build_firewalled_tools("agent-1", "session-1", client=client)
    read_file = tools[0]

    result = read_file("/tmp/note.txt")

    assert result == "file contents"


def test_write_file_returns_blocked_marker_when_denied_not_raise():
    client = _client_with_response(
        200, {"status": "denied", "reason": "Decision timed out; denied by default (fail-closed)."}
    )
    tools = build_firewalled_tools("agent-1", "session-1", client=client)
    write_file = tools[1]

    result = write_file("/tmp/index.html", "<html>new</html>")

    assert result.startswith(BLOCKED_PREFIX)
    assert "fail-closed" in result


def test_run_shell_sends_agent_session_and_intent_in_request():
    captured: list = []
    client = _client_capturing_request(200, {"status": "allowed", "result": "ok"}, captured)
    tools = build_firewalled_tools(
        "agent-42", "session-7", user_intent="Update the frontend", client=client
    )
    run_shell = tools[2]

    run_shell("echo hello")

    assert len(captured) == 1
    payload = captured[0]
    assert payload["tool_name"] == "run_shell"
    assert payload["args"] == {"command": "echo hello"}
    assert payload["agent_id"] == "agent-42"
    assert payload["session_id"] == "session-7"
    assert payload["user_intent"] == "Update the frontend"


def test_tools_have_docstrings_for_schema_inference():
    tools = build_firewalled_tools("agent-1", "session-1")

    for fn in tools:
        assert fn.__doc__, f"{fn.__name__} needs a docstring for LangChain schema inference"

from __future__ import annotations

from integrations.claude_code_hook import handle_hook, normalize_tool_call


def _base(event_name: str) -> dict:
    return {
        "hook_event_name": event_name,
        "session_id": "claude-session-1",
        "cwd": "/project",
        "permission_mode": "default",
    }


def test_user_prompt_is_forwarded_with_claude_agent_identity():
    calls = []

    def sender(path, payload):
        calls.append((path, payload))
        return {"action": "allow"}

    result = handle_hook({**_base("UserPromptSubmit"), "prompt": "fix the tests"}, sender)

    assert result == {}
    assert calls[0][0] == "/api/codex/event"
    assert calls[0][1]["agent_id"] == "claude-code-main"
    assert calls[0][1]["content"] == "fix the tests"
    assert calls[0][1]["turn_id"] == "claude-session-1"


def test_bash_pre_tool_uses_evaluate_only_gateway():
    calls = []

    def sender(path, payload):
        calls.append((path, payload))
        return {"status": "allowed"}

    result = handle_hook(
        {
            **_base("PreToolUse"),
            "tool_name": "Bash",
            "tool_input": {"command": "pytest -q"},
            "tool_use_id": "toolu-1",
        },
        sender,
    )

    assert result == {}
    assert calls[0][0] == "/api/tool_call"
    assert calls[0][1]["tool_name"] == "run_shell"
    assert calls[0][1]["args"]["command"] == "pytest -q"
    assert calls[0][1]["args"]["_tool_use_id"] == "toolu-1"
    assert calls[0][1]["execute"] is False


def test_read_and_write_tools_are_normalized_for_existing_risk_rules():
    read_name, read_args = normalize_tool_call(
        {
            **_base("PreToolUse"),
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/.env"},
            "tool_use_id": "toolu-read",
        }
    )
    write_name, write_args = normalize_tool_call(
        {
            **_base("PreToolUse"),
            "tool_name": "Write",
            "tool_input": {"file_path": "/project/app.py", "content": "print('ok')"},
            "tool_use_id": "toolu-write",
        }
    )

    assert read_name == "read_file"
    assert read_args["path"] == "/project/.env"
    assert write_name == "write_file"
    assert write_args["path"] == "/project/app.py"


def test_denied_pre_tool_maps_to_claude_permission_decision():
    def sender(_path, _payload):
        return {"status": "denied", "reason": "credential access"}

    result = handle_hook(
        {
            **_base("PreToolUse"),
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/.env"},
        },
        sender,
    )

    assert result["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert result["hookSpecificOutput"]["permissionDecisionReason"] == "credential access"


def test_post_tool_success_and_failure_are_recorded():
    calls = []

    def sender(path, payload):
        calls.append((path, payload))
        return {"action": "recorded"}

    success = handle_hook(
        {
            **_base("PostToolUse"),
            "tool_name": "Write",
            "tool_input": {"file_path": "/project/app.py"},
            "tool_response": {"filePath": "/project/app.py", "success": True},
        },
        sender,
    )
    failure = handle_hook(
        {
            **_base("PostToolUseFailure"),
            "tool_name": "Bash",
            "tool_input": {"command": "pytest"},
            "error": "exit status 1",
            "is_interrupt": False,
        },
        sender,
    )

    assert success == {}
    assert failure == {}
    assert calls[0][1]["tool_response"]["success"] is True
    assert calls[1][1]["tool_response"] == {
        "status": "failure",
        "error": "exit status 1",
        "is_interrupt": False,
    }


def test_post_tool_and_stop_fail_open_during_backend_outage():
    def sender(_path, _payload):
        raise RuntimeError("offline")

    post = handle_hook(
        {
            **_base("PostToolUse"),
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/a.txt"},
            "tool_response": "ok",
        },
        sender,
    )
    stop = handle_hook(
        {**_base("Stop"), "last_assistant_message": "done"}, sender
    )

    assert post == {}
    assert stop == {}


def test_pre_tool_fails_closed_during_backend_outage():
    def sender(_path, _payload):
        raise RuntimeError("offline")

    result = handle_hook(
        {
            **_base("PreToolUse"),
            "tool_name": "Bash",
            "tool_input": {"command": "echo safe"},
        },
        sender,
    )

    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

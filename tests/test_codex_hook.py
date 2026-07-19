from __future__ import annotations

from pathlib import Path

from integrations.codex_hook import handle_hook, normalize_tool_call


def _base(event_name: str) -> dict:
    return {
        "hook_event_name": event_name,
        "session_id": "session-1",
        "turn_id": "turn-1",
        "cwd": "/project",
        "model": "gpt-test",
        "permission_mode": "default",
    }


def test_user_prompt_is_forwarded_and_denial_blocks():
    calls = []

    def sender(path, payload):
        calls.append((path, payload))
        return {"action": "deny", "reason": "reviewer denied"}

    result = handle_hook({**_base("UserPromptSubmit"), "prompt": "hello"}, sender)

    assert calls[0][0] == "/api/codex/event"
    assert calls[0][1]["content"] == "hello"
    assert result == {"decision": "block", "reason": "reviewer denied"}


def test_pre_tool_bash_uses_evaluate_only_gateway():
    calls = []

    def sender(path, payload):
        calls.append((path, payload))
        return {"status": "allowed"}

    result = handle_hook(
        {
            **_base("PreToolUse"),
            "tool_name": "Bash",
            "tool_input": {"command": "echo safe"},
        },
        sender,
    )

    assert result == {}
    assert calls[0][0] == "/api/tool_call"
    assert calls[0][1]["tool_name"] == "run_shell"
    assert calls[0][1]["args"]["command"] == "echo safe"
    assert calls[0][1]["execute"] is False


def test_apply_patch_collects_absolute_paths(tmp_path):
    tool_name, args = normalize_tool_call(
        {
            **_base("PreToolUse"),
            "cwd": str(tmp_path),
            "tool_name": "apply_patch",
            "tool_input": {
                "command": "*** Begin Patch\n*** Update File: app/main.py\n*** Delete File: .env\n*** End Patch"
            },
        }
    )

    assert tool_name == "apply_patch"
    assert args["path"] == str((tmp_path / "app" / "main.py").resolve())
    assert str((tmp_path / ".env").resolve()) in args["paths"]


def test_preflight_outage_fails_closed():
    def sender(_path, _payload):
        raise RuntimeError("offline")

    prompt = handle_hook(
        {**_base("UserPromptSubmit"), "prompt": "hello"}, sender
    )
    tool = handle_hook(
        {
            **_base("PreToolUse"),
            "tool_name": "Bash",
            "tool_input": {"command": "echo safe"},
        },
        sender,
    )

    assert prompt["decision"] == "block"
    assert tool["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_stop_continue_and_post_tool_block_are_mapped():
    def sender(_path, payload):
        if payload["event_type"] == "assistant_response":
            return {"action": "continue", "reason": "rewrite safely"}
        return {"action": "deny", "reason": "secret result"}

    stop = handle_hook(
        {**_base("Stop"), "last_assistant_message": "unsafe", "stop_hook_active": False},
        sender,
    )
    post = handle_hook(
        {
            **_base("PostToolUse"),
            "tool_name": "Bash",
            "tool_input": {"command": "printenv"},
            "tool_response": "secret",
        },
        sender,
    )

    assert stop == {"decision": "block", "reason": "rewrite safely"}
    assert post == {"decision": "block", "reason": "secret result"}


def test_post_events_fail_open_on_outage():
    def sender(_path, _payload):
        raise RuntimeError("offline")

    stop = handle_hook(
        {**_base("Stop"), "last_assistant_message": "hello"}, sender
    )
    post = handle_hook(
        {
            **_base("PostToolUse"),
            "tool_name": "Bash",
            "tool_input": {},
            "tool_response": "ok",
        },
        sender,
    )

    assert stop == {}
    assert post == {}

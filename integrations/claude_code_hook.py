from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

FIREWALL_URL = os.getenv("AGENT_FIREWALL_URL", "http://127.0.0.1:8000").rstrip("/")
HOOK_TIMEOUT_SECONDS = float(os.getenv("AGENT_FIREWALL_HOOK_TIMEOUT_SECONDS", "170"))
AGENT_ID = os.getenv("CLAUDE_CODE_FIREWALL_AGENT_ID", "claude-code-main")

Sender = Callable[[str, dict[str, Any]], dict[str, Any]]


def _post_json(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = Request(
        f"{FIREWALL_URL}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=HOOK_TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Firewall returned HTTP {exc.code}: {detail}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Firewall request failed: {exc}") from exc
    decoded = json.loads(body)
    if not isinstance(decoded, dict):
        raise RuntimeError("Firewall response was not a JSON object")
    return decoded


def handle_hook(payload: dict[str, Any], sender: Sender = _post_json) -> dict[str, Any]:
    event_name = payload.get("hook_event_name")
    try:
        if event_name == "UserPromptSubmit":
            return _handle_user_prompt(payload, sender)
        if event_name == "PreToolUse":
            return _handle_pre_tool(payload, sender)
        if event_name in {"PostToolUse", "PostToolUseFailure"}:
            return _handle_post_tool(payload, sender)
        if event_name == "Stop":
            return _handle_stop(payload, sender)
        return {}
    except Exception as exc:
        if event_name == "UserPromptSubmit":
            return {
                "decision": "block",
                "reason": f"Agent Firewall unavailable; prompt blocked by fail-closed policy. {exc}",
            }
        if event_name == "PreToolUse":
            return _deny_tool(
                f"Agent Firewall unavailable; tool blocked by fail-closed policy. {exc}"
            )
        # The action has already completed for post-tool hooks. Keep telemetry
        # failures from trapping Claude Code in an outage loop.
        return {}


def _handle_user_prompt(payload: dict[str, Any], sender: Sender) -> dict[str, Any]:
    response = sender(
        "/api/codex/event",
        {
            **_common_event(payload),
            "event_type": "user_prompt",
            "content": payload.get("prompt", ""),
        },
    )
    if response.get("action") == "deny":
        return {
            "decision": "block",
            "reason": response.get("reason") or "Prompt denied by Agent Firewall.",
        }
    additional_context = response.get("additional_context")
    if additional_context:
        return {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": additional_context,
            }
        }
    return {}


def _handle_pre_tool(payload: dict[str, Any], sender: Sender) -> dict[str, Any]:
    tool_name, args = normalize_tool_call(payload)
    response = sender(
        "/api/tool_call",
        {
            "tool_name": tool_name,
            "args": args,
            "agent_id": AGENT_ID,
            "session_id": _session_id(payload),
            # Claude Code does not currently provide a turn id to hooks. Use
            # the session id consistently so the latest prompt can be joined
            # to subsequent tool calls by the existing backend.
            "turn_id": _turn_id(payload),
            "execute": False,
        },
    )
    if response.get("status") == "denied":
        return _deny_tool(response.get("reason") or "Tool denied by Agent Firewall.")
    return {}


def _handle_post_tool(payload: dict[str, Any], sender: Sender) -> dict[str, Any]:
    failed = payload.get("hook_event_name") == "PostToolUseFailure"
    tool_response: Any
    if failed:
        tool_response = {
            "status": "failure",
            "error": payload.get("error"),
            "is_interrupt": bool(payload.get("is_interrupt")),
        }
    else:
        tool_response = payload.get("tool_response")

    response = sender(
        "/api/codex/event",
        {
            **_common_event(payload),
            "event_type": "post_tool_use",
            "tool_name": payload.get("tool_name"),
            "tool_input": _dict_or_wrapped(payload.get("tool_input")),
            "tool_response": tool_response,
        },
    )
    if response.get("action") == "deny":
        return {
            "decision": "block",
            "reason": response.get("reason") or "Sensitive tool result withheld.",
        }
    return {}


def _handle_stop(payload: dict[str, Any], sender: Sender) -> dict[str, Any]:
    response = sender(
        "/api/codex/event",
        {
            **_common_event(payload),
            "event_type": "assistant_response",
            "content": payload.get("last_assistant_message") or "",
            "stop_hook_active": bool(payload.get("stop_hook_active")),
        },
    )
    if response.get("action") == "continue":
        return {
            "decision": "block",
            "reason": response.get("reason") or "Run one safe corrective pass.",
        }
    return {}


def _session_id(payload: dict[str, Any]) -> str:
    return str(payload.get("session_id") or "unknown")


def _turn_id(payload: dict[str, Any]) -> str:
    return str(payload.get("turn_id") or _session_id(payload))


def _common_event(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent_id": AGENT_ID,
        "session_id": _session_id(payload),
        "turn_id": _turn_id(payload),
        "cwd": payload.get("cwd"),
        "model": payload.get("model"),
        "permission_mode": payload.get("permission_mode"),
    }


def normalize_tool_call(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    claude_name = str(payload.get("tool_name") or "unknown")
    tool_input = _dict_or_wrapped(payload.get("tool_input"))

    if claude_name == "Bash":
        return "run_shell", {
            "command": str(tool_input.get("command") or ""),
            "_claude_tool_name": claude_name,
            "_tool_use_id": payload.get("tool_use_id"),
        }

    if claude_name in {"Write", "Edit", "MultiEdit"}:
        args = dict(tool_input)
        path = args.get("file_path")
        if isinstance(path, str):
            args["path"] = path
        args["_claude_tool_name"] = claude_name
        args["_tool_use_id"] = payload.get("tool_use_id")
        return "write_file", args

    if claude_name == "Read":
        args = dict(tool_input)
        path = args.get("file_path")
        if isinstance(path, str):
            args["path"] = path
        args["_claude_tool_name"] = claude_name
        args["_tool_use_id"] = payload.get("tool_use_id")
        return "read_file", args

    args = dict(tool_input)
    args["_claude_tool_name"] = claude_name
    args["_tool_use_id"] = payload.get("tool_use_id")
    return claude_name, args


def _dict_or_wrapped(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {"input": value}


def _deny_tool(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def main() -> None:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("Hook input must be a JSON object")
        result = handle_hook(payload)
    except Exception as exc:
        result = {
            "decision": "block",
            "reason": f"Agent Firewall hook failed closed: {exc}",
        }
    sys.stdout.write(json.dumps(result))


if __name__ == "__main__":
    main()

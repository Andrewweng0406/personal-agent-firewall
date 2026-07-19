from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from integrations.hook_payload import bound_payload, load_project_env
except ModuleNotFoundError:  # Direct execution from the integrations directory.
    from hook_payload import bound_payload, load_project_env

PROJECT_ENV = load_project_env()


def _setting(name: str, default: str | None = None) -> str | None:
    return os.getenv(name, PROJECT_ENV.get(name, default))

FIREWALL_URL = (_setting("AGENT_FIREWALL_URL", "http://127.0.0.1:8000") or "").rstrip("/")
HOOK_TIMEOUT_SECONDS = float(_setting("AGENT_FIREWALL_HOOK_TIMEOUT_SECONDS", "170") or "170")
AGENT_ID = _setting("CODEX_FIREWALL_AGENT_ID", "codex-main") or "codex-main"
FIREWALL_MODE = (_setting("FIREWALL_MODE", "review") or "review").strip().lower()
API_TOKEN = _setting("AGENT_FIREWALL_TOKEN")

_PATCH_FILE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$", re.MULTILINE)
Sender = Callable[[str, dict[str, Any]], dict[str, Any]]


def _post_json(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    payload = bound_payload(payload)
    headers = {"Content-Type": "application/json"}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    request = Request(
        f"{FIREWALL_URL}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
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
        if event_name == "PostToolUse":
            return _handle_post_tool(payload, sender)
        if event_name == "Stop":
            return _handle_stop(payload, sender)
        return {}
    except Exception as exc:
        if FIREWALL_MODE == "observe":
            return {}
        if event_name == "UserPromptSubmit":
            return {
                "decision": "block",
                "reason": f"Agent Firewall unavailable; prompt blocked by fail-closed policy. {exc}",
            }
        if event_name == "PreToolUse":
            return _deny_tool(
                f"Agent Firewall unavailable; tool blocked by fail-closed policy. {exc}"
            )
        # PostToolUse and Stop are telemetry/correction hooks. Mixed-safety
        # mode keeps Codex available if the backend cannot receive them.
        return {}


def _handle_user_prompt(payload: dict[str, Any], sender: Sender) -> dict[str, Any]:
    response = sender(
        "/api/codex/event",
        {
            **_common_event(payload),
            "event_type": "user_prompt",
            "source": "codex",
            "phase": "prompt",
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
            "session_id": str(payload.get("session_id") or "unknown"),
            "turn_id": payload.get("turn_id"),
            "execute": False,
            "source": "codex",
            "tool_use_id": payload.get("tool_use_id"),
            "phase": "before",
        },
    )
    if response.get("status") == "denied":
        return _deny_tool(response.get("reason") or "Tool denied by Agent Firewall.")
    return {}


def _handle_post_tool(payload: dict[str, Any], sender: Sender) -> dict[str, Any]:
    response = sender(
        "/api/codex/event",
        {
            **_common_event(payload),
            "event_type": "post_tool_use",
            "source": "codex",
            "phase": "after",
            "tool_use_id": payload.get("tool_use_id"),
            "tool_name": payload.get("tool_name"),
            "tool_input": _dict_or_wrapped(payload.get("tool_input")),
            "tool_response": payload.get("tool_response"),
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
            "source": "codex",
            "phase": "response",
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


def _common_event(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent_id": AGENT_ID,
        "session_id": str(payload.get("session_id") or "unknown"),
        "turn_id": str(payload.get("turn_id") or "unknown"),
        "cwd": payload.get("cwd"),
        "model": payload.get("model"),
        "permission_mode": payload.get("permission_mode"),
    }


def normalize_tool_call(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    codex_name = str(payload.get("tool_name") or "unknown")
    tool_input = _dict_or_wrapped(payload.get("tool_input"))

    if codex_name == "Bash":
        return "run_shell", {
            "command": str(tool_input.get("command") or ""),
            "_codex_tool_name": codex_name,
            "_source": "codex",
            "_tool_use_id": payload.get("tool_use_id"),
            "_phase": "before",
        }

    if codex_name == "apply_patch":
        command = str(tool_input.get("command") or "")
        cwd = Path(str(payload.get("cwd") or "."))
        paths = []
        for match in _PATCH_FILE.findall(command):
            candidate = Path(match.strip())
            if not candidate.is_absolute():
                candidate = cwd / candidate
            normalized = str(candidate.resolve(strict=False))
            if normalized not in paths:
                paths.append(normalized)
        args: dict[str, Any] = {
            "command": command,
            "paths": paths,
            "_codex_tool_name": codex_name,
            "_source": "codex",
            "_tool_use_id": payload.get("tool_use_id"),
            "_phase": "before",
        }
        if paths:
            args["path"] = paths[0]
        return "apply_patch", args

    args = dict(tool_input)
    args["_codex_tool_name"] = codex_name
    args["_source"] = "codex"
    args["_tool_use_id"] = payload.get("tool_use_id")
    args["_phase"] = "before"
    return codex_name, args


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
        # Unknown/malformed input cannot be classified as a post-event, so
        # fail closed rather than silently bypassing the firewall.
        result = (
            {}
            if FIREWALL_MODE == "observe"
            else {
                "decision": "block",
                "reason": f"Agent Firewall hook failed closed: {exc}",
            }
        )
    sys.stdout.write(json.dumps(result))


if __name__ == "__main__":
    main()

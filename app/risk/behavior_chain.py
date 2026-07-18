from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BehaviorSignal:
    score_delta: int = 0
    matched_rules: list[str] = field(default_factory=list)
    explanation: str = ""
    chain_detected: bool = False
    auto_contain: bool = False


SECRET_MARKERS = (
    "/.env",
    ".env",
    "/.ssh/",
    "id_rsa",
    "credentials",
    ".npmrc",
    ".pypirc",
    "secret",
    "token",
)

NETWORK_MARKERS = (
    "curl ",
    "wget ",
    "http://",
    "https://",
    "requests.post",
    "requests.put",
    "urllib.request",
    "socket.",
)

UPLOAD_MARKERS = (
    " -d ",
    "--data",
    "--form",
    " -f ",
    "@-",
    "post(",
    "put(",
    "send(",
    "upload",
)


def analyze_behavior_chain(
    tool_name: str,
    args: dict[str, Any],
    history: list[dict],
) -> BehaviorSignal:
    allowed_history = [row for row in history if row.get("decision") == "allowed"]
    sensitive_read = next(
        (row for row in allowed_history if _is_sensitive_read(row)),
        None,
    )

    if sensitive_read and _is_external_upload(tool_name, args):
        source = _event_target(sensitive_read) or "a sensitive source"
        return BehaviorSignal(
            score_delta=100,
            matched_rules=[
                "behavior_chain:sensitive_read_then_external_upload",
                f"behavior_chain:source:{source}",
            ],
            explanation=(
                "The agent previously read sensitive data and is now attempting "
                "an external upload in the same session. The action was blocked "
                "and the session was quarantined."
            ),
            chain_detected=True,
            auto_contain=True,
        )

    return BehaviorSignal()


def _is_sensitive_read(row: dict) -> bool:
    if row.get("tool_name") not in {"read_file", "run_shell", "exec_python"}:
        return False
    args = _event_args(row)
    text = " ".join(str(value) for value in args.values()).lower()
    reads_data = row.get("tool_name") == "read_file" or any(
        marker in text for marker in ("cat ", "open(", "read_text", "read(")
    )
    return reads_data and any(marker in text for marker in SECRET_MARKERS)


def _is_external_upload(tool_name: str, args: dict[str, Any]) -> bool:
    if tool_name not in {"run_shell", "exec_python"}:
        return False
    text = " ".join(str(value) for value in args.values()).lower()
    return any(marker in text for marker in NETWORK_MARKERS) and any(
        marker in text for marker in UPLOAD_MARKERS
    )


def _event_args(row: dict) -> dict:
    value = row.get("args")
    if isinstance(value, dict):
        return value
    try:
        decoded = json.loads(row.get("args_json", "{}"))
    except (TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _event_target(row: dict) -> str | None:
    args = _event_args(row)
    path = args.get("path")
    return path if isinstance(path, str) else None

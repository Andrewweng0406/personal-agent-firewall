from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

_MIN_TARGET_LENGTH = 4
_PATH_TOKEN_SPLIT = re.compile(r"[\s'\";|&()]+")


@dataclass
class CrossAgentSignal:
    correlated: bool = False
    score_delta: int = 0
    matched_rules: list[str] = field(default_factory=list)
    correlated_agent_ids: list[str] = field(default_factory=list)
    explanation: str = ""


def detect_cross_agent_pattern(
    agent_id: str,
    tool_name: str,
    args: dict[str, Any],
    recent_events: list[dict],
) -> CrossAgentSignal:
    """Detect coordinated or replayed attacks across different agent identities.

    A single compromised/misbehaving agent is already caught by
    `behavior_chain`'s same-session correlation. This looks wider: if a
    *different* agent_id was recently denied for touching the same target
    (file path, or the same path/command referenced inside a shell/exec
    call), that is evidence of a coordinated campaign or a replayed attack
    across multiple agent identities, not an isolated incident -- and
    warrants containing every agent involved, not just this one.
    """
    targets = _extract_targets(tool_name, args)
    if not targets:
        return CrossAgentSignal()

    correlated_agents: list[str] = []
    for row in recent_events:
        other_agent = row.get("agent_id")
        if not other_agent or other_agent == agent_id:
            continue
        if not str(row.get("decision") or "").startswith("denied"):
            continue
        other_targets = _extract_targets(row.get("tool_name") or "", _decode_args(row))
        if not other_targets:
            continue
        if other_agent in correlated_agents:
            continue
        if any(
            _same_asset(target, other_target)
            for target in targets
            for other_target in other_targets
        ):
            correlated_agents.append(other_agent)

    if not correlated_agents:
        return CrossAgentSignal()

    agents_text = ", ".join(correlated_agents)
    return CrossAgentSignal(
        correlated=True,
        score_delta=100,
        matched_rules=["cross_agent_correlation:coordinated_target"],
        correlated_agent_ids=correlated_agents,
        explanation=(
            "Another agent identity "
            f"({agents_text}) was already denied recently for targeting the "
            "same file or command -- treated as a coordinated or replayed "
            "attack across multiple agents, not an isolated incident."
        ),
    )


def _extract_targets(tool_name: str, args: dict[str, Any]) -> list[str]:
    path = args.get("path")
    if isinstance(path, str) and len(path) >= _MIN_TARGET_LENGTH:
        return [path]

    targets: list[str] = []
    for key in ("command", "code"):
        value = args.get(key)
        if not isinstance(value, str):
            continue
        for token in _PATH_TOKEN_SPLIT.split(value):
            if len(token) < _MIN_TARGET_LENGTH:
                continue
            if "/" in token or token.startswith("."):
                targets.append(token)
    return targets


def _decode_args(row: dict) -> dict:
    value = row.get("args")
    if isinstance(value, dict):
        return value
    try:
        decoded = json.loads(row.get("args_json") or "{}")
    except (TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _same_asset(target_a: str, target_b: str) -> bool:
    return target_a in target_b or target_b in target_a

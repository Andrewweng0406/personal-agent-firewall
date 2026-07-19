from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
BehaviorLane = Literal["green", "yellow", "red"]
IntentAlignment = Literal["aligned", "uncertain", "off_scope"]
CodexEventType = Literal["user_prompt", "assistant_response", "post_tool_use"]
CodexEventAction = Literal["allow", "deny", "continue", "recorded"]


class ToolCallRequest(BaseModel):
    tool_name: str
    args: dict[str, Any] = Field(default_factory=dict)
    agent_id: str
    session_id: str
    user_intent: str | None = None
    turn_id: str | None = None
    execute: bool = True
    source: str = "generic"
    tool_use_id: str | None = None
    phase: str = "before"


class ToolCallResponse(BaseModel):
    status: Literal["allowed", "denied"]
    result: Any | None = None
    risk_score: int | None = None
    reason: str | None = None
    behavior_lane: BehaviorLane | None = None
    intent_alignment: IntentAlignment | None = None
    chain_detected: bool = False
    containment_action: str | None = None
    correlated_agent_ids: list[str] = Field(default_factory=list)
    trust_score: int | None = None
    effective_threshold: int | None = None


class RiskAssessment(BaseModel):
    score: int
    level: RiskLevel
    plain_explanation: str = ""
    matched_rules: list[str] = Field(default_factory=list)
    behavior_lane: BehaviorLane = "green"
    intent_alignment: IntentAlignment = "uncertain"
    chain_detected: bool = False
    auto_contain: bool = False
    correlated_agent_ids: list[str] = Field(default_factory=list)
    trust_score: int | None = None
    effective_threshold: int | None = None


class DecisionRequest(BaseModel):
    decision: Literal["allow", "deny"]
    reviewer: str | None = None


class ContainmentRequest(BaseModel):
    scope: Literal["agent", "session"]
    agent_id: str
    session_id: str | None = None
    reason: str = "Manually quarantined by reviewer."


class CodexEventRequest(BaseModel):
    event_type: CodexEventType
    session_id: str
    turn_id: str
    agent_id: str = "codex-main"
    cwd: str | None = None
    model: str | None = None
    permission_mode: str | None = None
    content: str | None = None
    tool_name: str | None = None
    tool_input: dict[str, Any] = Field(default_factory=dict)
    tool_response: Any | None = None
    stop_hook_active: bool = False
    source: str = "codex"
    tool_use_id: str | None = None
    phase: str | None = None


class CodexEventResponse(BaseModel):
    event_id: str
    action: CodexEventAction
    reason: str | None = None
    risk_score: int = 0
    risk_level: RiskLevel = "LOW"
    matched_rules: list[str] = Field(default_factory=list)
    additional_context: str | None = None

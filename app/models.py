from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
BehaviorLane = Literal["green", "yellow", "red"]
IntentAlignment = Literal["aligned", "uncertain", "off_scope"]


class ToolCallRequest(BaseModel):
    tool_name: str
    args: dict[str, Any] = Field(default_factory=dict)
    agent_id: str
    session_id: str
    user_intent: str | None = None


class ToolCallResponse(BaseModel):
    status: Literal["allowed", "denied"]
    result: Any | None = None
    risk_score: int | None = None
    reason: str | None = None
    behavior_lane: BehaviorLane | None = None
    intent_alignment: IntentAlignment | None = None


class RiskAssessment(BaseModel):
    score: int
    level: RiskLevel
    plain_explanation: str = ""
    matched_rules: list[str] = Field(default_factory=list)
    behavior_lane: BehaviorLane = "green"
    intent_alignment: IntentAlignment = "uncertain"


class DecisionRequest(BaseModel):
    decision: Literal["allow", "deny"]
    reviewer: str | None = None

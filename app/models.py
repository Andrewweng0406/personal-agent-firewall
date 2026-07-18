from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ToolCallRequest(BaseModel):
    tool_name: str
    args: dict[str, Any] = Field(default_factory=dict)
    agent_id: str
    session_id: str


class ToolCallResponse(BaseModel):
    status: Literal["allowed", "denied"]
    result: Any | None = None
    risk_score: int | None = None
    reason: str | None = None


class RiskAssessment(BaseModel):
    score: int
    level: RiskLevel
    plain_explanation: str = ""
    matched_rules: list[str] = Field(default_factory=list)


class DecisionRequest(BaseModel):
    decision: Literal["allow", "deny"]
    reviewer: str | None = None

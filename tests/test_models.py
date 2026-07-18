import pytest
from pydantic import ValidationError

from app.models import DecisionRequest, RiskAssessment, ToolCallRequest, ToolCallResponse


def test_tool_call_request_requires_core_fields():
    request = ToolCallRequest(
        tool_name="read_file", args={"path": "/tmp/a.txt"}, agent_id="a1", session_id="s1"
    )
    assert request.tool_name == "read_file"
    assert request.args == {"path": "/tmp/a.txt"}


def test_tool_call_request_missing_field_raises():
    with pytest.raises(ValidationError):
        ToolCallRequest(tool_name="read_file", args={}, agent_id="a1")


def test_tool_call_request_defaults_empty_args():
    request = ToolCallRequest(tool_name="search_web", agent_id="a1", session_id="s1")
    assert request.args == {}


def test_risk_assessment_rejects_invalid_level():
    with pytest.raises(ValidationError):
        RiskAssessment(score=90, level="SUPER_DUPER_BAD")


def test_risk_assessment_valid_level():
    assessment = RiskAssessment(score=90, level="CRITICAL", plain_explanation="dangerous")
    assert assessment.matched_rules == []


def test_decision_request_rejects_invalid_decision():
    with pytest.raises(ValidationError):
        DecisionRequest(decision="maybe")


def test_decision_request_accepts_allow_and_deny():
    assert DecisionRequest(decision="allow").decision == "allow"
    assert DecisionRequest(decision="deny").decision == "deny"


def test_tool_call_response_allows_optional_fields_absent():
    response = ToolCallResponse(status="allowed", result="ok", risk_score=10)
    assert response.reason is None

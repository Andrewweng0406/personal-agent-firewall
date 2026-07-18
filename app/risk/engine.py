from __future__ import annotations

from app.config import Settings
from app.models import RiskAssessment
from app.risk.ast_analyzer import analyze as analyze_ast
from app.risk.llm_translator import RiskLlmClient


def _level_for_score(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def assess_risk(
    tool_name: str,
    args: dict,
    settings: Settings,
    llm_client: RiskLlmClient,
) -> RiskAssessment:
    static_score, matched_rules = analyze_ast(tool_name, args, settings)

    if static_score < settings.risk_threshold:
        return RiskAssessment(
            score=static_score,
            level=_level_for_score(static_score),
            plain_explanation="",
            matched_rules=matched_rules,
        )

    llm_result = llm_client.assess(tool_name, args, matched_rules)
    final_score = max(static_score, llm_result.score)
    return RiskAssessment(
        score=final_score,
        level=_level_for_score(final_score),
        plain_explanation=llm_result.plain_explanation,
        matched_rules=matched_rules,
    )

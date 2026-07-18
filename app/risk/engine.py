from __future__ import annotations

from app.config import Settings
from app.models import RiskAssessment
from app.risk.ast_analyzer import analyze as analyze_ast
from app.risk.behavior_chain import BehaviorSignal
from app.risk.intent_analyzer import assess_intent
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
    user_intent: str | None = None,
    behavior_signal: BehaviorSignal | None = None,
) -> RiskAssessment:
    behavior_signal = behavior_signal or BehaviorSignal()
    static_score, matched_rules = analyze_ast(tool_name, args, settings)
    intent_signal = assess_intent(tool_name, args, user_intent)
    contextual_score = min(
        100,
        static_score + intent_signal.score_delta + behavior_signal.score_delta,
    )
    # Intent alignment may reduce contextual uncertainty, but it must never
    # erase concrete evidence such as destructive code or a protected path.
    score = max(static_score, 0, contextual_score)
    all_rules = matched_rules + [
        rule for rule in intent_signal.matched_rules if rule not in matched_rules
    ]
    all_rules.extend(
        rule for rule in behavior_signal.matched_rules if rule not in all_rules
    )
    alignment = "off_scope" if behavior_signal.auto_contain else intent_signal.alignment
    lane = _lane_for_score_and_intent(score, alignment)

    if score < settings.risk_threshold:
        return RiskAssessment(
            score=score,
            level=_level_for_score(score),
            plain_explanation=behavior_signal.explanation or intent_signal.explanation,
            matched_rules=all_rules,
            behavior_lane=lane,
            intent_alignment=alignment,
            chain_detected=behavior_signal.chain_detected,
            auto_contain=behavior_signal.auto_contain,
        )

    llm_result = llm_client.assess(tool_name, args, all_rules)
    final_score = max(score, llm_result.score)
    return RiskAssessment(
        score=final_score,
        level=_level_for_score(final_score),
        plain_explanation=(
            behavior_signal.explanation
            or llm_result.plain_explanation
            or intent_signal.explanation
        ),
        matched_rules=all_rules,
        behavior_lane=_lane_for_score_and_intent(final_score, alignment),
        intent_alignment=alignment,
        chain_detected=behavior_signal.chain_detected,
        auto_contain=behavior_signal.auto_contain,
    )


def _lane_for_score_and_intent(score: int, alignment: str) -> str:
    if score >= 70 or alignment == "off_scope":
        return "red"
    if score >= 40 or alignment == "uncertain":
        return "yellow"
    return "green"

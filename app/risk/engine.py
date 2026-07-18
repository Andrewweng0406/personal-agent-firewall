from __future__ import annotations

from app.config import Settings
from app.models import RiskAssessment
from app.risk.ast_analyzer import analyze as analyze_ast
from app.risk.behavior_chain import BehaviorSignal
from app.risk.cross_agent_correlation import CrossAgentSignal
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
    cross_agent_signal: CrossAgentSignal | None = None,
) -> RiskAssessment:
    behavior_signal = behavior_signal or BehaviorSignal()
    cross_agent_signal = cross_agent_signal or CrossAgentSignal()
    static_score, matched_rules = analyze_ast(tool_name, args, settings)
    intent_signal = assess_intent(tool_name, args, user_intent)
    contextual_score = min(
        100,
        static_score
        + intent_signal.score_delta
        + behavior_signal.score_delta
        + cross_agent_signal.score_delta,
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
    all_rules.extend(
        rule for rule in cross_agent_signal.matched_rules if rule not in all_rules
    )
    auto_contain = behavior_signal.auto_contain or cross_agent_signal.correlated
    alignment = "off_scope" if auto_contain else intent_signal.alignment
    if alignment == "off_scope":
        # Off-scope intent alone must be enough to force human review, even if
        # the target isn't a statically protected path and the raw score
        # would otherwise land below the threshold.
        score = max(score, settings.risk_threshold)
    lane = _lane_for_score_and_intent(score, alignment)
    # behavior_chain/cross_agent signals are the strongest evidence and always
    # win; the LLM's explanation is preferred over intent_analyzer's generic
    # fallback text ("No user intent was provided...") whenever it's used.
    priority_explanation = behavior_signal.explanation or cross_agent_signal.explanation

    if score < settings.risk_threshold:
        return RiskAssessment(
            score=score,
            level=_level_for_score(score),
            plain_explanation=priority_explanation or intent_signal.explanation,
            matched_rules=all_rules,
            behavior_lane=lane,
            intent_alignment=alignment,
            chain_detected=behavior_signal.chain_detected,
            auto_contain=auto_contain,
            correlated_agent_ids=cross_agent_signal.correlated_agent_ids,
        )

    llm_result = llm_client.assess(tool_name, args, all_rules)
    final_score = max(score, llm_result.score)
    return RiskAssessment(
        score=final_score,
        level=_level_for_score(final_score),
        plain_explanation=(
            priority_explanation or llm_result.plain_explanation or intent_signal.explanation
        ),
        matched_rules=all_rules,
        behavior_lane=_lane_for_score_and_intent(final_score, alignment),
        intent_alignment=alignment,
        chain_detected=behavior_signal.chain_detected,
        auto_contain=auto_contain,
        correlated_agent_ids=cross_agent_signal.correlated_agent_ids,
    )


def _lane_for_score_and_intent(score: int, alignment: str) -> str:
    if score >= 70 or alignment == "off_scope":
        return "red"
    if score >= 40 or alignment == "uncertain":
        return "yellow"
    return "green"

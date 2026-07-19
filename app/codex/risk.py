from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ConversationAssessment:
    score: int
    level: str
    explanation: str
    matched_rules: list[str] = field(default_factory=list)


PII_WEIGHTS = {
    "EMAIL": 45,
    "TW_NATIONAL_ID": 95,
    "API_KEY": 100,
    "AWS_ACCESS_KEY": 100,
    "CREDIT_CARD": 95,
    "SEMANTIC_MATCH": 90,
}

PROMPT_INJECTION_MARKERS = {
    "ignore all previous instructions": 90,
    "ignore previous instructions": 85,
    "system override": 90,
    "reveal the system prompt": 90,
    "reveal your system prompt": 90,
    "bypass security": 85,
    "jailbreak": 85,
}


def assess_conversation_content(
    event_type: str,
    content: str,
    pii_matches: list[str],
) -> ConversationAssessment:
    score = 0
    matched_rules: list[str] = []

    for match in pii_matches:
        rule = f"privacy:{match.lower()}"
        if rule not in matched_rules:
            matched_rules.append(rule)
        score = max(score, PII_WEIGHTS.get(match, 70))

    if event_type == "user_prompt":
        lowered = content.lower()
        for marker, weight in PROMPT_INJECTION_MARKERS.items():
            if marker in lowered:
                rule = f"prompt_injection:{marker.replace(' ', '_')}"
                if rule not in matched_rules:
                    matched_rules.append(rule)
                score = max(score, weight)

    if matched_rules:
        if any(rule.startswith("privacy:") for rule in matched_rules):
            explanation = "The Codex event contains sensitive personal or credential data."
        else:
            explanation = "The submitted prompt contains a likely instruction-override attempt."
    else:
        explanation = "No conversation-level risk indicators were detected."

    return ConversationAssessment(
        score=min(score, 100),
        level=_level_for_score(score),
        explanation=explanation,
        matched_rules=matched_rules,
    )


def _level_for_score(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"

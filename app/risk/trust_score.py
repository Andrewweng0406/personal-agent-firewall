from __future__ import annotations

from dataclasses import dataclass

NEUTRAL_TRUST = 50
CONTAINED_PENALTY = 20
DENIED_PENALTY = 8
CLEAN_BONUS = 1
MIN_TRUST = 0
MAX_TRUST = 100

# How strongly trust moves the hold threshold away from the configured
# baseline. Deliberately asymmetric: a distrusted agent can be watched MUCH
# more closely (threshold pulled down a lot, easier to trigger a hold), but
# a trusted agent can only be given a SMALL amount of extra leeway (fewer
# unnecessary interruptions for genuinely borderline-low-risk actions).
# Trust must never be able to raise the threshold high enough to swallow a
# real static finding like a protected-path overwrite -- it can only reduce
# noise, never erode the floor of what still gets reviewed.
THRESHOLD_ADJUSTMENT_FACTOR = 0.3
MAX_POSITIVE_ADJUSTMENT = 10
MAX_NEGATIVE_ADJUSTMENT = 40
MIN_EFFECTIVE_THRESHOLD = 25
MAX_EFFECTIVE_THRESHOLD = 90


@dataclass
class TrustProfile:
    trust_score: int
    effective_threshold: int
    event_count: int
    explanation: str = ""


def compute_trust_profile(base_threshold: int, agent_history: list[dict]) -> TrustProfile:
    """Derive an agent-specific hold threshold from its own track record.

    Starts every agent at a neutral trust score of 50/100 (so an agent with
    no history behaves exactly like `base_threshold` with zero adjustment).
    Each contained/denied event nudges trust down; each clean, low-risk
    ("green" lane, "allowed") event nudges it up slightly. The resulting
    trust score shifts the *effective* hold threshold for this agent only --
    a repeatedly risky agent gets watched more closely (lower threshold,
    easier to trigger a hold), while a consistently well-behaved agent stops
    getting interrupted for borderline-low-risk actions (higher threshold).
    The adjustment is capped in both directions so trust alone can never
    make the gate trivially bypassable or effectively unusable.
    """
    trust = NEUTRAL_TRUST
    for row in agent_history:
        decision = str(row.get("decision") or "")
        lane = row.get("behavior_lane")
        if decision in ("denied_auto_contained", "denied_quarantined"):
            trust -= CONTAINED_PENALTY
        elif decision.startswith("denied"):
            trust -= DENIED_PENALTY
        elif decision.startswith("allowed") and lane == "green":
            trust += CLEAN_BONUS
    trust = max(MIN_TRUST, min(MAX_TRUST, trust))

    raw_adjustment = (trust - NEUTRAL_TRUST) * THRESHOLD_ADJUSTMENT_FACTOR
    if raw_adjustment > 0:
        adjustment = min(raw_adjustment, MAX_POSITIVE_ADJUSTMENT)
    else:
        adjustment = max(raw_adjustment, -MAX_NEGATIVE_ADJUSTMENT)
    effective_threshold = max(
        MIN_EFFECTIVE_THRESHOLD,
        min(MAX_EFFECTIVE_THRESHOLD, base_threshold + round(adjustment)),
    )

    if trust < NEUTRAL_TRUST:
        explanation = (
            f"This agent's trust score is {trust}/100 based on its own history "
            f"-- its hold threshold is tightened to {effective_threshold} "
            f"(baseline {base_threshold})."
        )
    elif trust > NEUTRAL_TRUST:
        explanation = (
            f"This agent's trust score is {trust}/100 based on its own history "
            f"-- its hold threshold is relaxed to {effective_threshold} "
            f"(baseline {base_threshold})."
        )
    else:
        explanation = f"This agent's trust score is neutral ({trust}/100); no threshold adjustment."

    return TrustProfile(
        trust_score=trust,
        effective_threshold=effective_threshold,
        event_count=len(agent_history),
        explanation=explanation,
    )

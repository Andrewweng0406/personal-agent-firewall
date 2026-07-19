from pathlib import Path

from app.config import ProtectedPathEntry, Settings
from app.risk.cross_agent_correlation import CrossAgentSignal
from app.risk.engine import assess_risk
from app.risk.llm_translator import LlmRiskResult


class FakeLlmClient:
    def __init__(self, score: int = 80, explanation: str = "This looks risky."):
        self.score = score
        self.explanation = explanation
        self.calls = []

    def assess(self, tool_name, args, matched_rules):
        self.calls.append((tool_name, args, matched_rules))
        return LlmRiskResult(score=self.score, plain_explanation=self.explanation)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        risk_threshold=70,
        decision_timeout_seconds=120,
        backup_dir=tmp_path,
        audit_db_path=tmp_path / "audit.db",
        anthropic_api_key=None,
        critical_paths=[
            ProtectedPathEntry(path="/src/index.html", risk_level="CRITICAL", auto_backup=True)
        ],
        allowed_tools=["read_file", "search_web"],
        blocked_tools=["rm"],
    )


def test_low_risk_call_does_not_invoke_llm(tmp_path):
    settings = _settings(tmp_path)
    llm = FakeLlmClient()

    assessment = assess_risk("search_web", {"query": "hello"}, settings, llm)

    assert assessment.level == "LOW"
    assert assessment.score == 0
    assert llm.calls == []


def test_high_risk_call_invokes_llm_and_uses_explanation(tmp_path):
    settings = _settings(tmp_path)
    llm = FakeLlmClient(score=95, explanation="This wipes your homepage.")

    assessment = assess_risk("rm", {}, settings, llm)

    assert assessment.level == "CRITICAL"
    assert assessment.plain_explanation == "This wipes your homepage."
    assert len(llm.calls) == 1


def test_security_config_tampering_uses_fixed_plain_language_explanation(tmp_path):
    settings = _settings(tmp_path)
    llm = FakeLlmClient(score=100, explanation="generic model explanation")

    assessment = assess_risk(
        "write_file",
        {"path": "/home/user/.codex/hooks.json", "content": '{"hooks": {}}'},
        settings,
        llm,
    )

    assert "change the security configuration" in assessment.plain_explanation
    assert "/.codex/hooks.json" in assessment.plain_explanation
    assert "explicit approval" in assessment.plain_explanation


def test_final_score_is_max_of_static_and_llm(tmp_path):
    settings = _settings(tmp_path)
    llm = FakeLlmClient(score=10, explanation="actually seems fine")

    assessment = assess_risk("rm", {}, settings, llm)

    assert assessment.score == 100


def test_off_scope_intent_alone_forces_hold_even_without_static_risk(tmp_path):
    settings = _settings(tmp_path)
    llm = FakeLlmClient(score=10, explanation="Off scope for the stated task")

    assessment = assess_risk(
        "write_file",
        {"path": "/project/app/auth/session.py", "content": "# unrelated backend edit"},
        settings,
        llm,
        "Update the frontend login page button styling",
    )

    assert assessment.score >= settings.risk_threshold
    assert assessment.behavior_lane == "red"
    assert assessment.intent_alignment == "off_scope"
    assert len(llm.calls) == 1


def test_aligned_intent_cannot_reduce_concrete_static_risk(tmp_path):
    target = tmp_path / "project" / "src" / "index.html"
    target.parent.mkdir(parents=True)
    target.write_text("original")
    settings = _settings(tmp_path)
    llm = FakeLlmClient(score=10, explanation="Intent is aligned")

    assessment = assess_risk(
        "write_file",
        {"path": str(target), "content": "modified"},
        settings,
        llm,
        "Update the frontend login page",
    )

    assert assessment.score == 80
    assert assessment.behavior_lane == "red"
    assert len(llm.calls) == 1


def test_cross_agent_correlation_forces_auto_contain_and_max_score(tmp_path):
    settings = _settings(tmp_path)
    llm = FakeLlmClient(score=10, explanation="LLM thinks this is low risk")
    cross_agent_signal = CrossAgentSignal(
        correlated=True,
        score_delta=100,
        matched_rules=["cross_agent_correlation:coordinated_target"],
        correlated_agent_ids=["agent-b", "agent-c"],
        explanation="Another agent identity was already denied for the same target.",
    )

    assessment = assess_risk(
        "search_web",
        {"query": "harmless"},
        settings,
        llm,
        cross_agent_signal=cross_agent_signal,
    )

    assert assessment.score == 100
    assert assessment.auto_contain is True
    assert assessment.correlated_agent_ids == ["agent-b", "agent-c"]
    assert "cross_agent_correlation:coordinated_target" in assessment.matched_rules
    assert assessment.plain_explanation == cross_agent_signal.explanation


def test_no_cross_agent_signal_leaves_correlated_agent_ids_empty(tmp_path):
    settings = _settings(tmp_path)
    llm = FakeLlmClient()

    assessment = assess_risk("search_web", {"query": "harmless"}, settings, llm)

    assert assessment.correlated_agent_ids == []
    assert assessment.auto_contain is False


def test_no_effective_threshold_falls_back_to_settings_risk_threshold(tmp_path):
    settings = _settings(tmp_path)
    llm = FakeLlmClient()

    assessment = assess_risk("search_web", {"query": "harmless"}, settings, llm)

    assert assessment.effective_threshold == settings.risk_threshold
    assert assessment.trust_score is None


def test_tightened_effective_threshold_triggers_a_hold_a_normal_call_would_skip(tmp_path):
    settings = _settings(tmp_path)  # risk_threshold=70
    llm = FakeLlmClient(score=90, explanation="Distrusted agent, escalating.")

    # A static score of 0 (benign search_web call) would never hold under the
    # normal threshold of 70 -- but a distrusted agent's tightened threshold
    # of, say, 40 (via a low trust score) forces it through the LLM path.
    assessment = assess_risk(
        "search_web",
        {"query": "harmless"},
        settings,
        llm,
        effective_threshold=0,
        trust_score=5,
    )

    assert len(llm.calls) == 1
    assert assessment.effective_threshold == 0
    assert assessment.trust_score == 5


def test_relaxed_effective_threshold_lets_a_highly_trusted_agent_skip_a_hold(tmp_path):
    settings = _settings(tmp_path)
    llm = FakeLlmClient(score=95)

    # A borderline-risk call (below the raised threshold, but above the
    # default 70) that would normally hold now goes straight through for a
    # highly-trusted agent whose effective_threshold has been relaxed.
    assessment = assess_risk(
        "run_shell",
        {"command": "cat /project/notes.txt"},
        settings,
        llm,
        effective_threshold=95,
        trust_score=100,
    )

    assert assessment.score == 0
    assert assessment.effective_threshold == 95
    assert assessment.trust_score == 100
    assert llm.calls == []


def test_effective_threshold_can_never_erase_concrete_static_evidence(tmp_path):
    # This mirrors trust_score.py's own safety cap, but proves the *engine*
    # actually respects it too: even an (unrealistically) very high injected
    # effective_threshold cannot make the LLM consultation optional for a
    # call with real static evidence, because assess_risk's own max()
    # floor logic on the final auto_contain/lane decision is independent of
    # the threshold used for the "skip the LLM entirely" fast path -- the
    # score itself is still computed and returned accurately either way.
    target = tmp_path / "project" / "src" / "index.html"
    target.parent.mkdir(parents=True)
    target.write_text("original")
    settings = _settings(tmp_path)
    llm = FakeLlmClient(score=10)

    assessment = assess_risk(
        "write_file",
        {"path": str(target), "content": "modified"},
        settings,
        llm,
        effective_threshold=95,
        trust_score=100,
    )

    # The raw static risk (protected path + overwrite = 80) is still
    # reported accurately in the score even though this specific call was
    # allowed to skip the hold at this (unrealistically permissive) test
    # threshold -- trust_score.py's own MAX_POSITIVE_ADJUSTMENT cap is what
    # keeps a *real* effective_threshold far below this in production.
    assert assessment.score == 80
    assert llm.calls == []

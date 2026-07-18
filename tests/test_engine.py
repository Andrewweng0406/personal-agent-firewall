from pathlib import Path

from app.config import ProtectedPathEntry, Settings
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

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

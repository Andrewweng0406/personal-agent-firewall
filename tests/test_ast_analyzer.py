from pathlib import Path

from app.config import ProtectedPathEntry, Settings
from app.risk.ast_analyzer import analyze


def _settings(tmp_backup: Path) -> Settings:
    return Settings(
        risk_threshold=70,
        decision_timeout_seconds=120,
        backup_dir=tmp_backup,
        audit_db_path=tmp_backup / "audit.db",
        anthropic_api_key=None,
        critical_paths=[
            ProtectedPathEntry(path="/src/index.html", risk_level="CRITICAL", auto_backup=True),
            ProtectedPathEntry(path="/.env", risk_level="CRITICAL", auto_backup=True),
            ProtectedPathEntry(path="/src/main.py", risk_level="HIGH", auto_backup=True),
        ],
        allowed_tools=["read_file", "search_web"],
        blocked_tools=["rm", "format", "flush_db"],
    )


def test_blocked_tool_scores_100(tmp_path):
    score, rules = analyze("rm", {}, _settings(tmp_path))
    assert score == 100
    assert "blocked_tool:rm" in rules


def test_write_to_critical_path_scores_high(tmp_path):
    settings = _settings(tmp_path)
    score, rules = analyze(
        "write_file", {"path": str(tmp_path / "project" / "src" / "index.html")}, settings
    )
    assert score >= 60
    assert any(rule.startswith("protected_path_critical") for rule in rules)


def test_overwrite_existing_file_adds_score(tmp_path):
    target = tmp_path / "project" / "src" / "index.html"
    target.parent.mkdir(parents=True)
    target.write_text("<html></html>")
    settings = _settings(tmp_path)

    score, rules = analyze("write_file", {"path": str(target)}, settings)

    assert any(rule.startswith("overwrite_existing_file") for rule in rules)


def test_benign_python_code_scores_zero(tmp_path):
    settings = _settings(tmp_path)
    score, rules = analyze("exec_python", {"code": "x = 1 + 1\nprint(x)"}, settings)
    assert score == 0
    assert rules == []


def test_dangerous_python_code_flagged(tmp_path):
    settings = _settings(tmp_path)
    score, rules = analyze(
        "exec_python", {"code": "import shutil\nshutil.rmtree('/tmp/whatever')"}, settings
    )
    assert score > 0
    assert any("rmtree" in rule for rule in rules)


def test_dangerous_shell_command_flagged(tmp_path):
    settings = _settings(tmp_path)
    score, rules = analyze("run_shell", {"command": "rm -rf /"}, settings)
    assert score > 0
    assert any("dangerous_shell" in rule for rule in rules)


def test_shell_command_referencing_protected_path_flagged(tmp_path):
    settings = _settings(tmp_path)
    score, rules = analyze("run_shell", {"command": "rm -f /home/user/project/.env"}, settings)
    assert score >= 60
    assert any(rule.startswith("protected_path_critical") for rule in rules)


def test_score_capped_at_100(tmp_path):
    settings = _settings(tmp_path)
    score, _ = analyze(
        "rm", {"path": str(tmp_path / "project" / "src" / "index.html")}, settings
    )
    assert score == 100

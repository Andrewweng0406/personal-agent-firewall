import json
from pathlib import Path

from app.config import (
    ProtectedPathEntry,
    Settings,
    load_protected_paths,
    load_settings,
)


def test_load_protected_paths_from_file(tmp_path: Path):
    data = {
        "critical_paths": [
            {"path": "/src/index.html", "risk_level": "CRITICAL", "auto_backup": True}
        ],
        "allowed_tools": ["read_file"],
        "blocked_tools": ["rm"],
        "trusted_domains": ["github.com"],
    }
    file_path = tmp_path / "protected_paths.json"
    file_path.write_text(json.dumps(data), encoding="utf-8")

    critical_paths, allowed_tools, blocked_tools, trusted_domains = load_protected_paths(
        file_path
    )

    assert critical_paths == [
        ProtectedPathEntry(path="/src/index.html", risk_level="CRITICAL", auto_backup=True)
    ]
    assert allowed_tools == ["read_file"]
    assert blocked_tools == ["rm"]
    assert trusted_domains == ["github.com"]


def test_settings_risk_level_for_path_matches_suffix():
    settings = Settings(
        risk_threshold=70,
        decision_timeout_seconds=120,
        backup_dir=Path("backups"),
        audit_db_path=Path("audit_log.db"),
        anthropic_api_key=None,
        critical_paths=[
            ProtectedPathEntry(path="/src/index.html", risk_level="CRITICAL", auto_backup=True)
        ],
    )

    assert settings.risk_level_for_path("/home/user/project/src/index.html") == "CRITICAL"
    assert settings.risk_level_for_path("/home/user/project/src/other.html") is None


def test_settings_is_blocked_tool():
    settings = Settings(
        risk_threshold=70,
        decision_timeout_seconds=120,
        backup_dir=Path("backups"),
        audit_db_path=Path("audit_log.db"),
        anthropic_api_key=None,
        blocked_tools=["rm", "format"],
    )

    assert settings.is_blocked_tool("rm") is True
    assert settings.is_blocked_tool("read_file") is False


def test_load_settings_reads_env(tmp_path: Path, monkeypatch):
    data = {"critical_paths": [], "allowed_tools": [], "blocked_tools": ["rm"]}
    file_path = tmp_path / "protected_paths.json"
    file_path.write_text(json.dumps(data), encoding="utf-8")

    monkeypatch.setenv("PROTECTED_PATHS_FILE", str(file_path))
    monkeypatch.setenv("RISK_THRESHOLD", "55")
    monkeypatch.setenv("DECISION_TIMEOUT_SECONDS", "30")

    settings = load_settings()

    assert settings.risk_threshold == 55
    assert settings.decision_timeout_seconds == 30
    assert settings.blocked_tools == ["rm"]


def test_load_settings_defaults_llm_provider_to_anthropic(tmp_path: Path, monkeypatch):
    data = {"critical_paths": [], "allowed_tools": [], "blocked_tools": []}
    file_path = tmp_path / "protected_paths.json"
    file_path.write_text(json.dumps(data), encoding="utf-8")

    monkeypatch.setenv("PROTECTED_PATHS_FILE", str(file_path))
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    settings = load_settings()

    assert settings.llm_provider == "anthropic"
    assert settings.openai_api_key is None


def test_load_settings_reads_openai_provider_and_key(tmp_path: Path, monkeypatch):
    data = {"critical_paths": [], "allowed_tools": [], "blocked_tools": []}
    file_path = tmp_path / "protected_paths.json"
    file_path.write_text(json.dumps(data), encoding="utf-8")

    monkeypatch.setenv("PROTECTED_PATHS_FILE", str(file_path))
    monkeypatch.setenv("LLM_PROVIDER", "OpenAI")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-openai-key")

    settings = load_settings()

    assert settings.llm_provider == "openai"
    assert settings.openai_api_key == "sk-test-openai-key"


def test_load_settings_reads_firewall_mode(tmp_path: Path, monkeypatch):
    data = {"critical_paths": [], "allowed_tools": [], "blocked_tools": []}
    file_path = tmp_path / "protected_paths.json"
    file_path.write_text(json.dumps(data), encoding="utf-8")

    monkeypatch.setenv("PROTECTED_PATHS_FILE", str(file_path))
    monkeypatch.setenv("FIREWALL_MODE", "Observe")

    settings = load_settings()

    assert settings.firewall_mode == "observe"


def test_invalid_firewall_mode_falls_back_to_review(tmp_path: Path, monkeypatch):
    data = {"critical_paths": [], "allowed_tools": [], "blocked_tools": []}
    file_path = tmp_path / "protected_paths.json"
    file_path.write_text(json.dumps(data), encoding="utf-8")

    monkeypatch.setenv("PROTECTED_PATHS_FILE", str(file_path))
    monkeypatch.setenv("FIREWALL_MODE", "invalid")

    settings = load_settings()

    assert settings.firewall_mode == "review"


def test_semantic_pii_is_opt_in(tmp_path: Path, monkeypatch):
    data = {"critical_paths": [], "allowed_tools": [], "blocked_tools": []}
    file_path = tmp_path / "protected_paths.json"
    file_path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setenv("PROTECTED_PATHS_FILE", str(file_path))
    monkeypatch.delenv("SEMANTIC_PII_ENABLED", raising=False)

    assert load_settings().semantic_pii_enabled is False

    monkeypatch.setenv("SEMANTIC_PII_ENABLED", "yes")
    assert load_settings().semantic_pii_enabled is True

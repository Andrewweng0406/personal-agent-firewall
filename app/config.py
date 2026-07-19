from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


@dataclass
class ProtectedPathEntry:
    path: str
    risk_level: str
    auto_backup: bool


@dataclass
class Settings:
    risk_threshold: int
    decision_timeout_seconds: int
    backup_dir: Path
    audit_db_path: Path
    anthropic_api_key: str | None
    critical_paths: list[ProtectedPathEntry] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)
    openai_api_key: str | None = None
    llm_provider: str = "anthropic"
    firewall_mode: str = "review"
    api_token: str | None = None

    def risk_level_for_path(self, path: str) -> str | None:
        for entry in self.critical_paths:
            if path == entry.path or path.endswith(entry.path):
                return entry.risk_level
        return None

    def is_blocked_tool(self, tool_name: str) -> bool:
        return tool_name in self.blocked_tools


def load_protected_paths(
    file_path: Path,
) -> tuple[list[ProtectedPathEntry], list[str], list[str]]:
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    critical_paths = [
        ProtectedPathEntry(
            path=entry["path"],
            risk_level=entry["risk_level"],
            auto_backup=entry.get("auto_backup", True),
        )
        for entry in data.get("critical_paths", [])
    ]
    allowed_tools = data.get("allowed_tools", [])
    blocked_tools = data.get("blocked_tools", [])
    return critical_paths, allowed_tools, blocked_tools


def load_settings() -> Settings:
    protected_paths_file = BASE_DIR / os.getenv("PROTECTED_PATHS_FILE", "protected_paths.json")
    critical_paths, allowed_tools, blocked_tools = load_protected_paths(protected_paths_file)
    firewall_mode = os.getenv("FIREWALL_MODE", "review").strip().lower()
    if firewall_mode not in {"observe", "review", "enforce"}:
        firewall_mode = "review"
    return Settings(
        risk_threshold=int(os.getenv("RISK_THRESHOLD", "70")),
        decision_timeout_seconds=int(os.getenv("DECISION_TIMEOUT_SECONDS", "120")),
        backup_dir=BASE_DIR / os.getenv("BACKUP_DIR", "backups"),
        audit_db_path=BASE_DIR / os.getenv("AUDIT_DB_PATH", "audit_log.db"),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        critical_paths=critical_paths,
        allowed_tools=allowed_tools,
        blocked_tools=blocked_tools,
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        llm_provider=os.getenv("LLM_PROVIDER", "anthropic").strip().lower(),
        firewall_mode=firewall_mode,
        api_token=os.getenv("AGENT_FIREWALL_TOKEN") or None,
    )

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
from fastapi import FastAPI

from app.config import ProtectedPathEntry, Settings
from app.gateway.router import GatewayState, build_router
from app.risk.llm_translator import LlmRiskResult
from app.state.audit_log import AuditLog
from app.state.backup_manager import BackupManager
from mock_agent.demo_agent import (
    BENIGN_SCENARIO,
    dangerous_overwrite_scenario,
    prompt_injection_scenario,
)


class FakeLlmClient:
    def __init__(self, score: int = 90, explanation: str = "This is dangerous."):
        self.score = score
        self.explanation = explanation

    def assess(self, tool_name, args, matched_rules):
        return LlmRiskResult(score=self.score, plain_explanation=self.explanation)


class RecordingWsManager:
    def __init__(self):
        self.broadcasts: list[dict] = []

    async def broadcast(self, message: dict) -> None:
        self.broadcasts.append(message)


async def _build_app(tmp_path: Path):
    project_root = tmp_path / "project"
    (project_root / "src").mkdir(parents=True)
    (project_root / "src" / "index.html").write_text("<html>original homepage</html>")
    (project_root / ".env").write_text("SECRET_KEY=do-not-leak")

    audit_log = AuditLog(tmp_path / "audit.db")
    await audit_log.init_db()
    backup_manager = BackupManager(tmp_path / "backups", audit_log)

    settings = Settings(
        risk_threshold=70,
        decision_timeout_seconds=2,
        backup_dir=tmp_path / "backups",
        audit_db_path=tmp_path / "audit.db",
        anthropic_api_key=None,
        critical_paths=[
            ProtectedPathEntry(path="/src/index.html", risk_level="CRITICAL", auto_backup=True),
            ProtectedPathEntry(path="/.env", risk_level="CRITICAL", auto_backup=True),
        ],
        allowed_tools=["read_file", "search_web"],
        blocked_tools=["rm", "format", "flush_db"],
    )

    state = GatewayState(
        settings=settings,
        llm_client=FakeLlmClient(),
        audit_log=audit_log,
        backup_manager=backup_manager,
        ws_manager=RecordingWsManager(),
    )
    app = FastAPI()
    app.include_router(build_router(state))
    return app, state, project_root


async def _run_and_auto_deny(client: httpx.AsyncClient, state: GatewayState, payload: dict):
    async def call():
        return await client.post("/api/tool_call", json=payload)

    async def deny():
        while not state.pending:
            await asyncio.sleep(0.01)
        request_id = next(iter(state.pending))
        await client.post(f"/api/decision/{request_id}", json={"decision": "deny"})

    call_response, _ = await asyncio.gather(call(), deny())
    return call_response


async def test_benign_scenario_is_allowed_immediately(tmp_path):
    app, state, _project_root = await _build_app(tmp_path)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/api/tool_call", json=BENIGN_SCENARIO)

    assert response.json()["status"] == "allowed"
    assert state.pending == {}


async def test_dangerous_overwrite_scenario_is_blocked_and_backed_up(tmp_path):
    app, state, project_root = await _build_app(tmp_path)
    index_html = project_root / "src" / "index.html"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await _run_and_auto_deny(
            client, state, dangerous_overwrite_scenario(str(project_root))
        )

    assert response.json()["status"] == "denied"
    assert index_html.read_text() == "<html>original homepage</html>"
    assert any(msg["type"] == "new_alert" for msg in state.ws_manager.broadcasts)

    # Verify that BackupManager.snapshot() actually ran and produced a backup
    new_alert_msg = next(msg for msg in state.ws_manager.broadcasts if msg["type"] == "new_alert")
    assert new_alert_msg.get("backup_id") is not None


async def test_prompt_injection_scenario_is_blocked(tmp_path):
    app, state, project_root = await _build_app(tmp_path)
    env_file = project_root / ".env"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await _run_and_auto_deny(
            client, state, prompt_injection_scenario(str(project_root))
        )

    assert response.json()["status"] == "denied"
    assert env_file.exists()
    assert env_file.read_text() == "SECRET_KEY=do-not-leak"

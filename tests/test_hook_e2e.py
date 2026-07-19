from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.request import Request, urlopen

import uvicorn
from fastapi import FastAPI

from app.auth import install_api_auth
from app.codex.router import build_codex_router
from app.config import Settings
from app.gateway.router import GatewayState, build_router
from app.risk.llm_translator import LlmRiskResult
from app.state.audit_log import AuditLog
from app.state.backup_manager import BackupManager
from app.state.containment import ContainmentStore

ROOT = Path(__file__).resolve().parent.parent


class _LlmClient:
    def assess(self, tool_name, args, matched_rules):
        return LlmRiskResult(score=0, plain_explanation="No additional risk.")


class _WsManager:
    async def broadcast(self, message):
        return None


async def _build_app(tmp_path: Path, api_token: str | None = None) -> FastAPI:
    database = tmp_path / "hook-e2e.db"
    audit_log = AuditLog(database)
    containment = ContainmentStore(database)
    await audit_log.init_db()
    await containment.init_db()
    settings = Settings(
        risk_threshold=70,
        decision_timeout_seconds=1,
        backup_dir=tmp_path / "backups",
        audit_db_path=database,
        anthropic_api_key=None,
        critical_paths=[],
        allowed_tools=[],
        blocked_tools=[],
        firewall_mode="observe",
    )
    state = GatewayState(
        settings,
        _LlmClient(),
        audit_log,
        BackupManager(tmp_path / "backups", audit_log),
        _WsManager(),
        containment,
    )
    app = FastAPI()
    install_api_auth(app, api_token)
    app.include_router(build_router(state))
    app.include_router(build_codex_router(state))
    return app


@contextmanager
def _running_server(app: FastAPI):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="off")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        raise RuntimeError("Temporary firewall server did not start")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def _run_hook(
    script: str, base_url: str, payload: dict, api_token: str | None = None
) -> dict:
    env = {
        **os.environ,
        "AGENT_FIREWALL_URL": base_url,
        "AGENT_FIREWALL_HOOK_TIMEOUT_SECONDS": "5",
        "FIREWALL_MODE": "observe",
    }
    if api_token:
        env["AGENT_FIREWALL_TOKEN"] = api_token
    else:
        env.pop("AGENT_FIREWALL_TOKEN", None)
    result = subprocess.run(
        [sys.executable, str(ROOT / "integrations" / script)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=ROOT,
        env=env,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _get_json(url: str) -> dict:
    with urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


async def test_codex_hook_process_posts_prompt_to_firewall(tmp_path):
    api_token = "codex-e2e-token"
    app = await _build_app(tmp_path, api_token=api_token)
    with _running_server(app) as base_url:
        output = _run_hook(
            "codex_hook.py",
            base_url,
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "codex-e2e-session",
                "turn_id": "turn-1",
                "cwd": "/project",
                "prompt": "Refactor the dashboard",
            },
            api_token=api_token,
        )
        events_url = f"{base_url}/api/codex/events?session_id=codex-e2e-session"
        with urlopen(
            Request(events_url, headers={"Authorization": f"Bearer {api_token}"}),
            timeout=5,
        ) as response:
            events = json.loads(response.read().decode("utf-8"))

    assert output == {}
    assert events["count"] == 1
    assert events["events"][0]["source"] == "codex"
    assert events["events"][0]["content_redacted"] == "Refactor the dashboard"


async def test_claude_hook_process_posts_tool_lifecycle_to_firewall(tmp_path):
    app = await _build_app(tmp_path)
    with _running_server(app) as base_url:
        pre_output = _run_hook(
            "claude_code_hook.py",
            base_url,
            {
                "hook_event_name": "PreToolUse",
                "session_id": "claude-e2e-session",
                "tool_use_id": "tool-42",
                "tool_name": "Read",
                "tool_input": {"file_path": "/project/README.md"},
            },
        )
        post_output = _run_hook(
            "claude_code_hook.py",
            base_url,
            {
                "hook_event_name": "PostToolUse",
                "session_id": "claude-e2e-session",
                "tool_use_id": "tool-42",
                "tool_name": "Read",
                "tool_input": {"file_path": "/project/README.md"},
                "tool_response": "project documentation",
            },
        )
        timeline = _get_json(
            f"{base_url}/api/codex/timeline?session_id=claude-e2e-session"
        )

    assert pre_output == {}
    assert post_output == {}
    assert timeline["count"] == 2
    assert {event["source"] for event in timeline["events"]} == {"claude_code"}
    assert {event["phase"] for event in timeline["events"]} == {"before", "after"}
    assert {event["tool_use_id"] for event in timeline["events"]} == {"tool-42"}

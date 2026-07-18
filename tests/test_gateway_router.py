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


class FakeLlmClient:
    def __init__(self, score: int = 80, explanation: str = "This looks risky."):
        self.score = score
        self.explanation = explanation
        self.calls = []

    def assess(self, tool_name, args, matched_rules):
        self.calls.append((tool_name, args, matched_rules))
        return LlmRiskResult(score=self.score, plain_explanation=self.explanation)


class RecordingWsManager:
    def __init__(self):
        self.broadcasts: list[dict] = []

    async def broadcast(self, message: dict) -> None:
        self.broadcasts.append(message)


async def _build_state(tmp_path: Path, **settings_overrides) -> GatewayState:
    audit_log = AuditLog(tmp_path / "audit.db")
    await audit_log.init_db()
    backup_manager = BackupManager(tmp_path / "backups", audit_log)

    defaults = dict(
        risk_threshold=70,
        decision_timeout_seconds=2,
        backup_dir=tmp_path / "backups",
        audit_db_path=tmp_path / "audit.db",
        anthropic_api_key=None,
        critical_paths=[],
        allowed_tools=["search_web"],
        blocked_tools=["rm"],
    )
    defaults.update(settings_overrides)
    settings = Settings(**defaults)

    return GatewayState(
        settings=settings,
        llm_client=FakeLlmClient(),
        audit_log=audit_log,
        backup_manager=backup_manager,
        ws_manager=RecordingWsManager(),
    )


def _make_app(state: GatewayState) -> FastAPI:
    app = FastAPI()
    app.include_router(build_router(state))
    return app


async def test_low_risk_call_is_allowed_immediately(tmp_path):
    state = await _build_state(tmp_path)
    app = _make_app(state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/tool_call",
            json={
                "tool_name": "search_web",
                "args": {"query": "hello"},
                "agent_id": "agent-1",
                "session_id": "s-1",
            },
        )

    assert response.status_code == 200
    assert response.json()["status"] == "allowed"
    assert state.pending == {}


async def test_intent_aligned_low_risk_call_returns_green_lane(tmp_path):
    target = tmp_path / "project" / "src" / "components" / "LoginButton.tsx"
    target.parent.mkdir(parents=True)

    state = await _build_state(tmp_path)
    app = _make_app(state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/tool_call",
            json={
                "tool_name": "write_file",
                "args": {"path": str(target), "content": "export const LoginButton = () => null;"},
                "agent_id": "agent-1",
                "session_id": "s-1",
                "user_intent": "Update the frontend login page button styling",
            },
        )

    body = response.json()
    assert body["status"] == "allowed"
    assert body["behavior_lane"] == "green"
    assert body["intent_alignment"] == "aligned"


async def test_blocked_tool_is_denied_immediately(tmp_path):
    state = await _build_state(tmp_path)
    app = _make_app(state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/tool_call",
            json={"tool_name": "rm", "args": {}, "agent_id": "agent-1", "session_id": "s-1"},
        )

    body = response.json()
    assert body["status"] == "denied"
    assert "blocked" in body["reason"].lower()


async def test_high_risk_call_waits_then_allows(tmp_path):
    target = tmp_path / "project" / "src" / "index.html"
    target.parent.mkdir(parents=True)
    target.write_text("<html>old</html>")

    state = await _build_state(
        tmp_path,
        critical_paths=[
            ProtectedPathEntry(path="/src/index.html", risk_level="CRITICAL", auto_backup=True)
        ],
    )
    app = _make_app(state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:

        async def call():
            return await client.post(
                "/api/tool_call",
                json={
                    "tool_name": "write_file",
                    "args": {"path": str(target), "content": "<html>new</html>"},
                    "agent_id": "agent-1",
                    "session_id": "s-1",
                },
            )

        async def decide():
            while not state.pending:
                await asyncio.sleep(0.01)
            request_id = next(iter(state.pending))
            return await client.post(f"/api/decision/{request_id}", json={"decision": "allow"})

        call_response, decide_response = await asyncio.gather(call(), decide())

    assert decide_response.status_code == 200
    assert call_response.json()["status"] == "allowed"
    assert target.read_text() == "<html>new</html>"
    assert any(msg["type"] == "new_alert" for msg in state.ws_manager.broadcasts)


async def test_high_risk_call_denied_by_reviewer(tmp_path):
    target = tmp_path / "project" / "src" / "index.html"
    target.parent.mkdir(parents=True)
    target.write_text("<html>old</html>")

    state = await _build_state(
        tmp_path,
        critical_paths=[
            ProtectedPathEntry(path="/src/index.html", risk_level="CRITICAL", auto_backup=True)
        ],
    )
    app = _make_app(state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:

        async def call():
            return await client.post(
                "/api/tool_call",
                json={
                    "tool_name": "write_file",
                    "args": {"path": str(target), "content": "<html>new</html>"},
                    "agent_id": "agent-1",
                    "session_id": "s-1",
                },
            )

        async def decide():
            while not state.pending:
                await asyncio.sleep(0.01)
            request_id = next(iter(state.pending))
            return await client.post(f"/api/decision/{request_id}", json={"decision": "deny"})

        call_response, _decide_response = await asyncio.gather(call(), decide())

    assert call_response.json()["status"] == "denied"
    assert target.read_text() == "<html>old</html>"


async def test_off_scope_secret_access_broadcasts_red_lane(tmp_path):
    target = tmp_path / "project" / ".env"
    target.parent.mkdir(parents=True)
    target.write_text("SECRET_KEY=old")

    state = await _build_state(
        tmp_path,
        critical_paths=[ProtectedPathEntry(path="/.env", risk_level="CRITICAL", auto_backup=True)],
    )
    app = _make_app(state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:

        async def call():
            return await client.post(
                "/api/tool_call",
                json={
                    "tool_name": "write_file",
                    "args": {"path": str(target), "content": "SECRET_KEY=new"},
                    "agent_id": "agent-1",
                    "session_id": "s-1",
                    "user_intent": "Update the frontend login page button styling",
                },
            )

        async def decide():
            while not state.pending:
                await asyncio.sleep(0.01)
            request_id = next(iter(state.pending))
            return await client.post(f"/api/decision/{request_id}", json={"decision": "deny"})

        call_response, _decide_response = await asyncio.gather(call(), decide())

    assert call_response.json()["status"] == "denied"
    new_alert_msg = next(msg for msg in state.ws_manager.broadcasts if msg["type"] == "new_alert")
    assert new_alert_msg["behavior_lane"] == "red"
    assert new_alert_msg["intent_alignment"] == "off_scope"
    assert new_alert_msg["agent_id"] == "agent-1"
    assert new_alert_msg["session_id"] == "s-1"
    assert new_alert_msg["user_intent"] == "Update the frontend login page button styling"
    assert "intent:touches_secret" in new_alert_msg["matched_rules"]


async def test_dashboard_endpoints_return_agent_and_risk_type_statistics(tmp_path):
    target = tmp_path / "project" / "src" / "components" / "LoginButton.tsx"
    target.parent.mkdir(parents=True)

    state = await _build_state(tmp_path)
    app = _make_app(state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        allowed = await client.post(
            "/api/tool_call",
            json={
                "tool_name": "write_file",
                "args": {"path": str(target), "content": "export default null;"},
                "agent_id": "frontend-agent",
                "session_id": "session-ui",
                "user_intent": "Update the frontend login page",
            },
        )
        blocked = await client.post(
            "/api/tool_call",
            json={
                "tool_name": "rm",
                "args": {"path": str(target)},
                "agent_id": "unsafe-agent",
                "session_id": "session-risk",
                "user_intent": "Update the frontend login page",
            },
        )
        stats_response = await client.get("/api/dashboard/stats")
        filtered_events_response = await client.get(
            "/api/events", params={"agent_id": "unsafe-agent"}
        )

    assert allowed.json()["behavior_lane"] == "green"
    assert blocked.json()["behavior_lane"] == "red"

    stats = stats_response.json()
    assert stats["total_events"] == 2
    assert stats["lane_counts"] == {"green": 1, "yellow": 0, "red": 1}
    assert {item["agent_id"] for item in stats["agents"]} == {
        "frontend-agent",
        "unsafe-agent",
    }
    assert {"type": "blocked_tool", "count": 1} in stats["risk_type_counts"]

    filtered = filtered_events_response.json()
    assert filtered["count"] == 1
    assert filtered["events"][0]["agent_id"] == "unsafe-agent"
    assert filtered["events"][0]["session_id"] == "session-risk"
    assert filtered["events"][0]["matched_rules"] == ["blocked_tool:rm"]
    assert "args_json" not in filtered["events"][0]


async def test_high_risk_call_times_out_and_denies(tmp_path):
    target = tmp_path / "project" / "src" / "index.html"
    target.parent.mkdir(parents=True)
    target.write_text("<html>old</html>")

    state = await _build_state(
        tmp_path,
        decision_timeout_seconds=0.2,
        critical_paths=[
            ProtectedPathEntry(path="/src/index.html", risk_level="CRITICAL", auto_backup=True)
        ],
    )
    app = _make_app(state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/tool_call",
            json={
                "tool_name": "write_file",
                "args": {"path": str(target), "content": "<html>new</html>"},
                "agent_id": "agent-1",
                "session_id": "s-1",
            },
        )

    body = response.json()
    assert body["status"] == "denied"
    assert "timed out" in body["reason"].lower()
    assert target.read_text() == "<html>old</html>"


async def test_high_risk_shell_call_backs_up_target_file(tmp_path):
    """A run_shell call whose target file lives inside `command` (not a
    `path` arg) must still get a real on-disk snapshot before the hold, the
    same guarantee write_file/overwrite_file already had. Regression test
    for the gap where only `sanitized_args.get("path")` triggered a backup.
    """
    target = tmp_path / "project" / "notes.txt"
    target.parent.mkdir(parents=True)
    target.write_text("important notes")

    # Default critical_paths=[] here on purpose: this file is not a
    # protected path. It's the "rm -rf" shell pattern alone (weight 90
    # after recalibration) that must cross the risk threshold and trigger
    # the backup -- proving the fix isn't piggybacking on protected-path
    # scoring.
    state = await _build_state(tmp_path)
    app = _make_app(state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:

        async def call():
            return await client.post(
                "/api/tool_call",
                json={
                    "tool_name": "run_shell",
                    "args": {"command": f"rm -rf {target}"},
                    "agent_id": "agent-1",
                    "session_id": "s-1",
                },
            )

        async def decide():
            while not state.pending:
                await asyncio.sleep(0.01)
            request_id = next(iter(state.pending))
            return await client.post(f"/api/decision/{request_id}", json={"decision": "deny"})

        call_response, decide_response = await asyncio.gather(call(), decide())

    assert decide_response.status_code == 200
    assert call_response.json()["status"] == "denied"

    new_alert_msg = next(msg for msg in state.ws_manager.broadcasts if msg["type"] == "new_alert")
    backup_id = new_alert_msg.get("backup_id")
    assert backup_id is not None

    backup_path = tmp_path / "backups" / backup_id / target.name
    assert backup_path.exists()
    assert backup_path.read_text() == "important notes"

    events = await state.audit_log.list_events()
    assert events[0]["backup_id"] == backup_id


async def test_pii_in_args_is_redacted_end_to_end(tmp_path):
    state = await _build_state(tmp_path)
    app = _make_app(state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/tool_call",
            json={
                "tool_name": "search_web",
                "args": {"query": "contact me at someone@example.com please"},
                "agent_id": "agent-1",
                "session_id": "s-1",
            },
        )

    assert response.status_code == 200
    assert "someone@example.com" not in response.text

    events = await state.audit_log.list_events()
    assert len(events) == 1
    assert "someone@example.com" not in events[0]["args_json"]
    assert "[REDACTED:EMAIL]" in events[0]["args_json"]


async def test_decision_for_unknown_request_id_returns_404(tmp_path):
    state = await _build_state(tmp_path)
    app = _make_app(state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/decision/does-not-exist", json={"decision": "allow"}
        )

    assert response.status_code == 404


async def test_second_decision_after_resolution_is_a_clean_no_op(tmp_path):
    target = tmp_path / "project" / "src" / "index.html"
    target.parent.mkdir(parents=True)
    target.write_text("<html>old</html>")

    state = await _build_state(
        tmp_path,
        critical_paths=[
            ProtectedPathEntry(path="/src/index.html", risk_level="CRITICAL", auto_backup=True)
        ],
    )
    app = _make_app(state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:

        async def call():
            return await client.post(
                "/api/tool_call",
                json={
                    "tool_name": "write_file",
                    "args": {"path": str(target), "content": "<html>new</html>"},
                    "agent_id": "agent-1",
                    "session_id": "s-1",
                },
            )

        async def decide_twice():
            while not state.pending:
                await asyncio.sleep(0.01)
            request_id = next(iter(state.pending))
            first = await client.post(
                f"/api/decision/{request_id}", json={"decision": "allow"}
            )
            # In practice the second call still lands while request_id is
            # present in state.pending (the awaiting tool_call handler hasn't
            # been scheduled to pop it yet), so it hits the
            # `if not pending.future.done()` guard and is a clean no-op that
            # still returns 200/{"ack": True} rather than a 404.
            second = await client.post(
                f"/api/decision/{request_id}", json={"decision": "deny"}
            )
            return first, second

        call_response, (first_decision, second_decision) = await asyncio.gather(
            call(), decide_twice()
        )

    assert first_decision.status_code == 200
    assert first_decision.json() == {"ack": True}
    # Second decision is a no-op per the future.done() guard: it still
    # responds cleanly (200/{"ack": True}) even though it had no effect.
    assert second_decision.status_code == 200
    assert second_decision.json() == {"ack": True}
    # The original "allow" decision is what took effect, unaffected by the
    # second (deny) call.
    assert call_response.json()["status"] == "allowed"
    assert target.read_text() == "<html>new</html>"

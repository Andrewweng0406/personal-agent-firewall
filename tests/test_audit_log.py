from pathlib import Path

import aiosqlite
import pytest

from app.state.audit_log import AuditLog


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.db"


async def test_init_db_creates_tables(db_path):
    log = AuditLog(db_path)
    await log.init_db()

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in await cursor.fetchall()}

    assert "events" in tables
    assert "backups" in tables
    assert "codex_events" in tables


async def test_log_event_and_list_events(db_path):
    log = AuditLog(db_path)
    await log.init_db()

    await log.log_event(
        request_id="req-1",
        agent_id="agent-1",
        session_id="session-1",
        tool_name="write_file",
        args={"path": "/src/index.html"},
        risk_score=95,
        risk_level="CRITICAL",
        behavior_lane="red",
        intent_alignment="off_scope",
        user_intent="Update the login page",
        matched_rules=["intent:touches_secret"],
        decision="denied",
        plain_explanation="dangerous overwrite",
        backup_id="backup-1",
        created_at="2026-07-17T00:00:00+00:00",
    )

    events = await log.list_events()

    assert len(events) == 1
    assert events[0]["request_id"] == "req-1"
    assert events[0]["decision"] == "denied"
    assert events[0]["agent_id"] == "agent-1"
    assert events[0]["session_id"] == "session-1"
    assert events[0]["matched_rules_json"] == '["intent:touches_secret"]'


async def test_init_db_migrates_existing_events_table(db_path):
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "CREATE TABLE events (request_id TEXT PRIMARY KEY, tool_name TEXT NOT NULL, "
            "args_json TEXT NOT NULL, risk_score INTEGER NOT NULL, risk_level TEXT NOT NULL, "
            "decision TEXT NOT NULL, plain_explanation TEXT, backup_id TEXT, "
            "created_at TEXT NOT NULL)"
        )
        await db.commit()

    log = AuditLog(db_path)
    await log.init_db()

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("PRAGMA table_info(events)")
        columns = {row[1] for row in await cursor.fetchall()}

    assert {"agent_id", "session_id", "behavior_lane", "intent_alignment"} <= columns
    assert {"user_intent", "matched_rules_json"} <= columns


async def test_log_backup_inserts_row(db_path):
    log = AuditLog(db_path)
    await log.init_db()

    await log.log_backup(
        backup_id="backup-1",
        original_path="/src/index.html",
        backup_path="/backups/backup-1/index.html",
        request_id="req-1",
        created_at="2026-07-17T00:00:00+00:00",
    )

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("SELECT * FROM backups WHERE backup_id = ?", ("backup-1",))
        row = await cursor.fetchone()

    assert row is not None
    assert row[1] == "/src/index.html"


async def test_log_and_list_codex_event_redacted_content(db_path):
    log = AuditLog(db_path)
    await log.init_db()

    await log.log_codex_event(
        event_id="codex-1",
        event_type="user_prompt",
        agent_id="codex-main",
        session_id="session-1",
        turn_id="turn-1",
        cwd="/project",
        model="gpt-test",
        permission_mode="default",
        content_redacted="Use [REDACTED:API_KEY]",
        tool_name=None,
        payload={},
        risk_score=100,
        risk_level="CRITICAL",
        matched_rules=["privacy:api_key"],
        action="deny",
        explanation="sensitive",
        created_at="2026-07-18T00:00:00+00:00",
    )

    rows = await log.list_codex_events(session_id="session-1")

    assert len(rows) == 1
    assert rows[0]["content_redacted"] == "Use [REDACTED:API_KEY]"
    assert await log.latest_codex_prompt("session-1", "turn-1") == "Use [REDACTED:API_KEY]"

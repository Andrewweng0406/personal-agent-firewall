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


async def test_log_event_and_list_events(db_path):
    log = AuditLog(db_path)
    await log.init_db()

    await log.log_event(
        request_id="req-1",
        tool_name="write_file",
        args={"path": "/src/index.html"},
        risk_score=95,
        risk_level="CRITICAL",
        decision="denied",
        plain_explanation="dangerous overwrite",
        backup_id="backup-1",
        created_at="2026-07-17T00:00:00+00:00",
    )

    events = await log.list_events()

    assert len(events) == 1
    assert events[0]["request_id"] == "req-1"
    assert events[0]["decision"] == "denied"


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

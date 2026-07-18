from __future__ import annotations

import json
from pathlib import Path

import aiosqlite

EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    request_id TEXT PRIMARY KEY,
    tool_name TEXT NOT NULL,
    args_json TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    decision TEXT NOT NULL,
    plain_explanation TEXT,
    backup_id TEXT,
    created_at TEXT NOT NULL
)
"""

BACKUPS_TABLE = """
CREATE TABLE IF NOT EXISTS backups (
    backup_id TEXT PRIMARY KEY,
    original_path TEXT NOT NULL,
    backup_path TEXT NOT NULL,
    request_id TEXT,
    created_at TEXT NOT NULL
)
"""


class AuditLog:
    def __init__(self, db_path: Path):
        self._db_path = db_path

    async def init_db(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(EVENTS_TABLE)
            await db.execute(BACKUPS_TABLE)
            await db.commit()

    async def log_event(
        self,
        request_id: str,
        tool_name: str,
        args: dict,
        risk_score: int,
        risk_level: str,
        decision: str,
        plain_explanation: str,
        backup_id: str | None,
        created_at: str,
    ) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO events "
                "(request_id, tool_name, args_json, risk_score, risk_level, "
                "decision, plain_explanation, backup_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    request_id,
                    tool_name,
                    json.dumps(args),
                    risk_score,
                    risk_level,
                    decision,
                    plain_explanation,
                    backup_id,
                    created_at,
                ),
            )
            await db.commit()

    async def log_backup(
        self,
        backup_id: str,
        original_path: str,
        backup_path: str,
        request_id: str | None,
        created_at: str,
    ) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT INTO backups "
                "(backup_id, original_path, backup_path, request_id, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (backup_id, original_path, backup_path, request_id, created_at),
            )
            await db.commit()

    async def list_events(self) -> list[dict]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM events ORDER BY created_at DESC") as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

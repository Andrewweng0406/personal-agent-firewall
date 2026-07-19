from __future__ import annotations

import json
from pathlib import Path

import aiosqlite

EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    request_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL DEFAULT 'unknown',
    session_id TEXT NOT NULL DEFAULT 'unknown',
    tool_name TEXT NOT NULL,
    args_json TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    behavior_lane TEXT NOT NULL DEFAULT 'yellow',
    intent_alignment TEXT NOT NULL DEFAULT 'uncertain',
    user_intent TEXT,
    matched_rules_json TEXT NOT NULL DEFAULT '[]',
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
    created_at TEXT NOT NULL,
    restore_count INTEGER NOT NULL DEFAULT 0,
    last_restored_at TEXT
)
"""

CODEX_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS codex_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    agent_id TEXT NOT NULL DEFAULT 'codex-main',
    session_id TEXT NOT NULL,
    turn_id TEXT NOT NULL,
    cwd TEXT,
    model TEXT,
    permission_mode TEXT,
    content_redacted TEXT,
    tool_name TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'LOW',
    matched_rules_json TEXT NOT NULL DEFAULT '[]',
    action TEXT NOT NULL,
    explanation TEXT,
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
            await db.execute(CODEX_EVENTS_TABLE)
            await self._migrate_events_table(db)
            await self._migrate_backups_table(db)
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_agent_created "
                "ON events (agent_id, created_at DESC)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_session_created "
                "ON events (session_id, created_at DESC)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_codex_events_session_created "
                "ON codex_events (session_id, created_at DESC)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_codex_events_turn_created "
                "ON codex_events (turn_id, created_at DESC)"
            )
            await db.commit()

    async def _migrate_events_table(self, db: aiosqlite.Connection) -> None:
        cursor = await db.execute("PRAGMA table_info(events)")
        existing = {row[1] for row in await cursor.fetchall()}
        additions = {
            "agent_id": "TEXT NOT NULL DEFAULT 'unknown'",
            "session_id": "TEXT NOT NULL DEFAULT 'unknown'",
            "behavior_lane": "TEXT NOT NULL DEFAULT 'yellow'",
            "intent_alignment": "TEXT NOT NULL DEFAULT 'uncertain'",
            "user_intent": "TEXT",
            "matched_rules_json": "TEXT NOT NULL DEFAULT '[]'",
        }
        for column, definition in additions.items():
            if column not in existing:
                await db.execute(f"ALTER TABLE events ADD COLUMN {column} {definition}")

    async def _migrate_backups_table(self, db: aiosqlite.Connection) -> None:
        cursor = await db.execute("PRAGMA table_info(backups)")
        existing = {row[1] for row in await cursor.fetchall()}
        additions = {
            "restore_count": "INTEGER NOT NULL DEFAULT 0",
            "last_restored_at": "TEXT",
        }
        for column, definition in additions.items():
            if column not in existing:
                await db.execute(f"ALTER TABLE backups ADD COLUMN {column} {definition}")

    async def log_event(
        self,
        request_id: str,
        agent_id: str,
        session_id: str,
        tool_name: str,
        args: dict,
        risk_score: int,
        risk_level: str,
        behavior_lane: str,
        intent_alignment: str,
        user_intent: str | None,
        matched_rules: list[str],
        decision: str,
        plain_explanation: str,
        backup_id: str | None,
        created_at: str,
    ) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO events "
                "(request_id, agent_id, session_id, tool_name, args_json, risk_score, "
                "risk_level, behavior_lane, intent_alignment, user_intent, "
                "matched_rules_json, decision, plain_explanation, backup_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    request_id,
                    agent_id,
                    session_id,
                    tool_name,
                    json.dumps(args),
                    risk_score,
                    risk_level,
                    behavior_lane,
                    intent_alignment,
                    user_intent,
                    json.dumps(matched_rules),
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

    async def get_backup(self, backup_id: str) -> dict | None:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM backups WHERE backup_id = ?", (backup_id,)
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def mark_backup_restored(self, backup_id: str, restored_at: str) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "UPDATE backups SET restore_count = restore_count + 1, "
                "last_restored_at = ? WHERE backup_id = ?",
                (restored_at, backup_id),
            )
            await db.commit()

    async def list_events(
        self,
        agent_id: str | None = None,
        session_id: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        clauses: list[str] = []
        values: list[str | int] = []
        if agent_id:
            clauses.append("agent_id = ?")
            values.append(agent_id)
        if session_id:
            clauses.append("session_id = ?")
            values.append(session_id)

        query = "SELECT * FROM events"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC"
        if limit is not None:
            query += " LIMIT ?"
            values.append(limit)

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, values) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def log_codex_event(
        self,
        event_id: str,
        event_type: str,
        agent_id: str,
        session_id: str,
        turn_id: str,
        cwd: str | None,
        model: str | None,
        permission_mode: str | None,
        content_redacted: str | None,
        tool_name: str | None,
        payload: dict,
        risk_score: int,
        risk_level: str,
        matched_rules: list[str],
        action: str,
        explanation: str | None,
        created_at: str,
    ) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO codex_events "
                "(event_id, event_type, agent_id, session_id, turn_id, cwd, model, "
                "permission_mode, content_redacted, tool_name, payload_json, risk_score, "
                "risk_level, matched_rules_json, action, explanation, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    event_type,
                    agent_id,
                    session_id,
                    turn_id,
                    cwd,
                    model,
                    permission_mode,
                    content_redacted,
                    tool_name,
                    json.dumps(payload),
                    risk_score,
                    risk_level,
                    json.dumps(matched_rules),
                    action,
                    explanation,
                    created_at,
                ),
            )
            await db.commit()

    async def list_codex_events(
        self,
        session_id: str | None = None,
        turn_id: str | None = None,
        limit: int | None = None,
        agent_id: str | None = None,
    ) -> list[dict]:
        clauses: list[str] = []
        values: list[str | int] = []
        if session_id:
            clauses.append("session_id = ?")
            values.append(session_id)
        if turn_id:
            clauses.append("turn_id = ?")
            values.append(turn_id)
        if agent_id:
            clauses.append("agent_id = ?")
            values.append(agent_id)

        query = "SELECT * FROM codex_events"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC"
        if limit is not None:
            query += " LIMIT ?"
            values.append(limit)

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, values) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def latest_codex_prompt(
        self, session_id: str, turn_id: str | None = None
    ) -> str | None:
        clauses = ["session_id = ?", "event_type = 'user_prompt'"]
        values: list[str] = [session_id]
        if turn_id:
            clauses.append("turn_id = ?")
            values.append(turn_id)
        query = (
            "SELECT content_redacted FROM codex_events WHERE "
            + " AND ".join(clauses)
            + " ORDER BY created_at DESC LIMIT 1"
        )
        async with aiosqlite.connect(self._db_path) as db:
            cursor = await db.execute(query, values)
            row = await cursor.fetchone()
            return row[0] if row else None

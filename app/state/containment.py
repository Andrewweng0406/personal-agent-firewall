from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import aiosqlite


CONTAINMENTS_TABLE = """
CREATE TABLE IF NOT EXISTS containments (
    scope TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    released_at TEXT,
    PRIMARY KEY (scope, agent_id, session_id)
)
"""


class ContainmentStore:
    def __init__(self, db_path: Path):
        self._db_path = db_path

    async def init_db(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(CONTAINMENTS_TABLE)
            await db.commit()

    async def quarantine(
        self,
        scope: str,
        agent_id: str,
        session_id: str | None,
        reason: str,
    ) -> dict:
        normalized_session = session_id or ""
        now = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT INTO containments "
                "(scope, agent_id, session_id, reason, active, created_at, released_at) "
                "VALUES (?, ?, ?, ?, 1, ?, NULL) "
                "ON CONFLICT(scope, agent_id, session_id) DO UPDATE SET "
                "reason = excluded.reason, active = 1, created_at = excluded.created_at, "
                "released_at = NULL",
                (scope, agent_id, normalized_session, reason, now),
            )
            await db.commit()
        return {
            "scope": scope,
            "agent_id": agent_id,
            "session_id": session_id,
            "reason": reason,
            "active": True,
            "created_at": now,
            "released_at": None,
        }

    async def release(
        self,
        scope: str,
        agent_id: str,
        session_id: str | None,
    ) -> bool:
        normalized_session = session_id or ""
        now = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self._db_path) as db:
            cursor = await db.execute(
                "UPDATE containments SET active = 0, released_at = ? "
                "WHERE scope = ? AND agent_id = ? AND session_id = ? AND active = 1",
                (now, scope, agent_id, normalized_session),
            )
            await db.commit()
            return cursor.rowcount > 0

    async def get_active(
        self,
        agent_id: str,
        session_id: str,
    ) -> dict | None:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM containments WHERE active = 1 AND agent_id = ? "
                "AND ((scope = 'agent' AND session_id = '') "
                "OR (scope = 'session' AND session_id = ?)) "
                "ORDER BY CASE scope WHEN 'agent' THEN 0 ELSE 1 END LIMIT 1",
                (agent_id, session_id),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def list_active(
        self,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> list[dict]:
        clauses = ["active = 1"]
        values: list[str] = []
        if agent_id:
            clauses.append("agent_id = ?")
            values.append(agent_id)
        if session_id:
            clauses.append("session_id = ?")
            values.append(session_id)
        query = (
            "SELECT * FROM containments WHERE "
            + " AND ".join(clauses)
            + " ORDER BY created_at DESC"
        )
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(query, values)
            return [dict(row) for row in await cursor.fetchall()]

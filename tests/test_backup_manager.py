from pathlib import Path

import aiosqlite

from app.state.audit_log import AuditLog
from app.state.backup_manager import BackupManager


async def test_snapshot_copies_file_and_logs(tmp_path: Path):
    source = tmp_path / "src" / "index.html"
    source.parent.mkdir(parents=True)
    source.write_text("<html>original</html>")

    audit_log = AuditLog(tmp_path / "audit.db")
    await audit_log.init_db()
    manager = BackupManager(tmp_path / "backups", audit_log)

    backup_id = await manager.snapshot(str(source), request_id="req-1")

    assert backup_id is not None
    backup_file = tmp_path / "backups" / backup_id / "index.html"
    assert backup_file.read_text() == "<html>original</html>"

    events = await audit_log.list_events()
    assert events == []

    # Verify backups table row contains correct manifest data
    async with aiosqlite.connect(tmp_path / "audit.db") as db:
        cursor = await db.execute("SELECT * FROM backups WHERE backup_id = ?", (backup_id,))
        row = await cursor.fetchone()

    assert row is not None
    assert row[1] == str(source)  # original_path
    assert row[2] == str(backup_file)  # backup_path
    assert row[3] == "req-1"  # request_id


async def test_snapshot_of_missing_file_returns_none(tmp_path: Path):
    audit_log = AuditLog(tmp_path / "audit.db")
    await audit_log.init_db()
    manager = BackupManager(tmp_path / "backups", audit_log)

    backup_id = await manager.snapshot(str(tmp_path / "does_not_exist.txt"))

    assert backup_id is None
    assert not (tmp_path / "backups").exists()

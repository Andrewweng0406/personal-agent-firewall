from __future__ import annotations

import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.state.audit_log import AuditLog


class BackupManager:
    def __init__(self, backup_dir: Path, audit_log: AuditLog):
        self._backup_dir = backup_dir
        self._audit_log = audit_log

    async def snapshot(self, original_path: str, request_id: str | None = None) -> str | None:
        source = Path(original_path)
        if not source.exists():
            return None

        backup_id = str(uuid.uuid4())
        target_dir = self._backup_dir / backup_id
        target_dir.mkdir(parents=True, exist_ok=True)
        target_path = target_dir / source.name
        shutil.copy2(source, target_path)

        await self._audit_log.log_backup(
            backup_id=backup_id,
            original_path=str(source),
            backup_path=str(target_path),
            request_id=request_id,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        return backup_id

    async def restore(self, backup_id: str) -> dict | None:
        manifest = await self._audit_log.get_backup(backup_id)
        if manifest is None:
            return None

        backup_path = Path(manifest["backup_path"])
        if not backup_path.is_file():
            return None

        original_path = Path(manifest["original_path"])
        original_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_path, original_path)

        restored_at = datetime.now(timezone.utc).isoformat()
        await self._audit_log.mark_backup_restored(backup_id, restored_at)
        return {
            "backup_id": backup_id,
            "request_id": manifest["request_id"],
            "original_path": str(original_path),
            "restored_at": restored_at,
        }

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

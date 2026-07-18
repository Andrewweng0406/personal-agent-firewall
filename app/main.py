from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from app.config import load_settings
from app.gateway.router import GatewayState, build_router
from app.privacy.vector_store import SemanticPiiDetector
from app.risk.llm_translator import build_llm_client
from app.state.audit_log import AuditLog
from app.state.backup_manager import BackupManager
from app.state.containment import ContainmentStore
from app.ws.manager import ConnectionManager

settings = load_settings()
audit_log = AuditLog(settings.audit_db_path)
backup_manager = BackupManager(settings.backup_dir, audit_log)
llm_client = build_llm_client(
    settings.llm_provider, settings.anthropic_api_key, settings.openai_api_key
)
ws_manager = ConnectionManager()
containment_store = ContainmentStore(settings.audit_db_path)
try:
    # Optional: local vector-similarity PII detection on top of regex. Never
    # let a network hiccup on the one-time embedding-model download (or any
    # other Chroma init failure) prevent the whole app from starting -- the
    # firewall's core guarantees don't depend on this enhancement.
    semantic_pii_detector: SemanticPiiDetector | None = SemanticPiiDetector()
except Exception:
    semantic_pii_detector = None
gateway_state = GatewayState(
    settings,
    llm_client,
    audit_log,
    backup_manager,
    ws_manager,
    containment_store,
    semantic_pii_detector,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    await audit_log.init_db()
    await containment_store.init_db()
    yield


app = FastAPI(title="Personal Agent Firewall", lifespan=lifespan)
app.include_router(build_router(gateway_state))


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

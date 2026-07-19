from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from app.codex.router import build_codex_router
from app.config import load_settings
from app.gateway.router import GatewayState, build_router
from app.privacy.vector_store import SemanticPiiDetector
from app.risk.llm_translator import build_llm_client
from app.state.audit_log import AuditLog
from app.state.backup_manager import BackupManager
from app.state.containment import ContainmentStore
from app.ws.manager import ConnectionManager

settings = load_settings()
logger = logging.getLogger(__name__)
audit_log = AuditLog(settings.audit_db_path)
backup_manager = BackupManager(settings.backup_dir, audit_log)
llm_client = build_llm_client(
    settings.llm_provider, settings.anthropic_api_key, settings.openai_api_key
)
ws_manager = ConnectionManager()
containment_store = ContainmentStore(settings.audit_db_path)
# The semantic detector is an optional enhancement. It may initialize an ONNX
# model (and download it on first use), so it must not block the HTTP server
# from reaching its ready state.
semantic_pii_detector: SemanticPiiDetector | None = None
gateway_state = GatewayState(
    settings,
    llm_client,
    audit_log,
    backup_manager,
    ws_manager,
    containment_store,
    semantic_pii_detector,
)


async def _initialize_semantic_pii_detector() -> None:
    try:
        detector = await asyncio.to_thread(SemanticPiiDetector)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning("Semantic PII detector unavailable; regex protection remains active: %s", exc)
        return
    gateway_state.semantic_pii_detector = detector
    logger.info("Semantic PII detector initialized")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    await audit_log.init_db()
    await containment_store.init_db()
    semantic_task = asyncio.create_task(_initialize_semantic_pii_detector())
    try:
        yield
    finally:
        if not semantic_task.done():
            semantic_task.cancel()


app = FastAPI(title="Personal Agent Firewall", lifespan=lifespan)
app.include_router(build_router(gateway_state))
app.include_router(build_codex_router(gateway_state))


@app.get("/api/health")
async def health() -> dict:
    return {
        "status": "ok",
        "mode": settings.firewall_mode,
        "database": "ok",
        "semantic_pii": "ready" if gateway_state.semantic_pii_detector else "initializing",
        "llm_provider": settings.llm_provider,
        "pending_reviews": len(gateway_state.pending),
    }


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException

from app.config import Settings
from app.gateway import tool_executor
from app.gateway.tool_executor import ToolExecutionError
from app.models import DecisionRequest, ToolCallRequest, ToolCallResponse
from app.privacy.shield import scan_and_redact
from app.risk.engine import assess_risk
from app.risk.llm_translator import RiskLlmClient
from app.state.audit_log import AuditLog
from app.state.backup_manager import BackupManager
from app.ws.manager import ConnectionManager


class PendingDecision:
    def __init__(self) -> None:
        self.future: asyncio.Future[str] = asyncio.get_running_loop().create_future()


class GatewayState:
    def __init__(
        self,
        settings: Settings,
        llm_client: RiskLlmClient,
        audit_log: AuditLog,
        backup_manager: BackupManager,
        ws_manager: ConnectionManager,
    ) -> None:
        self.settings = settings
        self.llm_client = llm_client
        self.audit_log = audit_log
        self.backup_manager = backup_manager
        self.ws_manager = ws_manager
        self.pending: dict[str, PendingDecision] = {}


_SHELL_TOKEN_SPLIT = re.compile(r"[\s'\";|&()]+")


def _extract_existing_paths_from_text(text: str) -> list[str]:
    """Best-effort extraction of path-like tokens that exist on disk.

    `run_shell` and `exec_python` calls carry their target file inside a
    `command`/`code` string rather than a `path` arg, so the ordinary
    `sanitized_args.get("path")` backup trigger never fires for them. This
    splits the text on common shell/quote separators and keeps tokens that
    look like a path (contain `/` or start with `.`) AND actually exist on
    disk, so callers can back those files up too before a high-risk call
    executes.
    """
    if not text:
        return []
    found: list[str] = []
    for token in _SHELL_TOKEN_SPLIT.split(text):
        if not token:
            continue
        if "/" not in token and not token.startswith("."):
            continue
        try:
            exists = Path(token).exists()
        except (OSError, ValueError):
            exists = False
        if exists and token not in found:
            found.append(token)
    return found


async def _log(
    state: GatewayState,
    request_id: str,
    tool_name: str,
    args: dict,
    risk_score: int,
    risk_level: str,
    decision: str,
    plain_explanation: str,
    backup_id: str | None,
) -> None:
    await state.audit_log.log_event(
        request_id=request_id,
        tool_name=tool_name,
        args=args,
        risk_score=risk_score,
        risk_level=risk_level,
        decision=decision,
        plain_explanation=plain_explanation,
        backup_id=backup_id,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


async def _execute_and_sanitize(tool_name: str, args: dict):
    try:
        result = await asyncio.to_thread(tool_executor.execute, tool_name, args)
    except ToolExecutionError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    sanitized_result, _ = scan_and_redact(result)
    return sanitized_result


def build_router(state: GatewayState) -> APIRouter:
    router = APIRouter()

    @router.post("/api/tool_call", response_model=ToolCallResponse)
    async def tool_call(request: ToolCallRequest) -> ToolCallResponse:
        settings = state.settings
        request_id = str(uuid.uuid4())
        sanitized_args, _ = scan_and_redact(request.args)

        if settings.is_blocked_tool(request.tool_name):
            await _log(
                state, request_id, request.tool_name, sanitized_args,
                100, "CRITICAL", "denied", "Tool is on the blocked list.", None,
            )
            return ToolCallResponse(
                status="denied", reason="Tool is on the blocked list.", risk_score=100
            )

        assessment = await asyncio.to_thread(
            assess_risk, request.tool_name, sanitized_args, settings, state.llm_client
        )

        if assessment.score < settings.risk_threshold:
            try:
                result = await _execute_and_sanitize(request.tool_name, sanitized_args)
            except HTTPException as exc:
                await _log(
                    state, request_id, request.tool_name, sanitized_args,
                    assessment.score, assessment.level, "allowed_execution_failed",
                    f"Tool execution failed: {exc.detail}", None,
                )
                raise
            await _log(
                state, request_id, request.tool_name, sanitized_args,
                assessment.score, assessment.level, "allowed", "", None,
            )
            return ToolCallResponse(status="allowed", result=result, risk_score=assessment.score)

        candidate_paths: list[str] = []
        path = sanitized_args.get("path")
        if path:
            candidate_paths.append(path)
        code_or_command = sanitized_args.get("code")
        if not isinstance(code_or_command, str):
            code_or_command = sanitized_args.get("command")
        if isinstance(code_or_command, str):
            for candidate in _extract_existing_paths_from_text(code_or_command):
                if candidate not in candidate_paths:
                    candidate_paths.append(candidate)

        backup_ids: list[str] = []
        for candidate in candidate_paths:
            candidate_backup_id = await state.backup_manager.snapshot(
                candidate, request_id=request_id
            )
            if candidate_backup_id:
                backup_ids.append(candidate_backup_id)
        backup_id = backup_ids[0] if backup_ids else None

        pending = PendingDecision()
        state.pending[request_id] = pending

        await state.ws_manager.broadcast(
            {
                "type": "new_alert",
                "request_id": request_id,
                "tool_name": request.tool_name,
                "args_summary": sanitized_args,
                "risk_score": assessment.score,
                "risk_level": assessment.level,
                "plain_explanation": assessment.plain_explanation,
                "matched_rules": assessment.matched_rules,
                "backup_id": backup_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        timed_out = False
        try:
            decision = await asyncio.wait_for(
                pending.future, timeout=settings.decision_timeout_seconds
            )
        except asyncio.TimeoutError:
            decision = "deny"
            timed_out = True
        finally:
            state.pending.pop(request_id, None)

        if decision == "allow":
            try:
                result = await _execute_and_sanitize(request.tool_name, sanitized_args)
            except HTTPException as exc:
                await _log(
                    state, request_id, request.tool_name, sanitized_args,
                    assessment.score, assessment.level, "allowed_execution_failed",
                    f"Tool execution failed: {exc.detail}", backup_id,
                )
                await state.ws_manager.broadcast(
                    {"type": "resolved", "request_id": request_id, "decision": "allowed"}
                )
                raise
            outcome = ToolCallResponse(status="allowed", result=result, risk_score=assessment.score)
            final_decision = "allowed"
        else:
            reason = (
                "Decision timed out; denied by default (fail-closed)."
                if timed_out
                else "Denied by reviewer."
            )
            outcome = ToolCallResponse(status="denied", reason=reason, risk_score=assessment.score)
            final_decision = "denied"

        await _log(
            state, request_id, request.tool_name, sanitized_args,
            assessment.score, assessment.level, final_decision,
            assessment.plain_explanation, backup_id,
        )
        await state.ws_manager.broadcast(
            {"type": "resolved", "request_id": request_id, "decision": final_decision}
        )
        return outcome

    @router.post("/api/decision/{request_id}")
    async def submit_decision(request_id: str, decision: DecisionRequest) -> dict:
        pending = state.pending.get(request_id)
        if pending is None:
            raise HTTPException(status_code=404, detail="No pending decision for this request_id")
        if not pending.future.done():
            pending.future.set_result(decision.decision)
        return {"ack": True}

    return router

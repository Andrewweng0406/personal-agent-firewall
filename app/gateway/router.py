from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

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
        result = tool_executor.execute(tool_name, args)
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

        assessment = assess_risk(request.tool_name, sanitized_args, settings, state.llm_client)

        if assessment.score < settings.risk_threshold:
            result = await _execute_and_sanitize(request.tool_name, sanitized_args)
            await _log(
                state, request_id, request.tool_name, sanitized_args,
                assessment.score, assessment.level, "allowed", "", None,
            )
            return ToolCallResponse(status="allowed", result=result, risk_score=assessment.score)

        backup_id = None
        path = sanitized_args.get("path")
        if path:
            backup_id = await state.backup_manager.snapshot(path, request_id=request_id)

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
            result = await _execute_and_sanitize(request.tool_name, sanitized_args)
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

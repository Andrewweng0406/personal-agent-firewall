from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.codex.risk import ConversationAssessment, assess_conversation_content
from app.gateway.router import GatewayState, PendingDecision
from app.models import CodexEventRequest, CodexEventResponse
from app.privacy.shield import scan_and_redact


def build_codex_router(state: GatewayState) -> APIRouter:
    router = APIRouter(prefix="/api/codex", tags=["codex"])

    @router.post("/event", response_model=CodexEventResponse)
    async def ingest_event(request: CodexEventRequest) -> CodexEventResponse:
        _validate_event(request)
        event_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        if request.event_type in {"user_prompt", "assistant_response"}:
            raw_content = request.content or ""
            redacted_content, matches = await asyncio.to_thread(
                scan_and_redact, raw_content, state.semantic_pii_detector
            )
            assessment = assess_conversation_content(
                request.event_type, raw_content, matches
            )
            if request.event_type == "user_prompt":
                response = await _handle_user_prompt(
                    state, request, event_id, redacted_content, assessment, created_at
                )
            else:
                response = await _handle_assistant_response(
                    state, request, event_id, redacted_content, assessment, created_at
                )
            return response

        redacted_payload, matches = await asyncio.to_thread(
            scan_and_redact,
            {
                "tool_input": request.tool_input,
                "tool_response": request.tool_response,
            },
            state.semantic_pii_detector,
        )
        assessment = assess_conversation_content(
            request.event_type,
            json.dumps({"tool_input": request.tool_input, "tool_response": request.tool_response}),
            matches,
        )
        action = (
            "deny"
            if state.settings.firewall_mode != "observe"
            and assessment.score >= state.settings.risk_threshold
            else "recorded"
        )
        reason = (
            "The tool result was withheld because it contains sensitive data."
            if action == "deny"
            else None
        )
        await _store_event(
            state,
            request,
            event_id,
            None,
            redacted_payload,
            assessment,
            action,
            reason or assessment.explanation,
            created_at,
        )
        response = CodexEventResponse(
            event_id=event_id,
            action=action,
            reason=reason,
            risk_score=assessment.score,
            risk_level=assessment.level,
            matched_rules=assessment.matched_rules,
        )
        await _broadcast_event(state, request, response, created_at)
        return response

    @router.get("/events")
    async def list_codex_events(
        agent_id: str | None = None,
        session_id: str | None = None,
        turn_id: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict:
        rows = await state.audit_log.list_codex_events(
            session_id, turn_id, limit, agent_id=agent_id
        )
        events = [_decode_codex_row(row) for row in rows]
        return {"events": events, "count": len(events)}

    @router.get("/timeline")
    async def session_timeline(
        session_id: str,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict:
        codex_rows = await state.audit_log.list_codex_events(session_id=session_id, limit=limit)
        tool_rows = await state.audit_log.list_events(session_id=session_id, limit=limit)
        timeline = [_decode_codex_row(row) for row in codex_rows]
        timeline.extend(_decode_tool_row(row) for row in tool_rows)
        timeline.sort(key=lambda item: item["created_at"])
        timeline = timeline[-limit:]
        return {"events": timeline, "count": len(timeline)}

    return router


def _validate_event(request: CodexEventRequest) -> None:
    if request.event_type in {"user_prompt", "assistant_response"} and request.content is None:
        raise HTTPException(
            status_code=422,
            detail=f"content is required for {request.event_type}",
        )
    if request.event_type == "post_tool_use" and not request.tool_name:
        raise HTTPException(status_code=422, detail="tool_name is required for post_tool_use")


async def _handle_user_prompt(
    state: GatewayState,
    request: CodexEventRequest,
    event_id: str,
    redacted_content: str,
    assessment: ConversationAssessment,
    created_at: str,
) -> CodexEventResponse:
    active_containment = await state.containment_store.get_active(
        request.agent_id, request.session_id
    )
    if state.settings.firewall_mode == "observe":
        action = "allow"
        reason = None
    elif active_containment:
        scope = active_containment["scope"]
        reason = f"The {scope} is quarantined: {active_containment['reason']}"
        action = "deny"
        assessment = ConversationAssessment(
            score=100,
            level="CRITICAL",
            explanation=reason,
            matched_rules=[f"containment:{scope}_quarantined"],
        )
    elif assessment.score < state.settings.risk_threshold:
        action = "allow"
        reason = None
    elif state.settings.firewall_mode == "enforce":
        action = "deny"
        reason = assessment.explanation or "Prompt denied automatically by enforce mode."
    else:
        pending = PendingDecision()
        state.pending[event_id] = pending
        await state.ws_manager.broadcast(
            {
                "type": "new_alert",
                "request_id": event_id,
                "agent_id": request.agent_id,
                "session_id": request.session_id,
                "user_intent": redacted_content,
                "tool_name": "codex:user_prompt",
                "args_summary": {"prompt": redacted_content},
                "risk_score": assessment.score,
                "risk_level": assessment.level,
                "plain_explanation": assessment.explanation,
                "matched_rules": assessment.matched_rules,
                "backup_id": None,
                "behavior_lane": "red",
                "intent_alignment": "off_scope",
                "chain_detected": False,
                "auto_contained": False,
                "timestamp": created_at,
            }
        )
        timed_out = False
        try:
            decision = await asyncio.wait_for(
                pending.future, timeout=state.settings.decision_timeout_seconds
            )
        except asyncio.TimeoutError:
            decision = "deny"
            timed_out = True
        finally:
            state.pending.pop(event_id, None)
        action = "allow" if decision == "allow" else "deny"
        reason = (
            "Decision timed out; prompt denied by default (fail-closed)."
            if timed_out
            else (None if action == "allow" else "Prompt denied by reviewer.")
        )
        await state.ws_manager.broadcast(
            {
                "type": "resolved",
                "request_id": event_id,
                "agent_id": request.agent_id,
                "session_id": request.session_id,
                "decision": "allowed" if action == "allow" else "denied",
            }
        )

    additional_context = None
    if action == "allow" and assessment.matched_rules:
        additional_context = (
            "Treat sensitive material in the user prompt as confidential. "
            "Do not repeat credentials or personal data in responses or external tool calls."
        )
    await _store_event(
        state,
        request,
        event_id,
        redacted_content,
        {},
        assessment,
        action,
        reason or assessment.explanation,
        created_at,
    )
    response = CodexEventResponse(
        event_id=event_id,
        action=action,
        reason=reason,
        risk_score=assessment.score,
        risk_level=assessment.level,
        matched_rules=assessment.matched_rules,
        additional_context=additional_context,
    )
    await _broadcast_event(state, request, response, created_at)
    return response


async def _handle_assistant_response(
    state: GatewayState,
    request: CodexEventRequest,
    event_id: str,
    redacted_content: str,
    assessment: ConversationAssessment,
    created_at: str,
) -> CodexEventResponse:
    needs_correction = (
        state.settings.firewall_mode != "observe"
        and assessment.score >= state.settings.risk_threshold
    )
    if needs_correction and not request.stop_hook_active:
        action = "continue"
        reason = (
            "Rewrite the answer without exposing credentials or sensitive personal data. "
            "Do not repeat the flagged values; provide a safe summary instead."
        )
    else:
        action = "allow"
        reason = (
            "The response still contains sensitive data after one corrective pass; "
            "the loop limit prevented another automatic continuation."
            if needs_correction
            else None
        )
    await _store_event(
        state,
        request,
        event_id,
        redacted_content,
        {},
        assessment,
        action,
        reason or assessment.explanation,
        created_at,
    )
    response = CodexEventResponse(
        event_id=event_id,
        action=action,
        reason=reason,
        risk_score=assessment.score,
        risk_level=assessment.level,
        matched_rules=assessment.matched_rules,
    )
    await _broadcast_event(state, request, response, created_at)
    return response


async def _store_event(
    state: GatewayState,
    request: CodexEventRequest,
    event_id: str,
    content_redacted: str | None,
    payload: dict,
    assessment: ConversationAssessment,
    action: str,
    explanation: str,
    created_at: str,
) -> None:
    await state.audit_log.log_codex_event(
        event_id=event_id,
        event_type=request.event_type,
        agent_id=request.agent_id,
        session_id=request.session_id,
        turn_id=request.turn_id,
        cwd=request.cwd,
        model=request.model,
        permission_mode=request.permission_mode,
        content_redacted=content_redacted,
        tool_name=request.tool_name,
        payload=payload,
        risk_score=assessment.score,
        risk_level=assessment.level,
        matched_rules=assessment.matched_rules,
        action=action,
        explanation=explanation,
        created_at=created_at,
        source=request.source,
        tool_use_id=request.tool_use_id,
        phase=request.phase or _phase_for_event(request.event_type),
    )


async def _broadcast_event(
    state: GatewayState,
    request: CodexEventRequest,
    response: CodexEventResponse,
    created_at: str,
) -> None:
    await state.ws_manager.broadcast(
        {
            "type": "codex_event",
            "event_id": response.event_id,
            "event_type": request.event_type,
            "source": request.source,
            "phase": request.phase or _phase_for_event(request.event_type),
            "tool_use_id": request.tool_use_id,
            "agent_id": request.agent_id,
            "session_id": request.session_id,
            "turn_id": request.turn_id,
            "tool_name": request.tool_name,
            "action": response.action,
            "risk_score": response.risk_score,
            "risk_level": response.risk_level,
            "matched_rules": response.matched_rules,
            "reason": response.reason,
            "timestamp": created_at,
        }
    )


def _decode_codex_row(row: dict) -> dict:
    event = dict(row)
    event["payload"] = _decode_json(event.pop("payload_json"), {})
    event["matched_rules"] = _decode_json(event.pop("matched_rules_json"), [])
    return event


def _decode_tool_row(row: dict) -> dict:
    return {
        "event_id": row["request_id"],
        "event_type": "pre_tool_use",
        "source": row.get("source", "generic"),
        "phase": row.get("phase", "before"),
        "tool_use_id": row.get("tool_use_id"),
        "agent_id": row["agent_id"],
        "session_id": row["session_id"],
        "turn_id": None,
        "cwd": None,
        "model": None,
        "permission_mode": None,
        "content_redacted": None,
        "tool_name": row["tool_name"],
        "payload": {"tool_input": _decode_json(row.get("args_json"), {})},
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "matched_rules": _decode_json(row.get("matched_rules_json"), []),
        "action": row["decision"],
        "explanation": row.get("plain_explanation"),
        "created_at": row["created_at"],
    }


def _phase_for_event(event_type: str) -> str:
    return {
        "user_prompt": "prompt",
        "assistant_response": "response",
        "post_tool_use": "after",
    }.get(event_type, "event")


def _decode_json(value: Any, fallback: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback

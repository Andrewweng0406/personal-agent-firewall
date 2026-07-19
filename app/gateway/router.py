from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Query

from app.config import Settings
from app.gateway import tool_executor
from app.gateway.tool_executor import ToolExecutionError
from app.models import ContainmentRequest, DecisionRequest, ToolCallRequest, ToolCallResponse
from app.privacy.shield import scan_and_redact
from app.risk.behavior_chain import analyze_behavior_chain
from app.risk.cross_agent_correlation import detect_cross_agent_pattern
from app.risk.trust_score import compute_trust_profile
from app.risk.engine import assess_risk
from app.risk.llm_translator import RiskLlmClient
from app.state.audit_log import AuditLog
from app.state.backup_manager import BackupManager
from app.state.containment import ContainmentStore
from app.ws.manager import ConnectionManager

if TYPE_CHECKING:
    from app.privacy.vector_store import SemanticPiiDetector


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
        containment_store: ContainmentStore,
        semantic_pii_detector: SemanticPiiDetector | None = None,
    ) -> None:
        self.settings = settings
        self.llm_client = llm_client
        self.audit_log = audit_log
        self.backup_manager = backup_manager
        self.ws_manager = ws_manager
        self.containment_store = containment_store
        self.semantic_pii_detector = semantic_pii_detector
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
        if "/" not in token and "\\" not in token and not token.startswith("."):
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
) -> None:
    await state.audit_log.log_event(
        request_id=request_id,
        agent_id=agent_id,
        session_id=session_id,
        tool_name=tool_name,
        args=args,
        risk_score=risk_score,
        risk_level=risk_level,
        behavior_lane=behavior_lane,
        intent_alignment=intent_alignment,
        user_intent=user_intent,
        matched_rules=matched_rules,
        decision=decision,
        plain_explanation=plain_explanation,
        backup_id=backup_id,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


async def _execute_and_sanitize(
    tool_name: str, args: dict, semantic_detector: SemanticPiiDetector | None = None
):
    try:
        result = await asyncio.to_thread(tool_executor.execute, tool_name, args)
    except ToolExecutionError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    sanitized_result, _ = await asyncio.to_thread(scan_and_redact, result, semantic_detector)
    return sanitized_result


def build_router(state: GatewayState) -> APIRouter:
    router = APIRouter()

    @router.post("/api/tool_call", response_model=ToolCallResponse)
    async def tool_call(request: ToolCallRequest) -> ToolCallResponse:
        settings = state.settings
        request_id = str(uuid.uuid4())
        requested_intent = request.user_intent
        if requested_intent is None and request.turn_id:
            requested_intent = await state.audit_log.latest_codex_prompt(
                request.session_id, request.turn_id
            )
        sanitized_args, _ = await asyncio.to_thread(
            scan_and_redact, request.args, state.semantic_pii_detector
        )
        sanitized_intent, _ = await asyncio.to_thread(
            scan_and_redact, requested_intent, state.semantic_pii_detector
        )

        active_containment = await state.containment_store.get_active(
            request.agent_id, request.session_id
        )
        if active_containment:
            scope = active_containment["scope"]
            reason = f"The {scope} is quarantined: {active_containment['reason']}"
            await _log(
                state, request_id, request.agent_id, request.session_id,
                request.tool_name, sanitized_args, 100, "CRITICAL", "red", "off_scope",
                sanitized_intent, [f"containment:{scope}_quarantined"],
                "denied_quarantined", reason, None,
            )
            return ToolCallResponse(
                status="denied",
                reason=reason,
                risk_score=100,
                behavior_lane="red",
                intent_alignment="off_scope",
                containment_action=f"{scope}_quarantined",
            )

        if settings.is_blocked_tool(request.tool_name):
            await _log(
                state, request_id, request.agent_id, request.session_id,
                request.tool_name, sanitized_args, 100, "CRITICAL", "red", "off_scope",
                sanitized_intent, [f"blocked_tool:{request.tool_name}"], "denied",
                "Tool is on the blocked list.", None,
            )
            return ToolCallResponse(
                status="denied", reason="Tool is on the blocked list.", risk_score=100,
                behavior_lane="red", intent_alignment="off_scope",
            )

        history = await state.audit_log.list_events(
            request.agent_id, request.session_id, limit=20
        )
        behavior_signal = analyze_behavior_chain(
            request.tool_name, sanitized_args, history
        )
        system_wide_recent = await state.audit_log.list_events(limit=50)
        cross_agent_signal = detect_cross_agent_pattern(
            request.agent_id, request.tool_name, sanitized_args, system_wide_recent
        )
        agent_history = await state.audit_log.list_events(request.agent_id, None, limit=50)
        trust_profile = compute_trust_profile(settings.risk_threshold, agent_history)
        assessment = await asyncio.to_thread(
            assess_risk,
            request.tool_name,
            sanitized_args,
            settings,
            state.llm_client,
            sanitized_intent,
            behavior_signal,
            cross_agent_signal,
            trust_profile.effective_threshold,
            trust_profile.trust_score,
        )

        if assessment.auto_contain:
            containment = await state.containment_store.quarantine(
                "session",
                request.agent_id,
                request.session_id,
                assessment.plain_explanation,
            )
            correlated_containments = []
            for other_agent_id in assessment.correlated_agent_ids:
                other_containment = await state.containment_store.quarantine(
                    "agent",
                    other_agent_id,
                    None,
                    "Coordinated with a denied action from another agent identity: "
                    f"{assessment.plain_explanation}",
                )
                correlated_containments.append(other_containment)
                await state.ws_manager.broadcast(
                    {
                        "type": "containment_changed",
                        "action": "quarantined",
                        **other_containment,
                    }
                )
            await _log(
                state, request_id, request.agent_id, request.session_id,
                request.tool_name, sanitized_args, assessment.score, assessment.level,
                assessment.behavior_lane, assessment.intent_alignment, sanitized_intent,
                assessment.matched_rules, "denied_auto_contained",
                assessment.plain_explanation, None,
            )
            alert = {
                "type": "new_alert",
                "request_id": request_id,
                "agent_id": request.agent_id,
                "session_id": request.session_id,
                "user_intent": sanitized_intent,
                "tool_name": request.tool_name,
                "args_summary": sanitized_args,
                "risk_score": assessment.score,
                "risk_level": assessment.level,
                "plain_explanation": assessment.plain_explanation,
                "matched_rules": assessment.matched_rules,
                "backup_id": None,
                "behavior_lane": assessment.behavior_lane,
                "intent_alignment": assessment.intent_alignment,
                "chain_detected": True,
                "auto_contained": True,
                "containment": containment,
                "correlated_agent_ids": assessment.correlated_agent_ids,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            await state.ws_manager.broadcast(alert)
            await state.ws_manager.broadcast(
                {
                    "type": "containment_changed",
                    "action": "quarantined",
                    **containment,
                }
            )
            await state.ws_manager.broadcast(
                {
                    "type": "resolved",
                    "request_id": request_id,
                    "agent_id": request.agent_id,
                    "session_id": request.session_id,
                    "decision": "denied_auto_contained",
                }
            )
            return ToolCallResponse(
                status="denied",
                reason=assessment.plain_explanation,
                risk_score=assessment.score,
                behavior_lane="red",
                intent_alignment="off_scope",
                chain_detected=True,
                containment_action="session_quarantined",
                correlated_agent_ids=assessment.correlated_agent_ids,
                trust_score=assessment.trust_score,
                effective_threshold=assessment.effective_threshold,
            )

        if assessment.score < assessment.effective_threshold:
            result = None
            if request.execute:
                try:
                    result = await _execute_and_sanitize(
                        request.tool_name, request.args, state.semantic_pii_detector
                    )
                except HTTPException as exc:
                    await _log(
                        state, request_id, request.agent_id, request.session_id,
                        request.tool_name, sanitized_args, assessment.score, assessment.level,
                        assessment.behavior_lane, assessment.intent_alignment, sanitized_intent,
                        assessment.matched_rules, "allowed_execution_failed",
                        f"Tool execution failed: {exc.detail}", None,
                    )
                    raise
            await _log(
                state, request_id, request.agent_id, request.session_id,
                request.tool_name, sanitized_args, assessment.score, assessment.level,
                assessment.behavior_lane, assessment.intent_alignment, sanitized_intent,
                assessment.matched_rules, "allowed", assessment.plain_explanation, None,
            )
            return ToolCallResponse(
                status="allowed",
                result=result,
                risk_score=assessment.score,
                behavior_lane=assessment.behavior_lane,
                intent_alignment=assessment.intent_alignment,
                chain_detected=assessment.chain_detected,
                trust_score=assessment.trust_score,
                effective_threshold=assessment.effective_threshold,
            )

        candidate_paths: list[str] = []
        path = sanitized_args.get("path")
        if path:
            candidate_paths.append(path)
        paths = sanitized_args.get("paths")
        if isinstance(paths, list):
            candidate_paths.extend(
                candidate
                for candidate in paths
                if isinstance(candidate, str) and candidate not in candidate_paths
            )
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
                "agent_id": request.agent_id,
                "session_id": request.session_id,
                "user_intent": sanitized_intent,
                "tool_name": request.tool_name,
                "args_summary": sanitized_args,
                "risk_score": assessment.score,
                "risk_level": assessment.level,
                "plain_explanation": assessment.plain_explanation,
                "matched_rules": assessment.matched_rules,
                "backup_id": backup_id,
                "behavior_lane": assessment.behavior_lane,
                "intent_alignment": assessment.intent_alignment,
                "chain_detected": assessment.chain_detected,
                "auto_contained": False,
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
            result = None
            if request.execute:
                try:
                    result = await _execute_and_sanitize(
                        request.tool_name, request.args, state.semantic_pii_detector
                    )
                except HTTPException as exc:
                    await _log(
                        state, request_id, request.agent_id, request.session_id,
                        request.tool_name, sanitized_args, assessment.score, assessment.level,
                        assessment.behavior_lane, assessment.intent_alignment, sanitized_intent,
                        assessment.matched_rules, "allowed_execution_failed",
                        f"Tool execution failed: {exc.detail}", backup_id,
                    )
                    await state.ws_manager.broadcast(
                        {
                            "type": "resolved",
                            "request_id": request_id,
                            "agent_id": request.agent_id,
                            "session_id": request.session_id,
                            "decision": "allowed",
                        }
                    )
                    raise
            outcome = ToolCallResponse(
                status="allowed",
                result=result,
                risk_score=assessment.score,
                behavior_lane=assessment.behavior_lane,
                intent_alignment=assessment.intent_alignment,
                chain_detected=assessment.chain_detected,
                trust_score=assessment.trust_score,
                effective_threshold=assessment.effective_threshold,
            )
            final_decision = "allowed"
        else:
            reason = (
                "Decision timed out; denied by default (fail-closed)."
                if timed_out
                else "Denied by reviewer."
            )
            outcome = ToolCallResponse(
                status="denied",
                reason=reason,
                risk_score=assessment.score,
                behavior_lane=assessment.behavior_lane,
                intent_alignment=assessment.intent_alignment,
                chain_detected=assessment.chain_detected,
                trust_score=assessment.trust_score,
                effective_threshold=assessment.effective_threshold,
            )
            final_decision = "denied"

        await _log(
            state, request_id, request.agent_id, request.session_id,
            request.tool_name, sanitized_args, assessment.score, assessment.level,
            assessment.behavior_lane, assessment.intent_alignment, sanitized_intent,
            assessment.matched_rules, final_decision,
            assessment.plain_explanation, backup_id,
        )
        await state.ws_manager.broadcast(
            {
                "type": "resolved",
                "request_id": request_id,
                "agent_id": request.agent_id,
                "session_id": request.session_id,
                "decision": final_decision,
            }
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

    @router.post("/api/containment/quarantine")
    async def quarantine(request: ContainmentRequest) -> dict:
        _validate_containment_request(request)
        sanitized_reason, _ = await asyncio.to_thread(
            scan_and_redact, request.reason, state.semantic_pii_detector
        )
        containment = await state.containment_store.quarantine(
            request.scope, request.agent_id, request.session_id, sanitized_reason
        )
        await state.ws_manager.broadcast(
            {"type": "containment_changed", "action": "quarantined", **containment}
        )
        return {"containment": containment}

    @router.post("/api/containment/release")
    async def release_containment(request: ContainmentRequest) -> dict:
        _validate_containment_request(request)
        released = await state.containment_store.release(
            request.scope, request.agent_id, request.session_id
        )
        if not released:
            raise HTTPException(status_code=404, detail="Active containment not found")
        event = {
            "type": "containment_changed",
            "action": "released",
            "scope": request.scope,
            "agent_id": request.agent_id,
            "session_id": request.session_id,
        }
        await state.ws_manager.broadcast(event)
        return {"released": True}

    @router.get("/api/containment")
    async def list_containment(
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> dict:
        containments = await state.containment_store.list_active(agent_id, session_id)
        return {"containments": containments, "count": len(containments)}

    @router.post("/api/backups/{backup_id}/restore")
    async def restore_backup(backup_id: str) -> dict:
        restored = await state.backup_manager.restore(backup_id)
        if restored is None:
            raise HTTPException(status_code=404, detail="Restorable backup not found")
        await state.ws_manager.broadcast({"type": "backup_restored", **restored})
        return {"restored": True, **restored}

    @router.get("/api/events")
    async def list_events(
        agent_id: str | None = None,
        session_id: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict:
        rows = await state.audit_log.list_events(agent_id, session_id, limit)
        events = []
        for row in rows:
            event = dict(row)
            event["args"] = _decode_json(event.pop("args_json"), {})
            event["matched_rules"] = _decode_json(
                event.pop("matched_rules_json"), []
            )
            event["chain_detected"] = any(
                rule.startswith("behavior_chain:")
                for rule in event["matched_rules"]
            )
            events.append(event)
        return {"events": events, "count": len(events)}

    @router.get("/api/dashboard/stats")
    async def dashboard_stats(
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> dict:
        rows = await state.audit_log.list_events(agent_id, session_id)
        stats = _build_dashboard_stats(rows)
        codex_rows = await state.audit_log.list_codex_events(
            session_id=session_id, agent_id=agent_id
        )
        chat_stats = _build_chat_dashboard_stats(codex_rows)
        stats["chat"] = chat_stats
        stats["total_activity"] = stats["total_events"] + chat_stats["total_events"]
        stats["posture_counts"] = {
            "green": stats["lane_counts"]["green"] + chat_stats["posture_counts"]["green"],
            "yellow": stats["lane_counts"]["yellow"] + chat_stats["posture_counts"]["yellow"],
            "red": stats["lane_counts"]["red"] + chat_stats["posture_counts"]["red"],
        }
        stats["combined_risk_level_counts"] = {
            level: stats["risk_level_counts"][level] + chat_stats["risk_level_counts"][level]
            for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        }
        active_containments = await state.containment_store.list_active(
            agent_id, session_id
        )
        stats["active_containments"] = len(active_containments)
        return stats

    return router


def _validate_containment_request(request: ContainmentRequest) -> None:
    if request.scope == "session" and not request.session_id:
        raise HTTPException(
            status_code=422,
            detail="session_id is required when containment scope is session",
        )


def _decode_json(value: str, fallback):
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


def _increment(counter: dict[str, int], key: str) -> None:
    counter[key] = counter.get(key, 0) + 1


def _rule_type(rule: str) -> str:
    if rule.startswith(("intent:", "behavior_chain:", "containment:")):
        return ":".join(rule.split(":", 2)[:2])
    return rule.split(":", 1)[0]


def _build_dashboard_stats(rows: list[dict]) -> dict:
    lane_counts = {lane: 0 for lane in ("green", "yellow", "red")}
    risk_level_counts = {level: 0 for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}
    decision_counts: dict[str, int] = {}
    risk_type_counts: dict[str, int] = {}
    agents: dict[str, dict] = {}
    chain_events = 0
    auto_contained_events = 0

    for row in rows:
        lane = row.get("behavior_lane") or "yellow"
        level = row.get("risk_level") or "LOW"
        _increment(lane_counts, lane)
        _increment(risk_level_counts, level)
        _increment(decision_counts, row.get("decision") or "unknown")

        rules = _decode_json(row.get("matched_rules_json", "[]"), [])
        has_chain = any(rule.startswith("behavior_chain:") for rule in rules)
        chain_events += int(has_chain)
        auto_contained_events += int(row.get("decision") == "denied_auto_contained")
        for rule in rules:
            _increment(risk_type_counts, _rule_type(rule))

        current_agent = row.get("agent_id") or "unknown"
        summary = agents.setdefault(
            current_agent,
            {
                "agent_id": current_agent,
                "total_events": 0,
                "red_events": 0,
                "denied_events": 0,
                "chain_events": 0,
                "risk_score_total": 0,
                "last_seen": row.get("created_at"),
            },
        )
        summary["total_events"] += 1
        summary["red_events"] += int(lane == "red")
        summary["denied_events"] += int(
            str(row.get("decision", "")).startswith("denied")
        )
        summary["chain_events"] += int(has_chain)
        summary["risk_score_total"] += row.get("risk_score") or 0

    agent_summaries = []
    for summary in agents.values():
        score_total = summary.pop("risk_score_total")
        summary["average_risk_score"] = round(score_total / summary["total_events"], 1)
        agent_summaries.append(summary)
    agent_summaries.sort(key=lambda item: (-item["red_events"], -item["average_risk_score"]))

    risk_types = [
        {"type": rule_type, "count": count}
        for rule_type, count in sorted(
            risk_type_counts.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    return {
        "total_events": len(rows),
        "lane_counts": lane_counts,
        "risk_level_counts": risk_level_counts,
        "decision_counts": decision_counts,
        "chain_events": chain_events,
        "auto_contained_events": auto_contained_events,
        "risk_type_counts": risk_types,
        "agents": agent_summaries,
    }


def _build_chat_dashboard_stats(rows: list[dict]) -> dict:
    """Summarize visible conversation messages without double-counting tool telemetry."""
    messages = [
        row for row in rows
        if row.get("event_type") in {"user_prompt", "assistant_response"}
    ]
    event_type_counts = {"user_prompt": 0, "assistant_response": 0}
    action_counts: dict[str, int] = {}
    risk_level_counts = {level: 0 for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}
    posture_counts = {lane: 0 for lane in ("green", "yellow", "red")}

    for row in messages:
        event_type = row.get("event_type") or "unknown"
        action = row.get("action") or "unknown"
        level = row.get("risk_level") or "LOW"
        _increment(event_type_counts, event_type)
        _increment(action_counts, action)
        _increment(risk_level_counts, level)
        posture = "green" if level == "LOW" else "yellow" if level == "MEDIUM" else "red"
        _increment(posture_counts, posture)

    interventions = sum(
        count for action, count in action_counts.items()
        if action in {"deny", "continue"}
    )
    return {
        "total_events": len(messages),
        "event_type_counts": event_type_counts,
        "action_counts": action_counts,
        "risk_level_counts": risk_level_counts,
        "posture_counts": posture_counts,
        "interventions": interventions,
    }

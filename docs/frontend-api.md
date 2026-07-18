# Frontend Integration Guide

This guide explains how the frontend should connect to the Personal Agent Firewall backend.
The product goal is not to ask for approval on every action. The goal is to show whether an agent action is still aligned with the user's stated task.

Default local backend:

```text
http://127.0.0.1:8000
ws://127.0.0.1:8000/ws/alerts
```

If the backend is started on another port, replace `8000` with that port.

## Core Flow

The frontend has five jobs:

1. Send the user's task intent with tool calls when available.
2. Listen for red-lane agent actions over WebSocket.
3. Send an allow/deny decision back to the backend.
4. Render historical activity and aggregate risk statistics by agent.
5. Render containment and restore controls for incident response.

High-level flow:

```text
Agent/tool calls POST /api/tool_call with user_intent
        |
        | green lane: aligned and low risk
        v
Backend executes immediately and returns allowed

Agent/tool calls POST /api/tool_call with user_intent
        |
        | red lane: high risk or off-scope
        v
Backend sends WebSocket new_alert to frontend
        |
        v
Frontend shows review UI
        |
        v
User clicks Allow or Deny
        |
        v
Frontend POSTs /api/decision/{request_id}
        |
        v
Backend sends WebSocket resolved event

Sensitive read followed by external upload
        |
        v
Backend auto-denies and quarantines the session
        |
        v
Frontend shows the evidence chain; no Allow action is offered
```

## Behavior Lanes

The backend returns a `behavior_lane` and `intent_alignment` so the UI can explain *why* an action was allowed or interrupted.

| Lane | Meaning | UI behavior |
| --- | --- | --- |
| `green` | The action appears aligned with the user's task and low risk. | Auto-allow, optionally show in an activity feed. |
| `yellow` | The action is unclear or moderately risky. | Log or show a non-blocking warning. |
| `red` | The action is high-risk, off-scope, or part of a dangerous behavior chain. | Ask for Allow/Deny, or show an automatic containment result when `auto_contained` is true. |

Intent alignment values:

| Value | Meaning |
| --- | --- |
| `aligned` | The action matches the user's stated task area. |
| `uncertain` | The backend cannot clearly match the action to the task. |
| `off_scope` | The action appears outside the stated task or touches sensitive assets. |

## Start Backend Locally

From the repo root:

```bash
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

For faster local testing of timeout behavior:

```bash
DECISION_TIMEOUT_SECONDS=5 python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## REST API

### Tool Call

```http
POST /api/tool_call
Content-Type: application/json
```

Request body:

```json
{
  "tool_name": "write_file",
  "args": {
    "path": "/project/src/components/LoginButton.tsx",
    "content": "export const LoginButton = () => null;"
  },
  "agent_id": "demo-agent",
  "session_id": "demo-session-1",
  "user_intent": "Update the frontend login page button styling"
}
```

Response body:

```json
{
  "status": "allowed",
  "result": "Wrote 38 bytes to /project/src/components/LoginButton.tsx",
  "risk_score": 0,
  "reason": null,
  "behavior_lane": "green",
  "intent_alignment": "aligned",
  "chain_detected": false,
  "containment_action": null,
  "correlated_agent_ids": []
}
```

Response fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `status` | `"allowed"` or `"denied"` | Final backend decision for this tool call. |
| `result` | any or `null` | Tool execution result. Present when allowed and execution succeeds. |
| `risk_score` | number or `null` | Risk score from 0 to 100. |
| `reason` | string or `null` | Denial reason, timeout reason, or blocked-tool reason. |
| `behavior_lane` | `"green"`, `"yellow"`, `"red"`, or `null` | Product-level lane for the action. |
| `intent_alignment` | `"aligned"`, `"uncertain"`, `"off_scope"`, or `null` | Whether the action matches the user's stated task. |
| `chain_detected` | boolean | Whether recent actions in the same session (or a correlated different agent) formed a dangerous sequence. |
| `containment_action` | string or `null` | Automatic or existing containment that affected this call. |
| `correlated_agent_ids` | string array | Other agent identities whose recent denied activity targeted the same file/command as this call. Non-empty means this call was flagged (and, if `auto_contain`d, those other agents were also quarantined at `"agent"` scope) because of a cross-agent pattern, not just this session's own history. |

When `correlated_agent_ids` is non-empty, render it distinctly from a same-session `chain_detected` event -- this is evidence of a *coordinated or replayed* attack across multiple agent identities, not one agent going rogue. Every agent listed there has already been quarantined at `"agent"` scope (all of their sessions, not just the one that triggered this call), so no separate action is needed to contain them.

Important frontend behavior:

- Green-lane calls return quickly.
- Red-lane calls wait until a reviewer decision is submitted.
- If no decision arrives before timeout, the backend denies by default.
- If `user_intent` is omitted, the backend can still assess risk, but alignment becomes `uncertain`.
- High-confidence exfiltration chains are denied automatically and quarantine the session.

### Submit Decision

```http
POST /api/decision/{request_id}
Content-Type: application/json
```

Allow:

```json
{
  "decision": "allow"
}
```

Deny:

```json
{
  "decision": "deny"
}
```

Optional reviewer:

```json
{
  "decision": "allow",
  "reviewer": "andrew"
}
```

Success response:

```json
{
  "ack": true
}
```

If the `request_id` is missing or already gone:

```json
{
  "detail": "No pending decision for this request_id"
}
```

HTTP status: `404`

### Containment Controls

Quarantine an entire agent or one session:

```http
POST /api/containment/quarantine
Content-Type: application/json
```

```json
{
  "scope": "session",
  "agent_id": "demo-agent",
  "session_id": "demo-session-1",
  "reason": "Sensitive read followed by an external upload"
}
```

Use `scope: "agent"` and omit `session_id` to stop every session owned by an agent. If `scope` is `"session"`, `session_id` is required — omitting it returns HTTP `422`.

Success response:

```json
{
  "containment": {
    "scope": "session",
    "agent_id": "demo-agent",
    "session_id": "demo-session-1",
    "reason": "Sensitive read followed by an external upload",
    "active": true,
    "created_at": "2026-07-18T08:07:23.483608+00:00",
    "released_at": null
  }
}
```

A successful call also emits a `containment_changed` WebSocket event with `"action": "quarantined"`.

Release a containment with the same identity fields:

```http
POST /api/containment/release
```

```json
{
  "released": true
}
```

If there is no active containment matching that `scope`/`agent_id`/`session_id`, this returns HTTP `404` with `{"detail": "Active containment not found"}`. A successful release emits a `containment_changed` event with `"action": "released"`.

List active containments. Optional `agent_id` and `session_id` query parameters are supported:

```http
GET /api/containment?agent_id=demo-agent&session_id=demo-session-1
```

```json
{
  "containments": [
    {
      "scope": "session",
      "agent_id": "demo-agent",
      "session_id": "demo-session-1",
      "reason": "Sensitive read followed by an external upload",
      "active": true,
      "created_at": "2026-07-18T08:07:23.483608+00:00",
      "released_at": null
    }
  ],
  "count": 1
}
```

Calls from quarantined identities return `denied` with `risk_score: 100` and do not execute.

### Restore Backup

```http
POST /api/backups/{backup_id}/restore
```

```json
{
  "restored": true,
  "backup_id": "dd5ba1a2-358e-4eca-af88-f971dae5156f",
  "request_id": "52bf4de9-4943-4da9-acfa-ecc1f4c11775",
  "original_path": "/project/src/index.html",
  "restored_at": "2026-07-18T08:30:00+00:00"
}
```

Only backup IDs recorded by the backend can be restored. A successful restore also emits a `backup_restored` WebSocket event.

### Event History

```http
GET /api/events?agent_id=demo-agent&session_id=demo-session-1&limit=100
```

All query parameters are optional. `limit` defaults to `100` and accepts values from `1` to `500`.

Example response:

```json
{
  "events": [
    {
      "request_id": "52bf4de9-4943-4da9-acfa-ecc1f4c11775",
      "agent_id": "demo-agent",
      "session_id": "demo-session-1",
      "tool_name": "write_file",
      "risk_score": 100,
      "risk_level": "CRITICAL",
      "behavior_lane": "red",
      "intent_alignment": "off_scope",
      "user_intent": "Update the frontend login page",
      "decision": "denied",
      "plain_explanation": "The action touches a secret file.",
      "backup_id": null,
      "created_at": "2026-07-18T07:20:00+00:00",
      "args": {"path": "/project/.env"},
      "matched_rules": ["intent:touches_secret"],
      "chain_detected": false
    }
  ],
  "count": 1
}
```

Use this endpoint for the activity feed and agent/session filters.

### Dashboard Statistics

```http
GET /api/dashboard/stats?agent_id=demo-agent&session_id=demo-session-1
```

Both filters are optional. Without filters, the response covers all recorded events.

```json
{
  "total_events": 12,
  "lane_counts": {"green": 8, "yellow": 2, "red": 2},
  "risk_level_counts": {"LOW": 8, "MEDIUM": 2, "HIGH": 1, "CRITICAL": 1},
  "decision_counts": {"allowed": 9, "denied": 2, "denied_auto_contained": 1},
  "chain_events": 1,
  "auto_contained_events": 1,
  "active_containments": 1,
  "risk_type_counts": [
    {"type": "intent:touches_secret", "count": 2},
    {"type": "overwrite_existing_file", "count": 1}
  ],
  "agents": [
    {
      "agent_id": "demo-agent",
      "total_events": 12,
      "red_events": 2,
      "denied_events": 3,
      "chain_events": 1,
      "last_seen": "2026-07-18T07:20:00+00:00",
      "average_risk_score": 31.7
    }
  ]
}
```

Recommended dashboard mapping:

| UI element | API field |
| --- | --- |
| Green/yellow/red counters | `lane_counts` |
| Risk severity chart | `risk_level_counts` |
| Risk category chart | `risk_type_counts` |
| Agent leaderboard or table | `agents` |
| Attack-chain KPI | `chain_events` and `auto_contained_events` |
| Quarantine badge | `active_containments` |
| Recent activity feed | `GET /api/events` |

`decision_counts` keys are the raw `decision` values written to the audit log, not just `"allowed"`/`"denied"` — they also include `allowed_execution_failed`, `denied_quarantined`, and `denied_auto_contained`. Do not hardcode a two-key mapping; sum every key that starts with `"denied"` if you want a single "denied" total, and every key that starts with `"allowed"` for an "allowed" total (this is exactly what `agents[].denied_events` already does server-side for the per-agent breakdown).

## WebSocket API

Connect to:

```text
ws://127.0.0.1:8000/ws/alerts
```

The backend sends four event types:

1. `new_alert`
2. `resolved`
3. `containment_changed`
4. `backup_restored`

### new_alert

Example:

```json
{
  "type": "new_alert",
  "request_id": "52bf4de9-4943-4da9-acfa-ecc1f4c11775",
  "agent_id": "demo-agent",
  "session_id": "demo-session-1",
  "user_intent": "Update the frontend login page",
  "tool_name": "write_file",
  "args_summary": {
    "path": "/tmp/agent_firewall_demo/src/index.html",
    "content": "<html>new</html>"
  },
  "risk_score": 80,
  "risk_level": "HIGH",
  "plain_explanation": "Risk explanation unavailable: no Anthropic API key configured. Please review the raw details below before deciding.",
  "matched_rules": [
    "protected_path_critical:/src/index.html",
    "overwrite_existing_file:/tmp/agent_firewall_demo/src/index.html"
  ],
  "backup_id": "dd5ba1a2-358e-4eca-af88-f971dae5156f",
  "behavior_lane": "red",
  "intent_alignment": "off_scope",
  "chain_detected": false,
  "auto_contained": false,
  "timestamp": "2026-07-18T05:30:42.643443+00:00"
}
```

Frontend should render this as a review card/modal.

When `auto_contained` is `true`, render the event as an incident result rather than a pending approval. Do not show Allow/Deny buttons because the action has already been denied and contained.

An automatically contained attack-chain alert includes:

```json
{
  "chain_detected": true,
  "auto_contained": true,
  "matched_rules": [
    "behavior_chain:sensitive_read_then_external_upload",
    "behavior_chain:source:/project/.env"
  ],
  "containment": {
    "scope": "session",
    "agent_id": "demo-agent",
    "session_id": "demo-session-1",
    "active": true
  }
}
```

Recommended fields to show:

- `tool_name`
- `agent_id`
- `session_id`
- `user_intent`
- `risk_score`
- `risk_level`
- `behavior_lane`
- `intent_alignment`
- `chain_detected`
- `auto_contained`
- `plain_explanation`
- `args_summary.path`, if present
- `matched_rules`
- `backup_id`, if present
- `timestamp`

The important field for actions is:

```json
"request_id": "52bf4de9-4943-4da9-acfa-ecc1f4c11775"
```

Use this value when calling:

```text
POST /api/decision/{request_id}
```

### resolved

Example:

```json
{
  "type": "resolved",
  "request_id": "52bf4de9-4943-4da9-acfa-ecc1f4c11775",
  "agent_id": "demo-agent",
  "session_id": "demo-session-1",
  "decision": "allowed"
}
```

or:

```json
{
  "type": "resolved",
  "request_id": "71a24e1a-7e24-4bea-870f-da532a572abb",
  "agent_id": "demo-agent",
  "session_id": "demo-session-1",
  "decision": "denied"
}
```

Frontend should:

- Mark the matching alert as resolved.
- Disable Allow/Deny buttons for that alert.
- Show final state as allowed or denied.

### containment_changed

Emitted after a manual or automatic quarantine and after a release. Refresh `GET /api/containment` and update the affected agent/session badge.

### backup_restored

Emitted after a successful restore. Mark the matching backup and event as restored.

## Frontend State Shape

Suggested state:

```ts
type AlertStatus = "pending" | "allowed" | "denied";
type BehaviorLane = "green" | "yellow" | "red";
type IntentAlignment = "aligned" | "uncertain" | "off_scope";

type FirewallAlert = {
  request_id: string;
  agent_id: string;
  session_id: string;
  user_intent?: string | null;
  tool_name: string;
  args_summary: Record<string, unknown>;
  risk_score: number;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  behavior_lane: BehaviorLane;
  intent_alignment: IntentAlignment;
  chain_detected: boolean;
  auto_contained?: boolean;
  containment?: Record<string, unknown> | null;
  plain_explanation: string;
  matched_rules: string[];
  backup_id?: string | null;
  timestamp: string;
  status: AlertStatus;
};
```

When `new_alert` arrives:

```ts
setAlerts((alerts) => [
  {
    ...event,
    status: "pending",
  },
  ...alerts,
]);
```

When `resolved` arrives:

```ts
setAlerts((alerts) =>
  alerts.map((alert) =>
    alert.request_id === event.request_id
      ? {
          ...alert,
          status: event.decision === "allowed" ? "allowed" : "denied",
        }
      : alert
  )
);
```

## Frontend Button Handlers

Allow:

```ts
async function allowAction(requestId: string) {
  const response = await fetch(`/api/decision/${requestId}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ decision: "allow" }),
  });

  if (!response.ok) {
    throw new Error("Failed to allow action");
  }

  return response.json();
}
```

Deny:

```ts
async function denyAction(requestId: string) {
  const response = await fetch(`/api/decision/${requestId}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ decision: "deny" }),
  });

  if (!response.ok) {
    throw new Error("Failed to deny action");
  }

  return response.json();
}
```

If the frontend runs on a different origin from the backend, use the full backend URL:

```ts
const API_BASE_URL = "http://127.0.0.1:8000";

await fetch(`${API_BASE_URL}/api/decision/${requestId}`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ decision: "allow" }),
});
```

## WebSocket Client Example

```ts
const socket = new WebSocket("ws://127.0.0.1:8000/ws/alerts");

socket.onopen = () => {
  console.log("Connected to firewall alerts");
};

socket.onmessage = (message) => {
  const event = JSON.parse(message.data);

  if (event.type === "new_alert") {
    // Add pending alert to UI.
    console.log("New alert", event);
    return;
  }

  if (event.type === "resolved") {
    // Mark alert as allowed/denied.
    console.log("Resolved alert", event);
    return;
  }

  if (event.type === "containment_changed") {
    console.log("Containment changed", event);
    return;
  }

  if (event.type === "backup_restored") {
    console.log("Backup restored", event);
    return;
  }
};

socket.onclose = () => {
  console.log("Disconnected from firewall alerts");
};

socket.onerror = (error) => {
  console.error("Firewall WebSocket error", error);
};
```

## Curl Tests

### Low-Risk Call

```bash
curl -sS -X POST http://127.0.0.1:8000/api/tool_call \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "write_file",
    "args": {
      "path": "/tmp/agent_firewall_demo/src/components/LoginButton.tsx",
      "content": "export const LoginButton = () => null;"
    },
    "agent_id": "curl-agent",
    "session_id": "curl-low-risk",
    "user_intent": "Update the frontend login page button styling"
  }'
```

Expected:

```json
{
  "status": "allowed",
  "result": "Wrote 38 bytes to /tmp/agent_firewall_demo/src/components/LoginButton.tsx",
  "risk_score": 0,
  "reason": null,
  "behavior_lane": "green",
  "intent_alignment": "aligned"
}
```

### Blocked Tool

```bash
curl -sS -X POST http://127.0.0.1:8000/api/tool_call \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "rm",
    "args": {"path": "/tmp/anything"},
    "agent_id": "curl-agent",
    "session_id": "curl-blocked-tool"
  }'
```

Expected:

```json
{
  "status": "denied",
  "result": null,
  "risk_score": 100,
  "reason": "Tool is on the blocked list."
}
```

### High-Risk Call With Timeout

```bash
mkdir -p /tmp/agent_firewall_demo/src
printf '<html>old</html>' > /tmp/agent_firewall_demo/src/index.html

curl -sS -X POST http://127.0.0.1:8000/api/tool_call \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "write_file",
    "args": {
      "path": "/tmp/agent_firewall_demo/src/index.html",
      "content": "<html>new</html>"
    },
    "agent_id": "curl-agent",
    "session_id": "curl-high-risk-timeout",
    "user_intent": "Update the frontend login page button styling"
  }'
```

Expected if no reviewer responds before timeout:

```json
{
  "status": "denied",
  "result": null,
  "risk_score": 80,
  "reason": "Decision timed out; denied by default (fail-closed).",
  "behavior_lane": "red",
  "intent_alignment": "aligned"
}
```

The original file should remain unchanged.

### Off-Scope Secret Access

```bash
printf 'SECRET_KEY=old' > /tmp/agent_firewall_demo/.env

curl -sS -X POST http://127.0.0.1:8000/api/tool_call \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "write_file",
    "args": {
      "path": "/tmp/agent_firewall_demo/.env",
      "content": "SECRET_KEY=new"
    },
    "agent_id": "curl-agent",
    "session_id": "curl-off-scope-secret",
    "user_intent": "Update the frontend login page button styling"
  }'
```

Expected if no reviewer responds before timeout:

```json
{
  "status": "denied",
  "result": null,
  "risk_score": 100,
  "reason": "Decision timed out; denied by default (fail-closed).",
  "behavior_lane": "red",
  "intent_alignment": "off_scope"
}
```

## UI Requirements

Minimum UI:

- WebSocket connection indicator.
- List of pending alerts.
- Risk score and risk level.
- Behavior lane.
- Intent alignment.
- Tool name.
- Path or command summary.
- Plain-language explanation.
- Matched rules.
- Allow button.
- Deny button.
- Resolved state.
- Agent/session quarantine and release controls.
- Restore button when `backup_id` is present.
- Behavior-chain evidence for `chain_detected` events.

Recommended UI states:

- `connected`
- `disconnected`
- `reconnecting`
- `pending decision`
- `submitting decision`
- `allowed`
- `denied`
- `decision failed`

## Important Notes

- The frontend does not get `request_id` from the original `/api/tool_call` response.
- The frontend gets `request_id` from the WebSocket `new_alert` event.
- High-risk `/api/tool_call` requests remain pending until allow, deny, or timeout.
- Include `user_intent` whenever possible. This turns the product from a permission popup into an intent-aware behavior firewall.
- If Claude/Anthropic is unavailable, the backend still works. The explanation may say unavailable, but static risk checks still block dangerous actions.
- `backup_id` means a backup was created before the high-risk action was allowed or denied.
- `args_summary` is already redacted by the backend privacy shield.
- The backend currently accepts only `allow` and `deny` as decision values.
- Auto-contained alerts are already resolved and must not submit a reviewer decision.
- Session containment affects only that session; agent containment affects every session for that agent.
- The current intent analyzer is deterministic and local. It is designed for demo reliability, not perfect semantic understanding.

## Tested Behavior

These behaviors were manually verified:

- Intent-aligned frontend edits return `allowed` with `behavior_lane: "green"`.
- Blocked `rm` returns `denied`.
- High-risk overwrite sends `new_alert`.
- Off-scope `.env` access is marked `behavior_lane: "red"` and `intent_alignment: "off_scope"`.
- `allow` executes the tool call and sends `resolved`.
- `deny` prevents execution and sends `resolved`.
- Timeout denies by default.
- Dashboard event history can be filtered by agent and session.
- Dashboard statistics include lane, severity, risk type, and per-agent counts.
- Sensitive-read-to-external-upload chains are automatically blocked before execution.
- Auto-contained sessions reject later calls until released.
- Automatic backups can be restored through the API.
- Off-scope intent alone (e.g. a frontend-scoped task editing a backend file with no other static risk signal) forces a hold even when the target is not in `protected_paths.json`.
- Test suite passes with `105 passed`.

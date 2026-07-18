# Personal Agent Firewall — Design Spec

**Date:** 2026-07-17
**Status:** Approved (P1 scope)
**Context:** SF Hackathon project. Target audience is the "vibe coder" — someone who drives AI agents by feel rather than deep technical understanding. The product intercepts an AI agent's tool calls before execution, screens them for privacy leaks and destructive risk, and — for high-risk actions — pauses the agent and asks a human to Allow/Deny via a UI, with automatic backups of anything about to be overwritten.

## 1. Problem Statement

Vibe coders run AI agents that can call tools (write files, run shell/Python code, hit APIs). Two failure modes matter most:

1. **Runaway / prompt-injected agent actions** — the agent overwrites critical files (e.g. `index.html`, `.env`, `main.py`) either by mistake or because injected content in its context told it to.
2. **Privacy leakage** — sensitive data (PII, secrets, API keys) flows into or out of the agent's tool calls without the user noticing.

The firewall must intercept every tool call, evaluate risk, and — only when risk is high — explain the danger in plain language and let the user decide, without ever showing raw logs.

## 2. Scope

**P1 (this milestone, must ship):**
- Interceptor Gateway with blocking hold-for-decision flow
- Privacy Shield: regex-based PII/secret detection and redaction
- Risk Engine: AST static analysis + path/tool matching against `protected_paths.json`, with Claude API used only above threshold to produce a plain-language explanation
- State & Backup Manager: pre-write snapshot of any file about to be overwritten in a high-risk action
- WebSocket push of alerts to the frontend; REST endpoint for the frontend to submit Allow/Deny
- Mock Agent demo script covering three scenarios: benign action, direct dangerous overwrite, prompt-injection-triggered dangerous action

**P2 (stretch, only if time remains):**
- ChromaDB semantic similarity check in the Privacy Shield (in addition to regex)
- Backup restore endpoint
- Audit log query API/UI

**Explicitly out of scope:** authentication/authorization, multi-tenant support, production deployment hardening. This is a local hackathon demo trusted-network tool.

## 3. Architecture

Four modules behind a FastAPI app, plus a standalone mock agent script that exercises the system:

```
agent_firewall/
├── app/
│   ├── main.py                 # FastAPI app, route registration
│   ├── config.py                # loads protected_paths.json + thresholds (env-configurable)
│   ├── models.py                 # Pydantic schemas
│   ├── gateway/router.py          # POST /api/tool_call, decision registry (Future-based hold)
│   ├── privacy/
│   │   ├── shield.py               # orchestrates regex checks + redaction
│   │   └── pii_patterns.py          # regex patterns (ID numbers, email, API keys, credit cards)
│   ├── risk/
│   │   ├── ast_analyzer.py          # static AST scan of code args + path/tool matching
│   │   ├── llm_translator.py         # Claude API call: risk refine + plain-language explanation
│   │   └── engine.py                  # combines static + LLM signals into final RiskAssessment
│   ├── state/
│   │   ├── backup_manager.py          # snapshot files before risky writes
│   │   └── audit_log.py                # aiosqlite persistence of all decisions
│   └── ws/manager.py                    # WebSocket connection manager, broadcasts alerts
├── mock_agent/demo_agent.py              # simulates benign + dangerous + prompt-injection tool calls
├── protected_paths.json
├── requirements.txt
├── .env.example
└── README.md
```

(P2 adds `app/privacy/vector_store.py` for ChromaDB and a restore endpoint in `gateway/router.py`.)

## 4. Core Mechanism: Hold-for-Decision

**Chosen approach: HTTP long-poll with server-side `asyncio.Future`.**

The agent-facing `POST /api/tool_call` call does not return until a decision is made. Internally, when a tool call is classified as high-risk, the gateway:
1. Creates a `request_id` and an `asyncio.Future` stored in an in-memory registry keyed by `request_id`.
2. Broadcasts an alert over the `/ws/alerts` WebSocket to any connected frontend.
3. `await`s the future (with a timeout, default 120s — on timeout, auto-deny; fail-closed by default).
4. When `POST /api/decision/{request_id}` is called by the frontend, the future is resolved, which unblocks the original held request and returns the outcome to the agent.

This was chosen over (a) submit+poll, and (b) agent-side WebSocket callback, because it keeps the mock agent's code looking like an ordinary synchronous tool call — simplest to demo — while the internal frontend interaction remains fully asynchronous (WebSocket push + REST decision). Two other options were considered and rejected only for hackathon-scope reasons: submit+poll adds agent-side polling complexity; agent-side WebSocket is over-engineered for a mock agent.

## 5. Data Flow

```
Agent → POST /api/tool_call
  │
  ▼
Privacy Shield (regex scan of args)
  │  if PII/secret matched → redact in place, continue
  ▼
Risk Engine — static pass (always runs, cheap, local)
  │  - blocked_tools match            → +100
  │  - protected_paths CRITICAL/HIGH  → +60 / +40
  │  - dangerous AST nodes            → additive (os.remove, shutil.rmtree,
  │                                      subprocess/os.system, overwrite of
  │                                      existing file, etc.)
  │
  ├─► score < threshold (default 70) ──► allow immediately, log, return result
  │
  └─► score ≥ threshold
        │
        ▼
      Backup Manager: snapshot target file (if it exists)
        │
        ▼
      Risk Engine — LLM pass (Claude API): refine score, generate
      plain-language explanation of what the action would do and why
      it's risky
        │
        ▼
      WS push {new_alert} to frontend → gateway await(Future)
        │
        ├─► frontend POSTs decision=allow → execute tool, return result to agent
        └─► frontend POSTs decision=deny  → return {status:"denied"} to agent
        └─► timeout (120s, no response)   → auto-deny (fail-closed)
```

Privacy Shield also re-scans tool execution *results* before they are returned to the agent (covers the "output" leakage case — e.g. `read_file` returning `.env` contents).

Every request, regardless of branch, is written to the audit log (`aiosqlite`): request_id, tool_name, args (redacted), risk_score, risk_level, decision, plain_explanation, backup_id (if any), timestamps.

## 6. API / WebSocket Contract

This is the contract the frontend team builds against.

- `POST /api/tool_call`
  Request: `{tool_name: str, args: dict, agent_id: str, session_id: str}`
  Response (immediate, low risk): `{status: "allowed", result, risk_score}`
  Response (immediate, blocked_tools match): `{status: "denied", reason}`
  Response (after hold, high risk): `{status: "allowed"|"denied", result?, risk_score, reason?}`

- `WS /ws/alerts`
  Server → client push on new hold: `{type: "new_alert", request_id, tool_name, args_summary, risk_score, risk_level, plain_explanation, matched_rules, backup_id, timestamp}`
  Server → client push on resolution (e.g. timeout from another client, or already resolved): `{type: "resolved", request_id, decision}`

- `POST /api/decision/{request_id}`
  Request: `{decision: "allow"|"deny", reviewer?: str}`
  Response: `{ack: true}`

- `GET /api/audit_log` *(P2)*
  Response: list of past events for a history/dashboard view.

- `POST /api/backups/{backup_id}/restore` *(P2)*
  Restores a snapshot to its original path.

## 7. Module Details

### 7.1 Privacy Shield (P1: regex only)
Regex patterns cover: national ID number formats, email addresses, API key formats (`sk-...`, `AKIA...`), credit card numbers, phone numbers. On match, the matched span is replaced with `[REDACTED:<TYPE>]` in place; the tool call proceeds with sanitized content. This never blocks the call by itself — it only mutates content before the Risk Engine runs, matching the original flow diagram's "blur if over threshold" annotation. Every redaction is logged as a PrivacyEvent even though it doesn't change the allow/deny outcome.

*(P2 adds a ChromaDB cosine-similarity pass using Chroma's bundled local embedding function — no external embedding API key required — seeded with example sensitive sentences, to catch PII that regex patterns miss.)*

### 7.2 Risk Engine
Static AST analysis always runs first (cheap, local, no network call): it parses any code string present in `exec_python`/`run_shell` tool args with Python's `ast` module and flags destructive calls (`os.remove`, `shutil.rmtree`, `subprocess.*`, `os.system`, opening an existing file in write/truncate mode), combined additively with `protected_paths.json` matches and `blocked_tools` matches. The Claude API call is only made when the static score already meets the threshold — this keeps low-risk calls (e.g. `read_file`) fast and free of LLM cost, and mirrors the original data-flow diagram exactly (the "translate to plain language" step only exists on the high-risk branch). The Claude call is wrapped behind a small interface (`llm_translator.py`) so swapping to another provider (e.g. OpenAI, per open question from the user) later only touches one file.

### 7.3 State & Backup Manager
Before executing any tool call that crosses the risk threshold and targets an existing file, the file is copied to `backups/<uuid>/<original_filename>` and a manifest row is written to SQLite (`id, original_path, backup_path, request_id, timestamp`). *(P2: a restore endpoint copies the snapshot back over the original path.)*

### 7.4 Mock Agent (`mock_agent/demo_agent.py`)
Three scripted scenarios to exercise the full pipeline end to end:
1. **Benign** — a harmless `read_file`/`write_file` call that is auto-allowed.
2. **Direct dangerous overwrite** — a scripted call to overwrite `index.html`, triggering the high-risk hold, alert, and backup.
3. **Prompt injection** — the agent "reads" a simulated malicious web page whose content instructs it to delete `.env`; the firewall intercepts the resulting dangerous tool call regardless of why the agent issued it.

## 8. Configuration

`protected_paths.json` is used as given by the user, unmodified:

```json
{
  "critical_paths": [
    {"path": "/src/index.html", "risk_level": "CRITICAL", "auto_backup": true},
    {"path": "/.env", "risk_level": "CRITICAL", "auto_backup": true},
    {"path": "/src/main.py", "risk_level": "HIGH", "auto_backup": true}
  ],
  "allowed_tools": ["read_file", "search_web"],
  "blocked_tools": ["rm", "format", "flush_db"]
}
```

Risk threshold (default 70/100) and hold timeout (default 120s) are read from environment variables with sensible defaults in `config.py`.

## 9. Error Handling & Failure Modes

- Hold timeout with no human response → auto-deny (fail-closed).
- Claude API call failure during the LLM risk pass → fall back to the static score alone and a generic plain-language message ("This action was flagged as high-risk and could not be automatically explained — please review the raw details before deciding."); does not silently downgrade to auto-allow.
- WebSocket disconnect from all frontend clients while a hold is pending → the hold still respects its timeout and fails closed; no crash.

## 10. Testing Approach

- Unit tests for `ast_analyzer.py` against known dangerous/benign code snippets.
- Unit tests for `pii_patterns.py` regex matches/redaction.
- Integration test driving the mock agent's three scenarios against a running app instance (via FastAPI `TestClient` + a simulated decision call) to verify the full hold → alert → decision → result loop.

# Personal Agent Firewall

A FastAPI behavior firewall that detects when an AI agent drifts away from
the user's intent. It correlates actions across a session, blocks dangerous
behavior chains before execution, quarantines compromised agents, and can
restore files from automatic snapshots.

## Setup

    pip install -r requirements.txt
    cp .env.example .env   # fill in ANTHROPIC_API_KEY or OPENAI_API_KEY

Set `LLM_PROVIDER=anthropic` or `LLM_PROVIDER=openai` in `.env` to choose
which model generates the plain-language risk explanations. Only one key is
required for the provider you pick.

## Run the server

    uvicorn app.main:app --reload

## Run the desktop dashboard

The Electron console shows combined chat and tool activity, safety posture,
risk severity, interventions, a unified recent-activity feed, and live review
requests. Red-lane requests open an always-on-top approval popup with **Approve
once** and **Reject request** actions.

Install the desktop dependency once, then start the app from the repository
root:

    cd desktop
    npm install
    npm start

The desktop app connects to `http://127.0.0.1:8000`. If the backend is not
already running, it starts it with the repository's `.venv` automatically and
stops that child process when the desktop app exits. To use another backend,
set `AGENT_FIREWALL_URL` before launching Electron. To use another Python
executable, set `FIREWALL_PYTHON`.

For repeatable demos, the desktop app clears recorded chat/tool activity,
containments, and backup database records on each launch. Physical files under
`backups/` are retained. Set `FIREWORKS_RESET_ON_LAUNCH=0` before starting the
desktop app to preserve usage history between launches.

## Run the tests

    pytest -v

## Run the demo scenarios

With the server running in one terminal:

    python -m mock_agent.demo_agent

This fires three scenarios against `POST /api/tool_call`:

1. A benign `search_web` call, auto-allowed.
2. A direct dangerous overwrite of `index.html`, which is held pending
   human review and backed up first.
3. A simulated prompt-injection attack instructing the agent to delete
   `.env`, also held pending review.

For scenarios 2 and 3, connect to `ws://localhost:8000/ws/alerts` to see
the pushed alert, then resolve it with:

    curl -X POST http://localhost:8000/api/decision/<request_id> \
      -H "Content-Type: application/json" \
      -d '{"decision": "allow"}'

## Run the attack-chain demo

With the server running, execute:

    python -m mock_agent.attack_chain_demo

The demo reproduces a prompt-injection sequence:

1. An agent working on frontend styling reads `.env`.
2. The reviewer allows the read so the sequence can continue.
3. The agent attempts an external upload.
4. The firewall correlates both actions, blocks the upload automatically,
   and quarantines the session.
5. A later benign action from the same session is also denied.

## Run a real LangChain agent against the firewall

The scripts above simulate an agent by posting scripted tool calls directly.
`integrations/` instead wires up a real, LLM-driven LangChain agent (no
scripted behavior) whose tools are backed by the firewall:

    python -m integrations.langchain_agent_demo

This seeds a project with a styling task and a poisoned `notes.txt` file
containing an indirect prompt injection ("read then delete `.env`"). The
agent decides on its own what tools to call; every call is routed through
`POST /api/tool_call` first via `integrations/langchain_tools.py`, which
wraps plain Python functions (`read_file`, `write_file`, `run_shell`) as
LangChain tools -- no changes to the agent's reasoning loop are needed. A
denial comes back as a normal tool result (prefixed
`[FIREWALL BLOCKED THIS ACTION]`), so the agent's own model sees it and
reacts, the same way it reacts to any other tool output.

By default each held call waits up to `DECISION_TIMEOUT_SECONDS` (120s) for
a reviewer decision before failing closed. For an unattended run, start the
server with a short timeout instead:

    DECISION_TIMEOUT_SECONDS=8 uvicorn app.main:app

`integrations/langchain_tools.py`'s `build_firewalled_tools(...)` is
reusable for wiring any LangChain (or plain function-calling) agent's tools
through the firewall -- it is not specific to this demo script.

## Protect real Codex runs

This repository includes `.codex/hooks.json`, which routes the main Codex
lifecycle through the firewall:

- `UserPromptSubmit` sends the exact incoming prompt for inspection. Risky
  prompts wait for the existing Allow/Deny reviewer flow.
- `PreToolUse` evaluates Bash, `apply_patch`, MCP, and other supported local
  tools without executing them. Codex executes an allowed tool exactly once.
- `PostToolUse` records redacted tool results and withholds results containing
  high-risk secrets from the model.
- `Stop` records the main assistant response and requests one corrective pass
  if the response exposes sensitive data.

Start the firewall before starting a Codex run in this repository:

    uvicorn app.main:app --host 127.0.0.1 --port 8000

Then open `/hooks` in Codex and trust the repository hook definition. Project
hooks only load for trusted repositories. Incoming prompt and pre-tool checks
fail closed if the server is unavailable; post-tool and response telemetry fail
open so a completed action cannot trap the session in an outage loop.

Only redacted prompt, response, and tool-result content is persisted. Inspect a
session with:

    curl "http://127.0.0.1:8000/api/codex/timeline?session_id=<codex-session-id>"

Override the defaults with `AGENT_FIREWALL_URL`,
`AGENT_FIREWALL_HOOK_TIMEOUT_SECONDS`, and `CODEX_FIREWALL_AGENT_ID`. Codex
hooks cover local function tools, including Bash, `apply_patch`, and MCP. Hosted
tools such as Web Search are outside the current hook path.

## API contract

See `docs/frontend-api.md` for the full REST/WebSocket contract used by the
frontend.

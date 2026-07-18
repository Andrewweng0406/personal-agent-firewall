# Personal Agent Firewall

A FastAPI backend that intercepts AI agent tool calls, screens them for
privacy leaks and destructive risk, and holds high-risk actions for a
human Allow/Deny decision before they execute.

## Setup

    pip install -r requirements.txt
    cp .env.example .env   # fill in ANTHROPIC_API_KEY

## Run the server

    uvicorn app.main:app --reload

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

## API contract

See `docs/superpowers/specs/2026-07-17-personal-agent-firewall-design.md`
section 6 for the full REST/WebSocket contract used by the frontend.

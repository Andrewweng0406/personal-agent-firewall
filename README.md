# Personal Agent Firewall

A FastAPI behavior firewall that detects when an AI agent drifts away from
the user's intent. It correlates actions across a session, blocks dangerous
behavior chains before execution, quarantines compromised agents, and can
restore files from automatic snapshots.

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

## API contract

See `docs/frontend-api.md` for the full REST/WebSocket contract used by the
frontend.

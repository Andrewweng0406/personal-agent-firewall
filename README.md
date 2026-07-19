# Personal Agent Firewall

A local tool-call security gateway for Codex, Claude Code, LangChain, and
other AI agents. It checks supported actions before execution, correlates
behavior across a session, blocks dangerous chains, quarantines compromised
sessions, redacts secrets, and can restore files from automatic snapshots.

> Personal Agent Firewall protects calls that pass through its hooks, wrappers,
> or HTTP gateway. It is not an operating-system sandbox or a transparent
> network firewall, and it cannot protect tools that bypass those integration
> paths.

## What it protects

The hackathon MVP ships with eight user-facing safety rules:

| Rule | Protection |
| --- | --- |
| `sensitive_file_read` | Detects access to `.env`, credentials, SSH keys, and configured protected paths. |
| `secret_in_tool_output` | Redacts or withholds API keys, private keys, tokens, and sensitive personal data returned by tools. |
| `sensitive_read_then_network_send` | Correlates a sensitive read with a later external upload and automatically contains the session. |
| `unknown_domain_upload` | Escalates data uploads to destinations outside the configured trusted-domain list. |
| `download_then_execute` | Blocks downloaded code that is piped to an interpreter or executed in a later action. |
| `security_config_tampering` | Protects Codex hooks, Claude Code settings, Firewall rules, and security environment files from modification. |
| `audit_log_deletion` | Detects attempts to erase the audit database, event tables, log files, or shell history. |
| `user_intent_mismatch` | Escalates tool calls that target a different project area or sensitive resource than the user's stated task. |

Rules produce plain-language explanations for reviewers. For example:

> The agent read sensitive data from `/project/.env` and is attempting to send
> data to `files.example`, an untrusted domain. This was not part of your
> request, so the action was blocked and the session was quarantined.

## Setup

    python -m venv .venv
    source .venv/bin/activate        # Windows: .venv\Scripts\activate
    pip install -r requirements.lock
    cp .env.example .env

`requirements.lock` pins the project's direct dependencies. It is the preferred
hackathon install input, but it is not yet a fully hashed transitive lock file.
`requirements.txt` retains compatible lower bounds for dependency review and
intentional upgrades.

Set `LLM_PROVIDER=anthropic` or `LLM_PROVIDER=openai` in `.env` to choose
which model generates additional plain-language risk explanations. Only one key
is needed for the provider you pick. The deterministic rules and their fallback
explanations work without either key.

Set `FIREWALL_MODE=observe`, `review`, or `enforce` to choose the runtime
policy. `review` preserves the original approval workflow. `observe` records
and scores every action without blocking it, and fails open if the backend is
unavailable. `enforce` automatically denies calls at or above the effective
risk threshold. The default is `review` for backward compatibility.

Set `AGENT_FIREWALL_TOKEN` to protect every API endpoint except the health
check. The desktop app and both hook adapters read the same environment
variable and attach it automatically. Generate a long random value, keep it
out of source control, and set the same value for separately launched backend
and agent processes. Authentication remains disabled when the variable is
unset for backward-compatible local development. Do not expose an unauthenticated
instance to a LAN, public interface, or the internet.

Configure upload destinations in `protected_paths.json`:

    "trusted_domains": ["github.com", "api.github.com", "localhost", "127.0.0.1"]

An exact domain or its subdomains are trusted. For example, trusting
`github.com` also trusts `uploads.github.com`; it does not trust
`github.com.attacker.example`. Uploads to every other detected domain trigger
`unknown_domain_upload` review.

Regex and structured-field privacy redaction are always active. Optional
embedding-based semantic PII detection is disabled by default so startup is
fast, offline, and does not download a model unexpectedly. Set
`SEMANTIC_PII_ENABLED=1` to initialize it in the background; `/api/health`
reports `disabled`, `initializing`, `ready`, or `unavailable`.

## Run the server

    uvicorn app.main:app --host 127.0.0.1 --port 8000

After pulling code or changing `.env`/`protected_paths.json`, restart the
backend process. A running Python process does not automatically load new rules
unless it was explicitly started with development reload enabled.

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

The desktop app preserves recorded activity by default. For a repeatable demo,
set `FIREWALL_RESET_ON_LAUNCH=1` before starting it. This clears recorded
chat/tool activity, containments, and backup database records while retaining
physical files under `backups/`.

## Run the tests

    pytest -v

The current suite contains 219 regular tests plus 2 loopback Hook E2E tests.
The E2E tests bind a temporary `127.0.0.1` port and may require local-network
permission in a restricted sandbox.

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

- `UserPromptSubmit` inspects prompts for secrets, personal data, and known
  instruction-override markers. Matching prompts wait for the existing
  Allow/Deny reviewer flow. Behavioral requests such as “read `.env` and
  upload it” are ultimately enforced again at `PreToolUse` when the agent
  attempts the actual tools.
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

## Protect real Claude Code runs

This repository also includes `.claude/settings.json`, which sends Claude
Code lifecycle events through the same firewall backend:

- `UserPromptSubmit` evaluates and records the incoming prompt.
- `PreToolUse` evaluates Bash, Read, Write, Edit, MCP, and other tool calls
  before Claude Code executes them.
- `PostToolUse` records redacted successful tool results.
- `PostToolUseFailure` records failed tool calls without blocking recovery.
- `Stop` checks the final assistant response for sensitive data.

Start the firewall before opening Claude Code in this repository:

    uvicorn app.main:app --host 127.0.0.1 --port 8000
    claude

Claude Code loads project hooks from `.claude/settings.json`. Review and trust
the project configuration when prompted. The adapter uses
`${CLAUDE_PROJECT_DIR}` so it continues to work when Claude Code is launched
from a nested directory.

Incoming prompts and pre-tool checks fail closed if the backend is unavailable;
post-tool, failure, and response telemetry fail open. Tool calls are evaluated
with `execute: false`, so the firewall never executes a Claude Code tool itself.
Claude Code remains the only executor after an allowed preflight check.

Override the defaults with `AGENT_FIREWALL_URL`,
`AGENT_FIREWALL_HOOK_TIMEOUT_SECONDS`, and
`CLAUDE_CODE_FIREWALL_AGENT_ID`. Claude Code events currently reuse the
existing Codex event storage/API with a distinct `agent_id`; a future unified
event schema can migrate both sources without changing the hook contract.

Both hook adapters bound outbound events to 1 MiB and individual strings to
64 KiB by default. Oversized values retain their beginning and end, while the
event records its original byte size and SHA-256 digest. Override these limits
with `AGENT_FIREWALL_MAX_EVENT_BYTES` and
`AGENT_FIREWALL_MAX_STRING_BYTES`.

## Install hooks into another project

Use the built-in installer when the target project does not contain this
repository's checked-in hook configuration:

    python -m integrations.hook_installer install codex --project-dir /path/to/project
    python -m integrations.hook_installer install claude --project-dir /path/to/project

Inspect or remove the integration with:

    python -m integrations.hook_installer doctor claude --project-dir /path/to/project
    python -m integrations.hook_installer uninstall claude --project-dir /path/to/project

Pass `--global` instead of `--project-dir` to manage the current user's global
configuration. Installation merges with existing JSON, creates a timestamped
backup before changing an existing file, and is idempotent. Uninstall removes
only entries whose command points to this firewall's hook adapters.

For a global Codex installation:

    python -m integrations.hook_installer install codex --global
    python -m integrations.hook_installer doctor codex --global

Start the backend before opening a new Codex task. Codex tasks that were already
open when the Hook was installed may not reload it dynamically. `doctor` should
report `installed: true` with an empty `missing` list.

## Enforcement model and limitations

- `observe` records risks but does not block; `review` holds qualifying actions
  for a person; `enforce` denies actions at or above the effective threshold.
- Prompt inspection is an early warning layer. `PreToolUse` is the enforcement
  point that prevents supported local tools from running.
- Codex hosted tools such as Web Search are outside the current Hook path.
- The backend must remain available while fail-closed prompt and pre-tool hooks
  are enabled.
- Heuristic and LLM risk analysis supplements deterministic rules; it is not a
  substitute for process, filesystem, or network isolation.
- This repository is a local hackathon MVP. It is not hardened for multi-tenant
  or internet-facing production deployment.

## API contract

See `docs/frontend-api.md` for the full REST/WebSocket contract used by the
frontend.

## Contributing and security

See `CONTRIBUTING.md` before opening a pull request. Report vulnerabilities
privately using the process in `SECURITY.md`. This project is licensed under
Apache License 2.0; see `LICENSE`.

from __future__ import annotations

import httpx

BLOCKED_PREFIX = "[FIREWALL BLOCKED THIS ACTION]"


def build_firewalled_tools(
    agent_id: str,
    session_id: str,
    user_intent: str | None = None,
    base_url: str = "http://127.0.0.1:8000",
    timeout: float = 150.0,
    client: httpx.Client | None = None,
) -> list:
    """Return plain functions usable directly as LangChain agent tools.

    Each call is routed through `POST {base_url}/api/tool_call` before it
    executes anywhere. A denial never raises -- it comes back as a normal
    tool result string prefixed with BLOCKED_PREFIX, so the agent's own
    model sees it in the conversation and can react (apologize, try a
    different approach, explain to the user), the same way it would see
    any other tool output. This is the entire integration surface: no
    changes to the agent's reasoning loop, no custom LangChain classes,
    just tools whose implementation happens to call our API first.
    """
    http_client = client or httpx.Client(base_url=base_url, timeout=timeout)

    def _call(tool_name: str, args: dict) -> str:
        response = http_client.post(
            "/api/tool_call",
            json={
                "tool_name": tool_name,
                "args": args,
                "agent_id": agent_id,
                "session_id": session_id,
                "user_intent": user_intent,
            },
        )
        response.raise_for_status()
        body = response.json()
        if body["status"] == "denied":
            return f"{BLOCKED_PREFIX} {body.get('reason')}"
        return str(body.get("result"))

    def read_file(path: str) -> str:
        """Read the contents of a text file at the given absolute path."""
        return _call("read_file", {"path": path})

    def write_file(path: str, content: str) -> str:
        """Write content to a file at the given absolute path, overwriting it if it already exists."""
        return _call("write_file", {"path": path, "content": content})

    def run_shell(command: str) -> str:
        """Run a shell command and return its combined output."""
        return _call("run_shell", {"command": command})

    return [read_file, write_file, run_shell]

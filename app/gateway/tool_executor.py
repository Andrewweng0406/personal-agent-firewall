from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Callable


class ToolExecutionError(Exception):
    pass


def read_file(args: dict) -> Any:
    path = Path(args["path"])
    if not path.exists():
        raise ToolExecutionError(f"File not found: {path}")
    return path.read_text(encoding="utf-8")


def write_file(args: dict) -> Any:
    path = Path(args["path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    content = args.get("content", "")
    path.write_text(content, encoding="utf-8")
    return f"Wrote {len(content)} bytes to {path}"


def exec_python(args: dict) -> Any:
    code = args.get("code", "")
    local_scope: dict[str, Any] = {}
    try:
        exec(compile(code, "<agent_exec_python>", "exec"), {}, local_scope)
    except Exception as exc:
        raise ToolExecutionError(f"exec_python failed: {exc}") from exc
    return local_scope.get("result", "executed")


def run_shell(args: dict) -> Any:
    command = args.get("command", "")
    completed = subprocess.run(
        command, shell=True, capture_output=True, text=True, timeout=10
    )
    if completed.returncode != 0:
        raise ToolExecutionError(completed.stderr.strip())
    return completed.stdout.strip()


def search_web(args: dict) -> Any:
    return f"[mock search result for: {args.get('query', '')}]"


TOOL_REGISTRY: dict[str, Callable[[dict], Any]] = {
    "read_file": read_file,
    "write_file": write_file,
    "overwrite_file": write_file,
    "exec_python": exec_python,
    "run_shell": run_shell,
    "search_web": search_web,
}


def execute(tool_name: str, args: dict) -> Any:
    handler = TOOL_REGISTRY.get(tool_name)
    if handler is None:
        raise ToolExecutionError(f"Unknown tool: {tool_name}")
    return handler(args)

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


EVENTS = (
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
)


def config_path(agent: str, scope: str, project_dir: Path | None = None) -> Path:
    if scope == "global":
        return Path.home() / (".codex/hooks.json" if agent == "codex" else ".claude/settings.json")
    root = (project_dir or Path.cwd()).resolve()
    return root / (".codex/hooks.json" if agent == "codex" else ".claude/settings.json")


def install(agent: str, path: Path) -> dict[str, Any]:
    data = _load(path)
    hooks = data.setdefault("hooks", {})
    command = _hook_command(agent)
    added: list[str] = []

    for event in _events_for(agent):
        entries = hooks.setdefault(event, [])
        if _contains_command(entries, command):
            continue
        entry: dict[str, Any] = {
            "hooks": [{"type": "command", "command": command, "timeout": 180}]
        }
        if event in {"PreToolUse", "PostToolUse", "PostToolUseFailure"}:
            entry["matcher"] = ".*" if agent == "claude" else "*"
        entries.append(entry)
        added.append(event)

    backup = _write_if_changed(path, data, changed=bool(added))
    return {"path": str(path), "added": added, "backup": str(backup) if backup else None}


def uninstall(agent: str, path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "removed": [], "backup": None}
    data = _load(path)
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return {"path": str(path), "removed": [], "backup": None}

    marker = f"integrations/{'codex_hook.py' if agent == 'codex' else 'claude_code_hook.py'}"
    windows_marker = marker.replace("/", "\\")
    removed: list[str] = []
    for event, entries in list(hooks.items()):
        if not isinstance(entries, list):
            continue
        kept = [entry for entry in entries if not _entry_contains_marker(entry, marker, windows_marker)]
        if len(kept) != len(entries):
            removed.append(event)
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event, None)

    backup = _write_if_changed(path, data, changed=bool(removed))
    return {"path": str(path), "removed": removed, "backup": str(backup) if backup else None}


def doctor(agent: str, path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"agent": agent, "path": str(path), "installed": False, "missing": list(_events_for(agent))}
    try:
        data = _load(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"agent": agent, "path": str(path), "installed": False, "error": str(exc)}
    hooks = data.get("hooks") if isinstance(data, dict) else None
    command = _hook_command(agent)
    missing = [
        event
        for event in _events_for(agent)
        if not isinstance(hooks, dict) or not _contains_command(hooks.get(event, []), command)
    ]
    return {
        "agent": agent,
        "path": str(path),
        "installed": not missing,
        "missing": missing,
    }


def _events_for(agent: str) -> tuple[str, ...]:
    # Codex does not expose PostToolUseFailure as a separate lifecycle event.
    return tuple(event for event in EVENTS if agent == "claude" or event != "PostToolUseFailure")


def _hook_command(agent: str) -> str:
    script = Path(__file__).resolve().with_name(
        "codex_hook.py" if agent == "codex" else "claude_code_hook.py"
    )
    return f'python3 "{script}"'


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Hook config must contain a JSON object: {path}")
    return value


def _contains_command(entries: Any, command: str) -> bool:
    if not isinstance(entries, list):
        return False
    return any(_entry_commands(entry).count(command) > 0 for entry in entries)


def _entry_commands(entry: Any) -> list[str]:
    if not isinstance(entry, dict):
        return []
    hooks = entry.get("hooks")
    if not isinstance(hooks, list):
        return []
    return [
        hook.get("command")
        for hook in hooks
        if isinstance(hook, dict) and isinstance(hook.get("command"), str)
    ]


def _entry_contains_marker(entry: Any, *markers: str) -> bool:
    return any(marker in command for command in _entry_commands(entry) for marker in markers)


def _write_if_changed(path: Path, data: dict[str, Any], changed: bool) -> Path | None:
    if not changed:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if path.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = path.with_name(f"{path.name}.bak.{stamp}")
        suffix = 1
        while backup.exists():
            backup = path.with_name(f"{path.name}.bak.{stamp}.{suffix}")
            suffix += 1
        shutil.copy2(path, backup)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return backup


def main() -> None:
    parser = argparse.ArgumentParser(description="Install or inspect Personal Agent Firewall hooks")
    parser.add_argument("action", choices=("install", "uninstall", "doctor"))
    parser.add_argument("agent", choices=("codex", "claude"))
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--global", dest="global_scope", action="store_true")
    scope.add_argument("--project", action="store_true")
    parser.add_argument("--project-dir", type=Path)
    args = parser.parse_args()

    selected_scope = "global" if args.global_scope else "project"
    path = config_path(args.agent, selected_scope, args.project_dir)
    operation = {"install": install, "uninstall": uninstall, "doctor": doctor}[args.action]
    result = operation(args.agent, path)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

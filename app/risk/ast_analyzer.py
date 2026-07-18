from __future__ import annotations

import ast
import os

from app.config import Settings

CODE_ARG_TOOLS = {"exec_python", "run_shell"}
WRITE_TOOLS = {"write_file", "overwrite_file"}

DANGEROUS_CALL_NAMES: dict[str, int] = {
    "remove": 30,
    "rmtree": 40,
    "rmdir": 30,
    "unlink": 30,
    "system": 35,
    "run": 20,
    "Popen": 25,
}

SHELL_DANGEROUS_PATTERNS: dict[str, int] = {
    "rm -rf": 50,
    "rm -r": 40,
    " rm ": 30,
    "mkfs": 60,
    "dd if=": 40,
    "> /dev/": 30,
    ":(){:|:&};:": 100,
}

PATH_RISK_WEIGHTS = {"CRITICAL": 60, "HIGH": 40}


def _score_protected_paths_in_text(text: str, settings: Settings) -> tuple[int, list[str]]:
    score = 0
    matched: list[str] = []
    for entry in settings.critical_paths:
        if entry.path and entry.path in text:
            weight = PATH_RISK_WEIGHTS.get(entry.risk_level, 20)
            score += weight
            matched.append(f"protected_path_{entry.risk_level.lower()}:{entry.path}")
    return score, matched


def _score_python_code(code: str) -> tuple[int, list[str]]:
    score = 0
    matched: list[str] = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return 15, ["unparseable_code"]

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = None
            if isinstance(func, ast.Attribute):
                name = func.attr
            elif isinstance(func, ast.Name):
                name = func.id
            if name in DANGEROUS_CALL_NAMES:
                score += DANGEROUS_CALL_NAMES[name]
                matched.append(f"dangerous_call:{name}")
    return score, matched


def _score_shell_command(command: str) -> tuple[int, list[str]]:
    score = 0
    matched: list[str] = []
    padded = f" {command.lower()} "
    for pattern, weight in SHELL_DANGEROUS_PATTERNS.items():
        if pattern in padded:
            score += weight
            matched.append(f"dangerous_shell:{pattern.strip()}")
    return score, matched


def analyze(tool_name: str, args: dict, settings: Settings) -> tuple[int, list[str]]:
    score = 0
    matched_rules: list[str] = []

    if settings.is_blocked_tool(tool_name):
        score += 100
        matched_rules.append(f"blocked_tool:{tool_name}")

    path = args.get("path")
    if path:
        path_score, path_rules = _score_protected_paths_in_text(path, settings)
        score += path_score
        matched_rules.extend(path_rules)

        if tool_name in WRITE_TOOLS and os.path.exists(path):
            score += 20
            matched_rules.append(f"overwrite_existing_file:{path}")

    if tool_name in CODE_ARG_TOOLS:
        code = args.get("code") or args.get("command") or ""

        code_path_score, code_path_rules = _score_protected_paths_in_text(code, settings)
        score += code_path_score
        matched_rules.extend(code_path_rules)

        if tool_name == "exec_python":
            code_score, code_rules = _score_python_code(code)
        else:
            code_score, code_rules = _score_shell_command(code)
        score += code_score
        matched_rules.extend(code_rules)

    return min(score, 100), matched_rules

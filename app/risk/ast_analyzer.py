from __future__ import annotations

import ast
import os

from app.config import Settings

CODE_ARG_TOOLS = {"exec_python", "run_shell"}
WRITE_TOOLS = {"write_file", "overwrite_file", "apply_patch"}

DANGEROUS_CALL_NAMES: dict[str, int] = {
    "remove": 75,
    "rmtree": 85,
    "rmdir": 30,
    "unlink": 75,
    "system": 80,
    "run": 20,
    "Popen": 25,
}

SHELL_DANGEROUS_PATTERNS: dict[str, int] = {
    "rm -rf": 90,
    "rm -r": 75,
    " rm ": 30,
    "mkfs": 90,
    "dd if=": 80,
    "> /dev/": 30,
    ":(){:|:&};:": 100,
}

PATH_RISK_WEIGHTS = {"CRITICAL": 60, "HIGH": 40}


def _contains_protected_path(text: str, path: str) -> bool:
    """Return True if `path` occurs in `text` at a real path/extension boundary.

    A plain substring check would let `/.env` match inside `/.envrc`, or
    `/src/main.py` match inside `/src/main.pyc`. We require that the
    character immediately following any match, if present, is not
    alphanumeric -- that rejects both false positives above while still
    matching when the protected path is followed by a separator, more
    path segments, or the end of the string.
    """
    # Codex may report Windows-native paths even when protected_paths.json
    # uses portable forward slashes. Normalize separators before matching.
    text = text.replace("\\", "/")
    path = path.replace("\\", "/")
    start = 0
    while True:
        idx = text.find(path, start)
        if idx == -1:
            return False
        end = idx + len(path)
        next_char = text[end] if end < len(text) else ""
        if not next_char.isalnum():
            return True
        start = idx + 1


def _score_protected_paths_in_text(text: str, settings: Settings) -> list[tuple[str, int]]:
    matches: list[tuple[str, int]] = []
    for entry in settings.critical_paths:
        if entry.path and _contains_protected_path(text, entry.path):
            weight = PATH_RISK_WEIGHTS.get(entry.risk_level, 20)
            matches.append((f"protected_path_{entry.risk_level.lower()}:{entry.path}", weight))
    return matches


def _score_python_code(code: str) -> list[tuple[str, int]]:
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, TypeError):
        # SyntaxError: malformed source. ValueError: e.g. embedded null bytes.
        # TypeError: non-str input slipped through. All three mean the code
        # is unparseable, not that the risk gate itself should crash.
        return [("unparseable_code", 15)]

    matches: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = None
            if isinstance(func, ast.Attribute):
                name = func.attr
            elif isinstance(func, ast.Name):
                name = func.id
            if name in DANGEROUS_CALL_NAMES:
                matches.append((f"dangerous_call:{name}", DANGEROUS_CALL_NAMES[name]))
    return matches


def _score_shell_command(command: str) -> list[tuple[str, int]]:
    """Return (rule, weight) pairs for every dangerous shell pattern found.

    Overlapping patterns (e.g. "rm -rf" / "rm -r" / " rm ") can all match the
    same substring for what is really a single dangerous event. Callers
    should use the *maximum* weight among the returned pairs as the score
    contribution, while still surfacing every matched pattern name in
    matched_rules for visibility.
    """
    padded = f" {command.lower()} "
    return [
        (f"dangerous_shell:{pattern.strip()}", weight)
        for pattern, weight in SHELL_DANGEROUS_PATTERNS.items()
        if pattern in padded
    ]


def analyze(tool_name: str, args: dict, settings: Settings) -> tuple[int, list[str]]:
    score = 0
    matched_rules: list[str] = []

    def add_rule(rule: str, weight: int) -> None:
        """Add a rule and its score, but only the first time it is seen."""
        nonlocal score
        if rule not in matched_rules:
            matched_rules.append(rule)
            score += weight

    def add_visible_rule(rule: str) -> None:
        """Record a rule name without contributing its own score weight."""
        if rule not in matched_rules:
            matched_rules.append(rule)

    if settings.is_blocked_tool(tool_name):
        add_rule(f"blocked_tool:{tool_name}", 100)

    paths: list[str] = []
    path = args.get("path")
    if isinstance(path, str):
        paths.append(path)
    extra_paths = args.get("paths")
    if isinstance(extra_paths, list):
        paths.extend(
            candidate
            for candidate in extra_paths
            if isinstance(candidate, str) and candidate not in paths
        )

    for path in paths:
        for rule, weight in _score_protected_paths_in_text(path, settings):
            add_rule(rule, weight)

        try:
            path_exists = os.path.exists(path)
        except (ValueError, TypeError):
            # e.g. a path containing a null byte, or a non-str/bytes path.
            # Treat as "does not exist" rather than crashing the risk gate.
            path_exists = False

        if tool_name in WRITE_TOOLS and path_exists:
            add_rule(f"overwrite_existing_file:{path}", 20)

    if tool_name == "apply_patch":
        patch = args.get("command") or ""
        if isinstance(patch, str) and "*** Delete File:" in patch:
            add_rule("apply_patch:delete_file", 75)

    if tool_name in CODE_ARG_TOOLS:
        code = args.get("code") or args.get("command") or ""
        if not isinstance(code, str):
            code = ""

        for rule, weight in _score_protected_paths_in_text(code, settings):
            add_rule(rule, weight)

        if tool_name == "exec_python":
            for rule, weight in _score_python_code(code):
                add_rule(rule, weight)
        else:
            shell_matches = _score_shell_command(code)
            if shell_matches:
                for rule, _weight in shell_matches:
                    add_visible_rule(rule)
                score += max(weight for _, weight in shell_matches)

    return min(score, 100), matched_rules

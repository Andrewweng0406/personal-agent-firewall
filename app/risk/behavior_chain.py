from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit


@dataclass
class BehaviorSignal:
    score_delta: int = 0
    matched_rules: list[str] = field(default_factory=list)
    explanation: str = ""
    chain_detected: bool = False
    auto_contain: bool = False


SECRET_MARKERS = (
    "/.env",
    ".env",
    "/.ssh/",
    "id_rsa",
    "credentials",
    ".npmrc",
    ".pypirc",
    "secret",
    "token",
)

NETWORK_MARKERS = (
    "curl ",
    "wget ",
    "http://",
    "https://",
    "requests.post",
    "requests.put",
    "urllib.request",
    "socket.",
)

UPLOAD_MARKERS = (
    " -d ",
    "--data",
    "--form",
    " -f ",
    "@-",
    "post(",
    "put(",
    "send(",
    "upload",
)


def analyze_behavior_chain(
    tool_name: str,
    args: dict[str, Any],
    history: list[dict],
    trusted_domains: list[str] | None = None,
) -> BehaviorSignal:
    allowed_history = [row for row in history if row.get("decision") == "allowed"]
    sensitive_read = next(
        (row for row in allowed_history if _is_sensitive_read(row)),
        None,
    )

    upload_domain = _external_upload_domain(tool_name, args)
    unknown_domain = upload_domain and not _is_trusted_domain(
        upload_domain, trusted_domains or []
    )

    download_source, download_target = _download_then_execute(tool_name, args, allowed_history)
    if download_source:
        target_text = f" as {download_target}" if download_target else ""
        return BehaviorSignal(
            score_delta=100,
            matched_rules=[
                "behavior_chain:download_then_execute",
                f"behavior_chain:download_source:{download_source}",
            ],
            explanation=(
                f"The agent downloaded code from {download_source}{target_text} and is "
                "now attempting to execute it. Downloaded code can take control of "
                "your machine, so the action was blocked and the session was quarantined."
            ),
            chain_detected=True,
            auto_contain=True,
        )

    if sensitive_read and upload_domain:
        source = _event_target(sensitive_read) or "a sensitive source"
        rules = [
            "behavior_chain:sensitive_read_then_external_upload",
            f"behavior_chain:source:{source}",
        ]
        if unknown_domain:
            rules.append(f"unknown_domain_upload:{upload_domain}")
        return BehaviorSignal(
            score_delta=100,
            matched_rules=rules,
            explanation=(
                f"The agent read sensitive data from {source} and is attempting to "
                f"send data to {upload_domain}"
                + (", an untrusted domain" if unknown_domain else "")
                + ". This was not part of your request, so the action was blocked "
                "and the session was quarantined."
            ),
            chain_detected=True,
            auto_contain=True,
        )

    if unknown_domain:
        return BehaviorSignal(
            score_delta=70,
            matched_rules=[f"unknown_domain_upload:{upload_domain}"],
            explanation=(
                f"The agent is attempting to upload data to {upload_domain}, "
                "which is not on your trusted-domain list. Review the destination "
                "before allowing this action."
            ),
        )

    return BehaviorSignal()


def _is_sensitive_read(row: dict) -> bool:
    if row.get("tool_name") not in {"read_file", "run_shell", "exec_python"}:
        return False
    args = _event_args(row)
    text = " ".join(str(value) for value in args.values()).lower()
    reads_data = row.get("tool_name") == "read_file" or any(
        marker in text for marker in ("cat ", "open(", "read_text", "read(")
    )
    return reads_data and any(marker in text for marker in SECRET_MARKERS)


def _is_external_upload(tool_name: str, args: dict[str, Any]) -> bool:
    return _external_upload_domain(tool_name, args) is not None


def _external_upload_domain(tool_name: str, args: dict[str, Any]) -> str | None:
    if tool_name not in {"run_shell", "exec_python"}:
        return None
    text = " ".join(str(value) for value in args.values()).lower()
    if not any(marker in text for marker in NETWORK_MARKERS) or not any(
        marker in text for marker in UPLOAD_MARKERS
    ):
        return None
    for candidate in re.findall(r"https?://[^\s'\"<>]+", text):
        hostname = urlsplit(candidate.rstrip(").,;" )).hostname
        if hostname:
            return hostname.lower().rstrip(".")
    return None


def _is_trusted_domain(domain: str, trusted_domains: list[str]) -> bool:
    normalized = domain.lower().rstrip(".")
    return any(
        normalized == trusted.lower().rstrip(".")
        or normalized.endswith("." + trusted.lower().rstrip("."))
        for trusted in trusted_domains
        if trusted.strip()
    )


def _download_then_execute(
    tool_name: str, args: dict[str, Any], history: list[dict]
) -> tuple[str | None, str | None]:
    current = _command_text(tool_name, args)
    if not current:
        return None, None

    # A pipe from a downloader straight into an interpreter is the same
    # behavior chain compressed into one shell invocation.
    direct_source = _download_url(current)
    if direct_source and re.search(
        r"\|\s*(?:sudo\s+)?(?:ba|z|fi)?sh(?:\s|$)|\|\s*(?:python\d*|node|ruby|perl)(?:\s|$)",
        current,
        re.IGNORECASE,
    ):
        return direct_source, None

    executed_targets = _execution_targets(current)
    if not executed_targets:
        return None, None

    direct_target = _download_target(current, direct_source)
    if direct_source and direct_target and any(
        _same_target(direct_target, item) for item in executed_targets
    ):
        return direct_source, direct_target

    for row in history:
        prior = _command_text(str(row.get("tool_name") or ""), _event_args(row))
        source = _download_url(prior)
        target = _download_target(prior, source)
        if source and target and any(_same_target(target, item) for item in executed_targets):
            return source, target
    return None, None


def _command_text(tool_name: str, args: dict[str, Any]) -> str:
    if tool_name not in {"run_shell", "exec_python"}:
        return ""
    value = args.get("command") if tool_name == "run_shell" else args.get("code")
    return value if isinstance(value, str) else ""


def _download_url(command: str) -> str | None:
    if not re.search(r"(?:^|[;&|]\s*|\s)(?:curl|wget)\s", command, re.IGNORECASE):
        return None
    match = re.search(r"https?://[^\s'\"<>|]+", command, re.IGNORECASE)
    return match.group(0).rstrip(").,;") if match else None


def _download_target(command: str, source: str | None) -> str | None:
    if not source:
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for option in ("-o", "--output", "-O"):
        if option in tokens:
            index = tokens.index(option)
            if index + 1 < len(tokens):
                return tokens[index + 1].rstrip(";|&")
    path = urlsplit(source).path
    name = PurePosixPath(path).name
    return name or None


def _execution_targets(command: str) -> set[str]:
    targets: set[str] = set()
    patterns = (
        r"(?:^|[;&|]\s*|\s)(?:sudo\s+)?(?:python\d*|node|ruby|perl|bash|sh|zsh)\s+([^\s;&|]+)",
        r"(?:^|[;&|]\s*)(\.?\.?/[^\s;&|]+)",
    )
    for pattern in patterns:
        targets.update(
            match.strip("'\"")
            for match in re.findall(pattern, command, re.IGNORECASE)
        )
    return targets


def _same_target(downloaded: str, executed: str) -> bool:
    left = downloaded.replace("\\", "/").lstrip("./")
    right = executed.replace("\\", "/").lstrip("./")
    return left == right or PurePosixPath(left).name == PurePosixPath(right).name


def _event_args(row: dict) -> dict:
    value = row.get("args")
    if isinstance(value, dict):
        return value
    try:
        decoded = json.loads(row.get("args_json", "{}"))
    except (TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _event_target(row: dict) -> str | None:
    args = _event_args(row)
    path = args.get("path")
    return path if isinstance(path, str) else None

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from app.models import IntentAlignment


@dataclass
class IntentSignal:
    alignment: IntentAlignment
    score_delta: int
    matched_rules: list[str] = field(default_factory=list)
    explanation: str = ""


FRONTEND_TERMS = {
    "frontend",
    "front-end",
    "ui",
    "ux",
    "react",
    "vue",
    "next",
    "css",
    "html",
    "component",
    "components",
    "page",
    "button",
    "login page",
}

BACKEND_TERMS = {
    "backend",
    "back-end",
    "api",
    "server",
    "database",
    "db",
    "fastapi",
    "auth",
    "authentication",
    "authorization",
}

DOCS_TERMS = {"docs", "documentation", "readme", "guide", "markdown"}
TEST_TERMS = {"test", "tests", "pytest", "spec"}

SECRET_PATH_PARTS = {".env", ".npmrc", ".pypirc", ".ssh", "id_rsa", "credentials"}
BACKEND_PATH_PARTS = {"app", "api", "server", "db", "database", "auth", "models.py"}
FRONTEND_PATH_PARTS = {
    "src",
    "components",
    "pages",
    "app",
    "styles",
    "public",
    "index.html",
}
DOC_EXTENSIONS = {".md", ".mdx", ".txt"}
TEST_PATH_PARTS = {"test", "tests", "__tests__", "spec"}


def assess_intent(tool_name: str, args: dict[str, Any], user_intent: str | None) -> IntentSignal:
    if not user_intent:
        return IntentSignal(
            alignment="uncertain",
            score_delta=0,
            matched_rules=["intent:missing"],
            explanation="No user intent was provided for this action.",
        )

    intent = user_intent.lower()
    target_text = _target_text(tool_name, args)
    target_path = _target_path(args)
    target_domain = _domain_for_path(target_path)
    intent_domains = _domains_for_intent(intent)

    if _touches_secret(target_text):
        return IntentSignal(
            alignment="off_scope",
            score_delta=45,
            matched_rules=["intent:touches_secret"],
            explanation="The action touches a secret or credential file, which is outside normal task scope.",
        )

    if _exfiltrates_data(tool_name, target_text):
        return IntentSignal(
            alignment="off_scope",
            score_delta=50,
            matched_rules=["intent:possible_data_exfiltration"],
            explanation="The action appears to send local data to an external destination.",
        )

    if target_domain and intent_domains and target_domain in intent_domains:
        return IntentSignal(
            alignment="aligned",
            score_delta=-15,
            matched_rules=[f"intent:aligned_{target_domain}"],
            explanation="The action matches the user's stated task area.",
        )

    if target_domain and intent_domains and target_domain not in intent_domains:
        return IntentSignal(
            alignment="off_scope",
            score_delta=35,
            matched_rules=[f"intent:off_scope_{target_domain}"],
            explanation="The action targets a different project area than the user's stated task.",
        )

    return IntentSignal(
        alignment="uncertain",
        score_delta=10,
        matched_rules=["intent:uncertain_scope"],
        explanation="The action could not be clearly matched to the user's stated task.",
    )


def _target_text(tool_name: str, args: dict[str, Any]) -> str:
    parts = [tool_name]
    for key in ("path", "command", "code", "query", "url"):
        value = args.get(key)
        if isinstance(value, str):
            parts.append(value)
    return " ".join(parts).lower()


def _target_path(args: dict[str, Any]) -> str | None:
    path = args.get("path")
    return path if isinstance(path, str) else None


def _domains_for_intent(intent: str) -> set[str]:
    domains: set[str] = set()
    if any(term in intent for term in FRONTEND_TERMS):
        domains.add("frontend")
    if any(term in intent for term in BACKEND_TERMS):
        domains.add("backend")
    if any(term in intent for term in DOCS_TERMS):
        domains.add("docs")
    if any(term in intent for term in TEST_TERMS):
        domains.add("tests")
    return domains


def _domain_for_path(path: str | None) -> str | None:
    if not path:
        return None

    normalized = path.replace("\\", "/").lower()
    parts = set(PurePosixPath(normalized).parts)
    suffix = PurePosixPath(normalized).suffix

    if suffix in DOC_EXTENSIONS or "readme.md" in normalized:
        return "docs"
    if any(part in parts for part in TEST_PATH_PARTS) or normalized.endswith("_test.py"):
        return "tests"
    if any(part in parts for part in BACKEND_PATH_PARTS):
        return "backend"
    if any(part in parts for part in FRONTEND_PATH_PARTS):
        return "frontend"
    return None


def _touches_secret(text: str) -> bool:
    return any(secret in text for secret in SECRET_PATH_PARTS)


def _exfiltrates_data(tool_name: str, text: str) -> bool:
    if tool_name not in {"run_shell", "exec_python"}:
        return False
    has_external_destination = any(token in text for token in ("curl ", "wget ", "http://", "https://"))
    has_local_read = any(token in text for token in ("cat ", "open(", "read_text", ".env", "secret", "token"))
    return has_external_destination and has_local_read

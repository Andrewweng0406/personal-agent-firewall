from __future__ import annotations

import re

PATTERNS: dict[str, re.Pattern[str]] = {
    "DATABASE_URL": re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s@/]+@[^\s]+"
    ),
    "EMAIL": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "TW_NATIONAL_ID": re.compile(r"\b[A-Z][12]\d{8}\b"),
    "API_KEY": re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    "ANTHROPIC_API_KEY": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"),
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GITHUB_TOKEN": re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
    ),
    "GOOGLE_API_KEY": re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "SLACK_TOKEN": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "BEARER_TOKEN": re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}={0,2}"),
    "PRIVATE_KEY": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?"
        r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    "URL_SECRET": re.compile(
        r"(?i)([?&](?:access_?token|api_?key|password|secret|token)=)[^&#\s]+"
    ),
    "CREDIT_CARD": re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
}


def redact(text: str) -> tuple[str, list[str]]:
    matched_types: list[str] = []
    redacted = text
    for name, pattern in PATTERNS.items():
        if pattern.search(redacted):
            matched_types.append(name)
            redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    return redacted, matched_types

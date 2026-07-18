from __future__ import annotations

import re

PATTERNS: dict[str, re.Pattern[str]] = {
    "EMAIL": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "TW_NATIONAL_ID": re.compile(r"\b[A-Z][12]\d{8}\b"),
    "API_KEY": re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
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

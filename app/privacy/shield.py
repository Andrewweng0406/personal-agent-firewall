from __future__ import annotations

from typing import Any

from app.privacy.pii_patterns import redact


def scan_and_redact(value: Any) -> tuple[Any, list[str]]:
    matched_types: list[str] = []

    def _walk(node: Any) -> Any:
        if isinstance(node, str):
            redacted, matches = redact(node)
            for match in matches:
                if match not in matched_types:
                    matched_types.append(match)
            return redacted
        if isinstance(node, dict):
            return {key: _walk(val) for key, val in node.items()}
        if isinstance(node, list):
            return [_walk(item) for item in node]
        return node

    redacted_value = _walk(value)
    return redacted_value, matched_types

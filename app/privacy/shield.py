from __future__ import annotations

from typing import Any

from app.privacy.pii_patterns import redact

SEMANTIC_MATCH_TYPE = "SEMANTIC_MATCH"
_SEMANTIC_REDACTION = "[REDACTED:SEMANTIC_MATCH]"
SENSITIVE_FIELD_TYPE = "SENSITIVE_FIELD"
_SENSITIVE_FIELDS = {
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
}


def scan_and_redact(value: Any, semantic_detector: Any = None) -> tuple[Any, list[str]]:
    """Recursively redact strings inside `value`.

    `semantic_detector` is optional and defaults to `None`, which preserves
    the original regex-only behavior exactly (existing callers and tests
    are unaffected). When a `SemanticPiiDetector`-shaped object (anything
    with `.is_sensitive(text: str) -> bool`) is passed, each string is also
    checked for cosine-similarity to known-sensitive examples after regex
    redaction, catching natural-language secrets regex can't match (e.g.
    "here is my private key for the wallet"). A semantic hit replaces the
    *entire* string, since -- unlike a regex match -- there is no reliable
    span to redact within it.
    """
    matched_types: list[str] = []

    def _walk(node: Any) -> Any:
        if isinstance(node, str):
            redacted, matches = redact(node)
            for match in matches:
                if match not in matched_types:
                    matched_types.append(match)
            if semantic_detector is not None and semantic_detector.is_sensitive(redacted):
                if SEMANTIC_MATCH_TYPE not in matched_types:
                    matched_types.append(SEMANTIC_MATCH_TYPE)
                return _SEMANTIC_REDACTION
            return redacted
        if isinstance(node, dict):
            result = {}
            for key, val in node.items():
                normalized_key = str(key).strip().lower().replace("-", "_")
                sensitive_key = (
                    normalized_key in _SENSITIVE_FIELDS
                    or normalized_key.endswith("_password")
                    or normalized_key.endswith("_secret")
                    or normalized_key.endswith("_token")
                    or normalized_key.endswith("_api_key")
                )
                if sensitive_key and val not in (None, ""):
                    if SENSITIVE_FIELD_TYPE not in matched_types:
                        matched_types.append(SENSITIVE_FIELD_TYPE)
                    result[key] = "[REDACTED:SENSITIVE_FIELD]"
                else:
                    result[key] = _walk(val)
            return result
        if isinstance(node, list):
            return [_walk(item) for item in node]
        return node

    redacted_value = _walk(value)
    return redacted_value, matched_types

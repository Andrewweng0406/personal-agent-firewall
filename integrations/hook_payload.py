from __future__ import annotations

import hashlib
import json
import os
from typing import Any

DEFAULT_MAX_EVENT_BYTES = 1_048_576
DEFAULT_MAX_STRING_BYTES = 65_536
_MIN_EVENT_BYTES = 4_096
_MIN_STRING_BYTES = 128
_MIN_COLLECTION_ITEMS = 8


def bound_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-safe hook payload that cannot grow without bound."""
    max_event_bytes = _env_int(
        "AGENT_FIREWALL_MAX_EVENT_BYTES", DEFAULT_MAX_EVENT_BYTES, _MIN_EVENT_BYTES
    )
    max_string_bytes = min(
        _env_int(
            "AGENT_FIREWALL_MAX_STRING_BYTES",
            DEFAULT_MAX_STRING_BYTES,
            _MIN_STRING_BYTES,
        ),
        max_event_bytes // 2,
    )
    original = _json_bytes(payload)
    if len(original) <= max_event_bytes:
        return payload

    digest = hashlib.sha256(original).hexdigest()
    string_limit = max_string_bytes
    collection_limit = 256
    bounded: dict[str, Any] = payload

    while True:
        candidate = _bound_value(payload, string_limit, collection_limit)
        if not isinstance(candidate, dict):  # pragma: no cover - root is typed as dict
            candidate = {"payload": candidate}
        candidate["_firewall_payload_meta"] = {
            "truncated": True,
            "original_bytes": len(original),
            "sha256": digest,
        }
        encoded = _json_bytes(candidate)
        if len(encoded) <= max_event_bytes:
            _set_sent_bytes(candidate)
            return candidate
        bounded = candidate
        if string_limit > _MIN_STRING_BYTES:
            string_limit = max(_MIN_STRING_BYTES, string_limit // 2)
        elif collection_limit > _MIN_COLLECTION_ITEMS:
            collection_limit = max(_MIN_COLLECTION_ITEMS, collection_limit // 2)
        else:
            # With the documented 4 KiB minimum this is only reachable for an
            # unusually wide top-level object. Keep its earliest fields and
            # the integrity metadata rather than sending an oversized event.
            metadata = bounded.pop("_firewall_payload_meta")
            compact: dict[str, Any] = {}
            for key, value in bounded.items():
                compact[key] = value
                compact["_firewall_payload_meta"] = metadata
                if len(_json_bytes(compact)) > max_event_bytes:
                    compact.pop(key)
                    break
                compact.pop("_firewall_payload_meta")
            compact["_firewall_payload_meta"] = metadata
            _set_sent_bytes(compact)
            return compact


def _bound_value(value: Any, string_limit: int, collection_limit: int) -> Any:
    if isinstance(value, str):
        return _truncate_string(value, string_limit)
    if isinstance(value, dict):
        items = list(value.items())
        result = {
            str(key): _bound_value(item, string_limit, collection_limit)
            for key, item in items[:collection_limit]
        }
        if len(items) > collection_limit:
            result["_firewall_omitted_items"] = len(items) - collection_limit
        return result
    if isinstance(value, (list, tuple)):
        result = [
            _bound_value(item, string_limit, collection_limit)
            for item in value[:collection_limit]
        ]
        if len(value) > collection_limit:
            result.append({"_firewall_omitted_items": len(value) - collection_limit})
        return result
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _truncate_string(str(value), string_limit)


def _truncate_string(value: str, byte_limit: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= byte_limit:
        return value
    marker = f"\n...[Agent Firewall omitted {len(encoded) - byte_limit} bytes]...\n"
    marker_bytes = marker.encode("utf-8")
    content_budget = max(0, byte_limit - len(marker_bytes))
    head_budget = content_budget // 2
    tail_budget = content_budget - head_budget
    head = encoded[:head_budget].decode("utf-8", errors="ignore")
    tail = encoded[-tail_budget:].decode("utf-8", errors="ignore") if tail_budget else ""
    return f"{head}{marker}{tail}"


def _env_int(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _set_sent_bytes(payload: dict[str, Any]) -> None:
    metadata = payload["_firewall_payload_meta"]
    previous = -1
    while metadata.get("sent_bytes") != previous:
        previous = metadata.get("sent_bytes", -1)
        metadata["sent_bytes"] = len(_json_bytes(payload))

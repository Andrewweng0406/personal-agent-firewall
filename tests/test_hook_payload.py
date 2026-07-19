import hashlib
import json

from integrations.hook_payload import bound_payload


def _encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def test_small_payload_is_unchanged(monkeypatch):
    monkeypatch.setenv("AGENT_FIREWALL_MAX_EVENT_BYTES", "4096")
    payload = {"event_type": "user_prompt", "content": "hello"}

    assert bound_payload(payload) is payload


def test_large_string_keeps_head_tail_and_integrity_metadata(monkeypatch):
    monkeypatch.setenv("AGENT_FIREWALL_MAX_EVENT_BYTES", "4096")
    monkeypatch.setenv("AGENT_FIREWALL_MAX_STRING_BYTES", "512")
    content = "HEAD" + ("x" * 10_000) + "TAIL"
    payload = {"event_type": "assistant_response", "content": content}

    bounded = bound_payload(payload)

    assert bounded["content"].startswith("HEAD")
    assert bounded["content"].endswith("TAIL")
    assert "Agent Firewall omitted" in bounded["content"]
    metadata = bounded["_firewall_payload_meta"]
    assert metadata["truncated"] is True
    assert metadata["original_bytes"] == len(_encoded(payload))
    assert metadata["sha256"] == hashlib.sha256(_encoded(payload)).hexdigest()
    assert len(_encoded(bounded)) <= 4096
    assert metadata["sent_bytes"] == len(_encoded(bounded))


def test_large_collections_are_bounded(monkeypatch):
    monkeypatch.setenv("AGENT_FIREWALL_MAX_EVENT_BYTES", "4096")
    monkeypatch.setenv("AGENT_FIREWALL_MAX_STRING_BYTES", "256")
    payload = {
        "tool_name": "example",
        "args": {f"field-{index}": "z" * 500 for index in range(1_000)},
    }

    bounded = bound_payload(payload)

    assert bounded["tool_name"] == "example"
    assert len(_encoded(bounded)) <= 4096
    assert bounded["_firewall_payload_meta"]["original_bytes"] > 4096

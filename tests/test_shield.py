from app.privacy.shield import scan_and_redact


def test_redacts_string_value_in_dict():
    data = {"content": "contact jane@example.com now"}
    redacted, matches = scan_and_redact(data)
    assert redacted["content"] == "contact [REDACTED:EMAIL] now"
    assert matches == ["EMAIL"]


def test_redacts_nested_list_and_dict():
    data = {"notes": ["fine", {"email": "a@b.com"}]}
    redacted, matches = scan_and_redact(data)
    assert redacted["notes"][1]["email"] == "[REDACTED:EMAIL]"
    assert matches == ["EMAIL"]


def test_non_string_values_pass_through_unchanged():
    data = {"count": 5, "active": True, "missing": None}
    redacted, matches = scan_and_redact(data)
    assert redacted == data
    assert matches == []


def test_scan_and_redact_on_plain_string():
    redacted, matches = scan_and_redact("my card is 4111 1111 1111 1111")
    assert redacted == "my card is [REDACTED:CREDIT_CARD]"
    assert matches == ["CREDIT_CARD"]

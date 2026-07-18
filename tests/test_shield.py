from app.privacy.shield import scan_and_redact


class _FakeSemanticDetector:
    def __init__(self, sensitive_texts: set[str]):
        self._sensitive_texts = sensitive_texts
        self.calls: list[str] = []

    def is_sensitive(self, text: str) -> bool:
        self.calls.append(text)
        return text in self._sensitive_texts


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


def test_semantic_detector_none_preserves_regex_only_behavior():
    redacted, matches = scan_and_redact("contact jane@example.com now", semantic_detector=None)
    assert redacted == "contact [REDACTED:EMAIL] now"
    assert matches == ["EMAIL"]


def test_semantic_hit_redacts_entire_string():
    text = "here is my private key for the wallet"
    detector = _FakeSemanticDetector({text})

    redacted, matches = scan_and_redact(text, semantic_detector=detector)

    assert redacted == "[REDACTED:SEMANTIC_MATCH]"
    assert matches == ["SEMANTIC_MATCH"]


def test_semantic_detector_runs_after_regex_on_the_already_redacted_text():
    text = "contact jane@example.com about the private key"
    detector = _FakeSemanticDetector(set())

    scan_and_redact(text, semantic_detector=detector)

    assert detector.calls == ["contact [REDACTED:EMAIL] about the private key"]


def test_semantic_miss_leaves_regex_result_untouched():
    detector = _FakeSemanticDetector(set())

    redacted, matches = scan_and_redact("just a normal sentence", semantic_detector=detector)

    assert redacted == "just a normal sentence"
    assert matches == []


def test_semantic_detector_applies_inside_nested_structures():
    detector = _FakeSemanticDetector({"my private key text"})
    data = {"notes": ["fine", {"secret": "my private key text"}]}

    redacted, matches = scan_and_redact(data, semantic_detector=detector)

    assert redacted["notes"][1]["secret"] == "[REDACTED:SEMANTIC_MATCH]"
    assert redacted["notes"][0] == "fine"
    assert matches == ["SEMANTIC_MATCH"]

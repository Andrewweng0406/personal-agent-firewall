from app.privacy.pii_patterns import redact


def test_redact_email():
    text, matches = redact("contact me at jane.doe@example.com please")
    assert "[REDACTED:EMAIL]" in text
    assert "jane.doe@example.com" not in text
    assert matches == ["EMAIL"]


def test_redact_tw_national_id():
    text, matches = redact("my ID number is A123456789")
    assert "[REDACTED:TW_NATIONAL_ID]" in text
    assert matches == ["TW_NATIONAL_ID"]


def test_redact_api_key():
    text, matches = redact("key: sk-abcdefghij1234567890")
    assert "[REDACTED:API_KEY]" in text
    assert matches == ["API_KEY"]


def test_redact_aws_key():
    text, matches = redact("AKIAABCDEFGHIJKLMNOP is my access key")
    assert "[REDACTED:AWS_ACCESS_KEY]" in text
    assert matches == ["AWS_ACCESS_KEY"]


def test_redact_credit_card():
    text, matches = redact("card 4111 1111 1111 1111 expires soon")
    assert "[REDACTED:CREDIT_CARD]" in text
    assert matches == ["CREDIT_CARD"]


def test_redact_no_match_returns_original():
    text, matches = redact("just a normal sentence")
    assert text == "just a normal sentence"
    assert matches == []


def test_redact_multiple_matches_in_one_string():
    text, matches = redact("email me at a@b.com or check sk-abcdefghij1234567890")
    assert "EMAIL" in matches
    assert "API_KEY" in matches

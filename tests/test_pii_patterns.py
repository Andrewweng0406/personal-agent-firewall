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
    aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    text, matches = redact(f"{aws_key} is my access key")
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


def test_redacts_common_agent_credentials():
    values = {
        "ANTHROPIC_API_KEY": "sk-ant-" + "api03-abcdefghijklmnopqrstuvwxyz123456",
        "GITHUB_TOKEN": "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890",
        "GOOGLE_API_KEY": "AIza" + "abcdefghijklmnopqrstuvwxyz1234567890",
        "SLACK_TOKEN": "xoxb-" + "1234567890-abcdefghijklmnopqrstuvwxyz",
        "BEARER_TOKEN": "Bearer " + "abcdefghijklmnopqrstuvwxyz.123456",
    }

    for expected_type, value in values.items():
        redacted, matches = redact(value)
        assert value not in redacted
        assert expected_type in matches


def test_redacts_private_key_database_url_and_url_query_secret():
    text = (
        "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----\n"
        "postgresql://admin:" + "supersecret@db.example.com/app\n"
        "https://example.com/callback?token=very-secret-token-value"
    )

    redacted, matches = redact(text)

    assert "abc123" not in redacted
    assert "supersecret" not in redacted
    assert "very-secret-token-value" not in redacted
    assert {"PRIVATE_KEY", "DATABASE_URL", "URL_SECRET"} <= set(matches)

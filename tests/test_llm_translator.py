import json

from app.risk.llm_translator import ClaudeRiskClient, LlmRiskResult, _parse_response


class _FakeContentBlock:
    def __init__(self, text: str):
        self.text = text


class _FakeMessage:
    def __init__(self, text: str):
        self.content = [_FakeContentBlock(text)]


class _FakeMessages:
    def __init__(self, response_text: str | None = None, raise_error: bool = False):
        self._response_text = response_text
        self._raise_error = raise_error

    def create(self, **kwargs):
        if self._raise_error:
            raise RuntimeError("API unavailable")
        return _FakeMessage(self._response_text)


class _FakeAnthropicClient:
    def __init__(self, response_text: str | None = None, raise_error: bool = False):
        self.messages = _FakeMessages(response_text, raise_error)


def test_assess_with_no_client_returns_fallback():
    client = ClaudeRiskClient(api_key=None)
    result = client.assess("write_file", {"path": "/x"}, ["blocked_tool:rm"])
    assert result.score == 0
    assert "no Anthropic API key" in result.plain_explanation


def test_assess_parses_valid_json_response():
    fake = _FakeAnthropicClient(
        response_text=json.dumps({"score": 85, "explanation": "This deletes your homepage."})
    )
    client = ClaudeRiskClient(client=fake)
    result = client.assess("write_file", {"path": "/src/index.html"}, [])
    assert result.score == 85
    assert result.plain_explanation == "This deletes your homepage."


def test_assess_falls_back_on_api_error():
    fake = _FakeAnthropicClient(raise_error=True)
    client = ClaudeRiskClient(client=fake)
    result = client.assess("write_file", {"path": "/x"}, [])
    assert result.score == 0
    assert "could not be automatically" in result.plain_explanation


def test_parse_response_handles_malformed_json():
    result = _parse_response("not json at all")
    assert result.score == 0
    assert "could not be automatically" in result.plain_explanation


def test_parse_response_handles_valid_json():
    result = _parse_response(json.dumps({"score": 42, "explanation": "medium risk"}))
    assert result == LlmRiskResult(score=42, plain_explanation="medium risk")

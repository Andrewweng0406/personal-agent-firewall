import json

from app.risk.llm_translator import (
    ClaudeRiskClient,
    LlmRiskResult,
    OpenAIRiskClient,
    _parse_response,
    build_llm_client,
)


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
    assert "no LLM API key configured" in result.plain_explanation


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


class _FakeOpenAIMessage:
    def __init__(self, content: str):
        self.content = content


class _FakeOpenAIChoice:
    def __init__(self, content: str):
        self.message = _FakeOpenAIMessage(content)


class _FakeOpenAIResponse:
    def __init__(self, content: str):
        self.choices = [_FakeOpenAIChoice(content)]


class _FakeOpenAICompletions:
    def __init__(self, response_text: str | None = None, raise_error: bool = False):
        self._response_text = response_text
        self._raise_error = raise_error

    def create(self, **kwargs):
        if self._raise_error:
            raise RuntimeError("API unavailable")
        return _FakeOpenAIResponse(self._response_text)


class _FakeOpenAIChat:
    def __init__(self, response_text: str | None = None, raise_error: bool = False):
        self.completions = _FakeOpenAICompletions(response_text, raise_error)


class _FakeOpenAIClient:
    def __init__(self, response_text: str | None = None, raise_error: bool = False):
        self.chat = _FakeOpenAIChat(response_text, raise_error)


def test_openai_assess_with_no_client_returns_fallback():
    client = OpenAIRiskClient(api_key=None)
    result = client.assess("write_file", {"path": "/x"}, ["blocked_tool:rm"])
    assert result.score == 0
    assert "no LLM API key configured" in result.plain_explanation


def test_openai_assess_parses_valid_json_response():
    fake = _FakeOpenAIClient(
        response_text=json.dumps({"score": 90, "explanation": "This deletes your homepage."})
    )
    client = OpenAIRiskClient(client=fake)
    result = client.assess("write_file", {"path": "/src/index.html"}, [])
    assert result.score == 90
    assert result.plain_explanation == "This deletes your homepage."


def test_openai_assess_falls_back_on_api_error():
    fake = _FakeOpenAIClient(raise_error=True)
    client = OpenAIRiskClient(client=fake)
    result = client.assess("write_file", {"path": "/x"}, [])
    assert result.score == 0
    assert "could not be automatically" in result.plain_explanation


def test_build_llm_client_selects_openai_when_configured():
    client = build_llm_client("openai", anthropic_api_key=None, openai_api_key=None)
    assert isinstance(client, OpenAIRiskClient)


def test_build_llm_client_defaults_to_claude():
    client = build_llm_client("anthropic", anthropic_api_key=None, openai_api_key=None)
    assert isinstance(client, ClaudeRiskClient)


def test_build_llm_client_falls_back_to_claude_for_unknown_provider():
    client = build_llm_client("unknown-provider", anthropic_api_key=None, openai_api_key=None)
    assert isinstance(client, ClaudeRiskClient)

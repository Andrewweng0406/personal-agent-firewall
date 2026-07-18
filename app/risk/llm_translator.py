from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol

from anthropic import Anthropic


@dataclass
class LlmRiskResult:
    score: int
    plain_explanation: str


class RiskLlmClient(Protocol):
    def assess(self, tool_name: str, args: dict, matched_rules: list[str]) -> LlmRiskResult: ...


_UNAVAILABLE_EXPLANATION = (
    "Risk explanation unavailable: no Anthropic API key configured. "
    "Please review the raw details below before deciding."
)

_FAILURE_EXPLANATION = (
    "This action was flagged as high-risk and could not be automatically "
    "explained — please review the raw details before deciding."
)


class ClaudeRiskClient:
    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-haiku-4-5-20251001",
        client=None,
    ):
        if client is not None:
            self._client = client
        elif api_key:
            self._client = Anthropic(api_key=api_key)
        else:
            self._client = None
        self._model = model

    def assess(self, tool_name: str, args: dict, matched_rules: list[str]) -> LlmRiskResult:
        if self._client is None:
            return LlmRiskResult(score=0, plain_explanation=_UNAVAILABLE_EXPLANATION)

        prompt = _build_prompt(tool_name, args, matched_rules)
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=300,
                messages=[{"role": "user", "content": prompt}],
            )
            return _parse_response(response.content[0].text)
        except Exception:
            return LlmRiskResult(score=0, plain_explanation=_FAILURE_EXPLANATION)


def _build_prompt(tool_name: str, args: dict, matched_rules: list[str]) -> str:
    return (
        "You are a security assistant explaining a risky AI agent action to a "
        "non-technical user (a 'vibe coder'). Given the tool call below, respond "
        "with ONLY a JSON object of the form "
        '{"score": <0-100 integer risk score>, "explanation": "<one or two plain '
        'English sentences, no jargon, explaining what this action would do and '
        'why it is risky>"}.\n\n'
        f"Tool: {tool_name}\n"
        f"Arguments: {json.dumps(args)}\n"
        f"Static analysis flags: {matched_rules}\n"
    )


def _parse_response(text: str) -> LlmRiskResult:
    try:
        data = json.loads(text)
        return LlmRiskResult(score=int(data["score"]), plain_explanation=str(data["explanation"]))
    except (json.JSONDecodeError, KeyError, ValueError, TypeError):
        return LlmRiskResult(score=0, plain_explanation=_FAILURE_EXPLANATION)

"""Security-corpus and bypass tests for OWASP LLM05 output boundaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from trustrail import (
    GuardAction,
    OutputContext,
    OutputHandlingError,
    OutputHandlingPolicy,
    SafeOutputHandler,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "output_handling.json"
PATH_ROOT = Path("/srv/trustrail/generated")


class Operation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: str
    resource_id: int


def _corpus() -> list[dict[str, str]]:
    return json.loads(CORPUS_PATH.read_text())


def _handler() -> SafeOutputHandler:
    return SafeOutputHandler(
        OutputHandlingPolicy(
            allowed_url_hosts=frozenset({"docs.example.test"}),
            path_root=PATH_ROOT,
        )
    )


@pytest.mark.parametrize("case", _corpus(), ids=lambda case: case["name"])
def test_output_handling_corpus(case: dict[str, str]):
    result = _handler().handle(case["value"], OutputContext(case["context"]))

    assert result.action == GuardAction(case["expected_action"])
    forbidden = case.get("forbid_in_safe_value")
    if forbidden is not None:
        assert result.safe_value is not None
        assert forbidden not in result.safe_value
    if result.is_blocked:
        assert result.safe_value is None
        assert "private-output-marker" not in result.model_dump_json()


@pytest.mark.parametrize(
    "value",
    [
        "https://docs.example.test.attacker.invalid/",
        "https://docs.example.test@attacker.invalid/",
        "https://docs.example.test\\@attacker.invalid/",
        "//docs.example.test/relative",
        "javascript:dangerousCall()",
        "https://docs.example.test/a b",
    ],
)
def test_url_parser_confusion_fails_closed(value: str):
    assert _handler().handle(value, OutputContext.URL).is_blocked


@pytest.mark.parametrize(
    "value",
    [
        "![pixel](https://docs.example.test/pixel)",
        "![pixel][tracking]\n[tracking]: https://docs.example.test/pixel",
        "<https://attacker.invalid/>",
        "<video src=https://attacker.invalid/ autoplay>",
        "[click](javascript:dangerousCall())",
        "[click][destination]\n[destination]: https://attacker.invalid/",
    ],
)
def test_markdown_renderer_bypasses_fail_closed(value: str):
    assert _handler().handle(value, OutputContext.MARKDOWN).is_blocked


@pytest.mark.parametrize(
    "value",
    [
        '{"operation":"read","resource_id":1,"resource_id":2}',
        '{"operation":"read","resource_id":NaN}',
        '{"operation":"read","resource_id":"1"}',
        '{"operation":"read","resource_id":1,"extra":true}',
    ],
)
def test_ambiguous_or_untyped_structured_output_fails_closed(value: str):
    with pytest.raises(OutputHandlingError):
        _handler().parse_json(value, Operation)

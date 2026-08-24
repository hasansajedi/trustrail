"""Unit tests for typed, destination-aware model output handling."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict, Field

from trustrail import (
    GuardAction,
    OutputContext,
    OutputHandlingCode,
    OutputHandlingError,
    OutputHandlingPolicy,
    SafeOutputHandler,
)


class AnswerPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str
    confidence: float = Field(ge=0.0, le=1.0)


class EmailArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipient_id: int
    subject: str


def _handler(**overrides: object) -> SafeOutputHandler:
    values: dict[str, object] = {
        "allowed_url_hosts": frozenset({"docs.example.test"}),
    }
    values.update(overrides)
    return SafeOutputHandler(OutputHandlingPolicy(**values))


class TestDisplayEncoding:
    def test_plain_text_is_allowed(self):
        result = _handler().handle("A normal answer.", OutputContext.TEXT)

        assert result.action == GuardAction.ALLOW
        assert result.safe_value == "A normal answer."

    def test_html_is_encoded_as_text(self):
        result = _handler().handle(
            '<img src=x onerror="alert(1)">',
            OutputContext.HTML,
        )

        assert result.action == GuardAction.TRANSFORM
        assert result.safe_value == ("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;")
        assert result.findings[0].code == OutputHandlingCode.HTML_ENCODED

    def test_javascript_is_encoded_as_one_string_literal(self):
        result = _handler().handle(
            "</script><script>alert(1)</script>\u2028next",
            OutputContext.JAVASCRIPT,
        )

        assert result.action == GuardAction.TRANSFORM
        assert result.safe_value is not None
        assert "<" not in result.safe_value
        assert r"\u003c/script\u003e" in result.safe_value
        assert r"\u2028" in result.safe_value

    def test_output_size_limit_fails_closed_without_returning_raw_value(self):
        dangerous = "private-output-marker"
        result = _handler(max_output_chars=5).handle(dangerous, OutputContext.TEXT)

        assert result.is_blocked
        assert result.safe_value is None
        assert result.findings[0].code == OutputHandlingCode.OUTPUT_TOO_LARGE
        assert dangerous not in result.model_dump_json()

    def test_control_character_is_blocked(self):
        result = _handler().handle("safe\x00suffix", OutputContext.TEXT)

        assert result.is_blocked
        assert result.findings[0].code == OutputHandlingCode.CONTROL_CHARACTER


class TestMarkdownHandling:
    def test_allows_plain_markdown(self):
        value = "## Result\n\nA **safe** answer."

        assert _handler().require(value, OutputContext.MARKDOWN) == value

    def test_allows_link_to_allowlisted_host(self):
        value = "Read [the guide](https://docs.example.test/guide)."

        assert _handler().require(value, OutputContext.MARKDOWN) == value

    @pytest.mark.parametrize(
        ("value", "code"),
        [
            (
                "![pixel](https://docs.example.test/pixel)",
                OutputHandlingCode.MARKDOWN_IMAGE_NOT_ALLOWED,
            ),
            ("<script>alert(1)</script>", OutputHandlingCode.RAW_HTML_NOT_ALLOWED),
            (
                "[click](javascript:alert(1))",
                OutputHandlingCode.URL_SCHEME_NOT_ALLOWED,
            ),
            (
                "[lookalike](https://docs.example.test.attacker.invalid/)",
                OutputHandlingCode.URL_HOST_NOT_ALLOWED,
            ),
            (
                "[reference][x]\n\n[x]: https://attacker.invalid/",
                OutputHandlingCode.URL_HOST_NOT_ALLOWED,
            ),
        ],
    )
    def test_blocks_unsafe_markdown(self, value: str, code: OutputHandlingCode):
        result = _handler().handle(value, OutputContext.MARKDOWN)

        assert result.is_blocked
        assert result.findings[0].code == code

    def test_markdown_links_can_be_disabled(self):
        result = _handler(allow_markdown_links=False).handle(
            "[guide](https://docs.example.test/guide)",
            OutputContext.MARKDOWN,
        )

        assert result.is_blocked
        assert result.findings[0].code == OutputHandlingCode.MARKDOWN_LINK_NOT_ALLOWED

    def test_enabled_markdown_images_still_require_allowlisted_url(self):
        handler = _handler(allow_markdown_images=True)

        assert handler.handle(
            "![diagram](https://docs.example.test/diagram.png)",
            OutputContext.MARKDOWN,
        ).is_allowed
        assert handler.handle(
            "![pixel](https://attacker.invalid/pixel)",
            OutputContext.MARKDOWN,
        ).is_blocked


class TestUrlHandling:
    def test_allows_exact_host_and_https_scheme_case_insensitively(self):
        result = _handler().handle(
            "HTTPS://DOCS.EXAMPLE.TEST./guide",
            OutputContext.URL,
        )

        assert result.action == GuardAction.ALLOW

    @pytest.mark.parametrize(
        ("value", "code"),
        [
            ("javascript:alert(1)", OutputHandlingCode.URL_SCHEME_NOT_ALLOWED),
            ("https://attacker.invalid/", OutputHandlingCode.URL_HOST_NOT_ALLOWED),
            (
                "https://docs.example.test.attacker.invalid/",
                OutputHandlingCode.URL_HOST_NOT_ALLOWED,
            ),
            (
                "https://user:pass@docs.example.test/",
                OutputHandlingCode.URL_CREDENTIALS_NOT_ALLOWED,
            ),
            ("//attacker.invalid/path", OutputHandlingCode.URL_SCHEME_NOT_ALLOWED),
            ("https://docs.example.test:bad/", OutputHandlingCode.URL_INVALID),
            ("https://docs.example.test/a b", OutputHandlingCode.URL_INVALID),
        ],
    )
    def test_rejects_unsafe_urls(self, value: str, code: OutputHandlingCode):
        result = _handler().handle(value, OutputContext.URL)

        assert result.is_blocked
        assert result.findings[0].code == code

    def test_relative_url_requires_explicit_policy(self):
        assert _handler().handle("/guide", OutputContext.URL).is_blocked
        result = _handler(allow_relative_urls=True).handle("/guide", OutputContext.URL)
        assert result.action == GuardAction.ALLOW


class TestPathHandling:
    def test_path_requires_configured_root(self):
        result = _handler().handle("report.txt", OutputContext.PATH)

        assert result.is_blocked
        assert result.findings[0].code == OutputHandlingCode.PATH_ROOT_REQUIRED

    def test_resolves_relative_path_beneath_root(self, tmp_path: Path):
        resolved = _handler(path_root=tmp_path).resolve_path("reports/summary.txt")

        assert resolved == tmp_path / "reports" / "summary.txt"

    @pytest.mark.parametrize("value", ["../outside.txt", "/etc/passwd", "a/../../outside"])
    def test_rejects_paths_outside_root(self, tmp_path: Path, value: str):
        result = _handler(path_root=tmp_path).handle(value, OutputContext.PATH)

        assert result.is_blocked
        assert result.findings[0].code == OutputHandlingCode.PATH_OUTSIDE_ROOT


class TestInterpreterBoundaries:
    @pytest.mark.parametrize(
        "context",
        [
            OutputContext.SQL,
            OutputContext.SHELL,
            OutputContext.TEMPLATE,
            OutputContext.TOOL,
            OutputContext.CODE,
        ],
    )
    def test_raw_interpreter_and_tool_sinks_are_rejected(self, context: OutputContext):
        result = _handler().handle("apparently harmless", context)

        assert result.is_blocked
        assert result.safe_value is None
        assert result.findings[0].code == (OutputHandlingCode.RAW_INTERPRETER_SINK_REJECTED)

    def test_generated_code_can_only_be_returned_for_review(self):
        handler = _handler(allow_code_for_review=True)

        result = handler.handle("print('hello')", OutputContext.CODE)

        assert result.requires_approval
        with pytest.raises(OutputHandlingError):
            handler.require("print('hello')", OutputContext.CODE)

    def test_sql_parameter_preserves_quotes_as_data(self):
        value = "Robert'); DROP TABLE users;--"

        assert _handler().as_sql_parameter(value) == value

    def test_command_argument_allows_data_metacharacters_but_not_options(self):
        handler = _handler()

        assert handler.as_command_argument("$(not-executed)") == "$(not-executed)"
        with pytest.raises(OutputHandlingError) as exc_info:
            handler.as_command_argument("--output=/outside")
        assert exc_info.value.result.findings[0].code == (
            OutputHandlingCode.COMMAND_ARGUMENT_INVALID
        )


class TestStructuredOutput:
    def test_raw_json_context_requires_schema(self):
        result = _handler().handle('{"answer":"ok"}', OutputContext.JSON)

        assert result.is_blocked
        assert result.findings[0].code == OutputHandlingCode.STRUCTURED_SCHEMA_REQUIRED

    def test_parses_strict_typed_json(self):
        payload = _handler().parse_json(
            '{"answer":"ok","confidence":0.75}',
            AnswerPayload,
        )

        assert payload == AnswerPayload(answer="ok", confidence=0.75)

    @pytest.mark.parametrize(
        "value",
        [
            '{"answer":"ok","confidence":"0.75"}',
            '{"answer":"ok","confidence":0.75,"extra":true}',
            '{"answer":"first","answer":"second","confidence":0.5}',
            '{"answer":"ok","confidence":NaN}',
            "not-json",
        ],
    )
    def test_rejects_ambiguous_or_schema_invalid_json(self, value: str):
        with pytest.raises(OutputHandlingError) as exc_info:
            _handler().parse_json(value, AnswerPayload)

        assert exc_info.value.result.is_blocked

    def test_structural_depth_limit_fails_closed(self):
        with pytest.raises(OutputHandlingError) as exc_info:
            _handler(max_structured_depth=1).parse_json(
                '{"answer":"ok","confidence":0.5,"nested":{"value":1}}',
                AnswerPayload,
            )

        assert exc_info.value.result.findings[0].code == (
            OutputHandlingCode.STRUCTURED_LIMIT_EXCEEDED
        )

    def test_json_decoder_recursion_limit_fails_closed(self):
        deeply_nested = "[" * 2_000 + "]" * 2_000

        with pytest.raises(OutputHandlingError) as exc_info:
            _handler(max_structured_depth=128).parse_json(deeply_nested, AnswerPayload)

        assert exc_info.value.result.findings[0].code == (
            OutputHandlingCode.INVALID_STRUCTURED_OUTPUT
        )

    def test_tool_call_is_fixed_name_strictly_typed_and_not_executed(self):
        call = _handler().parse_tool_call(
            '{"name":"send_email","arguments":{"recipient_id":42,"subject":"Hello"}}',
            expected_name="send_email",
            arguments_schema=EmailArguments,
        )

        assert call.name == "send_email"
        assert call.arguments.recipient_id == 42
        assert call.requires_approval

    def test_model_cannot_select_a_different_tool(self):
        with pytest.raises(OutputHandlingError) as exc_info:
            _handler().parse_tool_call(
                '{"name":"delete_account","arguments":{}}',
                expected_name="send_email",
                arguments_schema=EmailArguments,
            )

        assert exc_info.value.result.findings[0].code == (OutputHandlingCode.TOOL_NAME_MISMATCH)

    def test_tool_arguments_do_not_coerce_types(self):
        with pytest.raises(OutputHandlingError):
            _handler().parse_tool_call(
                '{"name":"send_email","arguments":{"recipient_id":"42","subject":"x"}}',
                expected_name="send_email",
                arguments_schema=EmailArguments,
            )

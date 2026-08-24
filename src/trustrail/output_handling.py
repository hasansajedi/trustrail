"""Destination-aware handling for untrusted model output."""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generic, TypeVar
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, ValidationError

from trustrail.exceptions import OutputHandlingError
from trustrail.models.enums import GuardAction, OutputContext, Severity
from trustrail.models.output_handling import (
    OutputHandlingCode,
    OutputHandlingFinding,
    OutputHandlingPolicy,
    OutputHandlingResult,
)

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_RAW_HTML_RE = re.compile(
    r"(?:<\s*/?\s*[a-z][^>\n]{0,2000}>|<!--[^>\n]{0,2000}-->|<![A-Z][^>\n]{0,2000}>)",
    re.IGNORECASE,
)
_MARKDOWN_IMAGE_RE = re.compile(r"(?<!\\)!\[[^\]\n]{0,500}\](?:\s*\(|\s*\[)")
_MARKDOWN_IMAGE_LINK_RE = re.compile(r"!\[[^\]]{0,500}\]\(\s*<?([^\s)>]+)>?")
_MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[[^\]]{0,500}\]\(\s*<?([^\s)>]+)>?")
_MARKDOWN_REFERENCE_RE = re.compile(r"^\s*\[[^\]]{1,500}\]:\s*<?([^\s>]+)>?", re.MULTILINE)

TModel = TypeVar("TModel", bound=BaseModel)


class _ToolEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ValidatedToolCall(Generic[TModel]):
    """Parsed tool intent that still requires deterministic authorization/execution."""

    name: str
    arguments: TModel
    requires_approval: bool = True


class SafeOutputHandler:
    """Encode display output and reject unsafe interpreter boundaries by default."""

    def __init__(self, policy: OutputHandlingPolicy | None = None) -> None:
        self._policy = (policy or OutputHandlingPolicy()).model_copy(deep=True)
        self._path_root = (
            self._policy.path_root.expanduser().resolve(strict=False)
            if self._policy.path_root is not None
            else None
        )

    @property
    def policy(self) -> OutputHandlingPolicy:
        """Return a defensive copy of the active output policy."""
        return self._policy.model_copy(deep=True)

    def handle(self, value: str, context: OutputContext) -> OutputHandlingResult:
        """Return a destination-safe value or a fail-closed decision."""
        invalid = self._base_validation(value, context)
        if invalid is not None:
            return invalid

        if context == OutputContext.TEXT:
            return self._allow(context, value)
        if context == OutputContext.HTML:
            return self._transform(
                context,
                html.escape(value, quote=True),
                OutputHandlingCode.HTML_ENCODED,
                "Model output was encoded as HTML text",
            )
        if context == OutputContext.JAVASCRIPT:
            encoded = json.dumps(value, ensure_ascii=False)
            encoded = (
                encoded.replace("<", r"\u003c")
                .replace(">", r"\u003e")
                .replace("&", r"\u0026")
                .replace("\u2028", r"\u2028")
                .replace("\u2029", r"\u2029")
            )
            return self._transform(
                context,
                encoded,
                OutputHandlingCode.JAVASCRIPT_ENCODED,
                "Model output was encoded as a JavaScript string literal",
            )
        if context == OutputContext.MARKDOWN:
            return self._handle_markdown(value)
        if context == OutputContext.URL:
            return self._handle_url(value, context)
        if context == OutputContext.PATH:
            return self._handle_path(value)
        if context == OutputContext.JSON:
            return self._block(
                context,
                OutputHandlingCode.STRUCTURED_SCHEMA_REQUIRED,
                Severity.HIGH,
                "Structured model output requires an explicit Pydantic schema",
            )
        if context == OutputContext.CODE and self._policy.allow_code_for_review:
            return OutputHandlingResult(
                context=context,
                action=GuardAction.REQUIRE_APPROVAL,
                safe_value=value,
                findings=(
                    self._finding(
                        OutputHandlingCode.GENERATED_CODE_REQUIRES_REVIEW,
                        Severity.HIGH,
                        "Generated code requires external review before any execution",
                    ),
                ),
            )
        return self._block(
            context,
            OutputHandlingCode.RAW_INTERPRETER_SINK_REJECTED,
            Severity.CRITICAL,
            "Raw model output cannot be used as interpreter or tool input",
        )

    def require(self, value: str, context: OutputContext) -> str:
        """Return a safe value or raise before the destination consumes it."""
        result = self.handle(value, context)
        if not result.is_allowed or result.safe_value is None:
            raise OutputHandlingError(result=result)
        return result.safe_value

    def parse_json(self, value: str, schema: type[TModel]) -> TModel:
        """Parse JSON once, enforce structural bounds, and validate a strict schema."""
        parsed = self._load_json(value)
        try:
            return schema.model_validate(parsed, strict=True)
        except ValidationError as exc:
            raise OutputHandlingError(
                result=self._block(
                    OutputContext.JSON,
                    OutputHandlingCode.INVALID_STRUCTURED_OUTPUT,
                    Severity.HIGH,
                    "Structured model output does not match the required schema",
                )
            ) from exc

    def parse_tool_call(
        self,
        value: str,
        *,
        expected_name: str,
        arguments_schema: type[TModel],
        requires_approval: bool = True,
    ) -> ValidatedToolCall[TModel]:
        """Parse a fixed-name tool intent without executing it or granting authority."""
        parsed = self._load_json(value)
        try:
            envelope = _ToolEnvelope.model_validate(parsed, strict=True)
        except ValidationError as exc:
            raise OutputHandlingError(
                result=self._block(
                    OutputContext.TOOL,
                    OutputHandlingCode.INVALID_STRUCTURED_OUTPUT,
                    Severity.CRITICAL,
                    "Tool output does not match the required envelope",
                )
            ) from exc
        if envelope.name != expected_name:
            raise OutputHandlingError(
                result=self._block(
                    OutputContext.TOOL,
                    OutputHandlingCode.TOOL_NAME_MISMATCH,
                    Severity.CRITICAL,
                    "Model-selected tool name differs from the application contract",
                )
            )
        try:
            arguments = arguments_schema.model_validate(envelope.arguments, strict=True)
        except ValidationError as exc:
            raise OutputHandlingError(
                result=self._block(
                    OutputContext.TOOL,
                    OutputHandlingCode.INVALID_STRUCTURED_OUTPUT,
                    Severity.CRITICAL,
                    "Tool arguments do not match the required schema",
                )
            ) from exc
        return ValidatedToolCall(
            name=expected_name,
            arguments=arguments,
            requires_approval=requires_approval,
        )

    def as_sql_parameter(self, value: str) -> str:
        """Validate a value for binding as data in a prepared SQL statement."""
        return self.require(value, OutputContext.TEXT)

    def as_command_argument(self, value: str, *, allow_leading_hyphen: bool = False) -> str:
        """Validate one argv element for a fixed executable invoked without a shell."""
        invalid = self._base_validation(value, OutputContext.SHELL)
        if invalid is not None or (value.startswith("-") and not allow_leading_hyphen):
            result = invalid or self._block(
                OutputContext.SHELL,
                OutputHandlingCode.COMMAND_ARGUMENT_INVALID,
                Severity.HIGH,
                "Command argument could be interpreted as an option",
            )
            raise OutputHandlingError(result=result)
        return value

    def resolve_path(self, value: str) -> Path:
        """Resolve a model-selected relative path beneath the configured root."""
        result = self._handle_path(value)
        if result.is_blocked or result.safe_value is None:
            raise OutputHandlingError(result=result)
        return Path(result.safe_value)

    def _load_json(self, value: str) -> object:
        invalid = self._base_validation(value, OutputContext.JSON)
        if invalid is not None:
            raise OutputHandlingError(result=invalid)

        def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, nested in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = nested
            return result

        def reject_constant(_: str) -> None:
            raise ValueError("non-finite JSON number")

        try:
            parsed = json.loads(
                value,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_constant,
            )
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise OutputHandlingError(
                result=self._block(
                    OutputContext.JSON,
                    OutputHandlingCode.INVALID_STRUCTURED_OUTPUT,
                    Severity.HIGH,
                    "Model output is not strict, unambiguous JSON",
                )
            ) from exc
        if self._structured_limits_exceeded(parsed):
            raise OutputHandlingError(
                result=self._block(
                    OutputContext.JSON,
                    OutputHandlingCode.STRUCTURED_LIMIT_EXCEEDED,
                    Severity.HIGH,
                    "Structured model output exceeds configured depth or node limits",
                )
            )
        return parsed

    def _structured_limits_exceeded(self, value: object) -> bool:
        stack: list[tuple[object, int]] = [(value, 0)]
        nodes = 0
        while stack:
            current, depth = stack.pop()
            nodes += 1
            if (
                nodes > self._policy.max_structured_nodes
                or depth > self._policy.max_structured_depth
            ):
                return True
            if isinstance(current, dict):
                stack.extend((nested, depth + 1) for nested in current.values())
            elif isinstance(current, list):
                stack.extend((nested, depth + 1) for nested in current)
        return False

    def _handle_markdown(self, value: str) -> OutputHandlingResult:
        if not self._policy.allow_markdown_images and _MARKDOWN_IMAGE_RE.search(value):
            return self._block(
                OutputContext.MARKDOWN,
                OutputHandlingCode.MARKDOWN_IMAGE_NOT_ALLOWED,
                Severity.HIGH,
                "Markdown images are not allowed by output policy",
            )
        if _RAW_HTML_RE.search(value):
            return self._block(
                OutputContext.MARKDOWN,
                OutputHandlingCode.RAW_HTML_NOT_ALLOWED,
                Severity.HIGH,
                "Raw HTML is not allowed in Markdown output",
            )
        link_destinations = _MARKDOWN_LINK_RE.findall(value)
        reference_destinations = _MARKDOWN_REFERENCE_RE.findall(value)
        if (link_destinations or reference_destinations) and not self._policy.allow_markdown_links:
            return self._block(
                OutputContext.MARKDOWN,
                OutputHandlingCode.MARKDOWN_LINK_NOT_ALLOWED,
                Severity.HIGH,
                "Markdown links are not allowed by output policy",
            )
        destinations = link_destinations + reference_destinations
        if self._policy.allow_markdown_images:
            destinations.extend(_MARKDOWN_IMAGE_LINK_RE.findall(value))
        for destination in destinations:
            url_result = self._handle_url(destination, OutputContext.MARKDOWN)
            if url_result.is_blocked:
                return url_result
        return self._allow(OutputContext.MARKDOWN, value)

    def _handle_url(self, value: str, context: OutputContext) -> OutputHandlingResult:
        if any(character.isspace() for character in value):
            return self._block(
                context,
                OutputHandlingCode.URL_INVALID,
                Severity.HIGH,
                "URL output contains whitespace or is not a single URL",
            )
        try:
            parsed = urlsplit(value)
            _ = parsed.port
        except ValueError:
            return self._block(
                context,
                OutputHandlingCode.URL_INVALID,
                Severity.HIGH,
                "URL output is malformed",
            )
        if not parsed.scheme:
            if self._policy.allow_relative_urls and not parsed.netloc:
                return self._allow(context, value)
            return self._block(
                context,
                OutputHandlingCode.URL_SCHEME_NOT_ALLOWED,
                Severity.HIGH,
                "Relative or scheme-less URL output is not allowed",
            )
        if parsed.scheme.casefold() not in self._policy.allowed_url_schemes:
            return self._block(
                context,
                OutputHandlingCode.URL_SCHEME_NOT_ALLOWED,
                Severity.CRITICAL,
                "URL scheme is not allowed by output policy",
            )
        if parsed.username is not None or parsed.password is not None:
            return self._block(
                context,
                OutputHandlingCode.URL_CREDENTIALS_NOT_ALLOWED,
                Severity.CRITICAL,
                "Credentials are not allowed in model-generated URLs",
            )
        hostname = parsed.hostname.casefold().rstrip(".") if parsed.hostname else None
        if hostname is None:
            return self._block(
                context,
                OutputHandlingCode.URL_INVALID,
                Severity.HIGH,
                "URL output lacks a valid host",
            )
        if hostname not in self._policy.allowed_url_hosts:
            return self._block(
                context,
                OutputHandlingCode.URL_HOST_NOT_ALLOWED,
                Severity.HIGH,
                "URL host is not present in the output allowlist",
            )
        return self._allow(context, value)

    def _handle_path(self, value: str) -> OutputHandlingResult:
        invalid = self._base_validation(value, OutputContext.PATH)
        if invalid is not None:
            return invalid
        if self._path_root is None:
            return self._block(
                OutputContext.PATH,
                OutputHandlingCode.PATH_ROOT_REQUIRED,
                Severity.CRITICAL,
                "Path output requires an application-configured root directory",
            )
        candidate = Path(value)
        if candidate.is_absolute():
            return self._block(
                OutputContext.PATH,
                OutputHandlingCode.PATH_OUTSIDE_ROOT,
                Severity.CRITICAL,
                "Absolute model-generated paths are not allowed",
            )
        resolved = (self._path_root / candidate).resolve(strict=False)
        if not resolved.is_relative_to(self._path_root):
            return self._block(
                OutputContext.PATH,
                OutputHandlingCode.PATH_OUTSIDE_ROOT,
                Severity.CRITICAL,
                "Model-generated path escapes the configured root",
            )
        return self._allow(OutputContext.PATH, str(resolved))

    def _base_validation(self, value: str, context: OutputContext) -> OutputHandlingResult | None:
        if len(value) > self._policy.max_output_chars:
            return self._block(
                context,
                OutputHandlingCode.OUTPUT_TOO_LARGE,
                Severity.HIGH,
                "Model output exceeds the configured destination limit",
            )
        if _CONTROL_RE.search(value):
            return self._block(
                context,
                OutputHandlingCode.CONTROL_CHARACTER,
                Severity.HIGH,
                "Model output contains a disallowed control character",
            )
        return None

    @staticmethod
    def _allow(context: OutputContext, value: str) -> OutputHandlingResult:
        return OutputHandlingResult(
            context=context,
            action=GuardAction.ALLOW,
            safe_value=value,
        )

    @staticmethod
    def _transform(
        context: OutputContext,
        value: str,
        code: OutputHandlingCode,
        message: str,
    ) -> OutputHandlingResult:
        return OutputHandlingResult(
            context=context,
            action=GuardAction.TRANSFORM,
            safe_value=value,
            findings=(SafeOutputHandler._finding(code, Severity.INFO, message),),
        )

    @staticmethod
    def _block(
        context: OutputContext,
        code: OutputHandlingCode,
        severity: Severity,
        message: str,
    ) -> OutputHandlingResult:
        return OutputHandlingResult(
            context=context,
            action=GuardAction.BLOCK,
            findings=(SafeOutputHandler._finding(code, severity, message),),
        )

    @staticmethod
    def _finding(
        code: OutputHandlingCode,
        severity: Severity,
        message: str,
    ) -> OutputHandlingFinding:
        return OutputHandlingFinding(code=code, severity=severity, message=message)

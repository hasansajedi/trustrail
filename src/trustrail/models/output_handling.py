"""Typed models for destination-aware model output handling."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from trustrail.models.enums import GuardAction, OutputContext, Severity


class OutputHandlingCode(StrEnum):
    """Stable machine-readable output handling outcomes."""

    OUTPUT_TOO_LARGE = "output_too_large"
    CONTROL_CHARACTER = "control_character"
    HTML_ENCODED = "html_encoded"
    JAVASCRIPT_ENCODED = "javascript_encoded"
    RAW_HTML_NOT_ALLOWED = "raw_html_not_allowed"
    MARKDOWN_LINK_NOT_ALLOWED = "markdown_link_not_allowed"
    MARKDOWN_IMAGE_NOT_ALLOWED = "markdown_image_not_allowed"
    URL_INVALID = "url_invalid"
    URL_SCHEME_NOT_ALLOWED = "url_scheme_not_allowed"
    URL_HOST_NOT_ALLOWED = "url_host_not_allowed"
    URL_CREDENTIALS_NOT_ALLOWED = "url_credentials_not_allowed"
    PATH_ROOT_REQUIRED = "path_root_required"
    PATH_OUTSIDE_ROOT = "path_outside_root"
    RAW_INTERPRETER_SINK_REJECTED = "raw_interpreter_sink_rejected"
    GENERATED_CODE_REQUIRES_REVIEW = "generated_code_requires_review"
    STRUCTURED_SCHEMA_REQUIRED = "structured_schema_required"
    INVALID_STRUCTURED_OUTPUT = "invalid_structured_output"
    STRUCTURED_LIMIT_EXCEEDED = "structured_limit_exceeded"
    COMMAND_ARGUMENT_INVALID = "command_argument_invalid"
    TOOL_NAME_MISMATCH = "tool_name_mismatch"


class OutputHandlingPolicy(BaseModel):
    """Fail-closed defaults for model output destinations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_output_chars: int = Field(default=100_000, ge=1, le=10_000_000)
    allowed_url_schemes: frozenset[str] = frozenset({"https"})
    allowed_url_hosts: frozenset[str] = frozenset()
    allow_relative_urls: bool = False
    allow_markdown_links: bool = True
    allow_markdown_images: bool = False
    path_root: Path | None = None
    max_structured_depth: int = Field(default=16, ge=1, le=128)
    max_structured_nodes: int = Field(default=10_000, ge=1, le=1_000_000)
    allow_code_for_review: bool = False

    @field_validator("allowed_url_schemes")
    @classmethod
    def normalize_schemes(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(value.casefold() for value in values)

    @field_validator("allowed_url_hosts")
    @classmethod
    def normalize_hosts(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(value.casefold().rstrip(".") for value in values)


class OutputHandlingFinding(BaseModel):
    """Content-free explanation of an output handling decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: OutputHandlingCode
    severity: Severity
    message: str


class OutputHandlingResult(BaseModel):
    """Destination-aware decision with only a downstream-safe value."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    context: OutputContext
    action: GuardAction
    safe_value: str | None = None
    findings: tuple[OutputHandlingFinding, ...] = ()

    @property
    def is_blocked(self) -> bool:
        """Return whether downstream use must stop."""
        return self.action in (GuardAction.BLOCK, GuardAction.QUARANTINE)

    @property
    def is_allowed(self) -> bool:
        """Return whether the safe value may be used at this destination."""
        return not self.is_blocked and self.action != GuardAction.REQUIRE_APPROVAL

    @property
    def requires_approval(self) -> bool:
        """Return whether generated code requires an external review decision."""
        return self.action == GuardAction.REQUIRE_APPROVAL

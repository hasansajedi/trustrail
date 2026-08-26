"""Typed models for system-prompt construction and leakage controls."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from trustrail.models.enums import GuardAction, Severity


class SystemPromptDataClass(StrEnum):
    """Security classification for data considered for prompt interpolation."""

    PUBLIC = "public"
    BEHAVIOR = "behavior"
    PERSONAL_DATA = "personal_data"
    INTERNAL = "internal"
    SECURITY_CONFIGURATION = "security_configuration"
    AUTHORIZATION = "authorization"
    CREDENTIAL = "credential"
    SECRET = "secret"  # noqa: S105 - classification label, not a credential


class SystemPromptValidationCode(StrEnum):
    """Stable machine-readable system-prompt validation outcomes."""

    INVALID_TEMPLATE = "invalid_template"
    UNDECLARED_VARIABLE = "undeclared_variable"
    UNUSED_VARIABLE = "unused_variable"
    FORBIDDEN_DATA_CLASS = "forbidden_data_class"
    PROMPT_TOO_LARGE = "prompt_too_large"
    SENSITIVE_DATA_DETECTED = "sensitive_data_detected"
    AUTHORIZATION_LOGIC_DETECTED = "authorization_logic_detected"


class SystemPromptLeakageCode(StrEnum):
    """Stable machine-readable generated-output leakage outcomes."""

    OUTPUT_TOO_LARGE = "output_too_large"
    REFERENCE_TOO_LARGE = "reference_too_large"
    STRUCTURED_ECHO = "structured_echo"
    VERBATIM_FRAGMENT = "verbatim_fragment"
    ENCODED_FRAGMENT = "encoded_fragment"


class SystemPromptVariable(BaseModel):
    """One explicitly classified value for a ``{{name}}`` placeholder."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
    value: str = Field(min_length=1, max_length=100_000, exclude=True, repr=False)
    data_class: SystemPromptDataClass


class SystemPromptTemplate(BaseModel):
    """A versioned prompt template and its explicitly classified variables."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    template_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
    template: str = Field(min_length=1, max_length=100_000, exclude=True, repr=False)
    variables: tuple[SystemPromptVariable, ...] = ()

    @model_validator(mode="after")
    def validate_unique_variables(self) -> SystemPromptTemplate:
        names = [variable.name for variable in self.variables]
        if len(names) != len(set(names)):
            raise ValueError("system-prompt variable names must be unique")
        return self


def _forbidden_data_classes() -> frozenset[SystemPromptDataClass]:
    return frozenset(
        {
            SystemPromptDataClass.PERSONAL_DATA,
            SystemPromptDataClass.INTERNAL,
            SystemPromptDataClass.SECURITY_CONFIGURATION,
            SystemPromptDataClass.AUTHORIZATION,
            SystemPromptDataClass.CREDENTIAL,
            SystemPromptDataClass.SECRET,
        }
    )


class SystemPromptPolicy(BaseModel):
    """Fail-closed policy for content admitted to a system prompt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    forbidden_data_classes: frozenset[SystemPromptDataClass] = Field(
        default_factory=_forbidden_data_classes
    )
    reject_undeclared_variables: bool = True
    reject_unused_variables: bool = True
    reject_sensitive_data: bool = True
    reject_authorization_logic: bool = True
    max_prompt_chars: int = Field(default=32_000, ge=1, le=1_000_000)


class SystemPromptValidationFinding(BaseModel):
    """Content-free explanation for a prompt-construction rejection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: SystemPromptValidationCode
    severity: Severity
    message: str
    detector_rule_id: str | None = None


class ValidatedSystemPrompt(BaseModel):
    """Validated prompt content that is intentionally excluded from serialization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    template_id: str
    content: str = Field(exclude=True, repr=False)


class SystemPromptValidationResult(BaseModel):
    """Allow or block decision for a rendered system prompt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    findings: tuple[SystemPromptValidationFinding, ...] = ()
    validated_prompt: ValidatedSystemPrompt | None = None

    @property
    def is_valid(self) -> bool:
        return self.action == GuardAction.ALLOW and self.validated_prompt is not None

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK


class SystemPromptReference(BaseModel):
    """Private reference used to compare model output with a system prompt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
    content: str = Field(min_length=1, max_length=1_000_000, exclude=True, repr=False)

    @classmethod
    def from_validated(cls, prompt: ValidatedSystemPrompt) -> SystemPromptReference:
        """Create a leakage reference from a validated prompt."""
        return cls(prompt_id=prompt.template_id, content=prompt.content)


class SystemPromptLeakagePolicy(BaseModel):
    """Bounded deterministic comparison policy for generated model output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    min_fragment_chars: int = Field(default=32, ge=8, le=1_000)
    fragment_words: int = Field(default=8, ge=4, le=100)
    max_fragments_per_prompt: int = Field(default=512, ge=1, le=10_000)
    max_prompt_chars: int = Field(default=100_000, ge=1, le=1_000_000)
    max_output_chars: int = Field(default=100_000, ge=1, le=1_000_000)
    detect_encoded_output: bool = True
    detect_structured_echo: bool = True


class SystemPromptLeakageFinding(BaseModel):
    """Content-free explanation for blocked generated output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: SystemPromptLeakageCode
    severity: Severity
    message: str
    prompt_id: str | None = None


class SystemPromptLeakageResult(BaseModel):
    """Allow or block decision for generated output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    findings: tuple[SystemPromptLeakageFinding, ...] = ()

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK

    @property
    def is_safe(self) -> bool:
        return self.action == GuardAction.ALLOW

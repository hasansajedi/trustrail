"""Typed contracts for strict, lifecycle-bound structured model output."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_REFERENCE_PATTERN = r"^sha256:[0-9a-f]{64}$"

TStructured = TypeVar("TStructured", bound=BaseModel)


def structured_output_digest(value: str | bytes) -> str:
    """Return a domain-separated SHA-256 digest for structured-output data."""
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(b"trustrail:structured-output:v1\x00" + raw).hexdigest()


def structured_output_reference(value: str | bytes) -> str:
    """Return a content-safe reference for an application context identifier."""
    return f"sha256:{structured_output_digest(value)}"


def canonical_structured_output_json(value: Any) -> str:
    """Serialize JSON-compatible data with the structured-output canonical profile."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


class StructuredOutputUse(StrEnum):
    """Downstream boundaries that must verify a validated-output binding."""

    AUTHORIZATION = "authorization"
    APPROVAL = "approval"
    DISPLAY = "display"
    PERSISTENCE = "persistence"
    RENDERING = "rendering"
    EXECUTION = "execution"


class StructuredOutputPhase(StrEnum):
    """Lifecycle phase represented by a structured-output decision."""

    VALIDATION = "validation"
    BINDING = "binding"
    USE = "use"
    REPAIR = "repair"


class StructuredOutputCode(StrEnum):
    """Stable, content-free structured-output outcomes."""

    VALIDATED = "validated"
    BOUND = "bound"
    USE_AUTHORIZED = "use_authorized"
    INVALID_JSON = "invalid_json"
    DUPLICATE_KEY = "duplicate_key"
    NON_FINITE_NUMBER = "non_finite_number"
    AMBIGUOUS_ENCODING = "ambiguous_encoding"
    TRAILING_DATA = "trailing_data"
    STRUCTURE_LIMIT_EXCEEDED = "structure_limit_exceeded"
    UNDECLARED_FIELD = "undeclared_field"
    IMPLICIT_COERCION = "implicit_coercion"
    SCHEMA_MISMATCH = "schema_mismatch"
    SCHEMA_IDENTITY_CHANGED = "schema_identity_changed"
    SCHEMA_PARSER_DISAGREEMENT = "schema_parser_disagreement"
    TYPED_OUTPUT_MISMATCH = "typed_output_mismatch"
    USE_NOT_ALLOWED = "use_not_allowed"
    BINDING_MISMATCH = "binding_mismatch"
    VALIDATED_OBJECT_CHANGED = "validated_object_changed"
    REPAIR_EXHAUSTED = "repair_exhausted"
    REPAIR_SESSION_CLOSED = "repair_session_closed"


class StructuredOutputPolicy(BaseModel):
    """Fail-closed parser, schema, and repair limits."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_input_bytes: int = Field(default=1_000_000, ge=1, le=10_000_000)
    max_input_chars: int = Field(default=1_000_000, ge=1, le=10_000_000)
    max_depth: int = Field(default=24, ge=1, le=128)
    max_nodes: int = Field(default=20_000, ge=1, le=1_000_000)
    max_array_items: int = Field(default=1_000, ge=1, le=100_000)
    max_object_properties: int = Field(default=1_000, ge=1, le=100_000)
    max_number_chars: int = Field(default=128, ge=1, le=1_000)
    max_repair_attempts: int = Field(default=2, ge=1, le=10)
    require_closed_objects: bool = True
    require_bounded_arrays: bool = True
    require_discriminated_unions: bool = True
    reject_non_normalized_unicode: bool = True


@dataclass(frozen=True, slots=True)
class StructuredOutputContract(Generic[TStructured]):
    """Application-owned schema identity and its permitted downstream uses."""

    schema_id: str
    schema_version: str
    model: type[TStructured] = field(repr=False)
    allowed_uses: frozenset[StructuredOutputUse]
    policy: StructuredOutputPolicy = field(default_factory=StructuredOutputPolicy)

    def __post_init__(self) -> None:
        if re.fullmatch(_IDENTIFIER_PATTERN, self.schema_id) is None:
            raise ValueError("schema_id must be a bounded application identifier")
        if re.fullmatch(_IDENTIFIER_PATTERN, self.schema_version) is None:
            raise ValueError("schema_version must be a bounded application identifier")
        if not isinstance(self.model, type) or not issubclass(self.model, BaseModel):
            raise TypeError("model must be a Pydantic BaseModel type")
        if not self.allowed_uses:
            raise ValueError("allowed_uses must declare at least one downstream boundary")
        try:
            normalized_uses = frozenset(StructuredOutputUse(value) for value in self.allowed_uses)
        except ValueError as exc:
            raise ValueError("allowed_uses contains an unknown downstream boundary") from exc
        object.__setattr__(self, "allowed_uses", normalized_uses)
        if not isinstance(self.policy, StructuredOutputPolicy):
            raise TypeError("policy must be a StructuredOutputPolicy")
        object.__setattr__(self, "policy", self.policy.model_copy(deep=True))


class StructuredOutputFinding(BaseModel):
    """Content-free explanation of a structured-output decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: StructuredOutputCode
    severity: Severity
    message: str = Field(min_length=1, max_length=500)


class StructuredOutputDecision(BaseModel):
    """Content-free decision; invalid output and partial values are never retained."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: StructuredOutputPhase
    action: GuardAction
    schema_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    schema_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    schema_digest: str = Field(pattern=_DIGEST_PATTERN)
    object_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    use: StructuredOutputUse | None = None
    attempt: int | None = Field(default=None, ge=1, le=10)
    findings: tuple[StructuredOutputFinding, ...] = ()

    @property
    def is_allowed(self) -> bool:
        """Return whether this phase completed successfully."""
        return self.action == GuardAction.ALLOW


class StructuredOutputBinding(BaseModel):
    """Exact schema, object, destination, and application-context binding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    schema_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    schema_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    schema_digest: str = Field(pattern=_DIGEST_PATTERN)
    object_digest: str = Field(pattern=_DIGEST_PATTERN)
    use: StructuredOutputUse
    context_reference: str = Field(pattern=_REFERENCE_PATTERN)

    @property
    def binding_digest(self) -> str:
        """Return a deterministic digest of every binding field."""
        return structured_output_digest(
            canonical_structured_output_json(self.model_dump(mode="json"))
        )


@dataclass(frozen=True, slots=True)
class ValidatedStructuredOutput(Generic[TStructured]):
    """Opaque validated value that still requires an exact downstream binding."""

    schema_id: str
    schema_version: str
    schema_digest: str
    object_digest: str
    _canonical_json: str = field(repr=False)
    _value: TStructured = field(repr=False)


@dataclass(frozen=True, slots=True)
class AuthorizedStructuredOutput(Generic[TStructured]):
    """Defensive value copy authorized for one exact downstream boundary."""

    value: TStructured
    binding: StructuredOutputBinding


class StructuredOutputAuditEvent(BaseModel):
    """Content-free structured-output lifecycle evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    phase: StructuredOutputPhase
    code: StructuredOutputCode
    action: GuardAction
    schema_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    schema_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    schema_digest: str = Field(pattern=_DIGEST_PATTERN)
    object_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    use: StructuredOutputUse | None = None
    context_reference: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    attempt: int | None = Field(default=None, ge=1, le=10)

    @field_validator("timestamp")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value

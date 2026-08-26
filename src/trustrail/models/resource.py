"""Typed resource-consumption models for OWASP LLM10:2025."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from trustrail.models.enums import GuardAction, Severity


class ResourceOperationKind(StrEnum):
    """Kind of bounded model or agent work being reserved."""

    MODEL = "model"
    TOOL = "tool"


class CompressionFormat(StrEnum):
    """Compression formats supported by the bounded decompressor."""

    GZIP = "gzip"
    ZLIB = "zlib"


class ResourceLimitCode(StrEnum):
    """Stable machine-readable resource-limit outcomes."""

    INPUT_CHARS_EXCEEDED = "input_chars_exceeded"
    INPUT_BYTES_EXCEEDED = "input_bytes_exceeded"
    INPUT_TOKENS_EXCEEDED = "input_tokens_exceeded"
    OUTPUT_CHARS_EXCEEDED = "output_chars_exceeded"
    OUTPUT_BYTES_EXCEEDED = "output_bytes_exceeded"
    OUTPUT_TOKENS_EXCEEDED = "output_tokens_exceeded"
    NESTING_DEPTH_EXCEEDED = "nesting_depth_exceeded"
    COMPRESSED_BYTES_EXCEEDED = "compressed_bytes_exceeded"
    DECOMPRESSED_BYTES_EXCEEDED = "decompressed_bytes_exceeded"
    DECOMPRESSION_RATIO_EXCEEDED = "decompression_ratio_exceeded"
    INVALID_COMPRESSED_PAYLOAD = "invalid_compressed_payload"
    CONCATENATED_COMPRESSED_STREAM = "concatenated_compressed_stream"
    PRINCIPAL_CONCURRENCY_EXCEEDED = "principal_concurrency_exceeded"
    TENANT_CONCURRENCY_EXCEEDED = "tenant_concurrency_exceeded"
    PRINCIPAL_RATE_EXCEEDED = "principal_rate_exceeded"
    TENANT_RATE_EXCEEDED = "tenant_rate_exceeded"
    RETRY_LIMIT_EXCEEDED = "retry_limit_exceeded"
    TOOL_LOOP_LIMIT_EXCEEDED = "tool_loop_limit_exceeded"
    SESSION_DURATION_EXCEEDED = "session_duration_exceeded"
    SESSION_TOKEN_BUDGET_EXCEEDED = "session_token_budget_exceeded"  # noqa: S105
    RESERVATION_REPLAYED = "reservation_replayed"
    TRACKING_CAPACITY_EXCEEDED = "tracking_capacity_exceeded"
    LEASE_UNKNOWN = "lease_unknown"
    LEASE_EXPIRED = "lease_expired"


class ConsumptionBudgetPolicy(BaseModel):
    """Fail-closed limits for model calls, agent work, and decompression."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_input_chars: int = Field(default=100_000, ge=1, le=10_000_000)
    max_input_bytes: int = Field(default=400_000, ge=1, le=40_000_000)
    max_input_tokens: int = Field(default=8_192, ge=1, le=10_000_000)
    max_output_chars: int = Field(default=100_000, ge=1, le=10_000_000)
    max_output_bytes: int = Field(default=400_000, ge=1, le=40_000_000)
    max_output_tokens: int = Field(default=4_096, ge=1, le=10_000_000)
    max_nesting_depth: int = Field(default=100, ge=1, le=10_000)
    max_compressed_bytes: int = Field(default=10_000_000, ge=1, le=1_000_000_000)
    max_decompressed_bytes: int = Field(default=50_000_000, ge=1, le=1_000_000_000)
    max_decompression_ratio: float = Field(default=100.0, ge=1.0, le=100_000.0)
    max_concurrent_operations_per_principal: int = Field(default=2, ge=1, le=10_000)
    max_concurrent_operations_per_tenant: int = Field(default=20, ge=1, le=100_000)
    max_retries_per_operation: int = Field(default=2, ge=0, le=1_000)
    max_tool_actions_per_session: int = Field(default=100, ge=1, le=1_000_000)
    max_session_duration_seconds: float = Field(default=300.0, gt=0.0, le=604_800.0)
    max_session_tokens: int = Field(default=100_000, ge=1, le=1_000_000_000)
    request_window_seconds: float = Field(default=60.0, gt=0.0, le=86_400.0)
    max_requests_per_principal_window: int = Field(default=60, ge=1, le=1_000_000)
    max_requests_per_tenant_window: int = Field(default=600, ge=1, le=10_000_000)
    lease_timeout_seconds: float = Field(default=30.0, gt=0.0, le=86_400.0)
    max_tracked_sessions: int = Field(default=10_000, ge=1, le=10_000_000)
    max_tracked_reservations: int = Field(default=100_000, ge=1, le=100_000_000)


class ResourceIdentity(BaseModel):
    """Application-authenticated ownership and operation identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=256)
    session_id: str = Field(min_length=1, max_length=256)
    request_id: str = Field(min_length=1, max_length=256)
    operation_id: str = Field(min_length=1, max_length=256)


class ResourceReservationRequest(BaseModel):
    """Exact input and expected output for one model or tool operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    reservation_id: str = Field(min_length=1, max_length=256)
    identity: ResourceIdentity
    kind: ResourceOperationKind
    input_text: str = Field(max_length=10_000_000, exclude=True, repr=False)
    input_tokens: int = Field(ge=0, le=10_000_000)
    requested_output_tokens: int = Field(ge=0, le=10_000_000)


class ResourceCompletionRequest(BaseModel):
    """Actual output returned for an active resource lease."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    lease_id: str = Field(min_length=1, max_length=256)
    output_text: str = Field(max_length=10_000_000, exclude=True, repr=False)
    output_tokens: int = Field(ge=0, le=10_000_000)


class CompressedPayloadRequest(BaseModel):
    """Compressed bytes to decode within configured expansion limits."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=256)
    format: CompressionFormat
    payload: bytes = Field(max_length=1_000_000_000, exclude=True, repr=False)


class ResourceLease(BaseModel):
    """Opaque, short-lived permission to perform one bounded operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    lease_id: str
    reservation_id: str
    request_id: str
    session_id: str
    reserved_tokens: int
    requested_output_tokens: int
    timeout_seconds: float


class ResourceLimitFinding(BaseModel):
    """Content-free explanation for a denied resource operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ResourceLimitCode
    severity: Severity = Severity.CRITICAL
    message: str
    observed: int | float | None = None
    limit: int | float | None = None


class ResourceUsageSignal(BaseModel):
    """Low-cardinality counters suitable for audit and monitoring."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    session_tokens_reserved: int = 0
    session_tool_actions: int = 0
    principal_window_requests: int = 0
    tenant_window_requests: int = 0
    principal_active_operations: int = 0
    tenant_active_operations: int = 0


class ResourceBudgetResult(BaseModel):
    """Resource decision with an optional lease or approved private output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    findings: tuple[ResourceLimitFinding, ...] = ()
    signal: ResourceUsageSignal | None = None
    lease: ResourceLease | None = None
    approved_output: str | None = Field(default=None, exclude=True, repr=False)

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK


class DecompressionResult(BaseModel):
    """Content-free decompression decision with private allowed bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    findings: tuple[ResourceLimitFinding, ...] = ()
    compressed_bytes: int
    decompressed_bytes: int = 0
    expansion_ratio: float = 0.0
    decompressed_payload: bytes | None = Field(default=None, exclude=True, repr=False)

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK

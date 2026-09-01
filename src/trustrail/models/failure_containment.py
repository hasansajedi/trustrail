"""Typed contracts for containing cascading agent and dependency failures."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def _canonicalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _canonicalize(value.model_dump(mode="json"))
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _canonicalize(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        items = [_canonicalize(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    return value


def _digest(payload: Any) -> str:
    canonical = json.dumps(
        _canonicalize(payload),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


class DependencyHealth(StrEnum):
    """Application-declared dependency availability."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class DependencyCriticality(StrEnum):
    """Business impact if a dependency cannot safely complete work."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CircuitState(StrEnum):
    """Runtime state of a tenant-isolated dependency circuit."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class FailureSignal(StrEnum):
    """Bounded signals that can deny admission or open a circuit."""

    ERROR_RATE = "error_rate"
    LATENCY = "latency"
    COST = "cost"
    RETRY = "retry"
    RECURSION = "recursion"
    ABNORMAL_TOOL_CALL = "abnormal_tool_call"


class FailureContainmentCode(StrEnum):
    """Stable machine-readable cascading-failure findings."""

    REQUEST_INTEGRITY_INVALID = "request_integrity_invalid"
    DEPENDENCY_UNKNOWN = "dependency_unknown"
    TENANT_NOT_ALLOWED = "tenant_not_allowed"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    FAILURE_DOMAIN_OPEN = "failure_domain_open"
    CIRCUIT_OPEN = "circuit_open"
    HALF_OPEN_PROBE_ACTIVE = "half_open_probe_active"
    FALLBACK_REQUIRED = "fallback_required"
    FALLBACK_NOT_REQUIRED = "fallback_not_required"
    FALLBACK_UNKNOWN = "fallback_unknown"
    FALLBACK_NOT_ALLOWED = "fallback_not_allowed"
    FALLBACK_INTEGRITY_INVALID = "fallback_integrity_invalid"
    FALLBACK_UNAVAILABLE = "fallback_unavailable"
    RETRY_LIMIT_EXCEEDED = "retry_limit_exceeded"
    RETRY_SEQUENCE_INVALID = "retry_sequence_invalid"
    RECURSION_LIMIT_EXCEEDED = "recursion_limit_exceeded"
    COST_LIMIT_EXCEEDED = "cost_limit_exceeded"
    ABNORMAL_TOOL_CALL_LIMIT_EXCEEDED = "abnormal_tool_call_limit_exceeded"
    DUPLICATE_ATTEMPT = "duplicate_attempt"
    IDEMPOTENCY_KEY_REQUIRED = "idempotency_key_required"
    DUPLICATE_SIDE_EFFECT = "duplicate_side_effect"
    PERMIT_INVALID = "permit_invalid"
    PERMIT_EXPIRED = "permit_expired"
    PERMIT_REPLAYED = "permit_replayed"
    REPORT_INTEGRITY_INVALID = "report_integrity_invalid"
    REPORT_UNVERIFIABLE = "report_unverifiable"
    REPORT_MISMATCH = "report_mismatch"
    REPORT_REPLAYED = "report_replayed"
    DEPENDENCY_ERROR = "dependency_error"
    ERROR_RATE_THRESHOLD_EXCEEDED = "error_rate_threshold_exceeded"
    LATENCY_THRESHOLD_EXCEEDED = "latency_threshold_exceeded"
    COST_THRESHOLD_EXCEEDED = "cost_threshold_exceeded"
    TOOL_CALL_THRESHOLD_EXCEEDED = "tool_call_threshold_exceeded"
    HOOK_FAILED = "hook_failed"


class FailureContainmentEventKind(StrEnum):
    """Content-free lifecycle events emitted by failure containment."""

    ADMISSION_ALLOWED = "admission_allowed"
    ADMISSION_BLOCKED = "admission_blocked"
    OUTCOME_RECORDED = "outcome_recorded"
    CIRCUIT_OPENED = "circuit_opened"
    CIRCUIT_HALF_OPENED = "circuit_half_opened"
    CIRCUIT_CLOSED = "circuit_closed"
    DEGRADED_MODE_ENTERED = "degraded_mode_entered"
    CANCELLATION_REQUESTED = "cancellation_requested"
    COMPENSATION_REQUESTED = "compensation_requested"
    RECOVERY_REQUESTED = "recovery_requested"
    HOOK_FAILED = "hook_failed"


class CircuitBreakerPolicy(BaseModel):
    """Sliding-window thresholds for one dependency circuit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    window_size: int = Field(default=20, ge=1, le=10_000)
    minimum_samples: int = Field(default=5, ge=1, le=10_000)
    error_rate_threshold: float = Field(default=0.5, gt=0.0, le=1.0, allow_inf_nan=False)
    average_latency_ms_threshold: float = Field(default=5_000.0, gt=0.0, allow_inf_nan=False)
    cumulative_cost_threshold: float = Field(default=100.0, gt=0.0, allow_inf_nan=False)
    abnormal_tool_call_threshold: int = Field(default=5, ge=1, le=1_000_000)
    open_seconds: int = Field(default=30, ge=1, le=86_400)

    @model_validator(mode="after")
    def validate_samples(self) -> CircuitBreakerPolicy:
        if self.minimum_samples > self.window_size:
            raise ValueError("minimum_samples cannot exceed window_size")
        return self


class FailureDomainDeclaration(BaseModel):
    """A correlated failure boundary whose state is isolated per tenant."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    failure_domain_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    max_open_dependencies: int = Field(default=1, ge=1, le=10_000)
    isolate_by_tenant: Literal[True] = True


class DependencyDeclaration(BaseModel):
    """A dependency's trust boundary, impact, health, and breaker policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dependency_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    failure_domain_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    criticality: DependencyCriticality = DependencyCriticality.MEDIUM
    health: DependencyHealth = DependencyHealth.HEALTHY
    allowed_tenant_ids: frozenset[str] = Field(default_factory=frozenset, max_length=10_000)
    allowed_fallback_ids: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    breaker: CircuitBreakerPolicy = Field(default_factory=CircuitBreakerPolicy)


class FallbackDeclaration(BaseModel):
    """An integrity-pinned substitute for one primary dependency."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fallback_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    primary_dependency_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    target_dependency_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    artifact_digest: str = Field(pattern=_DIGEST_PATTERN)
    allowed_tenant_ids: frozenset[str] = Field(default_factory=frozenset, max_length=10_000)


class FailureContainmentPolicy(BaseModel):
    """Fail-closed limits and inventory for a complete agent workflow."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dependencies: tuple[DependencyDeclaration, ...] = Field(min_length=1, max_length=10_000)
    failure_domains: tuple[FailureDomainDeclaration, ...] = Field(min_length=1, max_length=10_000)
    fallbacks: tuple[FallbackDeclaration, ...] = Field(default_factory=tuple, max_length=10_000)
    max_retries_per_operation: int = Field(default=3, ge=0, le=1_000)
    max_recursion_depth: int = Field(default=8, ge=0, le=1_000)
    max_cost_per_attempt: float = Field(default=25.0, gt=0.0, allow_inf_nan=False)
    max_abnormal_tool_calls_per_attempt: int = Field(default=0, ge=0, le=1_000_000)
    permit_ttl_seconds: int = Field(default=60, ge=1, le=3_600)

    @model_validator(mode="after")
    def validate_inventory(self) -> FailureContainmentPolicy:
        dependencies = {item.dependency_id: item for item in self.dependencies}
        domains = {item.failure_domain_id: item for item in self.failure_domains}
        fallback_ids = {item.fallback_id for item in self.fallbacks}
        if len(dependencies) != len(self.dependencies):
            raise ValueError("dependency IDs must be unique")
        if len(domains) != len(self.failure_domains):
            raise ValueError("failure-domain IDs must be unique")
        if len(fallback_ids) != len(self.fallbacks):
            raise ValueError("fallback IDs must be unique")
        for dependency in self.dependencies:
            if dependency.failure_domain_id not in domains:
                raise ValueError("every dependency must reference a declared failure domain")
            if not dependency.allowed_fallback_ids.issubset(fallback_ids):
                raise ValueError("dependency references an undeclared fallback")
        for fallback in self.fallbacks:
            primary = dependencies.get(fallback.primary_dependency_id)
            target = dependencies.get(fallback.target_dependency_id)
            if primary is None or target is None:
                raise ValueError("fallback dependencies must be declared")
            if fallback.fallback_id not in primary.allowed_fallback_ids:
                raise ValueError("fallback must be allowlisted by its primary dependency")
            if primary.failure_domain_id == target.failure_domain_id:
                raise ValueError("fallback must use a different failure domain")
        return self


class FallbackSelection(BaseModel):
    """Caller-proposed fallback bound to its application-pinned artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fallback_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    artifact_digest: str = Field(pattern=_DIGEST_PATTERN)


class FailureContainmentRequest(BaseModel):
    """One dependency attempt proposed before network or tool dispatch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    attempt_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    operation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    dependency_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    retry_count: int = Field(default=0, ge=0, le=1_000_000)
    recursion_depth: int = Field(default=0, ge=0, le=1_000_000)
    expected_cost: float = Field(default=0.0, ge=0.0, allow_inf_nan=False)
    abnormal_tool_call_count: int = Field(default=0, ge=0, le=1_000_000)
    side_effecting: bool = False
    idempotency_key: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    fallback: FallbackSelection | None = None
    request_digest: str = Field(pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_request(self) -> FailureContainmentRequest:
        if self.side_effecting and self.idempotency_key is None:
            raise ValueError("side-effecting requests require an idempotency key")
        if not self.has_valid_integrity:
            raise ValueError("failure-containment request integrity check failed")
        return self

    @classmethod
    def create(cls, **values: Any) -> FailureContainmentRequest:
        """Create an attempt with a digest over every security-relevant field."""
        candidate = cls.model_construct(**values, request_digest="0" * 64)
        payload = candidate.model_dump(exclude={"request_digest"})
        return cls(**payload, request_digest=_digest(payload))

    @property
    def has_valid_integrity(self) -> bool:
        values = self.model_dump(exclude={"request_digest"})
        return self.request_digest == _digest(self._digest_payload(**values))

    @staticmethod
    def _digest_payload(**values: Any) -> dict[str, Any]:
        return dict(values)


class AuthorizedDependencyAttempt(BaseModel):
    """Short-lived, integrity-bound, single-use dependency dispatch permit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    permit_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    operation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    attempt_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    primary_dependency_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    selected_dependency_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    failure_domain_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    fallback_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    idempotency_key: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    issued_at: datetime
    expires_at: datetime
    permit_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_permit(self) -> AuthorizedDependencyAttempt:
        if self.expires_at <= self.issued_at:
            raise ValueError("permit expires_at must be after issued_at")
        if not self.has_valid_integrity:
            raise ValueError("dependency permit integrity check failed")
        return self

    @classmethod
    def create(cls, **values: Any) -> AuthorizedDependencyAttempt:
        candidate = cls.model_construct(**values, permit_digest="0" * 64)
        payload = candidate.model_dump(exclude={"permit_digest"})
        return cls(**payload, permit_digest=_digest(payload))

    @property
    def has_valid_integrity(self) -> bool:
        return self.permit_digest == _digest(self.model_dump(exclude={"permit_digest"}))


class DependencyOutcomeReport(BaseModel):
    """Terminal dependency evidence bound to an issued permit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    report_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    permit_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    permit_digest: str = Field(pattern=_DIGEST_PATTERN)
    success: bool
    latency_ms: float = Field(ge=0.0, allow_inf_nan=False)
    cost: float = Field(default=0.0, ge=0.0, allow_inf_nan=False)
    abnormal_tool_call_count: int = Field(default=0, ge=0, le=1_000_000)
    side_effect_committed: bool = False
    completed_at: datetime
    report_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("completed_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "completed_at")

    @model_validator(mode="after")
    def validate_report(self) -> DependencyOutcomeReport:
        if not self.has_valid_integrity:
            raise ValueError("dependency outcome report integrity check failed")
        return self

    @classmethod
    def create(cls, **values: Any) -> DependencyOutcomeReport:
        candidate = cls.model_construct(**values, report_digest="0" * 64)
        payload = candidate.model_dump(exclude={"report_digest"})
        return cls(**payload, report_digest=_digest(payload))

    @property
    def has_valid_integrity(self) -> bool:
        return self.report_digest == _digest(self.model_dump(exclude={"report_digest"}))


class FailureContainmentFinding(BaseModel):
    """Content-free explanation of a containment decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: FailureContainmentCode
    severity: Severity
    message: str = Field(min_length=1, max_length=500)
    signal: FailureSignal | None = None


class FailureContainmentAuditEvent(BaseModel):
    """Deterministic metadata-only evidence for containment transitions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(pattern=_DIGEST_PATTERN)
    sequence: int = Field(ge=1)
    kind: FailureContainmentEventKind
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    operation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    dependency_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    failure_domain_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    action: GuardAction
    circuit_state: CircuitState
    finding_codes: tuple[FailureContainmentCode, ...] = ()
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "occurred_at")

    @classmethod
    def create(cls, **values: Any) -> FailureContainmentAuditEvent:
        return cls(**values, event_id=_digest(values))


class DependencyCircuitSnapshot(BaseModel):
    """Read-only runtime health for one tenant and dependency."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    dependency_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    failure_domain_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    declared_health: DependencyHealth
    circuit_state: CircuitState
    sample_count: int = Field(ge=0)
    error_rate: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    average_latency_ms: float = Field(ge=0.0, allow_inf_nan=False)
    cumulative_cost: float = Field(ge=0.0, allow_inf_nan=False)
    abnormal_tool_call_count: int = Field(ge=0)


class FailureContainmentResult(BaseModel):
    """Admission or completion decision with content-free evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: GuardAction
    findings: tuple[FailureContainmentFinding, ...] = ()
    permit: AuthorizedDependencyAttempt | None = None
    events: tuple[FailureContainmentAuditEvent, ...] = ()

    @property
    def is_authorized(self) -> bool:
        return self.action == GuardAction.ALLOW and self.permit is not None

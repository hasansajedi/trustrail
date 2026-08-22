"""trustrail core domain models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from trustrail.models.enums import (
    GuardAction,
    GuardStage,
    MemoryWriteClassification,
    RuleCategory,
    Severity,
    TrustLevel,
)


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class GuardContext(BaseModel):
    """Contextual metadata for a guard evaluation."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str | None = None
    user_id: str | None = None
    tenant_id: str | None = None
    stage: GuardStage = GuardStage.USER_INPUT
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=_utcnow)


class GuardFinding(BaseModel):
    """A specific detection finding from a guard rule."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_name: str
    category: RuleCategory
    severity: Severity
    message: str
    # Offset range in the original text (no content stored)
    offset_start: int | None = None
    offset_end: int | None = None
    # Replacement text if redaction was applied
    redacted_value: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    owasp: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskScore(BaseModel):
    """Aggregate risk score for a guard evaluation."""

    model_config = ConfigDict(extra="forbid")

    value: int = Field(default=0, ge=0, le=100)
    block_at: int = Field(default=80, ge=0, le=100)
    warn_at: int = Field(default=40, ge=0, le=100)

    @property
    def should_block(self) -> bool:
        return self.value >= self.block_at

    @property
    def should_warn(self) -> bool:
        return self.value >= self.warn_at

    @classmethod
    def from_findings(
        cls,
        findings: list[GuardFinding],
        block_at: int = 80,
        warn_at: int = 40,
    ) -> RiskScore:
        """Calculate aggregate score from findings."""
        score = 0
        for finding in findings:
            if finding.severity == Severity.CRITICAL:
                score = 100
                break
            elif finding.severity == Severity.HIGH:
                score += 30
            elif finding.severity == Severity.MEDIUM:
                score += 15
            elif finding.severity == Severity.LOW:
                score += 5
            # INFO findings don't add to score
        return cls(value=min(score, 100), block_at=block_at, warn_at=warn_at)


class GuardDecision(BaseModel):
    """Decision made by a single guard rule."""

    model_config = ConfigDict(extra="forbid")

    action: GuardAction = GuardAction.ALLOW
    finding: GuardFinding | None = None
    transformed_value: str | None = None
    rule_id: str = ""
    latency_ms: float = 0.0


class GuardResult(BaseModel):
    """Final result of a complete guard evaluation."""

    model_config = ConfigDict(extra="forbid")

    action: GuardAction = GuardAction.ALLOW
    findings: list[GuardFinding] = Field(default_factory=list)
    score: RiskScore = Field(default_factory=RiskScore)
    value: str = ""
    transformed_value: str | None = None
    stage: GuardStage = GuardStage.USER_INPUT
    context: GuardContext | None = None
    latency_ms: float = 0.0
    rules_evaluated: int = 0
    timestamp: datetime = Field(default_factory=_utcnow)

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK

    @property
    def blocked(self) -> bool:
        return self.is_blocked

    @property
    def is_allowed(self) -> bool:
        return self.action in (GuardAction.ALLOW, GuardAction.WARN)

    @property
    def allowed(self) -> bool:
        return self.is_allowed

    @property
    def requires_approval(self) -> bool:
        """Return whether an out-of-band decision is required."""
        return self.action == GuardAction.REQUIRE_APPROVAL

    @property
    def risk(self) -> RiskScore:
        return self.score

    @property
    def original_value(self) -> str:
        return self.value

    @property
    def output_value(self) -> str:
        """Return the value to use downstream (transformed if applicable)."""
        return self.transformed_value if self.transformed_value is not None else self.value


class AuditEvent(BaseModel):
    """Structured audit event emitted after each guard evaluation."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=_utcnow)
    stage: GuardStage
    action: GuardAction
    score: int
    # Finding summaries (no sensitive content)
    finding_ids: list[str] = Field(default_factory=list)
    finding_categories: list[str] = Field(default_factory=list)
    finding_severities: list[str] = Field(default_factory=list)
    rules_evaluated: int = 0
    latency_ms: float = 0.0
    # Context metadata (no user content)
    request_id: str | None = None
    session_id: str | None = None
    user_id: str | None = None
    tenant_id: str | None = None
    # Input metadata (not content)
    input_length: int = 0
    tags: list[str] = Field(default_factory=list)
    memory_classification: MemoryWriteClassification | None = None
    memory_approval_outcome: (
        Literal[
            "required",
            "approved",
            "denied",
            "missing_provider",
            "provider_error",
        ]
        | None
    ) = None
    extra: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_result(cls, result: GuardResult) -> AuditEvent:
        """Create an AuditEvent from a GuardResult (no sensitive content)."""
        ctx = result.context
        memory_finding = next(
            (finding for finding in result.findings if finding.rule_id == "MEM-001"),
            None,
        )
        memory_classification: MemoryWriteClassification | None = None
        if memory_finding is not None:
            classification_value = memory_finding.metadata.get("classification")
            if isinstance(classification_value, str):
                memory_classification = next(
                    (
                        classification
                        for classification in MemoryWriteClassification
                        if classification.value == classification_value
                    ),
                    None,
                )
        return cls(
            stage=result.stage,
            action=result.action,
            score=result.score.value,
            finding_ids=[f.rule_id for f in result.findings],
            finding_categories=[f.category.value for f in result.findings],
            finding_severities=[f.severity.value for f in result.findings],
            rules_evaluated=result.rules_evaluated,
            latency_ms=result.latency_ms,
            request_id=ctx.request_id if ctx else None,
            session_id=ctx.session_id if ctx else None,
            user_id=ctx.user_id if ctx else None,
            tenant_id=ctx.tenant_id if ctx else None,
            input_length=len(result.value),
            tags=ctx.tags if ctx else [],
            memory_classification=memory_classification,
            memory_approval_outcome=(
                "required" if result.action == GuardAction.REQUIRE_APPROVAL else None
            ),
        )


class Message(BaseModel):
    """A single message in a conversation."""

    model_config = ConfigDict(extra="forbid")

    role: str  # "user", "assistant", "system", "tool"
    content: str
    name: str | None = None
    tool_call_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Document(BaseModel):
    """A retrieved document or external content."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    content: str
    source: str | None = None
    source_url: str | None = None
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolCall(BaseModel):
    """A tool/function call from the LLM."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    """Result returned from a tool invocation."""

    model_config = ConfigDict(extra="forbid")

    tool_call_id: str
    name: str
    content: str
    is_error: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

"""Structured prompt-boundary models for multi-source LLM requests."""

from __future__ import annotations

import uuid
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from trustrail.models.core import GuardFinding, GuardResult
from trustrail.models.enums import GuardAction, TrustLevel


class PromptSource(StrEnum):
    """Origin of a prompt segment before it enters an LLM request."""

    SYSTEM = "system"
    USER = "user"
    RAG = "rag"
    TOOL = "tool"
    MEMORY = "memory"
    EXTERNAL = "external"
    MULTIMODAL = "multimodal"


class PromptSegment(BaseModel):
    """One explicitly labeled piece of content in a composed prompt."""

    model_config = ConfigDict(extra="forbid")

    content: str
    source: PromptSource
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    segment_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    metadata: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class PromptSegmentResult(BaseModel):
    """Guard result associated with its original prompt-segment label."""

    model_config = ConfigDict(extra="forbid")

    segment: PromptSegment
    result: GuardResult

    @property
    def output_segment(self) -> PromptSegment:
        """Return a copy containing the normalized or transformed safe content."""
        return self.segment.model_copy(update={"content": self.result.output_value})


class PromptScanResult(BaseModel):
    """Aggregate result for a structured, multi-source prompt scan."""

    model_config = ConfigDict(extra="forbid")

    action: GuardAction
    segment_results: list[PromptSegmentResult]
    boundary_findings: list[GuardFinding] = Field(default_factory=list)

    @property
    def findings(self) -> list[GuardFinding]:
        """Return segment findings followed by content-free boundary findings."""
        segment_findings = [
            finding
            for segment_result in self.segment_results
            for finding in segment_result.result.findings
        ]
        return [*segment_findings, *self.boundary_findings]

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK

    @property
    def is_allowed(self) -> bool:
        return self.action in (GuardAction.ALLOW, GuardAction.WARN)

    @property
    def output_segments(self) -> list[PromptSegment]:
        """Return downstream-safe segments while preserving source labels."""
        return [segment_result.output_segment for segment_result in self.segment_results]

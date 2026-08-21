"""Models for risk-aware human confirmation prompts (ASI09)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ConfirmationPrompt(BaseModel):
    """Risk-aware confirmation prompt for high-impact agent actions."""

    model_config = ConfigDict(extra="forbid")

    action: str = Field(description="The action being performed")
    target: str | None = Field(
        default=None, description="Target of the action (file, resource, API, etc.)"
    )
    side_effects: list[str] = Field(
        default_factory=list, description="Known side effects of this action"
    )
    data_exposure: list[str] = Field(
        default_factory=list, description="Data that may be exposed or accessed"
    )
    is_reversible: bool = Field(
        default=True, description="Whether this action can be undone"
    )
    approval_rationale: str = Field(
        description="Why approval is needed for this action"
    )
    risk_level: str = Field(
        default="medium", description="Risk level: low, medium, high, critical"
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_prompt_text(self) -> str:
        """Generate human-readable confirmation prompt."""
        lines = [
            "=== ACTION CONFIRMATION REQUIRED ===",
            f"\nAction: {self.action}",
        ]

        if self.target:
            lines.append(f"Target: {self.target}")

        lines.append(f"\nRisk Level: {self.risk_level.upper()}")
        lines.append(f"Reversible: {'Yes' if self.is_reversible else 'No'}")

        if self.side_effects:
            lines.append("\nSide Effects:")
            for effect in self.side_effects:
                lines.append(f"  - {effect}")

        if self.data_exposure:
            lines.append("\nData Exposure:")
            for exposure in self.data_exposure:
                lines.append(f"  - {exposure}")

        lines.append(f"\nRationale: {self.approval_rationale}")
        lines.append("\n=== PLEASE REVIEW AND APPROVE ===")

        return "\n".join(lines)


class EvidenceRequirement(BaseModel):
    """Evidence requirement for high-impact agent recommendations (ASI09)."""

    model_config = ConfigDict(extra="forbid")

    recommendation: str = Field(description="The recommendation being made")
    sources: list[str] = Field(
        default_factory=list, description="Source URLs or references"
    )
    provenance: list[str] = Field(
        default_factory=list,
        description="Chain of reasoning or data provenance",
    )
    confidence_level: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Confidence level (0-1)"
    )
    uncertainty_statement: str | None = Field(
        default=None,
        description="Explicit statement of uncertainty or limitations",
    )
    impact_category: str = Field(
        description="Impact category: financial, legal, medical, security, operational"
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContentOriginMarker(BaseModel):
    """Marker for agent-generated content and external claims (ASI09)."""

    model_config = ConfigDict(extra="forbid")

    content_type: str = Field(
        description=(
            "Type: model_generated, retrieved_evidence, tool_result, "
            "external_claim, verified_fact"
        )
    )
    source: str | None = Field(default=None, description="Source of the content")
    is_verified: bool = Field(
        default=False, description="Whether content has been verified"
    )
    timestamp: str | None = Field(default=None, description="When content was generated/retrieved")
    metadata: dict[str, Any] = Field(default_factory=dict)

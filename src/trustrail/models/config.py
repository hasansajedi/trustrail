"""trustrail configuration models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from trustrail.models.enums import FailMode, GuardAction, RuleCategory, Severity


class RuleConfig(BaseModel):
    """Configuration for an individual guard rule."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    action: GuardAction = GuardAction.BLOCK
    severity_override: Severity | None = None
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    # Extra rule-specific parameters
    params: dict[str, Any] = Field(default_factory=dict)


class GuardPolicy(BaseModel):
    """Policy grouping related rules under a category."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    fail_mode: FailMode = FailMode.CLOSED
    rules: dict[str, RuleConfig] = Field(default_factory=dict)
    # Default action if no specific rule matches
    default_action: GuardAction = GuardAction.ALLOW
    params: dict[str, Any] = Field(default_factory=dict)


class GuardConfig(BaseModel):
    """Top-level configuration for the Guard engine."""

    model_config = ConfigDict(extra="forbid")

    # Global fail mode
    fail_mode: FailMode = FailMode.CLOSED

    # Risk scoring thresholds
    block_at: int = Field(default=80, ge=0, le=100)
    warn_at: int = Field(default=40, ge=0, le=100)

    # Per-category policies
    policies: dict[str, GuardPolicy] = Field(default_factory=dict)

    # Global rule overrides keyed by rule_id
    rule_overrides: dict[str, RuleConfig] = Field(default_factory=dict)

    # Audit settings
    audit_enabled: bool = True
    audit_include_metadata: bool = True

    # Performance settings
    max_text_length: int = Field(default=100_000, ge=1)
    timeout_seconds: float = Field(default=10.0, ge=0.1)

    # Normalize invisible Unicode channels before downstream rule evaluation
    strip_invisible_unicode: bool = True

    # Reject raw, unlabeled RAG context assembled without a structured envelope
    require_rag_context_labels: bool = True

    # Require an out-of-band human decision before persistent memory writes
    require_memory_write_approval: bool = True

    # Structured prompt-boundary scan limits
    max_prompt_segments: int = Field(default=64, ge=1, le=1_000)
    prompt_boundary_window: int = Field(default=512, ge=32, le=10_000)

    # Enable/disable entire categories
    enabled_categories: list[RuleCategory] | None = None  # None = all
    disabled_categories: list[RuleCategory] = Field(default_factory=list)

    @classmethod
    def default(cls) -> GuardConfig:
        """Sensible defaults with low false-positive rate."""
        return cls(
            fail_mode=FailMode.CLOSED,
            block_at=80,
            warn_at=40,
        )

    @classmethod
    def balanced(cls) -> GuardConfig:
        """Balanced security/usability."""
        return cls(
            fail_mode=FailMode.CLOSED,
            block_at=60,
            warn_at=30,
        )

    @classmethod
    def strict(cls) -> GuardConfig:
        """Maximum security, higher false-positive rate."""
        return cls(
            fail_mode=FailMode.CLOSED,
            block_at=40,
            warn_at=20,
        )

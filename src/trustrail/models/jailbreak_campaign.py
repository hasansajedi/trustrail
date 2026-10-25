"""Typed models for bounded cross-turn jailbreak campaign detection."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import Severity

_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_REFERENCE = r"^hmac-sha256:[0-9a-f]{64}$"


def _aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


class CampaignAction(StrEnum):
    """Application response to the accumulated conversation trajectory."""

    ALLOW = "allow"
    WARN = "warn"
    CHALLENGE = "challenge"
    THROTTLE = "throttle"
    CONTEXT_RESET = "context_reset"
    BLOCK = "block"


class CampaignSignalKind(StrEnum):
    """Privacy-safe evidence accumulated across ordered turns."""

    REPETITION = "repetition"
    EXAMPLE_ACCUMULATION = "example_accumulation"
    POLICY_BOUNDARY_PROBING = "policy_boundary_probing"
    FRAGMENT_RECONSTRUCTION = "fragment_reconstruction"
    ENCODING_SHIFT = "encoding_shift"
    RETRY_ESCALATION = "retry_escalation"
    POLICY_EROSION = "policy_erosion"


class CampaignEncodingKind(StrEnum):
    """Low-cardinality encoding characteristics retained for one turn."""

    PLAIN = "plain"
    BASE64 = "base64"
    HEX = "hex"
    ESCAPED_UNICODE = "escaped_unicode"
    INVISIBLE_UNICODE = "invisible_unicode"


class CampaignCode(StrEnum):
    """Stable failure and enforcement reason codes."""

    CAMPAIGN_RISK = "campaign_risk"
    EVENT_TOO_LARGE = "event_too_large"
    EVENT_STALE = "event_stale"
    SEQUENCE_REPLAY = "sequence_replay"
    SEQUENCE_GAP = "sequence_gap"
    TIMESTAMP_REGRESSION = "timestamp_regression"
    POLICY_CHANGED = "policy_changed"
    STATE_INVALID = "state_invalid"
    STATE_UNAVAILABLE = "state_unavailable"
    TRACKING_CAPACITY_EXCEEDED = "tracking_capacity_exceeded"
    ATOMIC_UPDATE_EXHAUSTED = "atomic_update_exhausted"


class CampaignResponseThresholds(BaseModel):
    """Monotonic score thresholds for progressively stronger responses."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    warn: int = Field(default=15, ge=0, le=100)
    challenge: int = Field(default=30, ge=0, le=100)
    throttle: int = Field(default=45, ge=0, le=100)
    context_reset: int = Field(default=60, ge=0, le=100)
    block: int = Field(default=80, ge=0, le=100)

    @model_validator(mode="after")
    def validate_order(self) -> CampaignResponseThresholds:
        values = (self.warn, self.challenge, self.throttle, self.context_reset, self.block)
        if tuple(sorted(values)) != values or len(set(values)) != len(values):
            raise ValueError("campaign response thresholds must be strictly increasing")
        return self


class JailbreakCampaignPolicy(BaseModel):
    """Bounded storage, feature, scoring, and response policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version: str = Field(pattern=_IDENTIFIER)
    session_ttl_seconds: int = Field(default=1_800, ge=1, le=86_400)
    max_turns: int = Field(default=64, ge=2, le=512)
    max_tracked_sessions: int = Field(default=10_000, ge=1, le=10_000_000)
    max_event_chars: int = Field(default=100_000, ge=1, le=1_000_000)
    max_event_age_seconds: int = Field(default=300, ge=1, le=86_400)
    max_future_skew_seconds: int = Field(default=5, ge=0, le=300)
    max_atomic_retries: int = Field(default=8, ge=1, le=100)
    initial_sequence: int = Field(default=0, ge=0)
    repetition_turns: int = Field(default=3, ge=2, le=100)
    example_markers: int = Field(default=6, ge=2, le=1_000)
    boundary_probes: int = Field(default=4, ge=2, le=1_000)
    policy_erosion_markers: int = Field(default=3, ge=2, le=1_000)
    retry_markers: int = Field(default=3, ge=2, le=1_000)
    encoding_kinds: int = Field(default=3, ge=2, le=len(CampaignEncodingKind))
    repetition_weight: int = Field(default=15, ge=0, le=100)
    example_weight: int = Field(default=20, ge=0, le=100)
    boundary_weight: int = Field(default=20, ge=0, le=100)
    fragment_weight: int = Field(default=80, ge=0, le=100)
    encoding_weight: int = Field(default=15, ge=0, le=100)
    retry_weight: int = Field(default=25, ge=0, le=100)
    erosion_weight: int = Field(default=30, ge=0, le=100)
    thresholds: CampaignResponseThresholds = Field(default_factory=CampaignResponseThresholds)
    throttle_seconds: int = Field(default=30, ge=1, le=86_400)
    critical_signals: frozenset[CampaignSignalKind] = Field(
        default_factory=lambda: frozenset({CampaignSignalKind.FRAGMENT_RECONSTRUCTION})
    )
    protected_fragments: tuple[str, ...] = (
        "ignore previous instructions",
        "reveal system prompt",
        "disable safety filters",
        "bypass security policy",
        "you are now unrestricted",
    )

    @field_validator("protected_fragments")
    @classmethod
    def validate_fragments(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) > 100:
            raise ValueError("protected_fragments must contain 1 to 100 phrases")
        normalized = tuple(
            "".join(character.casefold() for character in item if character.isalnum())
            for item in value
        )
        if any(len(item) < 8 or len(item) > 1_000 for item in normalized):
            raise ValueError("protected fragments must normalize to 8 to 1000 characters")
        if len(set(normalized)) != len(normalized):
            raise ValueError("protected fragments must be unique after normalization")
        return value


class JailbreakCampaignEvent(BaseModel):
    """One authenticated ordered user turn; content is never serialized."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(pattern=_IDENTIFIER)
    tenant_id: str = Field(pattern=_IDENTIFIER)
    user_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    sequence: int = Field(ge=0)
    occurred_at: datetime
    content: str = Field(max_length=1_000_000, exclude=True, repr=False)

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_at(cls, value: datetime) -> datetime:
        return _aware(value, "occurred_at")


class CampaignTurnFeatures(BaseModel):
    """Bounded, content-free feature record retained for one accepted turn."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int = Field(ge=0)
    event_ref: str = Field(pattern=_REFERENCE)
    content_ref: str = Field(pattern=_REFERENCE)
    occurred_at: datetime
    char_count: int = Field(ge=0)
    token_count: int = Field(ge=0)
    example_markers: int = Field(ge=0)
    boundary_probes: int = Field(ge=0)
    policy_erosion_markers: int = Field(ge=0)
    retry_markers: int = Field(ge=0)
    encodings: frozenset[CampaignEncodingKind] = Field(min_length=1)

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_at(cls, value: datetime) -> datetime:
        return _aware(value, "occurred_at")


class CampaignFragmentProgress(BaseModel):
    """Prefix-automaton progress without retained prompt fragments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fragment_ref: str = Field(pattern=_REFERENCE)
    matched_chars: int = Field(ge=0, le=1_000)


class JailbreakCampaignState(BaseModel):
    """Privacy-safe bounded state suitable for a shared CAS backend."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope_ref: str = Field(pattern=_REFERENCE)
    tenant_ref: str = Field(pattern=_REFERENCE)
    user_ref: str = Field(pattern=_REFERENCE)
    session_ref: str = Field(pattern=_REFERENCE)
    policy_version: str = Field(pattern=_IDENTIFIER)
    version: int = Field(ge=1)
    next_sequence: int = Field(ge=0)
    started_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    turns: tuple[CampaignTurnFeatures, ...] = Field(default=(), max_length=512)
    fragment_progress: tuple[CampaignFragmentProgress, ...] = Field(max_length=100)
    risk_score: int = Field(ge=0, le=100)
    last_action: CampaignAction

    @field_validator("started_at", "last_seen_at", "expires_at")
    @classmethod
    def validate_times(cls, value: datetime, info: Any) -> datetime:
        return _aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_state(self) -> JailbreakCampaignState:
        if not (self.started_at <= self.last_seen_at < self.expires_at):
            raise ValueError("campaign state timestamps are inconsistent")
        sequences = [turn.sequence for turn in self.turns]
        if sequences != sorted(set(sequences)):
            raise ValueError("campaign turn sequences must be unique and ordered")
        if sequences and sequences[-1] >= self.next_sequence:
            raise ValueError("next_sequence must follow every retained turn")
        refs = [item.fragment_ref for item in self.fragment_progress]
        if len(refs) != len(set(refs)):
            raise ValueError("fragment progress references must be unique")
        return self


class CampaignSignal(BaseModel):
    """Low-cardinality signal safe for decisions and telemetry."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: CampaignSignalKind
    score: int = Field(ge=0, le=100)
    observed: int = Field(ge=0)
    threshold: int = Field(ge=0)


class CampaignFinding(BaseModel):
    """Content-free campaign decision explanation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: CampaignCode
    severity: Severity
    message: str


class JailbreakCampaignResult(BaseModel):
    """Committed trajectory decision without raw prompt content or identifiers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: CampaignAction
    score: int = Field(ge=0, le=100)
    scope_ref: str = Field(pattern=_REFERENCE)
    event_ref: str = Field(pattern=_REFERENCE)
    state_version: int | None = Field(default=None, ge=1)
    next_sequence: int = Field(ge=0)
    signals: tuple[CampaignSignal, ...] = ()
    findings: tuple[CampaignFinding, ...] = ()
    retry_after_seconds: int | None = Field(default=None, ge=1)

    @property
    def may_forward(self) -> bool:
        """Whether policy permits the caller to continue to ordinary input checks."""
        return self.action in {CampaignAction.ALLOW, CampaignAction.WARN}

    @property
    def reset_required(self) -> bool:
        return self.action == CampaignAction.CONTEXT_RESET

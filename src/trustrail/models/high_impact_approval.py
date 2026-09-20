"""Typed contracts for complete, tamper-resistant high-impact approvals."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_REFERENCE_PATTERN = r"^sha256:[0-9a-f]{64}$"
_NONCE_PATTERN = r"^[A-Za-z0-9_-]{22,128}$"


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(tz=UTC)


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


def _normalize_json(value: JsonValue) -> JsonValue:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize_json(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, JsonValue] = {}
        for key, item in value.items():
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise ValueError("object keys must remain unique after Unicode normalization")
            normalized[normalized_key] = _normalize_json(item)
        return normalized
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite numbers are not valid approval parameters")
    return value


def canonical_approval_json(value: JsonValue) -> str:
    """Serialize JSON using the deterministic high-impact approval profile."""
    return json.dumps(
        _normalize_json(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def approval_reference(value: str | bytes) -> str:
    """Return a one-way reference suitable for content-free audit evidence."""
    encoded = value.encode() if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _digest(value: JsonValue) -> str:
    return hashlib.sha256(canonical_approval_json(value).encode()).hexdigest()


def _safe_display_text(value: str, field_name: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in normalized):
        raise ValueError(f"{field_name} must not contain control or formatting characters")
    return normalized


class HighImpactLevel(StrEnum):
    """Trusted impact classification assigned by application policy."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionReversibility(StrEnum):
    """Trusted reversibility classification for an action."""

    REVERSIBLE = "reversible"
    COMPENSATABLE = "compensatable"
    IRREVERSIBLE = "irreversible"


class HighImpactCategory(StrEnum):
    """Security-relevant action categories shown to an approver."""

    DESTRUCTIVE = "destructive"
    FINANCIAL = "financial"
    ADMINISTRATIVE = "administrative"
    EXTERNAL_VISIBILITY = "external_visibility"
    DATA_DISCLOSURE = "data_disclosure"
    CODE_EXECUTION = "code_execution"
    OTHER = "other"


class ApprovalParameterClass(StrEnum):
    """How one canonical parameter is highlighted in an approval preview."""

    STANDARD = "standard"
    RECIPIENT = "recipient"
    AMOUNT = "amount"
    PERMISSION_SCOPE = "permission_scope"
    COMMAND = "command"
    DIFF = "diff"
    EXTERNAL_VISIBILITY = "external_visibility"
    DATA_DISCLOSURE = "data_disclosure"


class ApprovalParameterKind(StrEnum):
    """Closed JSON value kinds accepted by an action parameter policy."""

    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"


class HighImpactApprovalOperation(StrEnum):
    """Operations represented in content-free approval audit events."""

    PREVIEW = "preview"
    AUTHORIZE = "authorize"


class HighImpactApprovalCode(StrEnum):
    """Stable machine-readable approval outcomes."""

    VERIFIED = "verified"
    APPROVAL_NOT_REQUIRED = "approval_not_required"
    APPROVAL_REQUIRED = "approval_required"
    UNKNOWN_ACTION = "unknown_action"
    HIDDEN_PARAMETER = "hidden_parameter"
    REQUIRED_PARAMETER_MISSING = "required_parameter_missing"
    PARAMETER_TYPE_MISMATCH = "parameter_type_mismatch"
    ACTOR_CONTEXT_MISMATCH = "actor_context_mismatch"
    PREVIEW_TOO_LARGE = "preview_too_large"
    APPROVAL_FATIGUE = "approval_fatigue"
    APPROVAL_SERVICE_UNAVAILABLE = "approval_service_unavailable"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_NOT_YET_VALID = "approval_not_yet_valid"
    APPROVAL_TTL_EXCEEDED = "approval_ttl_exceeded"
    APPROVER_DENIED = "approver_denied"
    PREVIEW_MISMATCH = "preview_mismatch"
    PLAN_MISMATCH = "plan_mismatch"
    POLICY_MISMATCH = "policy_mismatch"
    ACTOR_MISMATCH = "actor_mismatch"
    EXECUTION_CONTEXT_MISMATCH = "execution_context_mismatch"
    APPROVAL_REPLAYED = "approval_replayed"
    STATE_STORE_FULL = "state_store_full"
    STATE_STORE_ERROR = "state_store_error"


class HighImpactApprovalStateStatus(StrEnum):
    """Atomic fatigue- and approval-state claim outcomes."""

    STORED = "stored"
    FATIGUE = "fatigue"
    REPLAYED = "replayed"
    FULL = "full"


class ActionParameterPolicy(BaseModel):
    """Trusted schema and display treatment for one complete action parameter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=_IDENTIFIER_PATTERN)
    display_name: str = Field(min_length=1, max_length=128)
    kind: ApprovalParameterKind
    parameter_class: ApprovalParameterClass = ApprovalParameterClass.STANDARD
    required: bool = True

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        return _safe_display_text(value, "display_name")


class HighImpactActionPolicy(BaseModel):
    """Application-owned impact, reversibility, and preview schema for one action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    display_name: str = Field(min_length=1, max_length=256)
    categories: frozenset[HighImpactCategory] = Field(min_length=1, max_length=16)
    impact: HighImpactLevel
    reversibility: ActionReversibility
    parameters: tuple[ActionParameterPolicy, ...] = Field(max_length=256)
    side_effects: tuple[str, ...] = Field(default_factory=tuple, max_length=128)
    external_visibility: bool = False
    data_disclosure_categories: tuple[str, ...] = Field(default_factory=tuple, max_length=128)
    requires_approval: bool = True

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        return _safe_display_text(value, "display_name")

    @field_validator("side_effects", "data_disclosure_categories")
    @classmethod
    def validate_display_values(cls, values: tuple[str, ...], info: Any) -> tuple[str, ...]:
        normalized = tuple(_safe_display_text(value, info.field_name) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError(f"{info.field_name} must contain unique values")
        return normalized

    @model_validator(mode="after")
    def validate_parameters(self) -> HighImpactActionPolicy:
        names = [parameter.name for parameter in self.parameters]
        if len(names) != len(set(names)):
            raise ValueError("action parameter policies must have unique names")
        return self


class HighImpactApprovalPolicy(BaseModel):
    """Fail-closed preview, approval, fatigue, and plan-escalation policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    policy_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    actions: tuple[HighImpactActionPolicy, ...] = Field(min_length=1, max_length=10_000)
    allowed_approver_ids: frozenset[str] = Field(min_length=1, max_length=10_000)
    max_plan_actions: int = Field(default=50, ge=1, le=10_000)
    max_parameters_per_action: int = Field(default=128, ge=1, le=1_000)
    max_preview_bytes: int = Field(default=65_536, ge=1_024, le=10_000_000)
    max_approval_ttl_seconds: int = Field(default=300, ge=1, le=86_400)
    clock_skew_seconds: int = Field(default=30, ge=0, le=300)
    prompt_window_seconds: int = Field(default=300, ge=1, le=86_400)
    max_prompts_per_window: int = Field(default=5, ge=1, le=10_000)
    max_repeated_preview_prompts: int = Field(default=2, ge=1, le=1_000)
    chain_escalation_action_count: int = Field(default=2, ge=2, le=10_000)

    @field_validator("allowed_approver_ids")
    @classmethod
    def validate_approvers(cls, values: frozenset[str]) -> frozenset[str]:
        if any(re.fullmatch(_IDENTIFIER_PATTERN, value) is None for value in values):
            raise ValueError("allowed approver IDs contain an invalid identifier")
        return values

    @model_validator(mode="after")
    def validate_policy(self) -> HighImpactApprovalPolicy:
        action_ids = [action.action_id for action in self.actions]
        if len(action_ids) != len(set(action_ids)):
            raise ValueError("high-impact action policies must have unique action IDs")
        if self.max_plan_actions < self.chain_escalation_action_count:
            raise ValueError("max_plan_actions cannot be below chain escalation count")
        if any(len(action.parameters) > self.max_parameters_per_action for action in self.actions):
            raise ValueError("action schema exceeds max_parameters_per_action")
        return self

    @property
    def policy_digest(self) -> str:
        """Return the canonical digest of the complete trusted approval policy."""
        return _digest(cast(JsonValue, self.model_dump(mode="json")))


class ApprovalActor(BaseModel):
    """Authenticated actor and represented subject supplied by trusted code."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    actor_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    subject_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)


class ApprovalExecutionContext(BaseModel):
    """Trusted execution context to which an approval is restricted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    goal_digest: str = Field(pattern=_DIGEST_PATTERN)
    task_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    chain_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    environment: str = Field(pattern=_IDENTIFIER_PATTERN)

    @property
    def context_digest(self) -> str:
        """Return the canonical context binding included in an approval."""
        return _digest(cast(JsonValue, self.model_dump(mode="json")))


class ProposedHighImpactAction(BaseModel):
    """One exact action proposed for preview and later execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_instance_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    action_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    parameters: dict[str, JsonValue] = Field(default_factory=dict, max_length=1_000, repr=False)


class ProposedHighImpactPlan(BaseModel):
    """Complete ordered plan submitted to the high-impact approval boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    actor: ApprovalActor
    context: ApprovalExecutionContext
    actions: tuple[ProposedHighImpactAction, ...] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def validate_plan(self) -> ProposedHighImpactPlan:
        instance_ids = [action.action_instance_id for action in self.actions]
        if len(instance_ids) != len(set(instance_ids)):
            raise ValueError("action instance IDs must be unique within a plan")
        if self.actor.tenant_id != self.context.tenant_id:
            raise ValueError("actor and execution context tenants must match")
        return self

    @property
    def canonical_json(self) -> str:
        """Return the exact deterministic plan snapshot used for execution."""
        return canonical_approval_json(cast(JsonValue, self.model_dump(mode="json")))

    @property
    def plan_digest(self) -> str:
        """Return the exact proposed-plan digest."""
        return hashlib.sha256(self.canonical_json.encode()).hexdigest()


class HighImpactActionPreview(BaseModel):
    """Canonical, fully rendered preview metadata for one plan action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_instance_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    action_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    display_name: str
    categories: tuple[HighImpactCategory, ...]
    impact: HighImpactLevel
    reversibility: ActionReversibility
    parameter_digest: str = Field(pattern=_DIGEST_PATTERN)
    requires_approval: bool


class HighImpactPlanPreview(BaseModel):
    """Deterministic complete text shown by an independent approval service."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    policy_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    policy_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    policy_digest: str = Field(pattern=_DIGEST_PATTERN)
    plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    actor_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    execution_context_digest: str = Field(pattern=_DIGEST_PATTERN)
    overall_impact: HighImpactLevel
    chain_impact_escalated: bool
    approval_required: bool
    actions: tuple[HighImpactActionPreview, ...]
    rendered_text: str = Field(min_length=1, repr=False)
    preview_digest: str = Field(pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_preview_digest(self) -> HighImpactPlanPreview:
        expected = hashlib.sha256(self.rendered_text.encode()).hexdigest()
        if self.preview_digest != expected:
            raise ValueError("preview_digest does not match rendered_text")
        return self


class HighImpactApprovalGrant(BaseModel):
    """Authenticated, short-lived approval bound to one exact rendered preview."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    nonce: str = Field(pattern=_NONCE_PATTERN)
    preview_digest: str = Field(pattern=_DIGEST_PATTERN)
    plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    actor_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    policy_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    policy_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    policy_digest: str = Field(pattern=_DIGEST_PATTERN)
    execution_context_digest: str = Field(pattern=_DIGEST_PATTERN)
    approver_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_window(self) -> HighImpactApprovalGrant:
        if self.expires_at <= self.issued_at:
            raise ValueError("approval expires_at must be after issued_at")
        return self


class AuthorizedHighImpactPlan(BaseModel):
    """Immutable execution lease containing only the exact approved plan snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    approval_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    preview_digest: str = Field(pattern=_DIGEST_PATTERN)
    policy_digest: str = Field(pattern=_DIGEST_PATTERN)
    execution_context_digest: str = Field(pattern=_DIGEST_PATTERN)
    expires_at: datetime
    plan_json: str = Field(exclude=True, repr=False)

    @field_validator("expires_at")
    @classmethod
    def require_aware_expiry(cls, value: datetime) -> datetime:
        return _require_aware(value, "expires_at")

    @property
    def plan(self) -> ProposedHighImpactPlan:
        """Return a fresh typed copy of the exact authorized plan."""
        decoded = json.loads(self.plan_json)
        if not isinstance(decoded, dict):
            raise ValueError("authorized plan must decode to an object")
        return ProposedHighImpactPlan.model_validate(decoded)


class HighImpactApprovalFinding(BaseModel):
    """Content-free explanation of a high-impact approval decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: HighImpactApprovalCode
    severity: Severity
    message: str = Field(min_length=1, max_length=500)


class HighImpactApprovalAuditEvent(BaseModel):
    """Metadata-only evidence for preview and authorization decisions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    occurred_at: datetime
    operation: HighImpactApprovalOperation
    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK, GuardAction.REQUIRE_APPROVAL]
    code: HighImpactApprovalCode
    plan_ref: str = Field(pattern=_REFERENCE_PATTERN)
    actor_ref: str = Field(pattern=_REFERENCE_PATTERN)
    tenant_ref: str = Field(pattern=_REFERENCE_PATTERN)
    session_ref: str = Field(pattern=_REFERENCE_PATTERN)
    policy_ref: str = Field(pattern=_REFERENCE_PATTERN)
    preview_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    approval_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    action_count: int = Field(ge=1, le=10_000)
    overall_impact: HighImpactLevel | None = None
    chain_impact_escalated: bool = False

    @field_validator("occurred_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "occurred_at")


class HighImpactApprovalResult(BaseModel):
    """Allow, block, or exact-approval-required decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK, GuardAction.REQUIRE_APPROVAL]
    findings: tuple[HighImpactApprovalFinding, ...] = ()
    preview: HighImpactPlanPreview | None = None
    authorization: AuthorizedHighImpactPlan | None = None
    audit_event: HighImpactApprovalAuditEvent

    @property
    def is_authorized(self) -> bool:
        return self.action == GuardAction.ALLOW and self.authorization is not None

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK

    @property
    def requires_approval(self) -> bool:
        return self.action == GuardAction.REQUIRE_APPROVAL and self.preview is not None

"""Typed contracts for signed persistent agent state and execution chains."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_KEY_ID_PATTERN = r"^sha256:[0-9a-f]{64}$"
_SIGNATURE_PATTERN = r"^[0-9a-f]{128}$"
EMPTY_CHAIN_DIGEST = hashlib.sha256(b"trustrail:workflow-chain:empty:v1").hexdigest()


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


def _canonicalize(value: JsonValue) -> JsonValue:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, JsonValue] = {}
        for key, item in value.items():
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise ValueError("object keys must remain unique after Unicode normalization")
            normalized[normalized_key] = _canonicalize(item)
        return normalized
    return value


def canonical_workflow_json(value: JsonValue) -> str:
    """Serialize JSON using the deterministic workflow signing profile."""
    return json.dumps(
        _canonicalize(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def workflow_digest(value: JsonValue) -> str:
    """Return a canonical SHA-256 digest without retaining workflow content."""
    return hashlib.sha256(canonical_workflow_json(value).encode()).hexdigest()


def workflow_reference(value: str | bytes) -> str:
    """Return a one-way reference suitable for content-free evidence."""
    encoded = value.encode() if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


class WorkflowExecutionEventKind(StrEnum):
    """Security-relevant events retained in the execution chain."""

    PLAN_ACCEPTED = "plan_accepted"
    ACTION_AUTHORIZED = "action_authorized"
    ACTION_STARTED = "action_started"
    ACTION_COMPLETED = "action_completed"
    ACTION_FAILED = "action_failed"
    ACTION_CANCELLED = "action_cancelled"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_RESOLVED = "approval_resolved"
    CHECKPOINT_CREATED = "checkpoint_created"


class PendingActionStatus(StrEnum):
    """Persistable non-terminal action states."""

    AUTHORIZED = "authorized"
    IN_PROGRESS = "in_progress"
    AWAITING_APPROVAL = "awaiting_approval"


class WorkflowIntegrityPhase(StrEnum):
    """Persistent-state operation represented in audit evidence."""

    SIGN_ENTRY = "sign_entry"
    SIGN_CHECKPOINT = "sign_checkpoint"
    VERIFY_RESUME = "verify_resume"
    REVOKE = "revoke"


class WorkflowResumeClaimStatus(StrEnum):
    """Atomic resume-claim outcome."""

    CLAIMED = "claimed"
    REPLAYED = "replayed"
    ROLLBACK = "rollback"
    OUT_OF_ORDER = "out_of_order"
    COLLISION = "collision"
    FULL = "full"


class WorkflowIntegrityCode(StrEnum):
    """Stable, content-free persistent-state verification outcomes."""

    RESUME_ALLOWED = "resume_allowed"
    CHECKPOINT_UNSIGNED = "checkpoint_unsigned"
    CHECKPOINT_SIGNATURE_INVALID = "checkpoint_signature_invalid"
    CHECKPOINT_KEY_UNKNOWN = "checkpoint_key_unknown"
    CHECKPOINT_KEY_INACTIVE = "checkpoint_key_inactive"
    CHECKPOINT_NOT_YET_VALID = "checkpoint_not_yet_valid"
    CHECKPOINT_EXPIRED = "checkpoint_expired"
    CHECKPOINT_TOO_OLD = "checkpoint_too_old"
    CHECKPOINT_TTL_EXCEEDED = "checkpoint_ttl_exceeded"
    CHECKPOINT_CONTEXT_MISMATCH = "checkpoint_context_mismatch"
    CHECKPOINT_CHAIN_MISMATCH = "checkpoint_chain_mismatch"
    PRIOR_STATE_MISMATCH = "prior_state_mismatch"
    EXECUTION_ENTRY_UNSIGNED = "execution_entry_unsigned"
    EXECUTION_SIGNATURE_INVALID = "execution_signature_invalid"
    EXECUTION_KEY_UNKNOWN = "execution_key_unknown"
    EXECUTION_KEY_INACTIVE = "execution_key_inactive"
    EXECUTION_CONTEXT_MISMATCH = "execution_context_mismatch"
    EXECUTION_INSERTION = "execution_insertion"
    EXECUTION_DELETION = "execution_deletion"
    EXECUTION_REORDERED = "execution_reordered"
    EXECUTION_TIME_INVALID = "execution_time_invalid"
    BUDGET_INVALID = "budget_invalid"
    POLICY_MISMATCH = "policy_mismatch"
    PENDING_ACTION_INVALID = "pending_action_invalid"
    PENDING_APPROVAL_EXPIRED = "pending_approval_expired"
    AUTHORIZATION_DENIED = "authorization_denied"
    AUTHORIZATION_UNAVAILABLE = "authorization_unavailable"
    WORKFLOW_REVOKED = "workflow_revoked"
    REVOCATION_UNAVAILABLE = "revocation_unavailable"
    RESUME_REPLAYED = "resume_replayed"
    ROLLBACK_DETECTED = "rollback_detected"
    RESUME_STATE_UNAVAILABLE = "resume_state_unavailable"


class WorkflowBudgetState(BaseModel):
    """Persisted use of one finite workflow budget."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    budget_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    limit: int = Field(ge=0, le=9_223_372_036_854_775_807)
    consumed: int = Field(ge=0, le=9_223_372_036_854_775_807)
    reserved: int = Field(default=0, ge=0, le=9_223_372_036_854_775_807)

    @model_validator(mode="after")
    def validate_usage(self) -> WorkflowBudgetState:
        if self.consumed + self.reserved > self.limit:
            raise ValueError("consumed and reserved budget must not exceed the limit")
        return self


class WorkflowPolicyVersion(BaseModel):
    """Exact policy revision governing a persisted workflow."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    version: int = Field(ge=1, le=2_147_483_647)
    policy_digest: str = Field(pattern=_DIGEST_PATTERN)


class PendingActionBinding(BaseModel):
    """Content-free binding for a resumable, non-terminal action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    action_digest: str = Field(pattern=_DIGEST_PATTERN)
    authorization_digest: str = Field(pattern=_DIGEST_PATTERN)
    status: PendingActionStatus
    created_at: datetime
    expires_at: datetime

    @field_validator("created_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> PendingActionBinding:
        if self.expires_at <= self.created_at:
            raise ValueError("pending action expires_at must be after created_at")
        return self


class PendingApprovalBinding(BaseModel):
    """Content-free binding for approval that remains pending at checkpoint time."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    action_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    action_digest: str = Field(pattern=_DIGEST_PATTERN)
    approval_request_digest: str = Field(pattern=_DIGEST_PATTERN)
    requested_at: datetime
    expires_at: datetime

    @field_validator("requested_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> PendingApprovalBinding:
        if self.expires_at <= self.requested_at:
            raise ValueError("pending approval expires_at must be after requested_at")
        return self


class WorkflowExecutionEntry(BaseModel):
    """Individually signed link in an append-only workflow execution chain."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    chain_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    sequence: int = Field(ge=0, le=9_223_372_036_854_775_807)
    entry_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    event_kind: WorkflowExecutionEventKind
    key_id: str = Field(pattern=_KEY_ID_PATTERN)
    authority_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    workflow_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    agent_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    goal_digest: str = Field(pattern=_DIGEST_PATTERN)
    plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    action_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    authorization_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    outcome_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    prior_entry_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    occurred_at: datetime
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @field_validator("occurred_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "occurred_at")

    @model_validator(mode="after")
    def validate_link(self) -> WorkflowExecutionEntry:
        if self.sequence == 0 and self.prior_entry_digest is not None:
            raise ValueError("genesis execution entry must not have a prior digest")
        if self.sequence > 0 and self.prior_entry_digest is None:
            raise ValueError("non-genesis execution entry must bind its predecessor")
        action_events = {
            WorkflowExecutionEventKind.ACTION_AUTHORIZED,
            WorkflowExecutionEventKind.ACTION_STARTED,
            WorkflowExecutionEventKind.ACTION_COMPLETED,
            WorkflowExecutionEventKind.ACTION_FAILED,
            WorkflowExecutionEventKind.ACTION_CANCELLED,
            WorkflowExecutionEventKind.APPROVAL_REQUESTED,
            WorkflowExecutionEventKind.APPROVAL_RESOLVED,
        }
        if self.event_kind in action_events and self.action_digest is None:
            raise ValueError("action and approval events require action_digest")
        if (
            self.event_kind == WorkflowExecutionEventKind.ACTION_AUTHORIZED
            and self.authorization_digest is None
        ):
            raise ValueError("authorized action events require authorization_digest")
        return self

    @property
    def signing_payload(self) -> dict[str, JsonValue]:
        return self.model_dump(mode="json", exclude={"signature"})

    @property
    def signing_bytes(self) -> bytes:
        return canonical_workflow_json(self.signing_payload).encode()

    @property
    def entry_digest(self) -> str:
        signature = self.signature or "unsigned"
        return hashlib.sha256(self.signing_bytes + signature.encode()).hexdigest()


class PersistentWorkflowCheckpoint(BaseModel):
    """Canonical signed continuity record for one resumable agent workflow."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    checkpoint_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    checkpoint_sequence: int = Field(ge=0, le=9_223_372_036_854_775_807)
    key_id: str = Field(pattern=_KEY_ID_PATTERN)
    authority_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    workflow_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    agent_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    goal_digest: str = Field(pattern=_DIGEST_PATTERN)
    plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    budgets: tuple[WorkflowBudgetState, ...] = Field(default_factory=tuple, max_length=10_000)
    policy_versions: tuple[WorkflowPolicyVersion, ...] = Field(
        min_length=1,
        max_length=10_000,
    )
    pending_actions: tuple[PendingActionBinding, ...] = Field(
        default_factory=tuple,
        max_length=100_000,
    )
    pending_approvals: tuple[PendingApprovalBinding, ...] = Field(
        default_factory=tuple,
        max_length=100_000,
    )
    resume_authorization_digest: str = Field(pattern=_DIGEST_PATTERN)
    chain_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    execution_chain_length: int = Field(ge=0, le=10_000_000)
    execution_chain_head_digest: str = Field(pattern=_DIGEST_PATTERN)
    prior_checkpoint_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    issued_at: datetime
    expires_at: datetime
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_checkpoint(self) -> PersistentWorkflowCheckpoint:
        if self.expires_at <= self.issued_at:
            raise ValueError("checkpoint expires_at must be after issued_at")
        if self.checkpoint_sequence == 0 and self.prior_checkpoint_digest is not None:
            raise ValueError("genesis checkpoint must not bind a predecessor")
        if self.checkpoint_sequence > 0 and self.prior_checkpoint_digest is None:
            raise ValueError("non-genesis checkpoint must bind its predecessor")
        budget_ids = [item.budget_id for item in self.budgets]
        if len(budget_ids) != len(set(budget_ids)) or budget_ids != sorted(budget_ids):
            raise ValueError("budgets must be unique and sorted by budget_id")
        policy_ids = [item.policy_id for item in self.policy_versions]
        if len(policy_ids) != len(set(policy_ids)) or policy_ids != sorted(policy_ids):
            raise ValueError("policy_versions must be unique and sorted by policy_id")
        action_ids = [item.action_id for item in self.pending_actions]
        if len(action_ids) != len(set(action_ids)) or action_ids != sorted(action_ids):
            raise ValueError("pending_actions must be unique and sorted by action_id")
        approval_ids = [item.approval_id for item in self.pending_approvals]
        if len(approval_ids) != len(set(approval_ids)) or approval_ids != sorted(approval_ids):
            raise ValueError("pending_approvals must be unique and sorted by approval_id")
        actions = {item.action_id: item for item in self.pending_actions}
        for approval in self.pending_approvals:
            action = actions.get(approval.action_id)
            if action is None or action.action_digest != approval.action_digest:
                raise ValueError("pending approval must bind a matching pending action")
            if action.status != PendingActionStatus.AWAITING_APPROVAL:
                raise ValueError("pending approval action must await approval")
        expected_head = EMPTY_CHAIN_DIGEST if self.execution_chain_length == 0 else None
        if expected_head is not None and self.execution_chain_head_digest != expected_head:
            raise ValueError("empty execution chain must use the empty-chain digest")
        return self

    @property
    def signing_payload(self) -> dict[str, JsonValue]:
        return self.model_dump(mode="json", exclude={"signature"})

    @property
    def signing_bytes(self) -> bytes:
        return canonical_workflow_json(self.signing_payload).encode()

    @property
    def checkpoint_digest(self) -> str:
        signature = self.signature or "unsigned"
        return hashlib.sha256(self.signing_bytes + signature.encode()).hexdigest()


class PersistedWorkflowState(BaseModel):
    """Persisted checkpoint plus the complete signed execution-chain evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    checkpoint: PersistentWorkflowCheckpoint
    execution_chain: tuple[WorkflowExecutionEntry, ...] = Field(
        default_factory=tuple,
        max_length=10_000_000,
    )


class WorkflowIntegrityTrustedKey(BaseModel):
    """Out-of-band public key for a checkpoint and execution authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authority_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    public_key: bytes = Field(min_length=32, max_length=32, exclude=True, repr=False)
    active_from: datetime | None = None
    expires_at: datetime | None = None
    revoked: bool = False

    @field_validator("active_from", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime | None, info: Any) -> datetime | None:
        if value is not None:
            return _require_aware(value, info.field_name)
        return value

    @model_validator(mode="after")
    def validate_lifetime(self) -> WorkflowIntegrityTrustedKey:
        if (
            self.active_from is not None
            and self.expires_at is not None
            and self.expires_at <= self.active_from
        ):
            raise ValueError("trusted key expires_at must be after active_from")
        return self

    @property
    def key_id(self) -> str:
        return workflow_reference(self.public_key)


class WorkflowIntegrityPolicy(BaseModel):
    """Fail-closed verification and persistence limits."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    version: int = Field(ge=1)
    trusted_authority_ids: frozenset[str] = Field(min_length=1, max_length=1_000)
    maximum_checkpoint_ttl_seconds: int = Field(default=3_600, ge=1, le=86_400)
    maximum_checkpoint_age_seconds: int = Field(default=900, ge=1, le=86_400)
    clock_skew_seconds: int = Field(default=30, ge=0, le=300)
    maximum_chain_entries: int = Field(default=100_000, ge=1, le=10_000_000)
    maximum_pending_actions: int = Field(default=10_000, ge=0, le=100_000)
    maximum_pending_approvals: int = Field(default=10_000, ge=0, le=100_000)
    resume_permit_ttl_seconds: int = Field(default=60, ge=1, le=900)

    @field_validator("trusted_authority_ids")
    @classmethod
    def validate_authorities(cls, values: frozenset[str]) -> frozenset[str]:
        if any(re.fullmatch(_IDENTIFIER_PATTERN, value) is None for value in values):
            raise ValueError("trusted_authority_ids contains an invalid identifier")
        return values

    @property
    def policy_digest(self) -> str:
        payload = self.model_dump(mode="json")
        payload["trusted_authority_ids"] = sorted(self.trusted_authority_ids)
        return workflow_digest(payload)


class WorkflowResumeContext(BaseModel):
    """Trusted current-state expectations used to reject persisted substitution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    workflow_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    agent_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    goal_digest: str = Field(pattern=_DIGEST_PATTERN)
    plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    policy_versions: tuple[WorkflowPolicyVersion, ...] = Field(min_length=1)
    resume_authorization_digest: str = Field(pattern=_DIGEST_PATTERN)
    expected_checkpoint_sequence: int = Field(ge=0)
    expected_checkpoint_digest: str = Field(pattern=_DIGEST_PATTERN)
    expected_prior_checkpoint_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    expected_chain_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    expected_chain_length: int = Field(ge=0)
    expected_chain_head_digest: str = Field(pattern=_DIGEST_PATTERN)
    budget_limits: dict[str, int] = Field(default_factory=dict, max_length=10_000)

    @model_validator(mode="after")
    def validate_context(self) -> WorkflowResumeContext:
        policy_ids = [item.policy_id for item in self.policy_versions]
        if len(policy_ids) != len(set(policy_ids)) or policy_ids != sorted(policy_ids):
            raise ValueError("policy_versions must be unique and sorted by policy_id")
        if any(
            re.fullmatch(_IDENTIFIER_PATTERN, key) is None or value < 0
            for key, value in self.budget_limits.items()
        ):
            raise ValueError("budget_limits contains an invalid budget")
        return self


class WorkflowIntegrityFinding(BaseModel):
    """Content-free explanation for a persistent-state decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: WorkflowIntegrityCode
    severity: Severity
    message: str


class AuthorizedWorkflowResume(BaseModel):
    """Short-lived immutable permit to resume one verified checkpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resume_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    checkpoint_digest: str = Field(pattern=_DIGEST_PATTERN)
    checkpoint_sequence: int = Field(ge=0)
    chain_head_digest: str = Field(pattern=_DIGEST_PATTERN)
    chain_length: int = Field(ge=0)
    workflow_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    agent_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    goal_digest: str = Field(pattern=_DIGEST_PATTERN)
    plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    resume_authorization_digest: str = Field(pattern=_DIGEST_PATTERN)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)


class WorkflowIntegrityDecision(BaseModel):
    """Fail-closed resume verification result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    authorization: AuthorizedWorkflowResume | None = None
    findings: tuple[WorkflowIntegrityFinding, ...] = ()

    @property
    def is_authorized(self) -> bool:
        return self.action == GuardAction.ALLOW and self.authorization is not None


class WorkflowIntegrityAuditEvent(BaseModel):
    """Content-free evidence for a checkpoint resume decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    occurred_at: datetime
    phase: WorkflowIntegrityPhase
    code: WorkflowIntegrityCode
    action: GuardAction
    workflow_ref: str = Field(pattern=_KEY_ID_PATTERN)
    tenant_ref: str = Field(pattern=_KEY_ID_PATTERN)
    agent_ref: str = Field(pattern=_KEY_ID_PATTERN)
    session_ref: str = Field(pattern=_KEY_ID_PATTERN)
    checkpoint_ref: str = Field(pattern=_KEY_ID_PATTERN)
    checkpoint_sequence: int = Field(ge=0)
    chain_length: int = Field(ge=0)

    @field_validator("occurred_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "occurred_at")

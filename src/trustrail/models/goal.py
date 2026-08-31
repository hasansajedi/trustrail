"""Typed goal-integrity models for agent planning and execution."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from trustrail.models.enums import GuardAction, Severity

GoalIdentifier = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"),
]
GoalIdentity = Annotated[str, StringConstraints(min_length=1, max_length=256)]


def _digest(payload: Any) -> str:
    canonical = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


class GoalConstraintKind(StrEnum):
    """How a trusted constraint limits an agent objective."""

    REQUIREMENT = "requirement"
    PROHIBITION = "prohibition"
    BOUNDARY = "boundary"


class GoalInputSource(StrEnum):
    """Security-relevant origin of a proposed step or mutation."""

    AUTHORIZED_USER = "authorized_user"
    APPLICATION = "application"
    AGENT = "agent"
    DELEGATED_AGENT = "delegated_agent"
    RETRIEVED_CONTENT = "retrieved_content"
    TOOL_OUTPUT = "tool_output"
    MEMORY = "memory"


class GoalIntegrityOperation(StrEnum):
    """Operation recorded by goal-integrity audit evidence."""

    PLAN_STEP = "plan_step"
    GOAL_MUTATION = "goal_mutation"


class GoalIntegrityCode(StrEnum):
    """Stable machine-readable goal-integrity outcomes."""

    MANIFEST_INTEGRITY_INVALID = "manifest_integrity_invalid"
    MANIFEST_EXPIRED = "manifest_expired"
    APPROVAL_CONTEXT_EXPIRED = "approval_context_expired"
    STATE_BINDING_MISMATCH = "state_binding_mismatch"
    STALE_MANIFEST = "stale_manifest"
    EXECUTION_MISMATCH = "execution_mismatch"
    SESSION_MISMATCH = "session_mismatch"
    OWNER_MISMATCH = "owner_mismatch"
    TENANT_MISMATCH = "tenant_mismatch"
    ACTOR_NOT_AUTHORIZED = "actor_not_authorized"
    DELEGATION_NOT_ESTABLISHED = "delegation_not_established"
    GOAL_BINDING_MISMATCH = "goal_binding_mismatch"
    CONSTRAINT_BINDING_MISMATCH = "constraint_binding_mismatch"
    ACTION_NOT_ALLOWED = "action_not_allowed"
    DELEGATE_NOT_ALLOWED = "delegate_not_allowed"
    STEP_SEQUENCE_INVALID = "step_sequence_invalid"
    STEP_REPLAYED = "step_replayed"
    STEP_LIMIT_EXCEEDED = "step_limit_exceeded"
    STEP_CONTENT_LIMIT_EXCEEDED = "step_content_limit_exceeded"
    GOAL_HIJACK_PATTERN = "goal_hijack_pattern"
    ENCODED_GOAL_HIJACK = "encoded_goal_hijack"
    SPLIT_GOAL_DRIFT = "split_goal_drift"
    MUTATION_APPROVAL_REQUIRED = "mutation_approval_required"
    MUTATION_LIMIT_EXCEEDED = "mutation_limit_exceeded"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_REPLAYED = "approval_replayed"
    INVALID_MUTATION = "invalid_mutation"


class GoalOwner(BaseModel):
    """Authenticated owner identity supplied by trusted application code."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    owner_id: GoalIdentity
    tenant_id: GoalIdentity


class GoalPrincipal(BaseModel):
    """Identity responsible for one proposed plan step or goal change."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    actor_id: GoalIdentity
    owner_id: GoalIdentity
    tenant_id: GoalIdentity


class GoalConstraint(BaseModel):
    """One immutable, application-authored goal constraint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    constraint_id: GoalIdentifier
    kind: GoalConstraintKind
    description: str = Field(min_length=1, max_length=4_096, exclude=True, repr=False)

    @property
    def content_digest(self) -> str:
        """Return a content-safe digest of this complete constraint."""
        return _digest(
            {
                "constraint_id": self.constraint_id,
                "description": self.description,
                "kind": self.kind.value,
            }
        )


class GoalApprovalContext(BaseModel):
    """Trusted context that authorized the original goal and future reviewers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    context_id: GoalIdentifier
    authorized_by: GoalIdentity
    allowed_approver_ids: frozenset[GoalIdentity] = Field(min_length=1, max_length=1_000)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_window(self) -> GoalApprovalContext:
        if self.expires_at <= self.issued_at:
            raise ValueError("approval context expires_at must be after issued_at")
        return self


class GoalManifest(BaseModel):
    """Integrity-bound authorized objective for exactly one agent execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_id: GoalIdentifier
    execution_id: GoalIdentity
    session_id: GoalIdentity
    owner: GoalOwner
    primary_actor_id: GoalIdentity
    objective: str = Field(min_length=1, max_length=16_000, exclude=True, repr=False)
    constraints: tuple[GoalConstraint, ...] = Field(
        default_factory=tuple,
        max_length=128,
        exclude=True,
        repr=False,
    )
    allowed_action_ids: frozenset[GoalIdentifier] = Field(min_length=1, max_length=1_000)
    allowed_delegate_ids: frozenset[GoalIdentity] = Field(
        default_factory=frozenset,
        max_length=1_000,
    )
    approval_context: GoalApprovalContext
    issued_at: datetime
    expires_at: datetime
    revision: int = Field(default=1, ge=1, le=10_000)
    parent_manifest_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    root_goal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    goal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_manifest(self) -> GoalManifest:
        constraint_ids = [constraint.constraint_id for constraint in self.constraints]
        if len(constraint_ids) != len(set(constraint_ids)):
            raise ValueError("goal constraint IDs must be unique")
        if self.primary_actor_id in self.allowed_delegate_ids:
            raise ValueError("primary actor must not also be declared as a delegate")
        if self.expires_at <= self.issued_at:
            raise ValueError("goal manifest expires_at must be after issued_at")
        if not self.has_valid_integrity:
            raise ValueError("goal manifest integrity check failed")
        return self

    @classmethod
    def create(
        cls,
        *,
        manifest_id: str,
        execution_id: str,
        session_id: str,
        owner: GoalOwner,
        primary_actor_id: str,
        objective: str,
        constraints: tuple[GoalConstraint, ...],
        allowed_action_ids: frozenset[str],
        approval_context: GoalApprovalContext,
        issued_at: datetime,
        expires_at: datetime,
        allowed_delegate_ids: frozenset[str] = frozenset(),
        revision: int = 1,
        parent_manifest_digest: str | None = None,
        root_goal_digest: str | None = None,
    ) -> GoalManifest:
        """Create an immutable manifest with goal and execution integrity digests."""
        goal_digest = cls._goal_digest(
            objective=objective,
            constraints=constraints,
            allowed_action_ids=allowed_action_ids,
            allowed_delegate_ids=allowed_delegate_ids,
        )
        root_digest = root_goal_digest or goal_digest
        manifest_digest = cls._manifest_digest(
            manifest_id=manifest_id,
            execution_id=execution_id,
            session_id=session_id,
            owner=owner,
            primary_actor_id=primary_actor_id,
            approval_context=approval_context,
            issued_at=issued_at,
            expires_at=expires_at,
            revision=revision,
            parent_manifest_digest=parent_manifest_digest,
            root_goal_digest=root_digest,
            goal_digest=goal_digest,
        )
        return cls(
            manifest_id=manifest_id,
            execution_id=execution_id,
            session_id=session_id,
            owner=owner,
            primary_actor_id=primary_actor_id,
            objective=objective,
            constraints=constraints,
            allowed_action_ids=allowed_action_ids,
            allowed_delegate_ids=allowed_delegate_ids,
            approval_context=approval_context,
            issued_at=issued_at,
            expires_at=expires_at,
            revision=revision,
            parent_manifest_digest=parent_manifest_digest,
            root_goal_digest=root_digest,
            goal_digest=goal_digest,
            manifest_digest=manifest_digest,
        )

    @property
    def constraint_ids(self) -> frozenset[str]:
        """Return the constraints every proposed step must carry forward."""
        return frozenset(constraint.constraint_id for constraint in self.constraints)

    @property
    def has_valid_integrity(self) -> bool:
        """Recompute both goal content and execution binding digests."""
        actual_goal_digest = self._goal_digest(
            objective=self.objective,
            constraints=self.constraints,
            allowed_action_ids=self.allowed_action_ids,
            allowed_delegate_ids=self.allowed_delegate_ids,
        )
        actual_manifest_digest = self._manifest_digest(
            manifest_id=self.manifest_id,
            execution_id=self.execution_id,
            session_id=self.session_id,
            owner=self.owner,
            primary_actor_id=self.primary_actor_id,
            approval_context=self.approval_context,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            revision=self.revision,
            parent_manifest_digest=self.parent_manifest_digest,
            root_goal_digest=self.root_goal_digest,
            goal_digest=actual_goal_digest,
        )
        return (
            self.goal_digest == actual_goal_digest
            and self.manifest_digest == actual_manifest_digest
        )

    @staticmethod
    def _goal_digest(
        *,
        objective: str,
        constraints: tuple[GoalConstraint, ...],
        allowed_action_ids: frozenset[str],
        allowed_delegate_ids: frozenset[str],
    ) -> str:
        return _digest(
            {
                "allowed_action_ids": sorted(allowed_action_ids),
                "allowed_delegate_ids": sorted(allowed_delegate_ids),
                "constraints": [
                    {
                        "constraint_id": constraint.constraint_id,
                        "description": constraint.description,
                        "kind": constraint.kind.value,
                    }
                    for constraint in sorted(
                        constraints,
                        key=lambda item: item.constraint_id,
                    )
                ],
                "objective": objective,
            }
        )

    @staticmethod
    def _manifest_digest(
        *,
        manifest_id: str,
        execution_id: str,
        session_id: str,
        owner: GoalOwner,
        primary_actor_id: str,
        approval_context: GoalApprovalContext,
        issued_at: datetime,
        expires_at: datetime,
        revision: int,
        parent_manifest_digest: str | None,
        root_goal_digest: str,
        goal_digest: str,
    ) -> str:
        return _digest(
            {
                "approval_context": approval_context.model_dump(mode="json"),
                "execution_id": execution_id,
                "expires_at": expires_at.isoformat(),
                "goal_digest": goal_digest,
                "issued_at": issued_at.isoformat(),
                "manifest_id": manifest_id,
                "owner": owner.model_dump(mode="json"),
                "parent_manifest_digest": parent_manifest_digest,
                "primary_actor_id": primary_actor_id,
                "revision": revision,
                "root_goal_digest": root_goal_digest,
                "session_id": session_id,
            }
        )


class ProposedPlanStep(BaseModel):
    """Untrusted plan step that must be authorized before execution/delegation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: GoalIdentifier
    sequence: int = Field(ge=1, le=1_000_000)
    execution_id: GoalIdentity
    session_id: GoalIdentity
    principal: GoalPrincipal
    source: GoalInputSource
    action_id: GoalIdentifier
    description: str = Field(min_length=1, max_length=100_000, exclude=True, repr=False)
    expected_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    constraint_ids: frozenset[GoalIdentifier] = Field(default_factory=frozenset, max_length=128)
    delegated_to: GoalIdentity | None = None


class GoalMutationApproval(BaseModel):
    """Out-of-band approval bound to one exact material goal mutation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: GoalIdentity
    mutation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    approver_id: GoalIdentity
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def require_aware_expiry(cls, value: datetime) -> datetime:
        return _aware(value, "expires_at")


class ProposedGoalMutation(BaseModel):
    """Untrusted proposal to replace part of the current authorized goal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mutation_id: GoalIdentifier
    execution_id: GoalIdentity
    session_id: GoalIdentity
    principal: GoalPrincipal
    source: GoalInputSource
    expected_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=1, max_length=4_096, exclude=True, repr=False)
    proposed_objective: str | None = Field(
        default=None,
        min_length=1,
        max_length=16_000,
        exclude=True,
        repr=False,
    )
    proposed_constraints: tuple[GoalConstraint, ...] | None = Field(
        default=None,
        max_length=128,
        exclude=True,
        repr=False,
    )
    proposed_allowed_action_ids: frozenset[GoalIdentifier] | None = Field(
        default=None,
        min_length=1,
        max_length=1_000,
    )
    proposed_allowed_delegate_ids: frozenset[GoalIdentity] | None = Field(
        default=None,
        max_length=1_000,
    )
    approval: GoalMutationApproval | None = None

    @model_validator(mode="after")
    def require_proposed_change(self) -> ProposedGoalMutation:
        if all(
            value is None
            for value in (
                self.proposed_objective,
                self.proposed_constraints,
                self.proposed_allowed_action_ids,
                self.proposed_allowed_delegate_ids,
            )
        ):
            raise ValueError("goal mutation must propose at least one change")
        return self

    @property
    def mutation_digest(self) -> str:
        """Return the canonical digest that an approval must authorize."""
        return _digest(
            {
                "execution_id": self.execution_id,
                "expected_manifest_digest": self.expected_manifest_digest,
                "mutation_id": self.mutation_id,
                "principal": self.principal.model_dump(mode="json"),
                "proposed_allowed_action_ids": (
                    sorted(self.proposed_allowed_action_ids)
                    if self.proposed_allowed_action_ids is not None
                    else None
                ),
                "proposed_allowed_delegate_ids": (
                    sorted(self.proposed_allowed_delegate_ids)
                    if self.proposed_allowed_delegate_ids is not None
                    else None
                ),
                "proposed_constraints": (
                    [
                        {
                            "constraint_id": constraint.constraint_id,
                            "description": constraint.description,
                            "kind": constraint.kind.value,
                        }
                        for constraint in sorted(
                            self.proposed_constraints,
                            key=lambda item: item.constraint_id,
                        )
                    ]
                    if self.proposed_constraints is not None
                    else None
                ),
                "proposed_objective": self.proposed_objective,
                "reason": self.reason,
                "session_id": self.session_id,
                "source": self.source.value,
            }
        )


class GoalIntegrityPolicy(BaseModel):
    """Bounded fail-closed policy for goal-integrity validation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_steps_per_execution: int = Field(default=1_000, ge=1, le=1_000_000)
    max_mutations_per_execution: int = Field(default=20, ge=0, le=10_000)
    max_step_chars: int = Field(default=20_000, ge=1, le=1_000_000)
    max_drift_history_chars: int = Field(default=100_000, ge=1, le=2_000_000)
    require_all_constraint_bindings: bool = True
    detect_encoded_hijacking: bool = True
    detect_split_hijacking: bool = True


class GoalIntegrityFinding(BaseModel):
    """Content-free explanation of a goal-integrity decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: GoalIntegrityCode
    severity: Severity
    message: str


class AuthorizedPlanStep(BaseModel):
    """Execution lease for one exact, validated plan step."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str
    step_id: str
    sequence: int
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_id: str
    session_id: str
    actor_id: str
    action_id: str
    delegated_to: str | None = None
    description: str = Field(exclude=True, repr=False)


class GoalIntegrityAuditEvent(BaseModel):
    """Content-free audit evidence for goal decisions and attempted changes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    operation: GoalIntegrityOperation
    action: GuardAction
    manifest_id: str
    execution_id: str
    session_id: str
    owner_id: str
    tenant_id: str
    actor_id: str
    source: GoalInputSource
    root_goal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    current_goal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    current_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    attempted_change_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    approval_id: str | None = None
    finding_codes: tuple[GoalIntegrityCode, ...] = ()


class GoalIntegrityResult(BaseModel):
    """Allow, block, or approval decision for a step or goal mutation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[
        GuardAction.ALLOW,
        GuardAction.BLOCK,
        GuardAction.REQUIRE_APPROVAL,
    ]
    findings: tuple[GoalIntegrityFinding, ...] = ()
    authorization: AuthorizedPlanStep | None = None
    updated_manifest: GoalManifest | None = None
    audit_event: GoalIntegrityAuditEvent

    @property
    def is_authorized(self) -> bool:
        return self.action == GuardAction.ALLOW and self.authorization is not None

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK

    @property
    def requires_approval(self) -> bool:
        return self.action == GuardAction.REQUIRE_APPROVAL


def utcnow() -> datetime:
    """Return an aware current timestamp; isolated for deterministic testing."""
    return datetime.now(tz=UTC)

"""Typed least-privilege models for tool authorization."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity


class ToolEffect(StrEnum):
    """Security-relevant effects a tool is capable of producing."""

    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    EXTERNAL_COMMUNICATION = "external_communication"
    PERMISSION_CHANGE = "permission_change"


class ToolArgumentKind(StrEnum):
    """JSON scalar kinds supported by deterministic argument constraints."""

    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"


class ToolAuthorizationCode(StrEnum):
    """Stable machine-readable tool authorization outcomes."""

    UNKNOWN_TOOL = "unknown_tool"
    TOOL_VERSION_MISMATCH = "tool_version_mismatch"
    INTENT_PRINCIPAL_MISMATCH = "intent_principal_mismatch"
    INTENT_TENANT_MISMATCH = "intent_tenant_mismatch"
    INTENT_EXPIRED = "intent_expired"
    TOOL_OUTSIDE_INTENT = "tool_outside_intent"
    INTENT_CALL_LIMIT_EXCEEDED = "intent_call_limit_exceeded"
    SCOPE_DENIED = "scope_denied"
    PRIVILEGE_EXPANSION = "privilege_expansion"
    ARGUMENT_MISSING = "argument_missing"
    ARGUMENT_NOT_ALLOWED = "argument_not_allowed"
    ARGUMENT_TYPE_MISMATCH = "argument_type_mismatch"
    ARGUMENT_CONSTRAINT_FAILED = "argument_constraint_failed"
    RESOURCE_REQUIRED = "resource_required"
    RESOURCE_ID_MISMATCH = "resource_id_mismatch"
    RESOURCE_OWNER_MISMATCH = "resource_owner_mismatch"
    RESOURCE_TENANT_MISMATCH = "resource_tenant_mismatch"
    AUTONOMOUS_ACTION_DENIED = "autonomous_action_denied"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_REPLAYED = "approval_replayed"
    TOOL_CALL_LIMIT_EXCEEDED = "tool_call_limit_exceeded"
    CHAIN_LIMIT_EXCEEDED = "chain_limit_exceeded"
    RETRY_LIMIT_EXCEEDED = "retry_limit_exceeded"
    PARALLEL_LIMIT_EXCEEDED = "parallel_limit_exceeded"
    AUTONOMOUS_LIMIT_EXCEEDED = "autonomous_limit_exceeded"
    SEMANTIC_CONTEXT_REQUIRED = "semantic_context_required"
    PRECONDITION_MISSING = "precondition_missing"
    PRECONDITION_FAILED = "precondition_failed"
    ARGUMENT_BINDING_MISMATCH = "argument_binding_mismatch"
    EFFECT_OUTSIDE_INTENT = "effect_outside_intent"
    DESTINATION_NOT_APPROVED = "destination_not_approved"
    SEQUENCE_NOT_ALLOWED = "sequence_not_allowed"
    DATA_FLOW_PROVENANCE_REQUIRED = "data_flow_provenance_required"
    DATA_FLOW_NOT_ALLOWED = "data_flow_not_allowed"
    CHAIN_QUARANTINED = "chain_quarantined"
    EXECUTION_REPORT_UNVERIFIABLE = "execution_report_unverifiable"
    EXECUTION_REPORT_MISMATCH = "execution_report_mismatch"
    UNEXPECTED_EFFECT = "unexpected_effect"
    UNEXPECTED_RESOURCE = "unexpected_resource"
    UNEXPECTED_DESTINATION = "unexpected_destination"
    POSTCONDITION_MISSING = "postcondition_missing"
    POSTCONDITION_FAILED = "postcondition_failed"


ScalarValue = str | int | float | bool


class ToolExecutionStatus(StrEnum):
    """Trusted executor status for one completed tool invocation."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ToolArgumentBinding(BaseModel):
    """Require a model-proposed argument to equal an application-owned fact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    argument: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    trusted_fact: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")


class ToolPreconditionPolicy(BaseModel):
    """Facts and exact argument bindings that must hold before execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    required_facts: frozenset[str] = Field(default_factory=frozenset, max_length=256)
    expected_facts: dict[str, ScalarValue] = Field(default_factory=dict, max_length=256)
    argument_bindings: tuple[ToolArgumentBinding, ...] = Field(
        default_factory=tuple,
        max_length=256,
    )

    @model_validator(mode="after")
    def validate_preconditions(self) -> ToolPreconditionPolicy:
        bound_arguments = [binding.argument for binding in self.argument_bindings]
        if len(bound_arguments) != len(set(bound_arguments)):
            raise ValueError("precondition argument bindings must be unique")
        return self


class ToolInvariantPolicy(BaseModel):
    """Side-effect boundaries that hold before, during, and after a tool call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    destination_arguments: frozenset[str] = Field(default_factory=frozenset, max_length=256)
    provenance_required_arguments: frozenset[str] = Field(
        default_factory=frozenset,
        max_length=256,
    )
    max_affected_resources: int = Field(default=1, ge=0, le=100_000)


class ToolPostconditionPolicy(BaseModel):
    """Trusted outcome facts that must be observable after execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    required_facts: frozenset[str] = Field(default_factory=frozenset, max_length=256)
    expected_facts: dict[str, ScalarValue] = Field(default_factory=dict, max_length=256)
    require_exact_effects: bool = True
    require_expected_resource: bool = True


class ToolSemanticOperationPolicy(BaseModel):
    """Semantic preconditions, invariants, and postconditions for one tool."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    preconditions: ToolPreconditionPolicy = Field(default_factory=ToolPreconditionPolicy)
    invariants: ToolInvariantPolicy = Field(default_factory=ToolInvariantPolicy)
    postconditions: ToolPostconditionPolicy = Field(default_factory=ToolPostconditionPolicy)


class ToolSequenceTransition(BaseModel):
    """One explicitly allowed adjacent transition in an execution chain."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_tool: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    target_tool: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")


class ToolDataFlowRule(BaseModel):
    """Allow labeled output from one tool to feed one target argument."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_tool: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    target_tool: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    target_argument: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    allowed_labels: frozenset[str] = Field(min_length=1, max_length=256)
    require_same_intent: bool = True
    require_same_resource: bool = True
    max_uses: int = Field(default=1, ge=1, le=10_000)


class ToolSemanticAuthorizationPolicy(BaseModel):
    """Fail-closed semantic policy spanning operations and tool chains."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operations: tuple[ToolSemanticOperationPolicy, ...] = Field(min_length=1)
    allowed_transitions: tuple[ToolSequenceTransition, ...] = ()
    data_flow_rules: tuple[ToolDataFlowRule, ...] = ()
    deny_unlisted_transitions: bool = True
    deny_unlisted_data_flows: bool = True

    @model_validator(mode="after")
    def validate_semantic_policy(self) -> ToolSemanticAuthorizationPolicy:
        operation_names = [operation.tool_name for operation in self.operations]
        if len(operation_names) != len(set(operation_names)):
            raise ValueError("semantic operation tool names must be unique")
        known_tools = set(operation_names)
        for transition in self.allowed_transitions:
            if (
                transition.source_tool not in known_tools
                or transition.target_tool not in known_tools
            ):
                raise ValueError("sequence transitions must reference semantic operations")
        for flow in self.data_flow_rules:
            if flow.source_tool not in known_tools or flow.target_tool not in known_tools:
                raise ValueError("data-flow rules must reference semantic operations")
        return self


class ToolDataFlowReference(BaseModel):
    """Application-recorded provenance for one tool-derived argument."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_authorization_id: str = Field(min_length=1, max_length=256)
    target_argument: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    label: str = Field(min_length=1, max_length=256)
    value_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def bind(
        cls,
        *,
        source_authorization_id: str,
        target_argument: str,
        label: str,
        value: Any,
    ) -> ToolDataFlowReference:
        """Bind provenance to the exact value forwarded into the target call."""
        return cls(
            source_authorization_id=source_authorization_id,
            target_argument=target_argument,
            label=label,
            value_digest=cls.digest_value(value),
        )

    @staticmethod
    def digest_value(value: Any) -> str:
        """Return the canonical digest used for content-free value binding."""
        canonical = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def matches(self, value: Any) -> bool:
        """Return whether a proposed argument matches the provenance digest."""
        try:
            return self.value_digest == self.digest_value(value)
        except (TypeError, ValueError):
            return False


class ToolSemanticContext(BaseModel):
    """Trusted intent and provenance facts for semantic authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trusted_facts: dict[str, ScalarValue] = Field(default_factory=dict, max_length=256)
    expected_effects: frozenset[ToolEffect] = Field(min_length=1)
    approved_destinations: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    expected_resource_ids: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    data_flows: tuple[ToolDataFlowReference, ...] = Field(default_factory=tuple, max_length=256)

    @model_validator(mode="after")
    def validate_data_flows(self) -> ToolSemanticContext:
        arguments = [flow.target_argument for flow in self.data_flows]
        if len(arguments) != len(set(arguments)):
            raise ValueError("each target argument may have only one data-flow reference")
        return self


class ToolArgumentConstraint(BaseModel):
    """Closed, deterministic validation contract for one tool argument."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ToolArgumentKind
    allowed_values: tuple[ScalarValue, ...] | None = None
    pattern: str | None = Field(default=None, max_length=512)
    min_length: int | None = Field(default=None, ge=0)
    max_length: int | None = Field(default=None, ge=0)
    minimum: float | None = None
    maximum: float | None = None
    max_serialized_chars: int = Field(default=4_096, ge=1, le=100_000)

    @model_validator(mode="after")
    def validate_constraint(self) -> ToolArgumentConstraint:
        if self.pattern is not None:
            if self.kind != ToolArgumentKind.STRING:
                raise ValueError("pattern is only valid for string arguments")
            re.compile(self.pattern)
        if (self.min_length is not None or self.max_length is not None) and (
            self.kind != ToolArgumentKind.STRING
        ):
            raise ValueError("length constraints are only valid for string arguments")
        if (
            self.min_length is not None
            and self.max_length is not None
            and self.min_length > self.max_length
        ):
            raise ValueError("min_length cannot exceed max_length")
        if (self.minimum is not None or self.maximum is not None) and self.kind not in (
            ToolArgumentKind.INTEGER,
            ToolArgumentKind.NUMBER,
        ):
            raise ValueError("numeric bounds require an integer or number argument")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("minimum cannot exceed maximum")
        return self


class ToolCapability(BaseModel):
    """One explicitly exposed tool and its minimum required privileges."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    version: str = Field(min_length=1, max_length=128)
    effects: frozenset[ToolEffect] = Field(min_length=1)
    required_scopes: frozenset[str] = Field(default_factory=frozenset)
    delegatable_scopes: frozenset[str] = Field(default_factory=frozenset)
    arguments: dict[str, ToolArgumentConstraint] = Field(default_factory=dict)
    required_arguments: frozenset[str] = Field(default_factory=frozenset)
    resource_id_argument: str | None = None
    require_owned_resource: bool = False
    allow_autonomous: bool = False
    require_approval: bool = False

    @model_validator(mode="after")
    def validate_capability(self) -> ToolCapability:
        unknown_required = self.required_arguments.difference(self.arguments)
        if unknown_required:
            raise ValueError("required_arguments must be declared in arguments")
        if self.resource_id_argument is not None:
            constraint = self.arguments.get(self.resource_id_argument)
            if constraint is None:
                raise ValueError("resource_id_argument must be declared in arguments")
            if constraint.kind != ToolArgumentKind.STRING:
                raise ValueError("resource_id_argument must identify a string argument")
        if self.require_owned_resource and self.resource_id_argument is None:
            raise ValueError("owned resources require resource_id_argument")
        if not self.delegatable_scopes.issubset(self.required_scopes):
            raise ValueError("delegatable_scopes must be a subset of required_scopes")
        return self


class ToolPrincipal(BaseModel):
    """Trusted actor and end-user identity for a proposed tool invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    actor_id: str = Field(min_length=1, max_length=256)
    subject_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=256)
    scopes: frozenset[str] = Field(default_factory=frozenset)


class ToolIntent(BaseModel):
    """Application-recorded user intent that bounds agent-selected actions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    intent_id: str = Field(min_length=1, max_length=256)
    subject_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=256)
    allowed_tools: frozenset[str] = Field(min_length=1)
    purpose: str = Field(min_length=1, max_length=1_024)
    expires_at: datetime
    max_calls: int = Field(default=1, ge=1, le=10_000)

    @field_validator("expires_at")
    @classmethod
    def require_aware_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        return value


class ToolResource(BaseModel):
    """Ownership evidence loaded by trusted application code, not by the model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str = Field(min_length=1, max_length=1_024)
    owner_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=256)


class ToolApprovalGrant(BaseModel):
    """Out-of-band approval bound to one exact invocation fingerprint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(min_length=1, max_length=256)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    approver_id: str = Field(min_length=1, max_length=256)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def require_aware_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        return value


class ToolAuthorizationRequest(BaseModel):
    """Complete security context for one proposed tool invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    tool_version: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    principal: ToolPrincipal
    intent: ToolIntent
    resource: ToolResource | None = None
    requested_scopes: frozenset[str] = Field(default_factory=frozenset)
    session_id: str = Field(min_length=1, max_length=256)
    chain_id: str = Field(min_length=1, max_length=256)
    operation_id: str = Field(min_length=1, max_length=256)
    autonomous: bool = True
    approval: ToolApprovalGrant | None = None
    semantic_context: ToolSemanticContext | None = None

    @property
    def canonical_arguments_json(self) -> str:
        """Return an immutable canonical snapshot of the proposed arguments."""
        return json.dumps(
            self.arguments,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )

    @property
    def approval_digest(self) -> str:
        """Return the canonical digest to bind an approval to this request."""
        approval_payload = {
            "arguments": json.loads(self.canonical_arguments_json),
            "autonomous": self.autonomous,
            "chain_id": self.chain_id,
            "intent": {
                "allowed_tools": sorted(self.intent.allowed_tools),
                "expires_at": self.intent.expires_at.isoformat(),
                "intent_id": self.intent.intent_id,
                "max_calls": self.intent.max_calls,
                "purpose": self.intent.purpose,
                "subject_id": self.intent.subject_id,
                "tenant_id": self.intent.tenant_id,
            },
            "operation_id": self.operation_id,
            "principal": {
                "actor_id": self.principal.actor_id,
                "scopes": sorted(self.principal.scopes),
                "subject_id": self.principal.subject_id,
                "tenant_id": self.principal.tenant_id,
            },
            "requested_scopes": sorted(self.requested_scopes),
            "resource": self.resource.model_dump(mode="json") if self.resource else None,
            "semantic_context": self._canonical_semantic_context(),
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
        }
        canonical = json.dumps(
            approval_payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _canonical_semantic_context(self) -> dict[str, Any] | None:
        context = self.semantic_context
        if context is None:
            return None
        return {
            "approved_destinations": sorted(context.approved_destinations),
            "data_flows": sorted(
                (flow.model_dump(mode="json") for flow in context.data_flows),
                key=lambda flow: (
                    flow["target_argument"],
                    flow["source_authorization_id"],
                    flow["label"],
                ),
            ),
            "expected_effects": sorted(effect.value for effect in context.expected_effects),
            "expected_resource_ids": sorted(context.expected_resource_ids),
            "trusted_facts": context.trusted_facts,
        }


def _approval_effects() -> frozenset[ToolEffect]:
    return frozenset(
        {
            ToolEffect.DELETE,
            ToolEffect.EXTERNAL_COMMUNICATION,
            ToolEffect.PERMISSION_CHANGE,
        }
    )


class ToolAuthorizationPolicy(BaseModel):
    """Fail-closed capability and execution policy for agents."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capabilities: tuple[ToolCapability, ...] = Field(min_length=1)
    approval_required_for: frozenset[ToolEffect] = Field(default_factory=_approval_effects)
    max_tool_calls: int = Field(default=50, ge=1, le=100_000)
    max_chain_actions: int = Field(default=10, ge=1, le=10_000)
    max_retries_per_operation: int = Field(default=2, ge=0, le=100)
    max_parallel_calls: int = Field(default=4, ge=1, le=1_000)
    max_autonomous_actions: int = Field(default=10, ge=0, le=10_000)
    max_arguments: int = Field(default=32, ge=1, le=1_000)

    @model_validator(mode="after")
    def validate_unique_tool_names(self) -> ToolAuthorizationPolicy:
        names = [capability.name for capability in self.capabilities]
        if len(names) != len(set(names)):
            raise ValueError("capability names must be unique")
        return self


class ToolAuthorizationFinding(BaseModel):
    """Content-free explanation for an authorization decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ToolAuthorizationCode
    severity: Severity
    message: str


class ToolExecutionReport(BaseModel):
    """Application-observed outcome bound to one authorization lease."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str = Field(min_length=1, max_length=256)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    session_id: str = Field(min_length=1, max_length=256)
    tool_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    status: ToolExecutionStatus
    verifiable: bool = True
    observed_effects: frozenset[ToolEffect] = Field(default_factory=frozenset)
    affected_resource_ids: frozenset[str] = Field(default_factory=frozenset, max_length=100_000)
    destinations: frozenset[str] = Field(default_factory=frozenset, max_length=10_000)
    facts: dict[str, ScalarValue] = Field(default_factory=dict, max_length=256)
    output_labels: frozenset[str] = Field(default_factory=frozenset, max_length=256)
    output_value_digests: dict[str, str] = Field(default_factory=dict, max_length=256)

    @model_validator(mode="after")
    def validate_output_digests(self) -> ToolExecutionReport:
        if not set(self.output_value_digests).issubset(self.output_labels):
            raise ValueError("output value digests must have a declared output label")
        if any(
            re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for digest in self.output_value_digests.values()
        ):
            raise ValueError("output value digests must be lowercase SHA-256 values")
        return self


class ToolExecutionRecord(BaseModel):
    """Minimal verified history retained for sequence and data-flow decisions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str
    tool_name: str
    chain_id: str
    intent_id: str
    resource_ids: frozenset[str] = Field(default_factory=frozenset)
    output_labels: frozenset[str] = Field(default_factory=frozenset)
    output_value_digests: dict[str, str] = Field(default_factory=dict)


class ToolCompensationRequest(BaseModel):
    """Content-minimized request to roll back or compensate an unsafe outcome."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str
    request_digest: str
    session_id: str
    chain_id: str
    operation_id: str
    tool_name: str
    findings: tuple[ToolAuthorizationFinding, ...]


class ToolPostconditionResult(BaseModel):
    """Fail-closed verification result after a tool returns."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.QUARANTINE]
    findings: tuple[ToolAuthorizationFinding, ...] = ()
    compensation_required: bool = False
    compensation_succeeded: bool | None = None

    @property
    def is_verified(self) -> bool:
        return self.action == GuardAction.ALLOW


class AuthorizedToolCall(BaseModel):
    """Short-lived authorization lease returned for an exact tool request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str
    request_digest: str
    session_id: str
    tool_name: str
    tool_version: str
    arguments_json: str = Field(exclude=True, repr=False)

    @property
    def arguments(self) -> dict[str, Any]:
        """Return a fresh copy of the exact arguments authorized for execution."""
        decoded = json.loads(self.arguments_json)
        if not isinstance(decoded, dict):
            raise ValueError("authorized arguments must decode to an object")
        return cast(dict[str, Any], decoded)


class ToolAuthorizationResult(BaseModel):
    """Allow, block, or approval decision for a tool request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[
        GuardAction.ALLOW,
        GuardAction.BLOCK,
        GuardAction.REQUIRE_APPROVAL,
    ]
    findings: tuple[ToolAuthorizationFinding, ...] = ()
    authorization: AuthorizedToolCall | None = None

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
    """Return an aware timestamp; isolated for deterministic test patching."""
    return datetime.now(tz=UTC)

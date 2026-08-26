"""Deterministic tool authorization and bounded execution for LLM agents."""

from __future__ import annotations

import json
import math
import re
import threading
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from trustrail.exceptions import ToolAuthorizationError
from trustrail.models.agency import (
    AuthorizedToolCall,
    ToolApprovalGrant,
    ToolArgumentConstraint,
    ToolArgumentKind,
    ToolAuthorizationCode,
    ToolAuthorizationFinding,
    ToolAuthorizationPolicy,
    ToolAuthorizationRequest,
    ToolAuthorizationResult,
    ToolCapability,
    utcnow,
)
from trustrail.models.enums import GuardAction, Severity

if TYPE_CHECKING:
    from trustrail.protocols import ToolApprovalVerifier


@dataclass
class ToolExecutionBudget:
    """Application-owned mutable counters for one agent session.

    Keep one budget for the full session. Creating a new budget for every request
    defeats cumulative limits and is therefore intentionally outside the model's
    control.
    """

    session_id: str
    tool_calls: int = 0
    autonomous_actions: int = 0
    intent_calls: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    operation_attempts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    chain_actions: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    active_authorizations: set[str] = field(default_factory=set)
    used_approval_ids: set[str] = field(default_factory=set)

    @property
    def active_calls(self) -> int:
        """Return the number of authorization leases not yet completed."""
        return len(self.active_authorizations)


class ToolAuthorizer:
    """Apply complete mediation to every proposed tool invocation."""

    def __init__(
        self,
        policy: ToolAuthorizationPolicy,
        *,
        approval_verifier: ToolApprovalVerifier | None = None,
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._capabilities = {
            capability.name: capability for capability in self._policy.capabilities
        }
        self._approval_verifier = approval_verifier
        self._lock = threading.Lock()

    @property
    def policy(self) -> ToolAuthorizationPolicy:
        """Return the immutable policy used by this authorizer."""
        return self._policy.model_copy(deep=True)

    def new_budget(self, session_id: str) -> ToolExecutionBudget:
        """Create the application-owned execution budget for one agent session."""
        if not session_id:
            raise ValueError("session_id must not be empty")
        return ToolExecutionBudget(session_id=session_id)

    def authorize(
        self,
        request: ToolAuthorizationRequest,
        budget: ToolExecutionBudget,
        *,
        now: datetime | None = None,
    ) -> ToolAuthorizationResult:
        """Authorize an exact invocation and reserve an execution lease."""
        current_time = now or utcnow()
        findings: list[ToolAuthorizationFinding] = []
        capability = self._capabilities.get(request.tool_name)
        if capability is None:
            findings.append(
                self._finding(
                    ToolAuthorizationCode.UNKNOWN_TOOL,
                    Severity.CRITICAL,
                    "Tool is not present in the capability manifest",
                )
            )
            return self._blocked(findings)

        findings.extend(self._identity_findings(request, capability))
        findings.extend(self._intent_findings(request, current_time))
        findings.extend(self._scope_findings(request, capability))
        findings.extend(self._argument_findings(request.arguments, capability))
        findings.extend(self._resource_findings(request, capability))
        if request.autonomous and not capability.allow_autonomous:
            findings.append(
                self._finding(
                    ToolAuthorizationCode.AUTONOMOUS_ACTION_DENIED,
                    Severity.HIGH,
                    "Capability does not permit autonomous invocation",
                )
            )
        if findings:
            return self._blocked(findings)

        approval_required = capability.require_approval or bool(
            capability.effects.intersection(self._policy.approval_required_for)
        )
        approval_findings = self._approval_findings(
            request,
            budget,
            current_time,
            approval_required=approval_required,
        )
        if approval_findings:
            if all(
                finding.code == ToolAuthorizationCode.APPROVAL_REQUIRED
                for finding in approval_findings
            ):
                return ToolAuthorizationResult(
                    action=GuardAction.REQUIRE_APPROVAL,
                    findings=tuple(approval_findings),
                )
            return self._blocked(approval_findings)

        with self._lock:
            budget_findings = self._budget_findings(
                request,
                budget,
                consume_approval=approval_required,
            )
            if budget_findings:
                return self._blocked(budget_findings)

            authorization_id = str(uuid.uuid4())
            self._reserve(
                request,
                budget,
                authorization_id,
                consume_approval=approval_required,
            )

        return ToolAuthorizationResult(
            action=GuardAction.ALLOW,
            authorization=AuthorizedToolCall(
                authorization_id=authorization_id,
                request_digest=request.approval_digest,
                session_id=request.session_id,
                tool_name=request.tool_name,
                tool_version=request.tool_version,
                arguments_json=request.canonical_arguments_json,
            ),
        )

    def require(
        self,
        request: ToolAuthorizationRequest,
        budget: ToolExecutionBudget,
        *,
        now: datetime | None = None,
    ) -> AuthorizedToolCall:
        """Return an authorization lease or raise before tool execution."""
        result = self.authorize(request, budget, now=now)
        if not result.is_authorized or result.authorization is None:
            raise ToolAuthorizationError(result=result)
        return result.authorization

    def complete(self, authorization: AuthorizedToolCall, budget: ToolExecutionBudget) -> bool:
        """Release a parallel-call lease after the tool finishes or is cancelled."""
        if authorization.session_id != budget.session_id:
            return False
        with self._lock:
            if authorization.authorization_id not in budget.active_authorizations:
                return False
            budget.active_authorizations.remove(authorization.authorization_id)
        return True

    def _identity_findings(
        self,
        request: ToolAuthorizationRequest,
        capability: ToolCapability,
    ) -> list[ToolAuthorizationFinding]:
        if request.tool_version == capability.version:
            return []
        return [
            self._finding(
                ToolAuthorizationCode.TOOL_VERSION_MISMATCH,
                Severity.CRITICAL,
                "Tool version does not match the capability manifest",
            )
        ]

    def _intent_findings(
        self,
        request: ToolAuthorizationRequest,
        now: datetime,
    ) -> list[ToolAuthorizationFinding]:
        findings: list[ToolAuthorizationFinding] = []
        if request.intent.subject_id != request.principal.subject_id:
            findings.append(
                self._finding(
                    ToolAuthorizationCode.INTENT_PRINCIPAL_MISMATCH,
                    Severity.CRITICAL,
                    "Intent is bound to a different end user",
                )
            )
        if request.intent.tenant_id != request.principal.tenant_id:
            findings.append(
                self._finding(
                    ToolAuthorizationCode.INTENT_TENANT_MISMATCH,
                    Severity.CRITICAL,
                    "Intent is bound to a different tenant",
                )
            )
        if now >= request.intent.expires_at:
            findings.append(
                self._finding(
                    ToolAuthorizationCode.INTENT_EXPIRED,
                    Severity.HIGH,
                    "Recorded user intent has expired",
                )
            )
        if request.tool_name not in request.intent.allowed_tools:
            findings.append(
                self._finding(
                    ToolAuthorizationCode.TOOL_OUTSIDE_INTENT,
                    Severity.CRITICAL,
                    "Tool is outside the user's recorded intent",
                )
            )
        return findings

    def _scope_findings(
        self,
        request: ToolAuthorizationRequest,
        capability: ToolCapability,
    ) -> list[ToolAuthorizationFinding]:
        findings: list[ToolAuthorizationFinding] = []
        if not capability.required_scopes.issubset(request.principal.scopes):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.SCOPE_DENIED,
                    Severity.CRITICAL,
                    "Principal lacks a scope required by the capability",
                )
            )
        if not request.requested_scopes.issubset(request.principal.scopes):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.PRIVILEGE_EXPANSION,
                    Severity.CRITICAL,
                    "Invocation requests scope not held by the principal",
                )
            )
        if not request.requested_scopes.issubset(capability.delegatable_scopes):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.PRIVILEGE_EXPANSION,
                    Severity.CRITICAL,
                    "Invocation requests scope the capability cannot delegate",
                )
            )
        return findings

    def _argument_findings(
        self,
        arguments: dict[str, Any],
        capability: ToolCapability,
    ) -> list[ToolAuthorizationFinding]:
        findings: list[ToolAuthorizationFinding] = []
        if len(arguments) > self._policy.max_arguments:
            return [
                self._finding(
                    ToolAuthorizationCode.ARGUMENT_CONSTRAINT_FAILED,
                    Severity.HIGH,
                    "Invocation exceeds the maximum number of arguments",
                )
            ]
        for name in capability.required_arguments.difference(arguments):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.ARGUMENT_MISSING,
                    Severity.HIGH,
                    f"Required argument is missing: {name}",
                )
            )
        for name, value in arguments.items():
            constraint = capability.arguments.get(name)
            if constraint is None:
                findings.append(
                    self._finding(
                        ToolAuthorizationCode.ARGUMENT_NOT_ALLOWED,
                        Severity.CRITICAL,
                        f"Argument is not declared by the capability: {name}",
                    )
                )
                continue
            code = self._check_argument(value, constraint)
            if code is not None:
                message = (
                    f"Argument has the wrong type: {name}"
                    if code == ToolAuthorizationCode.ARGUMENT_TYPE_MISMATCH
                    else f"Argument violates its declared constraint: {name}"
                )
                findings.append(self._finding(code, Severity.HIGH, message))
        return findings

    @staticmethod
    def _check_argument(
        value: Any,
        constraint: ToolArgumentConstraint,
    ) -> ToolAuthorizationCode | None:
        valid_type = (
            (constraint.kind == ToolArgumentKind.STRING and isinstance(value, str))
            or (
                constraint.kind == ToolArgumentKind.INTEGER
                and isinstance(value, int)
                and not isinstance(value, bool)
            )
            or (
                constraint.kind == ToolArgumentKind.NUMBER
                and isinstance(value, (int, float))
                and not isinstance(value, bool)
            )
            or (constraint.kind == ToolArgumentKind.BOOLEAN and isinstance(value, bool))
        )
        if not valid_type:
            return ToolAuthorizationCode.ARGUMENT_TYPE_MISMATCH
        if (
            len(json.dumps(value, ensure_ascii=False, allow_nan=False))
            > constraint.max_serialized_chars
        ):
            return ToolAuthorizationCode.ARGUMENT_CONSTRAINT_FAILED
        if constraint.allowed_values is not None and value not in constraint.allowed_values:
            return ToolAuthorizationCode.ARGUMENT_CONSTRAINT_FAILED
        if isinstance(value, str):
            if constraint.min_length is not None and len(value) < constraint.min_length:
                return ToolAuthorizationCode.ARGUMENT_CONSTRAINT_FAILED
            if constraint.max_length is not None and len(value) > constraint.max_length:
                return ToolAuthorizationCode.ARGUMENT_CONSTRAINT_FAILED
            if constraint.pattern is not None and re.fullmatch(constraint.pattern, value) is None:
                return ToolAuthorizationCode.ARGUMENT_CONSTRAINT_FAILED
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if not math.isfinite(value):
                return ToolAuthorizationCode.ARGUMENT_CONSTRAINT_FAILED
            if constraint.minimum is not None and value < constraint.minimum:
                return ToolAuthorizationCode.ARGUMENT_CONSTRAINT_FAILED
            if constraint.maximum is not None and value > constraint.maximum:
                return ToolAuthorizationCode.ARGUMENT_CONSTRAINT_FAILED
        return None

    def _resource_findings(
        self,
        request: ToolAuthorizationRequest,
        capability: ToolCapability,
    ) -> list[ToolAuthorizationFinding]:
        if not capability.require_owned_resource:
            return []
        if request.resource is None:
            return [
                self._finding(
                    ToolAuthorizationCode.RESOURCE_REQUIRED,
                    Severity.CRITICAL,
                    "Trusted resource ownership evidence is required",
                )
            ]

        findings: list[ToolAuthorizationFinding] = []
        argument_resource_id = request.arguments.get(capability.resource_id_argument or "")
        if argument_resource_id != request.resource.resource_id:
            findings.append(
                self._finding(
                    ToolAuthorizationCode.RESOURCE_ID_MISMATCH,
                    Severity.CRITICAL,
                    "Requested resource differs from trusted ownership evidence",
                )
            )
        if request.resource.owner_id != request.principal.subject_id:
            findings.append(
                self._finding(
                    ToolAuthorizationCode.RESOURCE_OWNER_MISMATCH,
                    Severity.CRITICAL,
                    "Resource is not owned by the end user",
                )
            )
        if request.resource.tenant_id != request.principal.tenant_id:
            findings.append(
                self._finding(
                    ToolAuthorizationCode.RESOURCE_TENANT_MISMATCH,
                    Severity.CRITICAL,
                    "Resource belongs to a different tenant",
                )
            )
        return findings

    def _approval_findings(
        self,
        request: ToolAuthorizationRequest,
        budget: ToolExecutionBudget,
        now: datetime,
        *,
        approval_required: bool,
    ) -> list[ToolAuthorizationFinding]:
        if not approval_required:
            return []
        approval = request.approval
        if approval is None:
            return [
                self._finding(
                    ToolAuthorizationCode.APPROVAL_REQUIRED,
                    Severity.HIGH,
                    "An out-of-band approval is required for this effect",
                )
            ]
        if approval.expires_at <= now:
            return [
                self._finding(
                    ToolAuthorizationCode.APPROVAL_EXPIRED,
                    Severity.HIGH,
                    "Approval grant has expired",
                )
            ]
        if approval.approval_id in budget.used_approval_ids:
            return [
                self._finding(
                    ToolAuthorizationCode.APPROVAL_REPLAYED,
                    Severity.CRITICAL,
                    "Approval grant has already been consumed",
                )
            ]
        if approval.request_digest != request.approval_digest:
            return [
                self._finding(
                    ToolAuthorizationCode.APPROVAL_INVALID,
                    Severity.CRITICAL,
                    "Approval is not bound to this exact invocation",
                )
            ]
        if self._approval_verifier is None:
            return [
                self._finding(
                    ToolAuthorizationCode.APPROVAL_INVALID,
                    Severity.CRITICAL,
                    "Approval authenticity could not be verified",
                )
            ]
        try:
            verified = self._approval_verifier.verify_approval(approval)
        except Exception:
            verified = False
        if not verified:
            return [
                self._finding(
                    ToolAuthorizationCode.APPROVAL_INVALID,
                    Severity.CRITICAL,
                    "Approval authenticity could not be verified",
                )
            ]
        return []

    def _budget_findings(
        self,
        request: ToolAuthorizationRequest,
        budget: ToolExecutionBudget,
        *,
        consume_approval: bool,
    ) -> list[ToolAuthorizationFinding]:
        if request.session_id != budget.session_id:
            return [
                self._finding(
                    ToolAuthorizationCode.PRIVILEGE_EXPANSION,
                    Severity.CRITICAL,
                    "Execution budget belongs to a different session",
                )
            ]
        checks = (
            (
                consume_approval
                and request.approval is not None
                and request.approval.approval_id in budget.used_approval_ids,
                ToolAuthorizationCode.APPROVAL_REPLAYED,
                "Approval grant has already been consumed",
            ),
            (
                budget.tool_calls >= self._policy.max_tool_calls,
                ToolAuthorizationCode.TOOL_CALL_LIMIT_EXCEEDED,
                "Session tool-call limit has been reached",
            ),
            (
                budget.chain_actions[request.chain_id] >= self._policy.max_chain_actions,
                ToolAuthorizationCode.CHAIN_LIMIT_EXCEEDED,
                "Chained-action limit has been reached",
            ),
            (
                budget.operation_attempts[request.operation_id]
                > self._policy.max_retries_per_operation,
                ToolAuthorizationCode.RETRY_LIMIT_EXCEEDED,
                "Retry limit has been reached for this operation",
            ),
            (
                budget.active_calls >= self._policy.max_parallel_calls,
                ToolAuthorizationCode.PARALLEL_LIMIT_EXCEEDED,
                "Parallel tool-call limit has been reached",
            ),
            (
                request.autonomous
                and budget.autonomous_actions >= self._policy.max_autonomous_actions,
                ToolAuthorizationCode.AUTONOMOUS_LIMIT_EXCEEDED,
                "Autonomous-action limit has been reached",
            ),
            (
                budget.intent_calls[request.intent.intent_id] >= request.intent.max_calls,
                ToolAuthorizationCode.INTENT_CALL_LIMIT_EXCEEDED,
                "User intent call limit has been reached",
            ),
        )
        return [
            self._finding(code, Severity.HIGH, message)
            for exceeded, code, message in checks
            if exceeded
        ]

    @staticmethod
    def _reserve(
        request: ToolAuthorizationRequest,
        budget: ToolExecutionBudget,
        authorization_id: str,
        *,
        consume_approval: bool,
    ) -> None:
        budget.tool_calls += 1
        budget.chain_actions[request.chain_id] += 1
        budget.operation_attempts[request.operation_id] += 1
        budget.intent_calls[request.intent.intent_id] += 1
        if request.autonomous:
            budget.autonomous_actions += 1
        budget.active_authorizations.add(authorization_id)
        if consume_approval and request.approval is not None:
            budget.used_approval_ids.add(request.approval.approval_id)

    @staticmethod
    def _blocked(
        findings: list[ToolAuthorizationFinding],
    ) -> ToolAuthorizationResult:
        return ToolAuthorizationResult(action=GuardAction.BLOCK, findings=tuple(findings))

    @staticmethod
    def _finding(
        code: ToolAuthorizationCode,
        severity: Severity,
        message: str,
    ) -> ToolAuthorizationFinding:
        return ToolAuthorizationFinding(code=code, severity=severity, message=message)


class StaticToolApprovalVerifier:
    """Test/example verifier that accepts an application-owned approval ID set."""

    def __init__(self, valid_approval_ids: frozenset[str]) -> None:
        self._valid_approval_ids = valid_approval_ids

    def verify_approval(self, approval: ToolApprovalGrant) -> bool:
        """Return whether the trusted application issued this approval ID."""
        return approval.approval_id in self._valid_approval_ids

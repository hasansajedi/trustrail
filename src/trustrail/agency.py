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
    ToolCompensationRequest,
    ToolDataFlowReference,
    ToolDataFlowRule,
    ToolExecutionRecord,
    ToolExecutionReport,
    ToolExecutionStatus,
    ToolPostconditionResult,
    ToolSemanticAuthorizationPolicy,
    ToolSemanticOperationPolicy,
    utcnow,
)
from trustrail.models.enums import GuardAction, Severity

if TYPE_CHECKING:
    from trustrail.protocols import ToolApprovalVerifier, ToolCompensator


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
    active_semantic_requests: dict[str, ToolAuthorizationRequest] = field(
        default_factory=dict,
        repr=False,
    )
    verified_executions: dict[str, ToolExecutionRecord] = field(default_factory=dict)
    chain_history: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    quarantined_chains: set[str] = field(default_factory=set)
    data_flow_uses: dict[tuple[str, str, str], int] = field(
        default_factory=lambda: defaultdict(int)
    )

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
        semantic_policy: ToolSemanticAuthorizationPolicy | None = None,
        compensator: ToolCompensator | None = None,
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._capabilities = {
            capability.name: capability for capability in self._policy.capabilities
        }
        self._approval_verifier = approval_verifier
        self._semantic_policy = semantic_policy.model_copy(deep=True) if semantic_policy else None
        self._semantic_operations = (
            {operation.tool_name: operation for operation in self._semantic_policy.operations}
            if self._semantic_policy
            else {}
        )
        if self._semantic_policy and set(self._semantic_operations) != set(self._capabilities):
            raise ValueError("semantic policy must cover every declared capability")
        self._validate_semantic_contract()
        self._compensator = compensator
        self._lock = threading.Lock()

    @property
    def policy(self) -> ToolAuthorizationPolicy:
        """Return the immutable policy used by this authorizer."""
        return self._policy.model_copy(deep=True)

    @property
    def semantic_policy(self) -> ToolSemanticAuthorizationPolicy | None:
        """Return the optional immutable semantic authorization policy."""
        return self._semantic_policy.model_copy(deep=True) if self._semantic_policy else None

    def new_budget(self, session_id: str) -> ToolExecutionBudget:
        """Create the application-owned execution budget for one agent session."""
        if not session_id:
            raise ValueError("session_id must not be empty")
        return ToolExecutionBudget(session_id=session_id)

    def _validate_semantic_contract(self) -> None:
        if self._semantic_policy is None:
            return
        for operation in self._semantic_policy.operations:
            capability = self._capabilities[operation.tool_name]
            declared_arguments = set(capability.arguments)
            bound_arguments = {
                binding.argument for binding in operation.preconditions.argument_bindings
            }
            invariant_arguments = set(operation.invariants.destination_arguments).union(
                operation.invariants.provenance_required_arguments
            )
            if not bound_arguments.union(invariant_arguments).issubset(declared_arguments):
                raise ValueError("semantic controls must reference declared tool arguments")
        for rule in self._semantic_policy.data_flow_rules:
            capability = self._capabilities[rule.target_tool]
            if rule.target_argument not in capability.arguments:
                raise ValueError("data-flow target arguments must be declared by the capability")

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
        findings.extend(self._semantic_findings(request, capability, budget))
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
            semantic_findings = self._semantic_findings(request, capability, budget)
            if semantic_findings:
                return self._blocked(semantic_findings)
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
            if request.tool_name in self._semantic_operations:
                budget.active_semantic_requests[authorization_id] = request.model_copy(deep=True)
                if request.semantic_context is not None:
                    for flow in request.semantic_context.data_flows:
                        key = (
                            flow.source_authorization_id,
                            request.tool_name,
                            flow.target_argument,
                        )
                        budget.data_flow_uses[key] += 1

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
        """Release a non-semantic lease after the tool finishes or is cancelled.

        Semantic operations must use :meth:`verify_completion`; releasing those
        leases without a trusted execution report fails closed.
        """
        if authorization.session_id != budget.session_id:
            return False
        with self._lock:
            if authorization.authorization_id not in budget.active_authorizations:
                return False
            if authorization.authorization_id in budget.active_semantic_requests:
                return False
            budget.active_authorizations.remove(authorization.authorization_id)
        return True

    def verify_completion(
        self,
        authorization: AuthorizedToolCall,
        report: ToolExecutionReport,
        budget: ToolExecutionBudget,
    ) -> ToolPostconditionResult:
        """Verify a trusted outcome, close its lease, and quarantine violations."""
        with self._lock:
            request = budget.active_semantic_requests.get(authorization.authorization_id)
            if (
                request is None
                or authorization.authorization_id not in budget.active_authorizations
            ):
                findings = [
                    self._finding(
                        ToolAuthorizationCode.EXECUTION_REPORT_MISMATCH,
                        Severity.CRITICAL,
                        "Execution report does not reference an active semantic authorization",
                    )
                ]
                return self._postcondition_result(None, authorization, findings)

            operation = self._semantic_operations[request.tool_name]
            findings = self._postcondition_findings(
                authorization,
                request,
                report,
                operation,
            )
            budget.active_authorizations.remove(authorization.authorization_id)
            del budget.active_semantic_requests[authorization.authorization_id]

            if findings:
                budget.quarantined_chains.add(request.chain_id)
            elif report.status == ToolExecutionStatus.SUCCEEDED:
                resource_ids = report.affected_resource_ids
                record = ToolExecutionRecord(
                    authorization_id=authorization.authorization_id,
                    tool_name=request.tool_name,
                    chain_id=request.chain_id,
                    intent_id=request.intent.intent_id,
                    resource_ids=resource_ids,
                    output_labels=report.output_labels,
                    output_value_digests=report.output_value_digests,
                )
                budget.verified_executions[authorization.authorization_id] = record
                budget.chain_history[request.chain_id].append(authorization.authorization_id)

        return self._postcondition_result(request, authorization, findings)

    def _semantic_findings(
        self,
        request: ToolAuthorizationRequest,
        capability: ToolCapability,
        budget: ToolExecutionBudget,
    ) -> list[ToolAuthorizationFinding]:
        operation = self._semantic_operations.get(request.tool_name)
        if operation is None:
            return []
        if request.chain_id in budget.quarantined_chains:
            return [
                self._finding(
                    ToolAuthorizationCode.CHAIN_QUARANTINED,
                    Severity.CRITICAL,
                    "Execution chain is quarantined after an unverifiable tool outcome",
                )
            ]
        context = request.semantic_context
        if context is None:
            return [
                self._finding(
                    ToolAuthorizationCode.SEMANTIC_CONTEXT_REQUIRED,
                    Severity.CRITICAL,
                    "Trusted semantic context is required for this capability",
                )
            ]

        findings: list[ToolAuthorizationFinding] = []
        if any(
            active.chain_id == request.chain_id
            for active in budget.active_semantic_requests.values()
        ):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.SEQUENCE_NOT_ALLOWED,
                    Severity.CRITICAL,
                    "A semantic tool call is already active in this chain",
                )
            )
        if context.expected_effects != capability.effects:
            findings.append(
                self._finding(
                    ToolAuthorizationCode.EFFECT_OUTSIDE_INTENT,
                    Severity.CRITICAL,
                    "Capability effects do not exactly match the effects approved by user intent",
                )
            )

        preconditions = operation.preconditions
        missing_facts = preconditions.required_facts.difference(context.trusted_facts)
        for fact in sorted(missing_facts):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.PRECONDITION_MISSING,
                    Severity.HIGH,
                    f"Required trusted precondition is missing: {fact}",
                )
            )
        for fact, expected in preconditions.expected_facts.items():
            if context.trusted_facts.get(fact) != expected:
                findings.append(
                    self._finding(
                        ToolAuthorizationCode.PRECONDITION_FAILED,
                        Severity.CRITICAL,
                        f"Trusted precondition does not hold: {fact}",
                    )
                )
        for binding in preconditions.argument_bindings:
            if binding.trusted_fact not in context.trusted_facts:
                findings.append(
                    self._finding(
                        ToolAuthorizationCode.PRECONDITION_MISSING,
                        Severity.HIGH,
                        f"Argument binding fact is missing: {binding.trusted_fact}",
                    )
                )
            elif (
                request.arguments.get(binding.argument)
                != context.trusted_facts[binding.trusted_fact]
            ):
                findings.append(
                    self._finding(
                        ToolAuthorizationCode.ARGUMENT_BINDING_MISMATCH,
                        Severity.CRITICAL,
                        f"Argument is not bound to trusted intent: {binding.argument}",
                    )
                )

        invariants = operation.invariants
        for argument in invariants.destination_arguments:
            destination = request.arguments.get(argument)
            if not isinstance(destination, str) or destination not in context.approved_destinations:
                findings.append(
                    self._finding(
                        ToolAuthorizationCode.DESTINATION_NOT_APPROVED,
                        Severity.CRITICAL,
                        f"Destination argument is not approved by user intent: {argument}",
                    )
                )

        flows_by_argument = {flow.target_argument: flow for flow in context.data_flows}
        for argument in invariants.provenance_required_arguments:
            if argument in request.arguments and argument not in flows_by_argument:
                findings.append(
                    self._finding(
                        ToolAuthorizationCode.DATA_FLOW_PROVENANCE_REQUIRED,
                        Severity.CRITICAL,
                        f"Tool-derived argument lacks provenance: {argument}",
                    )
                )

        findings.extend(self._sequence_findings(request, budget))
        findings.extend(self._data_flow_findings(request, budget))
        return findings

    def _sequence_findings(
        self,
        request: ToolAuthorizationRequest,
        budget: ToolExecutionBudget,
    ) -> list[ToolAuthorizationFinding]:
        if self._semantic_policy is None or not budget.chain_history[request.chain_id]:
            return []
        previous_id = budget.chain_history[request.chain_id][-1]
        previous = budget.verified_executions[previous_id]
        transition = (previous.tool_name, request.tool_name)
        allowed = {
            (item.source_tool, item.target_tool)
            for item in self._semantic_policy.allowed_transitions
        }
        if transition in allowed or not self._semantic_policy.deny_unlisted_transitions:
            return []
        return [
            self._finding(
                ToolAuthorizationCode.SEQUENCE_NOT_ALLOWED,
                Severity.CRITICAL,
                "Adjacent tool sequence is not explicitly allowed",
            )
        ]

    def _data_flow_findings(
        self,
        request: ToolAuthorizationRequest,
        budget: ToolExecutionBudget,
    ) -> list[ToolAuthorizationFinding]:
        context = request.semantic_context
        if context is None or self._semantic_policy is None:
            return []
        findings: list[ToolAuthorizationFinding] = []
        target_resources = set(context.expected_resource_ids)
        if request.resource is not None:
            target_resources.add(request.resource.resource_id)
        for flow in context.data_flows:
            if flow.target_argument not in request.arguments:
                findings.append(
                    self._finding(
                        ToolAuthorizationCode.DATA_FLOW_NOT_ALLOWED,
                        Severity.CRITICAL,
                        "Tool data-flow target is not present in the proposed arguments",
                    )
                )
                continue
            if not flow.matches(request.arguments[flow.target_argument]):
                findings.append(
                    self._finding(
                        ToolAuthorizationCode.DATA_FLOW_NOT_ALLOWED,
                        Severity.CRITICAL,
                        "Tool-derived argument does not match its provenance digest",
                    )
                )
                continue
            source = budget.verified_executions.get(flow.source_authorization_id)
            if (
                source is None
                or source.chain_id != request.chain_id
                or flow.label not in source.output_labels
                or source.output_value_digests.get(flow.label) != flow.value_digest
            ):
                findings.append(
                    self._finding(
                        ToolAuthorizationCode.DATA_FLOW_NOT_ALLOWED,
                        Severity.CRITICAL,
                        f"Tool data-flow provenance could not be verified: {flow.target_argument}",
                    )
                )
                continue
            rule = self._matching_data_flow_rule(source.tool_name, request.tool_name, flow)
            if rule is None:
                if self._semantic_policy.deny_unlisted_data_flows:
                    findings.append(
                        self._finding(
                            ToolAuthorizationCode.DATA_FLOW_NOT_ALLOWED,
                            Severity.CRITICAL,
                            "Tool-to-tool data flow is not explicitly allowed: "
                            f"{flow.target_argument}",
                        )
                    )
                continue
            flow_key = (
                flow.source_authorization_id,
                request.tool_name,
                flow.target_argument,
            )
            if budget.data_flow_uses[flow_key] >= rule.max_uses:
                findings.append(
                    self._finding(
                        ToolAuthorizationCode.DATA_FLOW_NOT_ALLOWED,
                        Severity.CRITICAL,
                        "Tool-to-tool data-flow use limit has been reached",
                    )
                )
            if rule.require_same_intent and source.intent_id != request.intent.intent_id:
                findings.append(
                    self._finding(
                        ToolAuthorizationCode.DATA_FLOW_NOT_ALLOWED,
                        Severity.CRITICAL,
                        "Tool-to-tool data flow crosses user intents",
                    )
                )
            if rule.require_same_resource and (
                not source.resource_ids
                or not target_resources
                or source.resource_ids.isdisjoint(target_resources)
            ):
                findings.append(
                    self._finding(
                        ToolAuthorizationCode.DATA_FLOW_NOT_ALLOWED,
                        Severity.CRITICAL,
                        "Tool-to-tool data flow crosses resource boundaries",
                    )
                )
        return findings

    def _matching_data_flow_rule(
        self,
        source_tool: str,
        target_tool: str,
        flow: ToolDataFlowReference,
    ) -> ToolDataFlowRule | None:
        if self._semantic_policy is None:
            return None
        return next(
            (
                rule
                for rule in self._semantic_policy.data_flow_rules
                if rule.source_tool == source_tool
                and rule.target_tool == target_tool
                and rule.target_argument == flow.target_argument
                and flow.label in rule.allowed_labels
            ),
            None,
        )

    def _postcondition_findings(
        self,
        authorization: AuthorizedToolCall,
        request: ToolAuthorizationRequest,
        report: ToolExecutionReport,
        operation: ToolSemanticOperationPolicy,
    ) -> list[ToolAuthorizationFinding]:
        findings: list[ToolAuthorizationFinding] = []
        if (
            authorization.request_digest != request.approval_digest
            or authorization.session_id != request.session_id
            or authorization.tool_name != request.tool_name
            or authorization.tool_version != request.tool_version
            or authorization.arguments_json != request.canonical_arguments_json
            or report.authorization_id != authorization.authorization_id
            or report.request_digest != request.approval_digest
            or report.session_id != request.session_id
            or report.tool_name != request.tool_name
        ):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.EXECUTION_REPORT_MISMATCH,
                    Severity.CRITICAL,
                    "Execution report is not bound to the authorized invocation",
                )
            )
        if not report.verifiable or report.status == ToolExecutionStatus.UNKNOWN:
            findings.append(
                self._finding(
                    ToolAuthorizationCode.EXECUTION_REPORT_UNVERIFIABLE,
                    Severity.CRITICAL,
                    "Tool outcome cannot be independently verified",
                )
            )

        context = request.semantic_context
        if context is None:
            findings.append(
                self._finding(
                    ToolAuthorizationCode.EXECUTION_REPORT_UNVERIFIABLE,
                    Severity.CRITICAL,
                    "Authorized semantic context is unavailable",
                )
            )
            return findings

        expected_effects = context.expected_effects
        if not report.observed_effects.issubset(expected_effects):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.UNEXPECTED_EFFECT,
                    Severity.CRITICAL,
                    "Tool produced an effect outside the authorized intent",
                )
            )
        postconditions = operation.postconditions
        if (
            report.status == ToolExecutionStatus.SUCCEEDED
            and postconditions.require_exact_effects
            and report.observed_effects != expected_effects
        ):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.POSTCONDITION_MISSING,
                    Severity.HIGH,
                    "Successful tool outcome did not attest every expected effect",
                )
            )

        expected_resources = set(context.expected_resource_ids)
        if request.resource is not None:
            expected_resources.add(request.resource.resource_id)
        if not report.affected_resource_ids.issubset(expected_resources):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.UNEXPECTED_RESOURCE,
                    Severity.CRITICAL,
                    "Tool affected a resource outside the authorized boundary",
                )
            )
        if len(report.affected_resource_ids) > operation.invariants.max_affected_resources:
            findings.append(
                self._finding(
                    ToolAuthorizationCode.UNEXPECTED_RESOURCE,
                    Severity.CRITICAL,
                    "Tool affected more resources than the invariant permits",
                )
            )
        if (
            report.status == ToolExecutionStatus.SUCCEEDED
            and postconditions.require_expected_resource
            and expected_resources
            and not expected_resources.issubset(report.affected_resource_ids)
        ):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.POSTCONDITION_MISSING,
                    Severity.HIGH,
                    "Successful tool outcome did not attest the expected resource",
                )
            )

        expected_destinations = {
            value
            for argument in operation.invariants.destination_arguments
            if isinstance((value := request.arguments.get(argument)), str)
        }
        if not report.destinations.issubset(
            context.approved_destinations
        ) or not report.destinations.issubset(expected_destinations):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.UNEXPECTED_DESTINATION,
                    Severity.CRITICAL,
                    "Tool used a destination outside the authorized boundary",
                )
            )
        if (
            report.status == ToolExecutionStatus.SUCCEEDED
            and expected_destinations
            and not expected_destinations.issubset(report.destinations)
        ):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.POSTCONDITION_MISSING,
                    Severity.HIGH,
                    "Successful tool outcome did not attest the approved destination",
                )
            )

        for fact in postconditions.required_facts.difference(report.facts):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.POSTCONDITION_MISSING,
                    Severity.HIGH,
                    f"Required execution fact is missing: {fact}",
                )
            )
        for fact, expected in postconditions.expected_facts.items():
            if report.facts.get(fact) != expected:
                findings.append(
                    self._finding(
                        ToolAuthorizationCode.POSTCONDITION_FAILED,
                        Severity.CRITICAL,
                        f"Execution postcondition does not hold: {fact}",
                    )
                )
        if report.status == ToolExecutionStatus.FAILED and (
            report.observed_effects or report.affected_resource_ids or report.destinations
        ):
            findings.append(
                self._finding(
                    ToolAuthorizationCode.POSTCONDITION_FAILED,
                    Severity.CRITICAL,
                    "Failed tool call reported side effects that require compensation",
                )
            )
        return findings

    def _postcondition_result(
        self,
        request: ToolAuthorizationRequest | None,
        authorization: AuthorizedToolCall,
        findings: list[ToolAuthorizationFinding],
    ) -> ToolPostconditionResult:
        if not findings:
            return ToolPostconditionResult(action=GuardAction.ALLOW)
        compensation_succeeded: bool | None = None
        compensation_required = request is not None
        if request is not None and self._compensator is not None:
            compensation_request = ToolCompensationRequest(
                authorization_id=authorization.authorization_id,
                request_digest=authorization.request_digest,
                session_id=request.session_id,
                chain_id=request.chain_id,
                operation_id=request.operation_id,
                tool_name=request.tool_name,
                findings=tuple(findings),
            )
            try:
                compensation_succeeded = self._compensator.compensate(compensation_request)
            except Exception:
                compensation_succeeded = False
        return ToolPostconditionResult(
            action=GuardAction.QUARANTINE,
            findings=tuple(findings),
            compensation_required=compensation_required,
            compensation_succeeded=compensation_succeeded,
        )

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

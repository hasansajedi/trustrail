"""Tenant-isolated circuit breaking and cascading-failure containment."""

from __future__ import annotations

import contextlib
import re
import threading
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from trustrail.exceptions import FailureContainmentError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.failure_containment import (
    AuthorizedDependencyAttempt,
    CircuitState,
    DependencyCircuitSnapshot,
    DependencyCriticality,
    DependencyDeclaration,
    DependencyHealth,
    DependencyOutcomeReport,
    FailureContainmentAuditEvent,
    FailureContainmentCode,
    FailureContainmentEventKind,
    FailureContainmentFinding,
    FailureContainmentPolicy,
    FailureContainmentRequest,
    FailureContainmentResult,
    FailureSignal,
    FallbackDeclaration,
    utcnow,
)

_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


class FailureContainmentAuditSink(Protocol):
    """Persist content-free containment events."""

    def emit(self, event: FailureContainmentAuditEvent) -> None:
        """Persist one event without inspecting operation content."""
        ...


class DependencyOutcomeVerifier(Protocol):
    """Authenticate terminal dependency evidence from trusted application state."""

    def verify_outcome(self, report: DependencyOutcomeReport) -> bool:
        """Return whether a trusted observer issued this exact report."""
        ...


class FailureContainmentHooks(Protocol):
    """Application-owned callbacks for workflow containment and recovery."""

    def enter_degraded_mode(self, event: FailureContainmentAuditEvent) -> None:
        """Switch the affected workflow to its declared reduced capability set."""
        ...

    def cancel(self, event: FailureContainmentAuditEvent) -> None:
        """Cancel queued or in-flight work in the affected tenant and domain."""
        ...

    def compensate(self, event: FailureContainmentAuditEvent) -> None:
        """Request an application-specific compensating transaction."""
        ...

    def recover(self, event: FailureContainmentAuditEvent) -> None:
        """Restore normal mode after a successful half-open probe."""
        ...


class MemoryFailureContainmentAuditSink:
    """Bounded in-memory containment audit sink for tests and development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[FailureContainmentAuditEvent] = deque(maxlen=max_events)

    def emit(self, event: FailureContainmentAuditEvent) -> None:
        self._events.append(event)

    @property
    def events(self) -> list[FailureContainmentAuditEvent]:
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()


@dataclass(frozen=True)
class _Sample:
    success: bool
    latency_ms: float
    cost: float
    abnormal_tool_call_count: int


@dataclass
class _CircuitRuntime:
    samples: deque[_Sample]
    state: CircuitState = CircuitState.CLOSED
    opened_at: datetime | None = None
    half_open_probe_active: bool = False


@dataclass
class _ActivePermit:
    permit_digest: str
    expected_cost: float
    side_effecting: bool
    recursion_depth: int
    retry_count: int


@dataclass
class _HookDispatch:
    degraded: list[FailureContainmentAuditEvent] = field(default_factory=list)
    cancellation: list[FailureContainmentAuditEvent] = field(default_factory=list)
    compensation: list[FailureContainmentAuditEvent] = field(default_factory=list)
    recovery: list[FailureContainmentAuditEvent] = field(default_factory=list)


class FailureContainmentManager:
    """Admit dependency attempts and contain failures within tenant domains.

    The process-local implementation uses one lock for request sequencing,
    idempotency reservations, permit consumption, and breaker transitions. Use a
    shared atomic coordinator when multiple processes dispatch the same workflow.
    """

    def __init__(
        self,
        policy: FailureContainmentPolicy,
        *,
        outcome_verifier: DependencyOutcomeVerifier | None = None,
        hooks: FailureContainmentHooks | None = None,
        audit_sink: FailureContainmentAuditSink | None = None,
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._outcome_verifier = outcome_verifier
        self._hooks = hooks
        self._audit_sink = audit_sink
        self._dependencies = {item.dependency_id: item for item in self._policy.dependencies}
        self._domains = {item.failure_domain_id: item for item in self._policy.failure_domains}
        self._fallbacks = {item.fallback_id: item for item in self._policy.fallbacks}
        self._circuits: dict[tuple[str, str], _CircuitRuntime] = {}
        self._active_permits: dict[str, _ActivePermit] = {}
        self._used_report_ids: set[str] = set()
        self._seen_attempt_ids: set[tuple[str, str]] = set()
        self._operation_attempts: dict[tuple[str, str], int] = {}
        self._active_side_effects: set[tuple[str, str]] = set()
        self._committed_side_effects: set[tuple[str, str]] = set()
        self._event_sequence = 0
        self._lock = threading.Lock()

    @property
    def policy(self) -> FailureContainmentPolicy:
        """Return a defensive copy of the active policy."""
        return self._policy.model_copy(deep=True)

    def authorize(
        self,
        request: FailureContainmentRequest,
        *,
        now: datetime | None = None,
    ) -> FailureContainmentResult:
        """Atomically authorize one exact attempt before dependency dispatch."""
        current_time = now or utcnow()
        findings = self._static_request_findings(request)
        dependency = self._dependencies.get(request.dependency_id)
        if dependency is not None:
            findings.extend(self._tenant_findings(dependency, request.tenant_id))

        events: list[FailureContainmentAuditEvent] = []
        dispatch = _HookDispatch()
        permit: AuthorizedDependencyAttempt | None = None
        selected = dependency
        fallback: FallbackDeclaration | None = None

        with self._lock:
            if dependency is not None and not findings:
                mutable_findings = self._mutable_request_findings(request)
                unavailable = self._dependency_unavailable(
                    request.tenant_id, dependency, current_time, events
                )
                if unavailable:
                    fallback, fallback_findings = self._select_fallback(
                        request, dependency, current_time, events
                    )
                    findings.extend(fallback_findings)
                    if fallback is not None and not fallback_findings:
                        selected = self._dependencies[fallback.target_dependency_id]
                elif request.fallback is not None:
                    findings.append(
                        self._finding(
                            FailureContainmentCode.FALLBACK_NOT_REQUIRED,
                            Severity.HIGH,
                            "Fallback substitution is denied while the primary is available",
                        )
                    )
                findings.extend(mutable_findings)

            if dependency is not None and selected is not None and not findings:
                permit = self._issue_permit(
                    request,
                    dependency,
                    selected,
                    fallback,
                    current_time,
                )
                admission_event = self._event(
                    kind=FailureContainmentEventKind.ADMISSION_ALLOWED,
                    request=request,
                    dependency=selected,
                    action=GuardAction.ALLOW,
                    now=current_time,
                )
                events.append(admission_event)
                if fallback is not None:
                    degraded_event = self._event(
                        kind=FailureContainmentEventKind.DEGRADED_MODE_ENTERED,
                        request=request,
                        dependency=dependency,
                        action=GuardAction.WARN,
                        now=current_time,
                    )
                    events.append(degraded_event)
                    dispatch.degraded.append(degraded_event)
            else:
                event_dependency = dependency or self._placeholder_dependency(request.dependency_id)
                events.append(
                    self._event(
                        kind=FailureContainmentEventKind.ADMISSION_BLOCKED,
                        request=request,
                        dependency=event_dependency,
                        action=GuardAction.BLOCK,
                        findings=findings,
                        now=current_time,
                    )
                )

        self._publish(events, dispatch)
        return FailureContainmentResult(
            action=GuardAction.ALLOW if permit is not None else GuardAction.BLOCK,
            findings=tuple(self._deduplicate(findings)),
            permit=permit,
            events=tuple(events),
        )

    def require(
        self,
        request: FailureContainmentRequest,
        *,
        now: datetime | None = None,
    ) -> AuthorizedDependencyAttempt:
        """Return a dispatch permit or raise before dependency access."""
        result = self.authorize(request, now=now)
        if not result.is_authorized or result.permit is None:
            raise FailureContainmentError(result)
        return result.permit

    def record_outcome(
        self,
        permit: AuthorizedDependencyAttempt,
        report: DependencyOutcomeReport,
        *,
        now: datetime | None = None,
    ) -> FailureContainmentResult:
        """Consume a permit and apply authenticated terminal signals atomically."""
        current_time = now or utcnow()
        findings: list[FailureContainmentFinding] = []
        events: list[FailureContainmentAuditEvent] = []
        dispatch = _HookDispatch()
        dependency = self._dependencies.get(permit.selected_dependency_id)

        if not permit.has_valid_integrity:
            findings.append(
                self._finding(
                    FailureContainmentCode.PERMIT_INVALID,
                    Severity.CRITICAL,
                    "Dependency permit integrity is invalid",
                )
            )
        if not report.has_valid_integrity:
            findings.append(
                self._finding(
                    FailureContainmentCode.REPORT_INTEGRITY_INVALID,
                    Severity.CRITICAL,
                    "Dependency report integrity is invalid",
                )
            )
        if not self._verify_outcome(report):
            findings.append(
                self._finding(
                    FailureContainmentCode.REPORT_UNVERIFIABLE,
                    Severity.CRITICAL,
                    "Dependency report authenticity could not be verified",
                )
            )
        if report.permit_id != permit.permit_id or report.permit_digest != permit.permit_digest:
            findings.append(
                self._finding(
                    FailureContainmentCode.REPORT_MISMATCH,
                    Severity.CRITICAL,
                    "Dependency report is not bound to the supplied permit",
                )
            )
        if permit.expires_at < current_time:
            findings.append(
                self._finding(
                    FailureContainmentCode.PERMIT_EXPIRED,
                    Severity.HIGH,
                    "Dependency permit has expired",
                )
            )
        if report.completed_at < permit.issued_at or report.completed_at > current_time:
            findings.append(
                self._finding(
                    FailureContainmentCode.REPORT_MISMATCH,
                    Severity.CRITICAL,
                    "Dependency report completion time is outside the observed permit window",
                )
            )
        if dependency is None:
            findings.append(
                self._finding(
                    FailureContainmentCode.DEPENDENCY_UNKNOWN,
                    Severity.CRITICAL,
                    "Permit references an unknown dependency",
                )
            )

        request = self._request_from_permit(permit)
        with self._lock:
            active = self._active_permits.get(permit.permit_id)
            if active is None:
                findings.append(
                    self._finding(
                        FailureContainmentCode.PERMIT_REPLAYED,
                        Severity.CRITICAL,
                        "Dependency permit is not active",
                    )
                )
            elif active.permit_digest != permit.permit_digest:
                findings.append(
                    self._finding(
                        FailureContainmentCode.PERMIT_INVALID,
                        Severity.CRITICAL,
                        "Dependency permit does not match the active authorization",
                    )
                )
            if report.report_id in self._used_report_ids:
                findings.append(
                    self._finding(
                        FailureContainmentCode.REPORT_REPLAYED,
                        Severity.CRITICAL,
                        "Dependency report has already been consumed",
                    )
                )

            if not findings and active is not None and dependency is not None:
                self._active_permits.pop(permit.permit_id)
                self._used_report_ids.add(report.report_id)
                self._finish_side_effect(permit, report)
                circuit = self._circuit(permit.tenant_id, dependency)
                circuit.half_open_probe_active = False
                previous_state = circuit.state
                circuit.samples.append(
                    _Sample(
                        success=report.success,
                        latency_ms=report.latency_ms,
                        cost=report.cost,
                        abnormal_tool_call_count=report.abnormal_tool_call_count,
                    )
                )
                findings.extend(self._outcome_findings(report, dependency, circuit))
                threshold_crossed = any(
                    finding.code
                    in {
                        FailureContainmentCode.ERROR_RATE_THRESHOLD_EXCEEDED,
                        FailureContainmentCode.LATENCY_THRESHOLD_EXCEEDED,
                        FailureContainmentCode.COST_THRESHOLD_EXCEEDED,
                        FailureContainmentCode.TOOL_CALL_THRESHOLD_EXCEEDED,
                    }
                    for finding in findings
                )
                if (
                    previous_state == CircuitState.HALF_OPEN
                    and report.success
                    and not threshold_crossed
                ):
                    circuit.state = CircuitState.CLOSED
                    circuit.opened_at = None
                    circuit.samples.clear()
                    recovery_event = self._event(
                        kind=FailureContainmentEventKind.CIRCUIT_CLOSED,
                        request=request,
                        dependency=dependency,
                        action=GuardAction.ALLOW,
                        now=current_time,
                    )
                    events.append(recovery_event)
                    dispatch.recovery.append(
                        self._event(
                            kind=FailureContainmentEventKind.RECOVERY_REQUESTED,
                            request=request,
                            dependency=dependency,
                            action=GuardAction.ALLOW,
                            now=current_time,
                        )
                    )
                    events.extend(dispatch.recovery)
                elif threshold_crossed or (
                    previous_state == CircuitState.HALF_OPEN and not report.success
                ):
                    circuit.state = CircuitState.OPEN
                    circuit.opened_at = current_time
                    opened_event = self._event(
                        kind=FailureContainmentEventKind.CIRCUIT_OPENED,
                        request=request,
                        dependency=dependency,
                        action=GuardAction.BLOCK,
                        findings=findings,
                        now=current_time,
                    )
                    events.append(opened_event)
                    degraded_event = self._event(
                        kind=FailureContainmentEventKind.DEGRADED_MODE_ENTERED,
                        request=request,
                        dependency=dependency,
                        action=GuardAction.WARN,
                        findings=findings,
                        now=current_time,
                    )
                    events.append(degraded_event)
                    dispatch.degraded.append(degraded_event)
                    if dependency.criticality in {
                        DependencyCriticality.HIGH,
                        DependencyCriticality.CRITICAL,
                    }:
                        cancellation_event = self._event(
                            kind=FailureContainmentEventKind.CANCELLATION_REQUESTED,
                            request=request,
                            dependency=dependency,
                            action=GuardAction.BLOCK,
                            findings=findings,
                            now=current_time,
                        )
                        events.append(cancellation_event)
                        dispatch.cancellation.append(cancellation_event)
                    if report.side_effect_committed and not report.success:
                        compensation_event = self._event(
                            kind=FailureContainmentEventKind.COMPENSATION_REQUESTED,
                            request=request,
                            dependency=dependency,
                            action=GuardAction.BLOCK,
                            findings=findings,
                            now=current_time,
                        )
                        events.append(compensation_event)
                        dispatch.compensation.append(compensation_event)

                events.append(
                    self._event(
                        kind=FailureContainmentEventKind.OUTCOME_RECORDED,
                        request=request,
                        dependency=dependency,
                        action=(
                            GuardAction.ALLOW
                            if report.success and not findings
                            else GuardAction.BLOCK
                        ),
                        findings=findings,
                        now=current_time,
                    )
                )

        if not events:
            event_dependency = dependency or self._placeholder_dependency(
                permit.selected_dependency_id
            )
            with self._lock:
                events.append(
                    self._event(
                        kind=FailureContainmentEventKind.OUTCOME_RECORDED,
                        request=request,
                        dependency=event_dependency,
                        action=GuardAction.BLOCK,
                        findings=findings,
                        now=current_time,
                    )
                )

        self._publish(events, dispatch)
        action = GuardAction.ALLOW if report.success and not findings else GuardAction.BLOCK
        return FailureContainmentResult(
            action=action,
            findings=tuple(self._deduplicate(findings)),
            events=tuple(events),
        )

    def snapshot(self, tenant_id: str, dependency_id: str) -> DependencyCircuitSnapshot:
        """Return aggregate breaker signals without operation content."""
        dependency = self._dependencies.get(dependency_id)
        if dependency is None:
            raise KeyError(dependency_id)
        with self._lock:
            circuit = self._circuit(tenant_id, dependency)
            samples = tuple(circuit.samples)
            return DependencyCircuitSnapshot(
                tenant_id=tenant_id,
                dependency_id=dependency_id,
                failure_domain_id=dependency.failure_domain_id,
                declared_health=dependency.health,
                circuit_state=circuit.state,
                sample_count=len(samples),
                error_rate=self._error_rate(samples),
                average_latency_ms=self._average_latency(samples),
                cumulative_cost=sum(sample.cost for sample in samples),
                abnormal_tool_call_count=sum(sample.abnormal_tool_call_count for sample in samples),
            )

    def _static_request_findings(
        self, request: FailureContainmentRequest
    ) -> list[FailureContainmentFinding]:
        findings: list[FailureContainmentFinding] = []
        if not request.has_valid_integrity:
            findings.append(
                self._finding(
                    FailureContainmentCode.REQUEST_INTEGRITY_INVALID,
                    Severity.CRITICAL,
                    "Failure-containment request integrity is invalid",
                )
            )
        if request.dependency_id not in self._dependencies:
            findings.append(
                self._finding(
                    FailureContainmentCode.DEPENDENCY_UNKNOWN,
                    Severity.CRITICAL,
                    "Requested dependency is not declared",
                )
            )
        if request.retry_count > self._policy.max_retries_per_operation:
            findings.append(
                self._finding(
                    FailureContainmentCode.RETRY_LIMIT_EXCEEDED,
                    Severity.HIGH,
                    "Declared retry count exceeds policy",
                    FailureSignal.RETRY,
                )
            )
        if request.recursion_depth > self._policy.max_recursion_depth:
            findings.append(
                self._finding(
                    FailureContainmentCode.RECURSION_LIMIT_EXCEEDED,
                    Severity.HIGH,
                    "Agent recursion depth exceeds policy",
                    FailureSignal.RECURSION,
                )
            )
        if request.expected_cost > self._policy.max_cost_per_attempt:
            findings.append(
                self._finding(
                    FailureContainmentCode.COST_LIMIT_EXCEEDED,
                    Severity.HIGH,
                    "Expected attempt cost exceeds policy",
                    FailureSignal.COST,
                )
            )
        if request.abnormal_tool_call_count > self._policy.max_abnormal_tool_calls_per_attempt:
            findings.append(
                self._finding(
                    FailureContainmentCode.ABNORMAL_TOOL_CALL_LIMIT_EXCEEDED,
                    Severity.HIGH,
                    "Abnormal tool-call count exceeds policy",
                    FailureSignal.ABNORMAL_TOOL_CALL,
                )
            )
        return findings

    def _tenant_findings(
        self, dependency: DependencyDeclaration, tenant_id: str
    ) -> list[FailureContainmentFinding]:
        if dependency.allowed_tenant_ids and tenant_id not in dependency.allowed_tenant_ids:
            return [
                self._finding(
                    FailureContainmentCode.TENANT_NOT_ALLOWED,
                    Severity.CRITICAL,
                    "Tenant is not allowed to use this dependency",
                )
            ]
        return []

    def _mutable_request_findings(
        self, request: FailureContainmentRequest
    ) -> list[FailureContainmentFinding]:
        findings: list[FailureContainmentFinding] = []
        attempt_key = (request.tenant_id, request.attempt_id)
        operation_key = (request.tenant_id, request.operation_id)
        attempt_count = self._operation_attempts.get(operation_key, 0)
        if attempt_key in self._seen_attempt_ids:
            findings.append(
                self._finding(
                    FailureContainmentCode.DUPLICATE_ATTEMPT,
                    Severity.CRITICAL,
                    "Attempt identifier has already been authorized",
                )
            )
        if attempt_count > self._policy.max_retries_per_operation:
            findings.append(
                self._finding(
                    FailureContainmentCode.RETRY_LIMIT_EXCEEDED,
                    Severity.HIGH,
                    "Observed operation attempts exceed retry policy",
                    FailureSignal.RETRY,
                )
            )
        if request.retry_count != attempt_count:
            findings.append(
                self._finding(
                    FailureContainmentCode.RETRY_SEQUENCE_INVALID,
                    Severity.HIGH,
                    "Caller retry count does not match authoritative state",
                    FailureSignal.RETRY,
                )
            )
        if request.side_effecting:
            if request.idempotency_key is None:
                findings.append(
                    self._finding(
                        FailureContainmentCode.IDEMPOTENCY_KEY_REQUIRED,
                        Severity.CRITICAL,
                        "Side-effecting attempts require an idempotency key",
                    )
                )
            else:
                side_effect_key = (request.tenant_id, request.idempotency_key)
                if (
                    side_effect_key in self._active_side_effects
                    or side_effect_key in self._committed_side_effects
                ):
                    findings.append(
                        self._finding(
                            FailureContainmentCode.DUPLICATE_SIDE_EFFECT,
                            Severity.CRITICAL,
                            "Side-effect idempotency key is active or already committed",
                        )
                    )
        return findings

    def _dependency_unavailable(
        self,
        tenant_id: str,
        dependency: DependencyDeclaration,
        now: datetime,
        events: list[FailureContainmentAuditEvent],
    ) -> bool:
        if dependency.health != DependencyHealth.HEALTHY:
            return True
        circuit = self._circuit(tenant_id, dependency)
        self._advance_half_open(tenant_id, dependency, circuit, now, events)
        if circuit.state == CircuitState.OPEN:
            return True
        if circuit.state == CircuitState.HALF_OPEN and circuit.half_open_probe_active:
            return True
        if circuit.state == CircuitState.HALF_OPEN:
            return False
        domain = self._domains[dependency.failure_domain_id]
        open_count = 0
        for candidate in self._dependencies.values():
            if candidate.failure_domain_id != dependency.failure_domain_id:
                continue
            candidate_circuit = self._circuit(tenant_id, candidate)
            self._advance_half_open(tenant_id, candidate, candidate_circuit, now, events)
            if candidate_circuit.state in {CircuitState.OPEN, CircuitState.HALF_OPEN}:
                open_count += 1
        return open_count >= domain.max_open_dependencies

    def _select_fallback(
        self,
        request: FailureContainmentRequest,
        dependency: DependencyDeclaration,
        now: datetime,
        events: list[FailureContainmentAuditEvent],
    ) -> tuple[FallbackDeclaration | None, list[FailureContainmentFinding]]:
        if request.fallback is None:
            return None, [
                self._finding(
                    FailureContainmentCode.FALLBACK_REQUIRED,
                    Severity.HIGH,
                    "Primary dependency is unavailable and no trusted fallback was selected",
                )
            ]
        fallback = self._fallbacks.get(request.fallback.fallback_id)
        if fallback is None:
            return None, [
                self._finding(
                    FailureContainmentCode.FALLBACK_UNKNOWN,
                    Severity.CRITICAL,
                    "Fallback is not declared by policy",
                )
            ]
        findings: list[FailureContainmentFinding] = []
        if (
            fallback.primary_dependency_id != dependency.dependency_id
            or fallback.fallback_id not in dependency.allowed_fallback_ids
        ):
            findings.append(
                self._finding(
                    FailureContainmentCode.FALLBACK_NOT_ALLOWED,
                    Severity.CRITICAL,
                    "Fallback is not allowlisted for the primary dependency",
                )
            )
        if fallback.artifact_digest != request.fallback.artifact_digest:
            findings.append(
                self._finding(
                    FailureContainmentCode.FALLBACK_INTEGRITY_INVALID,
                    Severity.CRITICAL,
                    "Fallback artifact does not match the pinned digest",
                )
            )
        if fallback.allowed_tenant_ids and request.tenant_id not in fallback.allowed_tenant_ids:
            findings.append(
                self._finding(
                    FailureContainmentCode.TENANT_NOT_ALLOWED,
                    Severity.CRITICAL,
                    "Tenant is not allowed to use this fallback",
                )
            )
        target = self._dependencies[fallback.target_dependency_id]
        findings.extend(self._tenant_findings(target, request.tenant_id))
        if self._dependency_unavailable(request.tenant_id, target, now, events):
            findings.append(
                self._finding(
                    FailureContainmentCode.FALLBACK_UNAVAILABLE,
                    Severity.CRITICAL,
                    "Fallback dependency or failure domain is unavailable",
                )
            )
        return fallback, findings

    def _issue_permit(
        self,
        request: FailureContainmentRequest,
        primary: DependencyDeclaration,
        selected: DependencyDeclaration,
        fallback: FallbackDeclaration | None,
        now: datetime,
    ) -> AuthorizedDependencyAttempt:
        circuit = self._circuit(request.tenant_id, selected)
        if circuit.state == CircuitState.HALF_OPEN:
            circuit.half_open_probe_active = True
        permit = AuthorizedDependencyAttempt.create(
            permit_id=str(uuid.uuid4()),
            request_digest=request.request_digest,
            operation_id=request.operation_id,
            attempt_id=request.attempt_id,
            tenant_id=request.tenant_id,
            primary_dependency_id=primary.dependency_id,
            selected_dependency_id=selected.dependency_id,
            failure_domain_id=selected.failure_domain_id,
            fallback_id=fallback.fallback_id if fallback else None,
            idempotency_key=request.idempotency_key,
            issued_at=now,
            expires_at=now + timedelta(seconds=self._policy.permit_ttl_seconds),
        )
        self._active_permits[permit.permit_id] = _ActivePermit(
            permit_digest=permit.permit_digest,
            expected_cost=request.expected_cost,
            side_effecting=request.side_effecting,
            recursion_depth=request.recursion_depth,
            retry_count=request.retry_count,
        )
        self._seen_attempt_ids.add((request.tenant_id, request.attempt_id))
        operation_key = (request.tenant_id, request.operation_id)
        self._operation_attempts[operation_key] = self._operation_attempts.get(operation_key, 0) + 1
        if request.side_effecting and request.idempotency_key is not None:
            self._active_side_effects.add((request.tenant_id, request.idempotency_key))
        return permit

    def _outcome_findings(
        self,
        report: DependencyOutcomeReport,
        dependency: DependencyDeclaration,
        circuit: _CircuitRuntime,
    ) -> list[FailureContainmentFinding]:
        findings: list[FailureContainmentFinding] = []
        samples = tuple(circuit.samples)
        breaker = dependency.breaker
        if not report.success:
            findings.append(
                self._finding(
                    FailureContainmentCode.DEPENDENCY_ERROR,
                    Severity.HIGH,
                    "Dependency reported an unsuccessful terminal outcome",
                    FailureSignal.ERROR_RATE,
                )
            )
        if report.cost > self._policy.max_cost_per_attempt:
            findings.append(
                self._finding(
                    FailureContainmentCode.COST_LIMIT_EXCEEDED,
                    Severity.HIGH,
                    "Observed attempt cost exceeds policy",
                    FailureSignal.COST,
                )
            )
        if (
            len(samples) >= breaker.minimum_samples
            and self._error_rate(samples) >= breaker.error_rate_threshold
        ):
            findings.append(
                self._finding(
                    FailureContainmentCode.ERROR_RATE_THRESHOLD_EXCEEDED,
                    Severity.HIGH,
                    "Dependency error-rate threshold was reached",
                    FailureSignal.ERROR_RATE,
                )
            )
        if (
            len(samples) >= breaker.minimum_samples
            and self._average_latency(samples) >= breaker.average_latency_ms_threshold
        ):
            findings.append(
                self._finding(
                    FailureContainmentCode.LATENCY_THRESHOLD_EXCEEDED,
                    Severity.HIGH,
                    "Dependency average-latency threshold was reached",
                    FailureSignal.LATENCY,
                )
            )
        if sum(sample.cost for sample in samples) >= breaker.cumulative_cost_threshold:
            findings.append(
                self._finding(
                    FailureContainmentCode.COST_THRESHOLD_EXCEEDED,
                    Severity.HIGH,
                    "Dependency rolling cost threshold was reached",
                    FailureSignal.COST,
                )
            )
        if (
            sum(sample.abnormal_tool_call_count for sample in samples)
            >= breaker.abnormal_tool_call_threshold
        ):
            findings.append(
                self._finding(
                    FailureContainmentCode.TOOL_CALL_THRESHOLD_EXCEEDED,
                    Severity.HIGH,
                    "Dependency abnormal tool-call threshold was reached",
                    FailureSignal.ABNORMAL_TOOL_CALL,
                )
            )
        return findings

    def _advance_half_open(
        self,
        tenant_id: str,
        dependency: DependencyDeclaration,
        circuit: _CircuitRuntime,
        now: datetime,
        events: list[FailureContainmentAuditEvent],
    ) -> None:
        if (
            circuit.state == CircuitState.OPEN
            and circuit.opened_at is not None
            and now >= circuit.opened_at + timedelta(seconds=dependency.breaker.open_seconds)
        ):
            circuit.state = CircuitState.HALF_OPEN
            circuit.half_open_probe_active = False
            request = FailureContainmentRequest.create(
                request_id="circuit-transition",
                attempt_id="circuit-transition",
                operation_id="circuit-recovery",
                dependency_id=dependency.dependency_id,
                tenant_id=tenant_id,
            )
            events.append(
                self._event(
                    kind=FailureContainmentEventKind.CIRCUIT_HALF_OPENED,
                    request=request,
                    dependency=dependency,
                    action=GuardAction.WARN,
                    now=now,
                )
            )

    def _circuit(self, tenant_id: str, dependency: DependencyDeclaration) -> _CircuitRuntime:
        key = (tenant_id, dependency.dependency_id)
        circuit = self._circuits.get(key)
        if circuit is None:
            circuit = _CircuitRuntime(samples=deque(maxlen=dependency.breaker.window_size))
            self._circuits[key] = circuit
        return circuit

    def _finish_side_effect(
        self, permit: AuthorizedDependencyAttempt, report: DependencyOutcomeReport
    ) -> None:
        if permit.idempotency_key is None:
            return
        key = (permit.tenant_id, permit.idempotency_key)
        self._active_side_effects.discard(key)
        if report.side_effect_committed:
            self._committed_side_effects.add(key)

    def _event(
        self,
        *,
        kind: FailureContainmentEventKind,
        request: FailureContainmentRequest,
        dependency: DependencyDeclaration,
        action: GuardAction,
        now: datetime,
        findings: list[FailureContainmentFinding] | None = None,
    ) -> FailureContainmentAuditEvent:
        self._event_sequence += 1
        circuit = self._circuit(request.tenant_id, dependency)
        return FailureContainmentAuditEvent.create(
            sequence=self._event_sequence,
            kind=kind,
            tenant_id=self._safe_identifier(request.tenant_id, "invalid-tenant"),
            operation_id=self._safe_identifier(request.operation_id, "invalid-operation"),
            dependency_id=self._safe_identifier(dependency.dependency_id, "invalid-dependency"),
            failure_domain_id=self._safe_identifier(dependency.failure_domain_id, "invalid-domain"),
            action=action,
            circuit_state=circuit.state,
            finding_codes=tuple(item.code for item in self._deduplicate(findings or [])),
            occurred_at=now,
        )

    def _publish(
        self,
        events: list[FailureContainmentAuditEvent],
        dispatch: _HookDispatch,
    ) -> None:
        if self._audit_sink is not None:
            for event in events:
                with contextlib.suppress(Exception):
                    self._audit_sink.emit(event)
        if self._hooks is None:
            return
        for event in dispatch.degraded:
            self._invoke_hook(self._hooks.enter_degraded_mode, event, events)
        for event in dispatch.cancellation:
            self._invoke_hook(self._hooks.cancel, event, events)
        for event in dispatch.compensation:
            self._invoke_hook(self._hooks.compensate, event, events)
        for event in dispatch.recovery:
            self._invoke_hook(self._hooks.recover, event, events)

    def _invoke_hook(
        self,
        callback: Callable[[FailureContainmentAuditEvent], None],
        event: FailureContainmentAuditEvent,
        events: list[FailureContainmentAuditEvent],
    ) -> None:
        try:
            callback(event)
        except Exception:
            with self._lock:
                self._event_sequence += 1
                failed_event = FailureContainmentAuditEvent.create(
                    sequence=self._event_sequence,
                    kind=FailureContainmentEventKind.HOOK_FAILED,
                    tenant_id=event.tenant_id,
                    operation_id=event.operation_id,
                    dependency_id=event.dependency_id,
                    failure_domain_id=event.failure_domain_id,
                    action=GuardAction.BLOCK,
                    circuit_state=event.circuit_state,
                    finding_codes=(FailureContainmentCode.HOOK_FAILED,),
                    occurred_at=event.occurred_at,
                )
                events.append(failed_event)
            if self._audit_sink is not None:
                with contextlib.suppress(Exception):
                    self._audit_sink.emit(failed_event)

    def _verify_outcome(self, report: DependencyOutcomeReport) -> bool:
        if self._outcome_verifier is None:
            return False
        try:
            return self._outcome_verifier.verify_outcome(report)
        except Exception:
            return False

    @staticmethod
    def _error_rate(samples: tuple[_Sample, ...]) -> float:
        if not samples:
            return 0.0
        return sum(not sample.success for sample in samples) / len(samples)

    @staticmethod
    def _average_latency(samples: tuple[_Sample, ...]) -> float:
        if not samples:
            return 0.0
        return sum(sample.latency_ms for sample in samples) / len(samples)

    @staticmethod
    def _finding(
        code: FailureContainmentCode,
        severity: Severity,
        message: str,
        signal: FailureSignal | None = None,
    ) -> FailureContainmentFinding:
        return FailureContainmentFinding(
            code=code,
            severity=severity,
            message=message,
            signal=signal,
        )

    @staticmethod
    def _deduplicate(
        findings: list[FailureContainmentFinding],
    ) -> list[FailureContainmentFinding]:
        result: list[FailureContainmentFinding] = []
        seen: set[FailureContainmentCode] = set()
        for finding in findings:
            if finding.code not in seen:
                seen.add(finding.code)
                result.append(finding)
        return result

    @staticmethod
    def _placeholder_dependency(dependency_id: str) -> DependencyDeclaration:
        return DependencyDeclaration(
            dependency_id=FailureContainmentManager._safe_identifier(
                dependency_id, "unknown-dependency"
            ),
            failure_domain_id="unknown-domain",
            health=DependencyHealth.UNAVAILABLE,
        )

    @staticmethod
    def _request_from_permit(
        permit: AuthorizedDependencyAttempt,
    ) -> FailureContainmentRequest:
        return FailureContainmentRequest.model_construct(
            request_id=FailureContainmentManager._safe_identifier(
                permit.permit_id, "invalid-permit"
            ),
            attempt_id=FailureContainmentManager._safe_identifier(
                permit.attempt_id, "invalid-attempt"
            ),
            operation_id=FailureContainmentManager._safe_identifier(
                permit.operation_id, "invalid-operation"
            ),
            dependency_id=FailureContainmentManager._safe_identifier(
                permit.primary_dependency_id, "invalid-dependency"
            ),
            tenant_id=FailureContainmentManager._safe_identifier(
                permit.tenant_id, "invalid-tenant"
            ),
            idempotency_key=permit.idempotency_key,
            side_effecting=permit.idempotency_key is not None,
            request_digest=permit.request_digest,
        )

    @staticmethod
    def _safe_identifier(value: str, fallback: str) -> str:
        return value if _SAFE_IDENTIFIER_RE.fullmatch(value) is not None else fallback

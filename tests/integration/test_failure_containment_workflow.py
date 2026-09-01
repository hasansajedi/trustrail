"""End-to-end primary failure, containment, and trusted fallback workflow."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from trustrail import (
    CircuitBreakerPolicy,
    DependencyCriticality,
    DependencyDeclaration,
    DependencyHealth,
    DependencyOutcomeReport,
    FailureContainmentEventKind,
    FailureContainmentManager,
    FailureContainmentPolicy,
    FailureContainmentRequest,
    FailureDomainDeclaration,
    FallbackDeclaration,
    FallbackSelection,
    GuardAction,
    MemoryFailureContainmentAuditSink,
)

NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)
FALLBACK_DIGEST = "a" * 64


class AuthenticatedDependencyBroker:
    """Contract fake for reports issued by an authoritative dependency broker."""

    def __init__(self) -> None:
        self.reports: set[tuple[str, str]] = set()

    def report(self, permit, *, success: bool, report_id: str) -> DependencyOutcomeReport:
        report = DependencyOutcomeReport.create(
            report_id=report_id,
            permit_id=permit.permit_id,
            permit_digest=permit.permit_digest,
            success=success,
            latency_ms=25.0,
            cost=0.02,
            completed_at=permit.issued_at + timedelta(seconds=1),
        )
        self.reports.add((report.report_id, report.report_digest))
        return report

    def verify_outcome(self, report: DependencyOutcomeReport) -> bool:
        return (report.report_id, report.report_digest) in self.reports


class WorkflowHooks:
    def __init__(self) -> None:
        self.degraded_dependencies: list[str] = []
        self.cancelled_domains: list[str] = []
        self.compensated_operations: list[str] = []
        self.recovered_dependencies: list[str] = []

    def enter_degraded_mode(self, event) -> None:
        self.degraded_dependencies.append(event.dependency_id)

    def cancel(self, event) -> None:
        self.cancelled_domains.append(event.failure_domain_id)

    def compensate(self, event) -> None:
        self.compensated_operations.append(event.operation_id)

    def recover(self, event) -> None:
        self.recovered_dependencies.append(event.dependency_id)


def test_primary_outage_is_contained_and_trusted_cross_domain_fallback_completes():
    breaker = CircuitBreakerPolicy(minimum_samples=1, error_rate_threshold=1.0)
    policy = FailureContainmentPolicy(
        dependencies=(
            DependencyDeclaration(
                dependency_id="generation-primary",
                failure_domain_id="cloud-a/eu",
                criticality=DependencyCriticality.CRITICAL,
                health=DependencyHealth.HEALTHY,
                allowed_fallback_ids=frozenset({"generation-backup-v2"}),
                breaker=breaker,
            ),
            DependencyDeclaration(
                dependency_id="generation-backup",
                failure_domain_id="cloud-b/eu",
                breaker=breaker,
            ),
        ),
        failure_domains=(
            FailureDomainDeclaration(failure_domain_id="cloud-a/eu"),
            FailureDomainDeclaration(failure_domain_id="cloud-b/eu"),
        ),
        fallbacks=(
            FallbackDeclaration(
                fallback_id="generation-backup-v2",
                primary_dependency_id="generation-primary",
                target_dependency_id="generation-backup",
                artifact_digest=FALLBACK_DIGEST,
            ),
        ),
    )
    broker = AuthenticatedDependencyBroker()
    hooks = WorkflowHooks()
    audit = MemoryFailureContainmentAuditSink()
    manager = FailureContainmentManager(
        policy,
        outcome_verifier=broker,
        hooks=hooks,
        audit_sink=audit,
    )

    first_request = FailureContainmentRequest.create(
        request_id="request-primary",
        attempt_id="attempt-primary",
        operation_id="generate-answer-primary",
        dependency_id="generation-primary",
        tenant_id="customer-a",
    )
    first_permit = manager.require(first_request, now=NOW)
    failed = manager.record_outcome(
        first_permit,
        broker.report(first_permit, success=False, report_id="primary-failure"),
        now=NOW + timedelta(seconds=1),
    )
    assert failed.action == GuardAction.BLOCK
    assert hooks.cancelled_domains == ["cloud-a/eu"]

    fallback_request = FailureContainmentRequest.create(
        request_id="request-fallback",
        attempt_id="attempt-fallback",
        operation_id="generate-answer-fallback",
        dependency_id="generation-primary",
        tenant_id="customer-a",
        fallback=FallbackSelection(
            fallback_id="generation-backup-v2",
            artifact_digest=FALLBACK_DIGEST,
        ),
    )
    fallback_permit = manager.require(fallback_request, now=NOW + timedelta(seconds=2))
    completed = manager.record_outcome(
        fallback_permit,
        broker.report(fallback_permit, success=True, report_id="fallback-success"),
        now=NOW + timedelta(seconds=3),
    )

    assert fallback_permit.selected_dependency_id == "generation-backup"
    assert completed.action == GuardAction.ALLOW
    assert hooks.degraded_dependencies == ["generation-primary", "generation-primary"]
    assert FailureContainmentEventKind.CIRCUIT_OPENED in {event.kind for event in audit.events}
    assert [event.sequence for event in audit.events] == list(range(1, len(audit.events) + 1))

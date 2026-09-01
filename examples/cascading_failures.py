"""Contain a dependency outage and dispatch only an integrity-pinned fallback."""

from datetime import UTC, datetime

from trustrail import (
    DependencyDeclaration,
    DependencyHealth,
    DependencyOutcomeReport,
    FailureContainmentManager,
    FailureContainmentPolicy,
    FailureContainmentRequest,
    FailureDomainDeclaration,
    FallbackDeclaration,
    FallbackSelection,
)

fallback_digest = "a" * 64  # Resolve from a protected artifact catalog in production.
policy = FailureContainmentPolicy(
    dependencies=(
        DependencyDeclaration(
            dependency_id="primary-model",
            failure_domain_id="provider-a/eu",
            health=DependencyHealth.UNAVAILABLE,
            allowed_fallback_ids=frozenset({"backup-model-v1"}),
        ),
        DependencyDeclaration(
            dependency_id="backup-model",
            failure_domain_id="provider-b/eu",
        ),
    ),
    failure_domains=(
        FailureDomainDeclaration(failure_domain_id="provider-a/eu"),
        FailureDomainDeclaration(failure_domain_id="provider-b/eu"),
    ),
    fallbacks=(
        FallbackDeclaration(
            fallback_id="backup-model-v1",
            primary_dependency_id="primary-model",
            target_dependency_id="backup-model",
            artifact_digest=fallback_digest,
        ),
    ),
    max_retries_per_operation=2,
    max_recursion_depth=4,
)


class TrustedBroker:
    """Minimal stand-in for an authenticated dependency gateway."""

    def __init__(self) -> None:
        self.trusted_reports: set[tuple[str, str]] = set()

    def trust(self, report: DependencyOutcomeReport) -> None:
        self.trusted_reports.add((report.report_id, report.report_digest))

    def verify_outcome(self, report: DependencyOutcomeReport) -> bool:
        return (report.report_id, report.report_digest) in self.trusted_reports


broker = TrustedBroker()
manager = FailureContainmentManager(policy, outcome_verifier=broker)
request = FailureContainmentRequest.create(
    request_id="request-1",
    attempt_id="attempt-1",
    operation_id="generate-answer",
    dependency_id="primary-model",
    tenant_id="tenant-a",  # Derive from authenticated server-side identity.
    fallback=FallbackSelection(
        fallback_id="backup-model-v1",
        artifact_digest=fallback_digest,
    ),
)
now = datetime(2026, 9, 1, 12, tzinfo=UTC)
permit = manager.require(request, now=now)
assert permit.selected_dependency_id == "backup-model"

# The application dispatches through its broker, then authenticates the exact
# terminal report before trusting it as a breaker signal.
report = DependencyOutcomeReport.create(
    report_id="report-1",
    permit_id=permit.permit_id,
    permit_digest=permit.permit_digest,
    success=True,
    latency_ms=42.0,
    cost=0.01,
    completed_at=now,
)
broker.trust(report)
result = manager.record_outcome(permit, report, now=now)
print(result.action.value)  # allow

"""Bypass corpus for OWASP ASI08 cascading failures."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    CircuitBreakerPolicy,
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

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "cascading_failures.json"
CASES: list[dict[str, str]] = json.loads(CORPUS_PATH.read_text())
NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)
FALLBACK_DIGEST = "a" * 64


class ReportStore:
    def __init__(self) -> None:
        self.reports: set[tuple[str, str]] = set()

    def trust(self, report: DependencyOutcomeReport) -> None:
        self.reports.add((report.report_id, report.report_digest))

    def verify_outcome(self, report: DependencyOutcomeReport) -> bool:
        return (report.report_id, report.report_digest) in self.reports


def _policy(
    primary_health: DependencyHealth = DependencyHealth.HEALTHY,
) -> FailureContainmentPolicy:
    breaker = CircuitBreakerPolicy(minimum_samples=4)
    return FailureContainmentPolicy(
        dependencies=(
            DependencyDeclaration(
                dependency_id="primary",
                failure_domain_id="domain-a",
                health=primary_health,
                allowed_fallback_ids=frozenset({"fallback-v1"}),
                breaker=breaker,
            ),
            DependencyDeclaration(
                dependency_id="backup",
                failure_domain_id="domain-b",
                breaker=breaker,
            ),
        ),
        failure_domains=(
            FailureDomainDeclaration(failure_domain_id="domain-a"),
            FailureDomainDeclaration(failure_domain_id="domain-b"),
        ),
        fallbacks=(
            FallbackDeclaration(
                fallback_id="fallback-v1",
                primary_dependency_id="primary",
                target_dependency_id="backup",
                artifact_digest=FALLBACK_DIGEST,
            ),
        ),
        max_retries_per_operation=2,
        max_recursion_depth=2,
        max_cost_per_attempt=5.0,
        max_abnormal_tool_calls_per_attempt=0,
    )


def _request(**updates: object) -> FailureContainmentRequest:
    values: dict[str, object] = {
        "request_id": "security-request",
        "attempt_id": "security-attempt",
        "operation_id": "security-operation",
        "dependency_id": "primary",
        "tenant_id": "tenant-a",
    }
    values.update(updates)
    return FailureContainmentRequest.create(**values)


def _report(permit, **updates: object) -> DependencyOutcomeReport:
    values: dict[str, object] = {
        "report_id": "security-report",
        "permit_id": permit.permit_id,
        "permit_digest": permit.permit_digest,
        "success": True,
        "latency_ms": 10.0,
        "completed_at": NOW + timedelta(seconds=1),
    }
    values.update(updates)
    return DependencyOutcomeReport.create(**values)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_cascading_failure_bypass_corpus(case: dict[str, str]):
    mutation = case["mutation"]
    store = ReportStore()
    unavailable = mutation in {"fallback_digest", "fallback_unknown"}
    manager = FailureContainmentManager(
        _policy(DependencyHealth.UNAVAILABLE if unavailable else DependencyHealth.HEALTHY),
        outcome_verifier=None if mutation == "report_auth" else store,
    )

    if mutation == "request_tamper":
        request = _request().model_copy(update={"tenant_id": "tenant-attacker"})
        result = manager.authorize(request, now=NOW)
    elif mutation == "retry_reset":
        first = manager.require(_request(), now=NOW)
        report = _report(first)
        store.trust(report)
        manager.record_outcome(first, report, now=NOW + timedelta(seconds=1))
        result = manager.authorize(
            _request(attempt_id="security-retry", retry_count=0),
            now=NOW + timedelta(seconds=2),
        )
    elif mutation == "recursion":
        result = manager.authorize(_request(recursion_depth=3), now=NOW)
    elif mutation == "cost":
        result = manager.authorize(_request(expected_cost=5.01), now=NOW)
    elif mutation == "tool_calls":
        result = manager.authorize(_request(abnormal_tool_call_count=1), now=NOW)
    elif mutation in {"fallback_digest", "fallback_unknown"}:
        result = manager.authorize(
            _request(
                fallback=FallbackSelection(
                    fallback_id="unknown" if mutation == "fallback_unknown" else "fallback-v1",
                    artifact_digest="b" * 64,
                )
            ),
            now=NOW,
        )
    elif mutation == "duplicate_side_effect":
        manager.require(
            _request(side_effecting=True, idempotency_key="transfer-once"),
            now=NOW,
        )
        result = manager.authorize(
            _request(
                request_id="security-request-2",
                attempt_id="security-attempt-2",
                operation_id="security-operation-2",
                side_effecting=True,
                idempotency_key="transfer-once",
            ),
            now=NOW,
        )
    else:
        permit = manager.require(_request(), now=NOW)
        if mutation == "permit_tamper":
            permit = permit.model_copy(update={"selected_dependency_id": "backup"})
            report = _report(permit)
        else:
            report = _report(permit)
            if mutation == "report_binding":
                report = report.model_copy(update={"permit_id": "other-permit"})
        if mutation != "report_auth":
            store.trust(report)
        result = manager.record_outcome(permit, report, now=NOW + timedelta(seconds=1))

    assert case["expected_code"] in {finding.code.value for finding in result.findings}

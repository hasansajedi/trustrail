"""Unit tests for OWASP ASI08 cascading-failure containment."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from trustrail import (
    CircuitBreakerPolicy,
    CircuitState,
    DependencyCriticality,
    DependencyDeclaration,
    DependencyHealth,
    DependencyOutcomeReport,
    FailureContainmentCode,
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


def _breaker(**updates: object) -> CircuitBreakerPolicy:
    return CircuitBreakerPolicy(
        window_size=updates.pop("window_size", 4),
        minimum_samples=updates.pop("minimum_samples", 1),
        error_rate_threshold=updates.pop("error_rate_threshold", 1.0),
        average_latency_ms_threshold=updates.pop("average_latency_ms_threshold", 100.0),
        cumulative_cost_threshold=updates.pop("cumulative_cost_threshold", 10.0),
        abnormal_tool_call_threshold=updates.pop("abnormal_tool_call_threshold", 2),
        open_seconds=updates.pop("open_seconds", 10),
        **updates,
    )


def _policy(
    *,
    primary_health: DependencyHealth = DependencyHealth.HEALTHY,
    breaker: CircuitBreakerPolicy | None = None,
    criticality: DependencyCriticality = DependencyCriticality.CRITICAL,
    **updates: object,
) -> FailureContainmentPolicy:
    active_breaker = breaker or _breaker()
    return FailureContainmentPolicy(
        dependencies=(
            DependencyDeclaration(
                dependency_id="primary-model",
                failure_domain_id="provider-a",
                criticality=criticality,
                health=primary_health,
                allowed_tenant_ids=frozenset({"tenant-a", "tenant-b"}),
                allowed_fallback_ids=frozenset({"fallback-v1"}),
                breaker=active_breaker,
            ),
            DependencyDeclaration(
                dependency_id="backup-model",
                failure_domain_id="provider-b",
                allowed_tenant_ids=frozenset({"tenant-a", "tenant-b"}),
                breaker=active_breaker,
            ),
        ),
        failure_domains=(
            FailureDomainDeclaration(failure_domain_id="provider-a"),
            FailureDomainDeclaration(failure_domain_id="provider-b"),
        ),
        fallbacks=(
            FallbackDeclaration(
                fallback_id="fallback-v1",
                primary_dependency_id="primary-model",
                target_dependency_id="backup-model",
                artifact_digest=FALLBACK_DIGEST,
                allowed_tenant_ids=frozenset({"tenant-a", "tenant-b"}),
            ),
        ),
        **updates,
    )


def _request(sequence: int = 0, **updates: object) -> FailureContainmentRequest:
    values: dict[str, object] = {
        "request_id": f"request-{sequence}",
        "attempt_id": f"attempt-{sequence}",
        "operation_id": f"operation-{sequence}",
        "dependency_id": "primary-model",
        "tenant_id": "tenant-a",
    }
    values.update(updates)
    return FailureContainmentRequest.create(**values)


def _report(
    permit: object,
    sequence: int = 0,
    **updates: object,
) -> DependencyOutcomeReport:
    values: dict[str, object] = {
        "report_id": f"report-{sequence}",
        "permit_id": permit.permit_id,
        "permit_digest": permit.permit_digest,
        "success": True,
        "latency_ms": 10.0,
        "completed_at": permit.issued_at + timedelta(seconds=1),
    }
    values.update(updates)
    return DependencyOutcomeReport.create(**values)


def _codes(result: object) -> set[FailureContainmentCode]:
    return {finding.code for finding in result.findings}


class IntegrityReportVerifier:
    def verify_outcome(self, report):
        return report.has_valid_integrity


def _manager(policy=None, **kwargs):
    return FailureContainmentManager(
        policy or _policy(),
        outcome_verifier=IntegrityReportVerifier(),
        **kwargs,
    )


def test_policy_rejects_correlated_fallback_failure_domain():
    with pytest.raises(ValidationError, match="different failure domain"):
        FailureContainmentPolicy(
            dependencies=(
                DependencyDeclaration(
                    dependency_id="primary",
                    failure_domain_id="shared",
                    allowed_fallback_ids=frozenset({"fallback"}),
                ),
                DependencyDeclaration(
                    dependency_id="backup",
                    failure_domain_id="shared",
                ),
            ),
            failure_domains=(FailureDomainDeclaration(failure_domain_id="shared"),),
            fallbacks=(
                FallbackDeclaration(
                    fallback_id="fallback",
                    primary_dependency_id="primary",
                    target_dependency_id="backup",
                    artifact_digest=FALLBACK_DIGEST,
                ),
            ),
        )


def test_successful_attempt_uses_single_use_permit_and_records_snapshot():
    sink = MemoryFailureContainmentAuditSink()
    manager = _manager(audit_sink=sink)
    permit = manager.require(_request(), now=NOW)

    result = manager.record_outcome(permit, _report(permit), now=NOW + timedelta(seconds=1))

    assert result.action == GuardAction.ALLOW
    assert manager.snapshot("tenant-a", "primary-model").sample_count == 1
    assert [event.kind for event in sink.events] == [
        FailureContainmentEventKind.ADMISSION_ALLOWED,
        FailureContainmentEventKind.OUTCOME_RECORDED,
    ]
    assert len({event.event_id for event in sink.events}) == 2


def test_failed_attempt_opens_circuit_and_integrity_pinned_fallback_is_used():
    manager = _manager()
    permit = manager.require(_request(), now=NOW)
    failed = manager.record_outcome(
        permit,
        _report(permit, success=False),
        now=NOW + timedelta(seconds=1),
    )
    assert FailureContainmentCode.ERROR_RATE_THRESHOLD_EXCEEDED in _codes(failed)
    assert manager.snapshot("tenant-a", "primary-model").circuit_state == CircuitState.OPEN

    blocked = manager.authorize(_request(1), now=NOW + timedelta(seconds=2))
    assert blocked.action == GuardAction.BLOCK
    assert FailureContainmentCode.FALLBACK_REQUIRED in _codes(blocked)

    allowed = manager.authorize(
        _request(
            2,
            fallback=FallbackSelection(fallback_id="fallback-v1", artifact_digest=FALLBACK_DIGEST),
        ),
        now=NOW + timedelta(seconds=2),
    )
    assert allowed.is_authorized
    assert allowed.permit is not None
    assert allowed.permit.selected_dependency_id == "backup-model"
    assert allowed.permit.fallback_id == "fallback-v1"


def test_untrusted_or_unsolicited_fallback_substitution_is_blocked():
    unavailable = _manager(_policy(primary_health=DependencyHealth.UNAVAILABLE))
    bad_digest = unavailable.authorize(
        _request(fallback=FallbackSelection(fallback_id="fallback-v1", artifact_digest="b" * 64)),
        now=NOW,
    )
    assert FailureContainmentCode.FALLBACK_INTEGRITY_INVALID in _codes(bad_digest)

    healthy = _manager()
    unsolicited = healthy.authorize(
        _request(
            fallback=FallbackSelection(fallback_id="fallback-v1", artifact_digest=FALLBACK_DIGEST)
        ),
        now=NOW,
    )
    assert FailureContainmentCode.FALLBACK_NOT_REQUIRED in _codes(unsolicited)


def test_syntactically_tampered_request_returns_content_free_block():
    tampered = _request().model_copy(
        update={
            "dependency_id": "invalid\ndependency",
            "tenant_id": "invalid\ntenant",
            "operation_id": "invalid\noperation",
        }
    )
    result = _manager().authorize(tampered, now=NOW)
    assert result.action == GuardAction.BLOCK
    assert FailureContainmentCode.REQUEST_INTEGRITY_INVALID in _codes(result)
    assert result.events[0].dependency_id == "unknown-dependency"


def test_breaker_state_and_failure_domain_do_not_cross_tenants():
    manager = _manager()
    permit = manager.require(_request(), now=NOW)
    manager.record_outcome(
        permit,
        _report(permit, success=False),
        now=NOW + timedelta(seconds=1),
    )

    other_tenant = manager.authorize(
        _request(1, tenant_id="tenant-b"),
        now=NOW + timedelta(seconds=2),
    )
    assert other_tenant.is_authorized
    assert manager.snapshot("tenant-b", "primary-model").circuit_state == CircuitState.CLOSED


def test_authoritative_retry_sequence_stops_retry_storms():
    manager = _manager(
        _policy(
            breaker=_breaker(minimum_samples=4),
            max_retries_per_operation=1,
        )
    )
    first = _request(operation_id="shared-operation")
    first_permit = manager.require(first, now=NOW)
    manager.record_outcome(
        first_permit,
        _report(first_permit, success=False),
        now=NOW + timedelta(seconds=1),
    )

    skipped_sequence = manager.authorize(
        _request(1, operation_id="shared-operation", retry_count=0),
        now=NOW + timedelta(seconds=2),
    )
    assert FailureContainmentCode.RETRY_SEQUENCE_INVALID in _codes(skipped_sequence)

    retry = manager.require(
        _request(2, operation_id="shared-operation", retry_count=1),
        now=NOW + timedelta(seconds=2),
    )
    manager.record_outcome(retry, _report(retry, 2), now=NOW + timedelta(seconds=3))
    exhausted = manager.authorize(
        _request(3, operation_id="shared-operation", retry_count=2),
        now=NOW + timedelta(seconds=4),
    )
    assert FailureContainmentCode.RETRY_LIMIT_EXCEEDED in _codes(exhausted)


def test_side_effect_idempotency_reservation_is_atomic():
    manager = _manager()

    def authorize(index: int) -> GuardAction:
        return manager.authorize(
            _request(
                index,
                side_effecting=True,
                idempotency_key="charge-customer-1",
            ),
            now=NOW,
        ).action

    with ThreadPoolExecutor(max_workers=16) as executor:
        actions = list(executor.map(authorize, range(16)))

    assert actions.count(GuardAction.ALLOW) == 1
    assert actions.count(GuardAction.BLOCK) == 15


def test_committed_side_effect_cannot_be_replayed_after_completion():
    manager = _manager()
    request = _request(side_effecting=True, idempotency_key="payment-1")
    permit = manager.require(request, now=NOW)
    manager.record_outcome(
        permit,
        _report(permit, side_effect_committed=True),
        now=NOW + timedelta(seconds=1),
    )

    replay = manager.authorize(
        _request(1, side_effecting=True, idempotency_key="payment-1"),
        now=NOW + timedelta(seconds=2),
    )
    assert FailureContainmentCode.DUPLICATE_SIDE_EFFECT in _codes(replay)


@pytest.mark.parametrize(
    ("request_update", "expected_code"),
    [
        ({"recursion_depth": 9}, FailureContainmentCode.RECURSION_LIMIT_EXCEEDED),
        ({"expected_cost": 26.0}, FailureContainmentCode.COST_LIMIT_EXCEEDED),
        (
            {"abnormal_tool_call_count": 1},
            FailureContainmentCode.ABNORMAL_TOOL_CALL_LIMIT_EXCEEDED,
        ),
    ],
)
def test_admission_rejects_bounded_failure_signals(request_update, expected_code):
    result = _manager().authorize(_request(**request_update), now=NOW)
    assert expected_code in _codes(result)


@pytest.mark.parametrize(
    ("report_update", "expected_code"),
    [
        ({"latency_ms": 101.0}, FailureContainmentCode.LATENCY_THRESHOLD_EXCEEDED),
        ({"cost": 10.0}, FailureContainmentCode.COST_THRESHOLD_EXCEEDED),
        (
            {"abnormal_tool_call_count": 2},
            FailureContainmentCode.TOOL_CALL_THRESHOLD_EXCEEDED,
        ),
    ],
)
def test_observed_signals_open_the_circuit(report_update, expected_code):
    manager = _manager()
    permit = manager.require(_request(), now=NOW)
    result = manager.record_outcome(
        permit,
        _report(permit, **report_update),
        now=NOW + timedelta(seconds=1),
    )
    assert expected_code in _codes(result)
    assert manager.snapshot("tenant-a", "primary-model").circuit_state == CircuitState.OPEN


def test_report_and_permit_replay_are_blocked():
    manager = _manager()
    permit = manager.require(_request(), now=NOW)
    report = _report(permit)
    assert manager.record_outcome(permit, report, now=NOW + timedelta(seconds=1)).action == (
        GuardAction.ALLOW
    )

    replay = manager.record_outcome(permit, report, now=NOW + timedelta(seconds=2))
    assert FailureContainmentCode.PERMIT_REPLAYED in _codes(replay)
    assert FailureContainmentCode.REPORT_REPLAYED in _codes(replay)


class RecordingHooks:
    def __init__(self):
        self.degraded = []
        self.cancelled = []
        self.compensated = []
        self.recovered = []

    def enter_degraded_mode(self, event):
        self.degraded.append(event)

    def cancel(self, event):
        self.cancelled.append(event)

    def compensate(self, event):
        self.compensated.append(event)

    def recover(self, event):
        self.recovered.append(event)


class FailingHooks:
    def enter_degraded_mode(self, event):
        raise RuntimeError("degraded hook unavailable")

    def cancel(self, event):
        raise RuntimeError("cancellation hook unavailable")

    def compensate(self, event):
        raise RuntimeError("compensation hook unavailable")

    def recover(self, event):
        raise RuntimeError("recovery hook unavailable")


def test_critical_failure_dispatches_containment_and_successful_probe_recovers():
    hooks = RecordingHooks()
    manager = _manager(hooks=hooks)
    permit = manager.require(_request(side_effecting=True, idempotency_key="write-1"), now=NOW)
    manager.record_outcome(
        permit,
        _report(permit, success=False, side_effect_committed=True),
        now=NOW + timedelta(seconds=1),
    )
    assert hooks.degraded
    assert hooks.cancelled
    assert hooks.compensated

    probe = manager.require(_request(1), now=NOW + timedelta(seconds=11))
    recovered = manager.record_outcome(
        probe,
        _report(probe, 1),
        now=NOW + timedelta(seconds=12),
    )
    assert recovered.action == GuardAction.ALLOW
    assert hooks.recovered
    assert manager.snapshot("tenant-a", "primary-model").circuit_state == CircuitState.CLOSED


def test_only_one_concurrent_half_open_probe_is_allowed():
    manager = _manager()
    permit = manager.require(_request(), now=NOW)
    manager.record_outcome(
        permit,
        _report(permit, success=False),
        now=NOW + timedelta(seconds=1),
    )
    probe = manager.authorize(_request(1), now=NOW + timedelta(seconds=11))
    second = manager.authorize(_request(2), now=NOW + timedelta(seconds=11))
    assert probe.is_authorized
    assert second.action == GuardAction.BLOCK
    assert FailureContainmentCode.FALLBACK_REQUIRED in _codes(second)


def test_hook_exceptions_emit_deterministic_failure_events_without_raising():
    manager = _manager(hooks=FailingHooks())
    permit = manager.require(_request(side_effecting=True, idempotency_key="effect-1"), now=NOW)
    result = manager.record_outcome(
        permit,
        _report(permit, success=False, side_effect_committed=True),
        now=NOW + timedelta(seconds=1),
    )
    failed_events = [
        event for event in result.events if event.kind == FailureContainmentEventKind.HOOK_FAILED
    ]
    assert len(failed_events) == 3
    assert all(
        event.finding_codes == (FailureContainmentCode.HOOK_FAILED,) for event in failed_events
    )

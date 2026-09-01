# Cascading failure containment (OWASP ASI08:2026)

trustrail's failure-containment boundary addresses
[OWASP ASI08:2026 Cascading Failures](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
and complements the
[OWASP Secure AI Model Ops Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html).
Agent workflows can amplify one slow, compromised, unavailable, or incorrect
component through retries, delegation, shared state, and automated side effects.
`FailureContainmentManager` bounds that amplification before dispatch and turns
authenticated outcomes into tenant-isolated circuit decisions.

## Declare dependencies and failure domains

Inventory each dependency with an application-assigned criticality, initial
health, tenant allowlist, failure domain, and sliding-window thresholds. Put
correlated infrastructure in the same domain. A fallback must target a different
declared domain, be explicitly allowlisted by its primary, and match a pinned
artifact digest.

```python
from trustrail import (
    CircuitBreakerPolicy,
    DependencyCriticality,
    DependencyDeclaration,
    FailureContainmentPolicy,
    FailureDomainDeclaration,
    FallbackDeclaration,
)

breaker = CircuitBreakerPolicy(
    window_size=20,
    minimum_samples=5,
    error_rate_threshold=0.5,
    average_latency_ms_threshold=2_000,
    cumulative_cost_threshold=25.0,
    abnormal_tool_call_threshold=3,
    open_seconds=30,
)
policy = FailureContainmentPolicy(
    dependencies=(
        DependencyDeclaration(
            dependency_id="primary-model",
            failure_domain_id="provider-a/eu",
            criticality=DependencyCriticality.CRITICAL,
            allowed_tenant_ids=frozenset({"tenant-a"}),
            allowed_fallback_ids=frozenset({"backup-model-v2"}),
            breaker=breaker,
        ),
        DependencyDeclaration(
            dependency_id="backup-model",
            failure_domain_id="provider-b/eu",
            allowed_tenant_ids=frozenset({"tenant-a"}),
            breaker=breaker,
        ),
    ),
    failure_domains=(
        FailureDomainDeclaration(failure_domain_id="provider-a/eu"),
        FailureDomainDeclaration(failure_domain_id="provider-b/eu"),
    ),
    fallbacks=(
        FallbackDeclaration(
            fallback_id="backup-model-v2",
            primary_dependency_id="primary-model",
            target_dependency_id="backup-model",
            artifact_digest=approved_fallback_sha256,
            allowed_tenant_ids=frozenset({"tenant-a"}),
        ),
    ),
    max_retries_per_operation=2,
    max_recursion_depth=4,
    max_cost_per_attempt=5.0,
    max_abnormal_tool_calls_per_attempt=0,
    permit_ttl_seconds=30,
)
```

An empty dependency or fallback tenant set means the declaration is shared, but
runtime breaker, retry, attempt, and idempotency state is still keyed by tenant.
Never copy tenant IDs, health, criticality, domains, fallback digests, costs, or
tool-call anomaly counts from prompts or model output. Resolve them from trusted
identity, configuration, billing, and monitoring systems.

## Authorize before every dispatch

Use `FailureContainmentRequest.create()` and completely mediate primary calls,
fallback calls, retries, recursive sub-agents, and resumed workflows. Retry count
is checked against manager-owned operation state, so resetting or skipping the
caller counter does not bypass the limit. Side-effecting calls require an
idempotency key; its reservation is atomic with permit issuance.

```python
from trustrail import FailureContainmentManager, FailureContainmentRequest

manager = FailureContainmentManager(
    policy,
    outcome_verifier=authenticated_dependency_broker,
    hooks=workflow_hooks,
    audit_sink=containment_audit_sink,
)
request = FailureContainmentRequest.create(
    request_id=request_id,
    attempt_id=attempt_id,
    operation_id=operation_id,
    dependency_id="primary-model",
    tenant_id=authenticated_tenant_id,
    retry_count=authoritative_retry_count,
    recursion_depth=authoritative_agent_depth,
    expected_cost=estimated_provider_cost,
    abnormal_tool_call_count=trusted_anomaly_count,
    side_effecting=True,
    idempotency_key=transaction_id,
)
permit = manager.require(request)
dependency_gateway.dispatch(request, permit)
```

Permits are integrity-bound, short-lived, and single-use. The process-local lock
makes attempt sequencing, half-open probes, retry counters, and side-effect
reservations atomic within one manager. A committed idempotency key cannot be
dispatched again. If an attempt fails without committing its effect, completion
releases the reservation so a policy-compliant retry can reuse the downstream
idempotency key.

## Use trusted fallbacks only in degraded mode

The caller cannot substitute a fallback while the primary is healthy. When the
primary, its circuit, or its failure domain is unavailable, select the exact
declaration and pinned digest:

```python
from trustrail import FallbackSelection

request = FailureContainmentRequest.create(
    request_id=request_id,
    attempt_id=attempt_id,
    operation_id=operation_id,
    dependency_id="primary-model",
    tenant_id=authenticated_tenant_id,
    fallback=FallbackSelection(
        fallback_id="backup-model-v2",
        artifact_digest=approved_fallback_sha256,
    ),
)
permit = manager.require(request)
assert permit.selected_dependency_id == "backup-model"
```

Unknown, rebound, same-domain, tenant-incompatible, unavailable, or digest-mismatched
fallbacks fail closed. Fallback output still needs all normal authorization,
content, grounding, and output-handling checks; lower quality or different safety
behavior is not made trustworthy by successful admission.

## Authenticate outcomes and recover deliberately

The dependency gateway should issue a `DependencyOutcomeReport` bound to the
permit. `DependencyOutcomeVerifier` must authenticate the exact report using a
protected issuance record or signature. Missing, forged, rebound, replayed, or
expired evidence blocks and does not alter breaker observations.

Authenticated error rate and average latency use the configured rolling sample
window. Rolling cost and abnormal tool-call totals can open the circuit as soon
as their threshold is reached. An open circuit changes to half-open after
`open_seconds`; exactly one probe is admitted. A successful probe closes and
clears the circuit, while a failed probe reopens it.

`FailureContainmentHooks` exposes four application-owned actions:

- `enter_degraded_mode` reduces features and disables unsafe optional work;
- `cancel` stops queued and in-flight work for high or critical failures;
- `compensate` requests a domain-specific rollback after a failed committed effect;
- `recover` restores normal mode only after a successful half-open probe.

Each transition emits a `FailureContainmentAuditEvent` with a monotonic sequence,
stable event kind, finding codes, tenant, operation, dependency, domain, action,
and circuit state. Event IDs are canonical SHA-256 digests of those fields.
Events contain no prompts, model output, arguments, report payloads, or secrets.
Hook exceptions are isolated from breaker state and produce a metadata-only
`HOOK_FAILED` event; audit-sink exceptions cannot self-report. Monitor callback
delivery separately and design hooks to be idempotent.

## Security assumptions, limitations, and residual risk

- The built-in state is process-local. Multi-worker, multi-region, or restarted
  services require an application-owned shared atomic coordinator for circuits,
  permits, retries, report replay, and idempotency. Otherwise limits can be
  multiplied per worker and state is lost on restart.
- Report digests detect mutation but are not signatures. The verifier must use
  authenticated provider or gateway evidence. A compromised observer can poison
  health signals, suppress failures, or trip circuits deliberately.
- `expected_cost` and anomaly counts are only reliable when supplied from trusted
  accounting and monitoring. Reconcile reports with authoritative provider usage
  and enforce monetary quotas outside this component.
- Cancellation is cooperative in Python. Gate new work at the dispatcher and use
  provider deadlines, cancellation tokens, queue revocation, and infrastructure
  timeouts for already running work.
- Compensation cannot undo disclosed data, sent messages, external transfers,
  physical actions, or other irreversible effects. Prefer transactional APIs,
  conditional writes, downstream idempotency, and approval before high-impact work.
- Circuit breakers reduce blast radius; they do not diagnose correctness, prove a
  fallback is safe, isolate processes, authorize tools, ground output, or replace
  service-side access control, monitoring, incident response, and disaster recovery.

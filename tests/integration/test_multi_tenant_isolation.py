"""End-to-end multi-tenant isolation across every AI state category."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from trustrail import (
    DeploymentAttestationSigner,
    IsolationLevel,
    MemoryTenantIsolationAuditSink,
    TenantBatchRequest,
    TenantContextSigner,
    TenantIsolationGuard,
    TenantIsolationPolicy,
    TenantStateAccessRequest,
    TenantStateKeyBuilder,
    TenantStateKind,
    TenantStateOperation,
)

NOW = datetime(2026, 9, 27, 12, tzinfo=UTC)


def test_every_ai_state_is_tenant_keyed_bound_and_completely_mediated():
    context_signer = TenantContextSigner.generate(
        issuer_id="identity-control-plane",
        allowed_tenant_ids=frozenset({"tenant-confidential"}),
    )
    contexts = tuple(
        context_signer.issue(
            context_id=f"request-context-{index}",
            tenant_id="tenant-confidential",
            principal_id=f"support-agent-{index}",
            session_id=f"support-session-{index}",
            allowed_state_kinds=frozenset(TenantStateKind),
            issued_at=NOW,
            expires_at=NOW + timedelta(hours=1),
            nonce=f"nonce-{index}",
        )
        for index in range(2)
    )
    key_builder = TenantStateKeyBuilder(
        b"production-key-from-secret-manager-at-least-32-bytes",
        namespace="production-eu-ai-state",
    )
    isolated_kinds = frozenset({TenantStateKind.KV_CACHE, TenantStateKind.ADAPTER})
    policy = TenantIsolationPolicy.strict(
        policy_id="production-multi-tenant-policy",
        process_isolated=frozenset({TenantStateKind.ADAPTER}),
        hardware_isolated=frozenset({TenantStateKind.KV_CACHE}),
        dedicated_tenant=isolated_kinds,
    )
    attestor = DeploymentAttestationSigner.generate(
        issuer_id="confidential-compute-control-plane",
        allowed_deployment_ids=frozenset({"gpu-cluster-eu-1"}),
    )
    attestation = attestor.issue(
        attestation_id="deployment-attestation-17",
        deployment_id="gpu-cluster-eu-1",
        isolation_level=IsolationLevel.HARDWARE,
        covered_state_kinds=isolated_kinds,
        dedicated_tenant_ref=key_builder.tenant_reference("tenant-confidential"),
        measurement_digest="a" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
    )
    audit = MemoryTenantIsolationAuditSink()
    guard = TenantIsolationGuard(
        policy,
        key_builder,
        (context_signer.trusted_key,),
        trusted_attestation_keys=(attestor.trusted_key,),
        audit_sink=audit,
    )

    cache_kinds = {
        TenantStateKind.PROMPT_CACHE,
        TenantStateKind.RESPONSE_CACHE,
        TenantStateKind.SEMANTIC_CACHE,
        TenantStateKind.KV_CACHE,
    }
    for index, state_kind in enumerate(TenantStateKind):
        artifact_id = f"private-{state_kind.value}-artifact"
        state_key = key_builder.build(
            contexts[0],
            state_kind=state_kind,
            artifact_id=artifact_id,
        )
        deployment = "gpu-cluster-eu-1" if state_kind in isolated_kinds else None
        deployment_attestation = attestation if state_kind in isolated_kinds else None
        written = guard.require_state(
            TenantStateAccessRequest(
                request_id=f"write-{index}",
                context=contexts[0],
                state_kind=state_kind,
                operation=TenantStateOperation.WRITE,
                artifact_id=artifact_id,
                state_key=state_key,
                requested_expires_at=NOW + timedelta(minutes=20),
                deployment_id=deployment,
                attestation=deployment_attestation,
            ),
            now=NOW,
        )
        assert written.binding is not None

        operation = TenantStateOperation.RESTORE
        if state_kind in cache_kinds:
            operation = TenantStateOperation.CACHE_HIT
        elif state_kind == TenantStateKind.ADAPTER:
            operation = TenantStateOperation.ADAPTER_USE
        accessed = guard.require_state(
            TenantStateAccessRequest(
                request_id=f"access-{index}",
                context=contexts[1],
                state_kind=state_kind,
                operation=operation,
                artifact_id=artifact_id,
                state_key=key_builder.build(
                    contexts[1],
                    state_kind=state_kind,
                    artifact_id=artifact_id,
                ),
                observed_binding=written.binding,
                deployment_id=deployment,
                attestation=deployment_attestation,
            ),
            now=NOW + timedelta(minutes=1),
        )
        assert accessed.tenant_ref == written.tenant_ref
        assert accessed.storage_key == written.storage_key

    batch = guard.require_batch(
        TenantBatchRequest(
            request_id="same-tenant-inference-batch",
            contexts=contexts,
            state_kind=TenantStateKind.KV_CACHE,
            deployment_id="gpu-cluster-eu-1",
            attestation=attestation,
        ),
        now=NOW,
    )

    assert len(batch.context_digests) == 2
    assert len(audit.events) == 21
    serialized_audit = "".join(event.model_dump_json() for event in audit.events)
    assert "tenant-confidential" not in serialized_audit
    assert "private-" not in serialized_audit
    assert all(event.action.value == "allow" for event in audit.events)

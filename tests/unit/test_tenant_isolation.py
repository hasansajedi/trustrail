"""Unit tests for tenant-safe AI state and cache isolation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from trustrail import (
    DeploymentAttestationSigner,
    GuardAction,
    IsolationLevel,
    MemoryTenantIsolationAuditSink,
    MemoryTenantKeyClaimStore,
    TenantBatchRequest,
    TenantContextSigner,
    TenantIsolationCode,
    TenantIsolationError,
    TenantIsolationGuard,
    TenantIsolationPolicy,
    TenantSecurityContext,
    TenantStateAccessRequest,
    TenantStateKeyBuilder,
    TenantStateKind,
    TenantStateOperation,
)

NOW = datetime(2026, 9, 27, 10, tzinfo=UTC)
SECRET = b"tenant-isolation-test-secret-32-bytes-minimum"


def _signer() -> TenantContextSigner:
    return TenantContextSigner.generate(
        issuer_id="identity-control-plane",
        allowed_tenant_ids=frozenset({"tenant-a", "tenant-b"}),
    )


def _context(
    signer: TenantContextSigner,
    tenant_id: str = "tenant-a",
    *,
    context_id: str = "context-a",
    nonce: str = "nonce-a",
) -> TenantSecurityContext:
    return signer.issue(
        context_id=context_id,
        tenant_id=tenant_id,
        principal_id=f"principal-{tenant_id}",
        session_id=f"session-{tenant_id}",
        allowed_state_kinds=frozenset(TenantStateKind),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        nonce=nonce,
    )


def _guard(
    signer: TenantContextSigner,
    *,
    policy: TenantIsolationPolicy | None = None,
    builder: TenantStateKeyBuilder | None = None,
    claims: MemoryTenantKeyClaimStore | None = None,
    audit: MemoryTenantIsolationAuditSink | None = None,
    attestor: DeploymentAttestationSigner | None = None,
) -> TenantIsolationGuard:
    return TenantIsolationGuard(
        policy or TenantIsolationPolicy.strict(policy_id="tenant-policy"),
        builder or TenantStateKeyBuilder(SECRET, namespace="production-ai"),
        (signer.trusted_key,),
        trusted_attestation_keys=((attestor.trusted_key,) if attestor else ()),
        key_claim_store=claims,
        audit_sink=audit,
    )


def _request(
    context: TenantSecurityContext | None,
    builder: TenantStateKeyBuilder,
    *,
    kind: TenantStateKind = TenantStateKind.PROMPT_CACHE,
    operation: TenantStateOperation = TenantStateOperation.WRITE,
    artifact_id: str = "sensitive-prompt-42",
    binding=None,
):
    state_key = (
        builder.build(context, state_kind=kind, artifact_id=artifact_id)
        if context is not None
        else None
    )
    return TenantStateAccessRequest(
        request_id="state-request",
        context=context,
        state_kind=kind,
        operation=operation,
        artifact_id=artifact_id,
        state_key=state_key,
        observed_binding=binding,
        requested_expires_at=(
            NOW + timedelta(minutes=30) if operation == TenantStateOperation.WRITE else None
        ),
    )


def test_write_and_read_require_exact_tenant_binding_and_emit_safe_audit():
    signer = _signer()
    context = _context(signer)
    builder = TenantStateKeyBuilder(SECRET, namespace="production-ai")
    audit = MemoryTenantIsolationAuditSink()
    guard = _guard(signer, builder=builder, audit=audit)

    write = guard.require_state(_request(context, builder), now=NOW)

    assert write.binding is not None
    read_request = _request(
        context,
        builder,
        operation=TenantStateOperation.READ,
        binding=write.binding,
    )
    read = guard.require_state(read_request, now=NOW + timedelta(minutes=1))

    assert read.storage_key == write.storage_key
    assert read.tenant_ref == write.tenant_ref
    assert len(audit.events) == 2
    serialized = audit.events[-1].model_dump_json()
    assert "tenant-a" not in serialized
    assert "sensitive-prompt-42" not in serialized


def test_key_builder_separates_every_state_kind_and_tenant():
    signer = _signer()
    tenant_a = _context(signer)
    tenant_b = _context(signer, "tenant-b", context_id="context-b", nonce="nonce-b")
    builder = TenantStateKeyBuilder(SECRET, namespace="production-ai")

    keys_a = {
        builder.build(tenant_a, state_kind=kind, artifact_id="shared-id").storage_key
        for kind in TenantStateKind
    }
    keys_b = {
        builder.build(tenant_b, state_kind=kind, artifact_id="shared-id").storage_key
        for kind in TenantStateKind
    }

    assert len(keys_a) == len(TenantStateKind)
    assert len(keys_b) == len(TenantStateKind)
    assert keys_a.isdisjoint(keys_b)


def test_missing_and_forged_contexts_fail_closed():
    signer = _signer()
    context = _context(signer)
    builder = TenantStateKeyBuilder(SECRET, namespace="production-ai")
    guard = _guard(signer, builder=builder)
    forged = context.model_copy(update={"signature": "0" * 128})

    missing = guard.authorize_state(_request(None, builder), now=NOW)
    forged_result = guard.authorize_state(_request(forged, builder), now=NOW)

    assert missing.findings[0].code == TenantIsolationCode.CONTEXT_MISSING
    assert forged_result.findings[0].code == TenantIsolationCode.CONTEXT_SIGNATURE_INVALID


@pytest.mark.parametrize(
    ("kind", "operation", "expected"),
    [
        (
            TenantStateKind.SEMANTIC_CACHE,
            TenantStateOperation.CACHE_HIT,
            TenantIsolationCode.CACHE_HIT_CROSS_TENANT,
        ),
        (
            TenantStateKind.ADAPTER,
            TenantStateOperation.ADAPTER_USE,
            TenantIsolationCode.ADAPTER_CROSS_TENANT,
        ),
        (
            TenantStateKind.MEMORY,
            TenantStateOperation.RESTORE,
            TenantIsolationCode.RESTORE_CROSS_TENANT,
        ),
    ],
)
def test_cross_tenant_cache_adapter_and_restore_are_detected(kind, operation, expected):
    signer = _signer()
    tenant_a = _context(signer)
    tenant_b = _context(signer, "tenant-b", context_id="context-b", nonce="nonce-b")
    builder = TenantStateKeyBuilder(SECRET, namespace="production-ai")
    guard = _guard(signer, builder=builder)
    other_key = builder.build(tenant_b, state_kind=kind, artifact_id="shared-artifact")
    other_binding = builder.bind(
        other_key,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
    )

    result = guard.authorize_state(
        _request(
            tenant_a,
            builder,
            kind=kind,
            operation=operation,
            artifact_id="shared-artifact",
            binding=other_binding,
        ),
        now=NOW,
    )

    assert result.action == GuardAction.BLOCK
    assert expected in {finding.code for finding in result.findings}


def test_cross_tenant_inference_batch_is_rejected():
    signer = _signer()
    tenant_a = _context(signer)
    tenant_b = _context(signer, "tenant-b", context_id="context-b", nonce="nonce-b")
    guard = _guard(signer)

    result = guard.authorize_batch(
        TenantBatchRequest(
            request_id="mixed-batch",
            contexts=(tenant_a, tenant_b),
        ),
        now=NOW,
    )

    assert result.action == GuardAction.BLOCK
    assert TenantIsolationCode.BATCH_CROSS_TENANT in {finding.code for finding in result.findings}


def test_key_claim_collision_is_detected_atomically():
    signer = _signer()
    context = _context(signer)
    builder = TenantStateKeyBuilder(SECRET, namespace="production-ai")
    claims = MemoryTenantKeyClaimStore()
    request = _request(context, builder)
    assert request.state_key is not None
    assert claims.claim(request.state_key.storage_key, "0" * 64)

    result = _guard(signer, builder=builder, claims=claims).authorize_state(request, now=NOW)

    assert result.action == GuardAction.BLOCK
    assert result.findings[-1].code == TenantIsolationCode.STATE_KEY_COLLISION


def test_hardware_attestation_reports_claim_validation_not_infrastructure_proof():
    signer = _signer()
    context = _context(signer)
    builder = TenantStateKeyBuilder(SECRET, namespace="production-ai")
    policy = TenantIsolationPolicy.strict(
        policy_id="hardware-policy",
        hardware_isolated=frozenset({TenantStateKind.KV_CACHE}),
        dedicated_tenant=frozenset({TenantStateKind.KV_CACHE}),
    )
    attestor = DeploymentAttestationSigner.generate(
        issuer_id="deployment-control-plane",
        allowed_deployment_ids=frozenset({"gpu-cluster-eu"}),
    )
    attestation = attestor.issue(
        attestation_id="attestation-1",
        deployment_id="gpu-cluster-eu",
        isolation_level=IsolationLevel.HARDWARE,
        covered_state_kinds=frozenset({TenantStateKind.KV_CACHE}),
        dedicated_tenant_ref=builder.tenant_reference("tenant-a"),
        measurement_digest="a" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
    )
    guard = _guard(signer, policy=policy, builder=builder, attestor=attestor)

    result = guard.authorize_batch(
        TenantBatchRequest(
            request_id="isolated-batch",
            contexts=(context,),
            deployment_id="gpu-cluster-eu",
            attestation=attestation,
        ),
        now=NOW,
    )

    assert result.is_allowed
    assert result.attestation_evidence is not None
    assert result.attestation_evidence.claimed_isolation_level == IsolationLevel.HARDWARE
    assert result.attestation_evidence.validation_scope == "signature_and_claims_only"
    assert result.attestation_evidence.infrastructure_verified is False


def test_missing_or_insufficient_deployment_attestation_fails_closed():
    signer = _signer()
    context = _context(signer)
    policy = TenantIsolationPolicy.strict(
        policy_id="hardware-policy",
        hardware_isolated=frozenset({TenantStateKind.KV_CACHE}),
    )
    attestor = DeploymentAttestationSigner.generate(
        issuer_id="deployment-control-plane",
        allowed_deployment_ids=frozenset({"gpu-cluster-eu"}),
    )
    weak = attestor.issue(
        attestation_id="weak-attestation",
        deployment_id="gpu-cluster-eu",
        isolation_level=IsolationLevel.PROCESS,
        covered_state_kinds=frozenset({TenantStateKind.KV_CACHE}),
        measurement_digest="b" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
    )
    guard = _guard(signer, policy=policy, attestor=attestor)

    missing = guard.authorize_batch(
        TenantBatchRequest(request_id="missing-attestation", contexts=(context,)),
        now=NOW,
    )
    insufficient = guard.authorize_batch(
        TenantBatchRequest(
            request_id="weak-attestation",
            contexts=(context,),
            deployment_id="gpu-cluster-eu",
            attestation=weak,
        ),
        now=NOW,
    )

    assert missing.findings[-1].code == TenantIsolationCode.ATTESTATION_REQUIRED
    assert insufficient.findings[-1].code == TenantIsolationCode.ATTESTATION_LEVEL_INSUFFICIENT


def test_policy_requires_one_rule_for_every_state_kind():
    policy = TenantIsolationPolicy.strict(policy_id="complete-policy")

    with pytest.raises(ValidationError, match="at least 10 items"):
        TenantIsolationPolicy(
            policy_id="incomplete-policy",
            version=1,
            rules=policy.rules[:-1],
        )


def test_require_state_raises_typed_error():
    signer = _signer()
    builder = TenantStateKeyBuilder(SECRET, namespace="production-ai")

    with pytest.raises(TenantIsolationError) as raised:
        _guard(signer, builder=builder).require_state(_request(None, builder), now=NOW)

    assert raised.value.result.findings[0].code == TenantIsolationCode.CONTEXT_MISSING

"""Bypass-oriented security corpus for OWASP AISVS C5.3 isolation."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    DeploymentAttestationSigner,
    IsolationLevel,
    MemoryTenantKeyClaimStore,
    TenantBatchRequest,
    TenantContextSigner,
    TenantIsolationCode,
    TenantIsolationGuard,
    TenantIsolationPolicy,
    TenantStateAccessRequest,
    TenantStateKeyBuilder,
    TenantStateKind,
    TenantStateOperation,
)

NOW = datetime(2026, 9, 27, 14, tzinfo=UTC)
CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "multi_tenant_isolation.json"
CASES = json.loads(CORPUS_PATH.read_text())
SECRET = b"security-corpus-tenant-secret-at-least-32-bytes"


def _fixture():
    signer = TenantContextSigner.generate(
        issuer_id="security-identity-control-plane",
        allowed_tenant_ids=frozenset({"tenant-private-a", "tenant-private-b"}),
    )
    common = {
        "principal_id": "private-principal",
        "allowed_state_kinds": frozenset(TenantStateKind),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(hours=1),
    }
    tenant_a = signer.issue(
        context_id="private-context-a",
        tenant_id="tenant-private-a",
        session_id="private-session-a",
        nonce="private-nonce-a",
        **common,
    )
    tenant_b = signer.issue(
        context_id="private-context-b",
        tenant_id="tenant-private-b",
        session_id="private-session-b",
        nonce="private-nonce-b",
        **common,
    )
    builder = TenantStateKeyBuilder(SECRET, namespace="private-production-namespace")
    attestor = DeploymentAttestationSigner.generate(
        issuer_id="security-attestor",
        allowed_deployment_ids=frozenset({"private-gpu-cluster"}),
    )
    return signer, tenant_a, tenant_b, builder, attestor


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_multi_tenant_bypass_corpus_fails_closed_without_raw_identifiers(case):
    signer, tenant_a, tenant_b, builder, attestor = _fixture()
    mutation = case["mutation"]
    expected = TenantIsolationCode(case["expected_code"])

    if mutation == "mixed_batch":
        guard = TenantIsolationGuard(
            TenantIsolationPolicy.strict(policy_id="security-policy"),
            builder,
            (signer.trusted_key,),
        )
        result = guard.authorize_batch(
            TenantBatchRequest(
                request_id="private-mixed-batch",
                contexts=(tenant_a, tenant_b),
            ),
            now=NOW,
        )
    elif mutation in {"forged_attestation", "weak_attestation", "deployment_swap"}:
        policy = TenantIsolationPolicy.strict(
            policy_id="hardware-security-policy",
            hardware_isolated=frozenset({TenantStateKind.KV_CACHE}),
        )
        level = (
            IsolationLevel.PROCESS if mutation == "weak_attestation" else IsolationLevel.HARDWARE
        )
        attestation = attestor.issue(
            attestation_id="private-attestation",
            deployment_id="private-gpu-cluster",
            isolation_level=level,
            covered_state_kinds=frozenset({TenantStateKind.KV_CACHE}),
            measurement_digest="a" * 64,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
        )
        if mutation == "forged_attestation":
            attestation = attestation.model_copy(update={"measurement_digest": "b" * 64})
        deployment_id = (
            "private-attacker-cluster" if mutation == "deployment_swap" else "private-gpu-cluster"
        )
        guard = TenantIsolationGuard(
            policy,
            builder,
            (signer.trusted_key,),
            trusted_attestation_keys=(attestor.trusted_key,),
        )
        result = guard.authorize_batch(
            TenantBatchRequest(
                request_id="private-attested-batch",
                contexts=(tenant_a,),
                deployment_id=deployment_id,
                attestation=attestation,
            ),
            now=NOW,
        )
    else:
        kind = TenantStateKind(case.get("kind", TenantStateKind.PROMPT_CACHE))
        operation = TenantStateOperation(case.get("operation", TenantStateOperation.WRITE))
        context = tenant_a
        state_key = builder.build(
            tenant_a,
            state_kind=kind,
            artifact_id="private-artifact",
        )
        binding = None
        claims = MemoryTenantKeyClaimStore()
        if mutation == "missing_context":
            context = None
            state_key = None
        elif mutation == "forged_context":
            context = tenant_a.model_copy(update={"signature": "0" * 128})
        elif mutation == "tenant_key":
            state_key = builder.build(
                tenant_b,
                state_kind=kind,
                artifact_id="private-artifact",
            )
        elif mutation == "namespace_key":
            foreign_builder = TenantStateKeyBuilder(
                b"foreign-security-namespace-secret-at-least-32-bytes",
                namespace="private-foreign-namespace",
            )
            state_key = foreign_builder.build(
                tenant_a,
                state_kind=kind,
                artifact_id="private-artifact",
            )
        elif mutation == "key_collision":
            assert claims.claim(state_key.storage_key, "0" * 64)
        elif mutation == "cross_binding":
            other_key = builder.build(
                tenant_b,
                state_kind=kind,
                artifact_id="private-artifact",
            )
            binding = builder.bind(
                other_key,
                created_at=NOW,
                expires_at=NOW + timedelta(minutes=30),
            )
        guard = TenantIsolationGuard(
            TenantIsolationPolicy.strict(policy_id="security-policy"),
            builder,
            (signer.trusted_key,),
            key_claim_store=claims,
        )
        result = guard.authorize_state(
            TenantStateAccessRequest(
                request_id="private-state-request",
                context=context,
                state_kind=kind,
                operation=operation,
                artifact_id="private-artifact",
                state_key=state_key,
                observed_binding=binding,
                requested_expires_at=(
                    NOW + timedelta(minutes=30) if operation == TenantStateOperation.WRITE else None
                ),
            ),
            now=NOW,
        )

    assert not result.is_allowed
    assert expected in {finding.code for finding in result.findings}
    serialized = result.model_dump_json()
    assert "tenant-private" not in serialized
    assert "private-artifact" not in serialized
    assert "private-gpu-cluster" not in serialized
    assert "private-principal" not in serialized

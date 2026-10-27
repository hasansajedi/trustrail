"""Admit a model-serving workload without loading the model in this process."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from trustrail import (
    ModelArtifact,
    ModelLoader,
    ModelSerializationFormat,
    WorkloadAdmissionGuard,
    WorkloadAdmissionPolicy,
    WorkloadAttestation,
    WorkloadIsolationControl,
    WorkloadManifest,
    WorkloadSandboxKind,
    WorkloadTeardownEvidence,
)


class RuntimeControlPlane:
    """Example evidence verifier; production implementations verify signatures."""

    def __init__(self) -> None:
        self.attestations: set[tuple[str, str]] = set()
        self.teardowns: set[tuple[str, str]] = set()

    def verify_attestation(self, attestation: WorkloadAttestation) -> bool:
        return (attestation.attestation_id, attestation.attestation_digest) in self.attestations

    def verify_teardown(self, evidence: WorkloadTeardownEvidence) -> bool:
        return (evidence.evidence_id, evidence.evidence_digest) in self.teardowns


now = datetime.now(UTC)
loader = ModelLoader(
    loader_id="safetensors-loader-v3",
    implementation_digest="a" * 64,
    supported_formats=frozenset({ModelSerializationFormat.SAFETENSORS}),
)
manifest = WorkloadManifest.create(
    workload_id="support-inference",
    tenant_id="tenant-a",
    environment_id="production-eu",
    purpose_id="customer-support",
    artifact=ModelArtifact(
        artifact_id="support-model-v3",
        digest="b" * 64,
        format=ModelSerializationFormat.SAFETENSORS,
        size_bytes=1_000_000,
    ),
    loader_id=loader.loader_id,
    loader_digest=loader.implementation_digest,
    sandbox_kind=WorkloadSandboxKind.MICROVM,
    sandbox_profile_id="model-serving-v3",
)
policy = WorkloadAdmissionPolicy(
    loaders=(loader,),
    allowed_sandbox_profiles=frozenset({"model-serving-v3"}),
    trusted_attestation_providers=frozenset({"production-runtime"}),
)

# A trusted external control plane creates the microVM and returns authenticated
# evidence. This local example fabricates evidence but never opens model bytes.
control_plane = RuntimeControlPlane()
attestation = WorkloadAttestation.create(
    attestation_id="attestation-1",
    provider_id="production-runtime",
    manifest_digest=manifest.manifest_digest,
    workload_id=manifest.workload_id,
    tenant_id=manifest.tenant_id,
    environment_id=manifest.environment_id,
    runtime_instance_id="microvm-42",
    sandbox_kind=manifest.sandbox_kind,
    sandbox_profile_id=manifest.sandbox_profile_id,
    controls=frozenset(WorkloadIsolationControl),
    environment_separated=True,
    dedicated_tenant_runtime=True,
    memory_isolated=True,
    cache_isolated=True,
    issued_at=now - timedelta(seconds=1),
    expires_at=now + timedelta(seconds=30),
)
control_plane.attestations.add((attestation.attestation_id, attestation.attestation_digest))
guard = WorkloadAdmissionGuard(
    policy,
    attestation_verifier=control_plane,
    teardown_verifier=control_plane,
)
authorization = guard.require(manifest, attestation, now=now)

# Dispatch manifest + authorization to the external runtime broker here. After
# termination, authenticate every declared cleanup guarantee before reuse.
teardown = WorkloadTeardownEvidence.create(
    evidence_id="teardown-1",
    authorization_id=authorization.authorization_id,
    manifest_digest=authorization.manifest_digest,
    runtime_instance_id=authorization.runtime_instance_id,
    runtime_destroyed=True,
    credentials_revoked=True,
    network_policy_removed=True,
    mounts_detached=True,
    memory_cleared=True,
    accelerator_memory_cleared=True,
    caches_cleared=True,
    completed_at=now + timedelta(minutes=1),
)
control_plane.teardowns.add((teardown.evidence_id, teardown.evidence_digest))
guard.require_teardown(authorization, teardown)
print("workload admitted and teardown verified")

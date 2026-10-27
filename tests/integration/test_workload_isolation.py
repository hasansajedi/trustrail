"""End-to-end workload admission through an external runtime broker contract."""

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
    WorkloadResourceLimits,
    WorkloadSandboxKind,
    WorkloadTeardownEvidence,
)

NOW = datetime(2026, 10, 27, 12, tzinfo=UTC)


class FakeRuntimeBroker:
    """Control-plane fake; it never opens or deserializes the model artifact."""

    def __init__(self) -> None:
        self.attestations: set[tuple[str, str]] = set()
        self.teardowns: set[tuple[str, str]] = set()
        self.dispatched: list[tuple[str, str]] = []

    def prepare(self, manifest: WorkloadManifest) -> WorkloadAttestation:
        attestation = WorkloadAttestation.create(
            attestation_id="integration-attestation",
            provider_id="production-runtime",
            manifest_digest=manifest.manifest_digest,
            workload_id=manifest.workload_id,
            tenant_id=manifest.tenant_id,
            environment_id=manifest.environment_id,
            runtime_instance_id="microvm-integration",
            sandbox_kind=manifest.sandbox_kind,
            sandbox_profile_id=manifest.sandbox_profile_id,
            controls=frozenset(WorkloadIsolationControl),
            environment_separated=True,
            dedicated_tenant_runtime=True,
            memory_isolated=True,
            cache_isolated=True,
            issued_at=NOW - timedelta(seconds=1),
            expires_at=NOW + timedelta(seconds=30),
        )
        self.attestations.add((attestation.attestation_id, attestation.attestation_digest))
        return attestation

    def verify_attestation(self, attestation: WorkloadAttestation) -> bool:
        return (attestation.attestation_id, attestation.attestation_digest) in self.attestations

    def dispatch(self, manifest: WorkloadManifest, authorization: object) -> None:
        self.dispatched.append((manifest.manifest_digest, authorization.authorization_digest))

    def destroy(self, authorization: object) -> WorkloadTeardownEvidence:
        evidence = WorkloadTeardownEvidence.create(
            evidence_id="integration-teardown",
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
            completed_at=NOW + timedelta(minutes=1),
        )
        self.teardowns.add((evidence.evidence_id, evidence.evidence_digest))
        return evidence

    def verify_teardown(self, evidence: WorkloadTeardownEvidence) -> bool:
        return (evidence.evidence_id, evidence.evidence_digest) in self.teardowns


class DeploymentPolicyHook:
    def __init__(self) -> None:
        self.checked: list[str] = []

    def admit(self, manifest: WorkloadManifest, attestation: WorkloadAttestation) -> bool:
        self.checked.append(manifest.manifest_digest)
        return attestation.runtime_instance_id.startswith("microvm-")


def test_model_workload_is_dispatched_only_after_admission_and_verified_cleanup():
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
        resources=WorkloadResourceLimits(duration_seconds=600),
    )
    policy = WorkloadAdmissionPolicy(
        loaders=(loader,),
        allowed_sandbox_profiles=frozenset({manifest.sandbox_profile_id}),
        max_resources=WorkloadResourceLimits(duration_seconds=1_200),
        trusted_attestation_providers=frozenset({"production-runtime"}),
    )
    broker = FakeRuntimeBroker()
    hook = DeploymentPolicyHook()
    attestation = broker.prepare(manifest)
    guard = WorkloadAdmissionGuard(
        policy,
        attestation_verifier=broker,
        teardown_verifier=broker,
        enforcement_hooks=(hook,),
    )

    authorization = guard.require(manifest, attestation, now=NOW)
    broker.dispatch(manifest, authorization)
    teardown = broker.destroy(authorization)
    verified = guard.require_teardown(authorization, teardown)

    assert hook.checked == [manifest.manifest_digest]
    assert broker.dispatched == [(manifest.manifest_digest, authorization.authorization_digest)]
    assert verified.runtime_destroyed

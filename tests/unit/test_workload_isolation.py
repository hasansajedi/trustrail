"""Unit tests for safe model-loading and workload admission."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from trustrail import (
    ExecutableLoadApproval,
    HostMount,
    ModelArtifact,
    ModelLoader,
    ModelSerializationFormat,
    StaticWorkloadAttestationVerifier,
    WorkloadAdmissionCode,
    WorkloadAdmissionGuard,
    WorkloadAdmissionPolicy,
    WorkloadAttestation,
    WorkloadCredential,
    WorkloadDevice,
    WorkloadDeviceKind,
    WorkloadEgressRule,
    WorkloadIsolationControl,
    WorkloadManifest,
    WorkloadResourceLimits,
    WorkloadSandboxKind,
    WorkloadTeardownEvidence,
)

NOW = datetime(2026, 10, 27, 12, tzinfo=UTC)
LOADER_DIGEST = "a" * 64
ARTIFACT_DIGEST = "b" * 64
MOUNT = HostMount(source_path="/srv/models", target_path="/models")
EGRESS = WorkloadEgressRule(host="telemetry.example.com", port=443)
CREDENTIAL = WorkloadCredential(
    reference="credential:model-registry",
    audience="registry.example.com",
    scopes=frozenset({"models:read"}),
)
DEVICE = WorkloadDevice(
    kind=WorkloadDeviceKind.GPU,
    device_id="gpu-1",
    partition_id="mig-1",
)


class MutableTeardownVerifier:
    def __init__(self) -> None:
        self.accepted: set[tuple[str, str]] = set()

    def verify_teardown(self, evidence: WorkloadTeardownEvidence) -> bool:
        return (evidence.evidence_id, evidence.evidence_digest) in self.accepted


def _loader(
    *formats: ModelSerializationFormat,
) -> ModelLoader:
    return ModelLoader(
        loader_id="loader-v1",
        implementation_digest=LOADER_DIGEST,
        supported_formats=frozenset(formats or (ModelSerializationFormat.SAFETENSORS,)),
    )


def _manifest(**updates: object) -> WorkloadManifest:
    values: dict[str, object] = {
        "workload_id": "inference-1",
        "tenant_id": "tenant-a",
        "environment_id": "production-eu",
        "purpose_id": "customer-support-inference",
        "artifact": ModelArtifact(
            artifact_id="support-model-v3",
            digest=ARTIFACT_DIGEST,
            format=ModelSerializationFormat.SAFETENSORS,
            size_bytes=1_000_000,
        ),
        "loader_id": "loader-v1",
        "loader_digest": LOADER_DIGEST,
        "sandbox_kind": WorkloadSandboxKind.MICROVM,
        "sandbox_profile_id": "model-serving-v3",
        "host_mounts": (MOUNT,),
        "network_egress": (EGRESS,),
        "credentials": (CREDENTIAL,),
        "devices": (DEVICE,),
        "resources": WorkloadResourceLimits(
            cpu_millis=2_000,
            memory_bytes=2 * 1024**3,
            accelerator_memory_bytes=4 * 1024**3,
            disk_bytes=2 * 1024**3,
            process_count=2,
            duration_seconds=600,
        ),
    }
    values.update(updates)
    return WorkloadManifest.create(**values)


def _policy(**updates: object) -> WorkloadAdmissionPolicy:
    values: dict[str, object] = {
        "loaders": (_loader(ModelSerializationFormat.SAFETENSORS),),
        "allowed_sandbox_profiles": frozenset({"model-serving-v3"}),
        "allowed_host_mounts": frozenset({MOUNT}),
        "allowed_network_egress": frozenset({EGRESS}),
        "allowed_credentials": frozenset({CREDENTIAL}),
        "allowed_devices": frozenset({DEVICE}),
        "max_resources": WorkloadResourceLimits(
            cpu_millis=4_000,
            memory_bytes=4 * 1024**3,
            accelerator_memory_bytes=8 * 1024**3,
            disk_bytes=4 * 1024**3,
            process_count=4,
            duration_seconds=1_200,
        ),
        "trusted_attestation_providers": frozenset({"runtime-control-plane"}),
    }
    values.update(updates)
    return WorkloadAdmissionPolicy(**values)


def _attestation(manifest: WorkloadManifest, **updates: object) -> WorkloadAttestation:
    values: dict[str, object] = {
        "attestation_id": "attestation-1",
        "provider_id": "runtime-control-plane",
        "manifest_digest": manifest.manifest_digest,
        "workload_id": manifest.workload_id,
        "tenant_id": manifest.tenant_id,
        "environment_id": manifest.environment_id,
        "runtime_instance_id": "microvm-987",
        "sandbox_kind": manifest.sandbox_kind,
        "sandbox_profile_id": manifest.sandbox_profile_id,
        "controls": frozenset(WorkloadIsolationControl),
        "environment_separated": True,
        "dedicated_tenant_runtime": True,
        "memory_isolated": True,
        "cache_isolated": True,
        "issued_at": NOW - timedelta(seconds=1),
        "expires_at": NOW + timedelta(seconds=30),
    }
    values.update(updates)
    return WorkloadAttestation.create(**values)


def _guard(
    manifest: WorkloadManifest,
    attestation: WorkloadAttestation,
    *,
    policy: WorkloadAdmissionPolicy | None = None,
    hooks: tuple[object, ...] = (),
    teardown_verifier: object | None = None,
) -> WorkloadAdmissionGuard:
    return WorkloadAdmissionGuard(
        policy or _policy(),
        attestation_verifier=StaticWorkloadAttestationVerifier(
            frozenset({(attestation.attestation_id, attestation.attestation_digest)})
        ),
        enforcement_hooks=hooks,  # type: ignore[arg-type]
        teardown_verifier=teardown_verifier,  # type: ignore[arg-type]
    )


def _codes(result: object) -> set[WorkloadAdmissionCode]:
    return {finding.code for finding in result.findings}


def _teardown(authorization: object, **updates: object) -> WorkloadTeardownEvidence:
    values: dict[str, object] = {
        "evidence_id": "teardown-1",
        "authorization_id": authorization.authorization_id,
        "manifest_digest": authorization.manifest_digest,
        "runtime_instance_id": authorization.runtime_instance_id,
        "runtime_destroyed": True,
        "credentials_revoked": True,
        "network_policy_removed": True,
        "mounts_detached": True,
        "memory_cleared": True,
        "accelerator_memory_cleared": True,
        "caches_cleared": True,
        "completed_at": NOW + timedelta(minutes=1),
    }
    values.update(updates)
    return WorkloadTeardownEvidence.create(**values)


def test_admits_exact_safe_manifest_and_verifies_complete_teardown():
    manifest = _manifest()
    attestation = _attestation(manifest)
    verifier = StaticWorkloadAttestationVerifier(
        frozenset({(attestation.attestation_id, attestation.attestation_digest)})
    )
    teardown_verifier = MutableTeardownVerifier()
    guard = WorkloadAdmissionGuard(
        _policy(),
        attestation_verifier=verifier,
        teardown_verifier=teardown_verifier,
    )

    authorization = guard.require(manifest, attestation, now=NOW)
    evidence = _teardown(authorization)
    teardown_verifier.accepted.add((evidence.evidence_id, evidence.evidence_digest))

    assert guard.require_teardown(authorization, evidence) == evidence
    assert authorization.manifest_digest == manifest.manifest_digest


def test_manifest_rejects_tamper_and_non_normalized_mount_paths():
    manifest = _manifest()
    tampered = manifest.model_copy(update={"tenant_id": "tenant-b"})
    attestation = _attestation(manifest)

    result = _guard(manifest, attestation).authorize(tampered, attestation, now=NOW)

    assert WorkloadAdmissionCode.MANIFEST_INTEGRITY_INVALID in _codes(result)
    with pytest.raises(ValidationError, match="absolute normalized"):
        HostMount(source_path="/srv/../secrets", target_path="/models")


def test_executable_serialization_is_denied_without_narrow_approval():
    artifact = ModelArtifact(
        artifact_id="legacy-model",
        digest=ARTIFACT_DIGEST,
        format=ModelSerializationFormat.PYTORCH_PICKLE,
        size_bytes=10_000,
    )
    manifest = _manifest(artifact=artifact)
    attestation = _attestation(manifest)
    policy = _policy(loaders=(_loader(ModelSerializationFormat.PYTORCH_PICKLE),))

    result = _guard(manifest, attestation, policy=policy).authorize(manifest, attestation, now=NOW)

    assert _codes(result) == {WorkloadAdmissionCode.EXECUTABLE_LOAD_APPROVAL_REQUIRED}


def test_code_capable_loader_requires_approval_even_for_safe_format():
    manifest = _manifest()
    attestation = _attestation(manifest)
    loader = _loader(ModelSerializationFormat.SAFETENSORS).model_copy(
        update={"can_execute_arbitrary_code": True}
    )
    policy = _policy(loaders=(loader,))

    result = _guard(manifest, attestation, policy=policy).authorize(manifest, attestation, now=NOW)

    assert WorkloadAdmissionCode.EXECUTABLE_LOAD_APPROVAL_REQUIRED in _codes(result)


def test_artifact_specific_executable_serialization_approval_can_admit():
    artifact = ModelArtifact(
        artifact_id="legacy-model",
        digest=ARTIFACT_DIGEST,
        format=ModelSerializationFormat.PYTORCH_PICKLE,
        size_bytes=10_000,
    )
    manifest = _manifest(artifact=artifact)
    approval = ExecutableLoadApproval(
        approval_ref="risk-acceptance-42",
        tenant_id=manifest.tenant_id,
        artifact_digest=artifact.digest,
        format=artifact.format,
        loader_id=manifest.loader_id,
        loader_digest=manifest.loader_digest,
        sandbox_profile_id=manifest.sandbox_profile_id,
        approved_by="security-reviewer",
        expires_at=NOW + timedelta(hours=1),
    )
    policy = _policy(
        loaders=(_loader(ModelSerializationFormat.PYTORCH_PICKLE),),
        executable_load_approvals=(approval,),
    )
    attestation = _attestation(manifest)

    result = _guard(manifest, attestation, policy=policy).authorize(manifest, attestation, now=NOW)

    assert result.is_authorized


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"loader_digest": "c" * 64}, WorkloadAdmissionCode.LOADER_MISMATCH),
        ({"sandbox_kind": WorkloadSandboxKind.CONTAINER}, WorkloadAdmissionCode.SANDBOX_DENIED),
        (
            {"host_mounts": (HostMount(source_path="/", target_path="/host"),)},
            WorkloadAdmissionCode.HOST_MOUNT_DENIED,
        ),
        (
            {"network_egress": (WorkloadEgressRule(host="attacker.example", port=443),)},
            WorkloadAdmissionCode.NETWORK_EGRESS_DENIED,
        ),
        (
            {
                "credentials": (
                    WorkloadCredential(
                        reference="credential:admin",
                        audience="control-plane",
                        scopes=frozenset({"admin"}),
                    ),
                )
            },
            WorkloadAdmissionCode.CREDENTIAL_DENIED,
        ),
        (
            {
                "resources": WorkloadResourceLimits(
                    memory_bytes=8 * 1024**3,
                )
            },
            WorkloadAdmissionCode.RESOURCE_LIMIT_EXCEEDED,
        ),
    ],
)
def test_manifest_capability_expansion_is_denied(
    updates: dict[str, object], expected: WorkloadAdmissionCode
):
    manifest = _manifest(**updates)
    attestation = _attestation(manifest)

    result = _guard(manifest, attestation).authorize(manifest, attestation, now=NOW)

    assert expected in _codes(result)


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        (
            {"environment_separated": False},
            WorkloadAdmissionCode.ENVIRONMENT_SEPARATION_UNVERIFIED,
        ),
        (
            {"dedicated_tenant_runtime": False},
            WorkloadAdmissionCode.TENANT_BOUNDARY_UNVERIFIED,
        ),
        ({"memory_isolated": False}, WorkloadAdmissionCode.MEMORY_ISOLATION_UNVERIFIED),
        ({"cache_isolated": False}, WorkloadAdmissionCode.CACHE_ISOLATION_UNVERIFIED),
        (
            {"controls": frozenset({WorkloadIsolationControl.ENVIRONMENT_SEPARATION})},
            WorkloadAdmissionCode.ISOLATION_CONTROL_MISSING,
        ),
        ({"tenant_id": "tenant-b"}, WorkloadAdmissionCode.ATTESTATION_MISMATCH),
    ],
)
def test_missing_or_rebound_isolation_evidence_fails_closed(
    updates: dict[str, object], expected: WorkloadAdmissionCode
):
    manifest = _manifest()
    attestation = _attestation(manifest, **updates)

    result = _guard(manifest, attestation).authorize(manifest, attestation, now=NOW)

    assert expected in _codes(result)


def test_attestation_is_single_use():
    manifest = _manifest()
    attestation = _attestation(manifest)
    guard = _guard(manifest, attestation)

    assert guard.authorize(manifest, attestation, now=NOW).is_authorized
    replay = guard.authorize(manifest, attestation, now=NOW)

    assert WorkloadAdmissionCode.ATTESTATION_REPLAYED in _codes(replay)


def test_external_enforcement_hook_denial_and_failure_block():
    class Deny:
        def admit(self, manifest: WorkloadManifest, attestation: WorkloadAttestation) -> bool:
            return False

    class Failure:
        def admit(self, manifest: WorkloadManifest, attestation: WorkloadAttestation) -> bool:
            raise RuntimeError("policy service unavailable")

    manifest = _manifest()
    attestation = _attestation(manifest)

    denied = _guard(manifest, attestation, hooks=(Deny(),)).authorize(
        manifest, attestation, now=NOW
    )
    unavailable = _guard(manifest, attestation, hooks=(Failure(),)).authorize(
        manifest, attestation, now=NOW
    )

    assert WorkloadAdmissionCode.ENFORCEMENT_HOOK_REJECTED in _codes(denied)
    assert WorkloadAdmissionCode.ENFORCEMENT_HOOK_UNAVAILABLE in _codes(unavailable)


def test_incomplete_teardown_is_quarantined_and_consumes_lease():
    manifest = _manifest()
    attestation = _attestation(manifest)
    verifier = MutableTeardownVerifier()
    guard = _guard(manifest, attestation, teardown_verifier=verifier)
    authorization = guard.require(manifest, attestation, now=NOW)
    evidence = _teardown(authorization, accelerator_memory_cleared=False)
    verifier.accepted.add((evidence.evidence_id, evidence.evidence_digest))

    result = guard.verify_teardown(authorization, evidence)
    replay = guard.verify_teardown(authorization, evidence)

    assert result.is_quarantined
    assert WorkloadAdmissionCode.CLEANUP_UNVERIFIED in _codes(result)
    assert WorkloadAdmissionCode.TEARDOWN_EVIDENCE_REPLAYED in _codes(replay)

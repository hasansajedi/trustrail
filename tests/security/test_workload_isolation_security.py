"""Bypass corpus for OWASP AISVS C4 workload isolation and model loading."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    HostMount,
    ModelArtifact,
    ModelLoader,
    ModelSerializationFormat,
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

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "workload_isolation.json"
CASES: list[dict[str, str]] = json.loads(CORPUS_PATH.read_text())
NOW = datetime(2026, 10, 27, 12, tzinfo=UTC)


class EvidenceStore:
    def __init__(self) -> None:
        self.attestations: set[tuple[str, str]] = set()
        self.teardowns: set[tuple[str, str]] = set()

    def verify_attestation(self, attestation: WorkloadAttestation) -> bool:
        return (attestation.attestation_id, attestation.attestation_digest) in self.attestations

    def verify_teardown(self, evidence: WorkloadTeardownEvidence) -> bool:
        return (evidence.evidence_id, evidence.evidence_digest) in self.teardowns


def _loader(*, executable: bool = False) -> ModelLoader:
    return ModelLoader(
        loader_id="safe-loader",
        implementation_digest="a" * 64,
        supported_formats=frozenset(
            {ModelSerializationFormat.SAFETENSORS, ModelSerializationFormat.PICKLE}
        ),
        can_execute_arbitrary_code=executable,
    )


def _manifest(**updates: object) -> WorkloadManifest:
    values: dict[str, object] = {
        "workload_id": "security-workload",
        "tenant_id": "tenant-a",
        "environment_id": "production",
        "purpose_id": "inference",
        "artifact": ModelArtifact(
            artifact_id="safe-model",
            digest="b" * 64,
            format=ModelSerializationFormat.SAFETENSORS,
            size_bytes=10_000,
        ),
        "loader_id": "safe-loader",
        "loader_digest": "a" * 64,
        "sandbox_kind": WorkloadSandboxKind.MICROVM,
        "sandbox_profile_id": "hardened-v1",
    }
    values.update(updates)
    return WorkloadManifest.create(**values)


def _policy(*, executable_loader: bool = False) -> WorkloadAdmissionPolicy:
    return WorkloadAdmissionPolicy(
        loaders=(_loader(executable=executable_loader),),
        allowed_sandbox_profiles=frozenset({"hardened-v1"}),
        trusted_attestation_providers=frozenset({"runtime-provider"}),
    )


def _attestation(manifest: WorkloadManifest, **updates: object) -> WorkloadAttestation:
    values: dict[str, object] = {
        "attestation_id": "security-attestation",
        "provider_id": "runtime-provider",
        "manifest_digest": manifest.manifest_digest,
        "workload_id": manifest.workload_id,
        "tenant_id": manifest.tenant_id,
        "environment_id": manifest.environment_id,
        "runtime_instance_id": "runtime-security",
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


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_workload_isolation_bypass_corpus(case: dict[str, str]):
    mutation = case["mutation"]
    manifest_updates: dict[str, object] = {}
    if mutation == "executable_format":
        manifest_updates["artifact"] = ModelArtifact(
            artifact_id="pickle-model",
            digest="c" * 64,
            format=ModelSerializationFormat.PICKLE,
            size_bytes=10_000,
        )
    elif mutation == "loader":
        manifest_updates["loader_digest"] = "d" * 64
    elif mutation == "sandbox":
        manifest_updates["sandbox_kind"] = WorkloadSandboxKind.CONTAINER
    elif mutation == "mount":
        manifest_updates["host_mounts"] = (
            HostMount(source_path="/", target_path="/host", read_only=False),
        )
    elif mutation == "egress":
        manifest_updates["network_egress"] = (
            WorkloadEgressRule(host="attacker.example", port=443),
        )
    elif mutation == "credential":
        manifest_updates["credentials"] = (
            WorkloadCredential(
                reference="credential:cloud-admin",
                audience="cloud-control-plane",
                scopes=frozenset({"admin"}),
            ),
        )
    elif mutation == "device":
        manifest_updates["devices"] = (
            WorkloadDevice(kind=WorkloadDeviceKind.GPU, device_id="gpu-host-0"),
        )
    elif mutation == "resource":
        manifest_updates["resources"] = WorkloadResourceLimits(memory_bytes=8 * 1024**3)
    manifest = _manifest(**manifest_updates)

    attestation_updates: dict[str, object] = {}
    if mutation == "tenant":
        attestation_updates["tenant_id"] = "tenant-b"
    elif mutation == "environment":
        attestation_updates["environment_separated"] = False
    elif mutation == "runtime":
        attestation_updates["dedicated_tenant_runtime"] = False
    elif mutation == "memory":
        attestation_updates["memory_isolated"] = False
    elif mutation == "cache":
        attestation_updates["cache_isolated"] = False
    elif mutation == "controls":
        attestation_updates["controls"] = frozenset(
            {WorkloadIsolationControl.ENVIRONMENT_SEPARATION}
        )
    attestation = _attestation(manifest, **attestation_updates)
    store = EvidenceStore()
    store.attestations.add((attestation.attestation_id, attestation.attestation_digest))
    guard = WorkloadAdmissionGuard(
        _policy(executable_loader=mutation == "executable_loader"),
        attestation_verifier=store,
        teardown_verifier=store,
    )

    if mutation == "attestation_tamper":
        attestation = attestation.model_copy(update={"runtime_instance_id": "attacker-runtime"})

    if case["phase"] == "admission":
        result = guard.authorize(manifest, attestation, now=NOW)
    else:
        authorization = guard.require(manifest, attestation, now=NOW)
        evidence = WorkloadTeardownEvidence.create(
            evidence_id="security-teardown",
            authorization_id=authorization.authorization_id,
            manifest_digest=authorization.manifest_digest,
            runtime_instance_id=authorization.runtime_instance_id,
            runtime_destroyed=True,
            credentials_revoked=True,
            network_policy_removed=True,
            mounts_detached=True,
            memory_cleared=True,
            accelerator_memory_cleared=False,
            caches_cleared=True,
            completed_at=NOW + timedelta(minutes=1),
        )
        store.teardowns.add((evidence.evidence_id, evidence.evidence_digest))
        result = guard.verify_teardown(authorization, evidence)

    assert case["expected_code"] in {finding.code.value for finding in result.findings}

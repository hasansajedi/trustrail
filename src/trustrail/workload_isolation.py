"""Fail-closed admission for isolated AI workloads and model loaders."""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol

from trustrail.exceptions import WorkloadIsolationError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.workload_isolation import (
    ExecutableLoadApproval,
    ModelLoader,
    WorkloadAdmissionCode,
    WorkloadAdmissionDecision,
    WorkloadAdmissionFinding,
    WorkloadAdmissionPolicy,
    WorkloadAttestation,
    WorkloadAuthorization,
    WorkloadManifest,
    WorkloadResourceLimits,
    WorkloadTeardownEvidence,
    WorkloadTeardownRequirements,
    workload_digest,
)


class WorkloadAttestationVerifier(Protocol):
    """Authenticate infrastructure evidence against a trusted provider."""

    def verify_attestation(self, attestation: WorkloadAttestation) -> bool:
        """Return whether the provider issued this exact attestation."""
        ...


class WorkloadEnforcementHook(Protocol):
    """Application-owned external policy hook run before dispatch."""

    def admit(self, manifest: WorkloadManifest, attestation: WorkloadAttestation) -> bool:
        """Return whether external policy admits this exact workload."""
        ...


class WorkloadTeardownVerifier(Protocol):
    """Authenticate cleanup evidence from the runtime control plane."""

    def verify_teardown(self, evidence: WorkloadTeardownEvidence) -> bool:
        """Return whether the provider issued this exact teardown record."""
        ...


class StaticWorkloadAttestationVerifier:
    """Exact evidence allowlist intended for tests and local examples."""

    def __init__(self, accepted: frozenset[tuple[str, str]]) -> None:
        self._accepted = accepted

    def verify_attestation(self, attestation: WorkloadAttestation) -> bool:
        return (attestation.attestation_id, attestation.attestation_digest) in self._accepted


class StaticWorkloadTeardownVerifier:
    """Exact teardown allowlist intended for tests and local examples."""

    def __init__(self, accepted: frozenset[tuple[str, str]]) -> None:
        self._accepted = accepted

    def verify_teardown(self, evidence: WorkloadTeardownEvidence) -> bool:
        return (evidence.evidence_id, evidence.evidence_digest) in self._accepted


class WorkloadAdmissionGuard:
    """Validate model loaders and issue leases for externally isolated workloads."""

    def __init__(
        self,
        policy: WorkloadAdmissionPolicy,
        *,
        attestation_verifier: WorkloadAttestationVerifier | None = None,
        teardown_verifier: WorkloadTeardownVerifier | None = None,
        enforcement_hooks: tuple[WorkloadEnforcementHook, ...] = (),
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._attestation_verifier = attestation_verifier
        self._teardown_verifier = teardown_verifier
        self._enforcement_hooks = enforcement_hooks
        self._loaders = {loader.loader_id: loader for loader in self._policy.loaders}
        self._used_attestations: set[str] = set()
        self._used_teardown_evidence: set[str] = set()
        self._active: dict[str, tuple[str, WorkloadTeardownRequirements]] = {}
        self._lock = threading.Lock()

    @property
    def policy(self) -> WorkloadAdmissionPolicy:
        """Return a defensive copy of the active policy."""
        return self._policy.model_copy(deep=True)

    def authorize(
        self,
        manifest: WorkloadManifest,
        attestation: WorkloadAttestation | None,
        *,
        now: datetime | None = None,
    ) -> WorkloadAdmissionDecision:
        """Evaluate one complete manifest without loading its model artifact."""
        checked_at = self._current_time(now)
        loader = self._loaders.get(manifest.loader_id)
        findings = self._manifest_findings(manifest, loader, checked_at)
        findings.extend(self._attestation_findings(manifest, attestation, checked_at))
        if not findings and attestation is not None:
            findings.extend(self._hook_findings(manifest, attestation))
        findings = self._deduplicate(findings)
        if findings or attestation is None:
            return self._blocked(findings)

        with self._lock:
            if attestation.attestation_id in self._used_attestations:
                return self._blocked(
                    [
                        self._finding(
                            WorkloadAdmissionCode.ATTESTATION_REPLAYED,
                            Severity.CRITICAL,
                            "Workload attestation has already been consumed",
                        )
                    ]
                )
            self._used_attestations.add(attestation.attestation_id)
            authorization = WorkloadAuthorization.create(
                authorization_id=str(uuid.uuid4()),
                manifest_digest=manifest.manifest_digest,
                workload_id=manifest.workload_id,
                tenant_id=manifest.tenant_id,
                runtime_instance_id=attestation.runtime_instance_id,
                attestation_id=attestation.attestation_id,
                issued_at=checked_at,
                expires_at=min(
                    attestation.expires_at,
                    checked_at + timedelta(seconds=self._policy.authorization_ttl_seconds),
                ),
            )
            self._active[authorization.authorization_id] = (
                authorization.authorization_digest,
                manifest.teardown,
            )
        return WorkloadAdmissionDecision(
            action=GuardAction.ALLOW,
            authorization=authorization,
        )

    def require(
        self,
        manifest: WorkloadManifest,
        attestation: WorkloadAttestation | None,
        *,
        now: datetime | None = None,
    ) -> WorkloadAuthorization:
        """Return an exact dispatch lease or raise before model loading."""
        decision = self.authorize(manifest, attestation, now=now)
        if not decision.is_authorized or decision.authorization is None:
            raise WorkloadIsolationError(decision)
        return decision.authorization

    def verify_teardown(
        self,
        authorization: WorkloadAuthorization,
        evidence: WorkloadTeardownEvidence,
    ) -> WorkloadAdmissionDecision:
        """Authenticate cleanup before releasing or reusing runtime resources."""
        findings: list[WorkloadAdmissionFinding] = []
        if authorization.authorization_digest != workload_digest(
            authorization.model_dump(mode="python", exclude={"authorization_digest"})
        ):
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.AUTHORIZATION_INVALID,
                    Severity.CRITICAL,
                    "Workload authorization integrity check failed",
                )
            )
        if evidence.evidence_digest != workload_digest(
            evidence.model_dump(mode="python", exclude={"evidence_digest"})
        ):
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.TEARDOWN_EVIDENCE_INVALID,
                    Severity.CRITICAL,
                    "Teardown evidence integrity check failed",
                )
            )

        with self._lock:
            active = self._active.get(authorization.authorization_id)
            if evidence.evidence_id in self._used_teardown_evidence:
                findings.append(
                    self._finding(
                        WorkloadAdmissionCode.TEARDOWN_EVIDENCE_REPLAYED,
                        Severity.CRITICAL,
                        "Teardown evidence has already been consumed",
                    )
                )
            if active is None or active[0] != authorization.authorization_digest:
                findings.append(
                    self._finding(
                        WorkloadAdmissionCode.AUTHORIZATION_INVALID,
                        Severity.CRITICAL,
                        "Workload authorization is not active",
                    )
                )
                requirements = WorkloadTeardownRequirements()
            else:
                requirements = active[1]

        if (
            evidence.authorization_id != authorization.authorization_id
            or evidence.manifest_digest != authorization.manifest_digest
            or evidence.runtime_instance_id != authorization.runtime_instance_id
        ):
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.TEARDOWN_EVIDENCE_MISMATCH,
                    Severity.CRITICAL,
                    "Teardown evidence is not bound to the authorized workload",
                )
            )
        if self._teardown_verifier is None:
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.TEARDOWN_EVIDENCE_INVALID,
                    Severity.CRITICAL,
                    "No trusted teardown evidence verifier is configured",
                )
            )
        else:
            try:
                if not self._teardown_verifier.verify_teardown(evidence):
                    findings.append(
                        self._finding(
                            WorkloadAdmissionCode.TEARDOWN_EVIDENCE_INVALID,
                            Severity.CRITICAL,
                            "Teardown evidence was not authenticated",
                        )
                    )
            except Exception:
                findings.append(
                    self._finding(
                        WorkloadAdmissionCode.TEARDOWN_EVIDENCE_INVALID,
                        Severity.CRITICAL,
                        "Teardown evidence verification was unavailable",
                    )
                )
        findings.extend(self._cleanup_findings(requirements, evidence))
        findings = self._deduplicate(findings)

        with self._lock:
            self._used_teardown_evidence.add(evidence.evidence_id)
            self._active.pop(authorization.authorization_id, None)
        if findings:
            return WorkloadAdmissionDecision(
                action=GuardAction.QUARANTINE,
                findings=tuple(findings),
            )
        return WorkloadAdmissionDecision(
            action=GuardAction.ALLOW,
            authorization=authorization,
        )

    def require_teardown(
        self,
        authorization: WorkloadAuthorization,
        evidence: WorkloadTeardownEvidence,
    ) -> WorkloadTeardownEvidence:
        """Return authenticated complete cleanup evidence or raise."""
        decision = self.verify_teardown(authorization, evidence)
        if not decision.is_authorized:
            raise WorkloadIsolationError(decision)
        return evidence

    def _manifest_findings(
        self,
        manifest: WorkloadManifest,
        loader: ModelLoader | None,
        checked_at: datetime,
    ) -> list[WorkloadAdmissionFinding]:
        findings: list[WorkloadAdmissionFinding] = []
        expected_digest = workload_digest(
            manifest.model_dump(mode="python", exclude={"manifest_digest"})
        )
        if manifest.manifest_digest != expected_digest:
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.MANIFEST_INTEGRITY_INVALID,
                    Severity.CRITICAL,
                    "Workload manifest integrity check failed",
                )
            )
        artifact_format = manifest.artifact.format
        if artifact_format.can_execute_code or (
            loader is not None and loader.can_execute_arbitrary_code
        ):
            findings.extend(self._executable_load_findings(manifest, checked_at))
        elif artifact_format not in self._policy.allowed_safe_formats:
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.FORMAT_DENIED,
                    Severity.CRITICAL,
                    "Model serialization format is not allowed",
                )
            )
        if loader is None:
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.LOADER_DENIED,
                    Severity.CRITICAL,
                    "Model loader is not in the approved inventory",
                )
            )
        elif (
            loader.implementation_digest != manifest.loader_digest
            or artifact_format not in loader.supported_formats
        ):
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.LOADER_MISMATCH,
                    Severity.CRITICAL,
                    "Model loader identity or supported format does not match",
                )
            )
        if manifest.sandbox_kind not in self._policy.allowed_sandbox_kinds:
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.SANDBOX_DENIED,
                    Severity.CRITICAL,
                    "Requested sandbox mechanism is not allowed",
                )
            )
        if manifest.sandbox_profile_id not in self._policy.allowed_sandbox_profiles:
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.SANDBOX_PROFILE_DENIED,
                    Severity.CRITICAL,
                    "Requested sandbox profile is not allowed",
                )
            )
        findings.extend(
            self._set_boundary_findings(
                manifest.host_mounts,
                self._policy.allowed_host_mounts,
                WorkloadAdmissionCode.HOST_MOUNT_DENIED,
                "Host mount is not explicitly allowed",
            )
        )
        findings.extend(
            self._set_boundary_findings(
                manifest.network_egress,
                self._policy.allowed_network_egress,
                WorkloadAdmissionCode.NETWORK_EGRESS_DENIED,
                "Network egress is not explicitly allowed",
            )
        )
        findings.extend(
            self._set_boundary_findings(
                manifest.credentials,
                self._policy.allowed_credentials,
                WorkloadAdmissionCode.CREDENTIAL_DENIED,
                "Credential reference is not explicitly allowed",
            )
        )
        findings.extend(
            self._set_boundary_findings(
                manifest.devices,
                self._policy.allowed_devices,
                WorkloadAdmissionCode.DEVICE_DENIED,
                "Device partition is not explicitly allowed",
            )
        )
        if not self._resources_within(manifest.resources, self._policy.max_resources):
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.RESOURCE_LIMIT_EXCEEDED,
                    Severity.HIGH,
                    "Requested resources exceed policy ceilings",
                )
            )
        if not all(manifest.teardown.model_dump().values()):
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.TEARDOWN_DECLARATION_MISSING,
                    Severity.CRITICAL,
                    "Every required teardown guarantee must be declared",
                )
            )
        return findings

    def _executable_load_findings(
        self,
        manifest: WorkloadManifest,
        checked_at: datetime,
    ) -> list[WorkloadAdmissionFinding]:
        candidates = [
            approval
            for approval in self._policy.executable_load_approvals
            if approval.artifact_digest == manifest.artifact.digest
        ]
        if not candidates:
            return [
                self._finding(
                    WorkloadAdmissionCode.EXECUTABLE_LOAD_APPROVAL_REQUIRED,
                    Severity.CRITICAL,
                    "Code-capable model loading requires an artifact-specific approval",
                )
            ]
        if not any(
            self._approval_matches(approval, manifest, checked_at) for approval in candidates
        ):
            return [
                self._finding(
                    WorkloadAdmissionCode.EXECUTABLE_LOAD_APPROVAL_INVALID,
                    Severity.CRITICAL,
                    "Executable-load approval is expired or does not match",
                )
            ]
        return []

    @staticmethod
    def _approval_matches(
        approval: ExecutableLoadApproval,
        manifest: WorkloadManifest,
        checked_at: datetime,
    ) -> bool:
        return (
            approval.tenant_id == manifest.tenant_id
            and approval.format == manifest.artifact.format
            and approval.loader_id == manifest.loader_id
            and approval.loader_digest == manifest.loader_digest
            and approval.sandbox_profile_id == manifest.sandbox_profile_id
            and approval.expires_at > checked_at
        )

    def _attestation_findings(
        self,
        manifest: WorkloadManifest,
        attestation: WorkloadAttestation | None,
        checked_at: datetime,
    ) -> list[WorkloadAdmissionFinding]:
        if attestation is None:
            return [
                self._finding(
                    WorkloadAdmissionCode.ATTESTATION_REQUIRED,
                    Severity.CRITICAL,
                    "Authenticated workload isolation evidence is required",
                )
            ]
        findings: list[WorkloadAdmissionFinding] = []
        expected_digest = workload_digest(
            attestation.model_dump(mode="python", exclude={"attestation_digest"})
        )
        if attestation.attestation_digest != expected_digest:
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.ATTESTATION_INVALID,
                    Severity.CRITICAL,
                    "Workload attestation integrity check failed",
                )
            )
        if attestation.provider_id not in self._policy.trusted_attestation_providers:
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.ATTESTATION_INVALID,
                    Severity.CRITICAL,
                    "Workload attestation provider is not trusted",
                )
            )
        if (
            attestation.issued_at > checked_at
            or attestation.expires_at <= checked_at
            or (attestation.expires_at - attestation.issued_at).total_seconds()
            > self._policy.max_attestation_lifetime_seconds
        ):
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.ATTESTATION_EXPIRED,
                    Severity.CRITICAL,
                    "Workload attestation is not fresh",
                )
            )
        if (
            attestation.manifest_digest != manifest.manifest_digest
            or attestation.workload_id != manifest.workload_id
            or attestation.tenant_id != manifest.tenant_id
            or attestation.environment_id != manifest.environment_id
            or attestation.sandbox_kind != manifest.sandbox_kind
            or attestation.sandbox_profile_id != manifest.sandbox_profile_id
        ):
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.ATTESTATION_MISMATCH,
                    Severity.CRITICAL,
                    "Workload attestation is not bound to the exact manifest",
                )
            )
        if not self._policy.required_controls.issubset(attestation.controls):
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.ISOLATION_CONTROL_MISSING,
                    Severity.CRITICAL,
                    "Workload attestation omits required isolation controls",
                )
            )
        for required, observed, code, message in (
            (
                self._policy.require_environment_separation,
                attestation.environment_separated,
                WorkloadAdmissionCode.ENVIRONMENT_SEPARATION_UNVERIFIED,
                "Environment separation was not attested",
            ),
            (
                self._policy.require_dedicated_tenant_runtime,
                attestation.dedicated_tenant_runtime,
                WorkloadAdmissionCode.TENANT_BOUNDARY_UNVERIFIED,
                "Per-tenant runtime separation was not attested",
            ),
            (
                self._policy.require_memory_isolation,
                attestation.memory_isolated,
                WorkloadAdmissionCode.MEMORY_ISOLATION_UNVERIFIED,
                "Runtime memory isolation was not attested",
            ),
            (
                self._policy.require_cache_isolation,
                attestation.cache_isolated,
                WorkloadAdmissionCode.CACHE_ISOLATION_UNVERIFIED,
                "Runtime cache isolation was not attested",
            ),
        ):
            if required and not observed:
                findings.append(self._finding(code, Severity.CRITICAL, message))
        if self._attestation_verifier is None:
            findings.append(
                self._finding(
                    WorkloadAdmissionCode.ATTESTATION_INVALID,
                    Severity.CRITICAL,
                    "No trusted workload attestation verifier is configured",
                )
            )
        else:
            try:
                if not self._attestation_verifier.verify_attestation(attestation):
                    findings.append(
                        self._finding(
                            WorkloadAdmissionCode.ATTESTATION_INVALID,
                            Severity.CRITICAL,
                            "Workload attestation was not authenticated",
                        )
                    )
            except Exception:
                findings.append(
                    self._finding(
                        WorkloadAdmissionCode.ATTESTATION_INVALID,
                        Severity.CRITICAL,
                        "Workload attestation verification was unavailable",
                    )
                )
        return findings

    def _hook_findings(
        self,
        manifest: WorkloadManifest,
        attestation: WorkloadAttestation,
    ) -> list[WorkloadAdmissionFinding]:
        findings: list[WorkloadAdmissionFinding] = []
        for hook in self._enforcement_hooks:
            try:
                if not hook.admit(manifest, attestation):
                    findings.append(
                        self._finding(
                            WorkloadAdmissionCode.ENFORCEMENT_HOOK_REJECTED,
                            Severity.CRITICAL,
                            "External enforcement hook rejected the workload",
                        )
                    )
            except Exception:
                findings.append(
                    self._finding(
                        WorkloadAdmissionCode.ENFORCEMENT_HOOK_UNAVAILABLE,
                        Severity.CRITICAL,
                        "External enforcement hook was unavailable",
                    )
                )
        return findings

    @staticmethod
    def _cleanup_findings(
        requirements: WorkloadTeardownRequirements,
        evidence: WorkloadTeardownEvidence,
    ) -> list[WorkloadAdmissionFinding]:
        checks = (
            (requirements.destroy_runtime, evidence.runtime_destroyed),
            (requirements.revoke_credentials, evidence.credentials_revoked),
            (requirements.remove_network_policy, evidence.network_policy_removed),
            (requirements.detach_mounts, evidence.mounts_detached),
            (requirements.clear_memory, evidence.memory_cleared),
            (
                requirements.clear_accelerator_memory,
                evidence.accelerator_memory_cleared,
            ),
            (requirements.clear_caches, evidence.caches_cleared),
        )
        if any(required and not observed for required, observed in checks):
            return [
                WorkloadAdmissionFinding(
                    code=WorkloadAdmissionCode.CLEANUP_UNVERIFIED,
                    severity=Severity.CRITICAL,
                    message="Required workload cleanup was not confirmed",
                )
            ]
        return []

    @staticmethod
    def _set_boundary_findings(
        requested: tuple[object, ...],
        allowed: frozenset[object],
        code: WorkloadAdmissionCode,
        message: str,
    ) -> list[WorkloadAdmissionFinding]:
        if not set(requested).issubset(allowed):
            return [
                WorkloadAdmissionFinding(code=code, severity=Severity.CRITICAL, message=message)
            ]
        return []

    @staticmethod
    def _resources_within(
        requested: WorkloadResourceLimits,
        maximum: WorkloadResourceLimits,
    ) -> bool:
        return all(
            requested.model_dump()[field] <= maximum.model_dump()[field]
            for field in WorkloadResourceLimits.model_fields
        )

    @staticmethod
    def _current_time(now: datetime | None) -> datetime:
        value = now or datetime.now(UTC)
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        return value

    @staticmethod
    def _finding(
        code: WorkloadAdmissionCode,
        severity: Severity,
        message: str,
    ) -> WorkloadAdmissionFinding:
        return WorkloadAdmissionFinding(code=code, severity=severity, message=message)

    @staticmethod
    def _deduplicate(
        findings: list[WorkloadAdmissionFinding],
    ) -> list[WorkloadAdmissionFinding]:
        result: list[WorkloadAdmissionFinding] = []
        seen: set[WorkloadAdmissionCode] = set()
        for finding in findings:
            if finding.code not in seen:
                seen.add(finding.code)
                result.append(finding)
        return result

    @staticmethod
    def _blocked(
        findings: list[WorkloadAdmissionFinding],
    ) -> WorkloadAdmissionDecision:
        return WorkloadAdmissionDecision(action=GuardAction.BLOCK, findings=tuple(findings))

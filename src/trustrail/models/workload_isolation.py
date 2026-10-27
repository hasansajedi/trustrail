"""Typed contracts for AI workload isolation and safe model loading."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"


def _canonicalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _canonicalize(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _canonicalize(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        items = [_canonicalize(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    return value


def workload_digest(value: Any) -> str:
    """Return a deterministic SHA-256 digest for a workload control object."""
    canonical = json.dumps(
        _canonicalize(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


def _absolute_path(value: str) -> str:
    if "\x00" in value or "\\" in value:
        raise ValueError("mount paths must be absolute POSIX paths")
    path = PurePosixPath(value)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ValueError("mount paths must be absolute normalized POSIX paths")
    return str(path)


class ModelSerializationFormat(StrEnum):
    """Model artifact formats with materially different loading behavior."""

    SAFETENSORS = "safetensors"
    ONNX = "onnx"
    GGUF = "gguf"
    TFLITE = "tflite"
    PICKLE = "pickle"
    PYTORCH_PICKLE = "pytorch_pickle"
    JOBLIB = "joblib"
    KERAS_H5 = "keras_h5"
    CUSTOM_CODE = "custom_code"

    @property
    def can_execute_code(self) -> bool:
        """Whether loading this format can invoke general-purpose code."""
        return self in {
            self.PICKLE,
            self.PYTORCH_PICKLE,
            self.JOBLIB,
            self.KERAS_H5,
            self.CUSTOM_CODE,
        }


class WorkloadSandboxKind(StrEnum):
    """Externally enforced workload isolation mechanisms."""

    CONTAINER = "container"
    MICROVM = "microvm"
    WASM = "wasm"
    DEDICATED_HOST = "dedicated_host"


class WorkloadDeviceKind(StrEnum):
    """Accelerator or processor classes exposed to a workload."""

    CPU = "cpu"
    GPU = "gpu"
    TPU = "tpu"
    NPU = "npu"


class WorkloadIsolationControl(StrEnum):
    """Properties asserted by an authenticated infrastructure provider."""

    ENVIRONMENT_SEPARATION = "environment_separation"
    TENANT_RUNTIME_BOUNDARY = "tenant_runtime_boundary"
    FILESYSTEM_POLICY = "filesystem_policy"
    NETWORK_POLICY = "network_policy"
    CREDENTIAL_BROKER = "credential_broker"
    DEVICE_BOUNDARY = "device_boundary"
    RESOURCE_LIMITS = "resource_limits"
    EPHEMERAL_RUNTIME = "ephemeral_runtime"
    MEMORY_CLEAR = "memory_clear"
    CACHE_CLEAR = "cache_clear"
    TEARDOWN_REPORTING = "teardown_reporting"


class WorkloadAdmissionCode(StrEnum):
    """Stable reason codes for workload admission and teardown."""

    MANIFEST_INTEGRITY_INVALID = "manifest_integrity_invalid"
    FORMAT_DENIED = "format_denied"
    EXECUTABLE_LOAD_APPROVAL_REQUIRED = "executable_load_approval_required"
    EXECUTABLE_LOAD_APPROVAL_INVALID = "executable_load_approval_invalid"
    LOADER_DENIED = "loader_denied"
    LOADER_MISMATCH = "loader_mismatch"
    SANDBOX_DENIED = "sandbox_denied"
    SANDBOX_PROFILE_DENIED = "sandbox_profile_denied"
    HOST_MOUNT_DENIED = "host_mount_denied"
    NETWORK_EGRESS_DENIED = "network_egress_denied"
    CREDENTIAL_DENIED = "credential_denied"
    DEVICE_DENIED = "device_denied"
    RESOURCE_LIMIT_EXCEEDED = "resource_limit_exceeded"
    TEARDOWN_DECLARATION_MISSING = "teardown_declaration_missing"
    ATTESTATION_REQUIRED = "attestation_required"
    ATTESTATION_INVALID = "attestation_invalid"
    ATTESTATION_EXPIRED = "attestation_expired"
    ATTESTATION_MISMATCH = "attestation_mismatch"
    ISOLATION_CONTROL_MISSING = "isolation_control_missing"
    ENVIRONMENT_SEPARATION_UNVERIFIED = "environment_separation_unverified"
    TENANT_BOUNDARY_UNVERIFIED = "tenant_boundary_unverified"
    MEMORY_ISOLATION_UNVERIFIED = "memory_isolation_unverified"
    CACHE_ISOLATION_UNVERIFIED = "cache_isolation_unverified"
    ATTESTATION_REPLAYED = "attestation_replayed"
    ENFORCEMENT_HOOK_REJECTED = "enforcement_hook_rejected"
    ENFORCEMENT_HOOK_UNAVAILABLE = "enforcement_hook_unavailable"
    AUTHORIZATION_INVALID = "authorization_invalid"
    TEARDOWN_EVIDENCE_INVALID = "teardown_evidence_invalid"
    TEARDOWN_EVIDENCE_MISMATCH = "teardown_evidence_mismatch"
    TEARDOWN_EVIDENCE_REPLAYED = "teardown_evidence_replayed"
    CLEANUP_UNVERIFIED = "cleanup_unverified"


class ModelArtifact(BaseModel):
    """Exact model bytes and their declared serialization format."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    digest: str = Field(pattern=_DIGEST_PATTERN)
    format: ModelSerializationFormat
    size_bytes: int = Field(ge=1, le=10 * 1024**4)


class ModelLoader(BaseModel):
    """Immutable loader implementation approved for specific formats."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    loader_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    implementation_digest: str = Field(pattern=_DIGEST_PATTERN)
    supported_formats: frozenset[ModelSerializationFormat] = Field(min_length=1)
    can_execute_arbitrary_code: bool = False


class HostMount(BaseModel):
    """One exact host mount requested from the external runtime broker."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_path: str
    target_path: str
    read_only: bool = True
    no_exec: bool = True

    @field_validator("source_path", "target_path")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        return _absolute_path(value)


class WorkloadEgressRule(BaseModel):
    """An exact network destination; wildcards and URL syntax are rejected."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65_535)
    protocol: Literal["tcp", "https"] = "https"

    @field_validator("host")
    @classmethod
    def normalize_host(cls, value: str) -> str:
        normalized = value.casefold().rstrip(".")
        if (
            not normalized
            or any(character.isspace() for character in normalized)
            or any(character in normalized for character in "/*@[]")
        ):
            raise ValueError("egress hosts must be exact names or addresses without wildcards")
        return normalized


class WorkloadCredential(BaseModel):
    """Opaque broker reference and narrow purpose exposed to the workload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    reference: str = Field(pattern=_IDENTIFIER_PATTERN)
    audience: str = Field(pattern=_IDENTIFIER_PATTERN)
    scopes: frozenset[str] = Field(min_length=1, max_length=100)

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, values: frozenset[str]) -> frozenset[str]:
        if any(not value or len(value) > 128 for value in values):
            raise ValueError("credential scopes must be non-empty and bounded")
        return values


class WorkloadDevice(BaseModel):
    """Exact device partition requested by a workload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: WorkloadDeviceKind
    device_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    partition_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    exclusive: bool = True


class WorkloadResourceLimits(BaseModel):
    """Hard limits the external scheduler must enforce."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cpu_millis: int = Field(default=1_000, ge=1, le=1_000_000)
    memory_bytes: int = Field(default=1024**3, ge=1, le=1024**5)
    accelerator_memory_bytes: int = Field(default=0, ge=0, le=1024**5)
    disk_bytes: int = Field(default=1024**3, ge=0, le=1024**5)
    process_count: int = Field(default=1, ge=1, le=65_536)
    duration_seconds: int = Field(default=300, ge=1, le=604_800)


class WorkloadTeardownRequirements(BaseModel):
    """Cleanup guarantees requested before admission."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    destroy_runtime: bool = True
    revoke_credentials: bool = True
    remove_network_policy: bool = True
    detach_mounts: bool = True
    clear_memory: bool = True
    clear_accelerator_memory: bool = True
    clear_caches: bool = True


class WorkloadManifest(BaseModel):
    """Complete, integrity-bound request for one model-serving workload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    workload_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    environment_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    artifact: ModelArtifact
    loader_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    loader_digest: str = Field(pattern=_DIGEST_PATTERN)
    sandbox_kind: WorkloadSandboxKind
    sandbox_profile_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    host_mounts: tuple[HostMount, ...] = Field(default_factory=tuple, max_length=100)
    network_egress: tuple[WorkloadEgressRule, ...] = Field(default_factory=tuple, max_length=100)
    credentials: tuple[WorkloadCredential, ...] = Field(default_factory=tuple, max_length=100)
    devices: tuple[WorkloadDevice, ...] = Field(default_factory=tuple, max_length=100)
    resources: WorkloadResourceLimits = Field(default_factory=WorkloadResourceLimits)
    teardown: WorkloadTeardownRequirements = Field(default_factory=WorkloadTeardownRequirements)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_manifest(self) -> WorkloadManifest:
        if self.manifest_digest != workload_digest(
            self.model_dump(mode="python", exclude={"manifest_digest"})
        ):
            raise ValueError("workload manifest integrity check failed")
        for values, label in (
            (self.host_mounts, "host mounts"),
            (self.network_egress, "egress rules"),
            (self.credentials, "credentials"),
            (self.devices, "devices"),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must be unique")
        return self

    @classmethod
    def create(cls, **values: Any) -> WorkloadManifest:
        """Create a manifest with a digest over every enforcement-relevant field."""
        complete = {
            "host_mounts": (),
            "network_egress": (),
            "credentials": (),
            "devices": (),
            "resources": WorkloadResourceLimits(),
            "teardown": WorkloadTeardownRequirements(),
            **values,
        }
        return cls(manifest_digest=workload_digest(complete), **complete)


class ExecutableLoadApproval(BaseModel):
    """Narrow exception for one code-capable artifact and loader combination."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_ref: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    artifact_digest: str = Field(pattern=_DIGEST_PATTERN)
    format: ModelSerializationFormat
    loader_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    loader_digest: str = Field(pattern=_DIGEST_PATTERN)
    sandbox_profile_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    approved_by: str = Field(pattern=_IDENTIFIER_PATTERN)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def require_aware_expiry(cls, value: datetime) -> datetime:
        return _require_aware(value, "expires_at")


class WorkloadAdmissionPolicy(BaseModel):
    """Fail-closed policy for model loading and workload isolation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    loaders: tuple[ModelLoader, ...] = Field(min_length=1, max_length=1_000)
    allowed_safe_formats: frozenset[ModelSerializationFormat] = Field(
        default=frozenset(
            {
                ModelSerializationFormat.SAFETENSORS,
                ModelSerializationFormat.ONNX,
                ModelSerializationFormat.GGUF,
                ModelSerializationFormat.TFLITE,
            }
        )
    )
    executable_load_approvals: tuple[ExecutableLoadApproval, ...] = Field(
        default_factory=tuple, max_length=1_000
    )
    allowed_sandbox_kinds: frozenset[WorkloadSandboxKind] = Field(
        default=frozenset({WorkloadSandboxKind.MICROVM, WorkloadSandboxKind.WASM}),
        min_length=1,
    )
    allowed_sandbox_profiles: frozenset[str] = Field(min_length=1, max_length=1_000)
    allowed_host_mounts: frozenset[HostMount] = Field(default_factory=frozenset)
    allowed_network_egress: frozenset[WorkloadEgressRule] = Field(default_factory=frozenset)
    allowed_credentials: frozenset[WorkloadCredential] = Field(default_factory=frozenset)
    allowed_devices: frozenset[WorkloadDevice] = Field(default_factory=frozenset)
    max_resources: WorkloadResourceLimits = Field(default_factory=WorkloadResourceLimits)
    trusted_attestation_providers: frozenset[str] = Field(min_length=1, max_length=1_000)
    required_controls: frozenset[WorkloadIsolationControl] = Field(
        default=frozenset(WorkloadIsolationControl), min_length=1
    )
    require_environment_separation: bool = True
    require_dedicated_tenant_runtime: bool = True
    require_memory_isolation: bool = True
    require_cache_isolation: bool = True
    max_attestation_lifetime_seconds: int = Field(default=60, ge=1, le=3_600)
    authorization_ttl_seconds: int = Field(default=30, ge=1, le=3_600)

    @field_validator("allowed_safe_formats")
    @classmethod
    def reject_executable_safe_formats(
        cls, values: frozenset[ModelSerializationFormat]
    ) -> frozenset[ModelSerializationFormat]:
        if any(value.can_execute_code for value in values):
            raise ValueError("executable formats cannot be placed on the safe-format allowlist")
        return values

    @model_validator(mode="after")
    def validate_inventory(self) -> WorkloadAdmissionPolicy:
        loader_ids = [loader.loader_id for loader in self.loaders]
        if len(loader_ids) != len(set(loader_ids)):
            raise ValueError("loader IDs must be unique")
        return self


class WorkloadAttestation(BaseModel):
    """Authenticated infrastructure evidence bound to an exact manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    attestation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    workload_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    environment_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    runtime_instance_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    sandbox_kind: WorkloadSandboxKind
    sandbox_profile_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    controls: frozenset[WorkloadIsolationControl] = Field(min_length=1)
    environment_separated: bool
    dedicated_tenant_runtime: bool
    memory_isolated: bool
    cache_isolated: bool
    issued_at: datetime
    expires_at: datetime
    attestation_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_attestation(self) -> WorkloadAttestation:
        if self.expires_at <= self.issued_at:
            raise ValueError("attestation expiry must follow issuance")
        if self.attestation_digest != workload_digest(
            self.model_dump(mode="python", exclude={"attestation_digest"})
        ):
            raise ValueError("workload attestation integrity check failed")
        return self

    @classmethod
    def create(cls, **values: Any) -> WorkloadAttestation:
        """Create integrity-bound evidence for an external verifier to authenticate."""
        return cls(attestation_digest=workload_digest(values), **values)


class WorkloadAuthorization(BaseModel):
    """Short-lived lease for dispatching one exact manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    workload_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    runtime_instance_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    attestation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    issued_at: datetime
    expires_at: datetime
    authorization_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_authorization(self) -> WorkloadAuthorization:
        if self.expires_at <= self.issued_at:
            raise ValueError("authorization expiry must follow issuance")
        if self.authorization_digest != workload_digest(
            self.model_dump(mode="python", exclude={"authorization_digest"})
        ):
            raise ValueError("workload authorization integrity check failed")
        return self

    @classmethod
    def create(cls, **values: Any) -> WorkloadAuthorization:
        return cls(authorization_digest=workload_digest(values), **values)


class WorkloadTeardownEvidence(BaseModel):
    """Terminal cleanup evidence produced by the trusted runtime broker."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    authorization_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    runtime_instance_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    runtime_destroyed: bool
    credentials_revoked: bool
    network_policy_removed: bool
    mounts_detached: bool
    memory_cleared: bool
    accelerator_memory_cleared: bool
    caches_cleared: bool
    completed_at: datetime
    evidence_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("completed_at")
    @classmethod
    def require_aware_completion(cls, value: datetime) -> datetime:
        return _require_aware(value, "completed_at")

    @model_validator(mode="after")
    def validate_evidence(self) -> WorkloadTeardownEvidence:
        if self.evidence_digest != workload_digest(
            self.model_dump(mode="python", exclude={"evidence_digest"})
        ):
            raise ValueError("workload teardown evidence integrity check failed")
        return self

    @classmethod
    def create(cls, **values: Any) -> WorkloadTeardownEvidence:
        return cls(evidence_digest=workload_digest(values), **values)


class WorkloadAdmissionFinding(BaseModel):
    """Content-free reason emitted by workload admission or teardown checks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: WorkloadAdmissionCode
    severity: Severity
    message: str


class WorkloadAdmissionDecision(BaseModel):
    """Fail-closed workload admission or teardown decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK, GuardAction.QUARANTINE]
    findings: tuple[WorkloadAdmissionFinding, ...] = ()
    authorization: WorkloadAuthorization | None = None

    @model_validator(mode="after")
    def validate_decision(self) -> WorkloadAdmissionDecision:
        if self.action == GuardAction.ALLOW and self.authorization is None:
            raise ValueError("allow decisions require a workload authorization")
        if self.action != GuardAction.ALLOW and self.authorization is not None:
            raise ValueError("denied decisions must not carry an authorization")
        return self

    @property
    def is_authorized(self) -> bool:
        return self.action == GuardAction.ALLOW and self.authorization is not None

    @property
    def is_quarantined(self) -> bool:
        return self.action == GuardAction.QUARANTINE

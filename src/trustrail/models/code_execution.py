"""Typed models for admitting and verifying isolated agent code execution."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_ENVIRONMENT_NAME_PATTERN = r"^[A-Z_][A-Z0-9_]{0,127}$"
_PACKAGE_NAME_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,127}$"
_VERSION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$"


def _digest(payload: Any) -> str:
    canonical = json.dumps(
        _canonicalize(payload),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _canonicalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _canonicalize(value.model_dump(mode="json"))
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


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


def _validate_relative_path(value: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise ValueError("filesystem paths must be non-empty POSIX relative paths")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("filesystem paths must remain beneath the sandbox root")
    return str(path)


class ExecutionArtifactKind(StrEnum):
    """Explicit kinds of dynamic artifacts proposed for execution."""

    CODE = "code"
    SCRIPT = "script"
    COMMAND = "command"
    TEMPLATE = "template"
    PACKAGE_INSTALL = "package_install"


class ExecutionLanguage(StrEnum):
    """Runtime language families relevant to admission policy."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    WASM = "wasm"
    TEMPLATE = "template"
    NATIVE = "native"
    SHELL = "shell"


class NetworkProtocol(StrEnum):
    """Network protocols that a sandbox broker may enforce."""

    TCP = "tcp"
    UDP = "udp"
    HTTPS = "https"


class ExecutionOutputFormat(StrEnum):
    """Structural validation applied before output is released downstream."""

    TEXT = "text"
    JSON = "json"
    BINARY = "binary"


class CodeExecutionStatus(StrEnum):
    """Terminal states reported by an authenticated sandbox runner."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    TERMINATED = "terminated"


class SandboxControl(StrEnum):
    """Isolation properties asserted by an authenticated sandbox provider."""

    OS_ISOLATION = "os_isolation"
    FILESYSTEM_POLICY = "filesystem_policy"
    NETWORK_POLICY = "network_policy"
    ENVIRONMENT_ALLOWLIST = "environment_allowlist"
    RESOURCE_LIMITS = "resource_limits"
    NO_NEW_PRIVILEGES = "no_new_privileges"
    SHELL_DISABLED = "shell_disabled"
    PACKAGE_POLICY = "package_policy"
    EPHEMERAL_WORKSPACE = "ephemeral_workspace"
    CLEANUP_ON_EXIT = "cleanup_on_exit"


class CodeExecutionCode(StrEnum):
    """Stable machine-readable code-execution admission and outcome findings."""

    REQUEST_INTEGRITY_INVALID = "request_integrity_invalid"
    ARTIFACT_KIND_DENIED = "artifact_kind_denied"
    RUNTIME_DENIED = "runtime_denied"
    RUNTIME_MISMATCH = "runtime_mismatch"
    UNSAFE_INTERPRETER = "unsafe_interpreter"
    SOURCE_TOO_LARGE = "source_too_large"
    SOURCE_SYNTAX_INVALID = "source_syntax_invalid"
    INSPECTION_UNAVAILABLE = "inspection_unavailable"
    IMPORT_NOT_ALLOWED = "import_not_allowed"
    DANGEROUS_IMPORT = "dangerous_import"
    DANGEROUS_CONSTRUCT = "dangerous_construct"
    SHELL_EXPANSION_DENIED = "shell_expansion_denied"
    FILESYSTEM_ACCESS_DENIED = "filesystem_access_denied"
    NETWORK_ACCESS_DENIED = "network_access_denied"
    ENVIRONMENT_ACCESS_DENIED = "environment_access_denied"
    RESOURCE_LIMIT_EXCEEDED = "resource_limit_exceeded"
    PACKAGE_INSTALL_DENIED = "package_install_denied"
    PACKAGE_UNAPPROVED = "package_unapproved"
    ATTESTATION_REQUIRED = "attestation_required"
    ATTESTATION_INVALID = "attestation_invalid"
    ATTESTATION_EXPIRED = "attestation_expired"
    ATTESTATION_MISMATCH = "attestation_mismatch"
    SANDBOX_CONTROL_MISSING = "sandbox_control_missing"
    ATTESTATION_REPLAYED = "attestation_replayed"
    ADMISSION_HOOK_REJECTED = "admission_hook_rejected"
    ADMISSION_HOOK_UNAVAILABLE = "admission_hook_unavailable"
    AUTHORIZATION_INVALID = "authorization_invalid"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    AUTHORIZATION_REPLAYED = "authorization_replayed"
    REPORT_INVALID = "report_invalid"
    REPORT_UNVERIFIABLE = "report_unverifiable"
    REPORT_MISMATCH = "report_mismatch"
    REPORT_REPLAYED = "report_replayed"
    EXECUTION_TIMED_OUT = "execution_timed_out"
    EXIT_CONDITION_FAILED = "exit_condition_failed"
    RESOURCE_USAGE_EXCEEDED = "resource_usage_exceeded"
    OUTPUT_MISMATCH = "output_mismatch"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"
    OUTPUT_INVALID = "output_invalid"
    OUTPUT_VALIDATOR_REJECTED = "output_validator_rejected"
    OUTPUT_VALIDATOR_UNAVAILABLE = "output_validator_unavailable"
    CLEANUP_UNVERIFIED = "cleanup_unverified"


class ExecutionRuntime(BaseModel):
    """An exact, application-approved interpreter or fixed native entrypoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    runtime_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    language: ExecutionLanguage
    version: str = Field(pattern=_VERSION_PATTERN)
    executable_digest: str = Field(pattern=_DIGEST_PATTERN)
    sandbox_profile_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    allowed_artifact_kinds: frozenset[ExecutionArtifactKind] = Field(min_length=1)


class ExecutionPackage(BaseModel):
    """One exact package approved for installation inside an ephemeral sandbox."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=_PACKAGE_NAME_PATTERN)
    version: str = Field(pattern=_VERSION_PATTERN)
    digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        return value.casefold().replace("_", "-").replace(".", "-")


class FilesystemAccess(BaseModel):
    """Requested paths relative to an isolated sandbox workspace."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    read_paths: tuple[str, ...] = Field(default_factory=tuple, max_length=1_000)
    write_paths: tuple[str, ...] = Field(default_factory=tuple, max_length=1_000)

    @field_validator("read_paths", "write_paths")
    @classmethod
    def validate_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_validate_relative_path(value) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("filesystem access paths must be unique")
        return normalized


class FilesystemPolicy(BaseModel):
    """Allowlisted sandbox-relative filesystem prefixes and hard quotas."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    readable_prefixes: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    writable_prefixes: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    max_read_paths: int = Field(default=0, ge=0, le=10_000)
    max_write_paths: int = Field(default=0, ge=0, le=10_000)

    @field_validator("readable_prefixes", "writable_prefixes")
    @classmethod
    def validate_prefixes(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(_validate_relative_path(value) for value in values)


class NetworkEndpoint(BaseModel):
    """One exact host, port, and protocol requested from the sandbox."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65_535)
    protocol: NetworkProtocol = NetworkProtocol.HTTPS

    @field_validator("host")
    @classmethod
    def normalize_host(cls, value: str) -> str:
        normalized = value.casefold().rstrip(".")
        if (
            not normalized
            or any(character.isspace() for character in normalized)
            or any(character in normalized for character in "/*@[]")
        ):
            raise ValueError("network hosts must be exact names or addresses without wildcards")
        return normalized


class NetworkAccess(BaseModel):
    """Explicit network endpoints requested by generated code."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoints: tuple[NetworkEndpoint, ...] = Field(default_factory=tuple, max_length=1_000)

    @model_validator(mode="after")
    def validate_unique_endpoints(self) -> NetworkAccess:
        keys = {(item.host, item.port, item.protocol) for item in self.endpoints}
        if len(keys) != len(self.endpoints):
            raise ValueError("network endpoints must be unique")
        return self


class NetworkPolicy(BaseModel):
    """Exact network endpoint allowlist; an empty set means deny all."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_endpoints: frozenset[NetworkEndpoint] = Field(default_factory=frozenset)


class EnvironmentPolicy(BaseModel):
    """Names a sandbox may copy from application-controlled environment state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_names: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)

    @field_validator("allowed_names")
    @classmethod
    def validate_names(cls, values: frozenset[str]) -> frozenset[str]:
        for value in values:
            if re.fullmatch(_ENVIRONMENT_NAME_PATTERN, value) is None:
                raise ValueError("environment names must use uppercase portable identifiers")
        return values


class ExecutionResourceLimits(BaseModel):
    """Hard resource ceilings requested from and enforced by a sandbox."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    wall_time_ms: int = Field(default=5_000, ge=1, le=3_600_000)
    cpu_time_ms: int = Field(default=2_000, ge=1, le=3_600_000)
    memory_bytes: int = Field(default=128 * 1024 * 1024, ge=1, le=64 * 1024**3)
    output_bytes: int = Field(default=1_100_000, ge=1, le=1_000_000_000)
    process_count: int = Field(default=1, ge=1, le=1_024)
    thread_count: int = Field(default=4, ge=1, le=4_096)
    file_count: int = Field(default=16, ge=0, le=1_000_000)
    written_bytes: int = Field(default=1_000_000, ge=0, le=1_000_000_000)


class ExecutionResourceUsage(BaseModel):
    """Authoritative peak and cumulative usage observed by the sandbox."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    wall_time_ms: int = Field(ge=0)
    cpu_time_ms: int = Field(ge=0)
    peak_memory_bytes: int = Field(ge=0)
    process_count: int = Field(ge=0)
    thread_count: int = Field(ge=0)
    file_count: int = Field(ge=0)
    written_bytes: int = Field(ge=0)


class ExecutionExitConditions(BaseModel):
    """Success and output requirements declared before execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_exit_codes: frozenset[int] = Field(default=frozenset({0}), min_length=1)
    allow_stderr: bool = False
    output_format: ExecutionOutputFormat = ExecutionOutputFormat.TEXT
    max_stdout_bytes: int = Field(default=1_000_000, ge=0, le=1_000_000_000)
    max_stderr_bytes: int = Field(default=100_000, ge=0, le=1_000_000_000)


class CodeExecutionRequest(BaseModel):
    """Explicit proposal for one isolated dynamic execution operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    actor_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    operation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    artifact_kind: ExecutionArtifactKind
    language: ExecutionLanguage
    runtime_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    source: str | None = Field(default=None, exclude=True, repr=False)
    source_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    argv: tuple[str, ...] = Field(default_factory=tuple, max_length=256)
    packages: tuple[ExecutionPackage, ...] = Field(default_factory=tuple, max_length=256)
    filesystem: FilesystemAccess = Field(default_factory=FilesystemAccess)
    network: NetworkAccess = Field(default_factory=NetworkAccess)
    environment_names: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    resources: ExecutionResourceLimits = Field(default_factory=ExecutionResourceLimits)
    exit_conditions: ExecutionExitConditions = Field(default_factory=ExecutionExitConditions)

    @field_validator("environment_names")
    @classmethod
    def validate_environment_names(cls, values: frozenset[str]) -> frozenset[str]:
        for value in values:
            if re.fullmatch(_ENVIRONMENT_NAME_PATTERN, value) is None:
                raise ValueError("environment names must use uppercase portable identifiers")
        return values

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if len(value) > 10_000 or "\x00" in value or "\n" in value or "\r" in value:
                raise ValueError("argv elements must be bounded single values")
        return values

    @model_validator(mode="after")
    def validate_request_shape(self) -> CodeExecutionRequest:
        source_kinds = {
            ExecutionArtifactKind.CODE,
            ExecutionArtifactKind.SCRIPT,
            ExecutionArtifactKind.TEMPLATE,
        }
        if self.artifact_kind in source_kinds:
            if not self.source or self.source_digest is None:
                raise ValueError("source artifacts require source content and digest")
            if self.source_digest != hashlib.sha256(self.source.encode()).hexdigest():
                raise ValueError("source digest does not match source content")
        elif self.source is not None or self.source_digest is not None:
            raise ValueError("command and package requests must not carry source text")
        if self.artifact_kind == ExecutionArtifactKind.COMMAND and not self.argv:
            raise ValueError("command execution requires an explicit argv array")
        if self.artifact_kind == ExecutionArtifactKind.PACKAGE_INSTALL and not self.packages:
            raise ValueError("package installation requires exact package records")
        package_names = [package.name for package in self.packages]
        if len(package_names) != len(set(package_names)):
            raise ValueError("package names must be unique")
        if (
            self.exit_conditions.max_stdout_bytes + self.exit_conditions.max_stderr_bytes
            > self.resources.output_bytes
        ):
            raise ValueError("exit-condition output limits exceed the requested output budget")
        return self

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        actor_id: str,
        tenant_id: str,
        purpose_id: str,
        operation_id: str,
        artifact_kind: ExecutionArtifactKind,
        language: ExecutionLanguage,
        runtime_id: str,
        source: str | None = None,
        argv: tuple[str, ...] = (),
        packages: tuple[ExecutionPackage, ...] = (),
        filesystem: FilesystemAccess | None = None,
        network: NetworkAccess | None = None,
        environment_names: frozenset[str] = frozenset(),
        resources: ExecutionResourceLimits | None = None,
        exit_conditions: ExecutionExitConditions | None = None,
    ) -> CodeExecutionRequest:
        """Create a request while binding source content to a SHA-256 digest."""
        return cls(
            request_id=request_id,
            actor_id=actor_id,
            tenant_id=tenant_id,
            purpose_id=purpose_id,
            operation_id=operation_id,
            artifact_kind=artifact_kind,
            language=language,
            runtime_id=runtime_id,
            source=source,
            source_digest=hashlib.sha256(source.encode()).hexdigest() if source else None,
            argv=argv,
            packages=packages,
            filesystem=filesystem or FilesystemAccess(),
            network=network or NetworkAccess(),
            environment_names=environment_names,
            resources=resources or ExecutionResourceLimits(),
            exit_conditions=exit_conditions or ExecutionExitConditions(),
        )

    @property
    def request_digest(self) -> str:
        """Return a canonical digest of every execution-relevant request field."""
        return _digest(self.model_dump(mode="json", exclude={"source"}))


class CodeExecutionPolicy(BaseModel):
    """Fail-closed policy for admitting agent-selected dynamic execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    runtimes: tuple[ExecutionRuntime, ...] = Field(min_length=1, max_length=1_000)
    allowed_artifact_kinds: frozenset[ExecutionArtifactKind] = Field(min_length=1)
    filesystem: FilesystemPolicy = Field(default_factory=FilesystemPolicy)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    environment: EnvironmentPolicy = Field(default_factory=EnvironmentPolicy)
    max_resources: ExecutionResourceLimits = Field(default_factory=ExecutionResourceLimits)
    max_source_bytes: int = Field(default=100_000, ge=1, le=10_000_000)
    allow_package_installation: bool = False
    approved_packages: tuple[ExecutionPackage, ...] = Field(
        default_factory=tuple, max_length=10_000
    )
    allowed_python_imports: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    trusted_sandbox_providers: frozenset[str] = Field(min_length=1, max_length=1_000)
    required_sandbox_controls: frozenset[SandboxControl] = Field(
        default=frozenset(SandboxControl),
        min_length=1,
    )
    max_attestation_lifetime_seconds: int = Field(default=60, ge=1, le=3_600)
    authorization_ttl_seconds: int = Field(default=30, ge=1, le=3_600)

    @field_validator("allowed_python_imports")
    @classmethod
    def normalize_imports(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(value.casefold().split(".", 1)[0] for value in values)

    @model_validator(mode="after")
    def validate_inventory(self) -> CodeExecutionPolicy:
        runtime_ids = [runtime.runtime_id for runtime in self.runtimes]
        if len(runtime_ids) != len(set(runtime_ids)):
            raise ValueError("runtime IDs must be unique")
        package_names = [package.name for package in self.approved_packages]
        if len(package_names) != len(set(package_names)):
            raise ValueError("approved package names must be unique")
        return self


class SandboxAttestation(BaseModel):
    """Integrity-bound isolation evidence for one exact execution request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    attestation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    sandbox_instance_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    sandbox_profile_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    runtime_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    runtime_digest: str = Field(pattern=_DIGEST_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    controls: frozenset[SandboxControl] = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
    attestation_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_attestation(self) -> SandboxAttestation:
        if self.expires_at <= self.issued_at:
            raise ValueError("attestation expiry must follow issuance")
        if not self.has_valid_integrity:
            raise ValueError("sandbox attestation integrity check failed")
        return self

    @classmethod
    def create(
        cls,
        *,
        attestation_id: str,
        provider_id: str,
        sandbox_instance_id: str,
        sandbox_profile_id: str,
        request_digest: str,
        runtime_id: str,
        runtime_digest: str,
        tenant_id: str,
        controls: frozenset[SandboxControl],
        issued_at: datetime,
        expires_at: datetime,
    ) -> SandboxAttestation:
        """Create an attestation with a canonical integrity digest."""
        values = {
            "attestation_id": attestation_id,
            "provider_id": provider_id,
            "sandbox_instance_id": sandbox_instance_id,
            "sandbox_profile_id": sandbox_profile_id,
            "request_digest": request_digest,
            "runtime_id": runtime_id,
            "runtime_digest": runtime_digest,
            "tenant_id": tenant_id,
            "controls": controls,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        payload = cls._digest_payload(**values)
        return cls(
            attestation_id=attestation_id,
            provider_id=provider_id,
            sandbox_instance_id=sandbox_instance_id,
            sandbox_profile_id=sandbox_profile_id,
            request_digest=request_digest,
            runtime_id=runtime_id,
            runtime_digest=runtime_digest,
            tenant_id=tenant_id,
            controls=controls,
            issued_at=issued_at,
            expires_at=expires_at,
            attestation_digest=_digest(payload),
        )

    @property
    def has_valid_integrity(self) -> bool:
        values = self.model_dump(exclude={"attestation_digest"})
        return self.attestation_digest == _digest(self._digest_payload(**values))

    @staticmethod
    def _digest_payload(**values: Any) -> dict[str, Any]:
        controls = values["controls"]
        issued_at = values["issued_at"]
        expires_at = values["expires_at"]
        return {
            **{
                key: value
                for key, value in values.items()
                if key not in {"controls", "issued_at", "expires_at"}
            },
            "controls": sorted(
                control.value if isinstance(control, SandboxControl) else control
                for control in controls
            ),
            "issued_at": issued_at.isoformat() if isinstance(issued_at, datetime) else issued_at,
            "expires_at": expires_at.isoformat()
            if isinstance(expires_at, datetime)
            else expires_at,
        }


class CodeExecutionFinding(BaseModel):
    """Content-free explanation for an execution admission or outcome decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: CodeExecutionCode
    severity: Severity
    message: str


class AuthorizedCodeExecution(BaseModel):
    """Short-lived single-use lease for one exact sandbox execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    source_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    actor_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    operation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    artifact_kind: ExecutionArtifactKind
    runtime_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    runtime_digest: str = Field(pattern=_DIGEST_PATTERN)
    sandbox_attestation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    sandbox_instance_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    resources: ExecutionResourceLimits
    exit_conditions: ExecutionExitConditions
    issued_at: datetime
    expires_at: datetime
    authorization_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_authorization(self) -> AuthorizedCodeExecution:
        if self.expires_at <= self.issued_at:
            raise ValueError("authorization expiry must follow issuance")
        if not self.has_valid_integrity:
            raise ValueError("code execution authorization integrity check failed")
        return self

    @classmethod
    def create(cls, **values: Any) -> AuthorizedCodeExecution:
        payload = cls._digest_payload(**values)
        return cls(authorization_digest=_digest(payload), **values)

    @property
    def has_valid_integrity(self) -> bool:
        values = self.model_dump(exclude={"authorization_digest"})
        return self.authorization_digest == _digest(self._digest_payload(**values))

    @staticmethod
    def _digest_payload(**values: Any) -> dict[str, Any]:
        serialized: dict[str, Any] = {}
        for key, value in values.items():
            if isinstance(value, datetime):
                serialized[key] = value.isoformat()
            elif isinstance(value, BaseModel):
                serialized[key] = value.model_dump(mode="json")
            elif isinstance(value, StrEnum):
                serialized[key] = value.value
            else:
                serialized[key] = value
        return serialized


class CodeExecutionDecision(BaseModel):
    """Fail-closed admission decision for one proposed execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    findings: tuple[CodeExecutionFinding, ...] = ()
    authorization: AuthorizedCodeExecution | None = None

    @model_validator(mode="after")
    def validate_decision(self) -> CodeExecutionDecision:
        if self.action == GuardAction.ALLOW and self.authorization is None:
            raise ValueError("allow decisions require an execution authorization")
        if self.action == GuardAction.BLOCK and self.authorization is not None:
            raise ValueError("blocked decisions must not carry an authorization")
        return self

    @property
    def is_authorized(self) -> bool:
        return self.action == GuardAction.ALLOW and self.authorization is not None

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK


class ExecutionCleanupEvidence(BaseModel):
    """Sandbox-observed cleanup and privilege revocation evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sandbox_destroyed: bool
    processes_terminated: bool
    filesystem_discarded: bool
    network_revoked: bool
    credentials_revoked: bool

    @property
    def is_complete(self) -> bool:
        return all(
            (
                self.sandbox_destroyed,
                self.processes_terminated,
                self.filesystem_discarded,
                self.network_revoked,
                self.credentials_revoked,
            )
        )


class ExecutionOutput(BaseModel):
    """Raw sandbox output kept out of normal serialization and representations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stdout: bytes = Field(default=b"", exclude=True, repr=False)
    stderr: bytes = Field(default=b"", exclude=True, repr=False)

    @property
    def stdout_digest(self) -> str:
        return hashlib.sha256(self.stdout).hexdigest()

    @property
    def stderr_digest(self) -> str:
        return hashlib.sha256(self.stderr).hexdigest()


class CodeExecutionReport(BaseModel):
    """Integrity-bound terminal report from an authenticated sandbox runner."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    report_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    authorization_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    sandbox_attestation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    sandbox_instance_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    runtime_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    status: CodeExecutionStatus
    exit_code: int | None = None
    started_at: datetime
    completed_at: datetime
    usage: ExecutionResourceUsage
    stdout_size: int = Field(ge=0)
    stdout_digest: str = Field(pattern=_DIGEST_PATTERN)
    stderr_size: int = Field(ge=0)
    stderr_digest: str = Field(pattern=_DIGEST_PATTERN)
    cleanup: ExecutionCleanupEvidence
    report_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("started_at", "completed_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_report(self) -> CodeExecutionReport:
        if self.completed_at < self.started_at:
            raise ValueError("completion cannot precede execution start")
        if (
            self.status in {CodeExecutionStatus.SUCCEEDED, CodeExecutionStatus.FAILED}
            and self.exit_code is None
        ):
            raise ValueError("completed execution reports require an exit code")
        if not self.has_valid_integrity:
            raise ValueError("code execution report integrity check failed")
        return self

    @classmethod
    def create(
        cls,
        *,
        output: ExecutionOutput,
        report_id: str,
        authorization_id: str,
        request_digest: str,
        sandbox_attestation_id: str,
        sandbox_instance_id: str,
        runtime_id: str,
        status: CodeExecutionStatus,
        exit_code: int | None,
        started_at: datetime,
        completed_at: datetime,
        usage: ExecutionResourceUsage,
        cleanup: ExecutionCleanupEvidence,
    ) -> CodeExecutionReport:
        values = {
            "report_id": report_id,
            "authorization_id": authorization_id,
            "request_digest": request_digest,
            "sandbox_attestation_id": sandbox_attestation_id,
            "sandbox_instance_id": sandbox_instance_id,
            "runtime_id": runtime_id,
            "status": status,
            "exit_code": exit_code,
            "started_at": started_at,
            "completed_at": completed_at,
            "usage": usage,
            "cleanup": cleanup,
        }
        complete = {
            **values,
            "stdout_size": len(output.stdout),
            "stdout_digest": output.stdout_digest,
            "stderr_size": len(output.stderr),
            "stderr_digest": output.stderr_digest,
        }
        return cls(
            report_id=report_id,
            authorization_id=authorization_id,
            request_digest=request_digest,
            sandbox_attestation_id=sandbox_attestation_id,
            sandbox_instance_id=sandbox_instance_id,
            runtime_id=runtime_id,
            status=status,
            exit_code=exit_code,
            started_at=started_at,
            completed_at=completed_at,
            usage=usage,
            stdout_size=len(output.stdout),
            stdout_digest=output.stdout_digest,
            stderr_size=len(output.stderr),
            stderr_digest=output.stderr_digest,
            cleanup=cleanup,
            report_digest=_digest(cls._digest_payload(**complete)),
        )

    @property
    def has_valid_integrity(self) -> bool:
        values = self.model_dump(exclude={"report_digest"})
        return self.report_digest == _digest(self._digest_payload(**values))

    @staticmethod
    def _digest_payload(**values: Any) -> dict[str, Any]:
        serialized: dict[str, Any] = {}
        for key, value in values.items():
            if isinstance(value, datetime):
                serialized[key] = value.isoformat()
            elif isinstance(value, BaseModel):
                serialized[key] = value.model_dump(mode="json")
            elif isinstance(value, StrEnum):
                serialized[key] = value.value
            else:
                serialized[key] = value
        return serialized


class VerifiedExecutionOutput(BaseModel):
    """Output released only after report, resource, exit, and cleanup verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str
    report_id: str
    stdout: bytes = Field(exclude=True, repr=False)
    stderr: bytes = Field(exclude=True, repr=False)
    stdout_digest: str = Field(pattern=_DIGEST_PATTERN)
    stderr_digest: str = Field(pattern=_DIGEST_PATTERN)
    completed_at: datetime

    @field_validator("completed_at")
    @classmethod
    def require_aware_completion(cls, value: datetime) -> datetime:
        return _require_aware(value, "completed_at")


class CodeExecutionOutcome(BaseModel):
    """Verified output or a quarantined terminal execution decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.QUARANTINE]
    findings: tuple[CodeExecutionFinding, ...] = ()
    output: VerifiedExecutionOutput | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> CodeExecutionOutcome:
        if self.action == GuardAction.ALLOW and self.output is None:
            raise ValueError("allow outcomes require verified execution output")
        if self.action == GuardAction.QUARANTINE and self.output is not None:
            raise ValueError("quarantined outcomes must not release execution output")
        return self

    @property
    def is_verified(self) -> bool:
        return self.action == GuardAction.ALLOW and self.output is not None

    @property
    def is_quarantined(self) -> bool:
        return self.action == GuardAction.QUARANTINE

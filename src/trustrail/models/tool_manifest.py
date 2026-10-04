"""Typed contracts for signed runtime tool capability manifests."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_KEY_ID_PATTERN = r"^sha256:[0-9a-f]{64}$"
_SIGNATURE_PATTERN = r"^[0-9a-f]{128}$"
_SCHEMA_TYPES = frozenset({"array", "boolean", "integer", "null", "number", "object", "string"})
_SUPPORTED_SCHEMA_KEYS = frozenset(
    {
        "additionalProperties",
        "const",
        "description",
        "enum",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "pattern",
        "properties",
        "required",
        "type",
    }
)


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


def _canonicalize(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, BaseModel):
        return _canonicalize({name: getattr(value, name) for name in value.__class__.model_fields})
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = unicodedata.normalize("NFC", str(key))
            if normalized_key in normalized:
                raise ValueError("object keys must remain unique after Unicode normalization")
            normalized[normalized_key] = _canonicalize(item)
        return normalized
    if isinstance(value, (set, frozenset)):
        items = [_canonicalize(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    return value


def canonical_tool_manifest_json(value: Any) -> str:
    """Serialize manifest data with a deterministic signing profile."""
    return json.dumps(
        _canonicalize(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def tool_manifest_digest(value: Any) -> str:
    """Return a stable SHA-256 digest for capability-manifest data."""
    return hashlib.sha256(canonical_tool_manifest_json(value).encode()).hexdigest()


def tool_manifest_reference(value: str) -> str:
    """Return a one-way identifier suitable for content-free findings."""
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def _validate_schema(schema: dict[str, JsonValue], *, path: str = "$") -> None:
    unsupported = set(schema) - _SUPPORTED_SCHEMA_KEYS
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise ValueError(f"unsupported schema keywords at {path}: {names}")
    schema_type = schema.get("type")
    if not isinstance(schema_type, str) or schema_type not in _SCHEMA_TYPES:
        raise ValueError(f"schema at {path} requires one supported string type")
    properties = schema.get("properties", {})
    if schema_type == "object":
        if not isinstance(properties, dict):
            raise ValueError(f"object schema properties at {path} must be an object")
        if schema.get("additionalProperties") is not False:
            raise ValueError(f"object schema at {path} must set additionalProperties to false")
        for name, child in properties.items():
            if not isinstance(name, str) or not isinstance(child, dict):
                raise ValueError(f"schema property at {path} must contain a schema object")
            _validate_schema(child, path=f"{path}.{name}")
        required = schema.get("required", [])
        if (
            not isinstance(required, list)
            or any(not isinstance(item, str) for item in required)
            or not set(required).issubset(properties)
            or len(required) != len(set(required))
        ):
            raise ValueError(f"required fields at {path} must uniquely name declared properties")
    elif "properties" in schema or "required" in schema or "additionalProperties" in schema:
        raise ValueError(f"object-only schema keywords used at {path}")
    if schema_type == "array":
        items = schema.get("items")
        if not isinstance(items, dict):
            raise ValueError(f"array schema at {path} requires one items schema")
        _validate_schema(items, path=f"{path}[]")
    elif "items" in schema:
        raise ValueError(f"items is only supported for arrays at {path}")
    for key in ("minLength", "maxLength", "minItems", "maxItems"):
        value = schema.get(key)
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or value < 0
        ):
            raise ValueError(f"{key} at {path} must be a non-negative integer")
    for key in ("minimum", "maximum"):
        value = schema.get(key)
        if value is not None and (not isinstance(value, (int, float)) or isinstance(value, bool)):
            raise ValueError(f"{key} at {path} must be numeric")
    pattern = schema.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str):
            raise ValueError(f"pattern at {path} must be a string")
        try:
            re.compile(pattern)
        except re.error as error:
            raise ValueError(f"pattern at {path} is invalid") from error
    enum = schema.get("enum")
    if enum is not None and (not isinstance(enum, list) or not enum):
        raise ValueError(f"enum at {path} must be a non-empty array")


class ToolExecutorKind(StrEnum):
    """Kinds of executor identity that can be measured out of band."""

    EXECUTABLE = "executable"
    SERVICE = "service"


class ToolCapabilityEffect(StrEnum):
    """Externally observable effects a tool may perform."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    TRANSACT = "transact"
    COMMUNICATE = "communicate"
    EXECUTE = "execute"


class ToolDataClassification(StrEnum):
    """Ordered data classes used at tool input and output boundaries."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ToolEnforcementControl(StrEnum):
    """Controls an attested mediation layer can prove are active."""

    EXECUTOR_IDENTITY = "executor_identity"
    FILESYSTEM_POLICY = "filesystem_policy"
    EGRESS_POLICY = "egress_policy"
    CREDENTIAL_BROKER = "credential_broker"
    RESOURCE_LIMITS = "resource_limits"
    DATA_BOUNDARY = "data_boundary"


class ToolManifestBindingPhase(StrEnum):
    """Control-plane step represented by a signed manifest binding."""

    DISCOVERY = "discovery"
    APPROVAL = "approval"


class ToolManifestCode(StrEnum):
    """Stable machine-readable runtime capability outcomes."""

    MANIFEST_UNSIGNED = "manifest_unsigned"
    MANIFEST_KEY_UNKNOWN = "manifest_key_unknown"
    MANIFEST_KEY_INACTIVE = "manifest_key_inactive"
    MANIFEST_SIGNATURE_INVALID = "manifest_signature_invalid"
    MANIFEST_NOT_YET_VALID = "manifest_not_yet_valid"
    MANIFEST_EXPIRED = "manifest_expired"
    EXECUTOR_MISMATCH = "executor_mismatch"
    DISCOVERY_INVALID = "discovery_invalid"
    APPROVAL_INVALID = "approval_invalid"
    MANIFEST_SUBSTITUTION = "manifest_substitution"
    REQUEST_INTEGRITY_INVALID = "request_integrity_invalid"
    CAPABILITY_UNDECLARED = "capability_undeclared"
    FILESYSTEM_WIDENED = "filesystem_widened"
    EGRESS_WIDENED = "egress_widened"
    CREDENTIAL_WIDENED = "credential_widened"
    RESOURCE_LIMIT_WIDENED = "resource_limit_widened"
    DATA_CLASSIFICATION_DENIED = "data_classification_denied"
    INPUT_CONTRACT_INVALID = "input_contract_invalid"
    EVIDENCE_REQUIRED = "evidence_required"
    EVIDENCE_KEY_UNKNOWN = "evidence_key_unknown"
    EVIDENCE_KEY_INACTIVE = "evidence_key_inactive"
    EVIDENCE_SIGNATURE_INVALID = "evidence_signature_invalid"
    EVIDENCE_STALE = "evidence_stale"
    EVIDENCE_MISMATCH = "evidence_mismatch"
    ENFORCEMENT_CONTROL_MISSING = "enforcement_control_missing"
    AUTHORIZATION_INVALID = "authorization_invalid"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    AUTHORIZATION_REPLAYED = "authorization_replayed"
    OUTPUT_CONTRACT_INVALID = "output_contract_invalid"
    OUTPUT_CLASSIFICATION_DENIED = "output_classification_denied"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"


class ToolExecutorIdentity(BaseModel):
    """Measured executable digest or authenticated service identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ToolExecutorKind
    executor_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    identity_digest: str = Field(pattern=_DIGEST_PATTERN)

    @property
    def digest(self) -> str:
        return tool_manifest_digest(self)


def _normalize_root(value: str) -> str:
    if "\x00" in value or "\\" in value:
        raise ValueError("filesystem roots must be absolute POSIX paths")
    path = PurePosixPath(value)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ValueError("filesystem roots must be absolute normalized POSIX paths")
    return str(path)


class ToolFilesystemCapability(BaseModel):
    """Allowlisted filesystem roots enforced for one tool."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    read_roots: tuple[str, ...] = Field(default_factory=tuple, max_length=1_000)
    write_roots: tuple[str, ...] = Field(default_factory=tuple, max_length=1_000)

    @field_validator("read_roots", "write_roots")
    @classmethod
    def validate_roots(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_normalize_root(value) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("filesystem roots must be unique")
        return normalized


class ToolEgressDestination(BaseModel):
    """One exact outbound network destination."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: Literal["https", "tcp", "udp"] = "https"
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65_535)

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


class ToolResourceLimits(BaseModel):
    """Hard limits applied by the runtime mediation layer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cpu_millis: int = Field(ge=1, le=86_400_000)
    memory_bytes: int = Field(ge=1, le=1_099_511_627_776)
    duration_ms: int = Field(ge=1, le=86_400_000)
    output_bytes: int = Field(ge=1, le=1_073_741_824)
    network_bytes: int = Field(ge=1, le=1_099_511_627_776)


class ToolCapabilityManifest(BaseModel):
    """Canonical Ed25519-signed declaration for one exact tool implementation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    manifest_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tool_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    version: str = Field(pattern=_IDENTIFIER_PATTERN)
    executor: ToolExecutorIdentity
    effects: frozenset[ToolCapabilityEffect] = Field(max_length=64)
    scopes: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    filesystem: ToolFilesystemCapability
    egress: frozenset[ToolEgressDestination] = Field(default_factory=frozenset, max_length=1_000)
    credential_references: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    resources: ToolResourceLimits
    input_schema: dict[str, JsonValue]
    output_schema: dict[str, JsonValue]
    input_classifications: frozenset[ToolDataClassification] = Field(min_length=1)
    max_output_classification: ToolDataClassification
    authority_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    key_id: str = Field(pattern=_KEY_ID_PATTERN)
    issued_at: datetime
    expires_at: datetime
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @field_validator("scopes", "credential_references")
    @classmethod
    def validate_identifiers(cls, values: frozenset[str], info: Any) -> frozenset[str]:
        if any(re.fullmatch(_IDENTIFIER_PATTERN, value) is None for value in values):
            raise ValueError(f"{info.field_name} contains an invalid identifier")
        return values

    @model_validator(mode="after")
    def validate_contract(self) -> ToolCapabilityManifest:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        _validate_schema(self.input_schema)
        _validate_schema(self.output_schema)
        canonical_tool_manifest_json(self.signing_payload)
        return self

    @property
    def signing_payload(self) -> dict[str, Any]:
        return {
            name: getattr(self, name) for name in self.__class__.model_fields if name != "signature"
        }

    @property
    def signing_bytes(self) -> bytes:
        return canonical_tool_manifest_json(self.signing_payload).encode()

    @property
    def manifest_digest(self) -> str:
        return tool_manifest_digest({"payload": self.signing_payload, "signature": self.signature})


class ToolManifestTrustedKey(BaseModel):
    """Out-of-band trusted Ed25519 key for manifest or evidence authorities."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authority_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    public_key: bytes = Field(min_length=32, max_length=32, exclude=True, repr=False)
    active_from: datetime | None = None
    expires_at: datetime | None = None
    revoked: bool = False

    @field_validator("active_from", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime | None, info: Any) -> datetime | None:
        return None if value is None else _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> ToolManifestTrustedKey:
        if self.active_from and self.expires_at and self.expires_at <= self.active_from:
            raise ValueError("trusted key expires_at must be after active_from")
        return self

    @property
    def key_id(self) -> str:
        return f"sha256:{hashlib.sha256(self.public_key).hexdigest()}"


class ToolManifestBinding(BaseModel):
    """Signed discovery or approval bound to a manifest and executor identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    binding_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    phase: ToolManifestBindingPhase
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    executor_identity_digest: str = Field(pattern=_DIGEST_PATTERN)
    discovery_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    approved_by: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    authority_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    key_id: str = Field(pattern=_KEY_ID_PATTERN)
    issued_at: datetime
    expires_at: datetime
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_phase(self) -> ToolManifestBinding:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if self.phase == ToolManifestBindingPhase.DISCOVERY:
            if self.discovery_digest is not None or self.approved_by is not None:
                raise ValueError("discovery bindings cannot contain approval fields")
        elif self.discovery_digest is None or self.approved_by is None:
            raise ValueError("approval bindings require discovery_digest and approved_by")
        return self

    @property
    def signing_payload(self) -> dict[str, Any]:
        return {
            name: getattr(self, name) for name in self.__class__.model_fields if name != "signature"
        }

    @property
    def signing_bytes(self) -> bytes:
        return canonical_tool_manifest_json(self.signing_payload).encode()

    @property
    def binding_digest(self) -> str:
        return tool_manifest_digest({"payload": self.signing_payload, "signature": self.signature})


class ToolRuntimeEvidence(BaseModel):
    """Signed evidence of the controls and limits active at the executor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    evidence_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    executor: ToolExecutorIdentity
    filesystem: ToolFilesystemCapability
    egress: frozenset[ToolEgressDestination] = Field(default_factory=frozenset)
    credential_references: frozenset[str] = Field(default_factory=frozenset)
    resources: ToolResourceLimits
    controls: frozenset[ToolEnforcementControl] = Field(min_length=1)
    authority_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    key_id: str = Field(pattern=_KEY_ID_PATTERN)
    issued_at: datetime
    expires_at: datetime
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> ToolRuntimeEvidence:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self

    @property
    def signing_payload(self) -> dict[str, Any]:
        return {
            name: getattr(self, name) for name in self.__class__.model_fields if name != "signature"
        }

    @property
    def signing_bytes(self) -> bytes:
        return canonical_tool_manifest_json(self.signing_payload).encode()

    @property
    def evidence_digest(self) -> str:
        return tool_manifest_digest({"payload": self.signing_payload, "signature": self.signature})


class ToolExecutionRequest(BaseModel):
    """Exact capabilities and input proposed for one tool dispatch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    execution_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tool_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    version: str = Field(pattern=_IDENTIFIER_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    executor: ToolExecutorIdentity
    effects: frozenset[ToolCapabilityEffect] = Field(default_factory=frozenset)
    scopes: frozenset[str] = Field(default_factory=frozenset)
    filesystem: ToolFilesystemCapability
    egress: frozenset[ToolEgressDestination] = Field(default_factory=frozenset)
    credential_references: frozenset[str] = Field(default_factory=frozenset)
    resources: ToolResourceLimits
    input_classification: ToolDataClassification
    input_value: JsonValue

    @property
    def request_digest(self) -> str:
        return tool_manifest_digest(self)


class AuthorizedToolExecution(BaseModel):
    """Single-use lease bound to manifest, approval, request, and evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    execution_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    approval_digest: str = Field(pattern=_DIGEST_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    evidence_digest: str = Field(pattern=_DIGEST_PATTERN)
    output_schema_digest: str = Field(pattern=_DIGEST_PATTERN)
    max_output_classification: ToolDataClassification
    output_limit_bytes: int = Field(ge=1)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @property
    def authorization_digest(self) -> str:
        return tool_manifest_digest(self)


class ToolExecutionOutput(BaseModel):
    """Untrusted result submitted for contract validation before release."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    execution_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    value: JsonValue
    classification: ToolDataClassification


class VerifiedToolOutput(BaseModel):
    """Output that passed its manifest-bound contract and data boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    execution_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    value: JsonValue
    classification: ToolDataClassification
    verified_at: datetime


class ToolManifestPolicy(BaseModel):
    """Freshness and lease policy for runtime manifest enforcement."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_manifest_age_seconds: int = Field(default=86_400, ge=1, le=31_536_000)
    max_evidence_age_seconds: int = Field(default=60, ge=1, le=86_400)
    binding_ttl_seconds: int = Field(default=3_600, ge=1, le=604_800)
    authorization_ttl_seconds: int = Field(default=60, ge=1, le=3_600)
    clock_skew_seconds: int = Field(default=5, ge=0, le=300)
    required_controls: frozenset[ToolEnforcementControl] = Field(
        default_factory=lambda: frozenset(ToolEnforcementControl)
    )


class ToolManifestFinding(BaseModel):
    """Content-free capability enforcement finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ToolManifestCode
    severity: Severity
    message: str
    tool_reference: str | None = None


class ToolManifestDecision(BaseModel):
    """Discovery, approval, authorization, or output-verification result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: GuardAction
    findings: tuple[ToolManifestFinding, ...] = ()
    binding: ToolManifestBinding | None = None
    authorization: AuthorizedToolExecution | None = None
    output: VerifiedToolOutput | None = None

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW

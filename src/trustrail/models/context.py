"""Typed models for trusted, hierarchy-preserving model context assembly."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity, TrustLevel


def _canonicalize(value: JsonValue) -> JsonValue:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, JsonValue] = {}
        for key, item in value.items():
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise ValueError("object keys must remain unique after Unicode normalization")
            normalized[normalized_key] = _canonicalize(item)
        return normalized
    return value


def canonical_context_json(value: JsonValue) -> str:
    """Return deterministic NFC-normalized JSON used by context integrity controls."""
    return json.dumps(
        _canonicalize(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def context_digest(value: JsonValue) -> str:
    """Return a lowercase SHA-256 digest of canonical context JSON."""
    return hashlib.sha256(canonical_context_json(value).encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(tz=UTC)


class ContextOrigin(StrEnum):
    """Authenticated origin class for one context segment."""

    SYSTEM_POLICY = "system_policy"
    DEVELOPER = "developer"
    USER = "user"
    RETRIEVAL = "retrieval"
    MEMORY = "memory"
    TOOL = "tool"
    EXTERNAL = "external"
    MULTIMODAL = "multimodal"


class ContextRole(StrEnum):
    """Provider-neutral role before data-only segments are safely wrapped."""

    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    DATA = "data"


class InstructionPermission(StrEnum):
    """Maximum instruction authority assigned by trusted application code."""

    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    NONE = "none"


class ContextProviderProfile(StrEnum):
    """Reserved-token profile enforced before provider adaptation."""

    GENERIC = "generic"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class ReservedTokenMode(StrEnum):
    """Treatment for provider-reserved or synthetic boundary tokens."""

    REJECT = "reject"
    ESCAPE = "escape"


class ContextAssemblyCode(StrEnum):
    """Stable machine-readable trusted-context outcomes."""

    DUPLICATE_SEGMENT = "duplicate_segment"
    DUPLICATE_ORDINAL = "duplicate_ordinal"
    DUPLICATE_SYSTEM = "duplicate_system"
    MISSING_SYSTEM = "missing_system"
    INVALID_HIERARCHY = "invalid_hierarchy"
    TENANT_MISMATCH = "tenant_mismatch"
    PURPOSE_MISMATCH = "purpose_mismatch"
    CONTEXT_LIMIT_EXCEEDED = "context_limit_exceeded"
    RESERVED_TOKEN = "reserved_token"  # noqa: S105 -- detection code, not a credential
    SYNTHETIC_ROLE_BOUNDARY = "synthetic_role_boundary"
    TEMPLATE_INJECTION = "template_injection"
    UNICODE_SMUGGLING = "unicode_smuggling"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_EXPIRED = "manifest_expired"
    REQUEST_MISMATCH = "request_mismatch"
    POLICY_MISMATCH = "policy_mismatch"
    ADAPTER_TRANSFORMATION = "adapter_transformation"


class ContextSegment(BaseModel):
    """One application-labeled piece of model context.

    Identity, tenant, purpose, provenance, role, trust and permission values must
    come from authenticated application state, never from the content itself.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    segment_id: str = Field(min_length=1, max_length=256)
    ordinal: int = Field(ge=0, le=1_000_000)
    content: str = Field(max_length=10_000_000, repr=False)
    origin: ContextOrigin
    role: ContextRole
    trust_level: TrustLevel
    tenant_id: str = Field(min_length=1, max_length=512)
    purpose: str = Field(min_length=1, max_length=512)
    provenance_id: str = Field(min_length=1, max_length=1_024)
    instruction_permission: InstructionPermission
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("segment_id", "tenant_id", "purpose", "provenance_id")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("context identity values must not be blank")
        return value

    @model_validator(mode="after")
    def validate_canonical_form(self) -> ContextSegment:
        canonical_context_json(cast(dict[str, JsonValue], self.model_dump(mode="json")))
        return self

    @property
    def canonical_payload(self) -> dict[str, JsonValue]:
        """Return every security-relevant segment field in canonical shape."""
        return cast(
            dict[str, JsonValue],
            _canonicalize(cast(dict[str, JsonValue], self.model_dump(mode="json"))),
        )


class ContextAssemblyPolicy(BaseModel):
    """Bounds and fail-closed syntax policy for trusted context assembly."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_profile: ContextProviderProfile = ContextProviderProfile.GENERIC
    reserved_token_mode: ReservedTokenMode = ReservedTokenMode.REJECT
    max_segments: int = Field(default=128, ge=1, le=10_000)
    max_segment_chars: int = Field(default=100_000, ge=1, le=10_000_000)
    max_total_chars: int = Field(default=500_000, ge=1, le=50_000_000)
    max_metadata_nodes: int = Field(default=2_048, ge=1, le=100_000)
    require_system_policy: bool = True
    reject_template_syntax: bool = True
    reject_synthetic_role_boundaries: bool = True
    max_manifest_age_seconds: int = Field(default=60, ge=1, le=86_400)
    max_future_skew_seconds: int = Field(default=5, ge=0, le=300)
    extra_reserved_tokens: tuple[str, ...] = Field(default=(), max_length=128)

    @field_validator("extra_reserved_tokens")
    @classmethod
    def validate_tokens(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not token or len(token) > 512 for token in value):
            raise ValueError("extra reserved tokens must contain 1 to 512 characters")
        return value

    @property
    def policy_digest(self) -> str:
        """Bind every context-assembly policy setting to a manifest."""
        return context_digest(cast(dict[str, JsonValue], self.model_dump(mode="json")))


class ContextMessage(BaseModel):
    """One provider-neutral message with explicit data/instruction semantics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: Literal["system", "developer", "user"]
    content: str = Field(repr=False)
    origin: ContextOrigin
    trust_level: TrustLevel
    instruction_permission: InstructionPermission
    is_data: bool
    segment_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ProviderContextRequest(BaseModel):
    """Exact provider-neutral request that must be verified before dispatch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    provider_profile: ContextProviderProfile
    adapter_id: Literal["trustrail.provider-neutral"] = "trustrail.provider-neutral"
    adapter_version: Literal[1] = 1
    request_id: str = Field(min_length=1, max_length=512, repr=False)
    tenant_id: str = Field(min_length=1, max_length=512, repr=False)
    purpose: str = Field(min_length=1, max_length=512, repr=False)
    messages: tuple[ContextMessage, ...] = Field(min_length=1)

    @property
    def canonical_payload(self) -> dict[str, JsonValue]:
        """Return the exact request fields bound by the manifest."""
        return cast(dict[str, JsonValue], self.model_dump(mode="json"))

    @property
    def request_digest(self) -> str:
        """Return the digest that detects role, order, content or adapter changes."""
        return context_digest(self.canonical_payload)

    def provider_messages(self) -> list[dict[str, str]]:
        """Return exact role/content dictionaries for a compatible provider adapter."""
        return [{"role": item.role, "content": item.content} for item in self.messages]


class ContextSegmentFingerprint(BaseModel):
    """Content-free binding for one ordered context segment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    segment_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    ordinal: int = Field(ge=0, le=1_000_000)
    origin: ContextOrigin
    role: ContextRole
    trust_level: TrustLevel
    instruction_permission: InstructionPermission
    tenant_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    purpose_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    provenance_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    metadata_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ContextManifest(BaseModel):
    """Signed, content-free manifest for one exact provider request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    provider_profile: ContextProviderProfile
    adapter_id: Literal["trustrail.provider-neutral"] = "trustrail.provider-neutral"
    adapter_version: Literal[1] = 1
    request_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tenant_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    purpose_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    segment_fingerprints: tuple[ContextSegmentFingerprint, ...] = Field(min_length=1)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime = Field(default_factory=_now)
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("issued_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("issued_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def unique_segments(self) -> ContextManifest:
        refs = [item.segment_ref for item in self.segment_fingerprints]
        ordinals = [item.ordinal for item in self.segment_fingerprints]
        if len(refs) != len(set(refs)) or len(ordinals) != len(set(ordinals)):
            raise ValueError("manifest segments and ordinals must be unique")
        return self


class ContextAssemblyFinding(BaseModel):
    """Content-safe finding that never echoes context or raw identity values."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ContextAssemblyCode
    severity: Severity
    message: str
    segment_refs: tuple[str, ...] = ()
    field_paths: tuple[str, ...] = ()


class ContextAssemblyResult(BaseModel):
    """Result of assembly or immediate pre-provider verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: GuardAction
    findings: tuple[ContextAssemblyFinding, ...] = ()
    request: ProviderContextRequest | None = Field(default=None, repr=False)
    manifest: ContextManifest | None = None

    @property
    def is_allowed(self) -> bool:
        return self.action in {GuardAction.ALLOW, GuardAction.TRANSFORM}


def manifest_signing_payload(manifest: ContextManifest) -> dict[str, Any]:
    """Return exactly the content-free manifest fields covered by HMAC."""
    return manifest.model_dump(mode="json", exclude={"signature"})

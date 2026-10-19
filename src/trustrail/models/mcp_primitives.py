"""Typed models for MCP resource, prompt, subscription, and completion integrity."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity
from trustrail.models.mcp import MCPDefinitionChange, _canonicalize, _field_digests


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _canonical_json(value: JsonValue) -> str:
    return json.dumps(
        _canonicalize(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


class MCPPrimitiveKind(StrEnum):
    """Security-relevant MCP primitive kinds."""

    RESOURCE = "resource"
    RESOURCE_TEMPLATE = "resource_template"
    PROMPT = "prompt"
    SUBSCRIPTION = "subscription"
    COMPLETION = "completion"


class MCPPrimitivePhase(StrEnum):
    """Lifecycle phase represented by a signed primitive snapshot."""

    DISCOVERY = "discovery"
    APPROVAL = "approval"


class MCPPrimitiveCode(StrEnum):
    """Stable machine-readable primitive-integrity outcomes."""

    DUPLICATE_IDENTITY = "duplicate_identity"
    CONFUSABLE_IDENTITY = "confusable_identity"
    HIDDEN_INSTRUCTION = "hidden_instruction"
    UNICODE_SMUGGLING = "unicode_smuggling"
    CROSS_SERVER_REFERENCE = "cross_server_reference"
    AMBIGUOUS_SEMANTICS = "ambiguous_semantics"
    DANGEROUS_URI = "dangerous_uri"
    LIMIT_EXCEEDED = "limit_exceeded"
    PIN_INVALID = "pin_invalid"
    DISCOVERY_MISMATCH = "discovery_mismatch"
    PRIMITIVE_NOT_APPROVED = "primitive_not_approved"
    PRIMITIVE_CHANGED = "primitive_changed"
    IDENTITY_MISMATCH = "identity_mismatch"
    SCHEMA_MISMATCH = "schema_mismatch"
    PROVENANCE_MISMATCH = "provenance_mismatch"
    AUTHORIZATION_MISSING = "authorization_missing"
    MEDIA_TYPE_DENIED = "media_type_denied"
    SUBSCRIPTION_MISMATCH = "subscription_mismatch"


class MCPPrimitiveAnnotations(BaseModel):
    """Canonical MCP annotations, including bounded extension metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    audience: tuple[Literal["user", "assistant"], ...] = ()
    priority: float | None = Field(default=None, ge=0.0, le=1.0)
    last_modified: datetime | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("last_modified")
    @classmethod
    def require_aware_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("last_modified must be timezone-aware")
        return value


class MCPIcon(BaseModel):
    """Canonical MCP icon metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    src: str = Field(min_length=1, max_length=2_048)
    mime_type: str | None = Field(default=None, max_length=255)
    sizes: tuple[str, ...] = Field(default=(), max_length=16)
    theme: Literal["light", "dark"] | None = None


class MCPPromptArgument(BaseModel):
    """A bounded, explicitly described prompt argument."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$")
    description: str = Field(min_length=1, max_length=4_096)
    required: bool = False
    max_length: int = Field(default=4_096, ge=1, le=100_000)


class MCPResourceTemplateArgument(BaseModel):
    """An approved URI-template variable and its bounds."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$")
    description: str = Field(min_length=1, max_length=4_096)
    pattern: str = Field(default=r"^[A-Za-z0-9._~-]+$", min_length=1, max_length=1_024)
    max_length: int = Field(default=256, ge=1, le=4_096)


class _MCPPrimitiveDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    kind: MCPPrimitiveKind
    server_id: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=256)
    title: str | None = Field(default=None, max_length=512)
    description: str = Field(min_length=1, max_length=16_384)
    provenance_id: str = Field(min_length=1, max_length=512)
    required_scopes: frozenset[str] = Field(default_factory=frozenset, max_length=64)
    annotations: MCPPrimitiveAnnotations = Field(default_factory=MCPPrimitiveAnnotations)
    icons: tuple[MCPIcon, ...] = Field(default=(), max_length=16)

    @field_validator("server_id", "name", "description", "provenance_id")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must not be blank")
        return value

    @field_validator("required_scopes")
    @classmethod
    def validate_scopes(cls, value: frozenset[str]) -> frozenset[str]:
        if any(not scope.strip() or len(scope) > 256 for scope in value):
            raise ValueError("required scopes must be non-blank and at most 256 characters")
        return value

    @model_validator(mode="after")
    def validate_canonical_form(self) -> _MCPPrimitiveDefinition:
        # Reject non-finite numbers and keys that collide after NFC normalization.
        _canonical_json(self.canonical_payload)
        return self

    @property
    def identity(self) -> str:
        """Return a kind- and server-qualified primitive identity."""
        return f"{self.kind.value}:{self.server_id}:{self.name}"

    @property
    def canonical_payload(self) -> dict[str, JsonValue]:
        """Return every security-relevant field in deterministic shape."""
        payload = self.model_dump(mode="json", by_alias=True)
        return cast(dict[str, JsonValue], _canonicalize(payload))

    @property
    def canonical_json(self) -> str:
        """Return deterministic Unicode-normalized JSON for signing."""
        return _canonical_json(self.canonical_payload)

    @property
    def definition_digest(self) -> str:
        """Return the SHA-256 digest of the complete primitive definition."""
        return hashlib.sha256(self.canonical_json.encode()).hexdigest()

    @property
    def field_digests(self) -> dict[str, str]:
        """Return content-free field bindings for safe change reports."""
        return _field_digests(self.canonical_payload)


class MCPResourceDefinition(_MCPPrimitiveDefinition):
    """An exact MCP resource identity and approved content contract."""

    kind: Literal[MCPPrimitiveKind.RESOURCE] = MCPPrimitiveKind.RESOURCE
    uri: str = Field(min_length=1, max_length=8_192)
    mime_type: str = Field(alias="mimeType", min_length=1, max_length=255)
    max_size: int = Field(default=1_048_576, ge=1, le=100_000_000)
    content_schema: dict[str, JsonValue] | None = Field(default=None, alias="contentSchema")


class MCPResourceTemplateDefinition(_MCPPrimitiveDefinition):
    """An MCP resource template with explicit, bounded variables."""

    kind: Literal[MCPPrimitiveKind.RESOURCE_TEMPLATE] = MCPPrimitiveKind.RESOURCE_TEMPLATE
    uri_template: str = Field(alias="uriTemplate", min_length=1, max_length=8_192)
    mime_type: str = Field(alias="mimeType", min_length=1, max_length=255)
    max_size: int = Field(default=1_048_576, ge=1, le=100_000_000)
    arguments: tuple[MCPResourceTemplateArgument, ...] = Field(default=(), max_length=64)
    content_schema: dict[str, JsonValue] | None = Field(default=None, alias="contentSchema")


class MCPPromptDefinition(_MCPPrimitiveDefinition):
    """An MCP prompt and its complete argument contract."""

    kind: Literal[MCPPrimitiveKind.PROMPT] = MCPPrimitiveKind.PROMPT
    arguments: tuple[MCPPromptArgument, ...] = Field(default=(), max_length=64)
    max_messages: int = Field(default=32, ge=1, le=1_000)
    max_total_chars: int = Field(default=100_000, ge=1, le=10_000_000)

    @model_validator(mode="after")
    def unique_arguments(self) -> MCPPromptDefinition:
        names = [argument.name for argument in self.arguments]
        if len(names) != len(set(names)):
            raise ValueError("prompt argument names must be unique")
        return self


class MCPSubscriptionIdentity(_MCPPrimitiveDefinition):
    """An approved resource or list-change subscription identity."""

    kind: Literal[MCPPrimitiveKind.SUBSCRIPTION] = MCPPrimitiveKind.SUBSCRIPTION
    subscription_id: str = Field(min_length=1, max_length=512)
    event_type: Literal["resource_updated", "resource_list_changed", "prompt_list_changed"]
    resource_uri: str | None = Field(default=None, max_length=8_192)

    @model_validator(mode="after")
    def require_resource_for_update(self) -> MCPSubscriptionIdentity:
        if self.event_type == "resource_updated" and self.resource_uri is None:
            raise ValueError("resource_updated subscriptions require resource_uri")
        if self.event_type != "resource_updated" and self.resource_uri is not None:
            raise ValueError("list-change subscriptions cannot set resource_uri")
        return self


class MCPCompletionDefinition(_MCPPrimitiveDefinition):
    """An approved completion target and response contract."""

    kind: Literal[MCPPrimitiveKind.COMPLETION] = MCPPrimitiveKind.COMPLETION
    reference_kind: Literal["prompt", "resource_template"]
    reference_name: str = Field(min_length=1, max_length=8_192)
    argument_name: str = Field(min_length=1, max_length=128)
    allowed_context_arguments: frozenset[str] = Field(default_factory=frozenset, max_length=64)
    max_values: int = Field(default=100, ge=1, le=10_000)
    max_value_length: int = Field(default=1_024, ge=1, le=100_000)


MCPPrimitiveDefinition = Annotated[
    MCPResourceDefinition
    | MCPResourceTemplateDefinition
    | MCPPromptDefinition
    | MCPSubscriptionIdentity
    | MCPCompletionDefinition,
    Field(discriminator="kind"),
]


class MCPPrimitivePolicy(BaseModel):
    """Bounds and URI/media policy for untrusted MCP context primitives."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_primitives: int = Field(default=512, ge=1, le=10_000)
    max_nodes_per_primitive: int = Field(default=4_096, ge=16, le=100_000)
    max_total_string_chars: int = Field(default=100_000, ge=256, le=10_000_000)
    max_depth: int = Field(default=32, ge=2, le=128)
    allowed_uri_schemes: frozenset[str] = frozenset({"https", "mcp"})
    allowed_icon_schemes: frozenset[str] = frozenset({"https"})
    allowed_mime_types: frozenset[str] = frozenset(
        {"application/json", "text/html", "text/markdown", "text/plain"}
    )
    reject_cross_server_references: bool = True
    require_closed_content_schemas: bool = True


class MCPPrimitiveFingerprint(BaseModel):
    """Content-free fingerprint for one complete primitive definition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: MCPPrimitiveKind
    server_id: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=256)
    definition_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    field_digests: dict[str, str]

    @property
    def identity(self) -> str:
        return f"{self.kind.value}:{self.server_id}:{self.name}"


class MCPPrimitiveSnapshot(BaseModel):
    """Signed discovery or approval snapshot for MCP context primitives."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    phase: MCPPrimitivePhase
    fingerprints: tuple[MCPPrimitiveFingerprint, ...] = Field(min_length=1)
    issued_at: datetime = Field(default_factory=_now)
    approved_by: str | None = Field(default=None, min_length=1, max_length=256)
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_snapshot(self) -> MCPPrimitiveSnapshot:
        if self.issued_at.tzinfo is None or self.issued_at.utcoffset() is None:
            raise ValueError("issued_at must be timezone-aware")
        identities = [item.identity for item in self.fingerprints]
        if len(identities) != len(set(identities)):
            raise ValueError("snapshot fingerprints must have unique identities")
        if (self.phase == MCPPrimitivePhase.APPROVAL) != (self.approved_by is not None):
            raise ValueError("only approval snapshots require approved_by")
        return self


class MCPResourceContent(BaseModel):
    """Fetched resource data plus authenticated origin and authorization evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server_id: str = Field(min_length=1, max_length=256)
    uri: str = Field(min_length=1, max_length=8_192)
    mime_type: str = Field(alias="mimeType", min_length=1, max_length=255)
    data: str | bytes = Field(repr=False)
    provenance_id: str = Field(min_length=1, max_length=512)
    granted_scopes: frozenset[str] = Field(default_factory=frozenset, max_length=64)
    subscription_id: str | None = Field(default=None, max_length=512)


class MCPPromptMessage(BaseModel):
    """One bounded text message returned by ``prompts/get``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: Literal["user", "assistant"]
    content: str = Field(max_length=100_000, repr=False)


class MCPPromptRender(BaseModel):
    """A live prompt rendering and the evidence needed to authorize it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server_id: str = Field(min_length=1, max_length=256)
    prompt_name: str = Field(min_length=1, max_length=256)
    arguments: dict[str, str] = Field(default_factory=dict)
    messages: tuple[MCPPromptMessage, ...]
    provenance_id: str = Field(min_length=1, max_length=512)
    granted_scopes: frozenset[str] = Field(default_factory=frozenset, max_length=64)


class MCPCompletionMetadata(BaseModel):
    """A live completion response bound to an approved completion contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server_id: str = Field(min_length=1, max_length=256)
    reference_kind: Literal["prompt", "resource_template"]
    reference_name: str = Field(min_length=1, max_length=8_192)
    argument_name: str = Field(min_length=1, max_length=128)
    context_arguments: dict[str, str] = Field(default_factory=dict)
    values: tuple[str, ...]
    total: int | None = Field(default=None, ge=0)
    has_more: bool | None = None
    provenance_id: str = Field(min_length=1, max_length=512)
    granted_scopes: frozenset[str] = Field(default_factory=frozenset, max_length=64)


class MCPPrimitiveFinding(BaseModel):
    """Content-safe primitive finding with hashed identities and safe paths."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: MCPPrimitiveCode
    severity: Severity
    message: str
    identities: tuple[str, ...] = ()
    field_paths: tuple[str, ...] = ()
    changes: tuple[MCPDefinitionChange, ...] = ()


class MCPPrimitiveResult(BaseModel):
    """Result of primitive discovery, approval, or use-time validation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: GuardAction
    findings: tuple[MCPPrimitiveFinding, ...] = ()
    snapshot: MCPPrimitiveSnapshot | None = None

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW

    @property
    def requires_approval(self) -> bool:
        return self.action == GuardAction.REQUIRE_APPROVAL


def fingerprint_primitive(definition: MCPPrimitiveDefinition) -> MCPPrimitiveFingerprint:
    """Build the content-free fingerprint stored in signed snapshots."""
    return MCPPrimitiveFingerprint(
        kind=definition.kind,
        server_id=definition.server_id,
        name=definition.name,
        definition_digest=definition.definition_digest,
        field_digests=definition.field_digests,
    )


def snapshot_signing_payload(snapshot: MCPPrimitiveSnapshot) -> dict[str, Any]:
    """Return the exact fields covered by a snapshot signature."""
    return snapshot.model_dump(mode="json", exclude={"signature"})

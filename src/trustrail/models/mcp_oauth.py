"""Typed MCP OAuth resource-server authorization contracts."""

# ruff: noqa: S105 -- enum values describe security outcomes, not credentials.

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity
from trustrail.models.mcp import MCPToolDefinition

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_KEY_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_REFERENCE_PATTERN = r"^sha256:[0-9a-f]{64}$"
_POINTER_PATTERN = r"^(?:/(?:[^~/]|~[01])*)+$"


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(tz=UTC)


def oauth_reference(value: str | bytes) -> str:
    """Return a content-free reference for OAuth audit evidence."""
    encoded = value.encode() if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


class MCPOAuthAlgorithm(StrEnum):
    """Access-token signature algorithms supported by the resource server."""

    EDDSA = "EdDSA"


class MCPOAuthOperation(StrEnum):
    """MCP operation protected by OAuth authorization."""

    TOOLS_LIST = "tools/list"
    TOOLS_CALL = "tools/call"
    DOWNSTREAM_CREDENTIAL = "downstream_credential"


class MCPOAuthCode(StrEnum):
    """Stable, content-free MCP OAuth authorization outcomes."""

    ALLOWED = "allowed"
    TOKEN_MISSING = "token_missing"
    TOKEN_MALFORMED = "token_malformed"
    TOKEN_TOO_LARGE = "token_too_large"
    HEADER_INVALID = "header_invalid"
    ALGORITHM_NOT_ALLOWED = "algorithm_not_allowed"
    KEY_NOT_TRUSTED = "key_not_trusted"
    KEY_NOT_ACTIVE = "key_not_active"
    SIGNATURE_INVALID = "signature_invalid"
    ISSUER_MISMATCH = "issuer_mismatch"
    AUDIENCE_MISMATCH = "audience_mismatch"
    RESOURCE_MISMATCH = "resource_mismatch"
    TOKEN_NOT_YET_VALID = "token_not_yet_valid"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_TOO_OLD = "token_too_old"
    TOKEN_TTL_EXCEEDED = "token_ttl_exceeded"
    CLIENT_MISMATCH = "client_mismatch"
    SUBJECT_MISMATCH = "subject_mismatch"
    USER_MISMATCH = "user_mismatch"
    TENANT_MISMATCH = "tenant_mismatch"
    SERVER_MISMATCH = "server_mismatch"
    REQUEST_MISMATCH = "request_mismatch"
    OPERATION_MISMATCH = "operation_mismatch"
    SCOPE_MISSING = "scope_missing"
    SCOPE_EXCESSIVE = "scope_excessive"
    RESOURCE_EXCESSIVE = "resource_excessive"
    TOKEN_REPLAYED = "token_replayed"
    REPLAY_STORE_FULL = "replay_store_full"
    REPLAY_STORE_ERROR = "replay_store_error"
    TOOL_NOT_AUTHORIZED = "tool_not_authorized"
    ARGUMENT_RESOURCE_MISSING = "argument_resource_missing"
    ARGUMENT_RESOURCE_INVALID = "argument_resource_invalid"
    RESOURCE_NOT_AUTHORIZED = "resource_not_authorized"
    TOKEN_PASSTHROUGH = "token_passthrough"
    DOWNSTREAM_SCOPE_INVALID = "downstream_scope_invalid"
    DOWNSTREAM_CREDENTIAL_UNAVAILABLE = "downstream_credential_unavailable"


class MCPOAuthReplayStatus(StrEnum):
    """Atomic token replay-claim outcome."""

    STORED = "stored"
    REPLAYED = "replayed"
    FULL = "full"


class MCPOAuthDownstreamMode(StrEnum):
    """Permitted source of a downstream service credential."""

    TOKEN_EXCHANGE = "token_exchange"
    WORKLOAD_IDENTITY = "workload_identity"


class MCPOAuthTrustedKey(BaseModel):
    """Out-of-band issuer binding for one pinned access-token public key."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer: str = Field(min_length=1, max_length=2_048)
    key_id: str = Field(pattern=_KEY_ID_PATTERN)
    algorithm: MCPOAuthAlgorithm = MCPOAuthAlgorithm.EDDSA
    public_key: bytes = Field(min_length=32, max_length=32, exclude=True, repr=False)
    active_from: datetime | None = None
    expires_at: datetime | None = None
    revoked: bool = False

    @field_validator("active_from", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("trusted-key timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_lifetime(self) -> MCPOAuthTrustedKey:
        if (
            self.active_from is not None
            and self.expires_at is not None
            and self.expires_at <= self.active_from
        ):
            raise ValueError("trusted key expires_at must be after active_from")
        return self


class MCPOAuthToolPolicy(BaseModel):
    """Exact scopes and argument resources required for one MCP tool."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    required_scopes: frozenset[str] = Field(min_length=1)
    allowed_resource_ids: frozenset[str] = frozenset()
    resource_argument_pointers: tuple[str, ...] = ()

    @field_validator("required_scopes")
    @classmethod
    def validate_scopes(cls, value: frozenset[str]) -> frozenset[str]:
        if any(
            not item or len(item) > 256 or any(character.isspace() for character in item)
            for item in value
        ):
            raise ValueError("tool scopes must be non-empty strings without whitespace")
        return value

    @field_validator("allowed_resource_ids")
    @classmethod
    def validate_resources(cls, value: frozenset[str]) -> frozenset[str]:
        if any(not item or len(item) > 1_024 for item in value):
            raise ValueError("resource identifiers must contain 1 to 1024 characters")
        return value

    @field_validator("resource_argument_pointers")
    @classmethod
    def validate_pointers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("resource argument pointers must be unique")
        if any(len(item) > 1_024 for item in value):
            raise ValueError("resource argument pointers must not exceed 1024 characters")
        if any(re.fullmatch(_POINTER_PATTERN, item) is None for item in value):
            raise ValueError("resource argument pointers must be non-root JSON pointers")
        return value

    @model_validator(mode="after")
    def require_resource_policy(self) -> MCPOAuthToolPolicy:
        if self.resource_argument_pointers and not self.allowed_resource_ids:
            raise ValueError("resource-bound arguments require allowed_resource_ids")
        return self


class MCPOAuthPolicy(BaseModel):
    """Fail-closed resource-server and tool authorization policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer: str = Field(min_length=1, max_length=2_048)
    audience: str = Field(min_length=1, max_length=2_048)
    resource: str = Field(min_length=1, max_length=2_048)
    server_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    allowed_algorithms: frozenset[MCPOAuthAlgorithm] = frozenset({MCPOAuthAlgorithm.EDDSA})
    allowed_scopes: frozenset[str] = Field(min_length=1)
    tools_list_scope: str = Field(default="mcp:tools:list", min_length=1, max_length=256)
    tool_policies: tuple[MCPOAuthToolPolicy, ...] = Field(min_length=1, max_length=10_000)
    max_token_bytes: int = Field(default=16_384, ge=512, le=1_048_576)
    max_token_ttl_seconds: int = Field(default=300, ge=1, le=86_400)
    max_token_age_seconds: int = Field(default=300, ge=1, le=86_400)
    clock_skew_seconds: int = Field(default=30, ge=0, le=300)
    require_single_use: Literal[True] = True

    @field_validator("allowed_scopes")
    @classmethod
    def validate_scopes(cls, value: frozenset[str]) -> frozenset[str]:
        if any(
            not item or len(item) > 256 or any(character.isspace() for character in item)
            for item in value
        ):
            raise ValueError("allowed scopes must be non-empty strings without whitespace")
        return value

    @model_validator(mode="after")
    def validate_tool_policies(self) -> MCPOAuthPolicy:
        names = [item.tool_name for item in self.tool_policies]
        if len(names) != len(set(names)):
            raise ValueError("tool policies must have unique tool names")
        if self.tools_list_scope not in self.allowed_scopes:
            raise ValueError("tools_list_scope must be included in allowed_scopes")
        if any(
            not item.required_scopes.issubset(self.allowed_scopes) for item in self.tool_policies
        ):
            raise ValueError("tool required scopes must be included in allowed_scopes")
        return self

    def tool_policy_for(self, tool_name: str) -> MCPOAuthToolPolicy | None:
        """Return the exact configured tool policy, if present."""
        return next((item for item in self.tool_policies if item.tool_name == tool_name), None)

    @property
    def allowed_resource_ids(self) -> frozenset[str]:
        """Return the union of resources declared by every tool policy."""
        return frozenset(
            resource
            for tool_policy in self.tool_policies
            for resource in tool_policy.allowed_resource_ids
        )


class MCPOAuthRequestContext(BaseModel):
    """Authenticated request context that must match access-token claims."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation: MCPOAuthOperation
    server_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    user_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    subject_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    client_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)


class MCPOAuthTokenClaims(BaseModel):
    """Required JWT access-token claims for one MCP request."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    issuer: str = Field(alias="iss", min_length=1, max_length=2_048)
    audiences: frozenset[str] = Field(alias="aud", min_length=1)
    resources: frozenset[str] = Field(alias="resource", min_length=1)
    expires_at: StrictInt = Field(alias="exp", ge=0, le=253_402_300_799)
    not_before: StrictInt = Field(alias="nbf", ge=0, le=253_402_300_799)
    issued_at: StrictInt = Field(alias="iat", ge=0, le=253_402_300_799)
    token_id: str = Field(alias="jti", pattern=_IDENTIFIER_PATTERN)
    client_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    subject_id: str = Field(alias="sub", pattern=_IDENTIFIER_PATTERN)
    user_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    server_id: str = Field(alias="mcp_server_id", pattern=_IDENTIFIER_PATTERN)
    request_id: str = Field(alias="mcp_request_id", pattern=_IDENTIFIER_PATTERN)
    scopes: frozenset[str] = Field(alias="scope", min_length=1)
    resource_ids: frozenset[str] = frozenset()

    @field_validator("audiences", "resources", mode="before")
    @classmethod
    def normalize_string_set(cls, value: Any) -> Any:
        return [value] if isinstance(value, str) else value

    @field_validator("scopes", mode="before")
    @classmethod
    def normalize_scopes(cls, value: Any) -> Any:
        return value.split() if isinstance(value, str) else value

    @field_validator("audiences", "resources", "scopes", "resource_ids")
    @classmethod
    def validate_string_set(cls, value: frozenset[str]) -> frozenset[str]:
        if any(not item or len(item) > 2_048 for item in value):
            raise ValueError("claim sets must contain non-empty bounded strings")
        return value

    @model_validator(mode="after")
    def validate_times(self) -> MCPOAuthTokenClaims:
        if self.expires_at <= self.issued_at:
            raise ValueError("exp must be after iat")
        if self.not_before > self.expires_at:
            raise ValueError("nbf must not be after exp")
        return self


class MCPOAuthFinding(BaseModel):
    """Content-free explanation of an MCP OAuth authorization decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: MCPOAuthCode
    severity: Severity
    message: str = Field(min_length=1, max_length=500)


class MCPOAuthAuditEvent(BaseModel):
    """Metadata-only evidence for one MCP OAuth operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    occurred_at: datetime
    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    operation: MCPOAuthOperation
    code: MCPOAuthCode
    token_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    key_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    issuer_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    server_ref: str = Field(pattern=_REFERENCE_PATTERN)
    tenant_ref: str = Field(pattern=_REFERENCE_PATTERN)
    user_ref: str = Field(pattern=_REFERENCE_PATTERN)
    subject_ref: str = Field(pattern=_REFERENCE_PATTERN)
    client_ref: str = Field(pattern=_REFERENCE_PATTERN)
    request_ref: str = Field(pattern=_REFERENCE_PATTERN)
    tool_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    resource_refs: tuple[str, ...] = ()

    @field_validator("occurred_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        return value

    @field_validator("resource_refs")
    @classmethod
    def validate_resource_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.startswith("sha256:") or len(item) != 71 for item in value):
            raise ValueError("resource_refs must contain SHA-256 references")
        return value


class AuthorizedMCPOAuthRequest(BaseModel):
    """Immutable effective authority from a verified, consumed access token."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation: MCPOAuthOperation
    server_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    user_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    subject_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    client_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    scopes: frozenset[str]
    resource_ids: frozenset[str]
    token_ref: str = Field(pattern=_REFERENCE_PATTERN)
    token_id_ref: str = Field(pattern=_REFERENCE_PATTERN)
    expires_at: datetime
    tool_name: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    argument_resource_ids: frozenset[str] = frozenset()

    @field_validator("expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        return value


class MCPOAuthAuthorizationResult(BaseModel):
    """Fail-closed request decision with optional effective authority and tools."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    findings: tuple[MCPOAuthFinding, ...] = ()
    audit_event: MCPOAuthAuditEvent
    authorization: AuthorizedMCPOAuthRequest | None = None
    visible_tools: tuple[MCPToolDefinition, ...] = ()

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW


class MCPOAuthDownstreamRequest(BaseModel):
    """Bound request for a non-passthrough downstream credential."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization: AuthorizedMCPOAuthRequest
    mode: MCPOAuthDownstreamMode
    service_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    audience: str = Field(min_length=1, max_length=2_048)
    resource: str = Field(min_length=1, max_length=2_048)
    resource_id: str | None = Field(default=None, min_length=1, max_length=1_024)
    scopes: frozenset[str] = Field(min_length=1)

    @model_validator(mode="after")
    def require_call_authorization(self) -> MCPOAuthDownstreamRequest:
        authorization = self.authorization
        if (
            authorization.operation != MCPOAuthOperation.TOOLS_CALL
            or authorization.tool_name is None
        ):
            raise ValueError("downstream credentials require an authorized tools/call request")
        if authorization.argument_resource_ids:
            if self.resource_id not in authorization.argument_resource_ids:
                raise ValueError("downstream resource_id must match an authorized tool argument")
        elif self.resource_id is not None and self.resource_id not in authorization.resource_ids:
            raise ValueError("downstream resource_id must be authorized by the access token")
        return self


__all__ = [
    "AuthorizedMCPOAuthRequest",
    "MCPOAuthAlgorithm",
    "MCPOAuthAuditEvent",
    "MCPOAuthAuthorizationResult",
    "MCPOAuthCode",
    "MCPOAuthDownstreamMode",
    "MCPOAuthDownstreamRequest",
    "MCPOAuthFinding",
    "MCPOAuthOperation",
    "MCPOAuthPolicy",
    "MCPOAuthReplayStatus",
    "MCPOAuthRequestContext",
    "MCPOAuthTokenClaims",
    "MCPOAuthToolPolicy",
    "MCPOAuthTrustedKey",
    "oauth_reference",
]

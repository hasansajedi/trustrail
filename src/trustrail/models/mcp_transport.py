"""Typed contracts for fail-closed MCP transport validation."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal
from urllib.parse import SplitResult, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_REFERENCE_PATTERN = r"^sha256:[0-9a-f]{64}$"
_PROTOCOL_VERSION_PATTERN = r"^\d{4}-\d{2}-\d{2}$"
_CAPABILITY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(tz=UTC)


def transport_reference(value: str | bytes) -> str:
    """Return a content-free SHA-256 reference for transport evidence."""
    raw = value.encode() if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def canonical_host(value: str) -> str:
    """Return a strict ASCII hostname or canonical IP address.

    Ambiguous numeric forms, Unicode lookalikes, userinfo, percent encoding,
    zone identifiers, and delimiter smuggling are rejected.
    """
    if not value or value != value.strip() or len(value) > 253:
        raise ValueError("host must be non-empty canonical text")
    if any(ord(character) > 127 or ord(character) < 33 for character in value):
        raise ValueError("host must contain printable ASCII only")
    if any(character in value for character in "/\\@%#?,"):
        raise ValueError("host contains a forbidden delimiter")
    normalized = value.casefold().removesuffix(".")
    if not normalized:
        raise ValueError("host must not be the DNS root")
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        labels = normalized.split(".")
        if any(
            not label
            or len(label) > 63
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
            for label in labels
        ):
            raise ValueError("host is not a canonical DNS name") from None
        if normalized == "localhost" or all(
            re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", label) for label in labels
        ):
            raise ValueError("host uses an ambiguous local or numeric form") from None
        return normalized
    if "%" in normalized:
        raise ValueError("scoped IP addresses are not supported")
    return address.compressed


def _canonical_uri_host(parsed: SplitResult) -> str:
    """Reject authority forms that URL and HTTP parsers can interpret differently."""
    raw_host = parsed.hostname or ""
    authority = f"[{raw_host}]" if ":" in raw_host else raw_host
    if parsed.netloc.casefold() not in {authority, f"{authority}:443"}:
        raise ValueError("URI authority must use a canonical host and optional :443")
    return canonical_host(raw_host)


def canonical_endpoint_uri(value: str) -> str:
    """Canonicalize one HTTPS endpoint without credentials, query, or fragment."""
    if not value or value != value.strip() or any(not 33 <= ord(char) <= 126 for char in value):
        raise ValueError("endpoint URI must be non-empty canonical text")
    parsed = urlsplit(value)
    if (
        parsed.scheme.casefold() != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(char in value for char in "?#")
    ):
        raise ValueError("remote MCP endpoints must be credential-free HTTPS URIs")
    host = _canonical_uri_host(parsed)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("endpoint URI contains an invalid port") from None
    if port is not None and port != 443:
        raise ValueError("remote MCP endpoints must use the HTTPS default port")
    if "%" in parsed.path or "\\" in parsed.path or "//" in parsed.path:
        raise ValueError("endpoint path must not contain ambiguous encoding or separators")
    path = parsed.path or "/"
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise ValueError("endpoint path must be normalized")
    authority = f"[{host}]" if ":" in host else host
    return f"https://{authority}{path}"


def canonical_origin(value: str) -> str:
    """Canonicalize one HTTPS web origin."""
    if not value or value != value.strip() or any(not 33 <= ord(char) <= 126 for char in value):
        raise ValueError("origin must be non-empty canonical text")
    parsed = urlsplit(value)
    if (
        parsed.scheme.casefold() != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or any(char in value for char in "?#")
    ):
        raise ValueError("origins must be credential-free HTTPS origins")
    host = _canonical_uri_host(parsed)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("origin contains an invalid port") from None
    if port is not None and port != 443:
        raise ValueError("origins must use the HTTPS default port")
    authority = f"[{host}]" if ":" in host else host
    return f"https://{authority}"


class MCPTransportKind(StrEnum):
    """Transport boundary being authorized."""

    STREAMABLE_HTTP = "streamable_http"
    STDIO = "stdio"


class MCPTLSVersion(StrEnum):
    """Accepted modern TLS versions."""

    TLS_1_2 = "TLSv1.2"
    TLS_1_3 = "TLSv1.3"


class MCPTransportCode(StrEnum):
    """Stable machine-readable transport decisions."""

    ALLOWED = "allowed"
    ENDPOINT_DENIED = "endpoint_denied"
    TLS_REQUIRED = "tls_required"
    PEER_AUTH_REQUIRED = "peer_auth_required"
    HOST_DENIED = "host_denied"
    ORIGIN_DENIED = "origin_denied"
    DNS_RESOLUTION_INVALID = "dns_resolution_invalid"
    PRIVATE_ADDRESS_DENIED = "private_address_denied"
    PEER_ADDRESS_MISMATCH = "peer_address_mismatch"
    FORWARDED_HEADER_DENIED = "forwarded_header_denied"
    FORWARDED_HEADER_INVALID = "forwarded_header_invalid"
    PROTOCOL_VERSION_DENIED = "protocol_version_denied"
    PROTOCOL_DOWNGRADE = "protocol_downgrade"
    CAPABILITY_DENIED = "capability_denied"
    CAPABILITY_NEGOTIATION_INVALID = "capability_negotiation_invalid"
    CONTENT_TYPE_DENIED = "content_type_denied"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    HEADER_LIMIT_EXCEEDED = "header_limit_exceeded"
    REDIRECT_DENIED = "redirect_denied"
    TIMEOUT_POLICY_DENIED = "timeout_policy_denied"
    CONNECTION_LIMIT_EXCEEDED = "connection_limit_exceeded"
    STDIO_ENVIRONMENT_DENIED = "stdio_environment_denied"
    STDIO_EXECUTABLE_DENIED = "stdio_executable_denied"
    STDIO_CONTROL_REQUIRED = "stdio_control_required"


class MCPDNSResolution(BaseModel):
    """Resolution evidence captured immediately around connection establishment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str = Field(min_length=1, max_length=253)
    resolved_addresses: tuple[str, ...] = Field(min_length=1, max_length=100)
    connected_address: str = Field(min_length=2, max_length=64)
    revalidated_addresses: tuple[str, ...] = Field(default_factory=tuple, max_length=100)
    resolver_authenticated: bool = False


class MCPForwardedHeaders(BaseModel):
    """Already separated forwarding values from an explicitly configured proxy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    for_chain: tuple[str, ...] = Field(min_length=1, max_length=20)
    host: str = Field(min_length=1, max_length=300)
    proto: str = Field(min_length=1, max_length=20)


class MCPProtocolNegotiation(BaseModel):
    """Complete protocol-version and capability handshake evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    client_versions: frozenset[str] = Field(min_length=1, max_length=100)
    server_versions: frozenset[str] = Field(min_length=1, max_length=100)
    negotiated_version: str = Field(min_length=1, max_length=32)
    client_capabilities: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    server_capabilities: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    negotiated_capabilities: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    used_capabilities: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)


class MCPHTTPRuntimeControls(BaseModel):
    """Effective connection configuration and current bounded counters."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    certificate_validation: bool = True
    hostname_validation: bool = True
    redirects_enabled: bool = False
    connect_timeout_seconds: float = Field(gt=0, le=3_600)
    read_timeout_seconds: float = Field(gt=0, le=86_400)
    idle_timeout_seconds: float = Field(gt=0, le=86_400)
    max_connection_lifetime_seconds: float = Field(gt=0, le=604_800)
    configured_max_payload_bytes: int = Field(ge=1, le=100_000_000)
    configured_max_header_bytes: int = Field(ge=1, le=1_000_000)
    configured_max_headers: int = Field(ge=1, le=10_000)
    configured_max_connections: int = Field(ge=1, le=1_000_000)
    configured_max_connections_per_peer: int = Field(ge=1, le=1_000_000)
    active_connections: int = Field(ge=0, le=1_000_000)
    active_connections_for_peer: int = Field(ge=0, le=1_000_000)


class MCPHTTPTransportPolicy(BaseModel):
    """Closed remote HTTP endpoint, negotiation, and resource policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    allowed_endpoint_uris: frozenset[str] = Field(min_length=1, max_length=100)
    allowed_hosts: frozenset[str] = Field(min_length=1, max_length=100)
    allowed_origins: frozenset[str] = Field(min_length=1, max_length=100)
    allowed_peer_ids: frozenset[str] = Field(min_length=1, max_length=1_000)
    allowed_protocol_versions: frozenset[str] = Field(min_length=1, max_length=100)
    minimum_protocol_version: str = Field(pattern=_PROTOCOL_VERSION_PATTERN)
    allowed_capabilities: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    required_capabilities: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    allowed_content_types: frozenset[str] = Field(
        default_factory=lambda: frozenset({"application/json", "text/event-stream"}),
        min_length=1,
    )
    trusted_proxy_networks: tuple[str, ...] = Field(default_factory=tuple, max_length=100)
    max_forwarded_hops: int = Field(default=1, ge=1, le=20)
    allow_non_global_addresses: bool = False
    require_authenticated_dns: bool = False
    max_payload_bytes: int = Field(default=1_048_576, ge=1_024, le=100_000_000)
    max_header_bytes: int = Field(default=32_768, ge=1_024, le=1_000_000)
    max_headers: int = Field(default=100, ge=1, le=10_000)
    max_redirects: Literal[0] = 0
    max_connect_timeout_seconds: float = Field(default=10, gt=0, le=3_600)
    max_read_timeout_seconds: float = Field(default=30, gt=0, le=86_400)
    max_idle_timeout_seconds: float = Field(default=60, gt=0, le=86_400)
    max_connection_lifetime_seconds: float = Field(default=300, gt=0, le=604_800)
    max_connections: int = Field(default=100, ge=1, le=1_000_000)
    max_connections_per_peer: int = Field(default=10, ge=1, le=1_000_000)
    authorization_ttl_seconds: int = Field(default=60, ge=1, le=3_600)

    @field_validator("allowed_endpoint_uris")
    @classmethod
    def normalize_endpoints(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(canonical_endpoint_uri(value) for value in values)

    @field_validator("allowed_hosts")
    @classmethod
    def normalize_hosts(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(canonical_host(value) for value in values)

    @field_validator("allowed_origins")
    @classmethod
    def normalize_origins(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(canonical_origin(value) for value in values)

    @field_validator("allowed_protocol_versions")
    @classmethod
    def validate_versions(cls, values: frozenset[str]) -> frozenset[str]:
        try:
            for value in values:
                if re.fullmatch(_PROTOCOL_VERSION_PATTERN, value) is None:
                    raise ValueError
                date.fromisoformat(value)
        except ValueError:
            raise ValueError("protocol versions must use valid YYYY-MM-DD dates") from None
        return values

    @field_validator("allowed_peer_ids")
    @classmethod
    def validate_peer_ids(cls, values: frozenset[str]) -> frozenset[str]:
        if any(re.fullmatch(_IDENTIFIER_PATTERN, value) is None for value in values):
            raise ValueError("peer identities contain an unsupported identifier")
        return values

    @field_validator("allowed_capabilities", "required_capabilities")
    @classmethod
    def validate_capabilities(cls, values: frozenset[str]) -> frozenset[str]:
        if any(re.fullmatch(_CAPABILITY_PATTERN, value) is None for value in values):
            raise ValueError("capabilities contain an unsupported identifier")
        return values

    @field_validator("allowed_content_types")
    @classmethod
    def normalize_content_types(cls, values: frozenset[str]) -> frozenset[str]:
        normalized = frozenset(value.casefold().strip() for value in values)
        if any(
            re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", value) is None
            for value in normalized
        ):
            raise ValueError("content types must be exact media types")
        return normalized

    @field_validator("trusted_proxy_networks")
    @classmethod
    def validate_proxy_networks(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(str(ipaddress.ip_network(value, strict=True)) for value in values)

    @model_validator(mode="after")
    def validate_policy(self) -> MCPHTTPTransportPolicy:
        endpoint_hosts = {
            canonical_host(urlsplit(endpoint).hostname or "")
            for endpoint in self.allowed_endpoint_uris
        }
        if not endpoint_hosts.issubset(self.allowed_hosts):
            raise ValueError("every endpoint host must be present in allowed_hosts")
        if self.minimum_protocol_version not in self.allowed_protocol_versions:
            raise ValueError("minimum_protocol_version must be explicitly allowed")
        if not self.required_capabilities.issubset(self.allowed_capabilities):
            raise ValueError("required_capabilities must be allowed")
        if self.max_connections_per_peer > self.max_connections:
            raise ValueError("per-peer connection limit cannot exceed the global limit")
        return self


class MCPStdioTransportPolicy(BaseModel):
    """Closed policy for controlled local stdio processes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    allowed_environments: frozenset[str] = Field(min_length=1, max_length=100)
    allowed_executables: frozenset[str] = Field(min_length=1, max_length=100)
    require_isolation: bool = True
    forbid_inherited_network: bool = True
    authorization_ttl_seconds: int = Field(default=60, ge=1, le=3_600)

    @field_validator("allowed_environments")
    @classmethod
    def validate_environments(cls, values: frozenset[str]) -> frozenset[str]:
        if any(re.fullmatch(_IDENTIFIER_PATTERN, value) is None for value in values):
            raise ValueError("stdio environments contain an unsupported identifier")
        return values

    @field_validator("allowed_executables")
    @classmethod
    def validate_executables(cls, values: frozenset[str]) -> frozenset[str]:
        for value in values:
            path = PurePosixPath(value)
            if (
                not value
                or "\x00" in value
                or "\\" in value
                or not path.is_absolute()
                or str(path) != value
                or any(part in {"", ".", ".."} for part in path.parts[1:])
            ):
                raise ValueError("stdio executables must be normalized absolute paths")
        return values


class MCPHTTPTransportRequest(BaseModel):
    """Untrusted HTTP connection metadata captured before body parsing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    server_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    endpoint_uri: str = Field(min_length=1, max_length=2_048)
    host_header: str = Field(min_length=1, max_length=300)
    origin_header: str = Field(min_length=1, max_length=2_048)
    socket_peer_ip: str = Field(min_length=2, max_length=64)
    tls_version: MCPTLSVersion | None = None
    authenticated_peer_id: str | None = Field(default=None, max_length=256)
    dns: MCPDNSResolution
    forwarded: MCPForwardedHeaders | None = None
    negotiation: MCPProtocolNegotiation
    content_type: str = Field(min_length=1, max_length=256)
    content_length: int | None = Field(default=None, ge=0, le=1_000_000_000)
    received_body_bytes: int = Field(ge=0, le=1_000_000_000)
    header_count: int = Field(ge=0, le=100_000)
    header_bytes: int = Field(ge=0, le=100_000_000)
    redirect_count: int = Field(default=0, ge=0, le=1_000)
    runtime: MCPHTTPRuntimeControls


class MCPStdioTransportRequest(BaseModel):
    """Local stdio launch evidence captured outside model-controlled state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    server_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    environment: str = Field(min_length=1, max_length=256)
    executable: str = Field(min_length=1, max_length=2_048)
    local_control_attestation_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    isolated: bool
    inherits_network: bool


class MCPTransportFinding(BaseModel):
    """Content-free explanation of one transport decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: MCPTransportCode
    severity: Severity
    message: str = Field(min_length=1, max_length=500)
    fields: tuple[str, ...] = ()


class MCPTransportAuditEvent(BaseModel):
    """Metadata-only transport evidence safe for centralized logging."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    occurred_at: datetime
    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    code: MCPTransportCode
    kind: MCPTransportKind
    request_ref: str = Field(pattern=_REFERENCE_PATTERN)
    server_ref: str = Field(pattern=_REFERENCE_PATTERN)
    endpoint_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    peer_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)

    @field_validator("occurred_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        return value


class MCPTransportAuthorization(BaseModel):
    """Short-lived proof that a transport boundary passed policy checks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: MCPTransportKind
    request_ref: str = Field(pattern=_REFERENCE_PATTERN)
    server_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    endpoint_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    peer_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    protocol_version: str | None = Field(default=None, pattern=_PROTOCOL_VERSION_PATTERN)
    capabilities: frozenset[str] = Field(default_factory=frozenset)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authorization timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_lifetime(self) -> MCPTransportAuthorization:
        if self.expires_at <= self.issued_at:
            raise ValueError("authorization must expire after issuance")
        return self


class MCPTransportResult(BaseModel):
    """Fail-closed transport result returned before MCP message processing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    findings: tuple[MCPTransportFinding, ...] = ()
    authorization: MCPTransportAuthorization | None = None
    audit_event: MCPTransportAuditEvent

    @property
    def is_allowed(self) -> bool:
        """Return whether the request may proceed to MCP message parsing."""
        return self.action == GuardAction.ALLOW and self.authorization is not None

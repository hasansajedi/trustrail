"""Fail-closed MCP HTTP transport and protocol negotiation controls."""

from __future__ import annotations

import ipaddress
import re
import threading
from collections import deque
from datetime import date, datetime, timedelta
from typing import Literal, Protocol
from urllib.parse import urlsplit

from trustrail.exceptions import MCPTransportError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.mcp_transport import (
    MCPHTTPTransportPolicy,
    MCPHTTPTransportRequest,
    MCPStdioTransportPolicy,
    MCPStdioTransportRequest,
    MCPTransportAuditEvent,
    MCPTransportAuthorization,
    MCPTransportCode,
    MCPTransportFinding,
    MCPTransportKind,
    MCPTransportResult,
    canonical_endpoint_uri,
    canonical_host,
    canonical_origin,
    transport_reference,
    utcnow,
)

_PROTOCOL_VERSION_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CAPABILITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
# Conservative exclusions for special-purpose allocations classified differently
# across supported Python patch versions. Reviewed private deployments may opt in.
_SPECIAL_ADDRESS_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.0.0/24", "64:ff9b:1::/48", "2001::/23", "2002::/16", "3fff::/20")
)


class MCPTransportAuditSink(Protocol):
    """Persist content-free MCP transport decisions."""

    def emit(self, event: MCPTransportAuditEvent) -> None:
        """Persist one transport decision."""
        ...


class MemoryMCPTransportAuditSink:
    """Thread-safe bounded transport audit sink for tests and development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[MCPTransportAuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def emit(self, event: MCPTransportAuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> list[MCPTransportAuditEvent]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if "%" in value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return _is_public_address(address.ipv4_mapped)
    if not address.is_global or address.is_multicast or address.is_reserved:
        return False
    return not any(address in network for network in _SPECIAL_ADDRESS_NETWORKS)


def _valid_protocol_version(value: str) -> bool:
    if _PROTOCOL_VERSION_RE.fullmatch(value) is None:
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _canonical_host_header(value: str) -> str | None:
    if not value or value != value.strip() or "," in value or any(char.isspace() for char in value):
        return None
    raw_host = value
    port: str | None = None
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0:
            return None
        raw_host = value[1:closing]
        if not isinstance(_parse_ip(raw_host), ipaddress.IPv6Address):
            return None
        remainder = value[closing + 1 :]
        if remainder:
            if not remainder.startswith(":"):
                return None
            port = remainder[1:]
    elif value.count(":") == 1:
        raw_host, port = value.rsplit(":", 1)
    elif value.count(":") > 1:
        return None
    if port is not None and port != "443":
        return None
    try:
        return canonical_host(raw_host)
    except ValueError:
        return None


def _content_type(value: str) -> str | None:
    if "," in value or "\r" in value or "\n" in value:
        return None
    media_type, separator, parameters = value.partition(";")
    media_type = media_type.casefold().strip()
    if not media_type or (separator and not parameters.strip()):
        return None
    if parameters:
        entries = [entry.strip().casefold() for entry in parameters.split(";")]
        if len(entries) != 1 or entries[0] not in {"charset=utf-8", 'charset="utf-8"'}:
            return None
    return media_type


class MCPTransportGuard:
    """Validate an MCP connection before reading or parsing its message body.

    The caller must capture socket, DNS, TLS, proxy, and runtime values from
    trusted networking infrastructure rather than request-controlled payloads.
    """

    def __init__(
        self,
        *,
        http_policy: MCPHTTPTransportPolicy | None = None,
        stdio_policy: MCPStdioTransportPolicy | None = None,
        audit_sink: MCPTransportAuditSink | None = None,
    ) -> None:
        if http_policy is None and stdio_policy is None:
            raise ValueError("at least one MCP transport policy is required")
        if (
            http_policy is not None
            and stdio_policy is not None
            and http_policy.server_id != stdio_policy.server_id
        ):
            raise ValueError("HTTP and stdio policies must protect the same server")
        self._http_policy = None if http_policy is None else http_policy.model_copy(deep=True)
        self._stdio_policy = None if stdio_policy is None else stdio_policy.model_copy(deep=True)
        self._audit_sink = audit_sink

    @property
    def http_policy(self) -> MCPHTTPTransportPolicy | None:
        return None if self._http_policy is None else self._http_policy.model_copy(deep=True)

    @property
    def stdio_policy(self) -> MCPStdioTransportPolicy | None:
        return None if self._stdio_policy is None else self._stdio_policy.model_copy(deep=True)

    def validate_http(
        self,
        request: MCPHTTPTransportRequest,
        *,
        now: datetime | None = None,
    ) -> MCPTransportResult:
        """Authorize one remote streamable-HTTP connection and handshake."""
        current_time = now or utcnow()
        policy = self._http_policy
        findings: list[MCPTransportFinding] = []
        if policy is None or request.server_id != policy.server_id:
            findings.append(
                self._finding(
                    MCPTransportCode.ENDPOINT_DENIED,
                    "No remote HTTP policy authorizes this MCP server",
                    "server_id",
                )
            )
            return self._http_result(request, findings, current_time)

        endpoint: str | None
        try:
            endpoint = canonical_endpoint_uri(request.endpoint_uri)
        except ValueError:
            endpoint = None
        if endpoint is None or endpoint not in policy.allowed_endpoint_uris:
            findings.append(
                self._finding(
                    MCPTransportCode.ENDPOINT_DENIED,
                    "Remote endpoint is malformed or outside the canonical allow-list",
                    "endpoint_uri",
                )
            )
        endpoint_host = None if endpoint is None else urlsplit(endpoint).hostname

        if request.tls_version is None or not (
            request.runtime.certificate_validation and request.runtime.hostname_validation
        ):
            findings.append(
                self._finding(
                    MCPTransportCode.TLS_REQUIRED,
                    "Remote MCP HTTP requires validated TLS and hostname verification",
                    "tls_version",
                    "runtime.certificate_validation",
                    "runtime.hostname_validation",
                )
            )
        if (
            request.authenticated_peer_id is None
            or request.authenticated_peer_id not in policy.allowed_peer_ids
        ):
            findings.append(
                self._finding(
                    MCPTransportCode.PEER_AUTH_REQUIRED,
                    "Remote MCP peer identity is missing or not approved",
                    "authenticated_peer_id",
                )
            )

        host = _canonical_host_header(request.host_header)
        if host is None or host not in policy.allowed_hosts or host != endpoint_host:
            findings.append(
                self._finding(
                    MCPTransportCode.HOST_DENIED,
                    "HTTP Host is malformed or outside its independent allow-list",
                    "host_header",
                )
            )
        try:
            origin = canonical_origin(request.origin_header)
        except ValueError:
            origin = None
        if origin is None or origin not in policy.allowed_origins:
            findings.append(
                self._finding(
                    MCPTransportCode.ORIGIN_DENIED,
                    "HTTP Origin is malformed or outside its independent allow-list",
                    "origin_header",
                )
            )

        self._append_dns_findings(request, policy, endpoint_host, findings)
        self._append_proxy_findings(request, policy, findings)
        self._append_negotiation_findings(request, policy, findings)
        self._append_resource_findings(request, policy, findings)
        return self._http_result(request, findings, current_time)

    def require_http(
        self,
        request: MCPHTTPTransportRequest,
        *,
        now: datetime | None = None,
    ) -> MCPTransportAuthorization:
        """Return HTTP authorization or raise before message processing."""
        result = self.validate_http(request, now=now)
        if result.authorization is None:
            raise MCPTransportError(result)
        return result.authorization

    def validate_stdio(
        self,
        request: MCPStdioTransportRequest,
        *,
        now: datetime | None = None,
    ) -> MCPTransportResult:
        """Authorize one declared, controlled-local stdio process."""
        current_time = now or utcnow()
        policy = self._stdio_policy
        findings: list[MCPTransportFinding] = []
        if policy is None or request.server_id != policy.server_id:
            findings.append(
                self._finding(
                    MCPTransportCode.STDIO_ENVIRONMENT_DENIED,
                    "No stdio policy authorizes this MCP server",
                    "server_id",
                )
            )
            return self._stdio_result(request, findings, current_time)
        if request.environment not in policy.allowed_environments:
            findings.append(
                self._finding(
                    MCPTransportCode.STDIO_ENVIRONMENT_DENIED,
                    "Stdio environment is not declared as controlled local infrastructure",
                    "environment",
                )
            )
        if request.executable not in policy.allowed_executables:
            findings.append(
                self._finding(
                    MCPTransportCode.STDIO_EXECUTABLE_DENIED,
                    "Stdio executable is outside the exact allow-list",
                    "executable",
                )
            )
        if (
            request.local_control_attestation_ref is None
            or (policy.require_isolation and not request.isolated)
            or (policy.forbid_inherited_network and request.inherits_network)
        ):
            findings.append(
                self._finding(
                    MCPTransportCode.STDIO_CONTROL_REQUIRED,
                    "Stdio requires trusted local-control evidence and configured isolation",
                    "local_control_attestation_ref",
                    "isolated",
                    "inherits_network",
                )
            )
        return self._stdio_result(request, findings, current_time)

    def require_stdio(
        self,
        request: MCPStdioTransportRequest,
        *,
        now: datetime | None = None,
    ) -> MCPTransportAuthorization:
        """Return stdio authorization or raise before starting the process."""
        result = self.validate_stdio(request, now=now)
        if result.authorization is None:
            raise MCPTransportError(result)
        return result.authorization

    def _append_dns_findings(
        self,
        request: MCPHTTPTransportRequest,
        policy: MCPHTTPTransportPolicy,
        endpoint_host: str | None,
        findings: list[MCPTransportFinding],
    ) -> None:
        dns = request.dns
        try:
            dns_host = canonical_host(dns.hostname)
        except ValueError:
            dns_host = None
        addresses = tuple(_parse_ip(value) for value in dns.resolved_addresses)
        revalidated = tuple(_parse_ip(value) for value in dns.revalidated_addresses)
        connected = _parse_ip(dns.connected_address)
        socket_peer = _parse_ip(request.socket_peer_ip)
        if (
            dns_host is None
            or dns_host != endpoint_host
            or any(address is None for address in addresses)
            or any(address is None for address in revalidated)
            or not revalidated
            or connected is None
            or (policy.require_authenticated_dns and not dns.resolver_authenticated)
        ):
            findings.append(
                self._finding(
                    MCPTransportCode.DNS_RESOLUTION_INVALID,
                    "DNS evidence is malformed, unauthenticated, or bound to another host",
                    "dns",
                )
            )
        all_addresses = tuple(address for address in (*addresses, *revalidated) if address)
        if not policy.allow_non_global_addresses and any(
            not _is_public_address(address) for address in all_addresses
        ):
            findings.append(
                self._finding(
                    MCPTransportCode.PRIVATE_ADDRESS_DENIED,
                    "DNS resolution reached a loopback, link-local, private, or reserved address",
                    "dns.resolved_addresses",
                    "dns.revalidated_addresses",
                )
            )
        resolved_set = {address for address in addresses if address is not None}
        revalidated_set = {address for address in revalidated if address is not None}
        endpoint_address = _parse_ip(endpoint_host or "")
        if (
            connected is None
            or (endpoint_address is not None and connected != endpoint_address)
            or connected not in resolved_set
            or (revalidated_set and connected not in revalidated_set)
            or socket_peer is None
            or (request.forwarded is None and socket_peer != connected)
        ):
            findings.append(
                self._finding(
                    MCPTransportCode.PEER_ADDRESS_MISMATCH,
                    "Connected peer is not pinned to both approved DNS observations",
                    "socket_peer_ip",
                    "dns.connected_address",
                )
            )

    def _append_proxy_findings(
        self,
        request: MCPHTTPTransportRequest,
        policy: MCPHTTPTransportPolicy,
        findings: list[MCPTransportFinding],
    ) -> None:
        forwarded = request.forwarded
        if forwarded is None:
            return
        socket_peer = _parse_ip(request.socket_peer_ip)
        networks = tuple(ipaddress.ip_network(value) for value in policy.trusted_proxy_networks)
        if socket_peer is None or not any(socket_peer in network for network in networks):
            findings.append(
                self._finding(
                    MCPTransportCode.FORWARDED_HEADER_DENIED,
                    "Forwarding metadata was supplied by an untrusted socket peer",
                    "forwarded",
                    "socket_peer_ip",
                )
            )
            return
        chain = tuple(_parse_ip(value) for value in forwarded.for_chain)
        forwarded_host = _canonical_host_header(forwarded.host)
        malformed = (
            len(chain) > policy.max_forwarded_hops
            or any(address is None for address in chain)
            or forwarded_host is None
            or forwarded_host not in policy.allowed_hosts
            or forwarded_host != _canonical_host_header(request.host_header)
            or forwarded.proto.casefold() != "https"
        )
        valid_chain = tuple(address for address in chain if address is not None)
        if len(valid_chain) > 1 and any(
            not any(address in network for network in networks) for address in valid_chain[1:]
        ):
            malformed = True
        if (
            valid_chain
            and not policy.allow_non_global_addresses
            and not _is_public_address(valid_chain[0])
        ):
            malformed = True
        if malformed:
            findings.append(
                self._finding(
                    MCPTransportCode.FORWARDED_HEADER_INVALID,
                    "Trusted-proxy metadata is malformed, downgraded, or exceeds the hop policy",
                    "forwarded",
                )
            )

    def _append_negotiation_findings(
        self,
        request: MCPHTTPTransportRequest,
        policy: MCPHTTPTransportPolicy,
        findings: list[MCPTransportFinding],
    ) -> None:
        negotiation = request.negotiation
        versions = (*negotiation.client_versions, *negotiation.server_versions)
        common = (
            negotiation.client_versions
            & negotiation.server_versions
            & policy.allowed_protocol_versions
        )
        malformed_version = any(not _valid_protocol_version(value) for value in versions)
        if (
            malformed_version
            or negotiation.negotiated_version not in common
            or negotiation.negotiated_version < policy.minimum_protocol_version
        ):
            findings.append(
                self._finding(
                    MCPTransportCode.PROTOCOL_VERSION_DENIED,
                    "Negotiated MCP protocol version is unsupported or below the minimum",
                    "negotiation",
                )
            )
        elif common and negotiation.negotiated_version != max(common):
            findings.append(
                self._finding(
                    MCPTransportCode.PROTOCOL_DOWNGRADE,
                    "Negotiation selected an older mutually supported MCP protocol version",
                    "negotiation.negotiated_version",
                )
            )
        capability_values = (
            *negotiation.client_capabilities,
            *negotiation.server_capabilities,
            *negotiation.negotiated_capabilities,
            *negotiation.used_capabilities,
        )
        advertised = negotiation.client_capabilities | negotiation.server_capabilities
        if (
            any(_CAPABILITY_RE.fullmatch(value) is None for value in capability_values)
            or not negotiation.negotiated_capabilities.issubset(advertised)
            or not negotiation.used_capabilities.issubset(negotiation.negotiated_capabilities)
        ):
            findings.append(
                self._finding(
                    MCPTransportCode.CAPABILITY_NEGOTIATION_INVALID,
                    "Capabilities must be advertised, negotiated, and used in that order",
                    "negotiation",
                )
            )
        if not negotiation.negotiated_capabilities.issubset(
            policy.allowed_capabilities
        ) or not policy.required_capabilities.issubset(negotiation.negotiated_capabilities):
            findings.append(
                self._finding(
                    MCPTransportCode.CAPABILITY_DENIED,
                    "Negotiated capabilities violate the closed capability policy",
                    "negotiation.negotiated_capabilities",
                )
            )

    def _append_resource_findings(
        self,
        request: MCPHTTPTransportRequest,
        policy: MCPHTTPTransportPolicy,
        findings: list[MCPTransportFinding],
    ) -> None:
        media_type = _content_type(request.content_type)
        if media_type is None or media_type not in policy.allowed_content_types:
            findings.append(
                self._finding(
                    MCPTransportCode.CONTENT_TYPE_DENIED,
                    "Content-Type is malformed or outside the exact media-type policy",
                    "content_type",
                )
            )
        runtime = request.runtime
        payload_limit = min(policy.max_payload_bytes, runtime.configured_max_payload_bytes)
        if (
            runtime.configured_max_payload_bytes > policy.max_payload_bytes
            or request.received_body_bytes > payload_limit
            or (
                request.content_length is not None
                and (
                    request.content_length > payload_limit
                    or request.received_body_bytes > request.content_length
                )
            )
        ):
            findings.append(
                self._finding(
                    MCPTransportCode.PAYLOAD_TOO_LARGE,
                    "Payload configuration, declarations, and observations must be bounded",
                    "content_length",
                    "received_body_bytes",
                )
            )
        if (
            runtime.configured_max_headers > policy.max_headers
            or runtime.configured_max_header_bytes > policy.max_header_bytes
            or request.header_count > min(policy.max_headers, runtime.configured_max_headers)
            or request.header_bytes
            > min(policy.max_header_bytes, runtime.configured_max_header_bytes)
        ):
            findings.append(
                self._finding(
                    MCPTransportCode.HEADER_LIMIT_EXCEEDED,
                    "HTTP header count or byte size exceeds policy",
                    "header_count",
                    "header_bytes",
                )
            )
        if request.redirect_count > policy.max_redirects or (
            runtime.redirects_enabled and policy.max_redirects == 0
        ):
            findings.append(
                self._finding(
                    MCPTransportCode.REDIRECT_DENIED,
                    "Redirect behavior exceeds the explicit transport policy",
                    "redirect_count",
                    "runtime.redirects_enabled",
                )
            )
        if (
            runtime.connect_timeout_seconds > policy.max_connect_timeout_seconds
            or runtime.read_timeout_seconds > policy.max_read_timeout_seconds
            or runtime.idle_timeout_seconds > policy.max_idle_timeout_seconds
            or runtime.max_connection_lifetime_seconds > policy.max_connection_lifetime_seconds
        ):
            findings.append(
                self._finding(
                    MCPTransportCode.TIMEOUT_POLICY_DENIED,
                    "Configured connection timeouts exceed policy ceilings",
                    "runtime",
                )
            )
        if (
            runtime.configured_max_connections > policy.max_connections
            or runtime.configured_max_connections_per_peer > policy.max_connections_per_peer
            or runtime.active_connections
            >= min(policy.max_connections, runtime.configured_max_connections)
            or runtime.active_connections_for_peer
            >= min(policy.max_connections_per_peer, runtime.configured_max_connections_per_peer)
        ):
            findings.append(
                self._finding(
                    MCPTransportCode.CONNECTION_LIMIT_EXCEEDED,
                    "Configured or active connection counts exceed policy",
                    "runtime",
                )
            )

    def _http_result(
        self,
        request: MCPHTTPTransportRequest,
        findings: list[MCPTransportFinding],
        now: datetime,
    ) -> MCPTransportResult:
        policy = self._http_policy
        action: Literal[GuardAction.ALLOW, GuardAction.BLOCK] = (
            GuardAction.BLOCK if findings else GuardAction.ALLOW
        )
        authorization = None
        if not findings and policy is not None:
            authorization = MCPTransportAuthorization(
                kind=MCPTransportKind.STREAMABLE_HTTP,
                request_ref=transport_reference(request.request_id),
                server_id=request.server_id,
                endpoint_ref=transport_reference(request.endpoint_uri),
                peer_ref=transport_reference(
                    request.authenticated_peer_id or request.socket_peer_ip
                ),
                protocol_version=request.negotiation.negotiated_version,
                capabilities=request.negotiation.negotiated_capabilities,
                issued_at=now,
                expires_at=now + timedelta(seconds=policy.authorization_ttl_seconds),
            )
        result = MCPTransportResult(
            action=action,
            findings=tuple(findings),
            authorization=authorization,
            audit_event=MCPTransportAuditEvent(
                occurred_at=now,
                action=action,
                code=findings[0].code if findings else MCPTransportCode.ALLOWED,
                kind=MCPTransportKind.STREAMABLE_HTTP,
                request_ref=transport_reference(request.request_id),
                server_ref=transport_reference(request.server_id),
                endpoint_ref=transport_reference(request.endpoint_uri),
                peer_ref=transport_reference(
                    request.authenticated_peer_id or request.socket_peer_ip
                ),
            ),
        )
        self._emit(result.audit_event)
        return result

    def _stdio_result(
        self,
        request: MCPStdioTransportRequest,
        findings: list[MCPTransportFinding],
        now: datetime,
    ) -> MCPTransportResult:
        policy = self._stdio_policy
        action: Literal[GuardAction.ALLOW, GuardAction.BLOCK] = (
            GuardAction.BLOCK if findings else GuardAction.ALLOW
        )
        authorization = None
        if not findings and policy is not None:
            authorization = MCPTransportAuthorization(
                kind=MCPTransportKind.STDIO,
                request_ref=transport_reference(request.request_id),
                server_id=request.server_id,
                endpoint_ref=transport_reference(request.executable),
                issued_at=now,
                expires_at=now + timedelta(seconds=policy.authorization_ttl_seconds),
            )
        result = MCPTransportResult(
            action=action,
            findings=tuple(findings),
            authorization=authorization,
            audit_event=MCPTransportAuditEvent(
                occurred_at=now,
                action=action,
                code=findings[0].code if findings else MCPTransportCode.ALLOWED,
                kind=MCPTransportKind.STDIO,
                request_ref=transport_reference(request.request_id),
                server_ref=transport_reference(request.server_id),
                endpoint_ref=transport_reference(request.executable),
            ),
        )
        self._emit(result.audit_event)
        return result

    def _emit(self, event: MCPTransportAuditEvent) -> None:
        if self._audit_sink is not None:
            self._audit_sink.emit(event)

    @staticmethod
    def _finding(
        code: MCPTransportCode,
        message: str,
        *fields: str,
    ) -> MCPTransportFinding:
        severity = (
            Severity.CRITICAL if code != MCPTransportCode.HEADER_LIMIT_EXCEEDED else Severity.HIGH
        )
        return MCPTransportFinding(code=code, severity=severity, message=message, fields=fields)

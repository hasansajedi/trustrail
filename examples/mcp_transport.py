"""Authorize an MCP HTTP transport before parsing a JSON-RPC message."""

from __future__ import annotations

from trustrail import (
    MCPDNSResolution,
    MCPHTTPRuntimeControls,
    MCPHTTPTransportPolicy,
    MCPHTTPTransportRequest,
    MCPProtocolNegotiation,
    MCPTLSVersion,
    MCPTransportGuard,
    MemoryMCPTransportAuditSink,
)

# Keep this policy in application-owned configuration. Endpoint, origin, peer,
# version, and capability values must never come from model output.
policy = MCPHTTPTransportPolicy(
    server_id="search-production",
    allowed_endpoint_uris=frozenset({"https://mcp.example.com/mcp"}),
    allowed_hosts=frozenset({"mcp.example.com"}),
    allowed_origins=frozenset({"https://console.example.com"}),
    allowed_peer_ids=frozenset({"spiffe://example.com/mcp/search-production"}),
    allowed_protocol_versions=frozenset({"2025-06-18"}),
    minimum_protocol_version="2025-06-18",
    allowed_capabilities=frozenset({"tools", "resources"}),
    required_capabilities=frozenset({"tools"}),
    max_payload_bytes=1_048_576,
    max_connect_timeout_seconds=10,
    max_read_timeout_seconds=30,
    max_connections=100,
    max_connections_per_peer=10,
)
audit = MemoryMCPTransportAuditSink()
guard = MCPTransportGuard(http_policy=policy, audit_sink=audit)

# Build this request only from the TLS socket, trusted resolver, HTTP server,
# and protocol implementation. The example uses inert values and makes no
# network connection.
address = "93.184.216.34"
request = MCPHTTPTransportRequest(
    request_id="request-90",
    server_id="search-production",
    endpoint_uri="https://mcp.example.com/mcp",
    host_header="mcp.example.com",
    origin_header="https://console.example.com",
    socket_peer_ip=address,
    tls_version=MCPTLSVersion.TLS_1_3,
    authenticated_peer_id="spiffe://example.com/mcp/search-production",
    dns=MCPDNSResolution(
        hostname="mcp.example.com",
        resolved_addresses=(address,),
        connected_address=address,
        revalidated_addresses=(address,),
        resolver_authenticated=True,
    ),
    negotiation=MCPProtocolNegotiation(
        client_versions=frozenset({"2025-06-18"}),
        server_versions=frozenset({"2025-06-18"}),
        negotiated_version="2025-06-18",
        client_capabilities=frozenset({"tools"}),
        server_capabilities=frozenset({"tools", "resources"}),
        negotiated_capabilities=frozenset({"tools", "resources"}),
        used_capabilities=frozenset({"tools"}),
    ),
    content_type="application/json; charset=utf-8",
    content_length=128,
    received_body_bytes=128,
    header_count=12,
    header_bytes=1_024,
    runtime=MCPHTTPRuntimeControls(
        certificate_validation=True,
        hostname_validation=True,
        redirects_enabled=False,
        connect_timeout_seconds=5,
        read_timeout_seconds=20,
        idle_timeout_seconds=30,
        max_connection_lifetime_seconds=120,
        configured_max_payload_bytes=1_048_576,
        configured_max_header_bytes=32_768,
        configured_max_headers=100,
        configured_max_connections=50,
        configured_max_connections_per_peer=5,
        active_connections=4,
        active_connections_for_peer=1,
    ),
)

# Only pass bytes to the JSON-RPC parser after this succeeds.
authorization = guard.require_http(request)
print(authorization.protocol_version)
print(audit.events[-1].code)

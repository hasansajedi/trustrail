"""Integration coverage for transport admission before MCP message verification."""

from __future__ import annotations

from datetime import UTC, datetime

from trustrail import (
    MCPDNSResolution,
    MCPHTTPRuntimeControls,
    MCPHTTPTransportPolicy,
    MCPHTTPTransportRequest,
    MCPMessageSigner,
    MCPMessageType,
    MCPMessageVerificationContext,
    MCPMessageVerifier,
    MCPProtocolNegotiation,
    MCPTLSVersion,
    MCPTransportError,
    MCPTransportGuard,
)

NOW = datetime(2026, 9, 12, 14, tzinfo=UTC)
PEER_ID = "spiffe://example.com/mcp/inventory"
ADDRESS = "93.184.216.34"


def _transport_request(*, origin: str = "https://console.example.com"):
    return MCPHTTPTransportRequest(
        request_id="inventory-request-1",
        server_id="inventory",
        endpoint_uri="https://mcp.example.com/mcp",
        host_header="mcp.example.com",
        origin_header=origin,
        socket_peer_ip=ADDRESS,
        tls_version=MCPTLSVersion.TLS_1_3,
        authenticated_peer_id=PEER_ID,
        dns=MCPDNSResolution(
            hostname="mcp.example.com",
            resolved_addresses=(ADDRESS,),
            connected_address=ADDRESS,
            revalidated_addresses=(ADDRESS,),
        ),
        negotiation=MCPProtocolNegotiation(
            client_versions=frozenset({"2025-06-18"}),
            server_versions=frozenset({"2025-06-18"}),
            negotiated_version="2025-06-18",
            client_capabilities=frozenset({"tools"}),
            server_capabilities=frozenset({"tools"}),
            negotiated_capabilities=frozenset({"tools"}),
            used_capabilities=frozenset({"tools"}),
        ),
        content_type="application/json",
        content_length=80,
        received_body_bytes=80,
        header_count=10,
        header_bytes=900,
        runtime=MCPHTTPRuntimeControls(
            connect_timeout_seconds=5,
            read_timeout_seconds=20,
            idle_timeout_seconds=30,
            max_connection_lifetime_seconds=120,
            configured_max_payload_bytes=1_048_576,
            configured_max_header_bytes=32_768,
            configured_max_headers=100,
            configured_max_connections=20,
            configured_max_connections_per_peer=4,
            active_connections=2,
            active_connections_for_peer=1,
        ),
    )


def _guard():
    return MCPTransportGuard(
        http_policy=MCPHTTPTransportPolicy(
            server_id="inventory",
            allowed_endpoint_uris=frozenset({"https://mcp.example.com/mcp"}),
            allowed_hosts=frozenset({"mcp.example.com"}),
            allowed_origins=frozenset({"https://console.example.com"}),
            allowed_peer_ids=frozenset({PEER_ID}),
            allowed_protocol_versions=frozenset({"2025-06-18"}),
            minimum_protocol_version="2025-06-18",
            allowed_capabilities=frozenset({"tools"}),
            required_capabilities=frozenset({"tools"}),
        )
    )


def test_transport_is_authorized_before_signed_message_processing():
    transport = _guard().require_http(_transport_request(), now=NOW)
    signer = MCPMessageSigner.generate(sender_id="inventory-client")
    verifier = MCPMessageVerifier((signer.trusted_key,))
    definition_digest = "a" * 64
    envelope = signer.sign(
        {"jsonrpc": "2.0", "id": "1", "method": "tools/list"},
        message_type=MCPMessageType.REQUEST,
        recipient_id="inventory",
        user_id="user-7",
        agent_id="agent-7",
        session_id="session-7",
        tool_definition_digest=definition_digest,
        now=NOW,
    )
    payload = verifier.require_verified(
        envelope,
        MCPMessageVerificationContext(
            message_type=MCPMessageType.REQUEST,
            sender_id="inventory-client",
            recipient_id="inventory",
            user_id="user-7",
            agent_id="agent-7",
            session_id="session-7",
            tool_definition_digest=definition_digest,
        ),
        now=NOW,
    )

    assert transport.protocol_version == "2025-06-18"
    assert payload["method"] == "tools/list"


def test_denied_origin_never_reaches_message_processing():
    processed: list[str] = []
    try:
        _guard().require_http(_transport_request(origin="https://evil.example"), now=NOW)
        processed.append("parsed")
    except MCPTransportError:
        pass

    assert processed == []

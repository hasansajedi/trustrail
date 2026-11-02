"""Bypass-oriented security corpus for MCP transport validation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from trustrail import (
    MCPDNSResolution,
    MCPForwardedHeaders,
    MCPHTTPRuntimeControls,
    MCPHTTPTransportPolicy,
    MCPHTTPTransportRequest,
    MCPProtocolNegotiation,
    MCPTLSVersion,
    MCPTransportCode,
    MCPTransportGuard,
)

CASES: list[dict[str, str]] = json.loads(
    (Path(__file__).parent.parent / "security_corpus" / "mcp_transport.json").read_text()
)
NOW = datetime(2026, 9, 12, 15, tzinfo=UTC)
PUBLIC_IP = "93.184.216.34"


def _guard():
    return MCPTransportGuard(
        http_policy=MCPHTTPTransportPolicy(
            server_id="corpus-server",
            allowed_endpoint_uris=frozenset({"https://mcp.example.com/mcp"}),
            allowed_hosts=frozenset({"mcp.example.com"}),
            allowed_origins=frozenset({"https://app.example.com"}),
            allowed_peer_ids=frozenset({"corpus-peer"}),
            allowed_protocol_versions=frozenset({"2025-03-26", "2025-06-18"}),
            minimum_protocol_version="2025-03-26",
            allowed_capabilities=frozenset({"tools"}),
            required_capabilities=frozenset({"tools"}),
        )
    )


def _request(case: dict[str, str]):
    value = case["value"]
    host = value if case["mutation"] == "host" else "mcp.example.com"
    origin = value if case["mutation"] == "origin" else "https://app.example.com"
    dns_host = value if case["mutation"] == "dns-host" else "mcp.example.com"
    revalidated = value if case["mutation"] == "revalidated-address" else PUBLIC_IP
    forwarded = None
    if case["mutation"] == "forwarded":
        forwarded = MCPForwardedHeaders(for_chain=("8.8.8.8",), host=value, proto="https")
    negotiated_version = value if case["mutation"] == "version" else "2025-06-18"
    negotiated_capabilities = frozenset({"tools"})
    if case["mutation"] == "capability":
        negotiated_capabilities = frozenset({"tools", value})
    body_bytes = int(value) if case["mutation"] == "body-bytes" else 64
    content_type = value if case["mutation"] == "content-type" else "application/json"
    redirect_count = int(value) if case["mutation"] == "redirect" else 0
    return MCPHTTPTransportRequest(
        request_id=f"corpus-{case['id']}",
        server_id="corpus-server",
        endpoint_uri="https://mcp.example.com/mcp",
        host_header=host,
        origin_header=origin,
        socket_peer_ip=PUBLIC_IP,
        tls_version=MCPTLSVersion.TLS_1_3,
        authenticated_peer_id="corpus-peer",
        dns=MCPDNSResolution(
            hostname=dns_host,
            resolved_addresses=(PUBLIC_IP,),
            connected_address=PUBLIC_IP,
            revalidated_addresses=(revalidated,),
        ),
        forwarded=forwarded,
        negotiation=MCPProtocolNegotiation(
            client_versions=frozenset({"2025-03-26", "2025-06-18"}),
            server_versions=frozenset({"2025-03-26", "2025-06-18"}),
            negotiated_version=negotiated_version,
            client_capabilities=frozenset({"tools"}),
            server_capabilities=frozenset({"tools"}),
            negotiated_capabilities=negotiated_capabilities,
            used_capabilities=negotiated_capabilities,
        ),
        content_type=content_type,
        content_length=body_bytes,
        received_body_bytes=body_bytes,
        header_count=10,
        header_bytes=1_000,
        redirect_count=redirect_count,
        runtime=MCPHTTPRuntimeControls(
            connect_timeout_seconds=5,
            read_timeout_seconds=20,
            idle_timeout_seconds=30,
            max_connection_lifetime_seconds=120,
            configured_max_payload_bytes=1_048_576,
            configured_max_header_bytes=32_768,
            configured_max_headers=100,
            configured_max_connections=20,
            configured_max_connections_per_peer=5,
            active_connections=2,
            active_connections_for_peer=1,
        ),
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_transport_bypass_corpus_is_blocked_without_echoing_payload(case):
    result = _guard().validate_http(_request(case), now=NOW)

    assert result.is_allowed is False
    assert MCPTransportCode(case["expected_code"]) in {finding.code for finding in result.findings}
    if not case["value"].isdigit():
        assert case["value"] not in result.model_dump_json()

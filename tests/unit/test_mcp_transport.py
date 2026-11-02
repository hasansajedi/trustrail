"""Unit coverage for MCP transport and protocol admission."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from trustrail import (
    GuardAction,
    MCPDNSResolution,
    MCPForwardedHeaders,
    MCPHTTPRuntimeControls,
    MCPHTTPTransportPolicy,
    MCPHTTPTransportRequest,
    MCPProtocolNegotiation,
    MCPStdioTransportPolicy,
    MCPStdioTransportRequest,
    MCPTLSVersion,
    MCPTransportCode,
    MCPTransportError,
    MCPTransportGuard,
    MemoryMCPTransportAuditSink,
    canonical_endpoint_uri,
    canonical_host,
    canonical_origin,
    transport_reference,
)

NOW = datetime(2026, 9, 12, 12, tzinfo=UTC)
PUBLIC_IP = "93.184.216.34"


def _policy(**updates: object) -> MCPHTTPTransportPolicy:
    values: dict[str, object] = {
        "server_id": "search-server",
        "allowed_endpoint_uris": frozenset({"https://mcp.example.com/mcp"}),
        "allowed_hosts": frozenset({"mcp.example.com"}),
        "allowed_origins": frozenset({"https://app.example.com"}),
        "allowed_peer_ids": frozenset({"spiffe://example.com/mcp/search-server"}),
        "allowed_protocol_versions": frozenset({"2025-03-26", "2025-06-18"}),
        "minimum_protocol_version": "2025-03-26",
        "allowed_capabilities": frozenset({"tools", "resources"}),
        "required_capabilities": frozenset({"tools"}),
    }
    values.update(updates)
    return MCPHTTPTransportPolicy(**values)


def _request(**updates: object) -> MCPHTTPTransportRequest:
    values: dict[str, object] = {
        "request_id": "request-90",
        "server_id": "search-server",
        "endpoint_uri": "https://mcp.example.com/mcp",
        "host_header": "mcp.example.com",
        "origin_header": "https://app.example.com",
        "socket_peer_ip": PUBLIC_IP,
        "tls_version": MCPTLSVersion.TLS_1_3,
        "authenticated_peer_id": "spiffe://example.com/mcp/search-server",
        "dns": MCPDNSResolution(
            hostname="mcp.example.com",
            resolved_addresses=(PUBLIC_IP,),
            connected_address=PUBLIC_IP,
            revalidated_addresses=(PUBLIC_IP,),
            resolver_authenticated=True,
        ),
        "negotiation": MCPProtocolNegotiation(
            client_versions=frozenset({"2025-03-26", "2025-06-18"}),
            server_versions=frozenset({"2025-03-26", "2025-06-18"}),
            negotiated_version="2025-06-18",
            client_capabilities=frozenset({"tools"}),
            server_capabilities=frozenset({"tools", "resources"}),
            negotiated_capabilities=frozenset({"tools", "resources"}),
            used_capabilities=frozenset({"tools"}),
        ),
        "content_type": "application/json; charset=utf-8",
        "content_length": 128,
        "received_body_bytes": 128,
        "header_count": 12,
        "header_bytes": 1_024,
        "runtime": MCPHTTPRuntimeControls(
            connect_timeout_seconds=5,
            read_timeout_seconds=20,
            idle_timeout_seconds=30,
            max_connection_lifetime_seconds=120,
            configured_max_payload_bytes=1_048_576,
            configured_max_header_bytes=32_768,
            configured_max_headers=100,
            configured_max_connections=50,
            configured_max_connections_per_peer=5,
            active_connections=10,
            active_connections_for_peer=1,
        ),
    }
    values.update(updates)
    return MCPHTTPTransportRequest(**values)


def _codes(request: MCPHTTPTransportRequest, policy: MCPHTTPTransportPolicy | None = None):
    result = MCPTransportGuard(http_policy=policy or _policy()).validate_http(request, now=NOW)
    return result, {finding.code for finding in result.findings}


def test_http_transport_issues_short_lived_authorization_and_safe_audit():
    audit = MemoryMCPTransportAuditSink()
    result = MCPTransportGuard(http_policy=_policy(), audit_sink=audit).validate_http(
        _request(), now=NOW
    )

    assert result.action == GuardAction.ALLOW
    assert result.authorization is not None
    assert result.authorization.protocol_version == "2025-06-18"
    assert result.authorization.capabilities == frozenset({"tools", "resources"})
    assert result.authorization.request_ref == transport_reference("request-90")
    assert len(audit.events) == 1
    serialized = audit.events[0].model_dump_json()
    assert "search-server" not in serialized
    assert "mcp.example.com" not in serialized
    assert "spiffe://example.com" not in serialized


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"tls_version": None}, MCPTransportCode.TLS_REQUIRED),
        ({"authenticated_peer_id": None}, MCPTransportCode.PEER_AUTH_REQUIRED),
        ({"host_header": "evil.example"}, MCPTransportCode.HOST_DENIED),
        ({"host_header": "mcp.example.com.evil"}, MCPTransportCode.HOST_DENIED),
        ({"origin_header": "https://app.example.com.evil"}, MCPTransportCode.ORIGIN_DENIED),
        ({"origin_header": "https://app.example.com@evil.example"}, MCPTransportCode.ORIGIN_DENIED),
        (
            {"content_type": "application/json,text/event-stream"},
            MCPTransportCode.CONTENT_TYPE_DENIED,
        ),
        ({"redirect_count": 1}, MCPTransportCode.REDIRECT_DENIED),
        ({"header_count": 101}, MCPTransportCode.HEADER_LIMIT_EXCEEDED),
    ],
)
def test_http_transport_rejects_independent_boundary_failures(updates, expected):
    result, codes = _codes(_request(**updates))

    assert result.is_allowed is False
    assert expected in codes
    assert result.authorization is None


def test_dns_rebinding_private_resolution_and_peer_mismatch_are_rejected():
    dns = MCPDNSResolution(
        hostname="mcp.example.com",
        resolved_addresses=(PUBLIC_IP,),
        connected_address=PUBLIC_IP,
        revalidated_addresses=("127.0.0.1",),
        resolver_authenticated=True,
    )
    result, codes = _codes(_request(dns=dns))

    assert result.is_allowed is False
    assert MCPTransportCode.PRIVATE_ADDRESS_DENIED in codes
    assert MCPTransportCode.PEER_ADDRESS_MISMATCH in codes


def test_protocol_downgrade_and_unadvertised_capability_are_rejected():
    negotiation = MCPProtocolNegotiation(
        client_versions=frozenset({"2025-03-26", "2025-06-18"}),
        server_versions=frozenset({"2025-03-26", "2025-06-18"}),
        negotiated_version="2025-03-26",
        client_capabilities=frozenset({"tools"}),
        server_capabilities=frozenset({"resources"}),
        negotiated_capabilities=frozenset({"tools", "sampling"}),
        used_capabilities=frozenset({"sampling"}),
    )
    _, codes = _codes(_request(negotiation=negotiation))

    assert MCPTransportCode.PROTOCOL_DOWNGRADE in codes
    assert MCPTransportCode.CAPABILITY_NEGOTIATION_INVALID in codes
    assert MCPTransportCode.CAPABILITY_DENIED in codes


def test_runtime_timeout_and_connection_configuration_must_be_bounded():
    runtime = _request().runtime.model_copy(
        update={
            "read_timeout_seconds": 31,
            "configured_max_connections": 101,
            "active_connections_for_peer": 10,
        }
    )
    _, codes = _codes(_request(runtime=runtime))

    assert MCPTransportCode.TIMEOUT_POLICY_DENIED in codes
    assert MCPTransportCode.CONNECTION_LIMIT_EXCEEDED in codes


def test_forwarding_headers_are_used_only_from_an_explicit_trusted_proxy():
    forwarded = MCPForwardedHeaders(
        for_chain=("8.8.8.8",),
        host="mcp.example.com",
        proto="https",
    )
    untrusted, untrusted_codes = _codes(_request(forwarded=forwarded))
    trusted_policy = _policy(trusted_proxy_networks=("10.0.0.0/24",))
    trusted_request = _request(socket_peer_ip="10.0.0.10", forwarded=forwarded)
    trusted, trusted_codes = _codes(trusted_request, trusted_policy)

    assert untrusted.is_allowed is False
    assert MCPTransportCode.FORWARDED_HEADER_DENIED in untrusted_codes
    assert trusted.is_allowed is True
    assert trusted_codes == set()


def test_malformed_forwarded_downgrade_fails_closed():
    policy = _policy(trusted_proxy_networks=("10.0.0.0/24",))
    forwarded = MCPForwardedHeaders(
        for_chain=("127.0.0.1",),
        host="evil.example",
        proto="http",
    )
    _, codes = _codes(_request(socket_peer_ip="10.0.0.10", forwarded=forwarded), policy)

    assert MCPTransportCode.FORWARDED_HEADER_INVALID in codes


def test_stdio_requires_declared_controlled_local_environment():
    policy = MCPStdioTransportPolicy(
        server_id="search-server",
        allowed_environments=frozenset({"sandbox-prod"}),
        allowed_executables=frozenset({"/opt/mcp/search-server"}),
    )
    guard = MCPTransportGuard(stdio_policy=policy)
    allowed = MCPStdioTransportRequest(
        request_id="stdio-1",
        server_id="search-server",
        environment="sandbox-prod",
        executable="/opt/mcp/search-server",
        local_control_attestation_ref=transport_reference("sandbox-attestation"),
        isolated=True,
        inherits_network=False,
    )

    assert guard.validate_stdio(allowed, now=NOW).is_allowed
    denied = allowed.model_copy(
        update={
            "environment": "developer-laptop",
            "executable": "/var/lib/unapproved/server",
            "local_control_attestation_ref": None,
            "isolated": False,
            "inherits_network": True,
        }
    )
    result = guard.validate_stdio(denied, now=NOW)
    assert {finding.code for finding in result.findings} == {
        MCPTransportCode.STDIO_ENVIRONMENT_DENIED,
        MCPTransportCode.STDIO_EXECUTABLE_DENIED,
        MCPTransportCode.STDIO_CONTROL_REQUIRED,
    }
    with pytest.raises(MCPTransportError) as caught:
        guard.require_stdio(denied, now=NOW)
    assert caught.value.result == result


@pytest.mark.parametrize(
    ("function", "value"),
    [
        (canonical_host, "mcp.example.com@127.0.0.1"),
        (canonical_host, "2130706433"),
        (canonical_host, "0x7f.0.0.1"),
        (canonical_host, "0x7f000001"),
        (canonical_host, "mcp.example.com.."),
        (canonical_host, "mcp.ex\u0430mple.com"),  # Cyrillic 'a'.
        (canonical_endpoint_uri, "https://mcp.example.com/%2e%2e/admin"),
        (canonical_endpoint_uri, "https://user@mcp.example.com/mcp"),
        (canonical_endpoint_uri, "https://mcp.example.com:/mcp"),
        (canonical_endpoint_uri, "https://mcp.example.com:0443/mcp"),
        (canonical_endpoint_uri, "https://[v1.mcp.example.com]/mcp"),
        (canonical_endpoint_uri, "https://mcp.example.com/mcp\u007f"),
        (canonical_origin, "https://app.example.com:"),
        (canonical_origin, "https://app.example.com/path"),
    ],
)
def test_canonicalizers_reject_hostname_confusion(function, value):
    with pytest.raises(ValueError):
        function(value)


def test_policy_rejects_endpoint_host_omitted_from_host_allowlist():
    with pytest.raises(ValidationError, match="endpoint host"):
        _policy(allowed_hosts=frozenset({"other.example.com"}))


def test_canonicalization_accepts_equivalent_https_names_and_ipv6():
    assert canonical_endpoint_uri("HTTPS://MCP.EXAMPLE.COM.:443/mcp") == (
        "https://mcp.example.com/mcp"
    )
    assert canonical_origin("https://APP.EXAMPLE.COM:443/") == "https://app.example.com"
    assert canonical_endpoint_uri("https://[2606:4700:4700::1111]:443/mcp") == (
        "https://[2606:4700:4700::1111]/mcp"
    )
    assert _codes(_request(host_header="MCP.EXAMPLE.COM.:443"))[0].is_allowed


def test_stream_without_content_length_requires_bounded_runtime_and_observation():
    request = _request(content_type="text/event-stream", content_length=None)
    assert _codes(request)[0].is_allowed
    oversized = request.model_copy(update={"received_body_bytes": 1_048_577})
    assert MCPTransportCode.PAYLOAD_TOO_LARGE in _codes(oversized)[1]
    unbounded = request.model_copy(
        update={
            "runtime": request.runtime.model_copy(
                update={"configured_max_payload_bytes": 2_097_152}
            )
        }
    )
    assert MCPTransportCode.PAYLOAD_TOO_LARGE in _codes(unbounded)[1]


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"certificate_validation": False}, MCPTransportCode.TLS_REQUIRED),
        ({"hostname_validation": False}, MCPTransportCode.TLS_REQUIRED),
        ({"redirects_enabled": True}, MCPTransportCode.REDIRECT_DENIED),
        ({"configured_max_header_bytes": 32_769}, MCPTransportCode.HEADER_LIMIT_EXCEEDED),
        ({"configured_max_headers": 101}, MCPTransportCode.HEADER_LIMIT_EXCEEDED),
        ({"configured_max_payload_bytes": 1_048_577}, MCPTransportCode.PAYLOAD_TOO_LARGE),
        ({"configured_max_connections": 10}, MCPTransportCode.CONNECTION_LIMIT_EXCEEDED),
        ({"configured_max_connections_per_peer": 1}, MCPTransportCode.CONNECTION_LIMIT_EXCEEDED),
    ],
)
def test_effective_runtime_controls_cannot_exceed_policy_or_admit_exhausted_pools(
    updates, expected
):
    runtime = _request().runtime.model_copy(update=updates)
    result, codes = _codes(_request(runtime=runtime))
    assert not result.is_allowed
    assert expected in codes


def test_ip_literal_endpoint_must_connect_to_the_exact_literal():
    policy = _policy(
        allowed_endpoint_uris=frozenset({"https://8.8.8.8/mcp"}),
        allowed_hosts=frozenset({"8.8.8.8"}),
    )
    request = _request(
        endpoint_uri="https://8.8.8.8/mcp",
        host_header="8.8.8.8",
        dns=_request().dns.model_copy(update={"hostname": "8.8.8.8"}),
    )
    assert MCPTransportCode.PEER_ADDRESS_MISMATCH in _codes(request, policy)[1]
    pinned = request.model_copy(
        update={
            "socket_peer_ip": "8.8.8.8",
            "dns": MCPDNSResolution(
                hostname="8.8.8.8",
                resolved_addresses=("8.8.8.8",),
                revalidated_addresses=("8.8.8.8",),
                connected_address="8.8.8.8",
            ),
        }
    )
    assert _codes(pinned, policy)[0].is_allowed


def test_missing_dns_revalidation_and_required_authentication_fail_closed():
    dns = _request().dns.model_copy(
        update={"revalidated_addresses": (), "resolver_authenticated": False}
    )
    assert (
        MCPTransportCode.DNS_RESOLUTION_INVALID
        in _codes(_request(dns=dns), _policy(require_authenticated_dns=True))[1]
    )


def test_host_cannot_switch_to_another_allowed_endpoint():
    policy = _policy(allowed_hosts=frozenset({"mcp.example.com", "other.example.com"}))
    assert (
        MCPTransportCode.HOST_DENIED in _codes(_request(host_header="other.example.com"), policy)[1]
    )


def test_redirect_policy_cannot_enable_unvalidated_intermediate_hops():
    with pytest.raises(ValidationError):
        _policy(max_redirects=1)


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"negotiated_version": "2024-11-05"}, MCPTransportCode.PROTOCOL_VERSION_DENIED),
        (
            {"client_versions": frozenset({"2025-06-18", "2025-99-99"})},
            MCPTransportCode.PROTOCOL_VERSION_DENIED,
        ),
        (
            {"used_capabilities": frozenset({"sampling"})},
            MCPTransportCode.CAPABILITY_NEGOTIATION_INVALID,
        ),
        ({"negotiated_capabilities": frozenset()}, MCPTransportCode.CAPABILITY_DENIED),
    ],
)
def test_invalid_handshake_never_issues_an_authorization(updates, expected):
    negotiation = _request().negotiation.model_copy(update=updates)
    request = _request(negotiation=negotiation)
    result, codes = _codes(request)
    assert expected in codes
    assert result.authorization is None
    with pytest.raises(MCPTransportError):
        MCPTransportGuard(http_policy=_policy()).require_http(request, now=NOW)


@pytest.mark.parametrize(
    ("chain", "host", "proto"),
    [
        (("8.8.8.8", "10.0.0.11", "10.0.0.12"), "mcp.example.com", "https"),
        (("8.8.8.8", "9.9.9.9"), "mcp.example.com", "https"),
        (("8.8.8.8,127.0.0.1",), "mcp.example.com", "https"),
        (("8.8.8.8",), "other.example.com", "https"),
        (("8.8.8.8",), "mcp.example.com", "https,http"),
    ],
)
def test_trusted_proxy_rejects_ambiguous_and_untrusted_forwarding_hops(chain, host, proto):
    policy = _policy(
        trusted_proxy_networks=("10.0.0.0/24",),
        allowed_hosts=frozenset({"mcp.example.com", "other.example.com"}),
        max_forwarded_hops=2,
    )
    forwarded = MCPForwardedHeaders(for_chain=chain, host=host, proto=proto)
    result, codes = _codes(_request(socket_peer_ip="10.0.0.10", forwarded=forwarded), policy)
    assert not result.is_allowed
    assert MCPTransportCode.FORWARDED_HEADER_INVALID in codes


def test_explicit_private_deployment_opt_in_preserves_other_controls():
    dns = MCPDNSResolution(
        hostname="mcp.example.com",
        resolved_addresses=("10.0.0.8",),
        connected_address="10.0.0.8",
        revalidated_addresses=("10.0.0.8",),
    )
    request = _request(dns=dns, socket_peer_ip="10.0.0.8")
    assert MCPTransportCode.PRIVATE_ADDRESS_DENIED in _codes(request)[1]
    policy = _policy(allow_non_global_addresses=True)
    assert _codes(request, policy)[0].is_allowed
    assert not _codes(request.model_copy(update={"tls_version": None}), policy)[0].is_allowed

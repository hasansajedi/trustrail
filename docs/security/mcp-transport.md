# MCP HTTP transport security

`MCPTransportGuard` validates network evidence and established handshake state
before application message parsing or dispatch. It addresses
[OWASP AISVS C10](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C10-MCP-Security.md)
transport risks beyond server onboarding, OAuth, and message signatures:

- exact, independently evaluated endpoint, `Host`, and `Origin` allow-lists;
- strict ASCII hostname and HTTPS URI canonicalization;
- public-address DNS resolution, connection pinning, and post-connect
  revalidation against rebinding, loopback, link-local, private, reserved,
  multicast, numeric-host, userinfo, and hostname-confusion bypasses;
- validated TLS plus an application-authenticated peer identity;
- explicit trusted-proxy networks, bounded forwarding hops, and fail-closed
  forwarded host/protocol/client parsing;
- highest-mutually-supported MCP version selection and closed capability
  negotiation;
- exact content types, consistent payload length, header limits, redirect
  policy, timeout ceilings, and global/per-peer connection limits; and
- stdio restricted to declared local environments, exact executables,
  isolation evidence, and network inheritance policy.

## Remote HTTP workflow

Define a closed policy in trusted application configuration:

```python
from trustrail import MCPHTTPTransportPolicy, MCPTransportGuard

policy = MCPHTTPTransportPolicy(
    server_id="search-production",
    allowed_endpoint_uris=frozenset({"https://mcp.example.com/mcp"}),
    allowed_hosts=frozenset({"mcp.example.com"}),
    allowed_origins=frozenset({"https://console.example.com"}),
    allowed_peer_ids=frozenset(
        {"spiffe://example.com/mcp/search-production"}
    ),
    allowed_protocol_versions=frozenset({"2025-06-18"}),
    minimum_protocol_version="2025-06-18",
    allowed_capabilities=frozenset({"tools", "resources"}),
    required_capabilities=frozenset({"tools"}),
    max_payload_bytes=1_048_576,
    max_connections=100,
    max_connections_per_peer=10,
)
guard = MCPTransportGuard(http_policy=policy)
```

Capture `MCPHTTPTransportRequest` fields from trusted infrastructure. In
particular, use the socket peer address, TLS session, authenticated workload or
client identity, resolver results, parsed HTTP metadata, protocol handshake,
and the effective runtime configuration. Do not copy these values from JSON-RPC
parameters, model output, query parameters, or an untrusted forwarding header.

```python
authorization = guard.require_http(request)
# Only now read/parse/dispatch the MCP message.
payload = parse_bounded_json_body()
```

For a new session, the networking layer must first enforce endpoint, TLS,
authentication, Host, Origin, and resource limits while a bounded initialization
parser obtains version and capability evidence. Supply that verified handshake
state to this guard before dispatching application messages. The guard does not
bootstrap or parse the MCP initialization handshake itself.

`validate_http()` returns every content-free finding for policy diagnostics.
`require_http()` raises `MCPTransportError` on any finding and returns a
short-lived, request-bound `MCPTransportAuthorization` on success. Treat that
object as in-process control flow; do not accept one deserialized from a client.

The runnable
[`examples/mcp_transport.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/mcp_transport.py)
constructs the complete request without making a network call.

## DNS and connection pinning

Populate `MCPDNSResolution.resolved_addresses` immediately before connecting,
connect only to one of those addresses, and put the actual connected address in
both `connected_address` and `socket_peer_ip`. Re-resolve around connection
establishment and provide non-empty `revalidated_addresses`; the connected
address must be in both observations. Every observed address must be public
unicast by default. Scoped IPv6 addresses are rejected. Special-purpose ranges
are conservatively denied across Python versions, including IPv6 transition
ranges. For IP-literal endpoints, the connected address must equal that literal.

`allow_non_global_addresses=True` is an explicit escape hatch for reviewed
private deployments. It permits non-global addresses; it does not decide which
private service is safe. Keep endpoint and host allow-lists exact and enforce
network egress separately.

If DNS authenticity is part of the deployment guarantee, set
`require_authenticated_dns=True` and supply resolver evidence through
`resolver_authenticated`. Trustrail consumes that assertion; it does not
perform DNSSEC validation or open sockets itself.

## Trusted proxies

Forwarded metadata is rejected unless the direct socket peer belongs to
`trusted_proxy_networks`. When it is accepted, the guard still checks the
ordinary `Host` and `Origin` independently, requires Host to match the endpoint,
and separately validates the forwarded host, HTTPS protocol, client address,
proxy hops, and hop count. Forwarded Host must also match the ordinary Host.

Configure the edge proxy to overwrite—not append client-supplied—forwarding
headers and pass already separated values in `MCPForwardedHeaders`. Do not set
`trusted_proxy_networks` merely because a header is present. Private socket
peers can be exact trusted proxies; forwarded client and endpoint addresses
remain subject to the global-address policy.

## Protocol and resource policy

The guard requires the negotiated version to be in the client offer, server
offer, exact allow-list, and minimum-version policy. When several allowed
versions overlap it requires the newest one, blocking silent downgrade. A
capability must be advertised before negotiation and negotiated before use;
required capabilities cannot disappear and unapproved capabilities cannot be
added.

Validate the effective HTTP client/server settings through
`MCPHTTPRuntimeControls`. Application and proxy limits must also stop reading
once `max_payload_bytes`, header, timeout, or connection limits are reached.
Provide the effective byte and header ceilings in
`configured_max_payload_bytes`, `configured_max_header_bytes`, and
`configured_max_headers`; they must not exceed policy. Connection counts are
measured before reserving a new slot and must be below both configured and
policy limits. Reserve slots atomically outside the guard.

Bounded streams may omit `Content-Length`, as supported by
[MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports).
The infrastructure must count received bytes and enforce the configured ceiling
throughout the stream, independently of the declared length. If a length is
present, observed bytes cannot exceed it; the HTTP stack must also reject
truncation when the body completes. Redirects must remain disabled:
`max_redirects` accepts only zero because this API cannot authenticate and pin
every intermediate hop.

The guard validates trusted observations and configuration—it is not itself an
HTTP server, streaming byte counter, socket limiter, TLS terminator, or proxy.

## Controlled stdio

Stdio is not a remote fallback. Declare the environment and executable, obtain
local-control evidence outside model state, and enforce process isolation:

```python
from trustrail import MCPStdioTransportPolicy, MCPTransportGuard

guard = MCPTransportGuard(
    stdio_policy=MCPStdioTransportPolicy(
        server_id="filesystem-production",
        allowed_environments=frozenset({"sandbox-prod"}),
        allowed_executables=frozenset({"/opt/mcp/filesystem"}),
        require_isolation=True,
        forbid_inherited_network=True,
    )
)
authorization = guard.require_stdio(request)
```

The attestation reference is an opaque evidence binding. Trustrail does not
authenticate or enforce the sandbox represented by that reference; create the
request only after trusted deployment infrastructure verifies it.

## Assumptions and residual risk

- Networking metadata and runtime counters are trustworthy only if captured
  outside attacker- and model-controlled state. Enforce the returned decision
  before parsing any message bytes.
- TLS certificate validation does not authenticate an MCP workload by itself.
  Derive `authenticated_peer_id` from mTLS, workload identity, or an equivalent
  authenticated channel and rotate/revoke that identity externally.
- This control does not implement TLS, DNSSEC, HTTP parsing, proxy sanitation,
  bandwidth/rate limiting, socket quotas, or network egress. Those controls
  must enforce the declared policy at the infrastructure boundary.
- A DNS name can change ownership while still resolving globally. Maintain the
  allow-list, identity binding, certificate policy, and incident monitoring.
- Payload length and byte-limit configuration are trusted evidence. The HTTP
  stack must reject conflicting framing and stop chunked/streamed input at the
  byte ceiling before buffering.
- Combine this guard with server onboarding, OAuth/resource authorization,
  message signing/replay defense, tool-definition integrity, output checks,
  and multi-server isolation as applicable. Transport authorization alone does
  not make a tool call safe.

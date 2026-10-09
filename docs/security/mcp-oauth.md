# MCP OAuth resource-server authorization

`MCPOAuthResourceServer` implements the application-layer resource-server
controls needed to keep an MCP server from becoming a confused deputy. It
validates a compact signed JWT access token for every `tools/list` and
`tools/call` request, then applies tool and argument-level authorization before
anything is exposed to a model or dispatched.

This control is designed for OWASP AISVS C10 and the authentication and
authorization guidance in the OWASP MCP Security Cheat Sheet. It complements,
but does not replace, MCP transport authentication, message integrity, tool
definition pinning, server isolation, or downstream service authorization.

## Enforced token profile

The verifier accepts only compact JWS access tokens with `typ=at+jwt` and a
pinned `EdDSA` key. The token must contain all of these claims:

- `iss`, exactly matching the configured issuer;
- `aud`, containing only the MCP service audience;
- `resource`, containing only the MCP resource indicator;
- `exp`, `nbf`, and `iat`, within configured age, lifetime, and clock-skew
  bounds;
- a unique `jti` for atomic single-use replay prevention;
- `client_id`, `sub`, `user_id`, `tenant_id`, and `mcp_server_id`, matching
  independently authenticated request context;
- `mcp_request_id`, binding the token to exactly one MCP request;
- `scope`, restricted to the resource server's allowlist; and
- `resource_ids`, restricted to resources declared by tool policy.

Unknown fields, missing fields, duplicate JSON members, padded or malformed
base64url, unpinned keys, algorithm substitution, multi-audience tokens,
multi-resource tokens, and authorization expansion all fail closed. Tokens are
intentionally request-bound and single-use; issue a different token for
`tools/list` and each `tools/call`.

## Configure the resource server

Provision the public key through authenticated configuration. Do not accept a
key embedded in the token or discover a token-selected `jku`, `jwk`, or `x5u`.

```python
from trustrail import (
    MCPOAuthPolicy,
    MCPOAuthResourceServer,
    MCPOAuthToolPolicy,
    MCPOAuthTrustedKey,
)

policy = MCPOAuthPolicy(
    issuer="https://identity.example.com",
    audience="mcp://records-server",
    resource="https://mcp.example.com/records",
    server_id="records-server",
    allowed_scopes=frozenset(
        {"mcp:tools:list", "records:read", "records:delete"}
    ),
    tool_policies=(
        MCPOAuthToolPolicy(
            tool_name="records.search",
            required_scopes=frozenset({"records:read"}),
            allowed_resource_ids=frozenset({"project-1", "project-2"}),
            resource_argument_pointers=("/project_id",),
        ),
    ),
    max_token_ttl_seconds=300,
    max_token_age_seconds=300,
    clock_skew_seconds=30,
)

resource_server = MCPOAuthResourceServer(
    policy,
    (
        MCPOAuthTrustedKey(
            issuer=policy.issuer,
            key_id="issuer-key-2026-10",
            public_key=load_pinned_ed25519_public_key(),
        ),
    ),
    replay_store=shared_replay_store,
    audit_sink=durable_audit_sink,
)
```

`resource_argument_pointers` are non-root JSON pointers into tool arguments.
Each referenced value must be one string identifier authorized by both the
token and the tool policy. Arrays and wildcard paths are intentionally not
interpreted; model them as separate explicit checks in application code.

## Filter `tools/list`

Build request context from authenticated transport/session state, never from
token claims or model-controlled arguments.

```python
from trustrail import MCPOAuthOperation, MCPOAuthRequestContext

context = MCPOAuthRequestContext(
    operation=MCPOAuthOperation.TOOLS_LIST,
    server_id=authenticated_server_id,
    tenant_id=authenticated_tenant_id,
    user_id=authenticated_user_id,
    subject_id=authenticated_subject_id,
    client_id=authenticated_client_id,
    request_id=json_rpc_request_id,
)

visible_tools = resource_server.require_tools_list(
    bearer_token,
    context,
    approved_tool_definitions,
)
```

Unknown tools, tools from another server, tools missing required scopes, and
resource-bound tools with no authorized resource intersection are omitted. The
returned definitions are defensive copies. Continue to use
`MCPToolDefinitionGuard` to authenticate and pin the definitions themselves.

## Authorize `tools/call`

Use a new request-bound token and context for the call. Dispatch only the exact
definition and arguments that were authorized.

```python
call_context = context.model_copy(
    update={
        "operation": MCPOAuthOperation.TOOLS_CALL,
        "request_id": call_request_id,
    }
)

authorization = resource_server.require_tool_call(
    call_bearer_token,
    call_context,
    approved_definition,
    {"project_id": "project-1", "query": "quarterly report"},
)
```

The resulting `AuthorizedMCPOAuthRequest` is immutable and records effective
scopes, resources, exact tool identity, request identity, expiry, and only
one-way token/JTI references. The raw token is never included. Supplying the
caller token anywhere in nested tool arguments is rejected as passthrough.

## Downstream credentials

Do not send the MCP client token to a tool or downstream API. Use
`MCPOAuthDownstreamBroker` with either:

- `TOKEN_EXCHANGE`, where a trusted authorization-server adapter exchanges the
  exact verified subject token for a new audience/resource-bound credential; or
- `WORKLOAD_IDENTITY`, where trusted infrastructure obtains a credential owned
  by the MCP workload without receiving the caller token.

The broker rejects scope expansion, the wrong subject token, caller tokens in
the workload flow, discovery-only authorization, a downstream resource ID that
does not match an authorized tool argument, and a provider that returns the
original caller token. Raw
credentials remain wrapped in `CredentialMaterial`; reveal them only inside the
trusted connector and close them immediately after use.

## Security assumptions and residual risk

- Authenticate client, user, subject, tenant, server, and request identity
  independently of the token. Comparing one attacker-controlled claim with
  another provides no security.
- Use a shared, durable, atomic `MCPOAuthReplayStore` across every worker and
  region. The included memory store is process-local, bounded, and loses claims
  on restart.
- Protect and rotate issuer private keys, provision public keys out of band,
  distribute revocation promptly, synchronize clocks, and rate-limit before
  expensive signature verification.
- The built-in profile supports Ed25519 (`EdDSA`) only. It does not fetch JWKS,
  validate opaque tokens, perform token introspection, or implement an OAuth
  authorization server.
- Single-use bearer tokens reduce replay but are not proof-of-possession. A
  stolen unused token can still be used first. Prefer mutually authenticated
  transport and sender-constrained tokens at the identity layer.
- Argument checks cover configured exact JSON pointers and string resource IDs.
  Business invariants, ownership changes, transaction limits, indirect object
  references, and semantic authorization still require authoritative
  application checks and downstream enforcement.
- Token exchange adapters and workload identity providers are trusted code.
  Isolate them from model context, logs, tracing, exceptions, and untrusted
  connectors; restrict network egress and monitor issuance.
- Audit events contain only hashes and control metadata. Store them durably,
  protect them from tampering, and correlate them with identity-provider and
  downstream-service logs during incident response.

See also [MCP message integrity](mcp-message-integrity.md),
[MCP tool-definition integrity](mcp-tool-integrity.md),
[MCP server isolation](mcp-server-isolation.md), and
[model-blind credential brokering](credential-brokering.md).

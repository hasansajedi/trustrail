"""Authorize MCP discovery, a tool call, and safe downstream credentials."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from trustrail import (
    CredentialMaterial,
    MCPOAuthDownstreamBroker,
    MCPOAuthDownstreamMode,
    MCPOAuthDownstreamRequest,
    MCPOAuthOperation,
    MCPOAuthPolicy,
    MCPOAuthRequestContext,
    MCPOAuthResourceServer,
    MCPOAuthToolPolicy,
    MCPOAuthTrustedKey,
    MCPToolDefinition,
    MemoryMCPOAuthAuditSink,
)

ISSUER = "https://identity.example.com"
AUDIENCE = "mcp://billing-server"
RESOURCE = "https://mcp.example.com/billing"


def encode_segment(value: object) -> str:
    """Encode canonical-enough demo JWT data without adding padding."""
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def issue_demo_token(
    key: Ed25519PrivateKey,
    *,
    now: datetime,
    request_id: str,
    jti: str,
    scopes: tuple[str, ...],
) -> str:
    """Stand in for a protected authorization server, not application code."""
    header = encode_segment({"alg": "EdDSA", "kid": "billing-key", "typ": "at+jwt"})
    claims = encode_segment(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "resource": RESOURCE,
            "exp": int((now + timedelta(minutes=2)).timestamp()),
            "nbf": int((now - timedelta(seconds=1)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": jti,
            "client_id": "trusted-mcp-client",
            "sub": "workload-7",
            "user_id": "user-7",
            "tenant_id": "tenant-7",
            "mcp_server_id": "billing-server",
            "mcp_request_id": request_id,
            "scope": " ".join(scopes),
            "resource_ids": ["account-7"],
        }
    )
    signing_input = f"{header}.{claims}".encode()
    signature = base64.urlsafe_b64encode(key.sign(signing_input)).rstrip(b"=").decode()
    return f"{header}.{claims}.{signature}"


def request_context(
    operation: MCPOAuthOperation,
    request_id: str,
) -> MCPOAuthRequestContext:
    """Build this from authenticated transport and server-side request state."""
    return MCPOAuthRequestContext(
        operation=operation,
        server_id="billing-server",
        tenant_id="tenant-7",
        user_id="user-7",
        subject_id="workload-7",
        client_id="trusted-mcp-client",
        request_id=request_id,
    )


def tool(name: str) -> MCPToolDefinition:
    return MCPToolDefinition(
        server_id="billing-server",
        name=name,
        description=f"Billing operation {name}",
        inputSchema={
            "type": "object",
            "properties": {"account_id": {"type": "string"}},
            "required": ["account_id"],
            "additionalProperties": False,
        },
    )


class WorkloadCredentialProvider:
    """Local stand-in for workload identity or a secrets broker."""

    def exchange(
        self,
        request: MCPOAuthDownstreamRequest,
        subject_token: CredentialMaterial,
    ) -> CredentialMaterial:
        del request, subject_token
        raise AssertionError("the configured workflow must not forward caller tokens")

    def workload_credential(
        self,
        request: MCPOAuthDownstreamRequest,
    ) -> CredentialMaterial:
        if request.resource_id != "account-7":
            raise RuntimeError("unexpected downstream resource")
        return CredentialMaterial("example-workload-credential")


now = datetime.now(tz=UTC)
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
policy = MCPOAuthPolicy(
    issuer=ISSUER,
    audience=AUDIENCE,
    resource=RESOURCE,
    server_id="billing-server",
    allowed_scopes=frozenset({"mcp:tools:list", "invoice:read", "invoice:refund"}),
    tool_policies=(
        MCPOAuthToolPolicy(
            tool_name="invoice.read",
            required_scopes=frozenset({"invoice:read"}),
            allowed_resource_ids=frozenset({"account-7"}),
            resource_argument_pointers=("/account_id",),
        ),
        MCPOAuthToolPolicy(
            tool_name="invoice.refund",
            required_scopes=frozenset({"invoice:refund"}),
            allowed_resource_ids=frozenset({"account-7"}),
            resource_argument_pointers=("/account_id",),
        ),
    ),
)
audit = MemoryMCPOAuthAuditSink()
server = MCPOAuthResourceServer(
    policy,
    (
        MCPOAuthTrustedKey(
            issuer=ISSUER,
            key_id="billing-key",
            public_key=public_key,
        ),
    ),
    audit_sink=audit,
)

# Discovery uses its own request-bound, single-use token. Only invoice.read is
# returned because the token does not carry invoice:refund.
list_token = issue_demo_token(
    private_key,
    now=now,
    request_id="list-request",
    jti="list-token-unique-id",
    scopes=("mcp:tools:list", "invoice:read"),
)
visible = server.require_tools_list(
    list_token,
    request_context(MCPOAuthOperation.TOOLS_LIST, "list-request"),
    (tool("invoice.read"), tool("invoice.refund")),
    now=now,
)
print("Visible tools:", [item.name for item in visible])

# The call needs a new token bound to this request, tool scope, and account.
call_token = issue_demo_token(
    private_key,
    now=now,
    request_id="call-request",
    jti="call-token-unique-id",
    scopes=("invoice:read",),
)
authorization = server.require_tool_call(
    call_token,
    request_context(MCPOAuthOperation.TOOLS_CALL, "call-request"),
    visible[0],
    {"account_id": "account-7"},
    now=now,
)

# The caller token never enters downstream arguments or headers. A trusted
# provider supplies a workload-owned credential for the authorized resource.
downstream = MCPOAuthDownstreamRequest(
    authorization=authorization,
    mode=MCPOAuthDownstreamMode.WORKLOAD_IDENTITY,
    service_id="billing-api",
    audience="https://billing.example.com",
    resource="https://billing.example.com/accounts/account-7",
    resource_id="account-7",
    scopes=frozenset({"invoice:read"}),
)
with MCPOAuthDownstreamBroker(
    WorkloadCredentialProvider(),
    audit_sink=audit,
).acquire(downstream, now=now) as credential:
    if not credential.reveal():
        raise RuntimeError("downstream credential was empty")

print("Authorized tool:", authorization.tool_name)
print("Content-free OAuth events:", len(audit.events))

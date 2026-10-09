"""End-to-end MCP OAuth discovery, call, and downstream credential workflow."""

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

NOW = datetime(2026, 10, 9, 14, tzinfo=UTC)
ISSUER = "https://identity.example.com"
AUDIENCE = "mcp://billing-server"
RESOURCE = "https://mcp.example.com/billing"


def _encode(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _issue_token(
    key: Ed25519PrivateKey,
    *,
    request_id: str,
    jti: str,
    scopes: tuple[str, ...],
) -> str:
    header = _encode({"alg": "EdDSA", "kid": "billing-key", "typ": "at+jwt"})
    claims = _encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "resource": RESOURCE,
            "exp": int((NOW + timedelta(minutes=2)).timestamp()),
            "nbf": int((NOW - timedelta(seconds=1)).timestamp()),
            "iat": int(NOW.timestamp()),
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


def _context(operation: MCPOAuthOperation, request_id: str) -> MCPOAuthRequestContext:
    return MCPOAuthRequestContext(
        operation=operation,
        server_id="billing-server",
        tenant_id="tenant-7",
        user_id="user-7",
        subject_id="workload-7",
        client_id="trusted-mcp-client",
        request_id=request_id,
    )


def _tool(name: str) -> MCPToolDefinition:
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


class _WorkloadProvider:
    def exchange(self, _request, _subject_token):
        raise AssertionError("workflow must not forward the caller token")

    def workload_credential(self, request):
        assert request.resource.endswith("/accounts/account-7")
        return CredentialMaterial("billing-workload-credential")


def test_mcp_gateway_filters_discovery_authorizes_call_and_uses_workload_identity():
    key = Ed25519PrivateKey.generate()
    public_key = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
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
        (MCPOAuthTrustedKey(issuer=ISSUER, key_id="billing-key", public_key=public_key),),
        audit_sink=audit,
    )
    list_token = _issue_token(
        key,
        request_id="list-request",
        jti="list-jti",
        scopes=("mcp:tools:list", "invoice:read"),
    )
    visible = server.require_tools_list(
        list_token,
        _context(MCPOAuthOperation.TOOLS_LIST, "list-request"),
        (_tool("invoice.read"), _tool("invoice.refund")),
        now=NOW,
    )
    assert [tool.name for tool in visible] == ["invoice.read"]

    call_token = _issue_token(
        key,
        request_id="call-request",
        jti="call-jti",
        scopes=("invoice:read",),
    )
    authorization = server.require_tool_call(
        call_token,
        _context(MCPOAuthOperation.TOOLS_CALL, "call-request"),
        visible[0],
        {"account_id": "account-7"},
        now=NOW,
    )
    downstream_request = MCPOAuthDownstreamRequest(
        authorization=authorization,
        mode=MCPOAuthDownstreamMode.WORKLOAD_IDENTITY,
        service_id="billing-api",
        audience="https://billing.example.com",
        resource="https://billing.example.com/accounts/account-7",
        resource_id="account-7",
        scopes=frozenset({"invoice:read"}),
    )
    with MCPOAuthDownstreamBroker(_WorkloadProvider(), audit_sink=audit).acquire(
        downstream_request,
        now=NOW,
    ) as credential:
        assert credential.reveal() == b"billing-workload-credential"

    assert [event.operation for event in audit.events] == [
        MCPOAuthOperation.TOOLS_LIST,
        MCPOAuthOperation.TOOLS_CALL,
        MCPOAuthOperation.DOWNSTREAM_CREDENTIAL,
    ]
    assert all(call_token not in event.model_dump_json() for event in audit.events)

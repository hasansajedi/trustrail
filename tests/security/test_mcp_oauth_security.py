"""Bypass-oriented regression corpus for MCP OAuth confused-deputy controls."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from trustrail import (
    MCPOAuthCode,
    MCPOAuthOperation,
    MCPOAuthPolicy,
    MCPOAuthRequestContext,
    MCPOAuthResourceServer,
    MCPOAuthToolPolicy,
    MCPOAuthTrustedKey,
    MCPToolDefinition,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "mcp_oauth.json"
CASES: list[dict[str, object]] = json.loads(CORPUS_PATH.read_text())
NOW = datetime(2026, 10, 9, 16, tzinfo=UTC)
ISSUER = "https://identity.example.com"
AUDIENCE = "mcp://secure-server"
RESOURCE = "https://mcp.example.com/files"


def _encode(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.mark.parametrize("case", CASES, ids=[str(case["id"]) for case in CASES])
def test_signed_confused_deputy_and_claim_expansion_corpus_is_rejected(
    case: dict[str, object],
):
    key = Ed25519PrivateKey.generate()
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "resource": RESOURCE,
        "exp": int((NOW + timedelta(minutes=2)).timestamp()),
        "nbf": int((NOW - timedelta(seconds=1)).timestamp()),
        "iat": int(NOW.timestamp()),
        "jti": "security-jti",
        "client_id": "secure-client",
        "sub": "secure-subject",
        "user_id": "secure-user",
        "tenant_id": "tenant-7",
        "mcp_server_id": "secure-server",
        "mcp_request_id": "security-request",
        "scope": "files:read",
        "resource_ids": ["folder-7"],
    }
    claims[str(case["claim"])] = case["value"]
    header = _encode({"alg": "EdDSA", "kid": "security-key", "typ": "at+jwt"})
    payload = _encode(claims)
    signing_input = f"{header}.{payload}".encode()
    signature = base64.urlsafe_b64encode(key.sign(signing_input)).rstrip(b"=").decode()
    token = f"{header}.{payload}.{signature}"
    public_key = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    server = MCPOAuthResourceServer(
        MCPOAuthPolicy(
            issuer=ISSUER,
            audience=AUDIENCE,
            resource=RESOURCE,
            server_id="secure-server",
            allowed_scopes=frozenset({"mcp:tools:list", "files:read"}),
            tool_policies=(
                MCPOAuthToolPolicy(
                    tool_name="files.read",
                    required_scopes=frozenset({"files:read"}),
                    allowed_resource_ids=frozenset({"folder-7"}),
                    resource_argument_pointers=("/folder_id",),
                ),
            ),
        ),
        (MCPOAuthTrustedKey(issuer=ISSUER, key_id="security-key", public_key=public_key),),
    )
    context = MCPOAuthRequestContext(
        operation=MCPOAuthOperation.TOOLS_CALL,
        server_id="secure-server",
        tenant_id="tenant-7",
        user_id="secure-user",
        subject_id="secure-subject",
        client_id="secure-client",
        request_id="security-request",
    )
    definition = MCPToolDefinition(
        server_id="secure-server",
        name="files.read",
        description="Read an authorized folder",
        inputSchema={
            "type": "object",
            "properties": {"folder_id": {"type": "string"}},
            "required": ["folder_id"],
            "additionalProperties": False,
        },
    )

    result = server.authorize_tool_call(
        token,
        context,
        definition,
        {"folder_id": "folder-7"},
        now=NOW,
    )

    assert result.findings[0].code == MCPOAuthCode(str(case["expected_code"]))
    serialized = result.model_dump_json()
    for sensitive in (token, "secure-user", "secure-subject", "tenant-7", "folder-7"):
        assert sensitive not in serialized

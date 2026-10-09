"""Unit coverage for fail-closed MCP OAuth resource-server controls."""

from __future__ import annotations

import base64
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError

from trustrail import (
    CredentialMaterial,
    GuardAction,
    MCPOAuthAuthorizationError,
    MCPOAuthCode,
    MCPOAuthDownstreamBroker,
    MCPOAuthDownstreamCredentialError,
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
    MemoryMCPOAuthReplayStore,
)

NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)
ISSUER = "https://identity.example.com"
AUDIENCE = "mcp://records-server"
RESOURCE = "https://mcp.example.com/records"
SERVER_ID = "records-server"
PRIVATE_KEY = Ed25519PrivateKey.generate()
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _token(
    *,
    request_id: str = "request-1",
    jti: str = "jti-1",
    scopes: tuple[str, ...] = ("mcp:tools:list", "records:read"),
    resource_ids: tuple[str, ...] = ("project-1",),
    claims_update: dict[str, object] | None = None,
    header_update: dict[str, object] | None = None,
    private_key: Ed25519PrivateKey = PRIVATE_KEY,
) -> str:
    header: dict[str, object] = {"alg": "EdDSA", "kid": "issuer-key-1", "typ": "at+jwt"}
    header.update(header_update or {})
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "resource": RESOURCE,
        "exp": int((NOW + timedelta(minutes=2)).timestamp()),
        "nbf": int((NOW - timedelta(seconds=1)).timestamp()),
        "iat": int(NOW.timestamp()),
        "jti": jti,
        "client_id": "desktop-client",
        "sub": "subject-42",
        "user_id": "user-42",
        "tenant_id": "tenant-a",
        "mcp_server_id": SERVER_ID,
        "mcp_request_id": request_id,
        "scope": " ".join(scopes),
        "resource_ids": list(resource_ids),
    }
    claims.update(claims_update or {})
    segments = [
        _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode()),
        _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()),
    ]
    signing_input = ".".join(segments).encode()
    return f"{segments[0]}.{segments[1]}.{_b64url(private_key.sign(signing_input))}"


def _policy() -> MCPOAuthPolicy:
    return MCPOAuthPolicy(
        issuer=ISSUER,
        audience=AUDIENCE,
        resource=RESOURCE,
        server_id=SERVER_ID,
        allowed_scopes=frozenset({"mcp:tools:list", "records:read", "records:delete"}),
        tool_policies=(
            MCPOAuthToolPolicy(
                tool_name="records.search",
                required_scopes=frozenset({"records:read"}),
                allowed_resource_ids=frozenset({"project-1", "project-2"}),
                resource_argument_pointers=("/project_id",),
            ),
            MCPOAuthToolPolicy(
                tool_name="records.delete",
                required_scopes=frozenset({"records:delete"}),
                allowed_resource_ids=frozenset({"project-2"}),
                resource_argument_pointers=("/project_id",),
            ),
            MCPOAuthToolPolicy(
                tool_name="health.read",
                required_scopes=frozenset({"records:read"}),
            ),
        ),
    )


def _trusted_key(**updates: object) -> MCPOAuthTrustedKey:
    values: dict[str, object] = {
        "issuer": ISSUER,
        "key_id": "issuer-key-1",
        "public_key": PUBLIC_KEY,
    }
    values.update(updates)
    return MCPOAuthTrustedKey(**values)  # type: ignore[arg-type]


def _server(
    *,
    replay_store: MemoryMCPOAuthReplayStore | None = None,
    audit_sink: MemoryMCPOAuthAuditSink | None = None,
    trusted_key: MCPOAuthTrustedKey | None = None,
) -> MCPOAuthResourceServer:
    return MCPOAuthResourceServer(
        _policy(),
        (trusted_key or _trusted_key(),),
        replay_store=replay_store,
        audit_sink=audit_sink,
    )


def _context(
    operation: MCPOAuthOperation,
    *,
    request_id: str = "request-1",
    **updates: object,
) -> MCPOAuthRequestContext:
    values: dict[str, object] = {
        "operation": operation,
        "server_id": SERVER_ID,
        "tenant_id": "tenant-a",
        "user_id": "user-42",
        "subject_id": "subject-42",
        "client_id": "desktop-client",
        "request_id": request_id,
    }
    values.update(updates)
    return MCPOAuthRequestContext(**values)  # type: ignore[arg-type]


def _definition(name: str, *, server_id: str = SERVER_ID) -> MCPToolDefinition:
    return MCPToolDefinition(
        server_id=server_id,
        name=name,
        description=f"Safely invoke {name}",
        inputSchema={
            "type": "object",
            "properties": {"project_id": {"type": "string"}},
            "required": ["project_id"],
            "additionalProperties": False,
        },
    )


def test_tools_list_filters_by_server_scope_resource_and_known_tool():
    definitions = (
        _definition("records.search"),
        _definition("records.delete"),
        _definition("health.read"),
        _definition("unknown.tool"),
        _definition("records.search", server_id="other-server"),
    )

    result = _server().authorize_tools_list(
        _token(),
        _context(MCPOAuthOperation.TOOLS_LIST),
        definitions,
        now=NOW,
    )

    assert result.is_allowed
    assert [tool.name for tool in result.visible_tools] == ["records.search", "health.read"]
    assert result.authorization is not None


def test_tool_call_binds_identity_scope_and_argument_resource():
    authorization = _server().require_tool_call(
        _token(scopes=("records:read",)),
        _context(MCPOAuthOperation.TOOLS_CALL),
        _definition("records.search"),
        {"project_id": "project-1"},
        now=NOW,
    )

    assert authorization.tool_name == "records.search"
    assert authorization.argument_resource_ids == frozenset({"project-1"})
    assert authorization.server_id == SERVER_ID


@pytest.mark.parametrize(
    ("claims_update", "context_update", "expected"),
    [
        ({"iss": "https://attacker.example"}, {}, MCPOAuthCode.ISSUER_MISMATCH),
        ({"aud": "other-api"}, {}, MCPOAuthCode.AUDIENCE_MISMATCH),
        ({"aud": [AUDIENCE, "other-api"]}, {}, MCPOAuthCode.AUDIENCE_MISMATCH),
        ({"resource": "https://other.example/api"}, {}, MCPOAuthCode.RESOURCE_MISMATCH),
        ({"client_id": "other-client"}, {}, MCPOAuthCode.CLIENT_MISMATCH),
        ({"sub": "other-subject"}, {}, MCPOAuthCode.SUBJECT_MISMATCH),
        ({"user_id": "other-user"}, {}, MCPOAuthCode.USER_MISMATCH),
        ({"tenant_id": "tenant-b"}, {}, MCPOAuthCode.TENANT_MISMATCH),
        ({"mcp_server_id": "other-server"}, {}, MCPOAuthCode.SERVER_MISMATCH),
        ({"mcp_request_id": "other-request"}, {}, MCPOAuthCode.REQUEST_MISMATCH),
        ({"scope": "records:read admin:*"}, {}, MCPOAuthCode.SCOPE_EXCESSIVE),
        ({"resource_ids": ["project-1", "project-999"]}, {}, MCPOAuthCode.RESOURCE_EXCESSIVE),
        ({}, {"client_id": "other-client"}, MCPOAuthCode.CLIENT_MISMATCH),
        ({}, {"tenant_id": "tenant-b"}, MCPOAuthCode.TENANT_MISMATCH),
    ],
)
def test_claim_and_authenticated_context_confusion_is_rejected(
    claims_update: dict[str, object],
    context_update: dict[str, object],
    expected: MCPOAuthCode,
):
    result = _server().authorize_tool_call(
        _token(scopes=("records:read",), claims_update=claims_update),
        _context(MCPOAuthOperation.TOOLS_CALL, **context_update),
        _definition("records.search"),
        {"project_id": "project-1"},
        now=NOW,
    )

    assert result.action == GuardAction.BLOCK
    assert result.findings[0].code == expected


@pytest.mark.parametrize(
    ("claims_update", "expected"),
    [
        ({"nbf": int((NOW + timedelta(minutes=2)).timestamp())}, MCPOAuthCode.TOKEN_NOT_YET_VALID),
        (
            {
                "exp": int((NOW - timedelta(minutes=1)).timestamp()),
                "iat": int((NOW - timedelta(minutes=2)).timestamp()),
                "nbf": int((NOW - timedelta(minutes=2)).timestamp()),
            },
            MCPOAuthCode.TOKEN_EXPIRED,
        ),
        (
            {
                "iat": int((NOW - timedelta(minutes=10)).timestamp()),
                "nbf": int((NOW - timedelta(minutes=10)).timestamp()),
            },
            MCPOAuthCode.TOKEN_TTL_EXCEEDED,
        ),
    ],
)
def test_stale_future_and_excessive_lifetime_tokens_are_rejected(
    claims_update: dict[str, object], expected: MCPOAuthCode
):
    result = _server().authorize_tool_call(
        _token(scopes=("records:read",), claims_update=claims_update),
        _context(MCPOAuthOperation.TOOLS_CALL),
        _definition("records.search"),
        {"project_id": "project-1"},
        now=NOW,
    )

    assert result.findings[0].code == expected


def test_missing_malformed_unsigned_wrong_algorithm_and_bad_signature_are_rejected():
    context = _context(MCPOAuthOperation.TOOLS_CALL)
    definition = _definition("records.search")
    arguments = {"project_id": "project-1"}
    unsigned = _token(header_update={"alg": "none"})
    bad_signature = f"{_token(scopes=('records:read',)).rsplit('.', 1)[0]}.{'A' * 86}"

    results = (
        _server().authorize_tool_call(None, context, definition, arguments, now=NOW),
        _server().authorize_tool_call("not-a-jwt", context, definition, arguments, now=NOW),
        _server().authorize_tool_call(unsigned, context, definition, arguments, now=NOW),
        _server().authorize_tool_call(bad_signature, context, definition, arguments, now=NOW),
    )

    assert [result.findings[0].code for result in results] == [
        MCPOAuthCode.TOKEN_MISSING,
        MCPOAuthCode.TOKEN_MALFORMED,
        MCPOAuthCode.ALGORITHM_NOT_ALLOWED,
        MCPOAuthCode.SIGNATURE_INVALID,
    ]


def test_unknown_revoked_and_substituted_keys_are_rejected():
    attacker_key = Ed25519PrivateKey.generate()
    unknown = _token(private_key=attacker_key, header_update={"kid": "attacker-key"})
    substituted = _token(private_key=attacker_key)

    unknown_result = _server().authorize_tool_call(
        unknown,
        _context(MCPOAuthOperation.TOOLS_CALL),
        _definition("records.search"),
        {"project_id": "project-1"},
        now=NOW,
    )
    substituted_result = _server().authorize_tool_call(
        substituted,
        _context(MCPOAuthOperation.TOOLS_CALL),
        _definition("records.search"),
        {"project_id": "project-1"},
        now=NOW,
    )
    revoked_result = _server(trusted_key=_trusted_key(revoked=True)).authorize_tool_call(
        _token(scopes=("records:read",)),
        _context(MCPOAuthOperation.TOOLS_CALL),
        _definition("records.search"),
        {"project_id": "project-1"},
        now=NOW,
    )

    assert unknown_result.findings[0].code == MCPOAuthCode.KEY_NOT_TRUSTED
    assert substituted_result.findings[0].code == MCPOAuthCode.SIGNATURE_INVALID
    assert revoked_result.findings[0].code == MCPOAuthCode.KEY_NOT_ACTIVE


@pytest.mark.parametrize(
    ("definition", "arguments", "scopes", "expected"),
    [
        (
            _definition("records.search", server_id="other-server"),
            {"project_id": "project-1"},
            ("records:read",),
            MCPOAuthCode.SERVER_MISMATCH,
        ),
        (
            _definition("unknown.tool"),
            {"project_id": "project-1"},
            ("records:read",),
            MCPOAuthCode.TOOL_NOT_AUTHORIZED,
        ),
        (
            _definition("records.delete"),
            {"project_id": "project-2"},
            ("records:read",),
            MCPOAuthCode.SCOPE_MISSING,
        ),
        (
            _definition("records.search"),
            {},
            ("records:read",),
            MCPOAuthCode.ARGUMENT_RESOURCE_MISSING,
        ),
        (
            _definition("records.search"),
            {"project_id": ["project-1"]},
            ("records:read",),
            MCPOAuthCode.ARGUMENT_RESOURCE_INVALID,
        ),
        (
            _definition("records.search"),
            {"project_id": "project-2"},
            ("records:read",),
            MCPOAuthCode.RESOURCE_NOT_AUTHORIZED,
        ),
    ],
)
def test_tool_and_argument_authorization_bypasses_are_rejected(
    definition: MCPToolDefinition,
    arguments: dict[str, object],
    scopes: tuple[str, ...],
    expected: MCPOAuthCode,
):
    result = _server().authorize_tool_call(
        _token(scopes=scopes),
        _context(MCPOAuthOperation.TOOLS_CALL),
        definition,
        arguments,  # type: ignore[arg-type]
        now=NOW,
    )

    assert result.findings[0].code == expected


def test_caller_token_in_nested_tool_arguments_is_rejected():
    token = _token(scopes=("records:read",))

    result = _server().authorize_tool_call(
        token,
        _context(MCPOAuthOperation.TOOLS_CALL),
        _definition("records.search"),
        {"project_id": "project-1", "connector": {"authorization": f"Bearer {token}"}},
        now=NOW,
    )

    assert result.findings[0].code == MCPOAuthCode.TOKEN_PASSTHROUGH


def test_token_is_atomic_single_use_under_concurrency():
    replay_store = MemoryMCPOAuthReplayStore()
    server = _server(replay_store=replay_store)
    token = _token(scopes=("records:read",))

    def authorize(_: int):
        return server.authorize_tool_call(
            token,
            _context(MCPOAuthOperation.TOOLS_CALL),
            _definition("records.search"),
            {"project_id": "project-1"},
            now=NOW,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(authorize, range(32)))

    assert sum(result.is_allowed for result in results) == 1
    assert all(
        result.is_allowed or result.findings[0].code == MCPOAuthCode.TOKEN_REPLAYED
        for result in results
    )
    assert replay_store.size == 1


def test_valid_token_is_consumed_even_when_tool_authorization_is_denied():
    server = _server()
    token = _token(scopes=("records:read",))

    denied = server.authorize_tool_call(
        token,
        _context(MCPOAuthOperation.TOOLS_CALL),
        _definition("records.search"),
        {"project_id": "project-2"},
        now=NOW,
    )
    retried = server.authorize_tool_call(
        token,
        _context(MCPOAuthOperation.TOOLS_CALL),
        _definition("records.search"),
        {"project_id": "project-1"},
        now=NOW,
    )

    assert denied.findings[0].code == MCPOAuthCode.RESOURCE_NOT_AUTHORIZED
    assert retried.findings[0].code == MCPOAuthCode.TOKEN_REPLAYED


def test_replay_store_capacity_and_failure_are_fail_closed():
    full_store = MemoryMCPOAuthReplayStore(max_entries=1)
    server = _server(replay_store=full_store)
    assert server.authorize_tool_call(
        _token(scopes=("records:read",)),
        _context(MCPOAuthOperation.TOOLS_CALL),
        _definition("records.search"),
        {"project_id": "project-1"},
        now=NOW,
    ).is_allowed
    full = server.authorize_tool_call(
        _token(request_id="request-2", jti="jti-2", scopes=("records:read",)),
        _context(MCPOAuthOperation.TOOLS_CALL, request_id="request-2"),
        _definition("records.search"),
        {"project_id": "project-1"},
        now=NOW,
    )

    class BrokenStore:
        def claim(self, *_args, **_kwargs):
            raise RuntimeError("database unavailable")

    broken = MCPOAuthResourceServer(
        _policy(),
        (_trusted_key(),),
        replay_store=BrokenStore(),  # type: ignore[arg-type]
    ).authorize_tool_call(
        _token(scopes=("records:read",)),
        _context(MCPOAuthOperation.TOOLS_CALL),
        _definition("records.search"),
        {"project_id": "project-1"},
        now=NOW,
    )

    assert full.findings[0].code == MCPOAuthCode.REPLAY_STORE_FULL
    assert broken.findings[0].code == MCPOAuthCode.REPLAY_STORE_ERROR


def test_require_helpers_raise_with_content_free_results():
    with pytest.raises(MCPOAuthAuthorizationError) as caught:
        _server().require_tool_call(
            None,
            _context(MCPOAuthOperation.TOOLS_CALL),
            _definition("records.search"),
            {"project_id": "project-1"},
            now=NOW,
        )

    assert caught.value.result.findings[0].code == MCPOAuthCode.TOKEN_MISSING
    assert "user-42" not in caught.value.result.model_dump_json()


class _Provider:
    def __init__(self, *, passthrough: bool = False) -> None:
        self.passthrough = passthrough
        self.exchange_calls = 0
        self.workload_calls = 0

    def exchange(
        self,
        _request: MCPOAuthDownstreamRequest,
        subject_token: CredentialMaterial,
    ) -> CredentialMaterial:
        self.exchange_calls += 1
        if self.passthrough:
            return CredentialMaterial(subject_token.reveal())
        return CredentialMaterial("downstream-exchanged-token")

    def workload_credential(self, _request: MCPOAuthDownstreamRequest) -> CredentialMaterial:
        self.workload_calls += 1
        return CredentialMaterial("workload-owned-token")


def _authorized_call(token: str):
    return _server().require_tool_call(
        token,
        _context(MCPOAuthOperation.TOOLS_CALL),
        _definition("records.search"),
        {"project_id": "project-1"},
        now=NOW,
    )


def _downstream_request(authorization, mode: MCPOAuthDownstreamMode):
    return MCPOAuthDownstreamRequest(
        authorization=authorization,
        mode=mode,
        service_id="records-api",
        audience="https://api.example.com",
        resource="https://api.example.com/projects/project-1",
        resource_id="project-1",
        scopes=frozenset({"records:read"}),
    )


def test_downstream_broker_supports_exchange_and_workload_credentials_without_passthrough():
    token = _token(scopes=("records:read",))
    authorization = _authorized_call(token)
    provider = _Provider()
    broker = MCPOAuthDownstreamBroker(provider)

    with CredentialMaterial(token) as subject_token:
        exchanged = broker.acquire(
            _downstream_request(authorization, MCPOAuthDownstreamMode.TOKEN_EXCHANGE),
            subject_token=subject_token,
            now=NOW,
        )
    workload = broker.acquire(
        _downstream_request(authorization, MCPOAuthDownstreamMode.WORKLOAD_IDENTITY),
        now=NOW,
    )

    with exchanged, workload:
        assert exchanged.reveal() == b"downstream-exchanged-token"
        assert workload.reveal() == b"workload-owned-token"
    assert provider.exchange_calls == 1
    assert provider.workload_calls == 1


def test_downstream_broker_rejects_passthrough_wrong_subject_and_scope_expansion():
    token = _token(scopes=("records:read",))
    authorization = _authorized_call(token)
    passthrough = MCPOAuthDownstreamBroker(_Provider(passthrough=True))
    request = _downstream_request(authorization, MCPOAuthDownstreamMode.TOKEN_EXCHANGE)

    with (
        CredentialMaterial(token) as subject_token,
        pytest.raises(MCPOAuthDownstreamCredentialError) as caught,
    ):
        passthrough.acquire(request, subject_token=subject_token, now=NOW)
    assert caught.value.code == MCPOAuthCode.TOKEN_PASSTHROUGH

    with (
        CredentialMaterial("wrong-token") as wrong_token,
        pytest.raises(MCPOAuthDownstreamCredentialError) as caught,
    ):
        passthrough.acquire(request, subject_token=wrong_token, now=NOW)
    assert caught.value.code == MCPOAuthCode.REQUEST_MISMATCH

    expanded = request.model_copy(update={"scopes": frozenset({"records:delete"})})
    with pytest.raises(MCPOAuthDownstreamCredentialError) as caught:
        passthrough.acquire(expanded, now=NOW)
    assert caught.value.code == MCPOAuthCode.DOWNSTREAM_SCOPE_INVALID


def test_downstream_request_requires_call_and_exact_authorized_resource():
    list_authorization = (
        _server()
        .authorize_tools_list(
            _token(),
            _context(MCPOAuthOperation.TOOLS_LIST),
            (_definition("records.search"),),
            now=NOW,
        )
        .authorization
    )
    assert list_authorization is not None
    with pytest.raises(ValidationError):
        _downstream_request(list_authorization, MCPOAuthDownstreamMode.WORKLOAD_IDENTITY)

    token = _token(scopes=("records:read",))
    call_authorization = _authorized_call(token)
    valid_request = _downstream_request(
        call_authorization,
        MCPOAuthDownstreamMode.WORKLOAD_IDENTITY,
    )
    values = valid_request.model_dump(mode="python")
    values["resource_id"] = "project-2"
    with pytest.raises(ValidationError):
        MCPOAuthDownstreamRequest.model_validate(values)

    bypassed = valid_request.model_copy(update={"resource_id": "project-2"}, deep=True)
    with pytest.raises(MCPOAuthDownstreamCredentialError) as caught:
        MCPOAuthDownstreamBroker(_Provider()).acquire(bypassed, now=NOW)
    assert caught.value.code == MCPOAuthCode.RESOURCE_NOT_AUTHORIZED


def test_audit_events_are_content_free_and_hash_sensitive_identifiers():
    sink = MemoryMCPOAuthAuditSink()
    token = _token(scopes=("records:read",))
    result = _server(audit_sink=sink).authorize_tool_call(
        token,
        _context(MCPOAuthOperation.TOOLS_CALL),
        _definition("records.search"),
        {"project_id": "project-1"},
        now=NOW,
    )

    serialized = result.audit_event.model_dump_json()
    assert len(sink.events) == 1
    for sensitive in (
        token,
        "user-42",
        "tenant-a",
        "subject-42",
        "desktop-client",
        "records.search",
        "project-1",
    ):
        assert sensitive not in serialized


def test_policy_rejects_duplicate_tools_scope_expansion_and_unsafe_resource_pointers():
    tool = MCPOAuthToolPolicy(
        tool_name="records.search",
        required_scopes=frozenset({"records:read"}),
    )
    with pytest.raises(ValidationError):
        MCPOAuthPolicy(
            issuer=ISSUER,
            audience=AUDIENCE,
            resource=RESOURCE,
            server_id=SERVER_ID,
            allowed_scopes=frozenset({"mcp:tools:list", "records:read"}),
            tool_policies=(tool, tool),
        )
    with pytest.raises(ValidationError):
        MCPOAuthToolPolicy(
            tool_name="records.search",
            required_scopes=frozenset({"records:read"}),
            resource_argument_pointers=("project_id",),
        )

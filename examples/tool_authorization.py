"""Authorize a least-privilege tool call before execution."""

from datetime import UTC, datetime, timedelta

from trustrail import (
    ToolArgumentConstraint,
    ToolArgumentKind,
    ToolAuthorizationPolicy,
    ToolAuthorizationRequest,
    ToolAuthorizer,
    ToolCapability,
    ToolEffect,
    ToolIntent,
    ToolPrincipal,
    ToolResource,
)

capability = ToolCapability(
    name="documents.read",
    version="v1",
    effects=frozenset({ToolEffect.READ}),
    required_scopes=frozenset({"documents:read"}),
    arguments={
        "document_id": ToolArgumentConstraint(
            kind=ToolArgumentKind.STRING,
            pattern=r"doc-[a-z0-9]{8}",
        )
    },
    required_arguments=frozenset({"document_id"}),
    resource_id_argument="document_id",
    require_owned_resource=True,
    allow_autonomous=True,
)
authorizer = ToolAuthorizer(ToolAuthorizationPolicy(capabilities=(capability,)))
budget = authorizer.new_budget("session-123")

request = ToolAuthorizationRequest(
    tool_name="documents.read",
    tool_version="v1",
    arguments={"document_id": "doc-ab12cd34"},
    principal=ToolPrincipal(
        actor_id="document-agent",
        subject_id="user-7",
        tenant_id="tenant-a",
        scopes=frozenset({"documents:read"}),
    ),
    intent=ToolIntent(
        intent_id="read-selected-document",
        subject_id="user-7",
        tenant_id="tenant-a",
        allowed_tools=frozenset({"documents.read"}),
        purpose="Read the document selected by the user",
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
    ),
    resource=ToolResource(
        resource_id="doc-ab12cd34",
        owner_id="user-7",
        tenant_id="tenant-a",
    ),
    session_id="session-123",
    chain_id="read-document-chain",
    operation_id="read-document-once",
)

authorization = authorizer.require(request, budget)
try:
    print(f"Authorized {authorization.tool_name}")
finally:
    authorizer.complete(authorization, budget)

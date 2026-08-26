"""Unit tests for deterministic OWASP LLM06 tool authorization."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from trustrail import (
    GuardAction,
    StaticToolApprovalVerifier,
    ToolApprovalGrant,
    ToolArgumentConstraint,
    ToolArgumentKind,
    ToolAuthorizationCode,
    ToolAuthorizationError,
    ToolAuthorizationPolicy,
    ToolAuthorizationRequest,
    ToolAuthorizationResult,
    ToolAuthorizer,
    ToolCapability,
    ToolEffect,
    ToolIntent,
    ToolPrincipal,
    ToolResource,
)

NOW = datetime(2026, 8, 26, tzinfo=UTC)


def _read_capability(**updates: object) -> ToolCapability:
    capability = ToolCapability(
        name="documents.read",
        version="2026-08-01",
        effects=frozenset({ToolEffect.READ}),
        required_scopes=frozenset({"documents:read"}),
        arguments={
            "document_id": ToolArgumentConstraint(
                kind=ToolArgumentKind.STRING,
                pattern=r"doc-[a-z0-9]{4}",
            ),
            "format": ToolArgumentConstraint(
                kind=ToolArgumentKind.STRING,
                allowed_values=("text", "summary"),
            ),
        },
        required_arguments=frozenset({"document_id"}),
        resource_id_argument="document_id",
        require_owned_resource=True,
        allow_autonomous=True,
    )
    return ToolCapability(**{**capability.model_dump(), **updates})


def _request(**updates: object) -> ToolAuthorizationRequest:
    request = ToolAuthorizationRequest(
        tool_name="documents.read",
        tool_version="2026-08-01",
        arguments={"document_id": "doc-ab12", "format": "summary"},
        principal=ToolPrincipal(
            actor_id="support-agent",
            subject_id="user-7",
            tenant_id="tenant-a",
            scopes=frozenset({"documents:read"}),
        ),
        intent=ToolIntent(
            intent_id="intent-1",
            subject_id="user-7",
            tenant_id="tenant-a",
            allowed_tools=frozenset({"documents.read"}),
            purpose="Summarize the selected document",
            expires_at=NOW + timedelta(minutes=5),
            max_calls=20,
        ),
        resource=ToolResource(
            resource_id="doc-ab12",
            owner_id="user-7",
            tenant_id="tenant-a",
        ),
        session_id="session-1",
        chain_id="chain-1",
        operation_id="operation-1",
    )
    return request.model_copy(update=updates)


def _authorizer(
    capability: ToolCapability | None = None,
    **policy_updates: object,
) -> ToolAuthorizer:
    policy = ToolAuthorizationPolicy(capabilities=(capability or _read_capability(),))
    return ToolAuthorizer(policy.model_copy(update=policy_updates))


def _codes(result: ToolAuthorizationResult) -> set[ToolAuthorizationCode]:
    return {finding.code for finding in result.findings}


def test_authorizes_exact_least_privilege_request_and_releases_lease():
    authorizer = _authorizer()
    budget = authorizer.new_budget("session-1")

    result = authorizer.authorize(_request(), budget, now=NOW)

    assert result.is_authorized
    assert result.authorization is not None
    assert budget.active_calls == 1
    assert authorizer.complete(result.authorization, budget)
    assert budget.active_calls == 0


def test_authorization_lease_keeps_immutable_argument_snapshot():
    authorizer = _authorizer()
    request = _request()
    result = authorizer.authorize(request, authorizer.new_budget("session-1"), now=NOW)
    assert result.authorization is not None

    request.arguments["document_id"] = "doc-ffff"

    assert result.authorization.arguments["document_id"] == "doc-ab12"
    assert "arguments_json" not in result.model_dump()["authorization"]


@pytest.mark.parametrize(
    "update",
    [
        {"session_id": "session-2"},
        {"chain_id": "chain-2"},
        {"operation_id": "operation-2"},
        {"autonomous": False},
    ],
)
def test_approval_digest_binds_execution_context(update: dict[str, object]):
    request = _request()

    changed = request.model_copy(update=update)

    assert changed.approval_digest != request.approval_digest


@pytest.mark.parametrize(
    ("authorization_request", "code"),
    [
        (_request(tool_name="documents.read.evil"), ToolAuthorizationCode.UNKNOWN_TOOL),
        (
            _request(tool_version="latest"),
            ToolAuthorizationCode.TOOL_VERSION_MISMATCH,
        ),
        (
            _request(principal=_request().principal.model_copy(update={"scopes": frozenset()})),
            ToolAuthorizationCode.SCOPE_DENIED,
        ),
        (
            _request(arguments={"document_id": "doc-ab12", "admin": True}),
            ToolAuthorizationCode.ARGUMENT_NOT_ALLOWED,
        ),
        (
            _request(arguments={"document_id": 1234}),
            ToolAuthorizationCode.ARGUMENT_TYPE_MISMATCH,
        ),
        (
            _request(arguments={"document_id": "../../etc/passwd"}),
            ToolAuthorizationCode.ARGUMENT_CONSTRAINT_FAILED,
        ),
        (
            _request(resource=_request().resource.model_copy(update={"owner_id": "user-8"})),
            ToolAuthorizationCode.RESOURCE_OWNER_MISMATCH,
        ),
        (
            _request(resource=_request().resource.model_copy(update={"tenant_id": "tenant-b"})),
            ToolAuthorizationCode.RESOURCE_TENANT_MISMATCH,
        ),
        (
            _request(
                intent=_request().intent.model_copy(
                    update={"allowed_tools": frozenset({"documents.list"})}
                )
            ),
            ToolAuthorizationCode.TOOL_OUTSIDE_INTENT,
        ),
        (
            _request(
                requested_scopes=frozenset({"documents:delete"}),
            ),
            ToolAuthorizationCode.PRIVILEGE_EXPANSION,
        ),
    ],
)
def test_fails_closed_for_identity_scope_argument_ownership_and_intent_bypasses(
    authorization_request: ToolAuthorizationRequest,
    code: ToolAuthorizationCode,
):
    authorizer = _authorizer()

    result = authorizer.authorize(
        authorization_request, authorizer.new_budget("session-1"), now=NOW
    )

    assert result.action == GuardAction.BLOCK
    assert code in _codes(result)


def test_rejects_expired_and_cross_principal_intent():
    intent = _request().intent.model_copy(
        update={"subject_id": "user-8", "expires_at": NOW - timedelta(seconds=1)}
    )
    authorizer = _authorizer()

    result = authorizer.authorize(
        _request(intent=intent), authorizer.new_budget("session-1"), now=NOW
    )

    assert {
        ToolAuthorizationCode.INTENT_PRINCIPAL_MISMATCH,
        ToolAuthorizationCode.INTENT_EXPIRED,
    } <= _codes(result)


def test_requires_authenticated_exact_single_use_approval_for_destructive_effect():
    capability = _read_capability(
        name="documents.delete",
        effects=frozenset({ToolEffect.DELETE}),
        required_scopes=frozenset({"documents:delete"}),
        allow_autonomous=False,
    )
    request = _request(
        tool_name="documents.delete",
        principal=_request().principal.model_copy(
            update={"scopes": frozenset({"documents:delete"})}
        ),
        intent=_request().intent.model_copy(
            update={"allowed_tools": frozenset({"documents.delete"})}
        ),
        autonomous=False,
    )
    policy = ToolAuthorizationPolicy(capabilities=(capability,))
    verifier = StaticToolApprovalVerifier(frozenset({"approval-1"}))
    authorizer = ToolAuthorizer(policy, approval_verifier=verifier)
    budget = authorizer.new_budget("session-1")

    pending = authorizer.authorize(request, budget, now=NOW)
    assert pending.action == GuardAction.REQUIRE_APPROVAL

    grant = ToolApprovalGrant(
        approval_id="approval-1",
        request_digest=request.approval_digest,
        approver_id="human-reviewer",
        expires_at=NOW + timedelta(minutes=1),
    )
    approved_request = request.model_copy(update={"approval": grant})
    allowed = authorizer.authorize(approved_request, budget, now=NOW)
    assert allowed.is_authorized
    assert allowed.authorization is not None
    authorizer.complete(allowed.authorization, budget)

    replay = authorizer.authorize(approved_request, budget, now=NOW)
    assert ToolAuthorizationCode.APPROVAL_REPLAYED in _codes(replay)


def test_blocks_approval_rebound_to_changed_arguments():
    capability = _read_capability(require_approval=True)
    request = _request(autonomous=False)
    grant = ToolApprovalGrant(
        approval_id="approval-1",
        request_digest=request.approval_digest,
        approver_id="reviewer",
        expires_at=NOW + timedelta(minutes=1),
    )
    changed = request.model_copy(
        update={
            "arguments": {"document_id": "doc-ffff"},
            "resource": ToolResource(
                resource_id="doc-ffff", owner_id="user-7", tenant_id="tenant-a"
            ),
            "approval": grant,
        }
    )
    authorizer = ToolAuthorizer(
        ToolAuthorizationPolicy(capabilities=(capability,)),
        approval_verifier=StaticToolApprovalVerifier(frozenset({"approval-1"})),
    )

    result = authorizer.authorize(changed, authorizer.new_budget("session-1"), now=NOW)

    assert ToolAuthorizationCode.APPROVAL_INVALID in _codes(result)


@pytest.mark.parametrize(
    ("policy_updates", "second_request", "code", "keep_active"),
    [
        (
            {"max_tool_calls": 1},
            _request(operation_id="operation-2", chain_id="chain-2"),
            ToolAuthorizationCode.TOOL_CALL_LIMIT_EXCEEDED,
            False,
        ),
        (
            {"max_chain_actions": 1},
            _request(operation_id="operation-2"),
            ToolAuthorizationCode.CHAIN_LIMIT_EXCEEDED,
            False,
        ),
        (
            {"max_retries_per_operation": 0},
            _request(),
            ToolAuthorizationCode.RETRY_LIMIT_EXCEEDED,
            False,
        ),
        (
            {"max_parallel_calls": 1},
            _request(operation_id="operation-2", chain_id="chain-2"),
            ToolAuthorizationCode.PARALLEL_LIMIT_EXCEEDED,
            True,
        ),
        (
            {"max_autonomous_actions": 1},
            _request(operation_id="operation-2", chain_id="chain-2"),
            ToolAuthorizationCode.AUTONOMOUS_LIMIT_EXCEEDED,
            False,
        ),
    ],
)
def test_enforces_bounded_execution(
    policy_updates: dict[str, int],
    second_request: ToolAuthorizationRequest,
    code: ToolAuthorizationCode,
    keep_active: bool,
):
    authorizer = _authorizer(**policy_updates)
    budget = authorizer.new_budget("session-1")
    first = authorizer.authorize(_request(), budget, now=NOW)
    assert first.authorization is not None
    if not keep_active:
        authorizer.complete(first.authorization, budget)

    second = authorizer.authorize(second_request, budget, now=NOW)

    assert second.is_blocked
    assert code in _codes(second)


def test_require_raises_with_structured_result():
    authorizer = _authorizer()

    with pytest.raises(ToolAuthorizationError) as caught:
        authorizer.require(
            _request(tool_version="untrusted"),
            authorizer.new_budget("session-1"),
            now=NOW,
        )

    assert caught.value.result.is_blocked


def test_capability_rejects_undeclared_required_argument():
    with pytest.raises(ValidationError):
        _read_capability(required_arguments=frozenset({"undeclared"}))

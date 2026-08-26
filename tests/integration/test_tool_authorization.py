"""Integration coverage for scanning and authorizing a tool boundary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from trustrail import (
    Guard,
    GuardContext,
    GuardStage,
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


def test_model_tool_call_is_scanned_then_authorized_in_user_context():
    capability = ToolCapability(
        name="orders.read",
        version="v3",
        effects=frozenset({ToolEffect.READ}),
        required_scopes=frozenset({"orders:read"}),
        arguments={
            "order_id": ToolArgumentConstraint(
                kind=ToolArgumentKind.STRING,
                pattern=r"order-[0-9]{6}",
            )
        },
        required_arguments=frozenset({"order_id"}),
        resource_id_argument="order_id",
        require_owned_resource=True,
        allow_autonomous=True,
    )
    authorizer = ToolAuthorizer(ToolAuthorizationPolicy(capabilities=(capability,)))
    request = ToolAuthorizationRequest(
        tool_name="orders.read",
        tool_version="v3",
        arguments={"order_id": "order-123456"},
        principal=ToolPrincipal(
            actor_id="shopping-agent",
            subject_id="customer-1",
            tenant_id="shop-eu",
            scopes=frozenset({"orders:read"}),
        ),
        intent=ToolIntent(
            intent_id="show-order",
            subject_id="customer-1",
            tenant_id="shop-eu",
            allowed_tools=frozenset({"orders.read"}),
            purpose="Show the order selected by the customer",
            expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
        ),
        resource=ToolResource(
            resource_id="order-123456",
            owner_id="customer-1",
            tenant_id="shop-eu",
        ),
        session_id="checkout-session",
        chain_id="show-order-chain",
        operation_id="read-order-once",
    )

    scan = Guard.silent().check(
        request.tool_name,
        GuardStage.TOOL_REQUEST,
        context=GuardContext(
            stage=GuardStage.TOOL_REQUEST,
            metadata={"tool_name": request.tool_name, "tool_args": request.arguments},
        ),
    )
    assert scan.is_allowed

    budget = authorizer.new_budget(request.session_id)
    authorization = authorizer.require(request, budget)
    try:
        assert authorization.tool_name == "orders.read"
        assert authorization.request_digest == request.approval_digest
        assert authorization.arguments == {"order_id": "order-123456"}
    finally:
        authorizer.complete(authorization, budget)

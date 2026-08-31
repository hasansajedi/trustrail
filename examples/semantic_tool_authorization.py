"""Bind a tool call to trusted intent and verify its observed outcome."""

from datetime import UTC, datetime, timedelta

from trustrail import (
    ToolArgumentBinding,
    ToolArgumentConstraint,
    ToolArgumentKind,
    ToolAuthorizationPolicy,
    ToolAuthorizationRequest,
    ToolAuthorizer,
    ToolCapability,
    ToolEffect,
    ToolExecutionReport,
    ToolExecutionStatus,
    ToolIntent,
    ToolPostconditionPolicy,
    ToolPreconditionPolicy,
    ToolPrincipal,
    ToolResource,
    ToolSemanticAuthorizationPolicy,
    ToolSemanticContext,
    ToolSemanticOperationPolicy,
)

capability = ToolCapability(
    name="orders.refund",
    version="v2",
    effects=frozenset({ToolEffect.UPDATE}),
    required_scopes=frozenset({"orders:refund"}),
    arguments={
        "order_id": ToolArgumentConstraint(
            kind=ToolArgumentKind.STRING,
            pattern=r"order-[0-9]{6}",
        ),
        "amount": ToolArgumentConstraint(
            kind=ToolArgumentKind.NUMBER,
            minimum=0.01,
            maximum=1_000,
        ),
    },
    required_arguments=frozenset({"order_id", "amount"}),
    resource_id_argument="order_id",
    require_owned_resource=True,
    allow_autonomous=True,
)
semantic_policy = ToolSemanticAuthorizationPolicy(
    operations=(
        ToolSemanticOperationPolicy(
            tool_name="orders.refund",
            preconditions=ToolPreconditionPolicy(
                expected_facts={"refund_eligible": True},
                argument_bindings=(
                    ToolArgumentBinding(argument="amount", trusted_fact="approved_amount"),
                ),
            ),
            postconditions=ToolPostconditionPolicy(
                required_facts=frozenset({"refund_id"}),
                expected_facts={"ledger_committed": True},
            ),
        ),
    )
)
authorizer = ToolAuthorizer(
    ToolAuthorizationPolicy(
        capabilities=(capability,),
        approval_required_for=frozenset(),
    ),
    semantic_policy=semantic_policy,
)
budget = authorizer.new_budget("returns-session")

request = ToolAuthorizationRequest(
    tool_name="orders.refund",
    tool_version="v2",
    arguments={"order_id": "order-123456", "amount": 25.0},
    principal=ToolPrincipal(
        actor_id="returns-agent",
        subject_id="customer-1",
        tenant_id="shop-eu",
        scopes=frozenset({"orders:refund"}),
    ),
    intent=ToolIntent(
        intent_id="refund-order",
        subject_id="customer-1",
        tenant_id="shop-eu",
        allowed_tools=frozenset({"orders.refund"}),
        purpose="Refund exactly 25 EUR for the selected order",
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
    ),
    resource=ToolResource(
        resource_id="order-123456",
        owner_id="customer-1",
        tenant_id="shop-eu",
    ),
    session_id="returns-session",
    chain_id="refund-chain",
    operation_id="refund-once",
    semantic_context=ToolSemanticContext(
        # These facts come from trusted application state, never the model.
        trusted_facts={"refund_eligible": True, "approved_amount": 25.0},
        expected_effects=frozenset({ToolEffect.UPDATE}),
        expected_resource_ids=frozenset({"order-123456"}),
    ),
)

authorization = authorizer.require(request, budget)
# A real application executes only authorization.arguments here.
gateway_result = {
    "refund_id": "refund-1",
    "order_id": authorization.arguments["order_id"],
    "ledger_committed": True,
}
outcome = authorizer.verify_completion(
    authorization,
    ToolExecutionReport(
        authorization_id=authorization.authorization_id,
        request_digest=authorization.request_digest,
        session_id=request.session_id,
        tool_name=request.tool_name,
        status=ToolExecutionStatus.SUCCEEDED,
        observed_effects=frozenset({ToolEffect.UPDATE}),
        affected_resource_ids=frozenset({str(gateway_result["order_id"])}),
        facts={
            "refund_id": str(gateway_result["refund_id"]),
            "ledger_committed": bool(gateway_result["ledger_committed"]),
        },
    ),
    budget,
)
print(f"Verified refund: {outcome.is_verified}")

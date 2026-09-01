"""End-to-end delegated identity authorization before a tool invocation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from trustrail import (
    AgentIdentity,
    AgentIdentityKind,
    DelegatedAccessPolicy,
    DelegatedAccessRequest,
    DelegatedCapability,
    DelegatedIdentityAuthorizer,
    DelegationChain,
    StaticDelegatedCapabilityVerifier,
    ToolArgumentConstraint,
    ToolArgumentKind,
    ToolAuthorizationPolicy,
    ToolAuthorizationRequest,
    ToolAuthorizer,
    ToolCapability,
    ToolEffect,
    ToolIntent,
    ToolResource,
)


def test_delegated_subagent_identity_becomes_least_privilege_tool_principal():
    now = datetime.now(tz=UTC)
    user = AgentIdentity(
        identity_id="customer-1",
        kind=AgentIdentityKind.HUMAN,
        tenant_id="shop-eu",
    )
    shopping_agent = AgentIdentity(
        identity_id="shopping-agent",
        kind=AgentIdentityKind.AGENT,
        tenant_id="shop-eu",
    )
    order_agent = AgentIdentity(
        identity_id="order-reader",
        kind=AgentIdentityKind.SUB_AGENT,
        tenant_id="shop-eu",
    )
    root = DelegatedCapability.create(
        capability_id="cap-shopping-session",
        issuer=user,
        subject=shopping_agent,
        scopes=frozenset({"orders:read"}),
        delegatable_scopes=frozenset({"orders:read"}),
        audiences=frozenset({"tool:orders.read"}),
        purpose_id="show-selected-order",
        issued_at=now,
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        max_delegation_depth=1,
    )
    leaf = DelegatedCapability.create(
        capability_id="cap-order-reader",
        issuer=shopping_agent,
        subject=order_agent,
        scopes=frozenset({"orders:read"}),
        audiences=frozenset({"tool:orders.read"}),
        purpose_id="show-selected-order",
        issued_at=now,
        not_before=now,
        expires_at=now + timedelta(minutes=2),
        delegation_depth=1,
        max_delegation_depth=1,
        parent=root,
    )
    chain = DelegationChain(capabilities=(root, leaf))
    identity_authorizer = DelegatedIdentityAuthorizer(
        DelegatedAccessPolicy(
            trusted_root_issuer_ids=frozenset({"customer-1"}),
            allowed_audiences=frozenset({"tool:orders.read"}),
            max_capability_lifetime_seconds=300,
            max_delegation_depth=1,
        ),
        capability_verifier=StaticDelegatedCapabilityVerifier(
            frozenset(
                {
                    (root.capability_id, root.capability_digest),
                    (leaf.capability_id, leaf.capability_digest),
                }
            )
        ),
    )
    delegated_access = identity_authorizer.require(
        DelegatedAccessRequest(
            presenter=order_agent,
            chain=chain,
            audience="tool:orders.read",
            purpose_id="show-selected-order",
            requested_scopes=frozenset({"orders:read"}),
            tenant_id="shop-eu",
            operation_id="read-order-123456",
        ),
        now=now,
    )

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
    tool_authorizer = ToolAuthorizer(ToolAuthorizationPolicy(capabilities=(capability,)))
    tool_request = ToolAuthorizationRequest(
        tool_name="orders.read",
        tool_version="v3",
        arguments={"order_id": "order-123456"},
        principal=identity_authorizer.to_tool_principal(delegated_access, now=now),
        intent=ToolIntent(
            intent_id="show-selected-order",
            subject_id="customer-1",
            tenant_id="shop-eu",
            allowed_tools=frozenset({"orders.read"}),
            purpose="Show the order selected by the customer",
            expires_at=now + timedelta(minutes=2),
        ),
        resource=ToolResource(
            resource_id="order-123456",
            owner_id="customer-1",
            tenant_id="shop-eu",
        ),
        session_id="shopping-session",
        chain_id="show-order-chain",
        operation_id=delegated_access.operation_id,
    )
    budget = tool_authorizer.new_budget(tool_request.session_id)

    tool_lease = tool_authorizer.require(tool_request, budget, now=now)

    assert tool_lease.tool_name == "orders.read"
    assert tool_request.principal.actor_id == "order-reader"
    assert tool_request.principal.subject_id == "customer-1"
    assert tool_authorizer.complete(tool_lease, budget)

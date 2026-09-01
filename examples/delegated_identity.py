"""Bind a sub-agent to a short-lived, least-privilege identity chain."""

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
)

now = datetime.now(tz=UTC)
customer = AgentIdentity(
    identity_id="customer-42",
    kind=AgentIdentityKind.HUMAN,
    tenant_id="shop-eu",
)
shopping_agent = AgentIdentity(
    identity_id="shopping-agent",
    kind=AgentIdentityKind.AGENT,
    tenant_id="shop-eu",
)
order_reader = AgentIdentity(
    identity_id="order-reader",
    kind=AgentIdentityKind.SUB_AGENT,
    tenant_id="shop-eu",
)

# A trusted identity service issues these records. Each child can only narrow its
# parent's scope, audience, purpose, tenant, lifetime, and delegation depth.
root = DelegatedCapability.create(
    capability_id="cap-shopping-session",
    issuer=customer,
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
    subject=order_reader,
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

# This static verifier is for examples and tests. Production code must verify a
# signature or exact issuance record in a trusted identity service.
verifier = StaticDelegatedCapabilityVerifier(
    frozenset(
        {
            (root.capability_id, root.capability_digest),
            (leaf.capability_id, leaf.capability_digest),
        }
    )
)
authorizer = DelegatedIdentityAuthorizer(
    DelegatedAccessPolicy(
        trusted_root_issuer_ids=frozenset({customer.identity_id}),
        allowed_audiences=frozenset({"tool:orders.read"}),
        max_capability_lifetime_seconds=300,
        max_delegation_depth=1,
        authorization_ttl_seconds=30,
    ),
    capability_verifier=verifier,
)

access = authorizer.require(
    DelegatedAccessRequest(
        presenter=order_reader,
        chain=chain,
        audience="tool:orders.read",
        purpose_id="show-selected-order",
        requested_scopes=frozenset({"orders:read"}),
        tenant_id="shop-eu",
        operation_id="read-order-123456",
    ),
    now=now,
)
tool_principal = authorizer.to_tool_principal(access, now=now)
print(
    f"Authorized {tool_principal.actor_id} for {sorted(tool_principal.scopes)} "
    f"on behalf of {tool_principal.subject_id}"
)

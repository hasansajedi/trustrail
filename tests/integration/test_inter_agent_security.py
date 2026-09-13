"""End-to-end delegated and transformed inter-agent message flow."""

from datetime import UTC, datetime, timedelta

from pydantic import JsonValue

from trustrail import (
    AgentIdentity,
    AgentIdentityKind,
    DelegatedAccessPolicy,
    DelegatedCapability,
    DelegatedIdentityAuthorizer,
    DelegationChain,
    InterAgentMessagePolicy,
    InterAgentMessageSigner,
    InterAgentMessageType,
    InterAgentMessageVerifier,
    InterAgentRoute,
    InterAgentVerificationContext,
    MemoryInterAgentMessageAuditSink,
    StaticDelegatedCapabilityVerifier,
)


def test_delegated_worker_sends_ordered_result_with_coordinator_transformation():
    now = datetime(2026, 9, 12, 16, tzinfo=UTC)
    user = AgentIdentity(
        identity_id="user-a",
        kind=AgentIdentityKind.HUMAN,
        tenant_id="tenant-a",
    )
    coordinator = AgentIdentity(
        identity_id="coordinator-agent",
        kind=AgentIdentityKind.AGENT,
        tenant_id="tenant-a",
    )
    worker = AgentIdentity(
        identity_id="worker-agent",
        kind=AgentIdentityKind.SUB_AGENT,
        tenant_id="tenant-a",
    )
    reviewer = AgentIdentity(
        identity_id="review-agent",
        kind=AgentIdentityKind.AGENT,
        tenant_id="tenant-a",
    )
    root = DelegatedCapability.create(
        capability_id="root-capability",
        issuer=user,
        subject=coordinator,
        scopes=frozenset({"messages:send"}),
        delegatable_scopes=frozenset({"messages:send"}),
        audiences=frozenset({"review-agent"}),
        purpose_id="case-review",
        issued_at=now,
        not_before=now,
        expires_at=now + timedelta(minutes=10),
        max_delegation_depth=1,
    )
    leaf = DelegatedCapability.create(
        capability_id="worker-capability",
        issuer=coordinator,
        subject=worker,
        scopes=frozenset({"messages:send"}),
        audiences=frozenset({"review-agent"}),
        purpose_id="case-review",
        issued_at=now,
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        delegation_depth=1,
        max_delegation_depth=1,
        parent=root,
    )
    chain = DelegationChain(capabilities=(root, leaf))
    identity_authorizer = DelegatedIdentityAuthorizer(
        DelegatedAccessPolicy(
            trusted_root_issuer_ids=frozenset({"user-a"}),
            allowed_audiences=frozenset({"review-agent"}),
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
    policy = InterAgentMessagePolicy(
        routes=(
            InterAgentRoute(
                sender_id="worker-agent",
                recipient_id="review-agent",
                allowed_scopes=frozenset({"messages:send"}),
                allowed_message_types=frozenset(
                    {InterAgentMessageType.TASK_RESULT, InterAgentMessageType.STATUS}
                ),
            ),
        )
    )
    coordinator_signer = InterAgentMessageSigner.generate(identity=coordinator, policy=policy)
    worker_signer = InterAgentMessageSigner.generate(identity=worker, policy=policy)
    raw_result: JsonValue = {"records": ["record-a"], "internal_note": "remove"}
    released_result: JsonValue = {"records": ["record-a"]}
    transformation = coordinator_signer.attest_transformation(
        raw_result,
        released_result,
        operation_id="remove-internal-fields",
        hop_index=0,
        now=now,
    )
    result_message = worker_signer.sign(
        released_result,
        message_type=InterAgentMessageType.TASK_RESULT,
        recipient_ids=("review-agent",),
        session_id="session-a",
        goal_digest="a" * 64,
        task_id="task-a",
        purpose_id="case-review",
        message_scope="messages:send",
        delegation_chain=chain,
        sequence=0,
        transformations=(transformation,),
        now=now,
    )
    status_message = worker_signer.sign(
        {"status": "complete"},
        message_type=InterAgentMessageType.STATUS,
        recipient_ids=("review-agent",),
        session_id="session-a",
        goal_digest="a" * 64,
        task_id="task-a",
        purpose_id="case-review",
        message_scope="messages:send",
        delegation_chain=chain,
        sequence=1,
        now=now,
    )
    context = InterAgentVerificationContext(
        sender_id="worker-agent",
        recipient=reviewer,
        tenant_id="tenant-a",
        session_id="session-a",
        goal_digest="a" * 64,
        task_id="task-a",
        purpose_id="case-review",
        delegation_chain=chain,
    )
    audit_sink = MemoryInterAgentMessageAuditSink()
    verifier = InterAgentMessageVerifier(
        (worker_signer.trusted_key, coordinator_signer.trusted_key),
        identity_authorizer=identity_authorizer,
        policy=policy,
        audit_sink=audit_sink,
    )

    verified_result = verifier.require(result_message, context, now=now)
    verified_status = verifier.require(status_message, context, now=now)

    assert verified_result.payload == released_result
    assert verified_status.payload == {"status": "complete"}
    assert [event.sequence for event in audit_sink.events] == [0, 1]
    assert all("record-a" not in event.model_dump_json() for event in audit_sink.events)

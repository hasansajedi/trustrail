"""Bind a human approval to one complete, immutable high-impact plan."""

from datetime import UTC, datetime, timedelta

from trustrail import (
    ActionParameterPolicy,
    ActionReversibility,
    ApprovalActor,
    ApprovalExecutionContext,
    ApprovalParameterClass,
    ApprovalParameterKind,
    HighImpactActionPolicy,
    HighImpactApprovalGate,
    HighImpactApprovalGrant,
    HighImpactApprovalPolicy,
    HighImpactCategory,
    HighImpactLevel,
    MemoryHighImpactApprovalAuditSink,
    ProposedHighImpactAction,
    ProposedHighImpactPlan,
    StaticHighImpactApprovalVerifier,
)

now = datetime.now(tz=UTC)
action_policy = HighImpactActionPolicy(
    action_id="transfer-funds",
    display_name="Transfer funds",
    categories=frozenset({HighImpactCategory.FINANCIAL}),
    impact=HighImpactLevel.HIGH,
    reversibility=ActionReversibility.IRREVERSIBLE,
    parameters=(
        ActionParameterPolicy(
            name="recipient",
            display_name="Recipient account",
            kind=ApprovalParameterKind.STRING,
            parameter_class=ApprovalParameterClass.RECIPIENT,
        ),
        ActionParameterPolicy(
            name="amount",
            display_name="Amount and currency",
            kind=ApprovalParameterKind.STRING,
            parameter_class=ApprovalParameterClass.AMOUNT,
        ),
        ActionParameterPolicy(
            name="memo",
            display_name="Payment memo",
            kind=ApprovalParameterKind.STRING,
            required=False,
        ),
    ),
    side_effects=("Funds leave the source account",),
)
policy = HighImpactApprovalPolicy(
    policy_id="high-impact-actions",
    policy_version="2026-10-09",
    actions=(action_policy,),
    allowed_approver_ids=frozenset({"reviewer-a"}),
)
plan = ProposedHighImpactPlan(
    plan_id="payment-plan-42",
    actor=ApprovalActor(
        actor_id="finance-agent",
        subject_id="user-a",
        tenant_id="tenant-a",
    ),
    context=ApprovalExecutionContext(
        tenant_id="tenant-a",
        session_id="session-a",
        goal_digest="a" * 64,
        task_id="task-a",
        chain_id="chain-a",
        environment="production",
    ),
    actions=(
        ProposedHighImpactAction(
            action_instance_id="transfer-1",
            action_id="transfer-funds",
            parameters={
                "recipient": "DE89-3704-0044-0532-0130-00",
                "amount": "1250.00 EUR",
            },
        ),
    ),
)

# The static verifier is only a runnable stand-in. A production verifier must
# authenticate the reviewer decision in an independent approval service.
audit = MemoryHighImpactApprovalAuditSink()
gate = HighImpactApprovalGate(
    policy,
    approval_verifier=StaticHighImpactApprovalVerifier({"approval-42"}),
    audit_sink=audit,
)
pending = gate.prepare(plan, now=now)
if pending.preview is None or not pending.requires_approval:
    raise RuntimeError("expected the transfer to require a complete preview")

print(pending.preview.rendered_text)

# In production, send the exact rendered preview and digest to a non-spoofable
# reviewer UI. Never let an agent summarize or truncate this preview.
grant = HighImpactApprovalGrant(
    approval_id="approval-42",
    nonce="approval-nonce-1234567890",
    preview_digest=pending.preview.preview_digest,
    plan_digest=plan.plan_digest,
    actor_id=plan.actor.actor_id,
    tenant_id=plan.actor.tenant_id,
    policy_id=policy.policy_id,
    policy_version=policy.policy_version,
    policy_digest=policy.policy_digest,
    execution_context_digest=plan.context.context_digest,
    approver_id="reviewer-a",
    issued_at=now,
    expires_at=now + timedelta(minutes=2),
)
authorization = gate.require(plan, grant, now=now)

# Execute authorization.plan, not the mutable proposal or reconstructed model
# arguments. Every parameter shown to the reviewer is preserved here.
approved_action = authorization.plan.actions[0]
print("Approved action:", approved_action.action_id)
print("Approved plan digest:", authorization.plan_digest)
print("Content-free approval events:", len(audit.events))

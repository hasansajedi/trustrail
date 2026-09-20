"""End-to-end canonical approval for a multi-step administrative plan."""

from datetime import UTC, datetime, timedelta

from trustrail import (
    ActionParameterPolicy,
    ActionReversibility,
    ApprovalActor,
    ApprovalExecutionContext,
    ApprovalParameterClass,
    ApprovalParameterKind,
    HighImpactActionPolicy,
    HighImpactApprovalCode,
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


def test_user_approves_complete_permission_and_notification_plan_once() -> None:
    now = datetime(2026, 9, 20, 14, tzinfo=UTC)
    policy = HighImpactApprovalPolicy(
        policy_id="admin-change-approval",
        policy_version="v3",
        allowed_approver_ids=frozenset({"admin-reviewer"}),
        actions=(
            HighImpactActionPolicy(
                action_id="grant-role",
                display_name="Grant administrative role",
                categories=frozenset({HighImpactCategory.ADMINISTRATIVE}),
                impact=HighImpactLevel.HIGH,
                reversibility=ActionReversibility.REVERSIBLE,
                parameters=(
                    ActionParameterPolicy(
                        name="recipient",
                        display_name="Role recipient",
                        kind=ApprovalParameterKind.STRING,
                        parameter_class=ApprovalParameterClass.RECIPIENT,
                    ),
                    ActionParameterPolicy(
                        name="scopes",
                        display_name="Granted scopes",
                        kind=ApprovalParameterKind.ARRAY,
                        parameter_class=ApprovalParameterClass.PERMISSION_SCOPE,
                    ),
                ),
                side_effects=("Recipient gains administrative access",),
            ),
            HighImpactActionPolicy(
                action_id="notify-external",
                display_name="Notify external recipient",
                categories=frozenset(
                    {
                        HighImpactCategory.EXTERNAL_VISIBILITY,
                        HighImpactCategory.DATA_DISCLOSURE,
                    }
                ),
                impact=HighImpactLevel.MEDIUM,
                reversibility=ActionReversibility.IRREVERSIBLE,
                parameters=(
                    ActionParameterPolicy(
                        name="recipient",
                        display_name="Message recipient",
                        kind=ApprovalParameterKind.STRING,
                        parameter_class=ApprovalParameterClass.RECIPIENT,
                    ),
                    ActionParameterPolicy(
                        name="disclosed_fields",
                        display_name="Disclosed fields",
                        kind=ApprovalParameterKind.ARRAY,
                        parameter_class=ApprovalParameterClass.DATA_DISCLOSURE,
                    ),
                ),
                external_visibility=True,
                data_disclosure_categories=("account-role",),
            ),
        ),
    )
    plan = ProposedHighImpactPlan(
        plan_id="admin-plan-42",
        actor=ApprovalActor(
            actor_id="admin-agent",
            subject_id="owner-42",
            tenant_id="tenant-a",
        ),
        context=ApprovalExecutionContext(
            tenant_id="tenant-a",
            session_id="session-42",
            goal_digest="c" * 64,
            task_id="task-42",
            chain_id="chain-42",
            environment="production",
        ),
        actions=(
            ProposedHighImpactAction(
                action_instance_id="grant-1",
                action_id="grant-role",
                parameters={
                    "recipient": "operator@example.com",
                    "scopes": ["billing:write", "users:admin"],
                },
            ),
            ProposedHighImpactAction(
                action_instance_id="notify-1",
                action_id="notify-external",
                parameters={
                    "recipient": "auditor@external.example",
                    "disclosed_fields": ["recipient", "scopes"],
                },
            ),
        ),
    )
    audit = MemoryHighImpactApprovalAuditSink()
    gate = HighImpactApprovalGate(
        policy,
        approval_verifier=StaticHighImpactApprovalVerifier({"approval-42"}),
        audit_sink=audit,
    )

    pending = gate.prepare(plan, now=now)
    assert pending.requires_approval
    assert pending.preview is not None
    assert pending.preview.overall_impact == HighImpactLevel.CRITICAL
    assert "operator@example.com" in pending.preview.rendered_text
    assert "billing:write" in pending.preview.rendered_text
    assert "auditor@external.example" in pending.preview.rendered_text

    approval = HighImpactApprovalGrant(
        approval_id="approval-42",
        nonce="approvalnonce-1234567890",
        preview_digest=pending.preview.preview_digest,
        plan_digest=plan.plan_digest,
        actor_id="admin-agent",
        tenant_id="tenant-a",
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_digest=policy.policy_digest,
        execution_context_digest=plan.context.context_digest,
        approver_id="admin-reviewer",
        issued_at=now,
        expires_at=now + timedelta(minutes=2),
    )
    authorization = gate.require(plan, approval, now=now)

    executable_plan = authorization.plan
    assert executable_plan.actions[0].parameters["recipient"] == "operator@example.com"
    assert executable_plan.actions[1].parameters["disclosed_fields"] == [
        "recipient",
        "scopes",
    ]

    replay = gate.authorize(plan, approval, now=now)
    assert replay.is_blocked
    assert replay.findings[0].code == HighImpactApprovalCode.APPROVAL_REPLAYED
    assert all("operator@example.com" not in event.model_dump_json() for event in audit.events)

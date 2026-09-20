"""Bypass regression corpus for high-impact action approvals."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

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
    ProposedHighImpactAction,
    ProposedHighImpactPlan,
    StaticHighImpactApprovalVerifier,
)

NOW = datetime(2026, 9, 20, 12, tzinfo=UTC)
CORPUS_PATH = Path(__file__).parents[1] / "security_corpus" / "high_impact_approval.json"
CASES = json.loads(CORPUS_PATH.read_text())


def _policy(**updates: object) -> HighImpactApprovalPolicy:
    action = HighImpactActionPolicy(
        action_id="wire-transfer",
        display_name="Wire transfer",
        categories=frozenset({HighImpactCategory.FINANCIAL}),
        impact=HighImpactLevel.HIGH,
        reversibility=ActionReversibility.IRREVERSIBLE,
        parameters=(
            ActionParameterPolicy(
                name="recipient",
                display_name="Recipient",
                kind=ApprovalParameterKind.STRING,
                parameter_class=ApprovalParameterClass.RECIPIENT,
            ),
            ActionParameterPolicy(
                name="amount",
                display_name="Amount",
                kind=ApprovalParameterKind.STRING,
                parameter_class=ApprovalParameterClass.AMOUNT,
            ),
            ActionParameterPolicy(
                name="memo",
                display_name="Memo",
                kind=ApprovalParameterKind.STRING,
                required=False,
            ),
        ),
    )
    values: dict[str, object] = {
        "policy_id": "payments",
        "policy_version": "v1",
        "actions": (action,),
        "allowed_approver_ids": frozenset({"reviewer"}),
        "max_repeated_preview_prompts": 1,
    }
    values.update(updates)
    return HighImpactApprovalPolicy(**values)  # type: ignore[arg-type]


def _action(**parameters: object) -> ProposedHighImpactAction:
    values: dict[str, object] = {"recipient": "account-a", "amount": "5000 USD"}
    values.update(parameters)
    return ProposedHighImpactAction(
        action_instance_id="transfer-1",
        action_id="wire-transfer",
        parameters=values,  # type: ignore[arg-type]
    )


def _plan(
    action: ProposedHighImpactAction | None = None,
    *,
    actions: tuple[ProposedHighImpactAction, ...] | None = None,
) -> ProposedHighImpactPlan:
    return ProposedHighImpactPlan(
        plan_id="plan-1",
        actor=ApprovalActor(
            actor_id="payments-agent",
            subject_id="user-1",
            tenant_id="tenant-1",
        ),
        context=ApprovalExecutionContext(
            tenant_id="tenant-1",
            session_id="session-1",
            goal_digest="a" * 64,
            task_id="task-1",
            chain_id="chain-1",
            environment="production",
        ),
        actions=actions or (action or _action(),),
    )


def _grant(preview, plan, policy) -> HighImpactApprovalGrant:
    return HighImpactApprovalGrant(
        approval_id="approval-1",
        nonce="n" * 22,
        preview_digest=preview.preview_digest,
        plan_digest=plan.plan_digest,
        actor_id=plan.actor.actor_id,
        tenant_id=plan.actor.tenant_id,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_digest=policy.policy_digest,
        execution_context_digest=plan.context.context_digest,
        approver_id="reviewer",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
    )


class _UnavailableVerifier:
    def verify_approval(self, approval: HighImpactApprovalGrant) -> bool:
        raise ConnectionError("unavailable")


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_high_impact_approval_bypass_corpus_fails_closed(case) -> None:
    policy = _policy()
    plan = _plan()
    verifier = StaticHighImpactApprovalVerifier({"approval-1"})
    gate = HighImpactApprovalGate(policy, approval_verifier=verifier)
    prepared = gate.prepare(plan, now=NOW)
    assert prepared.preview is not None
    approval = _grant(prepared.preview, plan, policy)
    mutation = case["mutation"]

    if mutation == "hidden_parameter":
        result = gate.authorize(_plan(_action(admin_override=True)), approval, now=NOW)
    elif mutation == "unknown_action":
        unknown = _action().model_copy(update={"action_id": "unregistered-action"})
        result = gate.authorize(_plan(unknown), approval, now=NOW)
    elif mutation == "recipient":
        result = gate.authorize(_plan(_action(recipient="attacker-account")), approval, now=NOW)
    elif mutation == "amount":
        result = gate.authorize(_plan(_action(amount="50000 USD")), approval, now=NOW)
    elif mutation == "extend_plan":
        extra = _action().model_copy(update={"action_instance_id": "transfer-2"})
        result = gate.authorize(_plan(actions=(_action(), extra)), approval, now=NOW)
    elif mutation == "preview_digest":
        result = gate.authorize(
            plan,
            approval.model_copy(update={"preview_digest": "b" * 64}),
            now=NOW,
        )
    elif mutation == "policy":
        result = gate.authorize(
            plan,
            approval.model_copy(update={"policy_version": "downgraded"}),
            now=NOW,
        )
    elif mutation == "actor":
        result = gate.authorize(
            plan,
            approval.model_copy(update={"actor_id": "other-agent"}),
            now=NOW,
        )
    elif mutation == "context":
        result = gate.authorize(
            plan,
            approval.model_copy(update={"execution_context_digest": "b" * 64}),
            now=NOW,
        )
    elif mutation == "approver":
        result = gate.authorize(
            plan,
            approval.model_copy(update={"approver_id": "agent-selected-reviewer"}),
            now=NOW,
        )
    elif mutation == "expired":
        expired = approval.model_copy(update={"expires_at": NOW - timedelta(minutes=1)})
        result = gate.authorize(plan, expired, now=NOW)
    elif mutation == "replay":
        assert gate.authorize(plan, approval, now=NOW).is_authorized
        result = gate.authorize(plan, approval, now=NOW)
    elif mutation == "fatigue":
        result = gate.prepare(plan, now=NOW + timedelta(seconds=1))
    elif mutation == "service_unavailable":
        result = HighImpactApprovalGate(
            policy,
            approval_verifier=_UnavailableVerifier(),
        ).authorize(plan, approval, now=NOW)
    elif mutation == "oversized_preview":
        small_policy = _policy(max_preview_bytes=1_024)
        result = HighImpactApprovalGate(small_policy).prepare(
            _plan(_action(memo="x" * 2_000)),
            now=NOW,
        )
    else:  # pragma: no cover - the corpus is closed and reviewed
        raise AssertionError(f"Unknown corpus mutation: {mutation}")

    assert result.is_blocked
    assert result.findings[0].code == HighImpactApprovalCode(case["expected_code"])
    audit_json = result.audit_event.model_dump_json()
    assert "account-a" not in audit_json
    assert "5000 USD" not in audit_json

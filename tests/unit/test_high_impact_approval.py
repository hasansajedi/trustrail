"""Unit tests for complete, tamper-resistant high-impact approvals."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from trustrail import (
    ActionParameterPolicy,
    ActionReversibility,
    ApprovalActor,
    ApprovalExecutionContext,
    ApprovalParameterClass,
    ApprovalParameterKind,
    GuardAction,
    HighImpactActionPolicy,
    HighImpactApprovalCode,
    HighImpactApprovalError,
    HighImpactApprovalGate,
    HighImpactApprovalGrant,
    HighImpactApprovalPolicy,
    HighImpactCategory,
    HighImpactLevel,
    MemoryHighImpactApprovalAuditSink,
    MemoryHighImpactApprovalStateStore,
    ProposedHighImpactAction,
    ProposedHighImpactPlan,
    StaticHighImpactApprovalVerifier,
    canonical_approval_json,
)

NOW = datetime(2026, 9, 20, 10, tzinfo=UTC)


def _transfer_policy(*, requires_approval: bool = True) -> HighImpactActionPolicy:
    return HighImpactActionPolicy(
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
        requires_approval=requires_approval,
    )


def _publish_policy() -> HighImpactActionPolicy:
    return HighImpactActionPolicy(
        action_id="publish-records",
        display_name="Publish customer records",
        categories=frozenset(
            {HighImpactCategory.EXTERNAL_VISIBILITY, HighImpactCategory.DATA_DISCLOSURE}
        ),
        impact=HighImpactLevel.HIGH,
        reversibility=ActionReversibility.COMPENSATABLE,
        parameters=(
            ActionParameterPolicy(
                name="destination",
                display_name="Public destination",
                kind=ApprovalParameterKind.STRING,
                parameter_class=ApprovalParameterClass.EXTERNAL_VISIBILITY,
            ),
            ActionParameterPolicy(
                name="fields",
                display_name="Disclosed fields",
                kind=ApprovalParameterKind.ARRAY,
                parameter_class=ApprovalParameterClass.DATA_DISCLOSURE,
            ),
            ActionParameterPolicy(
                name="diff",
                display_name="Publication diff",
                kind=ApprovalParameterKind.OBJECT,
                parameter_class=ApprovalParameterClass.DIFF,
            ),
        ),
        side_effects=("Selected records become externally visible",),
        external_visibility=True,
        data_disclosure_categories=("customer-identifiers",),
    )


def _policy(**updates: object) -> HighImpactApprovalPolicy:
    values: dict[str, object] = {
        "policy_id": "high-impact-actions",
        "policy_version": "2026-09-20",
        "actions": (_transfer_policy(), _publish_policy()),
        "allowed_approver_ids": frozenset({"reviewer-a"}),
        "max_preview_bytes": 65_536,
        "max_prompts_per_window": 5,
        "max_repeated_preview_prompts": 2,
    }
    values.update(updates)
    return HighImpactApprovalPolicy(**values)  # type: ignore[arg-type]


def _context(**updates: object) -> ApprovalExecutionContext:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "session_id": "session-a",
        "goal_digest": "a" * 64,
        "task_id": "task-a",
        "chain_id": "chain-a",
        "environment": "production",
    }
    values.update(updates)
    return ApprovalExecutionContext(**values)  # type: ignore[arg-type]


def _transfer(**parameter_updates: object) -> ProposedHighImpactAction:
    parameters: dict[str, object] = {
        "recipient": "DE89-3704-0044-0532-0130-00",
        "amount": "1250.00 EUR",
    }
    parameters.update(parameter_updates)
    return ProposedHighImpactAction(
        action_instance_id="transfer-1",
        action_id="transfer-funds",
        parameters=parameters,  # type: ignore[arg-type]
    )


def _plan(
    *,
    actions: tuple[ProposedHighImpactAction, ...] | None = None,
    actor: ApprovalActor | None = None,
    context: ApprovalExecutionContext | None = None,
    plan_id: str = "plan-a",
) -> ProposedHighImpactPlan:
    return ProposedHighImpactPlan(
        plan_id=plan_id,
        actor=actor
        or ApprovalActor(actor_id="finance-agent", subject_id="user-a", tenant_id="tenant-a"),
        context=context or _context(),
        actions=actions or (_transfer(),),
    )


def _grant(
    preview,
    plan: ProposedHighImpactPlan,
    policy: HighImpactApprovalPolicy,
    **updates: object,
) -> HighImpactApprovalGrant:
    values: dict[str, object] = {
        "approval_id": "approval-a",
        "nonce": "n" * 22,
        "preview_digest": preview.preview_digest,
        "plan_digest": plan.plan_digest,
        "actor_id": plan.actor.actor_id,
        "tenant_id": plan.actor.tenant_id,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "policy_digest": policy.policy_digest,
        "execution_context_digest": plan.context.context_digest,
        "approver_id": "reviewer-a",
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=2),
    }
    values.update(updates)
    return HighImpactApprovalGrant(**values)  # type: ignore[arg-type]


def _prepared(
    policy: HighImpactApprovalPolicy | None = None,
    plan: ProposedHighImpactPlan | None = None,
    **gate_kwargs: object,
):
    configured_policy = policy or _policy()
    proposed_plan = plan or _plan()
    gate = HighImpactApprovalGate(configured_policy, **gate_kwargs)  # type: ignore[arg-type]
    result = gate.prepare(proposed_plan, now=NOW)
    assert result.preview is not None
    return configured_policy, proposed_plan, gate, result


def test_preview_is_complete_deterministic_and_highlights_sensitive_fields() -> None:
    policy, plan, _, first = _prepared()
    _, reordered_plan, _, second = _prepared(
        policy=policy,
        plan=_plan(
            actions=(
                ProposedHighImpactAction(
                    action_instance_id="transfer-1",
                    action_id="transfer-funds",
                    parameters={
                        "amount": "1250.00 EUR",
                        "recipient": "DE89-3704-0044-0532-0130-00",
                    },
                ),
            )
        ),
    )

    assert first.action == GuardAction.REQUIRE_APPROVAL
    assert first.preview is not None and second.preview is not None
    assert first.preview.preview_digest == second.preview.preview_digest
    assert plan.plan_digest == reordered_plan.plan_digest
    text = first.preview.rendered_text
    assert "[RECIPIENT] Recipient account" in text
    assert "[AMOUNT] Amount and currency" in text
    assert "[NOT PROVIDED]" in text
    assert "NOT TRUNCATED" in text
    assert "1250.00 EUR" in text
    assert policy.policy_digest in text


def test_complete_multistep_plan_escalates_chain_impact() -> None:
    publish = ProposedHighImpactAction(
        action_instance_id="publish-1",
        action_id="publish-records",
        parameters={
            "destination": "https://public.example/reports",
            "fields": ["customer_id", "balance"],
            "diff": {"added": ["customer_id", "balance"], "removed": []},
        },
    )
    _, _, _, result = _prepared(plan=_plan(actions=(_transfer(), publish)))

    assert result.preview is not None
    assert result.preview.overall_impact == HighImpactLevel.CRITICAL
    assert result.preview.chain_impact_escalated
    assert "ACTION 1" in result.preview.rendered_text
    assert "ACTION 2" in result.preview.rendered_text
    assert "DATA DISCLOSURE" in result.preview.rendered_text
    assert "External visibility: YES" in result.preview.rendered_text


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        (
            ProposedHighImpactAction(
                action_instance_id="transfer-1",
                action_id="transfer-funds",
                parameters={
                    "recipient": "account-a",
                    "amount": "10 EUR",
                    "hidden_fee": "900 EUR",
                },
            ),
            HighImpactApprovalCode.HIDDEN_PARAMETER,
        ),
        (
            ProposedHighImpactAction(
                action_instance_id="transfer-1",
                action_id="transfer-funds",
                parameters={"recipient": "account-a"},
            ),
            HighImpactApprovalCode.REQUIRED_PARAMETER_MISSING,
        ),
        (
            ProposedHighImpactAction(
                action_instance_id="transfer-1",
                action_id="transfer-funds",
                parameters={"recipient": "account-a", "amount": 10},
            ),
            HighImpactApprovalCode.PARAMETER_TYPE_MISMATCH,
        ),
        (
            ProposedHighImpactAction(
                action_instance_id="action-1",
                action_id="unknown-action",
                parameters={},
            ),
            HighImpactApprovalCode.UNKNOWN_ACTION,
        ),
    ],
)
def test_unsafe_or_incomplete_action_fields_fail_closed(action, expected) -> None:
    gate = HighImpactApprovalGate(_policy())

    result = gate.prepare(_plan(actions=(action,)), now=NOW)

    assert result.is_blocked
    assert result.findings[0].code == expected
    assert result.preview is None


def test_oversized_preview_is_rejected_instead_of_truncated() -> None:
    policy = _policy(max_preview_bytes=1_024)
    action = _transfer(memo="x" * 2_000)

    result = HighImpactApprovalGate(policy).prepare(_plan(actions=(action,)), now=NOW)

    assert result.is_blocked
    assert result.findings[0].code == HighImpactApprovalCode.PREVIEW_TOO_LARGE
    assert result.preview is None


def test_exact_approval_returns_immutable_execution_snapshot_and_safe_audit() -> None:
    sink = MemoryHighImpactApprovalAuditSink()
    policy, plan, gate, prepared = _prepared(
        approval_verifier=StaticHighImpactApprovalVerifier({"approval-a"}),
        audit_sink=sink,
    )
    approval = _grant(prepared.preview, plan, policy)

    authorization = gate.require(plan, approval, now=NOW)

    assert authorization.plan == plan
    assert authorization.approval_id == "approval-a"
    assert authorization.plan_digest == plan.plan_digest
    audit_json = "".join(event.model_dump_json() for event in sink.events)
    assert "1250.00 EUR" not in audit_json
    assert "DE89" not in audit_json
    assert "finance-agent" not in audit_json
    assert [event.code for event in sink.events] == [
        HighImpactApprovalCode.APPROVAL_REQUIRED,
        HighImpactApprovalCode.VERIFIED,
    ]


@pytest.mark.parametrize(
    ("update", "expected"),
    [
        ({"preview_digest": "b" * 64}, HighImpactApprovalCode.PREVIEW_MISMATCH),
        ({"plan_digest": "b" * 64}, HighImpactApprovalCode.PLAN_MISMATCH),
        ({"policy_version": "old"}, HighImpactApprovalCode.POLICY_MISMATCH),
        ({"policy_digest": "b" * 64}, HighImpactApprovalCode.POLICY_MISMATCH),
        ({"actor_id": "other-agent"}, HighImpactApprovalCode.ACTOR_MISMATCH),
        (
            {"execution_context_digest": "b" * 64},
            HighImpactApprovalCode.EXECUTION_CONTEXT_MISMATCH,
        ),
        ({"approver_id": "untrusted-reviewer"}, HighImpactApprovalCode.APPROVER_DENIED),
    ],
)
def test_approval_bindings_reject_substitution(update, expected) -> None:
    policy, plan, gate, prepared = _prepared(
        approval_verifier=StaticHighImpactApprovalVerifier({"approval-a"})
    )
    approval = _grant(prepared.preview, plan, policy).model_copy(update=update)

    result = gate.authorize(plan, approval, now=NOW)

    assert result.is_blocked
    assert result.findings[0].code == expected


def test_parameter_mutation_after_preview_requires_new_approval() -> None:
    policy, plan, gate, prepared = _prepared(
        approval_verifier=StaticHighImpactApprovalVerifier({"approval-a"})
    )
    approval = _grant(prepared.preview, plan, policy)
    changed = _plan(actions=(_transfer(amount="9999.00 EUR"),))

    result = gate.authorize(changed, approval, now=NOW)

    assert result.is_blocked
    assert result.findings[0].code == HighImpactApprovalCode.PREVIEW_MISMATCH


def test_plan_extension_after_preview_requires_new_approval() -> None:
    policy, plan, gate, prepared = _prepared(
        approval_verifier=StaticHighImpactApprovalVerifier({"approval-a"})
    )
    approval = _grant(prepared.preview, plan, policy)
    added = _transfer().model_copy(update={"action_instance_id": "transfer-2"})
    changed = _plan(actions=(_transfer(), added))

    result = gate.authorize(changed, approval, now=NOW)

    assert result.is_blocked
    assert result.findings[0].code == HighImpactApprovalCode.PREVIEW_MISMATCH


@pytest.mark.parametrize(
    ("updates", "now", "expected"),
    [
        (
            {"expires_at": NOW + timedelta(seconds=10)},
            NOW + timedelta(minutes=1),
            HighImpactApprovalCode.APPROVAL_EXPIRED,
        ),
        (
            {"issued_at": NOW + timedelta(minutes=2), "expires_at": NOW + timedelta(minutes=3)},
            NOW,
            HighImpactApprovalCode.APPROVAL_NOT_YET_VALID,
        ),
        (
            {"expires_at": NOW + timedelta(minutes=10)},
            NOW,
            HighImpactApprovalCode.APPROVAL_TTL_EXCEEDED,
        ),
    ],
)
def test_approval_time_window_is_enforced(updates, now, expected) -> None:
    policy, plan, gate, prepared = _prepared(
        approval_verifier=StaticHighImpactApprovalVerifier({"approval-a"})
    )
    approval = _grant(prepared.preview, plan, policy, **updates)

    result = gate.authorize(plan, approval, now=now)

    assert result.is_blocked
    assert result.findings[0].code == expected


class _FailingVerifier:
    def verify_approval(self, approval: HighImpactApprovalGrant) -> bool:
        raise OSError("approval database is unavailable")


@pytest.mark.parametrize("verifier", [None, _FailingVerifier()])
def test_unavailable_approval_service_fails_closed(verifier) -> None:
    policy, plan, gate, prepared = _prepared(approval_verifier=verifier)
    approval = _grant(prepared.preview, plan, policy)

    result = gate.authorize(plan, approval, now=NOW)

    assert result.is_blocked
    assert result.findings[0].code == HighImpactApprovalCode.APPROVAL_SERVICE_UNAVAILABLE


def test_invalid_authenticated_approval_fails_closed() -> None:
    policy, plan, gate, prepared = _prepared(
        approval_verifier=StaticHighImpactApprovalVerifier(set())
    )
    approval = _grant(prepared.preview, plan, policy)

    result = gate.authorize(plan, approval, now=NOW)

    assert result.is_blocked
    assert result.findings[0].code == HighImpactApprovalCode.APPROVAL_INVALID


def test_approval_nonce_is_single_use_and_atomic() -> None:
    policy, plan, gate, prepared = _prepared(
        approval_verifier=StaticHighImpactApprovalVerifier({"approval-a"})
    )
    approval = _grant(prepared.preview, plan, policy)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: gate.authorize(plan, approval, now=NOW), range(16)))

    assert sum(result.is_authorized for result in results) == 1
    assert (
        sum(
            result.is_blocked
            and result.findings[0].code == HighImpactApprovalCode.APPROVAL_REPLAYED
            for result in results
        )
        == 15
    )


def test_repeated_preview_requests_trigger_approval_fatigue_block() -> None:
    gate = HighImpactApprovalGate(_policy(max_repeated_preview_prompts=2))
    plan = _plan()

    assert gate.prepare(plan, now=NOW).requires_approval
    assert gate.prepare(plan, now=NOW + timedelta(seconds=1)).requires_approval
    blocked = gate.prepare(plan, now=NOW + timedelta(seconds=2))

    assert blocked.is_blocked
    assert blocked.findings[0].code == HighImpactApprovalCode.APPROVAL_FATIGUE


def test_total_prompt_rate_triggers_approval_fatigue_block() -> None:
    gate = HighImpactApprovalGate(
        _policy(max_prompts_per_window=2, max_repeated_preview_prompts=10)
    )

    assert gate.prepare(_plan(plan_id="plan-1"), now=NOW).requires_approval
    assert gate.prepare(_plan(plan_id="plan-2"), now=NOW).requires_approval
    blocked = gate.prepare(_plan(plan_id="plan-3"), now=NOW)

    assert blocked.is_blocked
    assert blocked.findings[0].code == HighImpactApprovalCode.APPROVAL_FATIGUE


class _BrokenStateStore:
    def record_prompt(self, *args, **kwargs):
        raise OSError("state unavailable")

    def claim_approval(self, *args, **kwargs):
        raise OSError("state unavailable")


def test_state_store_failures_and_capacity_fail_closed() -> None:
    broken = HighImpactApprovalGate(_policy(), state_store=_BrokenStateStore())
    prompt_result = broken.prepare(_plan(), now=NOW)
    assert prompt_result.findings[0].code == HighImpactApprovalCode.STATE_STORE_ERROR

    state = MemoryHighImpactApprovalStateStore(max_approval_nonces=1)
    verifier = StaticHighImpactApprovalVerifier({"approval-a", "approval-b"})
    policy, first_plan, gate, prepared = _prepared(
        state_store=state,
        approval_verifier=verifier,
    )
    assert gate.authorize(
        first_plan,
        _grant(prepared.preview, first_plan, policy),
        now=NOW,
    ).is_authorized

    second_plan = _plan(plan_id="plan-b")
    second_preview = gate.prepare(second_plan, now=NOW).preview
    assert second_preview is not None
    second = _grant(
        second_preview,
        second_plan,
        policy,
        approval_id="approval-b",
        nonce="z" * 22,
    )
    capacity_result = gate.authorize(second_plan, second, now=NOW)
    assert capacity_result.findings[0].code == HighImpactApprovalCode.STATE_STORE_FULL


def test_non_approval_action_returns_exact_authorization_directly() -> None:
    low_action = _transfer_policy(requires_approval=False).model_copy(
        update={
            "impact": HighImpactLevel.LOW,
            "reversibility": ActionReversibility.REVERSIBLE,
        }
    )
    policy = _policy(actions=(low_action,))
    gate = HighImpactApprovalGate(policy)

    result = gate.prepare(_plan(), now=NOW)

    assert result.is_authorized
    assert result.authorization is not None
    assert result.authorization.approval_id is None
    assert result.authorization.plan == _plan()
    assert result.audit_event.code == HighImpactApprovalCode.APPROVAL_NOT_REQUIRED


def test_require_raises_with_content_free_result() -> None:
    policy, plan, gate, prepared = _prepared()
    approval = _grant(prepared.preview, plan, policy)

    with pytest.raises(HighImpactApprovalError) as exc_info:
        gate.require(plan, approval, now=NOW)

    assert exc_info.value.result.findings[0].code == (
        HighImpactApprovalCode.APPROVAL_SERVICE_UNAVAILABLE
    )
    assert "1250.00" not in str(exc_info.value)


def test_models_reject_ambiguous_or_unsafe_input() -> None:
    with pytest.raises(ValidationError):
        ActionParameterPolicy(
            name="recipient",
            display_name="Recipient\u202eaccount",
            kind=ApprovalParameterKind.STRING,
        )
    with pytest.raises(ValidationError):
        ProposedHighImpactPlan(
            plan_id="plan-a",
            actor=ApprovalActor(
                actor_id="agent",
                subject_id="user",
                tenant_id="tenant-a",
            ),
            context=_context(tenant_id="tenant-b"),
            actions=(_transfer(),),
        )
    with pytest.raises(ValueError, match="unique"):
        canonical_approval_json({"e\u0301": 1, "é": 2})

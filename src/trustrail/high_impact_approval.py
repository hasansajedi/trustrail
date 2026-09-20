"""Complete, canonical, and tamper-resistant approval for high-impact plans."""

from __future__ import annotations

import contextlib
import json
import math
import threading
import uuid
from collections import defaultdict, deque
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Literal, Protocol

from pydantic import JsonValue

from trustrail.exceptions import HighImpactApprovalError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.high_impact_approval import (
    ActionParameterPolicy,
    ApprovalParameterClass,
    ApprovalParameterKind,
    AuthorizedHighImpactPlan,
    HighImpactActionPolicy,
    HighImpactActionPreview,
    HighImpactApprovalAuditEvent,
    HighImpactApprovalCode,
    HighImpactApprovalFinding,
    HighImpactApprovalGrant,
    HighImpactApprovalOperation,
    HighImpactApprovalPolicy,
    HighImpactApprovalResult,
    HighImpactApprovalStateStatus,
    HighImpactLevel,
    HighImpactPlanPreview,
    ProposedHighImpactAction,
    ProposedHighImpactPlan,
    approval_reference,
    canonical_approval_json,
    utcnow,
)

_IMPACT_RANK = {
    HighImpactLevel.LOW: 0,
    HighImpactLevel.MEDIUM: 1,
    HighImpactLevel.HIGH: 2,
    HighImpactLevel.CRITICAL: 3,
}
_IMPACT_BY_RANK = {rank: level for level, rank in _IMPACT_RANK.items()}
_HIGHLIGHT_TITLES = {
    ApprovalParameterClass.RECIPIENT: "RECIPIENT",
    ApprovalParameterClass.AMOUNT: "AMOUNT",
    ApprovalParameterClass.PERMISSION_SCOPE: "PERMISSION SCOPE",
    ApprovalParameterClass.COMMAND: "COMMAND",
    ApprovalParameterClass.DIFF: "DIFF",
    ApprovalParameterClass.EXTERNAL_VISIBILITY: "EXTERNAL VISIBILITY",
    ApprovalParameterClass.DATA_DISCLOSURE: "DATA DISCLOSURE",
    ApprovalParameterClass.STANDARD: "PARAMETER",
}


class HighImpactApprovalVerifier(Protocol):
    """Authenticate an approval issued by an independent trusted service."""

    def verify_approval(self, approval: HighImpactApprovalGrant) -> bool:
        """Return whether the approval service issued this exact grant."""
        ...


class HighImpactApprovalStateStore(Protocol):
    """Atomically track approval prompts and consume single-use nonces."""

    def record_prompt(
        self,
        fatigue_key: str,
        preview_digest: str,
        *,
        now: datetime,
        window_seconds: int,
        max_prompts: int,
        max_repeated_preview_prompts: int,
    ) -> HighImpactApprovalStateStatus:
        """Record a prompt or reject an approval-fatigue pattern."""
        ...

    def claim_approval(
        self,
        replay_key: str,
        *,
        expires_at: datetime,
        now: datetime,
    ) -> HighImpactApprovalStateStatus:
        """Atomically consume a single-use approval nonce."""
        ...


class HighImpactApprovalAuditSink(Protocol):
    """Persist content-free approval evidence."""

    def emit(self, event: HighImpactApprovalAuditEvent) -> None:
        """Persist one preview or authorization event."""
        ...


class StaticHighImpactApprovalVerifier:
    """Deterministic approval verifier for tests and small examples only."""

    def __init__(self, approval_ids: Iterable[str]) -> None:
        self._approval_ids = frozenset(approval_ids)

    def verify_approval(self, approval: HighImpactApprovalGrant) -> bool:
        return approval.approval_id in self._approval_ids


class MemoryHighImpactApprovalAuditSink:
    """Bounded process-local audit sink for tests and development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[HighImpactApprovalAuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def emit(self, event: HighImpactApprovalAuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> list[HighImpactApprovalAuditEvent]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


class MemoryHighImpactApprovalStateStore:
    """Capacity-bounded process-local fatigue and replay state."""

    def __init__(
        self, *, max_fatigue_keys: int = 10_000, max_approval_nonces: int = 100_000
    ) -> None:
        if max_fatigue_keys < 1:
            raise ValueError("max_fatigue_keys must be at least 1")
        if max_approval_nonces < 1:
            raise ValueError("max_approval_nonces must be at least 1")
        self._max_fatigue_keys = max_fatigue_keys
        self._max_approval_nonces = max_approval_nonces
        self._prompts: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
        self._approvals: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def record_prompt(
        self,
        fatigue_key: str,
        preview_digest: str,
        *,
        now: datetime,
        window_seconds: int,
        max_prompts: int,
        max_repeated_preview_prompts: int,
    ) -> HighImpactApprovalStateStatus:
        if now.tzinfo is None:
            raise ValueError("prompt timestamp must be timezone-aware")
        cutoff = now - timedelta(seconds=window_seconds)
        with self._lock:
            for key, prompts in tuple(self._prompts.items()):
                while prompts and prompts[0][0] <= cutoff:
                    prompts.popleft()
                if not prompts:
                    del self._prompts[key]
            existing = self._prompts.get(fatigue_key)
            if existing is None:
                if len(self._prompts) >= self._max_fatigue_keys:
                    return HighImpactApprovalStateStatus.FULL
                existing = deque()
                self._prompts[fatigue_key] = existing
            repeated = sum(digest == preview_digest for _, digest in existing)
            if len(existing) >= max_prompts or repeated >= max_repeated_preview_prompts:
                return HighImpactApprovalStateStatus.FATIGUE
            existing.append((now, preview_digest))
            return HighImpactApprovalStateStatus.STORED

    def claim_approval(
        self,
        replay_key: str,
        *,
        expires_at: datetime,
        now: datetime,
    ) -> HighImpactApprovalStateStatus:
        if expires_at.tzinfo is None or now.tzinfo is None:
            raise ValueError("approval state timestamps must be timezone-aware")
        if expires_at <= now:
            raise ValueError("approval state expiration must be in the future")
        with self._lock:
            self._approvals = {
                key: expiry for key, expiry in self._approvals.items() if expiry > now
            }
            if replay_key in self._approvals:
                return HighImpactApprovalStateStatus.REPLAYED
            if len(self._approvals) >= self._max_approval_nonces:
                return HighImpactApprovalStateStatus.FULL
            self._approvals[replay_key] = expires_at
            return HighImpactApprovalStateStatus.STORED

    def clear(self) -> None:
        with self._lock:
            self._prompts.clear()
            self._approvals.clear()


class HighImpactApprovalGate:
    """Fail-closed canonical preview and exact approval boundary."""

    def __init__(
        self,
        policy: HighImpactApprovalPolicy,
        *,
        approval_verifier: HighImpactApprovalVerifier | None = None,
        state_store: HighImpactApprovalStateStore | None = None,
        audit_sink: HighImpactApprovalAuditSink | None = None,
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._actions = {action.action_id: action for action in self._policy.actions}
        self._approval_verifier = approval_verifier
        self._state_store = state_store or MemoryHighImpactApprovalStateStore()
        self._audit_sink = audit_sink

    @property
    def policy(self) -> HighImpactApprovalPolicy:
        """Return an immutable copy of the configured policy."""
        return self._policy.model_copy(deep=True)

    def prepare(
        self,
        plan: ProposedHighImpactPlan,
        *,
        now: datetime | None = None,
    ) -> HighImpactApprovalResult:
        """Build a complete preview and atomically enforce prompt-fatigue limits."""
        current_time = now or utcnow()
        preview, finding = self._build_preview(plan)
        if finding is not None or preview is None:
            return self._blocked(
                plan,
                HighImpactApprovalOperation.PREVIEW,
                current_time,
                finding
                or self._finding(
                    HighImpactApprovalCode.APPROVAL_INVALID,
                    "High-impact preview could not be constructed",
                ),
            )

        if not preview.approval_required:
            authorization = self._authorization(
                plan,
                preview,
                approval=None,
                expires_at=current_time + timedelta(seconds=self._policy.max_approval_ttl_seconds),
            )
            return self._result(
                plan,
                preview,
                HighImpactApprovalOperation.PREVIEW,
                GuardAction.ALLOW,
                HighImpactApprovalCode.APPROVAL_NOT_REQUIRED,
                current_time,
                authorization=authorization,
            )

        fatigue_key = approval_reference(
            canonical_approval_json(
                {
                    "actor_id": plan.actor.actor_id,
                    "session_id": plan.context.session_id,
                    "tenant_id": plan.actor.tenant_id,
                }
            )
        )
        try:
            status = self._state_store.record_prompt(
                fatigue_key,
                preview.preview_digest,
                now=current_time,
                window_seconds=self._policy.prompt_window_seconds,
                max_prompts=self._policy.max_prompts_per_window,
                max_repeated_preview_prompts=self._policy.max_repeated_preview_prompts,
            )
        except Exception:
            return self._blocked(
                plan,
                HighImpactApprovalOperation.PREVIEW,
                current_time,
                self._finding(
                    HighImpactApprovalCode.STATE_STORE_ERROR,
                    "Approval prompt state is unavailable",
                ),
                preview=preview,
            )
        if status == HighImpactApprovalStateStatus.FATIGUE:
            return self._blocked(
                plan,
                HighImpactApprovalOperation.PREVIEW,
                current_time,
                self._finding(
                    HighImpactApprovalCode.APPROVAL_FATIGUE,
                    "Approval prompt rate or repetition limit was exceeded",
                ),
                preview=preview,
            )
        if status == HighImpactApprovalStateStatus.FULL:
            return self._blocked(
                plan,
                HighImpactApprovalOperation.PREVIEW,
                current_time,
                self._finding(
                    HighImpactApprovalCode.STATE_STORE_FULL,
                    "Approval prompt state is at capacity",
                ),
                preview=preview,
            )
        return self._result(
            plan,
            preview,
            HighImpactApprovalOperation.PREVIEW,
            GuardAction.REQUIRE_APPROVAL,
            HighImpactApprovalCode.APPROVAL_REQUIRED,
            current_time,
            finding=self._finding(
                HighImpactApprovalCode.APPROVAL_REQUIRED,
                "Complete high-impact plan requires exact independent approval",
                severity=Severity.HIGH,
            ),
        )

    def authorize(
        self,
        plan: ProposedHighImpactPlan,
        approval: HighImpactApprovalGrant | None,
        *,
        now: datetime | None = None,
    ) -> HighImpactApprovalResult:
        """Verify and consume one approval before returning an immutable plan lease."""
        current_time = now or utcnow()
        preview, finding = self._build_preview(plan)
        if finding is not None or preview is None:
            return self._blocked(
                plan,
                HighImpactApprovalOperation.AUTHORIZE,
                current_time,
                finding
                or self._finding(
                    HighImpactApprovalCode.APPROVAL_INVALID,
                    "High-impact preview could not be reconstructed",
                ),
            )
        if not preview.approval_required:
            authorization = self._authorization(
                plan,
                preview,
                approval=None,
                expires_at=current_time + timedelta(seconds=self._policy.max_approval_ttl_seconds),
            )
            return self._result(
                plan,
                preview,
                HighImpactApprovalOperation.AUTHORIZE,
                GuardAction.ALLOW,
                HighImpactApprovalCode.APPROVAL_NOT_REQUIRED,
                current_time,
                authorization=authorization,
            )
        if approval is None:
            return self._result(
                plan,
                preview,
                HighImpactApprovalOperation.AUTHORIZE,
                GuardAction.REQUIRE_APPROVAL,
                HighImpactApprovalCode.APPROVAL_REQUIRED,
                current_time,
                finding=self._finding(
                    HighImpactApprovalCode.APPROVAL_REQUIRED,
                    "Exact approval is required before this plan can execute",
                    severity=Severity.HIGH,
                ),
            )

        binding_failure = self._approval_binding_failure(plan, preview, approval, current_time)
        if binding_failure is not None:
            return self._blocked(
                plan,
                HighImpactApprovalOperation.AUTHORIZE,
                current_time,
                binding_failure,
                preview=preview,
                approval=approval,
            )
        if self._approval_verifier is None:
            return self._blocked(
                plan,
                HighImpactApprovalOperation.AUTHORIZE,
                current_time,
                self._finding(
                    HighImpactApprovalCode.APPROVAL_SERVICE_UNAVAILABLE,
                    "No authenticated approval verifier is configured",
                ),
                preview=preview,
                approval=approval,
            )
        try:
            authentic = self._approval_verifier.verify_approval(approval)
        except Exception:
            return self._blocked(
                plan,
                HighImpactApprovalOperation.AUTHORIZE,
                current_time,
                self._finding(
                    HighImpactApprovalCode.APPROVAL_SERVICE_UNAVAILABLE,
                    "Authenticated approval service is unavailable",
                ),
                preview=preview,
                approval=approval,
            )
        if not authentic:
            return self._blocked(
                plan,
                HighImpactApprovalOperation.AUTHORIZE,
                current_time,
                self._finding(
                    HighImpactApprovalCode.APPROVAL_INVALID,
                    "Approval grant is not authentic",
                ),
                preview=preview,
                approval=approval,
            )

        replay_key = approval_reference(
            canonical_approval_json({"nonce": approval.nonce, "tenant_id": approval.tenant_id})
        )
        try:
            status = self._state_store.claim_approval(
                replay_key,
                expires_at=approval.expires_at + timedelta(seconds=self._policy.clock_skew_seconds),
                now=current_time,
            )
        except Exception:
            return self._blocked(
                plan,
                HighImpactApprovalOperation.AUTHORIZE,
                current_time,
                self._finding(
                    HighImpactApprovalCode.STATE_STORE_ERROR,
                    "Approval replay state is unavailable",
                ),
                preview=preview,
                approval=approval,
            )
        if status == HighImpactApprovalStateStatus.REPLAYED:
            return self._blocked(
                plan,
                HighImpactApprovalOperation.AUTHORIZE,
                current_time,
                self._finding(
                    HighImpactApprovalCode.APPROVAL_REPLAYED,
                    "Approval nonce has already been consumed",
                ),
                preview=preview,
                approval=approval,
            )
        if status == HighImpactApprovalStateStatus.FULL:
            return self._blocked(
                plan,
                HighImpactApprovalOperation.AUTHORIZE,
                current_time,
                self._finding(
                    HighImpactApprovalCode.STATE_STORE_FULL,
                    "Approval replay state is at capacity",
                ),
                preview=preview,
                approval=approval,
            )

        authorization = self._authorization(
            plan,
            preview,
            approval=approval,
            expires_at=approval.expires_at,
        )
        return self._result(
            plan,
            preview,
            HighImpactApprovalOperation.AUTHORIZE,
            GuardAction.ALLOW,
            HighImpactApprovalCode.VERIFIED,
            current_time,
            authorization=authorization,
            approval=approval,
        )

    def require(
        self,
        plan: ProposedHighImpactPlan,
        approval: HighImpactApprovalGrant | None,
        *,
        now: datetime | None = None,
    ) -> AuthorizedHighImpactPlan:
        """Return the exact authorized snapshot or raise before execution."""
        result = self.authorize(plan, approval, now=now)
        if not result.is_authorized or result.authorization is None:
            raise HighImpactApprovalError(result=result)
        return result.authorization

    def _build_preview(
        self,
        plan: ProposedHighImpactPlan,
    ) -> tuple[HighImpactPlanPreview | None, HighImpactApprovalFinding | None]:
        if plan.actor.tenant_id != plan.context.tenant_id:
            return None, self._finding(
                HighImpactApprovalCode.ACTOR_CONTEXT_MISMATCH,
                "Approval actor and execution context belong to different tenants",
            )
        if len(plan.actions) > self._policy.max_plan_actions:
            return None, self._finding(
                HighImpactApprovalCode.PREVIEW_TOO_LARGE,
                "Complete plan exceeds the configured action limit and cannot be truncated",
            )

        action_previews: list[HighImpactActionPreview] = []
        action_lines: list[str] = []
        impacts: list[HighImpactLevel] = []
        approval_required = False
        for index, action in enumerate(plan.actions, start=1):
            policy = self._actions.get(action.action_id)
            if policy is None:
                return None, self._finding(
                    HighImpactApprovalCode.UNKNOWN_ACTION,
                    "Plan contains an action absent from trusted approval policy",
                )
            validation = self._parameter_finding(action, policy)
            if validation is not None:
                return None, validation
            try:
                parameter_json = canonical_approval_json(action.parameters)
            except (TypeError, ValueError):
                return None, self._finding(
                    HighImpactApprovalCode.PARAMETER_TYPE_MISMATCH,
                    "Action parameters cannot be canonicalized safely",
                )
            impacts.append(policy.impact)
            approval_required = approval_required or policy.requires_approval
            action_previews.append(
                HighImpactActionPreview(
                    action_instance_id=action.action_instance_id,
                    action_id=action.action_id,
                    display_name=policy.display_name,
                    categories=tuple(sorted(policy.categories, key=lambda item: item.value)),
                    impact=policy.impact,
                    reversibility=policy.reversibility,
                    parameter_digest=approval_reference(parameter_json).removeprefix("sha256:"),
                    requires_approval=policy.requires_approval,
                )
            )
            action_lines.extend(self._render_action(index, action, policy))

        overall_impact, escalated = self._overall_impact(impacts)
        policy_digest = self._policy.policy_digest
        context = plan.context
        header = [
            "=== COMPLETE HIGH-IMPACT ACTION APPROVAL ===",
            f"Policy: {self._policy.policy_id}@{self._policy.policy_version}",
            f"Policy digest: {policy_digest}",
            f"Plan ID: {plan.plan_id}",
            f"Plan digest: {plan.plan_digest}",
            f"Actor: {plan.actor.actor_id}",
            f"Represented subject: {plan.actor.subject_id}",
            f"Tenant: {plan.actor.tenant_id}",
            f"Session: {context.session_id}",
            f"Goal digest: {context.goal_digest}",
            f"Task: {context.task_id}",
            f"Chain: {context.chain_id}",
            f"Environment: {context.environment}",
            f"Overall impact: {overall_impact.value.upper()}",
            f"Chain impact escalated: {'YES' if escalated else 'NO'}",
            f"Action count: {len(plan.actions)}",
            "--- ACTIONS (FULL, ORDERED, NOT TRUNCATED) ---",
        ]
        footer = [
            "--- END OF COMPLETE PLAN ---",
            "Approval authorizes this exact preview once; any change requires a new approval.",
        ]
        rendered_text = "\n".join([*header, *action_lines, *footer])
        if len(rendered_text.encode()) > self._policy.max_preview_bytes:
            return None, self._finding(
                HighImpactApprovalCode.PREVIEW_TOO_LARGE,
                "Complete approval preview exceeds the byte limit and cannot be truncated",
            )
        preview_digest = approval_reference(rendered_text).removeprefix("sha256:")
        return (
            HighImpactPlanPreview(
                plan_id=plan.plan_id,
                policy_id=self._policy.policy_id,
                policy_version=self._policy.policy_version,
                policy_digest=policy_digest,
                plan_digest=plan.plan_digest,
                actor_id=plan.actor.actor_id,
                tenant_id=plan.actor.tenant_id,
                execution_context_digest=plan.context.context_digest,
                overall_impact=overall_impact,
                chain_impact_escalated=escalated,
                approval_required=approval_required,
                actions=tuple(action_previews),
                rendered_text=rendered_text,
                preview_digest=preview_digest,
            ),
            None,
        )

    def _parameter_finding(
        self,
        action: ProposedHighImpactAction,
        policy: HighImpactActionPolicy,
    ) -> HighImpactApprovalFinding | None:
        declared = {parameter.name: parameter for parameter in policy.parameters}
        unknown = set(action.parameters).difference(declared)
        if unknown:
            return self._finding(
                HighImpactApprovalCode.HIDDEN_PARAMETER,
                "Action contains a field absent from the complete preview schema",
            )
        missing = {
            parameter.name
            for parameter in policy.parameters
            if parameter.required and parameter.name not in action.parameters
        }
        if missing:
            return self._finding(
                HighImpactApprovalCode.REQUIRED_PARAMETER_MISSING,
                "Action omits a required preview field",
            )
        if len(action.parameters) > self._policy.max_parameters_per_action:
            return self._finding(
                HighImpactApprovalCode.PREVIEW_TOO_LARGE,
                "Action exceeds the configured complete-parameter limit",
            )
        for name, value in action.parameters.items():
            if not self._matches_kind(value, declared[name]):
                return self._finding(
                    HighImpactApprovalCode.PARAMETER_TYPE_MISMATCH,
                    "Action parameter does not match its trusted preview type",
                )
        return None

    @staticmethod
    def _matches_kind(value: JsonValue, policy: ActionParameterPolicy) -> bool:
        if policy.kind == ApprovalParameterKind.STRING:
            return isinstance(value, str)
        if policy.kind == ApprovalParameterKind.INTEGER:
            return isinstance(value, int) and not isinstance(value, bool)
        if policy.kind == ApprovalParameterKind.NUMBER:
            return (
                isinstance(value, int | float)
                and not isinstance(value, bool)
                and (not isinstance(value, float) or math.isfinite(value))
            )
        if policy.kind == ApprovalParameterKind.BOOLEAN:
            return isinstance(value, bool)
        if policy.kind == ApprovalParameterKind.ARRAY:
            return isinstance(value, list)
        return isinstance(value, dict)

    @staticmethod
    def _render_action(
        index: int,
        action: ProposedHighImpactAction,
        policy: HighImpactActionPolicy,
    ) -> list[str]:
        lines = [
            f"ACTION {index}",
            f"  Instance ID: {action.action_instance_id}",
            f"  Action: {policy.display_name} ({policy.action_id})",
            "  Categories: " + ", ".join(sorted(item.value for item in policy.categories)),
            f"  Impact: {policy.impact.value.upper()}",
            f"  Reversibility: {policy.reversibility.value.upper()}",
            f"  External visibility: {'YES' if policy.external_visibility else 'NO'}",
            "  Data disclosure categories: "
            + (
                ", ".join(policy.data_disclosure_categories)
                if policy.data_disclosure_categories
                else "NONE"
            ),
            "  Side effects:",
        ]
        if policy.side_effects:
            lines.extend(f"    - {effect}" for effect in policy.side_effects)
        else:
            lines.append("    - NONE DECLARED")
        lines.append("  Complete parameters:")
        for parameter in policy.parameters:
            value = action.parameters.get(parameter.name, _MISSING)
            rendered = "[NOT PROVIDED]" if value is _MISSING else _render_json_value(value)
            title = _HIGHLIGHT_TITLES[parameter.parameter_class]
            lines.append(f"    [{title}] {parameter.display_name} ({parameter.name}): {rendered}")
        if not policy.parameters:
            lines.append("    [PARAMETER] NONE")
        return lines

    def _overall_impact(
        self,
        impacts: list[HighImpactLevel],
    ) -> tuple[HighImpactLevel, bool]:
        base_rank = max(_IMPACT_RANK[impact] for impact in impacts)
        escalated = len(impacts) >= self._policy.chain_escalation_action_count and base_rank < 3
        final_rank = base_rank + 1 if escalated else base_rank
        return _IMPACT_BY_RANK[final_rank], escalated

    def _approval_binding_failure(
        self,
        plan: ProposedHighImpactPlan,
        preview: HighImpactPlanPreview,
        approval: HighImpactApprovalGrant,
        now: datetime,
    ) -> HighImpactApprovalFinding | None:
        if approval.preview_digest != preview.preview_digest:
            return self._finding(
                HighImpactApprovalCode.PREVIEW_MISMATCH,
                "Approval does not bind the exact complete preview",
            )
        if approval.plan_digest != plan.plan_digest:
            return self._finding(
                HighImpactApprovalCode.PLAN_MISMATCH,
                "Approval does not bind the exact proposed plan",
            )
        if (
            approval.policy_id != self._policy.policy_id
            or approval.policy_version != self._policy.policy_version
            or approval.policy_digest != self._policy.policy_digest
        ):
            return self._finding(
                HighImpactApprovalCode.POLICY_MISMATCH,
                "Approval was issued under a different policy or policy version",
            )
        if approval.actor_id != plan.actor.actor_id or approval.tenant_id != plan.actor.tenant_id:
            return self._finding(
                HighImpactApprovalCode.ACTOR_MISMATCH,
                "Approval actor or tenant binding does not match the plan",
            )
        if approval.execution_context_digest != plan.context.context_digest:
            return self._finding(
                HighImpactApprovalCode.EXECUTION_CONTEXT_MISMATCH,
                "Approval is bound to a different execution context",
            )
        if approval.approver_id not in self._policy.allowed_approver_ids:
            return self._finding(
                HighImpactApprovalCode.APPROVER_DENIED,
                "Approval issuer is not allowed by policy",
            )
        skew = timedelta(seconds=self._policy.clock_skew_seconds)
        if approval.issued_at > now + skew:
            return self._finding(
                HighImpactApprovalCode.APPROVAL_NOT_YET_VALID,
                "Approval issuance time is in the future",
            )
        if approval.expires_at <= now:
            return self._finding(
                HighImpactApprovalCode.APPROVAL_EXPIRED,
                "Approval acceptance window has expired",
            )
        lifetime = (approval.expires_at - approval.issued_at).total_seconds()
        if lifetime > self._policy.max_approval_ttl_seconds:
            return self._finding(
                HighImpactApprovalCode.APPROVAL_TTL_EXCEEDED,
                "Approval lifetime exceeds the configured maximum",
            )
        return None

    def _authorization(
        self,
        plan: ProposedHighImpactPlan,
        preview: HighImpactPlanPreview,
        *,
        approval: HighImpactApprovalGrant | None,
        expires_at: datetime,
    ) -> AuthorizedHighImpactPlan:
        return AuthorizedHighImpactPlan(
            authorization_id=str(uuid.uuid4()),
            approval_id=approval.approval_id if approval is not None else None,
            plan_digest=plan.plan_digest,
            preview_digest=preview.preview_digest,
            policy_digest=self._policy.policy_digest,
            execution_context_digest=plan.context.context_digest,
            expires_at=expires_at,
            plan_json=plan.canonical_json,
        )

    @staticmethod
    def _finding(
        code: HighImpactApprovalCode,
        message: str,
        *,
        severity: Severity = Severity.CRITICAL,
    ) -> HighImpactApprovalFinding:
        return HighImpactApprovalFinding(code=code, severity=severity, message=message)

    def _blocked(
        self,
        plan: ProposedHighImpactPlan,
        operation: HighImpactApprovalOperation,
        now: datetime,
        finding: HighImpactApprovalFinding,
        *,
        preview: HighImpactPlanPreview | None = None,
        approval: HighImpactApprovalGrant | None = None,
    ) -> HighImpactApprovalResult:
        return self._result(
            plan,
            preview,
            operation,
            GuardAction.BLOCK,
            finding.code,
            now,
            finding=finding,
            approval=approval,
        )

    def _result(
        self,
        plan: ProposedHighImpactPlan,
        preview: HighImpactPlanPreview | None,
        operation: HighImpactApprovalOperation,
        action: Literal[GuardAction.ALLOW, GuardAction.BLOCK, GuardAction.REQUIRE_APPROVAL],
        code: HighImpactApprovalCode,
        now: datetime,
        *,
        finding: HighImpactApprovalFinding | None = None,
        authorization: AuthorizedHighImpactPlan | None = None,
        approval: HighImpactApprovalGrant | None = None,
    ) -> HighImpactApprovalResult:
        event = HighImpactApprovalAuditEvent(
            occurred_at=now,
            operation=operation,
            action=action,
            code=code,
            plan_ref=approval_reference(plan.plan_id),
            actor_ref=approval_reference(plan.actor.actor_id),
            tenant_ref=approval_reference(plan.actor.tenant_id),
            session_ref=approval_reference(plan.context.session_id),
            policy_ref=f"sha256:{self._policy.policy_digest}",
            preview_ref=(f"sha256:{preview.preview_digest}" if preview is not None else None),
            approval_ref=(
                approval_reference(approval.approval_id) if approval is not None else None
            ),
            action_count=len(plan.actions),
            overall_impact=preview.overall_impact if preview is not None else None,
            chain_impact_escalated=(
                preview.chain_impact_escalated if preview is not None else False
            ),
        )
        if self._audit_sink is not None:
            with contextlib.suppress(Exception):
                self._audit_sink.emit(event)
        return HighImpactApprovalResult(
            action=action,
            findings=(finding,) if finding is not None else (),
            preview=preview,
            authorization=authorization,
            audit_event=event,
        )


_MISSING = object()


def _render_json_value(value: object) -> str:
    """Render the same normalized value covered by canonical approval digests."""
    canonical = canonical_approval_json(value)  # type: ignore[arg-type]
    return json.dumps(
        json.loads(canonical),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )

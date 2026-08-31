"""Deterministic goal-integrity enforcement for agent plans and mutations."""

from __future__ import annotations

import contextlib
import re
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol

from trustrail.exceptions import GoalIntegrityError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.goal import (
    AuthorizedPlanStep,
    GoalInputSource,
    GoalIntegrityAuditEvent,
    GoalIntegrityCode,
    GoalIntegrityFinding,
    GoalIntegrityOperation,
    GoalIntegrityPolicy,
    GoalIntegrityResult,
    GoalManifest,
    GoalMutationApproval,
    ProposedGoalMutation,
    ProposedPlanStep,
    utcnow,
)
from trustrail.normalization import TextNormalizer

_HIJACK_PATTERNS = (
    re.compile(
        r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,80}\b"
        r"(?:authorized|original|current|previous|primary)\b.{0,40}\b"
        r"(?:goal|objective|mission|constraints?|manifest)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:replace|change|switch|redirect|rewrite|adopt)\b.{0,60}\b"
        r"(?:goal|objective|mission|purpose)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:new|hidden|actual|real|replacement)\s+"
        r"(?:goal|objective|mission|task)\s*:",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:unrelated|different|attacker[- ]selected)\s+"
        r"(?:goal|objective|task|mission)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdo\s+not\s+(?:follow|honor|enforce)\b.{0,60}\b"
        r"(?:goal|manifest|constraints?)\b",
        re.IGNORECASE,
    ),
)
_COMPACT_HIJACK_PATTERNS = (
    re.compile(
        r"(?:ignore|disregard|forget|override|bypass)(?:the)?"
        r"(?:authorized|original|current|previous|primary)"
        r"(?:goal|objective|mission|constraints?|manifest)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:replace|change|switch|redirect|rewrite|adopt)(?:the)?"
        r"(?:goal|objective|mission|purpose)",
        re.IGNORECASE,
    ),
)


class GoalApprovalVerifier(Protocol):
    """Authenticate an out-of-band approval for one exact goal mutation."""

    def verify_approval(self, approval: GoalMutationApproval) -> bool:
        """Return whether trusted application state issued this approval."""
        ...


class GoalIntegrityAuditSink(Protocol):
    """Synchronous sink for content-free goal-integrity audit events."""

    def emit(self, event: GoalIntegrityAuditEvent) -> None:
        """Persist one audit event without raising into the decision path."""
        ...


class MemoryGoalIntegrityAuditSink:
    """Bounded in-memory goal audit sink for tests and local development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[GoalIntegrityAuditEvent] = deque(maxlen=max_events)

    def emit(self, event: GoalIntegrityAuditEvent) -> None:
        self._events.append(event)

    @property
    def events(self) -> list[GoalIntegrityAuditEvent]:
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()


class StaticGoalApprovalVerifier:
    """Test/example verifier backed by application-owned approval IDs."""

    def __init__(self, valid_approval_ids: frozenset[str]) -> None:
        self._valid_approval_ids = valid_approval_ids

    def verify_approval(self, approval: GoalMutationApproval) -> bool:
        return approval.approval_id in self._valid_approval_ids


@dataclass
class GoalExecutionState:
    """Application-owned mutable state for one complete agent execution."""

    manifest_id: str
    manifest_digest: str
    execution_id: str
    session_id: str
    primary_actor_id: str
    active_delegate_ids: set[str] = field(default_factory=set)
    step_count: int = 0
    mutation_count: int = 0
    seen_step_ids: set[str] = field(default_factory=set)
    used_approval_ids: set[str] = field(default_factory=set)
    _drift_fragments: deque[str] = field(default_factory=deque, repr=False)
    _drift_chars: int = field(default=0, repr=False)


class GoalIntegrityGuard:
    """Validate every plan step, delegation, and material goal mutation."""

    def __init__(
        self,
        policy: GoalIntegrityPolicy | None = None,
        *,
        approval_verifier: GoalApprovalVerifier | None = None,
        audit_sink: GoalIntegrityAuditSink | None = None,
    ) -> None:
        self._policy = (policy or GoalIntegrityPolicy()).model_copy(deep=True)
        self._approval_verifier = approval_verifier
        self._audit_sink = audit_sink
        self._normalizer = TextNormalizer()
        self._lock = threading.Lock()

    @property
    def policy(self) -> GoalIntegrityPolicy:
        return self._policy.model_copy(deep=True)

    def new_state(self, manifest: GoalManifest) -> GoalExecutionState:
        """Create state bound to an integrity-valid manifest."""
        if not manifest.has_valid_integrity:
            raise ValueError("cannot create execution state from an invalid goal manifest")
        return GoalExecutionState(
            manifest_id=manifest.manifest_id,
            manifest_digest=manifest.manifest_digest,
            execution_id=manifest.execution_id,
            session_id=manifest.session_id,
            primary_actor_id=manifest.primary_actor_id,
        )

    def validate_step(
        self,
        manifest: GoalManifest,
        step: ProposedPlanStep,
        state: GoalExecutionState,
        *,
        now: datetime | None = None,
    ) -> GoalIntegrityResult:
        """Authorize one exact plan step before execution or delegation."""
        current_time = now or utcnow()
        findings = self._manifest_findings(manifest, state, current_time)
        findings.extend(
            self._request_binding_findings(
                manifest,
                execution_id=step.execution_id,
                session_id=step.session_id,
                owner_id=step.principal.owner_id,
                tenant_id=step.principal.tenant_id,
                actor_id=step.principal.actor_id,
                expected_manifest_digest=step.expected_manifest_digest,
                state=state,
            )
        )
        findings.extend(self._step_findings(manifest, step, state))

        if findings:
            return self._result(
                manifest,
                operation=GoalIntegrityOperation.PLAN_STEP,
                action=GuardAction.BLOCK,
                actor_id=step.principal.actor_id,
                source=step.source,
                findings=findings,
            )

        with self._lock:
            # Recheck mutable counters and identifiers after waiting for another caller.
            concurrent_findings = self._state_step_findings(step, state)
            if concurrent_findings:
                return self._result(
                    manifest,
                    operation=GoalIntegrityOperation.PLAN_STEP,
                    action=GuardAction.BLOCK,
                    actor_id=step.principal.actor_id,
                    source=step.source,
                    findings=concurrent_findings,
                )
            state.step_count += 1
            state.seen_step_ids.add(step.step_id)
            self._remember_step(step.description, state)
            if step.delegated_to is not None:
                state.active_delegate_ids.add(step.delegated_to)

        authorization = AuthorizedPlanStep(
            authorization_id=str(uuid.uuid4()),
            step_id=step.step_id,
            sequence=step.sequence,
            manifest_digest=manifest.manifest_digest,
            execution_id=step.execution_id,
            session_id=step.session_id,
            actor_id=step.principal.actor_id,
            action_id=step.action_id,
            delegated_to=step.delegated_to,
            description=step.description,
        )
        return self._result(
            manifest,
            operation=GoalIntegrityOperation.PLAN_STEP,
            action=GuardAction.ALLOW,
            actor_id=step.principal.actor_id,
            source=step.source,
            authorization=authorization,
        )

    def require_step(
        self,
        manifest: GoalManifest,
        step: ProposedPlanStep,
        state: GoalExecutionState,
        *,
        now: datetime | None = None,
    ) -> AuthorizedPlanStep:
        """Return an authorized immutable step or raise before execution."""
        result = self.validate_step(manifest, step, state, now=now)
        if not result.is_authorized or result.authorization is None:
            raise GoalIntegrityError(result=result)
        return result.authorization

    def validate_mutation(
        self,
        manifest: GoalManifest,
        mutation: ProposedGoalMutation,
        state: GoalExecutionState,
        *,
        now: datetime | None = None,
    ) -> GoalIntegrityResult:
        """Require an exact authenticated approval for every material goal change."""
        current_time = now or utcnow()
        findings = self._manifest_findings(manifest, state, current_time)
        findings.extend(
            self._request_binding_findings(
                manifest,
                execution_id=mutation.execution_id,
                session_id=mutation.session_id,
                owner_id=mutation.principal.owner_id,
                tenant_id=mutation.principal.tenant_id,
                actor_id=mutation.principal.actor_id,
                expected_manifest_digest=mutation.expected_manifest_digest,
                state=state,
            )
        )
        if findings:
            return self._result(
                manifest,
                operation=GoalIntegrityOperation.GOAL_MUTATION,
                action=GuardAction.BLOCK,
                actor_id=mutation.principal.actor_id,
                source=mutation.source,
                findings=findings,
                attempted_change_digest=mutation.mutation_digest,
                approval_id=mutation.approval.approval_id if mutation.approval else None,
            )

        findings.extend(self._mutation_structure_findings(manifest, mutation))
        if findings:
            return self._result(
                manifest,
                operation=GoalIntegrityOperation.GOAL_MUTATION,
                action=GuardAction.BLOCK,
                actor_id=mutation.principal.actor_id,
                source=mutation.source,
                findings=findings,
                attempted_change_digest=mutation.mutation_digest,
                approval_id=mutation.approval.approval_id if mutation.approval else None,
            )

        if not self._is_material_mutation(manifest, mutation):
            return self._result(
                manifest,
                operation=GoalIntegrityOperation.GOAL_MUTATION,
                action=GuardAction.ALLOW,
                actor_id=mutation.principal.actor_id,
                source=mutation.source,
                updated_manifest=manifest,
                attempted_change_digest=mutation.mutation_digest,
                approval_id=mutation.approval.approval_id if mutation.approval else None,
            )

        if state.mutation_count >= self._policy.max_mutations_per_execution:
            findings.append(
                self._finding(
                    GoalIntegrityCode.MUTATION_LIMIT_EXCEEDED,
                    "Goal mutation limit has been reached for this execution",
                )
            )
        approval = mutation.approval
        if approval is None:
            approval_finding = self._finding(
                GoalIntegrityCode.MUTATION_APPROVAL_REQUIRED,
                "Material goal change requires explicit out-of-band approval",
            )
            return self._result(
                manifest,
                operation=GoalIntegrityOperation.GOAL_MUTATION,
                action=(GuardAction.BLOCK if findings else GuardAction.REQUIRE_APPROVAL),
                actor_id=mutation.principal.actor_id,
                source=mutation.source,
                findings=[*findings, approval_finding],
                attempted_change_digest=mutation.mutation_digest,
            )

        findings.extend(self._approval_findings(manifest, mutation, approval, state, current_time))
        if findings:
            return self._result(
                manifest,
                operation=GoalIntegrityOperation.GOAL_MUTATION,
                action=GuardAction.BLOCK,
                actor_id=mutation.principal.actor_id,
                source=mutation.source,
                findings=findings,
                attempted_change_digest=mutation.mutation_digest,
                approval_id=approval.approval_id,
            )

        with self._lock:
            if approval.approval_id in state.used_approval_ids:
                return self._result(
                    manifest,
                    operation=GoalIntegrityOperation.GOAL_MUTATION,
                    action=GuardAction.BLOCK,
                    actor_id=mutation.principal.actor_id,
                    source=mutation.source,
                    findings=[
                        self._finding(
                            GoalIntegrityCode.APPROVAL_REPLAYED,
                            "Goal mutation approval has already been consumed",
                        )
                    ],
                    attempted_change_digest=mutation.mutation_digest,
                    approval_id=approval.approval_id,
                )
            if state.manifest_digest != manifest.manifest_digest:
                return self._result(
                    manifest,
                    operation=GoalIntegrityOperation.GOAL_MUTATION,
                    action=GuardAction.BLOCK,
                    actor_id=mutation.principal.actor_id,
                    source=mutation.source,
                    findings=[
                        self._finding(
                            GoalIntegrityCode.STALE_MANIFEST,
                            "Goal manifest was superseded before mutation authorization",
                        )
                    ],
                    attempted_change_digest=mutation.mutation_digest,
                    approval_id=approval.approval_id,
                )
            updated = self._updated_manifest(manifest, mutation, current_time)
            state.manifest_digest = updated.manifest_digest
            state.mutation_count += 1
            state.used_approval_ids.add(approval.approval_id)
            state.active_delegate_ids.intersection_update(updated.allowed_delegate_ids)

        return self._result(
            manifest,
            operation=GoalIntegrityOperation.GOAL_MUTATION,
            action=GuardAction.ALLOW,
            actor_id=mutation.principal.actor_id,
            source=mutation.source,
            updated_manifest=updated,
            attempted_change_digest=mutation.mutation_digest,
            approval_id=approval.approval_id,
        )

    def require_mutation(
        self,
        manifest: GoalManifest,
        mutation: ProposedGoalMutation,
        state: GoalExecutionState,
        *,
        now: datetime | None = None,
    ) -> GoalManifest:
        """Return an approved updated manifest or raise before changing the goal."""
        result = self.validate_mutation(manifest, mutation, state, now=now)
        if result.action != GuardAction.ALLOW or result.updated_manifest is None:
            raise GoalIntegrityError(result=result)
        return result.updated_manifest

    def _manifest_findings(
        self,
        manifest: GoalManifest,
        state: GoalExecutionState,
        now: datetime,
    ) -> list[GoalIntegrityFinding]:
        findings: list[GoalIntegrityFinding] = []
        if not manifest.has_valid_integrity:
            findings.append(
                self._finding(
                    GoalIntegrityCode.MANIFEST_INTEGRITY_INVALID,
                    "Goal manifest failed its integrity check",
                    Severity.CRITICAL,
                )
            )
        if now >= manifest.expires_at:
            findings.append(
                self._finding(
                    GoalIntegrityCode.MANIFEST_EXPIRED,
                    "Goal manifest has expired",
                )
            )
        if now >= manifest.approval_context.expires_at:
            findings.append(
                self._finding(
                    GoalIntegrityCode.APPROVAL_CONTEXT_EXPIRED,
                    "Original goal approval context has expired",
                )
            )
        if (
            state.manifest_id != manifest.manifest_id
            or state.execution_id != manifest.execution_id
            or state.session_id != manifest.session_id
            or state.primary_actor_id != manifest.primary_actor_id
        ):
            findings.append(
                self._finding(
                    GoalIntegrityCode.STATE_BINDING_MISMATCH,
                    "Execution state is not bound to this goal manifest",
                    Severity.CRITICAL,
                )
            )
        elif state.manifest_digest != manifest.manifest_digest:
            findings.append(
                self._finding(
                    GoalIntegrityCode.STALE_MANIFEST,
                    "Goal manifest is stale or differs from execution state",
                )
            )
        return findings

    def _request_binding_findings(
        self,
        manifest: GoalManifest,
        *,
        execution_id: str,
        session_id: str,
        owner_id: str,
        tenant_id: str,
        actor_id: str,
        expected_manifest_digest: str,
        state: GoalExecutionState,
    ) -> list[GoalIntegrityFinding]:
        checks = (
            (
                execution_id != manifest.execution_id,
                GoalIntegrityCode.EXECUTION_MISMATCH,
                "Proposal belongs to a different execution",
            ),
            (
                session_id != manifest.session_id,
                GoalIntegrityCode.SESSION_MISMATCH,
                "Proposal belongs to a different session",
            ),
            (
                owner_id != manifest.owner.owner_id,
                GoalIntegrityCode.OWNER_MISMATCH,
                "Proposal owner differs from the authorized goal owner",
            ),
            (
                tenant_id != manifest.owner.tenant_id,
                GoalIntegrityCode.TENANT_MISMATCH,
                "Proposal tenant differs from the authorized goal tenant",
            ),
            (
                expected_manifest_digest != manifest.manifest_digest,
                GoalIntegrityCode.GOAL_BINDING_MISMATCH,
                "Proposal is not bound to the current goal manifest",
            ),
        )
        findings = [self._finding(code, message) for failed, code, message in checks if failed]
        active_actors = {manifest.primary_actor_id, *state.active_delegate_ids}
        if actor_id not in active_actors:
            code = (
                GoalIntegrityCode.DELEGATION_NOT_ESTABLISHED
                if actor_id in manifest.allowed_delegate_ids
                else GoalIntegrityCode.ACTOR_NOT_AUTHORIZED
            )
            findings.append(
                self._finding(code, "Actor is not authorized for the current execution")
            )
        return findings

    def _step_findings(
        self,
        manifest: GoalManifest,
        step: ProposedPlanStep,
        state: GoalExecutionState,
    ) -> list[GoalIntegrityFinding]:
        findings = self._state_step_findings(step, state)
        if self._policy.require_all_constraint_bindings:
            constraint_mismatch = step.constraint_ids != manifest.constraint_ids
        else:
            constraint_mismatch = not step.constraint_ids.issubset(manifest.constraint_ids)
        if constraint_mismatch:
            findings.append(
                self._finding(
                    GoalIntegrityCode.CONSTRAINT_BINDING_MISMATCH,
                    "Plan step does not carry the authorized constraint set",
                )
            )
        if step.action_id not in manifest.allowed_action_ids:
            findings.append(
                self._finding(
                    GoalIntegrityCode.ACTION_NOT_ALLOWED,
                    "Plan step action is outside the goal manifest",
                )
            )
        if step.delegated_to is not None and step.delegated_to not in manifest.allowed_delegate_ids:
            findings.append(
                self._finding(
                    GoalIntegrityCode.DELEGATE_NOT_ALLOWED,
                    "Plan step delegates to an actor outside the goal manifest",
                )
            )
        if len(step.description) > self._policy.max_step_chars:
            findings.append(
                self._finding(
                    GoalIntegrityCode.STEP_CONTENT_LIMIT_EXCEEDED,
                    "Plan step exceeds the bounded goal-drift scan limit",
                )
            )
            return findings

        direct, encoded = self._detect_hijack(step.description)
        if encoded and self._policy.detect_encoded_hijacking:
            findings.append(
                self._finding(
                    GoalIntegrityCode.ENCODED_GOAL_HIJACK,
                    "Plan step contains an encoded goal-hijacking instruction",
                )
            )
        elif direct:
            findings.append(
                self._finding(
                    GoalIntegrityCode.GOAL_HIJACK_PATTERN,
                    "Plan step contains a goal-hijacking instruction",
                )
            )

        if self._policy.detect_split_hijacking and state._drift_fragments:
            history = "".join(state._drift_fragments)
            combined = f"{history} {step.description}"
            compact_combined = re.sub(r"\W+", "", combined.casefold())
            if (
                not direct
                and not encoded
                and (
                    self._contains_hijack(combined)
                    or self._contains_compact_hijack(compact_combined)
                )
            ):
                findings.append(
                    self._finding(
                        GoalIntegrityCode.SPLIT_GOAL_DRIFT,
                        "Goal-hijacking instruction was assembled across plan steps",
                    )
                )
        return findings

    def _state_step_findings(
        self,
        step: ProposedPlanStep,
        state: GoalExecutionState,
    ) -> list[GoalIntegrityFinding]:
        findings: list[GoalIntegrityFinding] = []
        if step.step_id in state.seen_step_ids:
            findings.append(
                self._finding(
                    GoalIntegrityCode.STEP_REPLAYED,
                    "Plan step identifier has already been authorized",
                )
            )
        if step.sequence != state.step_count + 1:
            findings.append(
                self._finding(
                    GoalIntegrityCode.STEP_SEQUENCE_INVALID,
                    "Plan step sequence is missing, duplicated, or out of order",
                )
            )
        if state.step_count >= self._policy.max_steps_per_execution:
            findings.append(
                self._finding(
                    GoalIntegrityCode.STEP_LIMIT_EXCEEDED,
                    "Plan step limit has been reached for this execution",
                )
            )
        return findings

    def _approval_findings(
        self,
        manifest: GoalManifest,
        mutation: ProposedGoalMutation,
        approval: GoalMutationApproval,
        state: GoalExecutionState,
        now: datetime,
    ) -> list[GoalIntegrityFinding]:
        findings: list[GoalIntegrityFinding] = []
        if approval.approval_id in state.used_approval_ids:
            findings.append(
                self._finding(
                    GoalIntegrityCode.APPROVAL_REPLAYED,
                    "Goal mutation approval has already been consumed",
                )
            )
        if approval.expires_at <= now:
            findings.append(
                self._finding(
                    GoalIntegrityCode.APPROVAL_EXPIRED,
                    "Goal mutation approval has expired",
                )
            )
        invalid = (
            approval.mutation_digest != mutation.mutation_digest
            or approval.approver_id not in manifest.approval_context.allowed_approver_ids
            or self._approval_verifier is None
        )
        if not invalid and self._approval_verifier is not None:
            try:
                invalid = not self._approval_verifier.verify_approval(approval)
            except Exception:
                invalid = True
        if invalid:
            findings.append(
                self._finding(
                    GoalIntegrityCode.APPROVAL_INVALID,
                    "Goal mutation approval is invalid for this exact change",
                )
            )
        return findings

    @staticmethod
    def _is_material_mutation(
        manifest: GoalManifest,
        mutation: ProposedGoalMutation,
    ) -> bool:
        return any(
            (
                mutation.proposed_objective is not None
                and mutation.proposed_objective != manifest.objective,
                mutation.proposed_constraints is not None
                and mutation.proposed_constraints != manifest.constraints,
                mutation.proposed_allowed_action_ids is not None
                and mutation.proposed_allowed_action_ids != manifest.allowed_action_ids,
                mutation.proposed_allowed_delegate_ids is not None
                and mutation.proposed_allowed_delegate_ids != manifest.allowed_delegate_ids,
            )
        )

    def _mutation_structure_findings(
        self,
        manifest: GoalManifest,
        mutation: ProposedGoalMutation,
    ) -> list[GoalIntegrityFinding]:
        constraints = mutation.proposed_constraints
        duplicate_constraints = False
        if constraints is not None:
            constraint_ids = [constraint.constraint_id for constraint in constraints]
            duplicate_constraints = len(constraint_ids) != len(set(constraint_ids))
        invalid_delegates = (
            mutation.proposed_allowed_delegate_ids is not None
            and manifest.primary_actor_id in mutation.proposed_allowed_delegate_ids
        )
        if not duplicate_constraints and not invalid_delegates:
            return []
        return [
            self._finding(
                GoalIntegrityCode.INVALID_MUTATION,
                "Proposed goal mutation contains an invalid constraint or delegate set",
            )
        ]

    @staticmethod
    def _updated_manifest(
        manifest: GoalManifest,
        mutation: ProposedGoalMutation,
        now: datetime,
    ) -> GoalManifest:
        return GoalManifest.create(
            manifest_id=manifest.manifest_id,
            execution_id=manifest.execution_id,
            session_id=manifest.session_id,
            owner=manifest.owner,
            primary_actor_id=manifest.primary_actor_id,
            objective=mutation.proposed_objective or manifest.objective,
            constraints=(
                mutation.proposed_constraints
                if mutation.proposed_constraints is not None
                else manifest.constraints
            ),
            allowed_action_ids=(
                mutation.proposed_allowed_action_ids
                if mutation.proposed_allowed_action_ids is not None
                else manifest.allowed_action_ids
            ),
            allowed_delegate_ids=(
                mutation.proposed_allowed_delegate_ids
                if mutation.proposed_allowed_delegate_ids is not None
                else manifest.allowed_delegate_ids
            ),
            approval_context=manifest.approval_context,
            issued_at=now,
            expires_at=manifest.expires_at,
            revision=manifest.revision + 1,
            parent_manifest_digest=manifest.manifest_digest,
            root_goal_digest=manifest.root_goal_digest,
        )

    def _detect_hijack(self, text: str) -> tuple[bool, bool]:
        plain_direct = self._contains_hijack(text)
        original_direct = plain_direct or self._contains_compact_hijack(
            re.sub(r"\W+", "", text.casefold())
        )
        normalized = self._normalizer.normalize(text)
        normalized_direct = self._contains_hijack(
            normalized.normalized
        ) or self._contains_compact_hijack(re.sub(r"\W+", "", normalized.normalized.casefold()))
        decoded_direct = any(
            self._contains_hijack(decoded)
            or self._contains_compact_hijack(re.sub(r"\W+", "", decoded.casefold()))
            for decoded in self._normalizer.extract_base64_payloads(normalized.normalized)
        )
        encoded = decoded_direct or (
            normalized_direct and bool(normalized.signals) and not plain_direct
        )
        return original_direct or normalized_direct or decoded_direct, encoded

    @staticmethod
    def _contains_hijack(text: str) -> bool:
        return any(pattern.search(text) for pattern in _HIJACK_PATTERNS)

    @staticmethod
    def _contains_compact_hijack(text: str) -> bool:
        return any(pattern.search(text) for pattern in _COMPACT_HIJACK_PATTERNS)

    def _remember_step(self, description: str, state: GoalExecutionState) -> None:
        normalized = self._normalizer.normalize(description).normalized
        state._drift_fragments.append(normalized)
        state._drift_chars += len(normalized)
        while state._drift_fragments and state._drift_chars > self._policy.max_drift_history_chars:
            removed = state._drift_fragments.popleft()
            state._drift_chars -= len(removed)

    def _result(
        self,
        manifest: GoalManifest,
        *,
        operation: GoalIntegrityOperation,
        action: Literal[
            GuardAction.ALLOW,
            GuardAction.BLOCK,
            GuardAction.REQUIRE_APPROVAL,
        ],
        actor_id: str,
        source: GoalInputSource,
        findings: list[GoalIntegrityFinding] | None = None,
        authorization: AuthorizedPlanStep | None = None,
        updated_manifest: GoalManifest | None = None,
        attempted_change_digest: str | None = None,
        approval_id: str | None = None,
    ) -> GoalIntegrityResult:
        typed_findings = tuple(findings or ())
        event = GoalIntegrityAuditEvent(
            operation=operation,
            action=action,
            manifest_id=manifest.manifest_id,
            execution_id=manifest.execution_id,
            session_id=manifest.session_id,
            owner_id=manifest.owner.owner_id,
            tenant_id=manifest.owner.tenant_id,
            actor_id=actor_id,
            source=source,
            root_goal_digest=manifest.root_goal_digest,
            current_goal_digest=manifest.goal_digest,
            current_manifest_digest=manifest.manifest_digest,
            attempted_change_digest=attempted_change_digest,
            approval_id=approval_id,
            finding_codes=tuple(finding.code for finding in typed_findings),
        )
        if self._audit_sink is not None:
            with contextlib.suppress(Exception):
                self._audit_sink.emit(event)
        return GoalIntegrityResult(
            action=action,
            findings=typed_findings,
            authorization=authorization,
            updated_manifest=updated_manifest,
            audit_event=event,
        )

    @staticmethod
    def _finding(
        code: GoalIntegrityCode,
        message: str,
        severity: Severity = Severity.HIGH,
    ) -> GoalIntegrityFinding:
        return GoalIntegrityFinding(code=code, severity=severity, message=message)

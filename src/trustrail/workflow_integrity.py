"""Signed persistent agent state and append-only execution-chain verification."""

from __future__ import annotations

import contextlib
import threading
import uuid
from collections import deque
from datetime import datetime, timedelta
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from trustrail.exceptions import WorkflowIntegrityError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.workflow_integrity import (
    EMPTY_CHAIN_DIGEST,
    AuthorizedWorkflowResume,
    PendingActionBinding,
    PendingApprovalBinding,
    PersistedWorkflowState,
    PersistentWorkflowCheckpoint,
    WorkflowBudgetState,
    WorkflowExecutionEntry,
    WorkflowExecutionEventKind,
    WorkflowIntegrityAuditEvent,
    WorkflowIntegrityCode,
    WorkflowIntegrityDecision,
    WorkflowIntegrityFinding,
    WorkflowIntegrityPhase,
    WorkflowIntegrityPolicy,
    WorkflowIntegrityTrustedKey,
    WorkflowPolicyVersion,
    WorkflowResumeClaimStatus,
    WorkflowResumeContext,
    utcnow,
    workflow_reference,
)


class WorkflowResumeAuthorizer(Protocol):
    """Reauthorize a persisted workflow against current authoritative state."""

    def authorize_resume(
        self,
        context: WorkflowResumeContext,
        checkpoint: PersistentWorkflowCheckpoint,
        now: datetime,
    ) -> bool: ...


class WorkflowRevocationProvider(Protocol):
    """Return current workflow and checkpoint revocation state."""

    def is_revoked(
        self,
        workflow_id: str,
        checkpoint_digest: str,
        now: datetime,
    ) -> bool: ...


class WorkflowResumeStateStore(Protocol):
    """Atomically prevent replay, rollback, collision, and skipped continuity."""

    def claim_resume(
        self,
        workflow_ref: str,
        checkpoint_sequence: int,
        checkpoint_digest: str,
        chain_head_digest: str,
        expires_at: datetime,
        now: datetime,
    ) -> WorkflowResumeClaimStatus: ...


class WorkflowIntegrityAuditSink(Protocol):
    """Persist content-free checkpoint verification evidence."""

    def emit(self, event: WorkflowIntegrityAuditEvent) -> None: ...


class MemoryWorkflowResumeStateStore:
    """Process-local atomic resume state for tests and single-worker deployments."""

    def __init__(self, max_workflows: int = 10_000, max_claims: int = 100_000) -> None:
        if max_workflows < 1 or max_claims < 1:
            raise ValueError("resume-state capacities must be positive")
        self._max_workflows = max_workflows
        self._max_claims = max_claims
        self._workflows: dict[str, tuple[int, str, str, datetime]] = {}
        self._claims: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def claim_resume(
        self,
        workflow_ref: str,
        checkpoint_sequence: int,
        checkpoint_digest: str,
        chain_head_digest: str,
        expires_at: datetime,
        now: datetime,
    ) -> WorkflowResumeClaimStatus:
        if now.tzinfo is None or expires_at.tzinfo is None:
            raise ValueError("resume-state timestamps must be timezone-aware")
        if expires_at <= now:
            raise ValueError("resume-state expiry must be in the future")
        with self._lock:
            self._claims = {
                digest: expiry for digest, expiry in self._claims.items() if expiry > now
            }
            self._workflows = {
                key: value for key, value in self._workflows.items() if value[3] > now
            }
            if checkpoint_digest in self._claims:
                return WorkflowResumeClaimStatus.REPLAYED
            existing = self._workflows.get(workflow_ref)
            if existing is not None:
                previous_sequence, previous_digest, previous_head, _ = existing
                if checkpoint_sequence < previous_sequence:
                    return WorkflowResumeClaimStatus.ROLLBACK
                if checkpoint_sequence == previous_sequence:
                    if checkpoint_digest == previous_digest and chain_head_digest == previous_head:
                        return WorkflowResumeClaimStatus.REPLAYED
                    return WorkflowResumeClaimStatus.COLLISION
                if checkpoint_sequence != previous_sequence + 1:
                    return WorkflowResumeClaimStatus.OUT_OF_ORDER
            if len(self._claims) >= self._max_claims:
                return WorkflowResumeClaimStatus.FULL
            if existing is None and len(self._workflows) >= self._max_workflows:
                return WorkflowResumeClaimStatus.FULL
            self._claims[checkpoint_digest] = expires_at
            self._workflows[workflow_ref] = (
                checkpoint_sequence,
                checkpoint_digest,
                chain_head_digest,
                expires_at,
            )
            return WorkflowResumeClaimStatus.CLAIMED


class MemoryWorkflowRevocationProvider:
    """Thread-safe process-local workflow and checkpoint revocation provider."""

    def __init__(self) -> None:
        self._workflow_refs: set[str] = set()
        self._checkpoint_digests: set[str] = set()
        self._lock = threading.Lock()

    def revoke_workflow(self, workflow_id: str) -> None:
        with self._lock:
            self._workflow_refs.add(workflow_reference(workflow_id))

    def revoke_checkpoint(self, checkpoint_digest: str) -> None:
        with self._lock:
            self._checkpoint_digests.add(checkpoint_digest)

    def is_revoked(
        self,
        workflow_id: str,
        checkpoint_digest: str,
        now: datetime,
    ) -> bool:
        del now
        with self._lock:
            return (
                workflow_reference(workflow_id) in self._workflow_refs
                or checkpoint_digest in self._checkpoint_digests
            )


class StaticWorkflowResumeAuthorizer:
    """Exact-digest resume authorizer for tests and trusted adapters."""

    def __init__(self, accepted: frozenset[tuple[str, str]]) -> None:
        self._accepted = accepted

    def authorize_resume(
        self,
        context: WorkflowResumeContext,
        checkpoint: PersistentWorkflowCheckpoint,
        now: datetime,
    ) -> bool:
        del now
        return (
            checkpoint.checkpoint_digest,
            context.resume_authorization_digest,
        ) in self._accepted


class MemoryWorkflowIntegrityAuditSink:
    """Bounded process-local audit sink for tests and development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[WorkflowIntegrityAuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def emit(self, event: WorkflowIntegrityAuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> list[WorkflowIntegrityAuditEvent]:
        with self._lock:
            return list(self._events)


class WorkflowCheckpointSigner:
    """Sign canonical checkpoints and execution entries with Ed25519."""

    def __init__(self, private_key: Ed25519PrivateKey, *, authority_id: str) -> None:
        self._private_key = private_key
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._trusted_key = WorkflowIntegrityTrustedKey(
            authority_id=authority_id,
            public_key=public_key,
        )

    @classmethod
    def generate(cls, *, authority_id: str) -> WorkflowCheckpointSigner:
        return cls(Ed25519PrivateKey.generate(), authority_id=authority_id)

    @property
    def key_id(self) -> str:
        return self._trusted_key.key_id

    @property
    def trusted_key(self) -> WorkflowIntegrityTrustedKey:
        return self._trusted_key.model_copy(deep=True)

    def sign_entry(
        self,
        *,
        chain_id: str,
        entry_id: str,
        event_kind: WorkflowExecutionEventKind,
        workflow_id: str,
        tenant_id: str,
        agent_id: str,
        session_id: str,
        goal_digest: str,
        plan_digest: str,
        occurred_at: datetime,
        prior_entry: WorkflowExecutionEntry | None = None,
        action_digest: str | None = None,
        authorization_digest: str | None = None,
        outcome_digest: str | None = None,
    ) -> WorkflowExecutionEntry:
        """Create one signed link that commits to its exact predecessor."""
        sequence = 0 if prior_entry is None else prior_entry.sequence + 1
        if prior_entry is not None:
            expected = (
                prior_entry.chain_id,
                prior_entry.workflow_id,
                prior_entry.tenant_id,
                prior_entry.agent_id,
                prior_entry.session_id,
                prior_entry.goal_digest,
                prior_entry.plan_digest,
            )
            actual = (
                chain_id,
                workflow_id,
                tenant_id,
                agent_id,
                session_id,
                goal_digest,
                plan_digest,
            )
            if expected != actual:
                raise ValueError("execution entry cannot change chain context")
            if occurred_at < prior_entry.occurred_at:
                raise ValueError("execution entry time cannot move backward")
        unsigned = WorkflowExecutionEntry(
            chain_id=chain_id,
            sequence=sequence,
            entry_id=entry_id,
            event_kind=event_kind,
            key_id=self.key_id,
            authority_id=self._trusted_key.authority_id,
            workflow_id=workflow_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            session_id=session_id,
            goal_digest=goal_digest,
            plan_digest=plan_digest,
            action_digest=action_digest,
            authorization_digest=authorization_digest,
            outcome_digest=outcome_digest,
            prior_entry_digest=prior_entry.entry_digest if prior_entry else None,
            occurred_at=occurred_at,
        )
        return unsigned.model_copy(
            update={"signature": self._private_key.sign(unsigned.signing_bytes).hex()},
            deep=True,
        )

    def sign_checkpoint(
        self,
        *,
        checkpoint_id: str,
        workflow_id: str,
        tenant_id: str,
        agent_id: str,
        session_id: str,
        goal_digest: str,
        plan_digest: str,
        budgets: tuple[WorkflowBudgetState, ...],
        policy_versions: tuple[WorkflowPolicyVersion, ...],
        pending_actions: tuple[PendingActionBinding, ...],
        pending_approvals: tuple[PendingApprovalBinding, ...],
        resume_authorization_digest: str,
        chain_id: str,
        execution_chain: tuple[WorkflowExecutionEntry, ...],
        issued_at: datetime,
        expires_at: datetime,
        prior_checkpoint: PersistentWorkflowCheckpoint | None = None,
    ) -> PersistentWorkflowCheckpoint:
        """Sign a canonical checkpoint over state digests and the complete chain head."""
        checkpoint_sequence = (
            0 if prior_checkpoint is None else prior_checkpoint.checkpoint_sequence + 1
        )
        if prior_checkpoint is not None:
            expected = (
                prior_checkpoint.workflow_id,
                prior_checkpoint.tenant_id,
                prior_checkpoint.agent_id,
                prior_checkpoint.session_id,
                prior_checkpoint.chain_id,
            )
            actual = (workflow_id, tenant_id, agent_id, session_id, chain_id)
            if expected != actual:
                raise ValueError("checkpoint cannot change workflow context")
        unsigned = PersistentWorkflowCheckpoint(
            checkpoint_id=checkpoint_id,
            checkpoint_sequence=checkpoint_sequence,
            key_id=self.key_id,
            authority_id=self._trusted_key.authority_id,
            workflow_id=workflow_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            session_id=session_id,
            goal_digest=goal_digest,
            plan_digest=plan_digest,
            budgets=tuple(sorted(budgets, key=lambda item: item.budget_id)),
            policy_versions=tuple(sorted(policy_versions, key=lambda item: item.policy_id)),
            pending_actions=tuple(sorted(pending_actions, key=lambda item: item.action_id)),
            pending_approvals=tuple(sorted(pending_approvals, key=lambda item: item.approval_id)),
            resume_authorization_digest=resume_authorization_digest,
            chain_id=chain_id,
            execution_chain_length=len(execution_chain),
            execution_chain_head_digest=(
                execution_chain[-1].entry_digest if execution_chain else EMPTY_CHAIN_DIGEST
            ),
            prior_checkpoint_digest=(
                prior_checkpoint.checkpoint_digest if prior_checkpoint else None
            ),
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return unsigned.model_copy(
            update={"signature": self._private_key.sign(unsigned.signing_bytes).hex()},
            deep=True,
        )


class PersistentWorkflowVerifier:
    """Verify signed continuity and atomically authorize one workflow resume."""

    def __init__(
        self,
        policy: WorkflowIntegrityPolicy,
        trusted_keys: tuple[WorkflowIntegrityTrustedKey, ...],
        *,
        authorizer: WorkflowResumeAuthorizer,
        revocation_provider: WorkflowRevocationProvider,
        state_store: WorkflowResumeStateStore | None = None,
        audit_sink: WorkflowIntegrityAuditSink | None = None,
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._trusted_keys = {item.key_id: item.model_copy(deep=True) for item in trusted_keys}
        self._authorizer = authorizer
        self._revocations = revocation_provider
        self._state_store = state_store or MemoryWorkflowResumeStateStore()
        self._audit_sink = audit_sink

    @property
    def policy(self) -> WorkflowIntegrityPolicy:
        return self._policy.model_copy(deep=True)

    def verify_resume(
        self,
        state: PersistedWorkflowState,
        context: WorkflowResumeContext,
        *,
        now: datetime | None = None,
    ) -> WorkflowIntegrityDecision:
        """Fail closed unless checkpoint, chain, context, and live authority agree."""
        current_time = now or utcnow()
        checkpoint = state.checkpoint
        findings = self._checkpoint_findings(checkpoint, current_time)
        findings.extend(self._context_findings(checkpoint, context))
        findings.extend(self._chain_findings(state, current_time))
        findings.extend(self._pending_findings(checkpoint, context, current_time))
        findings.extend(self._revocation_findings(checkpoint, current_time))
        if findings:
            return self._blocked(checkpoint, findings, current_time)

        try:
            authorized = self._authorizer.authorize_resume(context, checkpoint, current_time)
        except Exception:
            return self._blocked(
                checkpoint,
                [
                    self._finding(
                        WorkflowIntegrityCode.AUTHORIZATION_UNAVAILABLE,
                        "Resume authorization service is unavailable",
                    )
                ],
                current_time,
            )
        if not authorized:
            return self._blocked(
                checkpoint,
                [
                    self._finding(
                        WorkflowIntegrityCode.AUTHORIZATION_DENIED,
                        "Current authority denied workflow resume",
                    )
                ],
                current_time,
            )

        try:
            claim = self._state_store.claim_resume(
                workflow_reference(checkpoint.workflow_id),
                checkpoint.checkpoint_sequence,
                checkpoint.checkpoint_digest,
                checkpoint.execution_chain_head_digest,
                checkpoint.expires_at,
                current_time,
            )
        except Exception:
            claim = WorkflowResumeClaimStatus.FULL
        if claim != WorkflowResumeClaimStatus.CLAIMED:
            code = {
                WorkflowResumeClaimStatus.REPLAYED: WorkflowIntegrityCode.RESUME_REPLAYED,
                WorkflowResumeClaimStatus.ROLLBACK: WorkflowIntegrityCode.ROLLBACK_DETECTED,
                WorkflowResumeClaimStatus.OUT_OF_ORDER: WorkflowIntegrityCode.ROLLBACK_DETECTED,
                WorkflowResumeClaimStatus.COLLISION: WorkflowIntegrityCode.ROLLBACK_DETECTED,
            }.get(claim, WorkflowIntegrityCode.RESUME_STATE_UNAVAILABLE)
            return self._blocked(
                checkpoint,
                [self._finding(code, "Atomic resume state rejected the checkpoint")],
                current_time,
            )

        authorization = AuthorizedWorkflowResume(
            resume_id=f"workflow-resume-{uuid.uuid4()}",
            checkpoint_digest=checkpoint.checkpoint_digest,
            checkpoint_sequence=checkpoint.checkpoint_sequence,
            chain_head_digest=checkpoint.execution_chain_head_digest,
            chain_length=checkpoint.execution_chain_length,
            workflow_id=checkpoint.workflow_id,
            tenant_id=checkpoint.tenant_id,
            agent_id=checkpoint.agent_id,
            session_id=checkpoint.session_id,
            goal_digest=checkpoint.goal_digest,
            plan_digest=checkpoint.plan_digest,
            resume_authorization_digest=checkpoint.resume_authorization_digest,
            issued_at=current_time,
            expires_at=min(
                checkpoint.expires_at,
                current_time + timedelta(seconds=self._policy.resume_permit_ttl_seconds),
            ),
        )
        self._emit(
            checkpoint,
            WorkflowIntegrityCode.RESUME_ALLOWED,
            GuardAction.ALLOW,
            current_time,
        )
        return WorkflowIntegrityDecision(
            action=GuardAction.ALLOW,
            authorization=authorization,
        )

    def require_resume(
        self,
        state: PersistedWorkflowState,
        context: WorkflowResumeContext,
        *,
        now: datetime | None = None,
    ) -> AuthorizedWorkflowResume:
        decision = self.verify_resume(state, context, now=now)
        if not decision.is_authorized or decision.authorization is None:
            raise WorkflowIntegrityError(decision=decision)
        return decision.authorization

    def _checkpoint_findings(
        self,
        checkpoint: PersistentWorkflowCheckpoint,
        now: datetime,
    ) -> list[WorkflowIntegrityFinding]:
        findings = self._signature_findings(
            key_id=checkpoint.key_id,
            authority_id=checkpoint.authority_id,
            signature=checkpoint.signature,
            signing_bytes=checkpoint.signing_bytes,
            signed_at=checkpoint.issued_at,
            checkpoint=True,
        )
        skew = timedelta(seconds=self._policy.clock_skew_seconds)
        if checkpoint.issued_at > now + skew:
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.CHECKPOINT_NOT_YET_VALID,
                    "Checkpoint issuance time is in the future",
                )
            )
        if now >= checkpoint.expires_at:
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.CHECKPOINT_EXPIRED,
                    "Checkpoint has expired",
                )
            )
        if (
            now - checkpoint.issued_at
            > timedelta(seconds=self._policy.maximum_checkpoint_age_seconds) + skew
        ):
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.CHECKPOINT_TOO_OLD,
                    "Checkpoint exceeds the maximum resume age",
                )
            )
        if checkpoint.expires_at - checkpoint.issued_at > timedelta(
            seconds=self._policy.maximum_checkpoint_ttl_seconds
        ):
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.CHECKPOINT_TTL_EXCEEDED,
                    "Checkpoint lifetime exceeds policy",
                )
            )
        return findings

    def _context_findings(
        self,
        checkpoint: PersistentWorkflowCheckpoint,
        context: WorkflowResumeContext,
    ) -> list[WorkflowIntegrityFinding]:
        findings: list[WorkflowIntegrityFinding] = []
        identities = (
            checkpoint.workflow_id,
            checkpoint.tenant_id,
            checkpoint.agent_id,
            checkpoint.session_id,
            checkpoint.goal_digest,
            checkpoint.plan_digest,
            checkpoint.resume_authorization_digest,
        )
        expected_identities = (
            context.workflow_id,
            context.tenant_id,
            context.agent_id,
            context.session_id,
            context.goal_digest,
            context.plan_digest,
            context.resume_authorization_digest,
        )
        if identities != expected_identities:
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.CHECKPOINT_CONTEXT_MISMATCH,
                    "Checkpoint does not match trusted workflow context",
                )
            )
        if checkpoint.policy_versions != context.policy_versions:
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.POLICY_MISMATCH,
                    "Persisted policy revisions are not current",
                )
            )
        if (
            checkpoint.checkpoint_sequence != context.expected_checkpoint_sequence
            or checkpoint.checkpoint_digest != context.expected_checkpoint_digest
        ):
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.ROLLBACK_DETECTED,
                    "Checkpoint does not match the trusted continuity anchor",
                )
            )
        if checkpoint.prior_checkpoint_digest != context.expected_prior_checkpoint_digest:
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.PRIOR_STATE_MISMATCH,
                    "Checkpoint predecessor does not match trusted state",
                )
            )
        if (
            checkpoint.chain_id != context.expected_chain_id
            or checkpoint.execution_chain_length != context.expected_chain_length
            or checkpoint.execution_chain_head_digest != context.expected_chain_head_digest
        ):
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.CHECKPOINT_CHAIN_MISMATCH,
                    "Execution chain does not match the trusted continuity anchor",
                )
            )
        return findings

    def _chain_findings(
        self,
        state: PersistedWorkflowState,
        now: datetime,
    ) -> list[WorkflowIntegrityFinding]:
        checkpoint = state.checkpoint
        chain = state.execution_chain
        findings: list[WorkflowIntegrityFinding] = []
        if len(chain) > self._policy.maximum_chain_entries:
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.EXECUTION_INSERTION,
                    "Execution chain exceeds policy capacity",
                )
            )
        if len(chain) < checkpoint.execution_chain_length:
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.EXECUTION_DELETION,
                    "Execution chain is missing signed entries",
                )
            )
        elif len(chain) > checkpoint.execution_chain_length:
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.EXECUTION_INSERTION,
                    "Execution chain contains uncommitted entries",
                )
            )
        seen_ids: set[str] = set()
        previous: WorkflowExecutionEntry | None = None
        for index, entry in enumerate(chain):
            if entry.entry_id in seen_ids:
                findings.append(
                    self._finding(
                        WorkflowIntegrityCode.EXECUTION_INSERTION,
                        "Execution chain contains a duplicate entry",
                    )
                )
            seen_ids.add(entry.entry_id)
            if entry.sequence != index:
                findings.append(
                    self._finding(
                        WorkflowIntegrityCode.EXECUTION_REORDERED,
                        "Execution entry sequence is not contiguous",
                    )
                )
            expected_prior = previous.entry_digest if previous else None
            if entry.prior_entry_digest != expected_prior:
                findings.append(
                    self._finding(
                        WorkflowIntegrityCode.EXECUTION_REORDERED,
                        "Execution entry predecessor digest is invalid",
                    )
                )
            expected_context = (
                checkpoint.chain_id,
                checkpoint.workflow_id,
                checkpoint.tenant_id,
                checkpoint.agent_id,
                checkpoint.session_id,
                checkpoint.goal_digest,
                checkpoint.plan_digest,
            )
            actual_context = (
                entry.chain_id,
                entry.workflow_id,
                entry.tenant_id,
                entry.agent_id,
                entry.session_id,
                entry.goal_digest,
                entry.plan_digest,
            )
            if actual_context != expected_context:
                findings.append(
                    self._finding(
                        WorkflowIntegrityCode.EXECUTION_CONTEXT_MISMATCH,
                        "Execution entry does not match checkpoint context",
                    )
                )
            findings.extend(
                self._signature_findings(
                    key_id=entry.key_id,
                    authority_id=entry.authority_id,
                    signature=entry.signature,
                    signing_bytes=entry.signing_bytes,
                    signed_at=entry.occurred_at,
                    checkpoint=False,
                )
            )
            if (
                entry.occurred_at
                > checkpoint.issued_at + timedelta(seconds=self._policy.clock_skew_seconds)
                or (previous is not None and entry.occurred_at < previous.occurred_at)
                or entry.occurred_at > now + timedelta(seconds=self._policy.clock_skew_seconds)
            ):
                findings.append(
                    self._finding(
                        WorkflowIntegrityCode.EXECUTION_TIME_INVALID,
                        "Execution entry time is inconsistent",
                    )
                )
            previous = entry
        actual_head = chain[-1].entry_digest if chain else EMPTY_CHAIN_DIGEST
        if actual_head != checkpoint.execution_chain_head_digest:
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.CHECKPOINT_CHAIN_MISMATCH,
                    "Execution chain head does not match checkpoint",
                )
            )
        return findings

    def _pending_findings(
        self,
        checkpoint: PersistentWorkflowCheckpoint,
        context: WorkflowResumeContext,
        now: datetime,
    ) -> list[WorkflowIntegrityFinding]:
        findings: list[WorkflowIntegrityFinding] = []
        if len(checkpoint.pending_actions) > self._policy.maximum_pending_actions:
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.PENDING_ACTION_INVALID,
                    "Pending action count exceeds policy",
                )
            )
        if len(checkpoint.pending_approvals) > self._policy.maximum_pending_approvals:
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.PENDING_ACTION_INVALID,
                    "Pending approval count exceeds policy",
                )
            )
        if any(item.expires_at <= now for item in checkpoint.pending_actions):
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.PENDING_ACTION_INVALID,
                    "A pending action is expired",
                )
            )
        if any(item.expires_at <= now for item in checkpoint.pending_approvals):
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.PENDING_APPROVAL_EXPIRED,
                    "A pending approval is expired",
                )
            )
        persisted_limits = {item.budget_id: item.limit for item in checkpoint.budgets}
        if persisted_limits != context.budget_limits:
            findings.append(
                self._finding(
                    WorkflowIntegrityCode.BUDGET_INVALID,
                    "Persisted budget limits do not match trusted policy",
                )
            )
        return findings

    def _revocation_findings(
        self,
        checkpoint: PersistentWorkflowCheckpoint,
        now: datetime,
    ) -> list[WorkflowIntegrityFinding]:
        try:
            revoked = self._revocations.is_revoked(
                checkpoint.workflow_id,
                checkpoint.checkpoint_digest,
                now,
            )
        except Exception:
            return [
                self._finding(
                    WorkflowIntegrityCode.REVOCATION_UNAVAILABLE,
                    "Workflow revocation state is unavailable",
                )
            ]
        if revoked:
            return [
                self._finding(
                    WorkflowIntegrityCode.WORKFLOW_REVOKED,
                    "Workflow or checkpoint has been revoked",
                )
            ]
        return []

    def _signature_findings(
        self,
        *,
        key_id: str,
        authority_id: str,
        signature: str | None,
        signing_bytes: bytes,
        signed_at: datetime,
        checkpoint: bool,
    ) -> list[WorkflowIntegrityFinding]:
        if signature is None:
            code = (
                WorkflowIntegrityCode.CHECKPOINT_UNSIGNED
                if checkpoint
                else WorkflowIntegrityCode.EXECUTION_ENTRY_UNSIGNED
            )
            return [self._finding(code, "Persistent state is unsigned")]
        key = self._trusted_keys.get(key_id)
        if (
            key is None
            or key.authority_id != authority_id
            or authority_id not in self._policy.trusted_authority_ids
        ):
            code = (
                WorkflowIntegrityCode.CHECKPOINT_KEY_UNKNOWN
                if checkpoint
                else WorkflowIntegrityCode.EXECUTION_KEY_UNKNOWN
            )
            return [self._finding(code, "Signing key is not trusted")]
        if (
            key.revoked
            or (key.active_from is not None and signed_at < key.active_from)
            or (key.expires_at is not None and signed_at >= key.expires_at)
        ):
            code = (
                WorkflowIntegrityCode.CHECKPOINT_KEY_INACTIVE
                if checkpoint
                else WorkflowIntegrityCode.EXECUTION_KEY_INACTIVE
            )
            return [self._finding(code, "Signing key was not active")]
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(
                bytes.fromhex(signature),
                signing_bytes,
            )
        except (InvalidSignature, ValueError):
            code = (
                WorkflowIntegrityCode.CHECKPOINT_SIGNATURE_INVALID
                if checkpoint
                else WorkflowIntegrityCode.EXECUTION_SIGNATURE_INVALID
            )
            return [self._finding(code, "Persistent state signature is invalid")]
        return []

    @staticmethod
    def _finding(code: WorkflowIntegrityCode, message: str) -> WorkflowIntegrityFinding:
        return WorkflowIntegrityFinding(code=code, severity=Severity.CRITICAL, message=message)

    def _blocked(
        self,
        checkpoint: PersistentWorkflowCheckpoint,
        findings: list[WorkflowIntegrityFinding],
        now: datetime,
    ) -> WorkflowIntegrityDecision:
        unique = tuple(dict.fromkeys((item.code, item.message) for item in findings))
        normalized = tuple(
            WorkflowIntegrityFinding(code=code, severity=Severity.CRITICAL, message=message)
            for code, message in unique
        )
        self._emit(checkpoint, normalized[0].code, GuardAction.BLOCK, now)
        return WorkflowIntegrityDecision(action=GuardAction.BLOCK, findings=normalized)

    def _emit(
        self,
        checkpoint: PersistentWorkflowCheckpoint,
        code: WorkflowIntegrityCode,
        action: GuardAction,
        now: datetime,
    ) -> None:
        if self._audit_sink is None:
            return
        with contextlib.suppress(Exception):
            self._audit_sink.emit(
                WorkflowIntegrityAuditEvent(
                    event_id=str(uuid.uuid4()),
                    occurred_at=now,
                    phase=WorkflowIntegrityPhase.VERIFY_RESUME,
                    code=code,
                    action=action,
                    workflow_ref=workflow_reference(checkpoint.workflow_id),
                    tenant_ref=workflow_reference(checkpoint.tenant_id),
                    agent_ref=workflow_reference(checkpoint.agent_id),
                    session_ref=workflow_reference(checkpoint.session_id),
                    checkpoint_ref=workflow_reference(checkpoint.checkpoint_digest),
                    checkpoint_sequence=checkpoint.checkpoint_sequence,
                    chain_length=checkpoint.execution_chain_length,
                )
            )

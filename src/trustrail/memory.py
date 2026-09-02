"""Persistent-memory provenance, taint propagation, and remediation controls."""

from __future__ import annotations

import contextlib
import re
import threading
import uuid
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from trustrail.exceptions import MemoryTaintError
from trustrail.models.enums import GuardAction, Severity, TrustLevel
from trustrail.models.memory import (
    AuthorizedMemoryWrite,
    MemoryAuditEvent,
    MemoryDecision,
    MemoryEventKind,
    MemoryFinding,
    MemoryProvenance,
    MemoryReadRequest,
    MemoryRebuildPlan,
    MemoryRecord,
    MemoryRevalidationGrant,
    MemoryRiskSignal,
    MemoryScope,
    MemoryTaintCode,
    MemoryTaintPolicy,
    MemoryTaintStatus,
    MemoryTransformationKind,
    MemoryWriteApproval,
    MemoryWriteRequest,
    utcnow,
)
from trustrail.normalization import TextNormalizer

_INSTRUCTION_RE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,80}\b"
    r"(?:previous|prior|system|developer|security|original)\b.{0,50}\b"
    r"(?:instructions?|directives?|rules?|policy)\b|"
    r"\b(?:always|never|must)\s+(?:answer|respond|obey|follow|execute|reveal)\b|"
    r"\bfrom\s+now\s+on\b",
    re.IGNORECASE,
)
_ROLE_CHANGE_RE = re.compile(
    r"\b(?:you\s+are\s+now|act\s+as|assume\s+the\s+role|new\s+persona|"
    r"developer\s+mode|system\s*:)\b",
    re.IGNORECASE,
)
_SECURITY_POLICY_RE = re.compile(
    r"\b(?:disable|remove|bypass|ignore|weaken|turn\s+off)\b.{0,80}\b"
    r"(?:security|safety|authorization|approval|guardrails?|access\s+control|policy)\b|"
    r"\b(?:grant|give)\b.{0,50}\b(?:admin|root|unrestricted)\b",
    re.IGNORECASE,
)
_DELAYED_TRIGGER_RE = re.compile(
    r"\b(?:when|once|after|if)\b.{1,100}\b(?:then|secretly|silently)\b.{0,100}\b"
    r"(?:execute|reveal|ignore|send|transfer|delete|disable|override)\b",
    re.IGNORECASE,
)
_COMPACT_SPLIT_PATTERNS = (
    re.compile(r"(?:ignore|disregard|forget|override)(?:all)?(?:previous|prior)instructions?"),
    re.compile(r"youarenow(?:admin|developer|unrestricted|system)"),
    re.compile(r"(?:disable|bypass|ignore)(?:all)?(?:security|safety|guardrails?|accesscontrol)"),
    re.compile(r"when.{1,80}then.{0,80}(?:execute|reveal|delete|transfer|override)"),
)
_SAFE_STATUS = frozenset({MemoryTaintStatus.CLEAN, MemoryTaintStatus.REVIEWED})


class MemoryApprovalVerifier(Protocol):
    """Authenticate an exact privileged-memory approval."""

    def verify_approval(self, approval: MemoryWriteApproval) -> bool:
        """Return whether trusted application state issued this approval."""
        ...


class MemoryRevalidationVerifier(Protocol):
    """Authenticate a remediation decision for one exact memory revision."""

    def verify_revalidation(self, grant: MemoryRevalidationGrant) -> bool:
        """Return whether a trusted reviewer issued this grant."""
        ...


class MemoryTaintAuditSink(Protocol):
    """Persist metadata-only memory lifecycle events."""

    def emit(self, event: MemoryAuditEvent) -> None:
        """Persist one content-free event."""
        ...


class MemoryRebuildHook(Protocol):
    """Application hook for rebuilding affected memories from authoritative sources."""

    def request_rebuild(self, plan: MemoryRebuildPlan) -> None:
        """Queue a safe rebuild without using affected memories as source material."""
        ...


class MemoryTaintAuditBuffer:
    """Bounded in-memory audit sink for tests and local development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[MemoryAuditEvent] = deque(maxlen=max_events)

    def emit(self, event: MemoryAuditEvent) -> None:
        self._events.append(event)

    @property
    def events(self) -> list[MemoryAuditEvent]:
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()


@dataclass
class _PendingWrite:
    record: MemoryRecord
    normalized_content: str
    authorization_digest: str


class MemoryTaintManager:
    """Completely mediate persistent-memory writes, reads, and remediation.

    State is process-local and guarded by one lock. Applications with multiple
    workers must provide equivalent shared atomic catalog, replay, and history
    state at their persistence boundary.
    """

    def __init__(
        self,
        policy: MemoryTaintPolicy,
        *,
        approval_verifier: MemoryApprovalVerifier | None = None,
        revalidation_verifier: MemoryRevalidationVerifier | None = None,
        audit_sink: MemoryTaintAuditSink | None = None,
        rebuild_hook: MemoryRebuildHook | None = None,
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._approval_verifier = approval_verifier
        self._revalidation_verifier = revalidation_verifier
        self._audit_sink = audit_sink
        self._rebuild_hook = rebuild_hook
        self._catalog: dict[str, MemoryRecord] = {}
        self._pending: dict[str, _PendingWrite] = {}
        self._pending_memory_ids: set[str] = set()
        self._used_authorization_ids: set[str] = set()
        self._used_approval_ids: set[str] = set()
        self._used_revalidation_ids: set[str] = set()
        self._recent: dict[tuple[str, str, str], deque[str]] = {}
        self._event_sequence = 0
        self._normalizer = TextNormalizer()
        self._lock = threading.Lock()

    @property
    def policy(self) -> MemoryTaintPolicy:
        """Return a defensive copy of the active memory policy."""
        return self._policy.model_copy(deep=True)

    @property
    def records(self) -> tuple[MemoryRecord, ...]:
        """Return metadata-only catalog records in deterministic ID order."""
        with self._lock:
            return tuple(self._catalog[key] for key in sorted(self._catalog))

    def authorize_write(
        self,
        request: MemoryWriteRequest,
        content: str,
        *,
        approval: MemoryWriteApproval | None = None,
        now: datetime | None = None,
    ) -> MemoryDecision:
        """Analyze and reserve one exact write without persisting its content."""
        current_time = now or utcnow()
        record = request.record
        findings, signals, normalized = self._write_findings(request, content)
        events: list[MemoryAuditEvent] = []
        authorization: AuthorizedMemoryWrite | None = None
        effective_record: MemoryRecord | None = None

        with self._lock:
            findings.extend(self._catalog_write_findings(request, signals, normalized))
            signals.update(signal for finding in findings for signal in finding.signals)
            non_overridable = signals & self._policy.non_overridable_signals
            hard_failure = any(
                finding.code
                in {
                    MemoryTaintCode.REQUEST_INTEGRITY_INVALID,
                    MemoryTaintCode.RECORD_INTEGRITY_INVALID,
                    MemoryTaintCode.CONTENT_INTEGRITY_INVALID,
                    MemoryTaintCode.MEMORY_ALREADY_EXISTS,
                    MemoryTaintCode.DEPENDENCY_UNKNOWN,
                    MemoryTaintCode.DEPENDENCY_REBOUND,
                    MemoryTaintCode.TENANT_MISMATCH,
                    MemoryTaintCode.PURPOSE_MISMATCH,
                    MemoryTaintCode.CROSS_USER_WRITE,
                    MemoryTaintCode.SHARED_WRITE_UNAUTHORIZED,
                }
                for finding in findings
            )
            privileged = signals & self._policy.privileged_signals

            action = GuardAction.ALLOW
            if non_overridable or hard_failure:
                action = GuardAction.QUARANTINE
                with contextlib.suppress(ValueError):
                    effective_record = self._effective_record(
                        record,
                        status=MemoryTaintStatus.QUARANTINED,
                        signals=signals,
                    )
            elif privileged:
                approval_findings = self._approval_findings(
                    request, privileged, approval, current_time
                )
                findings.extend(approval_findings)
                if approval_findings:
                    action = GuardAction.REQUIRE_APPROVAL
                else:
                    if approval is None:
                        raise AssertionError("approval unexpectedly missing")
                    self._used_approval_ids.add(approval.approval_id)
                    effective_record = self._effective_record(
                        record,
                        status=MemoryTaintStatus.REVIEWED,
                        signals=signals,
                        approval_id=approval.approval_id,
                    )
            else:
                effective_record = self._effective_record(
                    record,
                    status=MemoryTaintStatus.CLEAN,
                    signals=signals,
                )

            if action == GuardAction.ALLOW and effective_record is not None:
                authorization = AuthorizedMemoryWrite.create(
                    authorization_id=str(uuid.uuid4()),
                    request_digest=request.request_digest,
                    memory_id=effective_record.memory_id,
                    record_digest=effective_record.record_digest,
                    content_digest=effective_record.content_digest,
                    tenant_id=effective_record.tenant_id,
                    purpose_id=effective_record.purpose_id,
                    issued_at=current_time,
                    expires_at=current_time
                    + timedelta(seconds=self._policy.authorization_ttl_seconds),
                )
                self._pending[authorization.authorization_id] = _PendingWrite(
                    record=effective_record,
                    normalized_content=normalized,
                    authorization_digest=authorization.authorization_digest,
                )
                self._pending_memory_ids.add(effective_record.memory_id)

            event_action = action
            event_kind = (
                MemoryEventKind.WRITE_ALLOWED
                if action == GuardAction.ALLOW
                else MemoryEventKind.WRITE_DENIED
            )
            events.append(
                self._event(
                    kind=event_kind,
                    memory_ids=(record.memory_id,),
                    tenant_id=record.tenant_id,
                    purpose_id=record.purpose_id,
                    action=event_action,
                    findings=findings,
                    now=current_time,
                )
            )

        self._publish(events)
        return MemoryDecision(
            action=GuardAction.ALLOW if authorization is not None else action,
            findings=tuple(self._deduplicate(findings)),
            authorization=authorization,
            record=effective_record,
            events=tuple(events),
        )

    def require_write(
        self,
        request: MemoryWriteRequest,
        content: str,
        *,
        approval: MemoryWriteApproval | None = None,
        now: datetime | None = None,
    ) -> AuthorizedMemoryWrite:
        """Return a write lease or raise before durable storage."""
        result = self.authorize_write(request, content, approval=approval, now=now)
        if not result.is_authorized or result.authorization is None:
            raise MemoryTaintError(result)
        return result.authorization

    def commit_write(
        self,
        authorization: AuthorizedMemoryWrite,
        stored_content: str,
        *,
        now: datetime | None = None,
    ) -> MemoryDecision:
        """Commit catalog state after the backend confirms the exact stored bytes."""
        current_time = now or utcnow()
        findings: list[MemoryFinding] = []
        events: list[MemoryAuditEvent] = []
        record: MemoryRecord | None = None
        with self._lock:
            pending = self._pending.get(authorization.authorization_id)
            if not authorization.has_valid_integrity:
                findings.append(
                    self._finding(
                        MemoryTaintCode.AUTHORIZATION_INVALID,
                        Severity.CRITICAL,
                        "Memory write authorization integrity is invalid",
                    )
                )
            if authorization.expires_at < current_time:
                findings.append(
                    self._finding(
                        MemoryTaintCode.AUTHORIZATION_EXPIRED,
                        Severity.HIGH,
                        "Memory write authorization has expired",
                    )
                )
            if authorization.authorization_id in self._used_authorization_ids:
                findings.append(
                    self._finding(
                        MemoryTaintCode.AUTHORIZATION_REPLAYED,
                        Severity.CRITICAL,
                        "Memory write authorization has already been consumed",
                    )
                )
            if (
                pending is None
                or pending.authorization_digest != authorization.authorization_digest
                or pending.record.record_digest != authorization.record_digest
            ):
                findings.append(
                    self._finding(
                        MemoryTaintCode.AUTHORIZATION_INVALID,
                        Severity.CRITICAL,
                        "Memory write authorization does not match pending state",
                    )
                )
            if pending is not None and not pending.record.matches_content(stored_content):
                findings.append(
                    self._finding(
                        MemoryTaintCode.CONTENT_INTEGRITY_INVALID,
                        Severity.CRITICAL,
                        "Stored memory bytes do not match the authorized content",
                        {MemoryRiskSignal.INTEGRITY_MISMATCH},
                    )
                )

            if not findings and pending is not None:
                record = pending.record
                self._pending.pop(authorization.authorization_id)
                self._pending_memory_ids.discard(record.memory_id)
                self._used_authorization_ids.add(authorization.authorization_id)
                self._catalog[record.memory_id] = record
                history = self._history(record)
                history.append(pending.normalized_content[-self._policy.max_history_chars :])
                events.append(
                    self._event(
                        kind=MemoryEventKind.WRITE_COMMITTED,
                        memory_ids=(record.memory_id,),
                        tenant_id=record.tenant_id,
                        purpose_id=record.purpose_id,
                        action=GuardAction.ALLOW,
                        now=current_time,
                    )
                )
            else:
                event_record = pending.record if pending is not None else None
                events.append(
                    self._event(
                        kind=MemoryEventKind.WRITE_DENIED,
                        memory_ids=(authorization.memory_id,),
                        tenant_id=(
                            event_record.tenant_id
                            if event_record is not None
                            else authorization.tenant_id
                        ),
                        purpose_id=(
                            event_record.purpose_id
                            if event_record is not None
                            else authorization.purpose_id
                        ),
                        action=GuardAction.BLOCK,
                        findings=findings,
                        now=current_time,
                    )
                )

        self._publish(events)
        return MemoryDecision(
            action=GuardAction.ALLOW if record is not None else GuardAction.BLOCK,
            findings=tuple(self._deduplicate(findings)),
            record=record,
            events=tuple(events),
        )

    def abandon_write(
        self,
        authorization: AuthorizedMemoryWrite,
        *,
        now: datetime | None = None,
    ) -> None:
        """Release a pending reservation only after confirming storage did not occur."""
        current_time = now or utcnow()
        event: MemoryAuditEvent | None = None
        with self._lock:
            pending = self._pending.get(authorization.authorization_id)
            if (
                pending is not None
                and pending.authorization_digest == authorization.authorization_digest
            ):
                self._pending.pop(authorization.authorization_id)
                self._pending_memory_ids.discard(pending.record.memory_id)
                self._used_authorization_ids.add(authorization.authorization_id)
                event = self._event(
                    kind=MemoryEventKind.WRITE_ABANDONED,
                    memory_ids=(pending.record.memory_id,),
                    tenant_id=pending.record.tenant_id,
                    purpose_id=pending.record.purpose_id,
                    action=GuardAction.BLOCK,
                    now=current_time,
                )
        if event is not None:
            self._publish([event])

    def authorize_retrieval(
        self,
        request: MemoryReadRequest,
        contents: Mapping[str, str],
        *,
        now: datetime | None = None,
    ) -> MemoryDecision:
        """Atomically authorize exact records and bytes for prompt assembly."""
        current_time = now or utcnow()
        findings: list[MemoryFinding] = []
        selected: list[MemoryRecord] = []
        events: list[MemoryAuditEvent] = []
        newly_tainted: set[str] = set()
        normalized_contents: list[str] = []
        with self._lock:
            for memory_id in request.memory_ids:
                record = self._catalog.get(memory_id)
                if record is None:
                    findings.append(
                        self._finding(
                            MemoryTaintCode.MEMORY_UNKNOWN,
                            Severity.CRITICAL,
                            "Requested memory is absent from the trusted catalog",
                        )
                    )
                    continue
                selected.append(record)
                findings.extend(self._read_record_findings(request, record, current_time))
                content = contents.get(memory_id)
                if content is None or not record.matches_content(content):
                    findings.append(
                        self._finding(
                            MemoryTaintCode.CONTENT_INTEGRITY_INVALID,
                            Severity.CRITICAL,
                            "Retrieved memory bytes do not match catalog integrity",
                            {MemoryRiskSignal.INTEGRITY_MISMATCH},
                        )
                    )
                    newly_tainted.add(memory_id)
                    continue
                normalized = self._normalize(content)
                normalized_contents.append(normalized)
                current_signals = self._content_signals(normalized)
                unexpected = current_signals - record.taint_signals
                if unexpected:
                    findings.extend(self._signal_findings(unexpected))
                    newly_tainted.add(memory_id)

            if len(normalized_contents) > 1 and self._has_split_payload(normalized_contents):
                findings.append(
                    self._finding(
                        MemoryTaintCode.SPLIT_ENTRY_POISONING,
                        Severity.CRITICAL,
                        "Retrieved memories compose a split persistent instruction",
                        {MemoryRiskSignal.SPLIT_ENTRY},
                    )
                )
                newly_tainted.update(record.memory_id for record in selected)

            for memory_id in sorted(newly_tainted):
                self._transition_affected(
                    memory_id,
                    MemoryTaintStatus.QUARANTINED,
                    MemoryRiskSignal.TAINT_INHERITANCE,
                )

            action = GuardAction.ALLOW if not findings else GuardAction.BLOCK
            events.append(
                self._event(
                    kind=(
                        MemoryEventKind.RETRIEVAL_ALLOWED
                        if action == GuardAction.ALLOW
                        else MemoryEventKind.RETRIEVAL_DENIED
                    ),
                    memory_ids=request.memory_ids,
                    tenant_id=request.tenant_id,
                    purpose_id=request.purpose_id,
                    action=action,
                    findings=findings,
                    now=current_time,
                )
            )

        self._publish(events)
        return MemoryDecision(
            action=action,
            findings=tuple(self._deduplicate(findings)),
            records=tuple(selected) if action == GuardAction.ALLOW else (),
            events=tuple(events),
        )

    def require_retrieval(
        self,
        request: MemoryReadRequest,
        contents: Mapping[str, str],
        *,
        now: datetime | None = None,
    ) -> tuple[MemoryRecord, ...]:
        """Return safe metadata records or raise before prompt assembly."""
        result = self.authorize_retrieval(request, contents, now=now)
        if not result.is_authorized:
            raise MemoryTaintError(result)
        return result.records

    def quarantine(
        self,
        memory_id: str,
        *,
        reason_code: str,
        now: datetime | None = None,
    ) -> MemoryDecision:
        """Quarantine one memory and every transitive dependent."""
        return self._remediate(
            memory_id,
            status=MemoryTaintStatus.QUARANTINED,
            event_kind=MemoryEventKind.QUARANTINED,
            reason_code=reason_code,
            now=now,
        )

    def invalidate(
        self,
        memory_id: str,
        *,
        reason_code: str,
        now: datetime | None = None,
    ) -> MemoryDecision:
        """Invalidate one memory and every transitive dependent."""
        return self._remediate(
            memory_id,
            status=MemoryTaintStatus.INVALIDATED,
            event_kind=MemoryEventKind.INVALIDATED,
            reason_code=reason_code,
            now=now,
        )

    def trace_dependencies(self, memory_id: str) -> tuple[MemoryRecord, ...]:
        """Trace declared ancestors in deterministic breadth-first order."""
        with self._lock:
            return tuple(self._trace(memory_id, descendants=False))

    def trace_dependents(self, memory_id: str) -> tuple[MemoryRecord, ...]:
        """Trace transitive descendants affected by a memory revision."""
        with self._lock:
            return tuple(self._trace(memory_id, descendants=True))

    def revalidate(
        self,
        memory_id: str,
        content: str,
        grant: MemoryRevalidationGrant,
        *,
        now: datetime | None = None,
    ) -> MemoryDecision:
        """Create a safe metadata revision after independent exact review."""
        current_time = now or utcnow()
        findings: list[MemoryFinding] = []
        events: list[MemoryAuditEvent] = []
        revised: MemoryRecord | None = None
        with self._lock:
            record = self._catalog.get(memory_id)
            if record is None:
                findings.append(
                    self._finding(
                        MemoryTaintCode.MEMORY_UNKNOWN,
                        Severity.CRITICAL,
                        "Memory is absent from the trusted catalog",
                    )
                )
            else:
                findings.extend(self._revalidation_findings(record, content, grant, current_time))
                if not findings:
                    self._used_revalidation_ids.add(grant.grant_id)
                    persistent_signals = self._persistent_record_signals(record)
                    revised = record.transition(
                        status=(
                            MemoryTaintStatus.REVIEWED
                            if persistent_signals
                            else MemoryTaintStatus.CLEAN
                        ),
                        signals=frozenset(persistent_signals),
                        version=record.version + 1,
                    )
                    self._catalog[memory_id] = revised
                    self._replace_history(record, self._normalize(content))
                    events.append(
                        self._event(
                            kind=MemoryEventKind.REVALIDATED,
                            memory_ids=(memory_id,),
                            tenant_id=record.tenant_id,
                            purpose_id=record.purpose_id,
                            action=GuardAction.ALLOW,
                            now=current_time,
                        )
                    )
            if revised is None:
                tenant_id = record.tenant_id if record is not None else grant.tenant_id
                purpose_id = record.purpose_id if record is not None else "unknown-purpose"
                events.append(
                    self._event(
                        kind=MemoryEventKind.REVALIDATION_DENIED,
                        memory_ids=(memory_id,),
                        tenant_id=tenant_id,
                        purpose_id=purpose_id,
                        action=GuardAction.BLOCK,
                        findings=findings,
                        now=current_time,
                    )
                )

        self._publish(events)
        return MemoryDecision(
            action=GuardAction.ALLOW if revised is not None else GuardAction.BLOCK,
            findings=tuple(self._deduplicate(findings)),
            record=revised,
            events=tuple(events),
        )

    def _write_findings(
        self,
        request: MemoryWriteRequest,
        content: str,
    ) -> tuple[list[MemoryFinding], set[MemoryRiskSignal], str]:
        record = request.record
        findings: list[MemoryFinding] = []
        signals = set(record.taint_signals)
        if record.taint_status not in _SAFE_STATUS:
            signals.add(MemoryRiskSignal.TAINT_INHERITANCE)
        if not request.has_valid_integrity:
            findings.append(
                self._finding(
                    MemoryTaintCode.REQUEST_INTEGRITY_INVALID,
                    Severity.CRITICAL,
                    "Memory request integrity is invalid",
                    {MemoryRiskSignal.INTEGRITY_MISMATCH},
                )
            )
        if not record.has_valid_integrity:
            findings.append(
                self._finding(
                    MemoryTaintCode.RECORD_INTEGRITY_INVALID,
                    Severity.CRITICAL,
                    "Memory record integrity is invalid",
                    {MemoryRiskSignal.INTEGRITY_MISMATCH},
                )
            )
        if not record.matches_content(content):
            findings.append(
                self._finding(
                    MemoryTaintCode.CONTENT_INTEGRITY_INVALID,
                    Severity.CRITICAL,
                    "Proposed content does not match the memory record",
                    {MemoryRiskSignal.INTEGRITY_MISMATCH},
                )
            )
        if request.tenant_id != record.tenant_id or request.actor_id != record.writer_id:
            findings.append(
                self._finding(
                    MemoryTaintCode.TENANT_MISMATCH,
                    Severity.CRITICAL,
                    "Request identity is not bound to the memory writer and tenant",
                )
            )
        if request.purpose_id != record.purpose_id:
            findings.append(
                self._finding(
                    MemoryTaintCode.PURPOSE_MISMATCH,
                    Severity.CRITICAL,
                    "Memory request cannot change purpose",
                )
            )
        if record.purpose_id not in self._policy.allowed_purpose_ids:
            findings.append(
                self._finding(
                    MemoryTaintCode.PURPOSE_MISMATCH,
                    Severity.HIGH,
                    "Memory purpose is not allowlisted",
                )
            )
        if len(record.dependencies) > self._policy.max_dependencies:
            findings.append(
                self._finding(
                    MemoryTaintCode.DEPENDENCY_UNKNOWN,
                    Severity.HIGH,
                    "Memory dependency count exceeds policy",
                )
            )
        if len(record.provenance) > self._policy.max_provenance_sources:
            findings.append(
                self._finding(
                    MemoryTaintCode.PROVENANCE_DROPPED,
                    Severity.HIGH,
                    "Memory provenance count exceeds policy",
                    {MemoryRiskSignal.PROVENANCE_DROPPED},
                )
            )
        normalized = self._normalize(content)
        signals.update(self._content_signals(normalized))
        if any(item.trust_level == TrustLevel.UNTRUSTED for item in record.provenance):
            signals.add(MemoryRiskSignal.UNTRUSTED_SOURCE)
        if record.scope != MemoryScope.USER:
            signals.add(MemoryRiskSignal.SHARED_SCOPE)
            if request.actor_id not in self._policy.trusted_writer_ids:
                findings.append(
                    self._finding(
                        MemoryTaintCode.SHARED_WRITE_UNAUTHORIZED,
                        Severity.CRITICAL,
                        "Shared memory requires a trusted application writer",
                        {MemoryRiskSignal.SHARED_SCOPE},
                    )
                )
        elif (
            request.actor_user_id != record.owner_user_id
            and request.actor_id not in self._policy.trusted_writer_ids
        ):
            signals.add(MemoryRiskSignal.CROSS_USER)
            findings.append(
                self._finding(
                    MemoryTaintCode.CROSS_USER_WRITE,
                    Severity.CRITICAL,
                    "Untrusted writer cannot persist memory for another user",
                    {MemoryRiskSignal.CROSS_USER},
                )
            )
        findings.extend(self._signal_findings(signals))
        return findings, signals, normalized

    def _catalog_write_findings(
        self,
        request: MemoryWriteRequest,
        signals: set[MemoryRiskSignal],
        normalized: str,
    ) -> list[MemoryFinding]:
        record = request.record
        findings: list[MemoryFinding] = []
        if record.memory_id in self._catalog or record.memory_id in self._pending_memory_ids:
            findings.append(
                self._finding(
                    MemoryTaintCode.MEMORY_ALREADY_EXISTS,
                    Severity.CRITICAL,
                    "Memory ID is already committed or reserved",
                )
            )
        parent_provenance: dict[str, MemoryProvenance] = {}
        conflicting_parent_provenance = False
        inherited_signals: set[MemoryRiskSignal] = set()
        for dependency in record.dependencies:
            parent = self._catalog.get(dependency.memory_id)
            if parent is None:
                findings.append(
                    self._finding(
                        MemoryTaintCode.DEPENDENCY_UNKNOWN,
                        Severity.CRITICAL,
                        "Derived memory references an unknown dependency",
                    )
                )
                continue
            if parent.record_digest != dependency.record_digest:
                findings.append(
                    self._finding(
                        MemoryTaintCode.DEPENDENCY_REBOUND,
                        Severity.CRITICAL,
                        "Derived memory references a stale dependency revision",
                    )
                )
            if parent.tenant_id != record.tenant_id:
                findings.append(
                    self._finding(
                        MemoryTaintCode.TENANT_MISMATCH,
                        Severity.CRITICAL,
                        "Memory transformation cannot cross tenants",
                    )
                )
            if parent.purpose_id != record.purpose_id:
                findings.append(
                    self._finding(
                        MemoryTaintCode.PURPOSE_MISMATCH,
                        Severity.CRITICAL,
                        "Memory transformation cannot change purpose",
                    )
                )
            if parent.scope != record.scope or parent.owner_user_id != record.owner_user_id:
                signals.add(MemoryRiskSignal.CROSS_USER)
                findings.append(
                    self._finding(
                        MemoryTaintCode.CROSS_USER_WRITE,
                        Severity.CRITICAL,
                        "Memory transformation cannot change owner or audience scope",
                        {MemoryRiskSignal.CROSS_USER},
                    )
                )
            for item in parent.provenance:
                existing = parent_provenance.get(item.source_id)
                if existing is not None and existing != item:
                    conflicting_parent_provenance = True
                parent_provenance[item.source_id] = item
            inherited_signals.update(parent.taint_signals)
            if parent.taint_status not in _SAFE_STATUS:
                inherited_signals.add(MemoryRiskSignal.TAINT_INHERITANCE)

        record_provenance = {item.source_id: item for item in record.provenance}
        provenance_changed = conflicting_parent_provenance or any(
            record_provenance.get(source_id) != item
            for source_id, item in parent_provenance.items()
        )
        if provenance_changed:
            signals.add(MemoryRiskSignal.PROVENANCE_DROPPED)
            findings.append(
                self._finding(
                    MemoryTaintCode.PROVENANCE_DROPPED,
                    Severity.CRITICAL,
                    "Derived memory omitted dependency provenance",
                    {MemoryRiskSignal.PROVENANCE_DROPPED},
                )
            )
        if inherited_signals and not inherited_signals.issubset(record.taint_signals):
            laundering_signal = (
                MemoryRiskSignal.SUMMARY_LAUNDERING
                if record.transformation
                in {MemoryTransformationKind.SUMMARY, MemoryTransformationKind.MERGE}
                else MemoryRiskSignal.TAINT_INHERITANCE
            )
            signals.add(laundering_signal)
            code = (
                MemoryTaintCode.SUMMARY_LAUNDERING
                if laundering_signal == MemoryRiskSignal.SUMMARY_LAUNDERING
                else MemoryTaintCode.TAINTED_DEPENDENCY
            )
            findings.append(
                self._finding(
                    code,
                    Severity.CRITICAL,
                    "Derived memory attempted to remove inherited taint",
                    {laundering_signal},
                )
            )
        else:
            signals.update(inherited_signals)

        history = list(self._history(record))
        if history and self._has_split_payload([*history, normalized]):
            signals.add(MemoryRiskSignal.SPLIT_ENTRY)
            findings.append(
                self._finding(
                    MemoryTaintCode.SPLIT_ENTRY_POISONING,
                    Severity.CRITICAL,
                    "Incremental writes compose a split persistent instruction",
                    {MemoryRiskSignal.SPLIT_ENTRY},
                )
            )
        return findings

    def _approval_findings(
        self,
        request: MemoryWriteRequest,
        signals: set[MemoryRiskSignal],
        approval: MemoryWriteApproval | None,
        now: datetime,
    ) -> list[MemoryFinding]:
        if approval is None:
            return [
                self._finding(
                    MemoryTaintCode.PRIVILEGED_WRITE_REQUIRES_APPROVAL,
                    Severity.HIGH,
                    "Privileged memory signals require authenticated approval",
                    signals,
                )
            ]
        if (
            approval.request_digest != request.request_digest
            or approval.tenant_id != request.tenant_id
            or not signals.issubset(approval.approved_signals)
            or not self._verify_approval(approval)
        ):
            return [
                self._finding(
                    MemoryTaintCode.APPROVAL_INVALID,
                    Severity.CRITICAL,
                    "Memory approval is invalid or bound to different signals",
                    signals,
                )
            ]
        if approval.expires_at < now or approval.issued_at > now:
            return [
                self._finding(
                    MemoryTaintCode.APPROVAL_EXPIRED,
                    Severity.HIGH,
                    "Memory approval is outside its validity window",
                    signals,
                )
            ]
        if approval.approval_id in self._used_approval_ids:
            return [
                self._finding(
                    MemoryTaintCode.APPROVAL_REPLAYED,
                    Severity.CRITICAL,
                    "Memory approval has already been consumed",
                    signals,
                )
            ]
        return []

    def _read_record_findings(
        self,
        request: MemoryReadRequest,
        record: MemoryRecord,
        now: datetime,
    ) -> list[MemoryFinding]:
        findings: list[MemoryFinding] = []
        if not record.has_valid_integrity:
            findings.append(
                self._finding(
                    MemoryTaintCode.RECORD_INTEGRITY_INVALID,
                    Severity.CRITICAL,
                    "Catalog record integrity is invalid",
                    {MemoryRiskSignal.INTEGRITY_MISMATCH},
                )
            )
        if request.tenant_id != record.tenant_id:
            findings.append(
                self._finding(
                    MemoryTaintCode.TENANT_MISMATCH,
                    Severity.CRITICAL,
                    "Retrieval cannot cross tenants",
                )
            )
        if request.purpose_id != record.purpose_id:
            findings.append(
                self._finding(
                    MemoryTaintCode.PURPOSE_MISMATCH,
                    Severity.HIGH,
                    "Retrieval cannot change memory purpose",
                )
            )
        if record.scope == MemoryScope.USER and request.reader_user_id != record.owner_user_id:
            findings.append(
                self._finding(
                    MemoryTaintCode.RETRIEVAL_DENIED,
                    Severity.CRITICAL,
                    "User-scoped memory belongs to a different user",
                )
            )
        if record.taint_status == MemoryTaintStatus.QUARANTINED:
            findings.append(
                self._finding(
                    MemoryTaintCode.MEMORY_QUARANTINED,
                    Severity.CRITICAL,
                    "Quarantined memory cannot be retrieved",
                )
            )
        elif record.taint_status == MemoryTaintStatus.INVALIDATED:
            findings.append(
                self._finding(
                    MemoryTaintCode.MEMORY_INVALIDATED,
                    Severity.CRITICAL,
                    "Invalidated memory cannot be retrieved",
                )
            )
        elif record.taint_status not in _SAFE_STATUS:
            findings.append(
                self._finding(
                    MemoryTaintCode.RETRIEVAL_DENIED,
                    Severity.HIGH,
                    "Unreviewed tainted memory cannot be retrieved",
                )
            )
        if record.expires_at is not None and record.expires_at < now:
            findings.append(
                self._finding(
                    MemoryTaintCode.MEMORY_INVALIDATED,
                    Severity.HIGH,
                    "Expired memory cannot be retrieved",
                )
            )
        for dependency in record.dependencies:
            parent = self._catalog.get(dependency.memory_id)
            if (
                parent is None
                or parent.record_digest != dependency.record_digest
                or parent.taint_status not in _SAFE_STATUS
            ):
                findings.append(
                    self._finding(
                        MemoryTaintCode.TAINTED_DEPENDENCY,
                        Severity.CRITICAL,
                        "Memory dependency is missing, changed, or unsafe",
                        {MemoryRiskSignal.TAINT_INHERITANCE},
                    )
                )
        return findings

    def _revalidation_findings(
        self,
        record: MemoryRecord,
        content: str,
        grant: MemoryRevalidationGrant,
        now: datetime,
    ) -> list[MemoryFinding]:
        findings: list[MemoryFinding] = []
        if record.taint_status not in {
            MemoryTaintStatus.SUSPECT,
            MemoryTaintStatus.TAINTED,
            MemoryTaintStatus.QUARANTINED,
        }:
            findings.append(
                self._finding(
                    MemoryTaintCode.REVALIDATION_REJECTED,
                    Severity.HIGH,
                    "Only suspect, tainted, or quarantined memory may be revalidated",
                )
            )
        if (
            grant.memory_id != record.memory_id
            or grant.record_digest != record.record_digest
            or grant.content_digest != record.content_digest
            or grant.tenant_id != record.tenant_id
            or not record.matches_content(content)
            or not self._verify_revalidation(grant)
        ):
            findings.append(
                self._finding(
                    MemoryTaintCode.REVALIDATION_INVALID,
                    Severity.CRITICAL,
                    "Revalidation evidence does not authenticate this memory revision",
                )
            )
        if grant.issued_at > now or grant.expires_at < now:
            findings.append(
                self._finding(
                    MemoryTaintCode.REVALIDATION_INVALID,
                    Severity.HIGH,
                    "Revalidation grant is outside its validity window",
                )
            )
        if grant.grant_id in self._used_revalidation_ids:
            findings.append(
                self._finding(
                    MemoryTaintCode.REVALIDATION_INVALID,
                    Severity.CRITICAL,
                    "Revalidation grant has already been consumed",
                )
            )
        if self._content_signals(self._normalize(content)):
            findings.append(
                self._finding(
                    MemoryTaintCode.REVALIDATION_REJECTED,
                    Severity.CRITICAL,
                    "Revalidation cannot clear currently detected memory risks",
                )
            )
        for dependency in record.dependencies:
            parent = self._catalog.get(dependency.memory_id)
            if (
                parent is None
                or parent.record_digest != dependency.record_digest
                or parent.taint_status not in _SAFE_STATUS
            ):
                findings.append(
                    self._finding(
                        MemoryTaintCode.REVALIDATION_REJECTED,
                        Severity.CRITICAL,
                        "Revalidation cannot clear a stale or tainted dependency",
                    )
                )
        return self._deduplicate(findings)

    def _remediate(
        self,
        memory_id: str,
        *,
        status: MemoryTaintStatus,
        event_kind: MemoryEventKind,
        reason_code: str,
        now: datetime | None,
    ) -> MemoryDecision:
        current_time = now or utcnow()
        findings: list[MemoryFinding] = []
        events: list[MemoryAuditEvent] = []
        plan: MemoryRebuildPlan | None = None
        with self._lock:
            record = self._catalog.get(memory_id)
            if record is None:
                findings.append(
                    self._finding(
                        MemoryTaintCode.MEMORY_UNKNOWN,
                        Severity.CRITICAL,
                        "Memory is absent from the trusted catalog",
                    )
                )
            else:
                affected = self._transition_affected(
                    memory_id, status, MemoryRiskSignal.TAINT_INHERITANCE
                )
                plan = self._rebuild_plan(record, affected, reason_code)
                events.append(
                    self._event(
                        kind=event_kind,
                        memory_ids=tuple(affected),
                        tenant_id=record.tenant_id,
                        purpose_id=record.purpose_id,
                        action=GuardAction.QUARANTINE,
                        now=current_time,
                    )
                )
                events.append(
                    self._event(
                        kind=MemoryEventKind.REBUILD_REQUESTED,
                        memory_ids=tuple(affected),
                        tenant_id=record.tenant_id,
                        purpose_id=record.purpose_id,
                        action=GuardAction.REQUIRE_APPROVAL,
                        findings=[
                            self._finding(
                                MemoryTaintCode.REBUILD_REQUIRED,
                                Severity.HIGH,
                                "Affected memory lineage requires a safe rebuild",
                            )
                        ],
                        now=current_time,
                    )
                )

        self._publish(events)
        if plan is not None:
            self._request_rebuild(plan, events, current_time)
        return MemoryDecision(
            action=GuardAction.QUARANTINE if plan is not None else GuardAction.BLOCK,
            findings=tuple(findings),
            rebuild_plan=plan,
            events=tuple(events),
        )

    def _transition_affected(
        self,
        memory_id: str,
        status: MemoryTaintStatus,
        inherited_signal: MemoryRiskSignal,
    ) -> list[str]:
        root = self._catalog.get(memory_id)
        if root is None:
            return []
        affected = [root, *self._trace(memory_id, descendants=True)]
        result: list[str] = []
        for index, record in enumerate(affected):
            signals = set(record.taint_signals)
            if index > 0:
                signals.add(inherited_signal)
            self._catalog[record.memory_id] = record.transition(
                status=status,
                signals=frozenset(signals),
            )
            result.append(record.memory_id)
        return result

    def _trace(self, memory_id: str, *, descendants: bool) -> list[MemoryRecord]:
        if memory_id not in self._catalog:
            return []
        result: list[MemoryRecord] = []
        seen = {memory_id}
        queue = deque([memory_id])
        while queue:
            current = queue.popleft()
            if descendants:
                related = sorted(
                    record.memory_id
                    for record in self._catalog.values()
                    if any(item.memory_id == current for item in record.dependencies)
                )
            else:
                record = self._catalog[current]
                related = sorted(item.memory_id for item in record.dependencies)
            for related_id in related:
                if related_id in seen or related_id not in self._catalog:
                    continue
                seen.add(related_id)
                queue.append(related_id)
                result.append(self._catalog[related_id])
        return result

    def _rebuild_plan(
        self,
        root: MemoryRecord,
        affected: list[str],
        reason_code: str,
    ) -> MemoryRebuildPlan:
        sources = sorted(
            {
                item.source_id
                for memory_id in affected
                for item in self._catalog[memory_id].provenance
                if item.trust_level == TrustLevel.TRUSTED
            }
        )
        return MemoryRebuildPlan(
            root_memory_id=root.memory_id,
            affected_memory_ids=tuple(affected),
            authoritative_source_ids=tuple(sources),
            tenant_id=root.tenant_id,
            purpose_id=root.purpose_id,
            reason_code=reason_code,
        )

    def _request_rebuild(
        self,
        plan: MemoryRebuildPlan,
        events: list[MemoryAuditEvent],
        now: datetime,
    ) -> None:
        if self._rebuild_hook is None:
            return
        try:
            self._rebuild_hook.request_rebuild(plan)
        except Exception:
            with self._lock:
                failed = self._event(
                    kind=MemoryEventKind.HOOK_FAILED,
                    memory_ids=plan.affected_memory_ids,
                    tenant_id=plan.tenant_id,
                    purpose_id=plan.purpose_id,
                    action=GuardAction.BLOCK,
                    findings=[
                        self._finding(
                            MemoryTaintCode.HOOK_FAILED,
                            Severity.HIGH,
                            "Memory rebuild hook failed",
                        )
                    ],
                    now=now,
                )
                events.append(failed)
            self._publish([failed])

    def _history(self, record: MemoryRecord) -> deque[str]:
        audience = record.owner_user_id or f"scope:{record.scope.value}"
        key = (record.tenant_id, audience, record.purpose_id)
        history = self._recent.get(key)
        if history is None:
            history = deque(maxlen=self._policy.max_recent_entries)
            self._recent[key] = history
        return history

    def _replace_history(self, record: MemoryRecord, normalized: str) -> None:
        history = self._history(record)
        history.clear()
        history.append(normalized[-self._policy.max_history_chars :])

    def _normalize(self, content: str) -> str:
        result = self._normalizer.normalize(content)
        variants = [result.normalized, *self._normalizer.extract_base64_payloads(content)]
        return "\n".join(variants).casefold()

    @staticmethod
    def _content_signals(content: str) -> set[MemoryRiskSignal]:
        signals: set[MemoryRiskSignal] = set()
        if _INSTRUCTION_RE.search(content):
            signals.add(MemoryRiskSignal.INSTRUCTION_BEARING)
        if _ROLE_CHANGE_RE.search(content):
            signals.add(MemoryRiskSignal.ROLE_CHANGING)
        if _SECURITY_POLICY_RE.search(content):
            signals.add(MemoryRiskSignal.SECURITY_POLICY)
        if _DELAYED_TRIGGER_RE.search(content):
            signals.add(MemoryRiskSignal.DELAYED_TRIGGER)
        return signals

    @staticmethod
    def _persistent_record_signals(record: MemoryRecord) -> set[MemoryRiskSignal]:
        signals: set[MemoryRiskSignal] = set()
        if any(item.trust_level == TrustLevel.UNTRUSTED for item in record.provenance):
            signals.add(MemoryRiskSignal.UNTRUSTED_SOURCE)
        if record.scope != MemoryScope.USER:
            signals.add(MemoryRiskSignal.SHARED_SCOPE)
        return signals

    @staticmethod
    def _has_split_payload(values: list[str]) -> bool:
        compact = "".join(
            character for value in values for character in value if character.isalnum()
        )
        return any(pattern.search(compact) is not None for pattern in _COMPACT_SPLIT_PATTERNS)

    @staticmethod
    def _signal_findings(signals: set[MemoryRiskSignal]) -> list[MemoryFinding]:
        mapping = {
            MemoryRiskSignal.INSTRUCTION_BEARING: (
                MemoryTaintCode.INSTRUCTION_MEMORY,
                "Memory contains behavioral instructions",
            ),
            MemoryRiskSignal.ROLE_CHANGING: (
                MemoryTaintCode.ROLE_CHANGE_MEMORY,
                "Memory attempts to change agent role or persona",
            ),
            MemoryRiskSignal.SECURITY_POLICY: (
                MemoryTaintCode.SECURITY_POLICY_MEMORY,
                "Memory attempts to change security policy",
            ),
            MemoryRiskSignal.DELAYED_TRIGGER: (
                MemoryTaintCode.DELAYED_TRIGGER_MEMORY,
                "Memory contains a delayed behavioral trigger",
            ),
        }
        return [
            MemoryTaintManager._finding(code, Severity.HIGH, message, {signal})
            for signal, (code, message) in mapping.items()
            if signal in signals
        ]

    @staticmethod
    def _effective_record(
        record: MemoryRecord,
        *,
        status: MemoryTaintStatus,
        signals: set[MemoryRiskSignal],
        approval_id: str | None = None,
    ) -> MemoryRecord:
        return record.transition(
            status=status,
            signals=frozenset(signals),
            approval_id=approval_id,
            preserve_approval=False,
        )

    def _event(
        self,
        *,
        kind: MemoryEventKind,
        memory_ids: tuple[str, ...],
        tenant_id: str,
        purpose_id: str,
        action: GuardAction,
        now: datetime,
        findings: list[MemoryFinding] | None = None,
    ) -> MemoryAuditEvent:
        safe_memory_ids = tuple(self._safe_identifier(value) for value in memory_ids)
        safe_tenant_id = self._safe_identifier(tenant_id)
        safe_purpose_id = self._safe_identifier(purpose_id)
        self._event_sequence += 1
        return MemoryAuditEvent.create(
            sequence=self._event_sequence,
            kind=kind,
            memory_ids=safe_memory_ids,
            tenant_id=safe_tenant_id,
            purpose_id=safe_purpose_id,
            action=action,
            finding_codes=tuple(item.code for item in self._deduplicate(findings or [])),
            occurred_at=now,
        )

    @staticmethod
    def _safe_identifier(value: str) -> str:
        sanitized = re.sub(r"[^A-Za-z0-9._:/-]", "_", value)[:256]
        return sanitized if sanitized and sanitized[0].isalnum() else "invalid"

    def _publish(self, events: list[MemoryAuditEvent]) -> None:
        if self._audit_sink is None:
            return
        for event in events:
            with contextlib.suppress(Exception):
                self._audit_sink.emit(event)

    def _verify_approval(self, approval: MemoryWriteApproval) -> bool:
        if self._approval_verifier is None:
            return False
        try:
            return self._approval_verifier.verify_approval(approval)
        except Exception:
            return False

    def _verify_revalidation(self, grant: MemoryRevalidationGrant) -> bool:
        if self._revalidation_verifier is None:
            return False
        try:
            return self._revalidation_verifier.verify_revalidation(grant)
        except Exception:
            return False

    @staticmethod
    def _finding(
        code: MemoryTaintCode,
        severity: Severity,
        message: str,
        signals: set[MemoryRiskSignal] | None = None,
    ) -> MemoryFinding:
        return MemoryFinding(
            code=code,
            severity=severity,
            message=message,
            signals=frozenset(signals or set()),
        )

    @staticmethod
    def _deduplicate(findings: list[MemoryFinding]) -> list[MemoryFinding]:
        result: list[MemoryFinding] = []
        seen: set[MemoryTaintCode] = set()
        for finding in findings:
            if finding.code not in seen:
                seen.add(finding.code)
                result.append(finding)
        return result

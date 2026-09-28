"""Model-blind, execution-bound credential brokering and leak prevention."""

from __future__ import annotations

import base64
import dataclasses
import re
import threading
import uuid
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel

from trustrail.exceptions import CredentialBrokerError
from trustrail.models.credentials import (
    AuthorizedCredentialExecution,
    CredentialAuditEvent,
    CredentialBinding,
    CredentialBoundaryDecision,
    CredentialBrokerCode,
    CredentialBrokerDecision,
    CredentialBrokerFinding,
    CredentialBrokerPhase,
    CredentialBrokerPolicy,
    CredentialCapability,
    CredentialCapabilityState,
    CredentialReference,
    CredentialSurface,
    credential_reference,
    utcnow,
)
from trustrail.models.enums import GuardAction, Severity

_CREDENTIAL_KEY = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|access[_-]?token|auth(?:orization)?|client[_-]?secret|"
    r"credential|password|passwd|private[_-]?key|refresh[_-]?token|secret)(?:$|[_-])",
    re.IGNORECASE,
)
_RAW_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        r"(?:api[_-]?key|client[_-]?secret|password|refresh[_-]?token)\s*[:=]\s*[^\s,;]{8,}",
        re.IGNORECASE,
    ),
    re.compile(r"[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@", re.IGNORECASE),
)


class CredentialMaterial:
    """Ephemeral secret bytes with safe display and explicit, trusted access."""

    __slots__ = ("_buffer", "_closed")

    def __init__(self, value: str | bytes | bytearray) -> None:
        raw = value.encode() if isinstance(value, str) else bytes(value)
        if not raw:
            raise ValueError("credential material must not be empty")
        self._buffer = bytearray(raw)
        self._closed = False

    def reveal(self) -> bytes:
        """Copy the secret for immediate use inside a trusted connector boundary."""
        if self._closed:
            raise ValueError("credential material is closed")
        return bytes(self._buffer)

    def close(self) -> None:
        """Best-effort overwrite of the managed in-process copy."""
        if not self._closed:
            for index in range(len(self._buffer)):
                self._buffer[index] = 0
            self._closed = True

    def __enter__(self) -> CredentialMaterial:
        if self._closed:
            raise ValueError("credential material is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "<CredentialMaterial redacted>"

    def __str__(self) -> str:
        return "<credential-material:redacted>"

    def __bytes__(self) -> bytes:
        raise TypeError("use reveal() only inside a trusted connector boundary")

    def __copy__(self) -> CredentialMaterial:
        raise TypeError("credential material cannot be copied")

    def __deepcopy__(self, _memo: dict[int, Any]) -> CredentialMaterial:
        raise TypeError("credential material cannot be copied")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("credential material cannot be serialized")


class CredentialVault(Protocol):
    """Resolve secrets in trusted infrastructure outside the model context."""

    def current_version(self, reference: CredentialReference) -> str: ...

    def resolve(self, reference: CredentialReference) -> tuple[str, CredentialMaterial]: ...


class CredentialExecutionVerifier(Protocol):
    """Authenticate an authorized execution record against trusted state."""

    def verify_execution(self, execution: AuthorizedCredentialExecution) -> bool: ...


class CredentialCapabilityStore(Protocol):
    """Atomically control capability lifecycle across issuance and resolution."""

    def register(self, capability: CredentialCapability) -> CredentialCapabilityState: ...

    def consume(
        self,
        capability_id: str,
        capability_digest: str,
        now: datetime,
    ) -> CredentialCapabilityState: ...

    def revoke_reference(self, reference_digest: str) -> int: ...


class CredentialAuditSink(Protocol):
    """Persist content-free credential security events."""

    def emit(self, event: CredentialAuditEvent) -> None: ...


class MemoryCredentialCapabilityStore:
    """Process-local atomic state for tests and single-worker applications."""

    def __init__(self, max_capabilities: int = 10_000) -> None:
        if max_capabilities < 1:
            raise ValueError("max_capabilities must be at least 1")
        self._max_capabilities = max_capabilities
        self._items: dict[
            str,
            tuple[str, str, datetime, CredentialCapabilityState],
        ] = {}
        self._lock = threading.Lock()

    def register(self, capability: CredentialCapability) -> CredentialCapabilityState:
        with self._lock:
            existing = self._items.get(capability.capability_id)
            if existing is not None:
                return (
                    CredentialCapabilityState.REPLAYED
                    if existing[0] == capability.capability_digest
                    else CredentialCapabilityState.COLLISION
                )
            if len(self._items) >= self._max_capabilities:
                return CredentialCapabilityState.COLLISION
            self._items[capability.capability_id] = (
                capability.capability_digest,
                capability.reference.reference_digest,
                capability.expires_at,
                CredentialCapabilityState.STORED,
            )
            return CredentialCapabilityState.STORED

    def consume(
        self,
        capability_id: str,
        capability_digest: str,
        now: datetime,
    ) -> CredentialCapabilityState:
        with self._lock:
            existing = self._items.get(capability_id)
            if existing is None or existing[0] != capability_digest:
                return CredentialCapabilityState.MISSING
            digest, reference_digest, expires_at, state = existing
            if state == CredentialCapabilityState.REVOKED:
                return state
            if state == CredentialCapabilityState.CONSUMED:
                return CredentialCapabilityState.REPLAYED
            if now >= expires_at:
                self._items[capability_id] = (
                    digest,
                    reference_digest,
                    expires_at,
                    CredentialCapabilityState.EXPIRED,
                )
                return CredentialCapabilityState.EXPIRED
            self._items[capability_id] = (
                digest,
                reference_digest,
                expires_at,
                CredentialCapabilityState.CONSUMED,
            )
            return CredentialCapabilityState.CONSUMED

    def revoke_reference(self, reference_digest: str) -> int:
        with self._lock:
            revoked = 0
            for capability_id, (digest, stored_reference, expires_at, state) in list(
                self._items.items()
            ):
                if (
                    stored_reference == reference_digest
                    and state == CredentialCapabilityState.STORED
                ):
                    self._items[capability_id] = (
                        digest,
                        stored_reference,
                        expires_at,
                        CredentialCapabilityState.REVOKED,
                    )
                    revoked += 1
            return revoked


class MemoryCredentialAuditSink:
    """Bounded process-local audit sink with content-free events."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[CredentialAuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def emit(self, event: CredentialAuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> list[CredentialAuditEvent]:
        with self._lock:
            return list(self._events)


class StaticCredentialExecutionVerifier:
    """Exact-digest verifier for tests and trusted adapter implementations."""

    def __init__(self, accepted_execution_digests: frozenset[str]) -> None:
        self._accepted = accepted_execution_digests

    def verify_execution(self, execution: AuthorizedCredentialExecution) -> bool:
        return execution.execution_digest in self._accepted


class StaticCredentialVault:
    """In-memory vault for tests; production should adapt a KMS or secret manager."""

    def __init__(
        self,
        credentials: Mapping[str, tuple[str, str | bytes]],
    ) -> None:
        self._credentials = {
            reference_id: (version, bytes(value.encode() if isinstance(value, str) else value))
            for reference_id, (version, value) in credentials.items()
        }
        self._lock = threading.Lock()

    def current_version(self, reference: CredentialReference) -> str:
        with self._lock:
            return self._credentials[reference.reference_id][0]

    def resolve(self, reference: CredentialReference) -> tuple[str, CredentialMaterial]:
        with self._lock:
            version, raw = self._credentials[reference.reference_id]
            return version, CredentialMaterial(raw)

    def rotate(
        self,
        reference: CredentialReference,
        version: str,
        value: str | bytes,
    ) -> None:
        """Replace test-vault material without retaining the old value."""
        raw = value.encode() if isinstance(value, str) else bytes(value)
        with self._lock:
            self._credentials[reference.reference_id] = (version, raw)


class CredentialBroker:
    """Issue opaque capabilities and resolve secrets only for exact executions."""

    def __init__(
        self,
        policy: CredentialBrokerPolicy,
        *,
        vault: CredentialVault,
        execution_verifier: CredentialExecutionVerifier,
        state_store: CredentialCapabilityStore | None = None,
        audit_sink: CredentialAuditSink | None = None,
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._vault = vault
        self._execution_verifier = execution_verifier
        self._state_store = state_store or MemoryCredentialCapabilityStore()
        self._audit_sink = audit_sink
        self._versions = {
            item.reference.reference_digest: item.credential_version for item in policy.bindings
        }
        self._revoked_references: set[str] = set()
        self._lock = threading.Lock()

    @property
    def policy(self) -> CredentialBrokerPolicy:
        return self._policy.model_copy(deep=True)

    def issue(
        self,
        reference: CredentialReference,
        execution: AuthorizedCredentialExecution,
        *,
        ttl_seconds: int | None = None,
        now: datetime | None = None,
    ) -> CredentialBrokerDecision:
        """Issue a short-lived capability after authenticating exact execution state."""
        current_time = now or utcnow()
        binding, findings = self._binding_findings(reference, execution, current_time)
        if binding is None or findings:
            return self._blocked(
                findings,
                phase=CredentialBrokerPhase.ISSUE,
                reference=reference,
                execution=execution,
                now=current_time,
            )
        try:
            verified = self._execution_verifier.verify_execution(execution)
        except Exception:
            verified = False
        if not verified:
            return self._blocked(
                [
                    self._finding(
                        CredentialBrokerCode.EXECUTION_INVALID,
                        "Execution record was not authenticated",
                    )
                ],
                phase=CredentialBrokerPhase.ISSUE,
                reference=reference,
                execution=execution,
                now=current_time,
            )
        requested_ttl = ttl_seconds or binding.maximum_ttl_seconds
        if requested_ttl < 1 or requested_ttl > binding.maximum_ttl_seconds:
            return self._blocked(
                [
                    self._finding(
                        CredentialBrokerCode.CAPABILITY_INVALID,
                        "Capability lifetime exceeds policy",
                    )
                ],
                phase=CredentialBrokerPhase.ISSUE,
                reference=reference,
                execution=execution,
                now=current_time,
            )
        reference_digest = reference.reference_digest
        with self._lock:
            version = self._versions.get(reference_digest)
            revoked = reference_digest in self._revoked_references
        if revoked or version is None:
            return self._blocked(
                [
                    self._finding(
                        CredentialBrokerCode.REFERENCE_REVOKED, "Credential reference is revoked"
                    )
                ],
                phase=CredentialBrokerPhase.ISSUE,
                reference=reference,
                execution=execution,
                now=current_time,
            )
        try:
            vault_version = self._vault.current_version(reference)
        except Exception:
            return self._blocked(
                [
                    self._finding(
                        CredentialBrokerCode.VAULT_UNAVAILABLE, "Credential vault is unavailable"
                    )
                ],
                phase=CredentialBrokerPhase.ISSUE,
                reference=reference,
                execution=execution,
                now=current_time,
            )
        if vault_version != version:
            return self._blocked(
                [
                    self._finding(
                        CredentialBrokerCode.VERSION_CHANGED, "Credential version is not current"
                    )
                ],
                phase=CredentialBrokerPhase.ISSUE,
                reference=reference,
                execution=execution,
                now=current_time,
            )
        capability = CredentialCapability.create(
            capability_id=f"credential-capability-{uuid.uuid4()}",
            broker_id=self._policy.broker_id,
            reference=reference,
            scope=binding.scope,
            execution_digest=execution.execution_digest,
            credential_version=version,
            policy_digest=self._policy.policy_digest,
            issued_at=current_time,
            expires_at=min(
                current_time + timedelta(seconds=requested_ttl),
                execution.expires_at,
            ),
            one_time=self._policy.require_one_time_use,
        )
        try:
            state = self._state_store.register(capability)
        except Exception:
            state = CredentialCapabilityState.COLLISION
        if state != CredentialCapabilityState.STORED:
            return self._blocked(
                [
                    self._finding(
                        CredentialBrokerCode.STATE_UNAVAILABLE, "Capability state is unavailable"
                    )
                ],
                phase=CredentialBrokerPhase.ISSUE,
                reference=reference,
                execution=execution,
                now=current_time,
            )
        self._emit(
            CredentialBrokerPhase.ISSUE,
            CredentialBrokerCode.ALLOWED,
            reference=reference,
            execution=execution,
            capability=capability,
            now=current_time,
        )
        return CredentialBrokerDecision(action=GuardAction.ALLOW, capability=capability)

    def require_capability(
        self,
        reference: CredentialReference,
        execution: AuthorizedCredentialExecution,
        *,
        ttl_seconds: int | None = None,
        now: datetime | None = None,
    ) -> CredentialCapability:
        """Return a capability or raise a content-free exception."""
        decision = self.issue(reference, execution, ttl_seconds=ttl_seconds, now=now)
        if not decision.is_allowed or decision.capability is None:
            raise CredentialBrokerError(decision=decision)
        return decision.capability

    def resolve(
        self,
        capability: CredentialCapability,
        execution: AuthorizedCredentialExecution,
        *,
        now: datetime | None = None,
    ) -> CredentialMaterial:
        """Resolve material for immediate use inside a trusted connector boundary."""
        current_time = now or utcnow()
        findings = self._resolution_findings(capability, execution, current_time)
        if findings:
            decision = self._blocked(
                findings,
                phase=CredentialBrokerPhase.RESOLVE,
                reference=capability.reference,
                execution=execution,
                capability=capability,
                now=current_time,
            )
            raise CredentialBrokerError(decision=decision)
        try:
            verified = self._execution_verifier.verify_execution(execution)
        except Exception:
            verified = False
        if not verified:
            decision = self._blocked(
                [
                    self._finding(
                        CredentialBrokerCode.EXECUTION_INVALID,
                        "Execution record was not authenticated",
                    )
                ],
                phase=CredentialBrokerPhase.RESOLVE,
                reference=capability.reference,
                execution=execution,
                capability=capability,
                now=current_time,
            )
            raise CredentialBrokerError(decision=decision)
        try:
            state = self._state_store.consume(
                capability.capability_id,
                capability.capability_digest,
                current_time,
            )
        except Exception:
            state = CredentialCapabilityState.COLLISION
        if state != CredentialCapabilityState.CONSUMED:
            code = {
                CredentialCapabilityState.REPLAYED: CredentialBrokerCode.CAPABILITY_REPLAYED,
                CredentialCapabilityState.REVOKED: CredentialBrokerCode.CAPABILITY_REVOKED,
                CredentialCapabilityState.EXPIRED: CredentialBrokerCode.CAPABILITY_EXPIRED,
            }.get(state, CredentialBrokerCode.STATE_UNAVAILABLE)
            decision = self._blocked(
                [self._finding(code, "Credential capability cannot be consumed")],
                phase=CredentialBrokerPhase.RESOLVE,
                reference=capability.reference,
                execution=execution,
                capability=capability,
                now=current_time,
            )
            raise CredentialBrokerError(decision=decision)
        try:
            version, material = self._vault.resolve(capability.reference)
        except Exception:
            decision = self._blocked(
                [
                    self._finding(
                        CredentialBrokerCode.VAULT_UNAVAILABLE, "Credential vault is unavailable"
                    )
                ],
                phase=CredentialBrokerPhase.RESOLVE,
                reference=capability.reference,
                execution=execution,
                capability=capability,
                now=current_time,
            )
            raise CredentialBrokerError(decision=decision) from None
        if version != capability.credential_version:
            material.close()
            decision = self._blocked(
                [self._finding(CredentialBrokerCode.VERSION_CHANGED, "Credential version changed")],
                phase=CredentialBrokerPhase.RESOLVE,
                reference=capability.reference,
                execution=execution,
                capability=capability,
                now=current_time,
            )
            raise CredentialBrokerError(decision=decision)
        self._emit(
            CredentialBrokerPhase.RESOLVE,
            CredentialBrokerCode.ALLOWED,
            reference=capability.reference,
            execution=execution,
            capability=capability,
            now=current_time,
        )
        return material

    def revoke(self, reference: CredentialReference, *, now: datetime | None = None) -> int:
        """Revoke a reference and every unconsumed capability for it."""
        with self._lock:
            self._revoked_references.add(reference.reference_digest)
        try:
            count = self._state_store.revoke_reference(reference.reference_digest)
        except Exception:
            count = 0
        self._emit(
            CredentialBrokerPhase.REVOKE,
            CredentialBrokerCode.REFERENCE_REVOKED,
            reference=reference,
            now=now or utcnow(),
        )
        return count

    def rotate(
        self,
        reference: CredentialReference,
        *,
        credential_version: str,
        now: datetime | None = None,
    ) -> int:
        """Activate a new vault version and revoke outstanding old capabilities."""
        binding = self._policy.binding_for(reference)
        if binding is None:
            raise ValueError("credential reference is not configured")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}", credential_version) is None:
            raise ValueError("credential_version must be an opaque identifier")
        with self._lock:
            self._versions[reference.reference_digest] = credential_version
            self._revoked_references.discard(reference.reference_digest)
        try:
            count = self._state_store.revoke_reference(reference.reference_digest)
        except Exception:
            count = 0
        self._emit(
            CredentialBrokerPhase.ROTATE,
            CredentialBrokerCode.ALLOWED,
            reference=reference,
            now=now or utcnow(),
        )
        return count

    def _binding_findings(
        self,
        reference: CredentialReference,
        execution: AuthorizedCredentialExecution,
        now: datetime,
    ) -> tuple[CredentialBinding | None, list[CredentialBrokerFinding]]:
        binding = self._policy.binding_for(reference)
        findings: list[CredentialBrokerFinding] = []
        if reference.broker_id != self._policy.broker_id:
            findings.append(
                self._finding(
                    CredentialBrokerCode.BROKER_MISMATCH, "Credential broker does not match policy"
                )
            )
        if binding is None or not binding.active:
            findings.append(
                self._finding(
                    CredentialBrokerCode.REFERENCE_UNKNOWN, "Credential reference is not active"
                )
            )
            return binding, findings
        if execution.scope != binding.scope:
            findings.append(
                self._finding(
                    CredentialBrokerCode.SCOPE_MISMATCH,
                    "Execution scope does not match credential binding",
                )
            )
        if not execution.has_valid_integrity:
            findings.append(
                self._finding(
                    CredentialBrokerCode.EXECUTION_INVALID, "Execution integrity is invalid"
                )
            )
        if now < execution.issued_at or now >= execution.expires_at:
            findings.append(
                self._finding(
                    CredentialBrokerCode.EXECUTION_EXPIRED, "Execution record is not current"
                )
            )
        return binding, findings

    def _resolution_findings(
        self,
        capability: CredentialCapability,
        execution: AuthorizedCredentialExecution,
        now: datetime,
    ) -> list[CredentialBrokerFinding]:
        findings: list[CredentialBrokerFinding] = []
        if (
            not capability.has_valid_integrity
            or capability.policy_digest != self._policy.policy_digest
            or capability.broker_id != self._policy.broker_id
            or capability.reference.broker_id != self._policy.broker_id
        ):
            findings.append(
                self._finding(
                    CredentialBrokerCode.CAPABILITY_INVALID,
                    "Capability integrity or policy binding is invalid",
                )
            )
        if capability.execution_digest != execution.execution_digest:
            findings.append(
                self._finding(
                    CredentialBrokerCode.EXECUTION_INVALID,
                    "Capability is bound to another execution",
                )
            )
        if capability.scope != execution.scope:
            findings.append(
                self._finding(
                    CredentialBrokerCode.SCOPE_MISMATCH, "Capability scope does not match execution"
                )
            )
        if now < capability.issued_at or now >= capability.expires_at:
            findings.append(
                self._finding(CredentialBrokerCode.CAPABILITY_EXPIRED, "Capability is not current")
            )
        if now < execution.issued_at or now >= execution.expires_at:
            findings.append(
                self._finding(
                    CredentialBrokerCode.EXECUTION_EXPIRED, "Execution record is not current"
                )
            )
        reference_digest = capability.reference.reference_digest
        with self._lock:
            current_version = self._versions.get(reference_digest)
            revoked = reference_digest in self._revoked_references
        if revoked:
            findings.append(
                self._finding(
                    CredentialBrokerCode.REFERENCE_REVOKED, "Credential reference is revoked"
                )
            )
        elif current_version != capability.credential_version:
            findings.append(
                self._finding(CredentialBrokerCode.VERSION_CHANGED, "Credential version changed")
            )
        return findings

    @staticmethod
    def _finding(code: CredentialBrokerCode, message: str) -> CredentialBrokerFinding:
        return CredentialBrokerFinding(code=code, severity=Severity.CRITICAL, message=message)

    def _blocked(
        self,
        findings: list[CredentialBrokerFinding],
        *,
        phase: CredentialBrokerPhase,
        reference: CredentialReference | None = None,
        execution: AuthorizedCredentialExecution | None = None,
        capability: CredentialCapability | None = None,
        now: datetime,
    ) -> CredentialBrokerDecision:
        code = findings[0].code if findings else CredentialBrokerCode.CAPABILITY_INVALID
        self._emit(
            phase,
            code,
            reference=reference,
            execution=execution,
            capability=capability,
            now=now,
        )
        return CredentialBrokerDecision(action=GuardAction.BLOCK, findings=tuple(findings))

    def _emit(
        self,
        phase: CredentialBrokerPhase,
        code: CredentialBrokerCode,
        *,
        reference: CredentialReference | None = None,
        execution: AuthorizedCredentialExecution | None = None,
        capability: CredentialCapability | None = None,
        now: datetime,
    ) -> None:
        if self._audit_sink is None:
            return
        self._audit_sink.emit(
            CredentialAuditEvent(
                event_id=str(uuid.uuid4()),
                occurred_at=now,
                phase=phase,
                code=code,
                reference_ref=(credential_reference(reference.reference_id) if reference else None),
                execution_ref=(
                    credential_reference(execution.execution_digest) if execution else None
                ),
                capability_ref=(
                    credential_reference(capability.capability_digest) if capability else None
                ),
            )
        )


class CredentialBoundaryGuard:
    """Reject raw credentials recursively at every model-visible boundary."""

    def __init__(
        self,
        references: Iterable[CredentialReference],
        *,
        leak_canaries: Iterable[str | bytes] = (),
        max_depth: int = 32,
        max_nodes: int = 100_000,
        max_stream_bytes: int = 1_000_000,
        audit_sink: CredentialAuditSink | None = None,
    ) -> None:
        if max_depth < 1 or max_nodes < 1 or max_stream_bytes < 1:
            raise ValueError("inspection limits must be positive")
        self._reference_ids = frozenset(item.reference_id for item in references)
        self._reference_pairs = frozenset(
            (item.broker_id, item.reference_id) for item in references
        )
        self._canary_variants = self._build_canary_variants(leak_canaries)
        self._max_depth = max_depth
        self._max_nodes = max_nodes
        self._max_stream_bytes = max_stream_bytes
        self._audit_sink = audit_sink

    def inspect(
        self,
        value: object,
        surface: CredentialSurface,
        *,
        now: datetime | None = None,
    ) -> CredentialBoundaryDecision:
        """Recursively inspect a payload without returning or recording its content."""
        findings: list[CredentialBrokerFinding] = []
        seen: set[int] = set()
        count = [0]
        self._scan(value, findings, seen, count, depth=0, suspicious=False)
        unique = tuple(dict.fromkeys((item.code, item.message) for item in findings))
        normalized = tuple(
            CredentialBrokerFinding(code=code, severity=Severity.CRITICAL, message=message)
            for code, message in unique
        )
        decision = CredentialBoundaryDecision(
            action=GuardAction.BLOCK if normalized else GuardAction.ALLOW,
            surface=surface,
            findings=normalized,
        )
        if self._audit_sink is not None:
            code = normalized[0].code if normalized else CredentialBrokerCode.ALLOWED
            self._audit_sink.emit(
                CredentialAuditEvent(
                    event_id=str(uuid.uuid4()),
                    occurred_at=now or utcnow(),
                    phase=CredentialBrokerPhase.INSPECT,
                    code=code,
                    surface=surface,
                )
            )
        return decision

    def require_safe(self, value: object, surface: CredentialSurface) -> None:
        """Raise a content-free exception if a payload may disclose credentials."""
        decision = self.inspect(value, surface)
        if not decision.is_safe:
            raise CredentialBrokerError(decision=decision)

    def inspect_stream(
        self,
        chunks: Iterable[str | bytes],
        *,
        now: datetime | None = None,
    ) -> CredentialBoundaryDecision:
        """Inspect a complete stream, including credentials split across chunks."""
        combined = bytearray()
        for chunk in chunks:
            raw = chunk.encode() if isinstance(chunk, str) else bytes(chunk)
            if len(combined) + len(raw) > self._max_stream_bytes:
                decision = CredentialBoundaryDecision(
                    action=GuardAction.BLOCK,
                    surface=CredentialSurface.STREAM,
                    findings=(
                        CredentialBrokerFinding(
                            code=CredentialBrokerCode.INSPECTION_LIMIT,
                            severity=Severity.CRITICAL,
                            message="Credential stream inspection limit exceeded",
                        ),
                    ),
                )
                self._emit_boundary(decision, now or utcnow())
                return decision
            combined.extend(raw)
        return self.inspect(bytes(combined), CredentialSurface.STREAM, now=now)

    def _scan(
        self,
        value: object,
        findings: list[CredentialBrokerFinding],
        seen: set[int],
        count: list[int],
        *,
        depth: int,
        suspicious: bool,
    ) -> None:
        count[0] += 1
        if depth > self._max_depth or count[0] > self._max_nodes:
            findings.append(
                self._finding(
                    CredentialBrokerCode.INSPECTION_LIMIT, "Credential inspection limit exceeded"
                )
            )
            return
        if value is None or isinstance(value, (bool, int, float, datetime, Enum)):
            return
        if isinstance(value, CredentialReference):
            return
        if isinstance(value, CredentialMaterial):
            findings.append(
                self._finding(
                    CredentialBrokerCode.CREDENTIAL_OBJECT,
                    "Credential material crossed a model-visible boundary",
                )
            )
            return
        if suspicious and self._is_serialized_reference(value):
            return
        if isinstance(value, str):
            self._scan_text(value, findings, suspicious=suspicious)
            return
        if isinstance(value, (bytes, bytearray, memoryview)):
            self._scan_bytes(bytes(value), findings, suspicious=suspicious)
            return
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        if isinstance(value, BaseModel):
            self._scan(
                vars(value),
                findings,
                seen,
                count,
                depth=depth + 1,
                suspicious=suspicious,
            )
            return
        if isinstance(value, BaseException):
            self._scan(value.args, findings, seen, count, depth=depth + 1, suspicious=False)
            self._scan(vars(value), findings, seen, count, depth=depth + 1, suspicious=False)
            return
        if isinstance(value, Mapping):
            for key, item in value.items():
                key_text = key if isinstance(key, str) else ""
                key_is_suspicious = bool(_CREDENTIAL_KEY.search(key_text))
                self._scan(key, findings, seen, count, depth=depth + 1, suspicious=False)
                self._scan(
                    item,
                    findings,
                    seen,
                    count,
                    depth=depth + 1,
                    suspicious=suspicious or key_is_suspicious,
                )
            return
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            for field in dataclasses.fields(value):
                self._scan(
                    getattr(value, field.name),
                    findings,
                    seen,
                    count,
                    depth=depth + 1,
                    suspicious=suspicious or bool(_CREDENTIAL_KEY.search(field.name)),
                )
            return
        if isinstance(value, (Sequence, set, frozenset)):
            for item in value:
                self._scan(
                    item,
                    findings,
                    seen,
                    count,
                    depth=depth + 1,
                    suspicious=suspicious,
                )
            return
        findings.append(
            self._finding(
                CredentialBrokerCode.UNSUPPORTED_VALUE, "Unsupported value at credential boundary"
            )
        )

    def _scan_text(
        self,
        value: str,
        findings: list[CredentialBrokerFinding],
        *,
        suspicious: bool,
    ) -> None:
        if value in self._reference_ids:
            return
        if suspicious:
            findings.append(
                self._finding(
                    CredentialBrokerCode.SUSPICIOUS_FIELD, "Raw value in credential-bearing field"
                )
            )
        if any(variant in value for variant in self._canary_variants if isinstance(variant, str)):
            findings.append(
                self._finding(
                    CredentialBrokerCode.RAW_CREDENTIAL, "Credential leak canary detected"
                )
            )
        if any(pattern.search(value) for pattern in _RAW_PATTERNS):
            findings.append(
                self._finding(
                    CredentialBrokerCode.RAW_CREDENTIAL, "Raw credential pattern detected"
                )
            )

    def _scan_bytes(
        self,
        value: bytes,
        findings: list[CredentialBrokerFinding],
        *,
        suspicious: bool,
    ) -> None:
        if suspicious:
            findings.append(
                self._finding(
                    CredentialBrokerCode.SUSPICIOUS_FIELD, "Raw bytes in credential-bearing field"
                )
            )
        if any(variant in value for variant in self._canary_variants if isinstance(variant, bytes)):
            findings.append(
                self._finding(
                    CredentialBrokerCode.RAW_CREDENTIAL, "Credential leak canary detected"
                )
            )
        self._scan_text(value.decode("utf-8", errors="ignore"), findings, suspicious=False)

    @staticmethod
    def _build_canary_variants(values: Iterable[str | bytes]) -> tuple[str | bytes, ...]:
        variants: list[str | bytes] = []
        for value in values:
            raw = value.encode() if isinstance(value, str) else bytes(value)
            if not raw:
                raise ValueError("credential leak canaries must not be empty")
            encoded = base64.b64encode(raw)
            variants.extend((raw, raw.hex().encode(), encoded))
            try:
                text = raw.decode()
            except UnicodeDecodeError:
                continue
            variants.extend((text, raw.hex(), encoded.decode()))
        return tuple(variants)

    @staticmethod
    def _finding(code: CredentialBrokerCode, message: str) -> CredentialBrokerFinding:
        return CredentialBrokerFinding(code=code, severity=Severity.CRITICAL, message=message)

    def _is_serialized_reference(self, value: object) -> bool:
        if not isinstance(value, Mapping) or set(value) != {"broker_id", "reference_id"}:
            return False
        broker_id = value.get("broker_id")
        reference_id = value.get("reference_id")
        return (
            isinstance(broker_id, str)
            and isinstance(reference_id, str)
            and (broker_id, reference_id) in self._reference_pairs
        )

    def _emit_boundary(self, decision: CredentialBoundaryDecision, now: datetime) -> None:
        if self._audit_sink is None:
            return
        self._audit_sink.emit(
            CredentialAuditEvent(
                event_id=str(uuid.uuid4()),
                occurred_at=now,
                phase=CredentialBrokerPhase.INSPECT,
                code=decision.findings[0].code,
                surface=decision.surface,
            )
        )

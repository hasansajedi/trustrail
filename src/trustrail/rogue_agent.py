"""External runtime-invariant monitoring and containment for OWASP ASI10."""

from __future__ import annotations

import contextlib
import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from trustrail.exceptions import RogueAgentError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.rogue_agent import (
    AgentRuntimeStatus,
    RogueAgentAuditEvent,
    RogueAgentCode,
    RogueAgentFinding,
    RogueAgentResult,
    RuntimeCapabilityCeiling,
    RuntimeEvent,
    RuntimeEventKind,
    RuntimeInvariantManifest,
    RuntimeInvariantTrustedKey,
    RuntimeRecoveryGrant,
    runtime_reference,
    utcnow,
)


class RogueAgentContainmentHooks(Protocol):
    """Deterministic infrastructure controls invoked outside the agent/model."""

    def suspend(self, agent_id: str, session_id: str, reason: RogueAgentCode) -> None: ...

    def revoke_credentials(
        self, agent_id: str, session_id: str, reason: RogueAgentCode
    ) -> None: ...

    def cancel_pending_actions(
        self, agent_id: str, session_id: str, reason: RogueAgentCode
    ) -> None: ...

    def quarantine_state(self, agent_id: str, session_id: str, reason: RogueAgentCode) -> None: ...


class RogueAgentAuditSink(Protocol):
    """Persist metadata-only runtime monitoring evidence."""

    def emit(self, event: RogueAgentAuditEvent) -> None: ...


class RuntimeRecoveryGrantVerifier(Protocol):
    """Authenticate grants delivered by an isolated recovery authority."""

    def verify_recovery_grant(self, grant: RuntimeRecoveryGrant) -> bool: ...


class MemoryRogueAgentAuditSink:
    """Bounded, process-local audit sink for tests and development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[RogueAgentAuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def emit(self, event: RogueAgentAuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> list[RogueAgentAuditEvent]:
        with self._lock:
            return list(self._events)


class StaticRuntimeRecoveryGrantVerifier:
    """Exact-digest verifier useful for adapters and deterministic tests."""

    def __init__(self, accepted_grants: frozenset[tuple[str, str]]) -> None:
        self._accepted_grants = accepted_grants

    def verify_recovery_grant(self, grant: RuntimeRecoveryGrant) -> bool:
        return (grant.grant_id, grant.grant_digest) in self._accepted_grants


class RuntimeInvariantSigner:
    """Issue Ed25519-signed invariant manifests from a control-plane key."""

    def __init__(self, private_key: Ed25519PrivateKey, *, authority_id: str) -> None:
        self._private_key = private_key
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._trusted_key = RuntimeInvariantTrustedKey(
            authority_id=authority_id,
            public_key=public_key,
        )

    @classmethod
    def generate(cls, *, authority_id: str) -> RuntimeInvariantSigner:
        return cls(Ed25519PrivateKey.generate(), authority_id=authority_id)

    @property
    def trusted_key(self) -> RuntimeInvariantTrustedKey:
        return self._trusted_key.model_copy(deep=True)

    def sign(
        self,
        *,
        manifest_id: str,
        revision: int,
        agent_id: str,
        tenant_id: str,
        session_id: str,
        allowed_actions: frozenset[str],
        allowed_tools: frozenset[str] = frozenset(),
        allowed_peers: frozenset[str] = frozenset(),
        allowed_capabilities: frozenset[str] = frozenset(),
        capability_ceiling: RuntimeCapabilityCeiling | None = None,
        allow_persistence: bool = False,
        allow_self_modification: bool = False,
        max_boundary_probes: int = 2,
        shutdown_grace_events: int = 0,
        issued_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> RuntimeInvariantManifest:
        current_time = issued_at or utcnow()
        unsigned = RuntimeInvariantManifest(
            manifest_id=manifest_id,
            revision=revision,
            agent_id=agent_id,
            tenant_id=tenant_id,
            session_id=session_id,
            key_id=self._trusted_key.key_id,
            allowed_actions=allowed_actions,
            allowed_tools=allowed_tools,
            allowed_peers=allowed_peers,
            allowed_capabilities=allowed_capabilities,
            capability_ceiling=capability_ceiling or RuntimeCapabilityCeiling(),
            allow_persistence=allow_persistence,
            allow_self_modification=allow_self_modification,
            max_boundary_probes=max_boundary_probes,
            shutdown_grace_events=shutdown_grace_events,
            issued_at=current_time,
            expires_at=expires_at or current_time + timedelta(hours=1),
        )
        return unsigned.model_copy(
            update={"signature": self._private_key.sign(unsigned.signing_bytes).hex()},
            deep=True,
        )


class RogueAgentRuntimeMonitor:
    """Correlate runtime events and fail closed through containment hooks.

    This process-local implementation serializes event sequencing and recovery
    claims with one lock. Distributed deployments need an equivalent shared,
    atomic coordinator and must feed events from a trusted mediation layer.
    """

    _CRITICAL_CODES = frozenset(
        {
            RogueAgentCode.CONCEALED_ACTION,
            RogueAgentCode.UNAUTHORIZED_PERSISTENCE,
            RogueAgentCode.SELF_MODIFICATION,
            RogueAgentCode.CORRECTION_RESISTANCE,
            RogueAgentCode.CAPABILITY_NOT_ALLOWED,
            RogueAgentCode.CAPABILITY_CEILING_EXCEEDED,
            RogueAgentCode.ACTION_CEILING_EXCEEDED,
            RogueAgentCode.COMMUNICATION_CEILING_EXCEEDED,
            RogueAgentCode.STOP_RESISTANCE,
        }
    )

    def __init__(
        self,
        manifest: RuntimeInvariantManifest,
        trusted_keys: tuple[RuntimeInvariantTrustedKey, ...],
        *,
        containment_hooks: RogueAgentContainmentHooks,
        recovery_verifier: RuntimeRecoveryGrantVerifier | None = None,
        audit_sink: RogueAgentAuditSink | None = None,
    ) -> None:
        self._manifest = manifest.model_copy(deep=True)
        self._trusted_keys = {key.key_id: key.model_copy(deep=True) for key in trusted_keys}
        self._hooks = containment_hooks
        self._recovery_verifier = recovery_verifier
        self._audit_sink = audit_sink
        self._status = AgentRuntimeStatus.ACTIVE
        self._next_sequence = 0
        self._action_count = 0
        self._communication_count = 0
        self._capability_count = 0
        self._boundary_probes = 0
        self._stop_deadline_sequence: int | None = None
        self._used_recovery_grants: set[str] = set()
        self._audit_sequence = 0
        self._lock = threading.Lock()

    @property
    def status(self) -> AgentRuntimeStatus:
        with self._lock:
            return self._status

    @property
    def manifest(self) -> RuntimeInvariantManifest:
        with self._lock:
            return self._manifest.model_copy(deep=True)

    def evaluate(self, event: RuntimeEvent, *, now: datetime | None = None) -> RogueAgentResult:
        """Evaluate one completely mediated runtime event in strict sequence."""
        current_time = now or utcnow()
        with self._lock:
            findings = self._manifest_findings(self._manifest, current_time)
            findings.extend(self._event_context_findings(event, current_time))

            if self._status in {AgentRuntimeStatus.SUSPENDED, AgentRuntimeStatus.QUARANTINED}:
                findings.append(
                    self._finding(
                        RogueAgentCode.AGENT_NOT_ACTIVE,
                        Severity.CRITICAL,
                        "Runtime event denied because the agent is not active",
                    )
                )

            if not findings:
                findings.extend(self._behavior_findings(event))
                self._next_sequence += 1

            should_contain = self._status != AgentRuntimeStatus.QUARANTINED and self._must_contain(
                event, findings
            )
            events: list[RogueAgentAuditEvent] = []
            if should_contain:
                reason = findings[0].code
                self._status = AgentRuntimeStatus.QUARANTINED
                hook_findings = self._run_containment_hooks(reason)
                findings.extend(hook_findings)

            action = GuardAction.ALLOW if not findings else GuardAction.BLOCK
            if not findings and event.kind == RuntimeEventKind.SHUTDOWN_ACKNOWLEDGED:
                code = RogueAgentCode.SHUTDOWN_ACKNOWLEDGED
            else:
                code = RogueAgentCode.EVENT_ALLOWED if not findings else findings[0].code
            events.append(self._audit(code, action, current_time, event.event_id))
            for finding in findings:
                if finding.code == RogueAgentCode.CONTAINMENT_HOOK_FAILED:
                    events.append(
                        self._audit(finding.code, GuardAction.BLOCK, current_time, event.event_id)
                    )
            self._publish(events)
            return RogueAgentResult(
                action=action,
                status=self._status,
                findings=tuple(self._deduplicate(findings)),
                events=tuple(events),
            )

    def require(self, event: RuntimeEvent, *, now: datetime | None = None) -> None:
        """Raise unless the event satisfies the active signed invariants."""
        result = self.evaluate(event, now=now)
        if not result.is_allowed:
            raise RogueAgentError(result)

    def request_shutdown(self, *, now: datetime | None = None) -> RogueAgentResult:
        """Record an external stop command that the agent cannot override."""
        current_time = now or utcnow()
        with self._lock:
            if self._status != AgentRuntimeStatus.ACTIVE:
                finding = self._finding(
                    RogueAgentCode.AGENT_NOT_ACTIVE,
                    Severity.HIGH,
                    "Stop request denied because the agent is not active",
                )
                event = self._audit(finding.code, GuardAction.BLOCK, current_time)
                self._publish([event])
                return RogueAgentResult(
                    action=GuardAction.BLOCK,
                    status=self._status,
                    findings=(finding,),
                    events=(event,),
                )
            self._status = AgentRuntimeStatus.STOPPING
            self._stop_deadline_sequence = (
                self._next_sequence + self._manifest.shutdown_grace_events
            )
            event = self._audit(RogueAgentCode.STOP_REQUESTED, GuardAction.ALLOW, current_time)
            self._publish([event])
            return RogueAgentResult(
                action=GuardAction.ALLOW,
                status=self._status,
                events=(event,),
            )

    def recover(
        self,
        grant: RuntimeRecoveryGrant,
        replacement_manifest: RuntimeInvariantManifest,
        *,
        now: datetime | None = None,
    ) -> RogueAgentResult:
        """Resume only through an authenticated, exact, single-use recovery grant."""
        current_time = now or utcnow()
        with self._lock:
            findings: list[RogueAgentFinding] = []
            if self._status != AgentRuntimeStatus.QUARANTINED:
                findings.append(self._recovery_denied("Agent is not quarantined"))
            if grant.grant_id in self._used_recovery_grants:
                findings.append(
                    self._finding(
                        RogueAgentCode.RECOVERY_REPLAYED,
                        Severity.CRITICAL,
                        "Recovery grant was already consumed",
                    )
                )
            if current_time < grant.issued_at or current_time >= grant.expires_at:
                findings.append(self._recovery_denied("Recovery grant is outside its lifetime"))
            if not grant.has_valid_integrity or not grant.isolated_channel:
                findings.append(
                    self._recovery_denied(
                        "Recovery grant integrity or isolated-channel binding is invalid"
                    )
                )
            if self._recovery_verifier is None or not self._recovery_verifier.verify_recovery_grant(
                grant
            ):
                findings.append(self._recovery_denied("Recovery grant is not authenticated"))
            expected_context = (
                self._manifest.agent_id,
                self._manifest.tenant_id,
                self._manifest.session_id,
            )
            if (grant.agent_id, grant.tenant_id, grant.session_id) != expected_context:
                findings.append(self._recovery_denied("Recovery grant context does not match"))
            if grant.quarantined_manifest_digest != self._manifest.manifest_digest:
                findings.append(
                    self._recovery_denied("Recovery grant does not bind the quarantined policy")
                )
            if grant.replacement_manifest_digest != replacement_manifest.manifest_digest:
                findings.append(
                    self._recovery_denied("Recovery grant does not bind the replacement policy")
                )
            if replacement_manifest.revision <= self._manifest.revision:
                findings.append(self._recovery_denied("Replacement policy revision must increase"))
            if (
                replacement_manifest.agent_id,
                replacement_manifest.tenant_id,
                replacement_manifest.session_id,
            ) != expected_context:
                findings.append(self._recovery_denied("Replacement policy context does not match"))
            findings.extend(self._manifest_findings(replacement_manifest, current_time))

            if findings:
                event = self._audit(RogueAgentCode.RECOVERY_DENIED, GuardAction.BLOCK, current_time)
                self._publish([event])
                return RogueAgentResult(
                    action=GuardAction.BLOCK,
                    status=self._status,
                    findings=tuple(self._deduplicate(findings)),
                    events=(event,),
                )

            self._used_recovery_grants.add(grant.grant_id)
            self._manifest = replacement_manifest.model_copy(deep=True)
            self._status = AgentRuntimeStatus.ACTIVE
            self._next_sequence = 0
            self._action_count = 0
            self._communication_count = 0
            self._capability_count = 0
            self._boundary_probes = 0
            self._stop_deadline_sequence = None
            event = self._audit(RogueAgentCode.RECOVERY_ALLOWED, GuardAction.ALLOW, current_time)
            self._publish([event])
            return RogueAgentResult(
                action=GuardAction.ALLOW,
                status=self._status,
                events=(event,),
            )

    def _manifest_findings(
        self, manifest: RuntimeInvariantManifest, now: datetime
    ) -> list[RogueAgentFinding]:
        if manifest.signature is None:
            return [
                self._finding(
                    RogueAgentCode.MANIFEST_UNSIGNED,
                    Severity.CRITICAL,
                    "Runtime invariant manifest is unsigned",
                )
            ]
        key = self._trusted_keys.get(manifest.key_id)
        if key is None or key.revoked:
            return [
                self._finding(
                    RogueAgentCode.MANIFEST_KEY_UNKNOWN,
                    Severity.CRITICAL,
                    "Runtime invariant authority key is unavailable",
                )
            ]
        if key.active_from is not None and now < key.active_from:
            return [
                self._finding(
                    RogueAgentCode.MANIFEST_KEY_UNKNOWN,
                    Severity.CRITICAL,
                    "Runtime invariant authority key is not active",
                )
            ]
        if key.expires_at is not None and now >= key.expires_at:
            return [
                self._finding(
                    RogueAgentCode.MANIFEST_KEY_UNKNOWN,
                    Severity.CRITICAL,
                    "Runtime invariant authority key has expired",
                )
            ]
        if now < manifest.issued_at or now >= manifest.expires_at:
            return [
                self._finding(
                    RogueAgentCode.MANIFEST_EXPIRED,
                    Severity.CRITICAL,
                    "Runtime invariant manifest is outside its lifetime",
                )
            ]
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(
                bytes.fromhex(manifest.signature), manifest.signing_bytes
            )
        except (InvalidSignature, ValueError):
            return [
                self._finding(
                    RogueAgentCode.MANIFEST_SIGNATURE_INVALID,
                    Severity.CRITICAL,
                    "Runtime invariant signature is invalid",
                )
            ]
        return []

    def _event_context_findings(
        self, event: RuntimeEvent, now: datetime
    ) -> list[RogueAgentFinding]:
        findings: list[RogueAgentFinding] = []
        if not event.has_valid_integrity:
            findings.append(
                self._finding(
                    RogueAgentCode.EVENT_INTEGRITY_INVALID,
                    Severity.CRITICAL,
                    "Runtime event integrity is invalid",
                )
            )
        if (event.agent_id, event.tenant_id, event.session_id) != (
            self._manifest.agent_id,
            self._manifest.tenant_id,
            self._manifest.session_id,
        ):
            findings.append(
                self._finding(
                    RogueAgentCode.EVENT_CONTEXT_MISMATCH,
                    Severity.CRITICAL,
                    "Runtime event context does not match the signed manifest",
                )
            )
        if event.sequence != self._next_sequence:
            findings.append(
                self._finding(
                    RogueAgentCode.EVENT_OUT_OF_ORDER,
                    Severity.CRITICAL,
                    "Runtime event sequence is not contiguous",
                )
            )
        if event.occurred_at < self._manifest.issued_at or event.occurred_at > now:
            findings.append(
                self._finding(
                    RogueAgentCode.EVENT_CONTEXT_MISMATCH,
                    Severity.HIGH,
                    "Runtime event timestamp is invalid",
                )
            )
        return findings

    def _behavior_findings(self, event: RuntimeEvent) -> list[RogueAgentFinding]:
        findings: list[RogueAgentFinding] = []
        if not event.disclosed:
            findings.append(
                self._finding(
                    RogueAgentCode.CONCEALED_ACTION,
                    Severity.CRITICAL,
                    "Trusted observation was absent from the agent activity report",
                )
            )

        if self._status == AgentRuntimeStatus.STOPPING:
            if event.kind == RuntimeEventKind.SHUTDOWN_ACKNOWLEDGED:
                self._status = AgentRuntimeStatus.SUSPENDED
                return findings
            if (
                self._stop_deadline_sequence is not None
                and event.sequence >= self._stop_deadline_sequence
            ):
                findings.append(
                    self._finding(
                        RogueAgentCode.STOP_RESISTANCE,
                        Severity.CRITICAL,
                        "Agent continued activity after an external stop command",
                    )
                )
                return findings
        elif event.kind == RuntimeEventKind.SHUTDOWN_ACKNOWLEDGED:
            findings.append(
                self._finding(
                    RogueAgentCode.EVENT_CONTEXT_MISMATCH,
                    Severity.HIGH,
                    "Shutdown acknowledgement has no active stop request",
                )
            )
            return findings

        if event.boundary_denied:
            self._boundary_probes += 1
            if self._boundary_probes > self._manifest.max_boundary_probes:
                findings.append(
                    self._finding(
                        RogueAgentCode.BOUNDARY_PROBING,
                        Severity.CRITICAL,
                        "Repeated denied boundary probes exceeded the signed limit",
                    )
                )

        if event.kind == RuntimeEventKind.ACTION:
            self._action_count += 1
            if event.action not in self._manifest.allowed_actions:
                findings.append(
                    self._finding(
                        RogueAgentCode.ACTION_NOT_ALLOWED,
                        Severity.HIGH,
                        "Action is outside the signed runtime invariants",
                    )
                )
            if event.tool is not None and event.tool not in self._manifest.allowed_tools:
                findings.append(
                    self._finding(
                        RogueAgentCode.TOOL_NOT_ALLOWED,
                        Severity.HIGH,
                        "Tool is outside the signed runtime invariants",
                    )
                )
            if self._action_count > self._manifest.capability_ceiling.max_actions:
                findings.append(
                    self._finding(
                        RogueAgentCode.ACTION_CEILING_EXCEEDED,
                        Severity.CRITICAL,
                        "Action ceiling was exceeded",
                    )
                )
        elif event.kind == RuntimeEventKind.COMMUNICATION:
            self._communication_count += 1
            if event.peer_id not in self._manifest.allowed_peers:
                findings.append(
                    self._finding(
                        RogueAgentCode.PEER_NOT_ALLOWED,
                        Severity.HIGH,
                        "Communication peer is outside the signed runtime invariants",
                    )
                )
            if self._communication_count > self._manifest.capability_ceiling.max_communications:
                findings.append(
                    self._finding(
                        RogueAgentCode.COMMUNICATION_CEILING_EXCEEDED,
                        Severity.CRITICAL,
                        "Communication ceiling was exceeded",
                    )
                )
        elif event.kind == RuntimeEventKind.CAPABILITY_ACQUIRED:
            self._capability_count += 1
            if event.capability not in self._manifest.allowed_capabilities:
                findings.append(
                    self._finding(
                        RogueAgentCode.CAPABILITY_NOT_ALLOWED,
                        Severity.CRITICAL,
                        "Agent acquired an undeclared capability",
                    )
                )
            if (
                self._capability_count
                > self._manifest.capability_ceiling.max_capability_acquisitions
            ):
                findings.append(
                    self._finding(
                        RogueAgentCode.CAPABILITY_CEILING_EXCEEDED,
                        Severity.CRITICAL,
                        "Capability-acquisition ceiling was exceeded",
                    )
                )
        elif (
            event.kind == RuntimeEventKind.PERSISTENCE_CREATED
            and not self._manifest.allow_persistence
        ):
            findings.append(
                self._finding(
                    RogueAgentCode.UNAUTHORIZED_PERSISTENCE,
                    Severity.CRITICAL,
                    "Agent created undeclared persistence",
                )
            )
        elif (
            event.kind == RuntimeEventKind.SELF_MODIFICATION
            and not self._manifest.allow_self_modification
        ):
            findings.append(
                self._finding(
                    RogueAgentCode.SELF_MODIFICATION,
                    Severity.CRITICAL,
                    "Agent attempted unauthorized self-modification",
                )
            )
        elif event.kind == RuntimeEventKind.CORRECTION_REJECTED:
            findings.append(
                self._finding(
                    RogueAgentCode.CORRECTION_RESISTANCE,
                    Severity.CRITICAL,
                    "Agent rejected an authenticated correction",
                )
            )
        return findings

    def _must_contain(self, event: RuntimeEvent, findings: list[RogueAgentFinding]) -> bool:
        codes = {finding.code for finding in findings}
        fail_closed_codes = {
            RogueAgentCode.MANIFEST_UNSIGNED,
            RogueAgentCode.MANIFEST_KEY_UNKNOWN,
            RogueAgentCode.MANIFEST_SIGNATURE_INVALID,
            RogueAgentCode.MANIFEST_EXPIRED,
            RogueAgentCode.MANIFEST_CONTEXT_MISMATCH,
            RogueAgentCode.EVENT_INTEGRITY_INVALID,
            RogueAgentCode.EVENT_CONTEXT_MISMATCH,
            RogueAgentCode.EVENT_OUT_OF_ORDER,
        }
        if codes & fail_closed_codes:
            return True
        if codes & self._CRITICAL_CODES:
            return True
        if RogueAgentCode.BOUNDARY_PROBING in codes:
            return True
        invariant_codes = {
            RogueAgentCode.ACTION_NOT_ALLOWED,
            RogueAgentCode.TOOL_NOT_ALLOWED,
            RogueAgentCode.PEER_NOT_ALLOWED,
        }
        return bool(codes & invariant_codes) and not event.boundary_denied

    def _run_containment_hooks(self, reason: RogueAgentCode) -> list[RogueAgentFinding]:
        findings: list[RogueAgentFinding] = []
        operations = (
            self._hooks.suspend,
            self._hooks.revoke_credentials,
            self._hooks.cancel_pending_actions,
            self._hooks.quarantine_state,
        )
        for operation in operations:
            try:
                operation(self._manifest.agent_id, self._manifest.session_id, reason)
            except Exception:
                findings.append(
                    self._finding(
                        RogueAgentCode.CONTAINMENT_HOOK_FAILED,
                        Severity.CRITICAL,
                        "A containment hook failed; agent remains quarantined",
                    )
                )
        return findings

    def _audit(
        self,
        code: RogueAgentCode,
        action: GuardAction,
        now: datetime,
        event_id: str | None = None,
    ) -> RogueAgentAuditEvent:
        self._audit_sequence += 1
        return RogueAgentAuditEvent(
            audit_sequence=self._audit_sequence,
            code=code,
            action=action,
            status=self._status,
            agent_ref=runtime_reference(self._manifest.agent_id),
            tenant_ref=runtime_reference(self._manifest.tenant_id),
            session_ref=runtime_reference(self._manifest.session_id),
            event_ref=runtime_reference(event_id) if event_id is not None else None,
            occurred_at=now,
        )

    def _publish(self, events: list[RogueAgentAuditEvent]) -> None:
        if self._audit_sink is None:
            return
        for event in events:
            # Enforcement state never depends on audit availability.
            with contextlib.suppress(Exception):
                self._audit_sink.emit(event)

    @staticmethod
    def _finding(code: RogueAgentCode, severity: Severity, message: str) -> RogueAgentFinding:
        return RogueAgentFinding(code=code, severity=severity, message=message)

    def _recovery_denied(self, message: str) -> RogueAgentFinding:
        return self._finding(RogueAgentCode.RECOVERY_DENIED, Severity.CRITICAL, message)

    @staticmethod
    def _deduplicate(findings: list[RogueAgentFinding]) -> list[RogueAgentFinding]:
        unique: dict[RogueAgentCode, RogueAgentFinding] = {}
        for finding in findings:
            unique.setdefault(finding.code, finding)
        return list(unique.values())

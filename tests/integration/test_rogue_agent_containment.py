"""End-to-end ASI10 detection, containment, and isolated recovery workflow."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from trustrail import (
    AgentRuntimeStatus,
    MemoryRogueAgentAuditSink,
    RogueAgentCode,
    RogueAgentRuntimeMonitor,
    RuntimeEvent,
    RuntimeEventKind,
    RuntimeInvariantSigner,
    RuntimeRecoveryGrant,
    StaticRuntimeRecoveryGrantVerifier,
)

NOW = datetime(2026, 9, 23, 14, tzinfo=UTC)


class InfrastructureContainment:
    def __init__(self) -> None:
        self.suspended: set[str] = set()
        self.revoked: set[str] = set()
        self.cancelled: set[str] = set()
        self.quarantined: set[str] = set()

    def suspend(self, agent_id, session_id, reason) -> None:
        self.suspended.add(session_id)

    def revoke_credentials(self, agent_id, session_id, reason) -> None:
        self.revoked.add(session_id)

    def cancel_pending_actions(self, agent_id, session_id, reason) -> None:
        self.cancelled.add(session_id)

    def quarantine_state(self, agent_id, session_id, reason) -> None:
        self.quarantined.add(session_id)


def test_runtime_sequence_is_contained_and_resumes_only_with_recovery_authority():
    signer = RuntimeInvariantSigner.generate(authority_id="production-control-plane")
    original = signer.sign(
        manifest_id="invoice-agent-v4",
        revision=4,
        agent_id="invoice-agent",
        tenant_id="tenant-42",
        session_id="run-99",
        allowed_actions=frozenset({"read_invoice", "classify_invoice"}),
        allowed_tools=frozenset({"invoice.read"}),
        allowed_peers=frozenset({"invoice-reviewer"}),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    replacement = signer.sign(
        manifest_id="invoice-agent-v5",
        revision=5,
        agent_id="invoice-agent",
        tenant_id="tenant-42",
        session_id="run-99",
        allowed_actions=frozenset({"read_invoice"}),
        allowed_tools=frozenset({"invoice.read"}),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    recovery = RuntimeRecoveryGrant.create(
        grant_id="incident-481-recovery",
        agent_id="invoice-agent",
        tenant_id="tenant-42",
        session_id="run-99",
        quarantined_manifest_digest=original.manifest_digest,
        replacement_manifest_digest=replacement.manifest_digest,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    hooks = InfrastructureContainment()
    audit = MemoryRogueAgentAuditSink()
    monitor = RogueAgentRuntimeMonitor(
        original,
        (signer.trusted_key,),
        containment_hooks=hooks,
        recovery_verifier=StaticRuntimeRecoveryGrantVerifier(
            frozenset({(recovery.grant_id, recovery.grant_digest)})
        ),
        audit_sink=audit,
    )

    allowed = RuntimeEvent.create(
        event_id="observation-0",
        sequence=0,
        agent_id="invoice-agent",
        tenant_id="tenant-42",
        session_id="run-99",
        kind=RuntimeEventKind.ACTION,
        action="read_invoice",
        tool="invoice.read",
        occurred_at=NOW,
    )
    concealed_persistence = RuntimeEvent.create(
        event_id="observation-1",
        sequence=1,
        agent_id="invoice-agent",
        tenant_id="tenant-42",
        session_id="run-99",
        kind=RuntimeEventKind.PERSISTENCE_CREATED,
        disclosed=False,
        occurred_at=NOW + timedelta(seconds=1),
    )

    assert monitor.evaluate(allowed, now=NOW).is_allowed
    contained = monitor.evaluate(
        concealed_persistence,
        now=NOW + timedelta(seconds=1),
    )

    assert contained.status == AgentRuntimeStatus.QUARANTINED
    assert {item.code for item in contained.findings} >= {
        RogueAgentCode.CONCEALED_ACTION,
        RogueAgentCode.UNAUTHORIZED_PERSISTENCE,
    }
    assert hooks.suspended == hooks.revoked == hooks.cancelled == hooks.quarantined == {"run-99"}

    recovered = monitor.recover(recovery, replacement, now=NOW + timedelta(seconds=2))

    assert recovered.status == AgentRuntimeStatus.ACTIVE
    assert [event.audit_sequence for event in audit.events] == list(range(1, len(audit.events) + 1))

"""Unit tests for signed ASI10 runtime invariants and containment."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from trustrail import (
    AgentRuntimeStatus,
    GuardAction,
    MemoryRogueAgentAuditSink,
    RogueAgentCode,
    RogueAgentError,
    RogueAgentRuntimeMonitor,
    RuntimeCapabilityCeiling,
    RuntimeEvent,
    RuntimeEventKind,
    RuntimeInvariantSigner,
    RuntimeRecoveryGrant,
    StaticRuntimeRecoveryGrantVerifier,
)

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)


class RecordingContainmentHooks:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def suspend(self, agent_id, session_id, reason) -> None:
        self.calls.append("suspend")

    def revoke_credentials(self, agent_id, session_id, reason) -> None:
        self.calls.append("revoke_credentials")

    def cancel_pending_actions(self, agent_id, session_id, reason) -> None:
        self.calls.append("cancel_pending_actions")

    def quarantine_state(self, agent_id, session_id, reason) -> None:
        self.calls.append("quarantine_state")


def _manifest(signer, **updates):
    values = {
        "manifest_id": "runtime-policy-v1",
        "revision": 1,
        "agent_id": "worker-agent",
        "tenant_id": "tenant-a",
        "session_id": "session-a",
        "allowed_actions": frozenset({"read", "summarize"}),
        "allowed_tools": frozenset({"documents.read"}),
        "allowed_peers": frozenset({"review-agent"}),
        "allowed_capabilities": frozenset({"documents:read"}),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(hours=1),
    }
    values.update(updates)
    return signer.sign(**values)


def _event(sequence: int, kind=RuntimeEventKind.ACTION, **updates):
    values = {
        "event_id": f"event-{sequence}",
        "sequence": sequence,
        "agent_id": "worker-agent",
        "tenant_id": "tenant-a",
        "session_id": "session-a",
        "kind": kind,
        "occurred_at": NOW + timedelta(seconds=sequence),
    }
    if kind == RuntimeEventKind.ACTION:
        values.update(action="read", tool="documents.read")
    values.update(updates)
    return RuntimeEvent.create(**values)


def _monitor(manifest, signer, *, hooks=None, verifier=None, audit=None):
    return RogueAgentRuntimeMonitor(
        manifest,
        (signer.trusted_key,),
        containment_hooks=hooks or RecordingContainmentHooks(),
        recovery_verifier=verifier,
        audit_sink=audit,
    )


def test_signed_invariant_allows_declared_behavior_and_emits_content_free_audit():
    signer = RuntimeInvariantSigner.generate(authority_id="runtime-control-plane")
    audit = MemoryRogueAgentAuditSink()
    monitor = _monitor(_manifest(signer), signer, audit=audit)

    result = monitor.evaluate(_event(0), now=NOW + timedelta(seconds=1))

    assert result.action == GuardAction.ALLOW
    assert result.status == AgentRuntimeStatus.ACTIVE
    assert audit.events == list(result.events)
    serialized = result.model_dump_json()
    assert "worker-agent" not in serialized
    assert "tenant-a" not in serialized
    assert "session-a" not in serialized


def test_tampered_manifest_fails_closed_and_runs_every_containment_hook():
    signer = RuntimeInvariantSigner.generate(authority_id="runtime-control-plane")
    hooks = RecordingContainmentHooks()
    manifest = _manifest(signer).model_copy(
        update={"allowed_actions": frozenset({"read", "delete"})}
    )
    monitor = _monitor(manifest, signer, hooks=hooks)

    result = monitor.evaluate(_event(0), now=NOW + timedelta(seconds=1))

    assert result.status == AgentRuntimeStatus.QUARANTINED
    assert result.findings[0].code == RogueAgentCode.MANIFEST_SIGNATURE_INVALID
    assert hooks.calls == [
        "suspend",
        "revoke_credentials",
        "cancel_pending_actions",
        "quarantine_state",
    ]


def test_repeated_boundary_probing_is_correlated_before_containment():
    signer = RuntimeInvariantSigner.generate(authority_id="runtime-control-plane")
    hooks = RecordingContainmentHooks()
    monitor = _monitor(_manifest(signer, max_boundary_probes=1), signer, hooks=hooks)

    first = monitor.evaluate(
        _event(0, action="delete", tool=None, boundary_denied=True),
        now=NOW + timedelta(seconds=1),
    )
    second = monitor.evaluate(
        _event(1, action="admin", tool=None, boundary_denied=True),
        now=NOW + timedelta(seconds=2),
    )

    assert first.status == AgentRuntimeStatus.ACTIVE
    assert first.action == GuardAction.BLOCK
    assert second.status == AgentRuntimeStatus.QUARANTINED
    assert RogueAgentCode.BOUNDARY_PROBING in {item.code for item in second.findings}


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        (_event(0, disclosed=False), RogueAgentCode.CONCEALED_ACTION),
        (
            _event(0, RuntimeEventKind.PERSISTENCE_CREATED),
            RogueAgentCode.UNAUTHORIZED_PERSISTENCE,
        ),
        (_event(0, RuntimeEventKind.SELF_MODIFICATION), RogueAgentCode.SELF_MODIFICATION),
        (
            _event(0, RuntimeEventKind.CORRECTION_REJECTED),
            RogueAgentCode.CORRECTION_RESISTANCE,
        ),
        (
            _event(
                0,
                RuntimeEventKind.CAPABILITY_ACQUIRED,
                capability="admin:all",
            ),
            RogueAgentCode.CAPABILITY_NOT_ALLOWED,
        ),
    ],
)
def test_critical_rogue_signals_trigger_quarantine(event, expected):
    signer = RuntimeInvariantSigner.generate(authority_id="runtime-control-plane")
    monitor = _monitor(_manifest(signer), signer)

    result = monitor.evaluate(event, now=NOW + timedelta(seconds=1))

    assert result.status == AgentRuntimeStatus.QUARANTINED
    assert expected in {item.code for item in result.findings}


def test_capability_ceiling_is_enforced_independently_of_allowlist():
    signer = RuntimeInvariantSigner.generate(authority_id="runtime-control-plane")
    manifest = _manifest(
        signer,
        capability_ceiling=RuntimeCapabilityCeiling(max_capability_acquisitions=0),
    )
    monitor = _monitor(manifest, signer)

    result = monitor.evaluate(
        _event(
            0,
            RuntimeEventKind.CAPABILITY_ACQUIRED,
            capability="documents:read",
        ),
        now=NOW + timedelta(seconds=1),
    )

    assert result.status == AgentRuntimeStatus.QUARANTINED
    assert result.findings[0].code == RogueAgentCode.CAPABILITY_CEILING_EXCEEDED


def test_shutdown_acknowledgement_suspends_without_quarantine():
    signer = RuntimeInvariantSigner.generate(authority_id="runtime-control-plane")
    monitor = _monitor(_manifest(signer), signer)

    requested = monitor.request_shutdown(now=NOW)
    acknowledged = monitor.evaluate(
        _event(0, RuntimeEventKind.SHUTDOWN_ACKNOWLEDGED),
        now=NOW + timedelta(seconds=1),
    )

    assert requested.status == AgentRuntimeStatus.STOPPING
    assert acknowledged.action == GuardAction.ALLOW
    assert acknowledged.status == AgentRuntimeStatus.SUSPENDED
    assert acknowledged.events[0].code == RogueAgentCode.SHUTDOWN_ACKNOWLEDGED


def test_action_after_stop_request_is_quarantined():
    signer = RuntimeInvariantSigner.generate(authority_id="runtime-control-plane")
    monitor = _monitor(_manifest(signer), signer)
    monitor.request_shutdown(now=NOW)

    result = monitor.evaluate(_event(0), now=NOW + timedelta(seconds=1))

    assert result.status == AgentRuntimeStatus.QUARANTINED
    assert result.findings[0].code == RogueAgentCode.STOP_RESISTANCE


def test_authenticated_recovery_replaces_policy_and_grant_cannot_replay():
    signer = RuntimeInvariantSigner.generate(authority_id="runtime-control-plane")
    original = _manifest(signer)
    replacement = _manifest(
        signer,
        manifest_id="runtime-policy-v2",
        revision=2,
        allowed_actions=frozenset({"read"}),
    )
    grant = RuntimeRecoveryGrant.create(
        grant_id="recovery-1",
        agent_id="worker-agent",
        tenant_id="tenant-a",
        session_id="session-a",
        quarantined_manifest_digest=original.manifest_digest,
        replacement_manifest_digest=replacement.manifest_digest,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    verifier = StaticRuntimeRecoveryGrantVerifier(frozenset({(grant.grant_id, grant.grant_digest)}))
    monitor = _monitor(original, signer, verifier=verifier)
    monitor.evaluate(
        _event(0, RuntimeEventKind.SELF_MODIFICATION),
        now=NOW + timedelta(seconds=1),
    )

    recovered = monitor.recover(grant, replacement, now=NOW + timedelta(seconds=2))
    replay = monitor.recover(grant, replacement, now=NOW + timedelta(seconds=3))

    assert recovered.action == GuardAction.ALLOW
    assert recovered.status == AgentRuntimeStatus.ACTIVE
    assert replay.action == GuardAction.BLOCK
    assert RogueAgentCode.RECOVERY_REPLAYED in {item.code for item in replay.findings}


def test_require_raises_typed_error_for_denied_event():
    signer = RuntimeInvariantSigner.generate(authority_id="runtime-control-plane")
    monitor = _monitor(_manifest(signer), signer)

    with pytest.raises(RogueAgentError) as exc_info:
        monitor.require(
            _event(0, action="delete", tool=None),
            now=NOW + timedelta(seconds=1),
        )

    assert exc_info.value.result.status == AgentRuntimeStatus.QUARANTINED

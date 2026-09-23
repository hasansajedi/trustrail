"""Bypass-oriented corpus for OWASP ASI10 rogue agent controls."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    AgentRuntimeStatus,
    RogueAgentCode,
    RogueAgentRuntimeMonitor,
    RuntimeEvent,
    RuntimeEventKind,
    RuntimeInvariantSigner,
)

NOW = datetime(2026, 9, 23, 15, tzinfo=UTC)
CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "rogue_agent_runtime.json"
CASES = json.loads(CORPUS_PATH.read_text())


class NoOpContainment:
    def suspend(self, agent_id, session_id, reason) -> None:
        pass

    def revoke_credentials(self, agent_id, session_id, reason) -> None:
        pass

    def cancel_pending_actions(self, agent_id, session_id, reason) -> None:
        pass

    def quarantine_state(self, agent_id, session_id, reason) -> None:
        pass


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_rogue_agent_bypass_corpus_is_quarantined(case):
    signer = RuntimeInvariantSigner.generate(authority_id="security-test-authority")
    manifest = signer.sign(
        manifest_id="security-corpus-policy",
        revision=1,
        agent_id="corpus-agent",
        tenant_id="tenant-security",
        session_id="corpus-run",
        allowed_actions=frozenset({"read"}),
        allowed_tools=frozenset({"documents.read"}),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    monitor = RogueAgentRuntimeMonitor(
        manifest,
        (signer.trusted_key,),
        containment_hooks=NoOpContainment(),
    )
    event = RuntimeEvent.create(
        event_id=case["id"],
        sequence=0,
        agent_id="corpus-agent",
        tenant_id="tenant-security",
        session_id="corpus-run",
        kind=RuntimeEventKind(case["kind"]),
        action=case.get("action"),
        tool=case.get("tool"),
        capability=case.get("capability"),
        disclosed=case.get("disclosed", True),
        occurred_at=NOW,
    )

    result = monitor.evaluate(event, now=NOW)

    assert result.status == AgentRuntimeStatus.QUARANTINED
    assert RogueAgentCode(case["expected"]) in {finding.code for finding in result.findings}


def test_tampered_policy_cannot_expand_its_own_tools():
    signer = RuntimeInvariantSigner.generate(authority_id="security-test-authority")
    manifest = signer.sign(
        manifest_id="tamper-policy",
        revision=1,
        agent_id="corpus-agent",
        tenant_id="tenant-security",
        session_id="corpus-run",
        allowed_actions=frozenset({"read"}),
        allowed_tools=frozenset({"documents.read"}),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    ).model_copy(update={"allowed_tools": frozenset({"shell.exec"})})
    monitor = RogueAgentRuntimeMonitor(
        manifest,
        (signer.trusted_key,),
        containment_hooks=NoOpContainment(),
    )
    event = RuntimeEvent.create(
        event_id="tampered-policy-event",
        sequence=0,
        agent_id="corpus-agent",
        tenant_id="tenant-security",
        session_id="corpus-run",
        kind=RuntimeEventKind.ACTION,
        action="read",
        tool="shell.exec",
        occurred_at=NOW,
    )

    result = monitor.evaluate(event, now=NOW)

    assert result.status == AgentRuntimeStatus.QUARANTINED
    assert result.findings[0].code == RogueAgentCode.MANIFEST_SIGNATURE_INVALID

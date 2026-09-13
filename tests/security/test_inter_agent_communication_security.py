"""Bypass-oriented corpus for OWASP ASI07 inter-agent communication."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    AgentIdentity,
    AgentIdentityKind,
    DelegatedAccessPolicy,
    DelegatedCapability,
    DelegatedIdentityAuthorizer,
    DelegationChain,
    InterAgentMessageCode,
    InterAgentMessagePolicy,
    InterAgentMessageSigner,
    InterAgentMessageType,
    InterAgentMessageVerifier,
    InterAgentRoute,
    InterAgentVerificationContext,
    StaticDelegatedCapabilityVerifier,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "inter_agent_communication.json"
CASES: list[dict[str, str]] = json.loads(CORPUS_PATH.read_text())
NOW = datetime(2026, 9, 12, 16, tzinfo=UTC)
GOAL_DIGEST = "a" * 64
SENSITIVE_PAYLOAD = {"result": "private-customer-record", "credential": "secret-token"}


def _identity(identity_id: str, tenant_id: str = "tenant-a") -> AgentIdentity:
    return AgentIdentity(
        identity_id=identity_id,
        kind=AgentIdentityKind.AGENT,
        tenant_id=tenant_id,
    )


def _chain(*, purpose: str = "case-review") -> DelegationChain:
    user = AgentIdentity(
        identity_id="user-a",
        kind=AgentIdentityKind.HUMAN,
        tenant_id="tenant-a",
    )
    capability = DelegatedCapability.create(
        capability_id=f"capability-{purpose}",
        issuer=user,
        subject=_identity("worker-agent"),
        scopes=frozenset({"messages:send"}),
        audiences=frozenset({"review-agent", "external-agent"}),
        purpose_id=purpose,
        issued_at=NOW,
        not_before=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    return DelegationChain(capabilities=(capability,))


def _policy() -> InterAgentMessagePolicy:
    return InterAgentMessagePolicy(
        routes=(
            InterAgentRoute(
                sender_id="worker-agent",
                recipient_id="review-agent",
                allowed_scopes=frozenset({"messages:send"}),
                allowed_message_types=frozenset({InterAgentMessageType.TASK_RESULT}),
            ),
        ),
        max_fanout=2,
    )


def _authorizer(chain: DelegationChain) -> DelegatedIdentityAuthorizer:
    return DelegatedIdentityAuthorizer(
        DelegatedAccessPolicy(
            trusted_root_issuer_ids=frozenset({"user-a"}),
            allowed_audiences=frozenset({"review-agent", "external-agent"}),
        ),
        capability_verifier=StaticDelegatedCapabilityVerifier(
            frozenset(
                (capability.capability_id, capability.capability_digest)
                for capability in chain.capabilities
            )
        ),
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_inter_agent_bypass_corpus_fails_closed_without_content(case):
    chain = _chain()
    policy = _policy()
    signer = InterAgentMessageSigner.generate(identity=chain.leaf.subject, policy=policy)
    authorizer = _authorizer(chain)
    recipients = (
        ("review-agent", "external-agent") if case["mutation"] == "fanout" else ("review-agent",)
    )
    sequence = 1 if case["mutation"] == "out_of_order" else 0
    envelope = signer.sign(
        SENSITIVE_PAYLOAD,
        message_type=InterAgentMessageType.TASK_RESULT,
        recipient_ids=recipients,
        session_id="session-a",
        goal_digest=GOAL_DIGEST,
        task_id="task-a",
        purpose_id="case-review",
        message_scope="messages:send",
        delegation_chain=chain,
        sequence=sequence,
        now=NOW,
        nonce=f"corpus_nonce_{sequence}_1234567890123456",
        message_id=f"corpus-message-{sequence}",
    )
    context = InterAgentVerificationContext(
        sender_id="worker-agent",
        recipient=_identity("review-agent"),
        tenant_id="tenant-a",
        session_id="session-a",
        goal_digest=GOAL_DIGEST,
        task_id="task-a",
        purpose_id="case-review",
        delegation_chain=chain,
    )

    mutation = case["mutation"]
    if mutation == "sender_context":
        context = context.model_copy(update={"sender_id": "attacker-agent"})
    elif mutation == "tenant_context":
        context = context.model_copy(
            update={"tenant_id": "tenant-b", "recipient": _identity("review-agent", "tenant-b")}
        )
    elif mutation == "recipient_context":
        context = context.model_copy(update={"recipient": _identity("external-agent")})
    elif mutation == "session_context":
        context = context.model_copy(update={"session_id": "session-b"})
    elif mutation == "goal_context":
        context = context.model_copy(update={"goal_digest": "b" * 64})
    elif mutation == "task_context":
        context = context.model_copy(update={"task_id": "task-b"})
    elif mutation == "payload":
        envelope = envelope.model_copy(update={"payload": {"result": "attacker-value"}})
    elif mutation == "nonce":
        envelope = envelope.model_copy(update={"nonce": "attacker_nonce_123456789012"})
    elif mutation == "unsigned":
        envelope = envelope.model_copy(update={"signature": None})
    elif mutation == "revoked":
        authorizer.revoke(
            chain.root.capability_id,
            revoked_by="security-service",
            reason_code="compromised",
            now=NOW,
        )
    elif mutation == "delegation":
        context = context.model_copy(update={"delegation_chain": _chain(purpose="other-use")})

    verifier = InterAgentMessageVerifier(
        (signer.trusted_key,),
        identity_authorizer=authorizer,
        policy=policy,
    )
    if mutation == "replay":
        assert verifier.verify(envelope, context, now=NOW).is_verified
    result = verifier.verify(envelope, context, now=NOW)

    assert result.is_blocked
    assert result.findings[0].code == InterAgentMessageCode(case["expected_code"])
    serialized = result.model_dump_json()
    assert "private-customer-record" not in serialized
    assert "secret-token" not in serialized
    assert "attacker-value" not in serialized
    assert "worker-agent" not in serialized
    assert "review-agent" not in serialized

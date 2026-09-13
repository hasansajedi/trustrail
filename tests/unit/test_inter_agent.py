"""Unit tests for authenticated inter-agent communication."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import JsonValue, ValidationError

from trustrail import (
    AgentIdentity,
    AgentIdentityKind,
    DelegatedAccessPolicy,
    DelegatedCapability,
    DelegatedIdentityAuthorizer,
    DelegationChain,
    InterAgentMessageCode,
    InterAgentMessageEnvelope,
    InterAgentMessageError,
    InterAgentMessagePolicy,
    InterAgentMessageSigner,
    InterAgentMessageType,
    InterAgentMessageVerifier,
    InterAgentRoute,
    InterAgentStateClaimStatus,
    InterAgentVerificationContext,
    MemoryInterAgentMessageAuditSink,
    MemoryInterAgentStateStore,
    StaticDelegatedCapabilityVerifier,
)

NOW = datetime(2026, 9, 12, 16, tzinfo=UTC)
GOAL_DIGEST = "a" * 64
PAYLOAD: JsonValue = {"result": "approved", "records": ["record-1"]}


def _identity(
    identity_id: str,
    kind: AgentIdentityKind,
    tenant_id: str = "tenant-a",
) -> AgentIdentity:
    return AgentIdentity(identity_id=identity_id, kind=kind, tenant_id=tenant_id)


def _chain(*, audiences: frozenset[str] | None = None) -> DelegationChain:
    user = _identity("user-a", AgentIdentityKind.HUMAN)
    worker = _identity("worker-agent", AgentIdentityKind.AGENT)
    capability = DelegatedCapability.create(
        capability_id="inter-agent-root",
        issuer=user,
        subject=worker,
        scopes=frozenset({"messages:send"}),
        audiences=audiences or frozenset({"review-agent", "external-agent"}),
        purpose_id="case-review",
        issued_at=NOW,
        not_before=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    return DelegationChain(capabilities=(capability,))


def _policy(
    *,
    max_fanout: int = 2,
    max_payload_bytes: int = 1_048_576,
) -> InterAgentMessagePolicy:
    return InterAgentMessagePolicy(
        routes=(
            InterAgentRoute(
                sender_id="worker-agent",
                recipient_id="review-agent",
                allowed_scopes=frozenset({"messages:send"}),
                allowed_message_types=frozenset(
                    {InterAgentMessageType.TASK_REQUEST, InterAgentMessageType.TASK_RESULT}
                ),
            ),
        ),
        max_fanout=max_fanout,
        max_payload_bytes=max_payload_bytes,
    )


def _authorizer(chain: DelegationChain) -> DelegatedIdentityAuthorizer:
    capability = chain.root
    return DelegatedIdentityAuthorizer(
        DelegatedAccessPolicy(
            trusted_root_issuer_ids=frozenset({"user-a"}),
            allowed_audiences=frozenset({"review-agent", "external-agent"}),
        ),
        capability_verifier=StaticDelegatedCapabilityVerifier(
            frozenset({(capability.capability_id, capability.capability_digest)})
        ),
    )


def _context(
    chain: DelegationChain,
    *,
    recipient: AgentIdentity | None = None,
) -> InterAgentVerificationContext:
    actual_recipient = recipient or _identity("review-agent", AgentIdentityKind.AGENT)
    return InterAgentVerificationContext(
        sender_id="worker-agent",
        recipient=actual_recipient,
        tenant_id=actual_recipient.tenant_id,
        session_id="session-a",
        goal_digest=GOAL_DIGEST,
        task_id="task-a",
        purpose_id="case-review",
        delegation_chain=chain,
    )


def _signer_and_envelope(
    *,
    chain: DelegationChain | None = None,
    policy: InterAgentMessagePolicy | None = None,
    sequence: int = 0,
    recipient_ids: tuple[str, ...] = ("review-agent",),
    payload: JsonValue = PAYLOAD,
    now: datetime = NOW,
):
    actual_chain = chain or _chain()
    actual_policy = policy or _policy()
    signer = InterAgentMessageSigner.generate(
        identity=actual_chain.leaf.subject, policy=actual_policy
    )
    envelope = signer.sign(
        payload,
        message_type=InterAgentMessageType.TASK_RESULT,
        recipient_ids=recipient_ids,
        session_id="session-a",
        goal_digest=GOAL_DIGEST,
        task_id="task-a",
        purpose_id="case-review",
        message_scope="messages:send",
        delegation_chain=actual_chain,
        sequence=sequence,
        now=now,
        nonce=f"nonce_{sequence:02d}_12345678901234567890",
        message_id=f"message-{sequence}",
    )
    return actual_chain, actual_policy, signer, envelope


def _verifier(
    chain,
    policy,
    signer,
    *,
    state_store=None,
    audit_sink=None,
    extra_keys=(),
) -> InterAgentMessageVerifier:
    return InterAgentMessageVerifier(
        (signer.trusted_key, *extra_keys),
        identity_authorizer=_authorizer(chain),
        policy=policy,
        state_store=state_store,
        audit_sink=audit_sink,
    )


def test_signed_message_round_trip_and_content_free_audit():
    chain, policy, signer, envelope = _signer_and_envelope()
    audit_sink = MemoryInterAgentMessageAuditSink()
    verifier = _verifier(chain, policy, signer, audit_sink=audit_sink)

    result = verifier.verify(envelope, _context(chain), now=NOW)

    assert result.is_verified
    assert result.audit_event.code == InterAgentMessageCode.VERIFIED
    assert result.audit_event.sequence == 0
    assert result.audit_event.transformation_count == 0
    assert audit_sink.events == [result.audit_event]
    serialized = result.model_dump_json()
    assert "approved" not in serialized
    assert "record-1" not in serialized
    assert "worker-agent" not in serialized
    assert "review-agent" not in serialized
    assert "session-a" not in serialized


def test_require_raises_without_exposing_payload():
    chain, policy, signer, envelope = _signer_and_envelope()
    unsigned = envelope.model_copy(update={"signature": None})
    verifier = _verifier(chain, policy, signer)
    with pytest.raises(InterAgentMessageError, match="Inter-agent message was not verified") as exc:
        verifier.require(unsigned, _context(chain), now=NOW)

    assert exc.value.result.findings[0].code == InterAgentMessageCode.UNSIGNED_MESSAGE
    assert "approved" not in str(exc.value)


@pytest.mark.parametrize(
    ("context_update", "expected_code"),
    [
        ({"sender_id": "other-agent"}, InterAgentMessageCode.IDENTITY_MISMATCH),
        ({"session_id": "session-b"}, InterAgentMessageCode.SESSION_MISMATCH),
        ({"goal_digest": "b" * 64}, InterAgentMessageCode.GOAL_MISMATCH),
        ({"task_id": "task-b"}, InterAgentMessageCode.TASK_MISMATCH),
        ({"purpose_id": "other-purpose"}, InterAgentMessageCode.PURPOSE_MISMATCH),
    ],
)
def test_authenticated_context_mismatches_are_rejected(context_update, expected_code):
    chain, policy, signer, envelope = _signer_and_envelope()
    context = _context(chain).model_copy(update=context_update)

    result = _verifier(chain, policy, signer).verify(envelope, context, now=NOW)

    assert result.findings[0].code == expected_code


def test_cross_tenant_recipient_is_rejected():
    chain, policy, signer, envelope = _signer_and_envelope()
    recipient = _identity("review-agent", AgentIdentityKind.AGENT, "tenant-b")

    result = _verifier(chain, policy, signer).verify(
        envelope,
        _context(chain, recipient=recipient),
        now=NOW,
    )

    assert result.findings[0].code == InterAgentMessageCode.TENANT_MISMATCH


def test_payload_and_signed_field_mutation_are_rejected():
    chain, policy, signer, envelope = _signer_and_envelope()
    verifier = _verifier(chain, policy, signer)

    tampered_payload = envelope.model_copy(update={"payload": {"result": "exfiltrate"}}, deep=True)
    payload_result = verifier.verify(tampered_payload, _context(chain), now=NOW)
    assert payload_result.findings[0].code == InterAgentMessageCode.PAYLOAD_DIGEST_MISMATCH
    assert "exfiltrate" not in payload_result.model_dump_json()

    tampered_nonce = envelope.model_copy(update={"nonce": "attacker_nonce_123456789012"})
    signature_result = verifier.verify(tampered_nonce, _context(chain), now=NOW)
    assert signature_result.findings[0].code == InterAgentMessageCode.SIGNATURE_INVALID


def test_unknown_and_revoked_signers_are_rejected():
    chain, policy, signer, envelope = _signer_and_envelope()
    attacker = InterAgentMessageSigner.generate(identity=chain.leaf.subject, policy=policy)

    unknown_result = _verifier(chain, policy, attacker).verify(envelope, _context(chain), now=NOW)
    assert unknown_result.findings[0].code == InterAgentMessageCode.UNKNOWN_AGENT

    revoked_key = signer.trusted_key.model_copy(update={"revoked": True})
    revoked_verifier = InterAgentMessageVerifier(
        (revoked_key,),
        identity_authorizer=_authorizer(chain),
        policy=policy,
    )
    revoked_result = revoked_verifier.verify(envelope, _context(chain), now=NOW)
    assert revoked_result.findings[0].code == InterAgentMessageCode.KEY_NOT_ACTIVE


def test_current_capability_revocation_blocks_message():
    chain, policy, signer, envelope = _signer_and_envelope()
    authorizer = _authorizer(chain)
    authorizer.revoke(
        chain.root.capability_id,
        revoked_by="security-service",
        reason_code="compromised",
        now=NOW,
    )
    verifier = InterAgentMessageVerifier(
        (signer.trusted_key,),
        identity_authorizer=authorizer,
        policy=policy,
    )

    result = verifier.verify(envelope, _context(chain), now=NOW)

    assert result.findings[0].code == InterAgentMessageCode.DELEGATION_DENIED


def test_delegation_digest_substitution_is_rejected():
    chain, policy, signer, envelope = _signer_and_envelope()
    other_chain = _chain(audiences=frozenset({"review-agent"}))
    context = _context(chain).model_copy(update={"delegation_chain": other_chain})

    result = _verifier(chain, policy, signer).verify(envelope, context, now=NOW)

    assert result.findings[0].code == InterAgentMessageCode.DELEGATION_MISMATCH


def test_unauthorized_fanout_and_scope_are_rejected():
    chain, policy, signer, envelope = _signer_and_envelope(
        recipient_ids=("review-agent", "external-agent")
    )
    verifier = _verifier(chain, policy, signer)

    fanout = verifier.verify(envelope, _context(chain), now=NOW)
    assert fanout.findings[0].code == InterAgentMessageCode.FANOUT_DENIED

    one_recipient = signer.sign(
        PAYLOAD,
        message_type=InterAgentMessageType.TASK_RESULT,
        recipient_ids=("review-agent",),
        session_id="session-a",
        goal_digest=GOAL_DIGEST,
        task_id="task-a",
        purpose_id="case-review",
        message_scope="messages:send",
        delegation_chain=chain,
        sequence=0,
        now=NOW,
    )
    denied_scope = one_recipient.model_copy(update={"message_scope": "records:delete"})
    scope_result = verifier.verify(denied_scope, _context(chain), now=NOW)
    assert scope_result.findings[0].code == InterAgentMessageCode.ROUTE_DENIED


def test_expired_future_and_overlong_messages_are_rejected():
    chain, policy, signer, envelope = _signer_and_envelope()
    verifier = _verifier(chain, policy, signer)

    expired = envelope.model_copy(update={"expires_at": NOW - timedelta(seconds=31)})
    assert (
        verifier.verify(expired, _context(chain), now=NOW).findings[0].code
        == InterAgentMessageCode.MESSAGE_EXPIRED
    )

    future = envelope.model_copy(update={"issued_at": NOW + timedelta(seconds=31)})
    assert (
        verifier.verify(future, _context(chain), now=NOW).findings[0].code
        == InterAgentMessageCode.MESSAGE_NOT_YET_VALID
    )

    overlong = envelope.model_copy(update={"expires_at": NOW + timedelta(seconds=301)})
    assert (
        verifier.verify(overlong, _context(chain), now=NOW).findings[0].code
        == InterAgentMessageCode.TTL_EXCEEDED
    )


def test_replay_and_out_of_order_messages_are_atomic():
    chain, policy, signer, first = _signer_and_envelope(sequence=0)
    second = signer.sign(
        PAYLOAD,
        message_type=InterAgentMessageType.TASK_RESULT,
        recipient_ids=("review-agent",),
        session_id="session-a",
        goal_digest=GOAL_DIGEST,
        task_id="task-a",
        purpose_id="case-review",
        message_scope="messages:send",
        delegation_chain=chain,
        sequence=1,
        now=NOW,
        nonce="nonce_01_12345678901234567890",
        message_id="message-1",
    )
    verifier = _verifier(chain, policy, signer)
    context = _context(chain)

    skipped = verifier.verify(second, context, now=NOW)
    assert skipped.findings[0].code == InterAgentMessageCode.OUT_OF_ORDER
    assert verifier.verify(first, context, now=NOW).is_verified
    replay = verifier.verify(first, context, now=NOW)
    assert replay.findings[0].code == InterAgentMessageCode.REPLAY_DETECTED
    assert verifier.verify(second, context, now=NOW).is_verified


def test_only_one_concurrent_delivery_claims_a_message():
    chain, policy, signer, envelope = _signer_and_envelope()
    verifier = _verifier(chain, policy, signer)
    context = _context(chain)

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: verifier.verify(envelope, context, now=NOW), range(24)))

    assert sum(result.is_verified for result in results) == 1
    assert all(
        result.is_verified or result.findings[0].code == InterAgentMessageCode.REPLAY_DETECTED
        for result in results
    )


def test_valid_signed_transformation_chain_is_verified():
    chain = _chain()
    policy = _policy()
    signer = InterAgentMessageSigner.generate(identity=chain.leaf.subject, policy=policy)
    source: JsonValue = {"raw": "untrusted result"}
    transformed: JsonValue = {"result": "sanitized"}
    attestation = signer.attest_transformation(
        source,
        transformed,
        operation_id="sanitize-result",
        hop_index=0,
        now=NOW,
        transformation_id="transform-0",
    )
    envelope = signer.sign(
        transformed,
        message_type=InterAgentMessageType.TASK_RESULT,
        recipient_ids=("review-agent",),
        session_id="session-a",
        goal_digest=GOAL_DIGEST,
        task_id="task-a",
        purpose_id="case-review",
        message_scope="messages:send",
        delegation_chain=chain,
        sequence=0,
        transformations=(attestation,),
        now=NOW,
    )

    result = _verifier(chain, policy, signer).verify(envelope, _context(chain), now=NOW)

    assert result.is_verified
    assert result.audit_event.transformation_count == 1


def test_inner_transformation_signature_is_verified_independently():
    chain = _chain()
    policy = _policy()
    signer = InterAgentMessageSigner.generate(identity=chain.leaf.subject, policy=policy)
    source: JsonValue = {"raw": "input"}
    transformed: JsonValue = {"result": "safe"}
    attestation = signer.attest_transformation(
        source,
        transformed,
        operation_id="sanitize-result",
        hop_index=0,
        now=NOW,
    ).model_copy(update={"signature": "0" * 128})
    envelope = signer.sign(
        transformed,
        message_type=InterAgentMessageType.TASK_RESULT,
        recipient_ids=("review-agent",),
        session_id="session-a",
        goal_digest=GOAL_DIGEST,
        task_id="task-a",
        purpose_id="case-review",
        message_scope="messages:send",
        delegation_chain=chain,
        sequence=0,
        transformations=(attestation,),
        now=NOW,
    )

    result = _verifier(chain, policy, signer).verify(envelope, _context(chain), now=NOW)

    assert result.findings[0].code == InterAgentMessageCode.TRANSFORMATION_SIGNATURE_INVALID


def test_external_transformer_must_be_explicitly_authorized():
    chain = _chain()
    policy = _policy()
    signer = InterAgentMessageSigner.generate(identity=chain.leaf.subject, policy=policy)
    outsider = InterAgentMessageSigner.generate(
        identity=_identity("untrusted-transformer", AgentIdentityKind.SERVICE),
        policy=policy,
    )
    source: JsonValue = {"raw": "input"}
    transformed: JsonValue = {"result": "changed"}
    attestation = outsider.attest_transformation(
        source,
        transformed,
        operation_id="rewrite",
        hop_index=0,
        now=NOW,
    )
    envelope = signer.sign(
        transformed,
        message_type=InterAgentMessageType.TASK_RESULT,
        recipient_ids=("review-agent",),
        session_id="session-a",
        goal_digest=GOAL_DIGEST,
        task_id="task-a",
        purpose_id="case-review",
        message_scope="messages:send",
        delegation_chain=chain,
        sequence=0,
        transformations=(attestation,),
        now=NOW,
    )

    result = _verifier(
        chain,
        policy,
        signer,
        extra_keys=(outsider.trusted_key,),
    ).verify(envelope, _context(chain), now=NOW)

    assert result.findings[0].code == InterAgentMessageCode.TRANSFORMER_NOT_TRUSTED


class _FailingStore:
    def claim(self, *args, **kwargs):
        raise RuntimeError("backend credentials must not be exposed")


def test_state_store_failure_and_capacity_fail_closed():
    chain, policy, signer, envelope = _signer_and_envelope()
    context = _context(chain)
    failed = _verifier(chain, policy, signer, state_store=_FailingStore()).verify(
        envelope,
        context,
        now=NOW,
    )
    assert failed.findings[0].code == InterAgentMessageCode.STATE_STORE_ERROR
    assert "credentials" not in failed.model_dump_json()

    full_store = MemoryInterAgentStateStore(max_replay_entries=1)
    assert (
        full_store.claim(
            "other-stream",
            "other-replay",
            sequence=0,
            expires_at=NOW + timedelta(minutes=1),
            now=NOW,
        )
        == InterAgentStateClaimStatus.STORED
    )
    full = _verifier(chain, policy, signer, state_store=full_store).verify(
        envelope,
        context,
        now=NOW,
    )
    assert full.findings[0].code == InterAgentMessageCode.STATE_STORE_FULL


def test_models_and_signer_reject_unsafe_bounds():
    chain, policy, signer, envelope = _signer_and_envelope()
    data = envelope.model_dump()
    data["recipient_ids"] = ("review-agent", "review-agent")
    with pytest.raises(ValidationError, match="recipient_ids must be unique"):
        InterAgentMessageEnvelope.model_validate(data)

    with pytest.raises(ValidationError, match="default_ttl_seconds"):
        InterAgentMessagePolicy(
            routes=policy.routes,
            default_ttl_seconds=301,
            max_ttl_seconds=300,
        )

    with pytest.raises(ValueError, match="max_fanout"):
        signer.sign(
            PAYLOAD,
            message_type=InterAgentMessageType.TASK_RESULT,
            recipient_ids=("review-agent", "external-agent", "third-agent"),
            session_id="session-a",
            goal_digest=GOAL_DIGEST,
            task_id="task-a",
            purpose_id="case-review",
            message_scope="messages:send",
            delegation_chain=chain,
            sequence=0,
            now=NOW,
        )

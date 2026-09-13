"""Signed, identity-bound, ordered communication between agents."""

from __future__ import annotations

import contextlib
import secrets
import threading
import uuid
from collections import deque
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import JsonValue

from trustrail.delegated_identity import DelegatedIdentityAuthorizer
from trustrail.exceptions import InterAgentMessageError
from trustrail.models.delegated_identity import (
    AgentIdentity,
    DelegatedAccessRequest,
    DelegationChain,
)
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.inter_agent import (
    InterAgentMessageAuditEvent,
    InterAgentMessageCode,
    InterAgentMessageEnvelope,
    InterAgentMessageFinding,
    InterAgentMessagePolicy,
    InterAgentMessageType,
    InterAgentMessageVerificationResult,
    InterAgentStateClaimStatus,
    InterAgentTransformation,
    InterAgentTrustedKey,
    InterAgentVerificationContext,
    canonical_inter_agent_json,
    inter_agent_content_reference,
    inter_agent_payload_digest,
    utcnow,
)


class InterAgentStateStore(Protocol):
    """Atomically enforce nonce replay and per-stream message order."""

    def claim(
        self,
        stream_id: str,
        replay_id: str,
        *,
        sequence: int,
        expires_at: datetime,
        now: datetime,
    ) -> InterAgentStateClaimStatus:
        """Claim a nonce and exact next sequence, or return a failure status."""
        ...


class InterAgentMessageAuditSink(Protocol):
    """Persist metadata-only inter-agent verification evidence."""

    def emit(self, event: InterAgentMessageAuditEvent) -> None:
        """Persist one event without receiving message payloads."""
        ...


class MemoryInterAgentMessageAuditSink:
    """Bounded process-local audit sink for tests and development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[InterAgentMessageAuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def emit(self, event: InterAgentMessageAuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> list[InterAgentMessageAuditEvent]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


class MemoryInterAgentStateStore:
    """Capacity-bounded atomic replay and ordering state for one process."""

    def __init__(self, *, max_replay_entries: int = 10_000, max_streams: int = 10_000) -> None:
        if max_replay_entries < 1:
            raise ValueError("max_replay_entries must be at least 1")
        if max_streams < 1:
            raise ValueError("max_streams must be at least 1")
        self._max_replay_entries = max_replay_entries
        self._max_streams = max_streams
        self._replays: dict[str, datetime] = {}
        self._streams: dict[str, tuple[int, datetime]] = {}
        self._lock = threading.Lock()

    @property
    def replay_size(self) -> int:
        with self._lock:
            return len(self._replays)

    @property
    def stream_size(self) -> int:
        with self._lock:
            return len(self._streams)

    def claim(
        self,
        stream_id: str,
        replay_id: str,
        *,
        sequence: int,
        expires_at: datetime,
        now: datetime,
    ) -> InterAgentStateClaimStatus:
        if expires_at.tzinfo is None or now.tzinfo is None:
            raise ValueError("state-store timestamps must be timezone-aware")
        if expires_at <= now:
            raise ValueError("state-store expiration must be in the future")
        if sequence < 0:
            raise ValueError("sequence must not be negative")
        with self._lock:
            self._replays = {key: expiry for key, expiry in self._replays.items() if expiry > now}
            self._streams = {key: value for key, value in self._streams.items() if value[1] > now}
            if replay_id in self._replays:
                return InterAgentStateClaimStatus.REPLAYED

            stream = self._streams.get(stream_id)
            expected = 0 if stream is None else stream[0]
            if sequence != expected:
                return InterAgentStateClaimStatus.OUT_OF_ORDER
            if len(self._replays) >= self._max_replay_entries:
                return InterAgentStateClaimStatus.FULL
            if stream is None and len(self._streams) >= self._max_streams:
                return InterAgentStateClaimStatus.FULL

            self._replays[replay_id] = expires_at
            stream_expiry = expires_at if stream is None else max(stream[1], expires_at)
            self._streams[stream_id] = (sequence + 1, stream_expiry)
            return InterAgentStateClaimStatus.STORED

    def clear(self) -> None:
        with self._lock:
            self._replays.clear()
            self._streams.clear()


class InterAgentMessageSigner:
    """Sign messages and transformation attestations for one agent identity."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        identity: AgentIdentity,
        policy: InterAgentMessagePolicy,
    ) -> None:
        self._private_key = private_key
        self._identity = identity.model_copy(deep=True)
        self._policy = policy.model_copy(deep=True)
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._trusted_key = InterAgentTrustedKey(identity=identity, public_key=public_key)

    @classmethod
    def generate(
        cls,
        *,
        identity: AgentIdentity,
        policy: InterAgentMessagePolicy,
    ) -> InterAgentMessageSigner:
        """Create a signer backed by a new Ed25519 key pair."""
        return cls(Ed25519PrivateKey.generate(), identity=identity, policy=policy)

    @property
    def key_id(self) -> str:
        return self._trusted_key.key_id

    @property
    def trusted_key(self) -> InterAgentTrustedKey:
        """Return public identity evidence for authenticated provisioning."""
        return self._trusted_key.model_copy(deep=True)

    def attest_transformation(
        self,
        input_payload: JsonValue,
        output_payload: JsonValue,
        *,
        operation_id: str,
        hop_index: int,
        now: datetime | None = None,
        transformation_id: str | None = None,
    ) -> InterAgentTransformation:
        """Sign one content-free payload transformation link."""
        unsigned = InterAgentTransformation(
            transformation_id=transformation_id or str(uuid.uuid4()),
            hop_index=hop_index,
            transformer=self._identity,
            key_id=self.key_id,
            operation_id=operation_id,
            input_digest=inter_agent_payload_digest(input_payload),
            output_digest=inter_agent_payload_digest(output_payload),
            occurred_at=now or utcnow(),
        )
        return unsigned.model_copy(
            update={"signature": self._private_key.sign(unsigned.signing_bytes).hex()},
            deep=True,
        )

    def sign(
        self,
        payload: JsonValue,
        *,
        message_type: InterAgentMessageType,
        recipient_ids: tuple[str, ...],
        session_id: str,
        goal_digest: str,
        task_id: str,
        purpose_id: str,
        message_scope: str,
        delegation_chain: DelegationChain,
        sequence: int,
        transformations: tuple[InterAgentTransformation, ...] = (),
        source_payload_digest: str | None = None,
        now: datetime | None = None,
        ttl_seconds: int | None = None,
        nonce: str | None = None,
        message_id: str | None = None,
    ) -> InterAgentMessageEnvelope:
        """Create an identity-, authority-, task-, and content-bound message."""
        current_time = now or utcnow()
        ttl = self._policy.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        if ttl < 1 or ttl > self._policy.max_ttl_seconds:
            raise ValueError("ttl_seconds must be within the signing policy maximum")
        payload_bytes = canonical_inter_agent_json(payload).encode()
        if len(payload_bytes) > self._policy.max_payload_bytes:
            raise ValueError("canonical payload exceeds max_payload_bytes")
        if len(recipient_ids) > self._policy.max_fanout:
            raise ValueError("recipient count exceeds max_fanout")
        if len(transformations) > self._policy.max_transformations:
            raise ValueError("transformation count exceeds policy")

        payload_digest = inter_agent_payload_digest(payload)
        if source_payload_digest is None:
            source_payload_digest = (
                transformations[0].input_digest if transformations else payload_digest
            )
        unsigned = InterAgentMessageEnvelope(
            message_id=message_id or str(uuid.uuid4()),
            message_type=message_type,
            key_id=self.key_id,
            sender=self._identity,
            recipient_ids=recipient_ids,
            tenant_id=self._identity.tenant_id,
            session_id=session_id,
            goal_digest=goal_digest,
            task_id=task_id,
            purpose_id=purpose_id,
            message_scope=message_scope,
            delegation_chain_digest=delegation_chain.chain_digest,
            sequence=sequence,
            issued_at=current_time,
            expires_at=current_time + timedelta(seconds=ttl),
            nonce=nonce or secrets.token_urlsafe(32),
            source_payload_digest=source_payload_digest,
            payload_digest=payload_digest,
            payload=payload,
            transformations=transformations,
        )
        if len(unsigned.signing_bytes) > self._policy.max_envelope_bytes:
            raise ValueError("canonical envelope exceeds max_envelope_bytes")
        return unsigned.model_copy(
            update={"signature": self._private_key.sign(unsigned.signing_bytes).hex()},
            deep=True,
        )


class InterAgentMessageVerifier:
    """Fail-closed verifier for authenticated, delegated agent messages."""

    def __init__(
        self,
        trusted_keys: Iterable[InterAgentTrustedKey],
        *,
        identity_authorizer: DelegatedIdentityAuthorizer,
        policy: InterAgentMessagePolicy,
        state_store: InterAgentStateStore | None = None,
        audit_sink: InterAgentMessageAuditSink | None = None,
    ) -> None:
        keys = tuple(key.model_copy(deep=True) for key in trusted_keys)
        by_key_id = {key.key_id: key for key in keys}
        if not keys:
            raise ValueError("at least one trusted agent key is required")
        if len(by_key_id) != len(keys):
            raise ValueError("trusted agent keys must have unique fingerprints")
        self._trusted_keys = by_key_id
        self._identity_authorizer = identity_authorizer
        self._policy = policy.model_copy(deep=True)
        self._state_store = state_store or MemoryInterAgentStateStore()
        self._audit_sink = audit_sink

    @property
    def policy(self) -> InterAgentMessagePolicy:
        return self._policy.model_copy(deep=True)

    def verify(
        self,
        envelope: InterAgentMessageEnvelope | None,
        context: InterAgentVerificationContext,
        *,
        now: datetime | None = None,
    ) -> InterAgentMessageVerificationResult:
        """Verify identity, route, authority, content, freshness, replay, and order."""
        current_time = now or utcnow()
        if envelope is None or envelope.signature is None:
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.UNSIGNED_MESSAGE,
                "Inter-agent message is missing its required signature",
                current_time,
            )

        trusted_key = self._trusted_keys.get(envelope.key_id)
        if trusted_key is None:
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.UNKNOWN_AGENT,
                "Message signer is absent from the authenticated agent registry",
                current_time,
            )
        if not self._key_active(trusted_key, current_time, envelope.issued_at):
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.KEY_NOT_ACTIVE,
                "Message signing key is revoked, expired, or not yet active",
                current_time,
            )

        checks = (
            (
                trusted_key.identity == envelope.sender
                and envelope.sender.identity_id == context.sender_id,
                InterAgentMessageCode.IDENTITY_MISMATCH,
                "Message sender does not match the trusted key or authenticated peer",
            ),
            (
                envelope.tenant_id
                == envelope.sender.tenant_id
                == context.tenant_id
                == context.recipient.tenant_id,
                InterAgentMessageCode.TENANT_MISMATCH,
                "Message identities do not share the authenticated tenant",
            ),
            (
                context.recipient.identity_id in envelope.recipient_ids,
                InterAgentMessageCode.RECIPIENT_MISMATCH,
                "Message audience does not contain this authenticated recipient",
            ),
            (
                envelope.session_id == context.session_id,
                InterAgentMessageCode.SESSION_MISMATCH,
                "Message session does not match the active session",
            ),
            (
                envelope.goal_digest == context.goal_digest,
                InterAgentMessageCode.GOAL_MISMATCH,
                "Message is bound to a different authorized goal",
            ),
            (
                envelope.task_id == context.task_id,
                InterAgentMessageCode.TASK_MISMATCH,
                "Message is bound to a different delegated task",
            ),
            (
                envelope.purpose_id == context.purpose_id,
                InterAgentMessageCode.PURPOSE_MISMATCH,
                "Message purpose differs from the delegated authority",
            ),
        )
        for valid, code, message in checks:
            if not valid:
                return self._blocked(envelope, context, code, message, current_time)

        if len(envelope.recipient_ids) > self._policy.max_fanout:
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.FANOUT_DENIED,
                "Message fan-out exceeds the configured maximum",
                current_time,
            )
        for recipient_id in envelope.recipient_ids:
            if not self._route_allowed(envelope, recipient_id):
                code = (
                    InterAgentMessageCode.FANOUT_DENIED
                    if len(envelope.recipient_ids) > 1
                    else InterAgentMessageCode.ROUTE_DENIED
                )
                return self._blocked(
                    envelope,
                    context,
                    code,
                    "Message route, scope, or type is not explicitly authorized",
                    current_time,
                )

        lifetime = (envelope.expires_at - envelope.issued_at).total_seconds()
        if lifetime > self._policy.max_ttl_seconds:
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.TTL_EXCEEDED,
                "Message lifetime exceeds the configured maximum",
                current_time,
            )
        skew = timedelta(seconds=self._policy.clock_skew_seconds)
        if envelope.issued_at > current_time + skew:
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.MESSAGE_NOT_YET_VALID,
                "Message issuance time is in the future",
                current_time,
            )
        if envelope.expires_at <= current_time - skew:
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.MESSAGE_EXPIRED,
                "Message acceptance window has expired",
                current_time,
            )
        age = (current_time - envelope.issued_at).total_seconds()
        if age > self._policy.max_message_age_seconds + self._policy.clock_skew_seconds:
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.MESSAGE_TOO_OLD,
                "Message is older than the configured acceptance window",
                current_time,
            )

        try:
            payload_bytes = canonical_inter_agent_json(envelope.payload).encode()
            signing_bytes = envelope.signing_bytes
        except (TypeError, ValueError):
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.PAYLOAD_DIGEST_MISMATCH,
                "Message payload cannot be canonicalized safely",
                current_time,
            )
        if len(payload_bytes) > self._policy.max_payload_bytes:
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.PAYLOAD_TOO_LARGE,
                "Message payload exceeds the configured byte limit",
                current_time,
            )
        if len(signing_bytes) > self._policy.max_envelope_bytes:
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.ENVELOPE_TOO_LARGE,
                "Signed message envelope exceeds the configured byte limit",
                current_time,
            )
        if inter_agent_payload_digest(envelope.payload) != envelope.payload_digest:
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.PAYLOAD_DIGEST_MISMATCH,
                "Message payload does not match its integrity digest",
                current_time,
            )
        try:
            Ed25519PublicKey.from_public_bytes(trusted_key.public_key).verify(
                bytes.fromhex(envelope.signature),
                signing_bytes,
            )
        except (InvalidSignature, ValueError):
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.SIGNATURE_INVALID,
                "Message signature is invalid",
                current_time,
            )

        transformation_failure = self._verify_transformations(envelope, context, current_time)
        if transformation_failure is not None:
            code, message = transformation_failure
            return self._blocked(envelope, context, code, message, current_time)

        if envelope.delegation_chain_digest != context.delegation_chain.chain_digest:
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.DELEGATION_MISMATCH,
                "Message does not bind the presented delegation chain",
                current_time,
            )
        if context.delegation_chain.leaf.subject != envelope.sender:
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.DELEGATION_MISMATCH,
                "Delegated authority does not terminate at the message sender",
                current_time,
            )
        for recipient_id in envelope.recipient_ids:
            request = DelegatedAccessRequest(
                presenter=envelope.sender,
                chain=context.delegation_chain,
                audience=recipient_id,
                purpose_id=envelope.purpose_id,
                requested_scopes=frozenset({envelope.message_scope}),
                tenant_id=envelope.tenant_id,
                operation_id=envelope.message_id,
            )
            if not self._identity_authorizer.authorize(request, now=current_time).is_authorized:
                return self._blocked(
                    envelope,
                    context,
                    InterAgentMessageCode.DELEGATION_DENIED,
                    "Current delegated authority does not permit this message audience and scope",
                    current_time,
                )

        stream_id = inter_agent_content_reference(
            canonical_inter_agent_json(
                {
                    "recipient_id": context.recipient.identity_id,
                    "sender_id": envelope.sender.identity_id,
                    "session_id": envelope.session_id,
                    "task_id": envelope.task_id,
                    "tenant_id": envelope.tenant_id,
                }
            )
        )
        replay_id = inter_agent_content_reference(
            canonical_inter_agent_json(
                {
                    "key_id": envelope.key_id,
                    "message_id": envelope.message_id,
                    "nonce": envelope.nonce,
                    "recipient_id": context.recipient.identity_id,
                }
            )
        )
        try:
            claim = self._state_store.claim(
                stream_id,
                replay_id,
                sequence=envelope.sequence,
                expires_at=envelope.expires_at + skew,
                now=current_time,
            )
        except Exception:
            return self._blocked(
                envelope,
                context,
                InterAgentMessageCode.STATE_STORE_ERROR,
                "Message replay and ordering state is unavailable",
                current_time,
            )
        if claim != InterAgentStateClaimStatus.STORED:
            code = {
                InterAgentStateClaimStatus.REPLAYED: InterAgentMessageCode.REPLAY_DETECTED,
                InterAgentStateClaimStatus.OUT_OF_ORDER: InterAgentMessageCode.OUT_OF_ORDER,
                InterAgentStateClaimStatus.FULL: InterAgentMessageCode.STATE_STORE_FULL,
            }[claim]
            message = {
                InterAgentStateClaimStatus.REPLAYED: "Message nonce has already been accepted",
                InterAgentStateClaimStatus.OUT_OF_ORDER: (
                    "Message sequence is duplicated, stale, or skips the expected order"
                ),
                InterAgentStateClaimStatus.FULL: "Message replay or stream state is at capacity",
            }[claim]
            return self._blocked(envelope, context, code, message, current_time)

        return self._result(
            envelope,
            context,
            GuardAction.ALLOW,
            InterAgentMessageCode.VERIFIED,
            current_time,
        )

    def require(
        self,
        envelope: InterAgentMessageEnvelope | None,
        context: InterAgentVerificationContext,
        *,
        now: datetime | None = None,
    ) -> InterAgentMessageEnvelope:
        """Return a verified envelope or raise before its payload is consumed."""
        result = self.verify(envelope, context, now=now)
        if not result.is_verified or envelope is None:
            raise InterAgentMessageError(result=result)
        return envelope

    @staticmethod
    def _key_active(
        key: InterAgentTrustedKey,
        now: datetime,
        signed_at: datetime,
    ) -> bool:
        return not (
            key.revoked
            or (
                key.active_from is not None
                and (now < key.active_from or signed_at < key.active_from)
            )
            or (
                key.expires_at is not None
                and (now >= key.expires_at or signed_at >= key.expires_at)
            )
        )

    def _route_allowed(self, envelope: InterAgentMessageEnvelope, recipient_id: str) -> bool:
        return any(
            route.sender_id == envelope.sender.identity_id
            and route.recipient_id == recipient_id
            and envelope.message_scope in route.allowed_scopes
            and envelope.message_type in route.allowed_message_types
            for route in self._policy.routes
        )

    def _verify_transformations(
        self,
        envelope: InterAgentMessageEnvelope,
        context: InterAgentVerificationContext,
        now: datetime,
    ) -> tuple[InterAgentMessageCode, str] | None:
        transformations = envelope.transformations
        if len(transformations) > self._policy.max_transformations:
            return (
                InterAgentMessageCode.TRANSFORMATION_CHAIN_INVALID,
                "Message transformation chain exceeds the configured maximum",
            )
        if not transformations:
            if envelope.source_payload_digest != envelope.payload_digest:
                return (
                    InterAgentMessageCode.TRANSFORMATION_CHAIN_INVALID,
                    "Untransformed message changed its source payload digest",
                )
            return None

        chain_identities = {
            identity.identity_id
            for capability in context.delegation_chain.capabilities
            for identity in (capability.issuer, capability.subject)
        }
        allowed_transformers = chain_identities | set(self._policy.trusted_transformer_ids)
        expected_input = envelope.source_payload_digest
        for index, transformation in enumerate(transformations):
            if (
                transformation.hop_index != index
                or transformation.input_digest != expected_input
                or transformation.occurred_at > envelope.issued_at
                or transformation.transformer.tenant_id != envelope.tenant_id
            ):
                return (
                    InterAgentMessageCode.TRANSFORMATION_CHAIN_INVALID,
                    "Message transformation order, digest, time, or tenant is invalid",
                )
            if transformation.transformer.identity_id not in allowed_transformers:
                return (
                    InterAgentMessageCode.TRANSFORMER_NOT_TRUSTED,
                    "Message transformation was performed by an unauthorized identity",
                )
            key = self._trusted_keys.get(transformation.key_id)
            if key is None or key.identity != transformation.transformer:
                return (
                    InterAgentMessageCode.TRANSFORMER_NOT_TRUSTED,
                    "Message transformation key is not bound to the claimed identity",
                )
            if not self._key_active(key, now, transformation.occurred_at):
                return (
                    InterAgentMessageCode.KEY_NOT_ACTIVE,
                    "Message transformation key is revoked, expired, or not yet active",
                )
            if transformation.signature is None:
                return (
                    InterAgentMessageCode.TRANSFORMATION_SIGNATURE_INVALID,
                    "Message transformation is unsigned",
                )
            try:
                Ed25519PublicKey.from_public_bytes(key.public_key).verify(
                    bytes.fromhex(transformation.signature),
                    transformation.signing_bytes,
                )
            except (InvalidSignature, ValueError):
                return (
                    InterAgentMessageCode.TRANSFORMATION_SIGNATURE_INVALID,
                    "Message transformation signature is invalid",
                )
            expected_input = transformation.output_digest
        if expected_input != envelope.payload_digest:
            return (
                InterAgentMessageCode.TRANSFORMATION_CHAIN_INVALID,
                "Message transformation chain does not produce the payload digest",
            )
        return None

    def _blocked(
        self,
        envelope: InterAgentMessageEnvelope | None,
        context: InterAgentVerificationContext,
        code: InterAgentMessageCode,
        message: str,
        now: datetime,
    ) -> InterAgentMessageVerificationResult:
        finding = InterAgentMessageFinding(code=code, severity=Severity.CRITICAL, message=message)
        return self._result(envelope, context, GuardAction.BLOCK, code, now, finding=finding)

    def _result(
        self,
        envelope: InterAgentMessageEnvelope | None,
        context: InterAgentVerificationContext,
        action: Literal[GuardAction.ALLOW, GuardAction.BLOCK],
        code: InterAgentMessageCode,
        now: datetime,
        *,
        finding: InterAgentMessageFinding | None = None,
    ) -> InterAgentMessageVerificationResult:
        event = InterAgentMessageAuditEvent(
            occurred_at=now,
            action=action,
            code=code,
            message_type=envelope.message_type if envelope is not None else None,
            sequence=envelope.sequence if envelope is not None else None,
            message_ref=(
                inter_agent_content_reference(envelope.message_id) if envelope is not None else None
            ),
            sender_ref=(
                inter_agent_content_reference(envelope.sender.identity_id)
                if envelope is not None
                else None
            ),
            recipient_ref=inter_agent_content_reference(context.recipient.identity_id),
            tenant_ref=inter_agent_content_reference(context.tenant_id),
            session_ref=inter_agent_content_reference(context.session_id),
            goal_ref=inter_agent_content_reference(context.goal_digest),
            task_ref=inter_agent_content_reference(context.task_id),
            payload_ref=(f"sha256:{envelope.payload_digest}" if envelope is not None else None),
            delegation_ref=(
                f"sha256:{envelope.delegation_chain_digest}" if envelope is not None else None
            ),
            transformation_count=len(envelope.transformations) if envelope is not None else 0,
        )
        if self._audit_sink is not None:
            with contextlib.suppress(Exception):
                self._audit_sink.emit(event)
        return InterAgentMessageVerificationResult(
            action=action,
            findings=(finding,) if finding is not None else (),
            audit_event=event,
        )

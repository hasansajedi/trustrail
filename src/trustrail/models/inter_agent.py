"""Typed contracts for authenticated inter-agent communication."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from trustrail.models.delegated_identity import AgentIdentity, DelegationChain
from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_KEY_ID_PATTERN = r"^sha256:[0-9a-f]{64}$"
_NONCE_PATTERN = r"^[A-Za-z0-9_-]{22,128}$"
_SIGNATURE_PATTERN = r"^[0-9a-f]{128}$"


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(tz=UTC)


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


def _canonicalize(value: JsonValue) -> JsonValue:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, JsonValue] = {}
        for key, item in value.items():
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise ValueError("object keys must remain unique after Unicode normalization")
            normalized[normalized_key] = _canonicalize(item)
        return normalized
    return value


def canonical_inter_agent_json(value: JsonValue) -> str:
    """Serialize JSON using the deterministic inter-agent signing profile."""
    return json.dumps(
        _canonicalize(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def inter_agent_content_reference(value: str | bytes) -> str:
    """Return a one-way reference suitable for content-free evidence."""
    encoded = value.encode() if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def inter_agent_payload_digest(payload: JsonValue) -> str:
    """Return the canonical SHA-256 digest for a JSON message payload."""
    return hashlib.sha256(canonical_inter_agent_json(payload).encode()).hexdigest()


class InterAgentMessageType(StrEnum):
    """Purpose-sensitive message classes exchanged by agents."""

    TASK_REQUEST = "task_request"
    TASK_RESULT = "task_result"
    OBSERVATION = "observation"
    STATUS = "status"
    CANCELLATION = "cancellation"


class InterAgentTransformation(BaseModel):
    """Individually signed evidence for one payload transformation hop."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    transformation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    hop_index: int = Field(ge=0, le=10_000)
    transformer: AgentIdentity
    key_id: str = Field(pattern=_KEY_ID_PATTERN)
    operation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    input_digest: str = Field(pattern=_DIGEST_PATTERN)
    output_digest: str = Field(pattern=_DIGEST_PATTERN)
    occurred_at: datetime
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @field_validator("occurred_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "occurred_at")

    @property
    def signing_payload(self) -> dict[str, JsonValue]:
        """Return every protected field except the signature."""
        return self.model_dump(mode="json", exclude={"signature"})

    @property
    def signing_bytes(self) -> bytes:
        """Return canonical bytes for Ed25519 verification."""
        return canonical_inter_agent_json(self.signing_payload).encode()


class InterAgentMessageEnvelope(BaseModel):
    """Complete signed message with identity, task, lineage, and payload bindings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    message_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    message_type: InterAgentMessageType
    key_id: str = Field(pattern=_KEY_ID_PATTERN)
    sender: AgentIdentity
    recipient_ids: tuple[str, ...] = Field(min_length=1, max_length=100)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    goal_digest: str = Field(pattern=_DIGEST_PATTERN)
    task_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    message_scope: str = Field(pattern=_IDENTIFIER_PATTERN)
    delegation_chain_digest: str = Field(pattern=_DIGEST_PATTERN)
    sequence: int = Field(ge=0, le=9_223_372_036_854_775_807)
    issued_at: datetime
    expires_at: datetime
    nonce: str = Field(pattern=_NONCE_PATTERN)
    source_payload_digest: str = Field(pattern=_DIGEST_PATTERN)
    payload_digest: str = Field(pattern=_DIGEST_PATTERN)
    payload: JsonValue = Field(repr=False)
    transformations: tuple[InterAgentTransformation, ...] = Field(
        default_factory=tuple,
        max_length=100,
    )
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @field_validator("recipient_ids")
    @classmethod
    def validate_recipients(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("recipient_ids must be unique")
        for value in values:
            if re.fullmatch(_IDENTIFIER_PATTERN, value) is None:
                raise ValueError("recipient_ids contain an invalid identifier")
        return values

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_envelope(self) -> InterAgentMessageEnvelope:
        if self.sender.tenant_id != self.tenant_id:
            raise ValueError("sender tenant must match the message tenant")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if inter_agent_payload_digest(self.payload) != self.payload_digest:
            raise ValueError("payload_digest does not match payload")
        if not self.transformations:
            if self.source_payload_digest != self.payload_digest:
                raise ValueError("untransformed messages must preserve the source digest")
            return self
        for index, transformation in enumerate(self.transformations):
            if transformation.hop_index != index:
                raise ValueError("transformation hop indexes must be contiguous")
            if transformation.occurred_at > self.issued_at:
                raise ValueError("transformations cannot occur after message issuance")
            expected_input = (
                self.source_payload_digest
                if index == 0
                else self.transformations[index - 1].output_digest
            )
            if transformation.input_digest != expected_input:
                raise ValueError("transformation digest chain is discontinuous")
        if self.transformations[-1].output_digest != self.payload_digest:
            raise ValueError("final transformation does not produce the message payload")
        return self

    @property
    def signing_payload(self) -> dict[str, JsonValue]:
        """Return every protected envelope field except the signature."""
        return self.model_dump(mode="json", exclude={"signature"})

    @property
    def signing_bytes(self) -> bytes:
        """Return canonical bytes for Ed25519 verification."""
        return canonical_inter_agent_json(self.signing_payload).encode()

    @property
    def message_digest(self) -> str:
        """Return the stable signed-envelope reference used in audit and chaining."""
        signature = self.signature or "unsigned"
        return hashlib.sha256(self.signing_bytes + signature.encode()).hexdigest()


class InterAgentTrustedKey(BaseModel):
    """Out-of-band public-key binding for one authenticated agent identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    identity: AgentIdentity
    public_key: bytes = Field(min_length=32, max_length=32, exclude=True, repr=False)
    active_from: datetime | None = None
    expires_at: datetime | None = None
    revoked: bool = False

    @field_validator("active_from", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime | None, info: Any) -> datetime | None:
        if value is not None:
            return _require_aware(value, info.field_name)
        return value

    @model_validator(mode="after")
    def validate_lifetime(self) -> InterAgentTrustedKey:
        if (
            self.active_from is not None
            and self.expires_at is not None
            and self.expires_at <= self.active_from
        ):
            raise ValueError("trusted key expires_at must be after active_from")
        return self

    @property
    def key_id(self) -> str:
        """Return the public-key fingerprint used by signed messages."""
        return inter_agent_content_reference(self.public_key)


class InterAgentRoute(BaseModel):
    """Explicit sender-to-recipient messaging authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sender_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    recipient_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    allowed_scopes: frozenset[str] = Field(min_length=1, max_length=1_000)
    allowed_message_types: frozenset[InterAgentMessageType] = Field(
        min_length=1,
        max_length=len(InterAgentMessageType),
    )


class InterAgentMessagePolicy(BaseModel):
    """Fail-closed bounds and routes for authenticated agent messages."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    routes: tuple[InterAgentRoute, ...] = Field(min_length=1, max_length=100_000)
    trusted_transformer_ids: frozenset[str] = Field(default_factory=frozenset)
    default_ttl_seconds: int = Field(default=60, ge=1, le=3_600)
    max_ttl_seconds: int = Field(default=300, ge=1, le=86_400)
    max_message_age_seconds: int = Field(default=300, ge=1, le=86_400)
    clock_skew_seconds: int = Field(default=30, ge=0, le=300)
    max_payload_bytes: int = Field(default=1_048_576, ge=1, le=100_000_000)
    max_envelope_bytes: int = Field(default=2_097_152, ge=1_024, le=200_000_000)
    max_fanout: int = Field(default=1, ge=1, le=100)
    max_transformations: int = Field(default=16, ge=0, le=100)

    @model_validator(mode="after")
    def validate_policy(self) -> InterAgentMessagePolicy:
        if self.default_ttl_seconds > self.max_ttl_seconds:
            raise ValueError("default_ttl_seconds cannot exceed max_ttl_seconds")
        route_keys = [
            (route.sender_id, route.recipient_id, scope, message_type)
            for route in self.routes
            for scope in route.allowed_scopes
            for message_type in route.allowed_message_types
        ]
        if len(route_keys) != len(set(route_keys)):
            raise ValueError("inter-agent routes must not contain duplicate authorities")
        return self


class InterAgentVerificationContext(BaseModel):
    """Authenticated local expectations and current delegated authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sender_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    recipient: AgentIdentity
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    goal_digest: str = Field(pattern=_DIGEST_PATTERN)
    task_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    delegation_chain: DelegationChain

    @model_validator(mode="after")
    def validate_context(self) -> InterAgentVerificationContext:
        if self.recipient.tenant_id != self.tenant_id:
            raise ValueError("recipient tenant must match verification tenant")
        return self


class InterAgentStateClaimStatus(StrEnum):
    """Atomic message-state claim outcome."""

    STORED = "stored"
    REPLAYED = "replayed"
    OUT_OF_ORDER = "out_of_order"
    FULL = "full"


class InterAgentMessageCode(StrEnum):
    """Stable machine-readable inter-agent verification outcomes."""

    VERIFIED = "verified"
    UNSIGNED_MESSAGE = "unsigned_message"
    UNKNOWN_AGENT = "unknown_agent"
    KEY_NOT_ACTIVE = "key_not_active"
    IDENTITY_MISMATCH = "identity_mismatch"
    TENANT_MISMATCH = "tenant_mismatch"
    RECIPIENT_MISMATCH = "recipient_mismatch"
    SESSION_MISMATCH = "session_mismatch"
    GOAL_MISMATCH = "goal_mismatch"
    TASK_MISMATCH = "task_mismatch"
    PURPOSE_MISMATCH = "purpose_mismatch"
    ROUTE_DENIED = "route_denied"
    FANOUT_DENIED = "fanout_denied"
    DELEGATION_MISMATCH = "delegation_mismatch"
    DELEGATION_DENIED = "delegation_denied"
    MESSAGE_NOT_YET_VALID = "message_not_yet_valid"
    MESSAGE_EXPIRED = "message_expired"
    MESSAGE_TOO_OLD = "message_too_old"
    TTL_EXCEEDED = "ttl_exceeded"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    ENVELOPE_TOO_LARGE = "envelope_too_large"
    PAYLOAD_DIGEST_MISMATCH = "payload_digest_mismatch"
    SIGNATURE_INVALID = "signature_invalid"
    TRANSFORMATION_CHAIN_INVALID = "transformation_chain_invalid"
    TRANSFORMER_NOT_TRUSTED = "transformer_not_trusted"
    TRANSFORMATION_SIGNATURE_INVALID = "transformation_signature_invalid"
    REPLAY_DETECTED = "replay_detected"
    OUT_OF_ORDER = "out_of_order"
    STATE_STORE_FULL = "state_store_full"
    STATE_STORE_ERROR = "state_store_error"


class InterAgentMessageFinding(BaseModel):
    """Content-free explanation of an inter-agent message decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: InterAgentMessageCode
    severity: Severity
    message: str = Field(min_length=1, max_length=500)


class InterAgentMessageAuditEvent(BaseModel):
    """Metadata-only evidence for one verification attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    occurred_at: datetime
    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    code: InterAgentMessageCode
    message_type: InterAgentMessageType | None = None
    sequence: int | None = Field(default=None, ge=0)
    message_ref: str | None = Field(default=None, pattern=_KEY_ID_PATTERN)
    sender_ref: str | None = Field(default=None, pattern=_KEY_ID_PATTERN)
    recipient_ref: str | None = Field(default=None, pattern=_KEY_ID_PATTERN)
    tenant_ref: str | None = Field(default=None, pattern=_KEY_ID_PATTERN)
    session_ref: str | None = Field(default=None, pattern=_KEY_ID_PATTERN)
    goal_ref: str | None = Field(default=None, pattern=_KEY_ID_PATTERN)
    task_ref: str | None = Field(default=None, pattern=_KEY_ID_PATTERN)
    payload_ref: str | None = Field(default=None, pattern=_KEY_ID_PATTERN)
    delegation_ref: str | None = Field(default=None, pattern=_KEY_ID_PATTERN)
    transformation_count: int = Field(default=0, ge=0, le=100)

    @field_validator("occurred_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "occurred_at")


class InterAgentMessageVerificationResult(BaseModel):
    """Fail-closed decision that never serializes message content."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    findings: tuple[InterAgentMessageFinding, ...] = ()
    audit_event: InterAgentMessageAuditEvent

    @property
    def is_verified(self) -> bool:
        return self.action == GuardAction.ALLOW and not self.findings

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK

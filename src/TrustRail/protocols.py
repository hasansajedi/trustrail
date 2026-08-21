"""aiRail Protocol interfaces."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Protocol, runtime_checkable

from aiRail.models.core import (
    AuditEvent,
    Document,
    GuardContext,
    GuardDecision,
    GuardFinding,
    ToolCall,
)


@runtime_checkable
class GuardRule(Protocol):
    """Synchronous guard rule protocol."""

    @property
    def id(self) -> str:
        """Unique rule identifier."""
        ...

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Evaluate a value and return a decision."""
        ...


@runtime_checkable
class AsyncGuardRule(Protocol):
    """Asynchronous guard rule protocol."""

    @property
    def id(self) -> str:
        """Unique rule identifier."""
        ...

    async def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Asynchronously evaluate a value and return a decision."""
        ...


@runtime_checkable
class ContentSafetyProvider(Protocol):
    """External content safety / moderation provider."""

    async def check(
        self,
        text: str,
        context: GuardContext | None = None,
    ) -> list[GuardFinding]:
        """Check text for unsafe content. Returns findings."""
        ...


@runtime_checkable
class PromptInjectionProvider(Protocol):
    """External prompt injection detection provider."""

    async def check(
        self,
        text: str,
        context: GuardContext | None = None,
    ) -> list[GuardFinding]:
        """Check text for prompt injection. Returns findings."""
        ...


@runtime_checkable
class SensitiveDataProvider(Protocol):
    """External sensitive data detection/redaction provider (e.g. Presidio)."""

    async def detect(
        self,
        text: str,
        context: GuardContext | None = None,
    ) -> list[GuardFinding]:
        """Detect sensitive data. Returns findings with offsets."""
        ...

    async def redact(
        self,
        text: str,
        context: GuardContext | None = None,
    ) -> str:
        """Redact sensitive data and return sanitized text."""
        ...


@runtime_checkable
class GroundingVerifier(Protocol):
    """Verifies that LLM output is grounded in provided context."""

    async def verify(
        self,
        response: str,
        documents: list[Document],
        context: GuardContext | None = None,
    ) -> list[GuardFinding]:
        """Check response against source documents for hallucinations."""
        ...


@runtime_checkable
class TokenCounter(Protocol):
    """Token counter for estimating token usage."""

    def count_tokens(self, text: str, model: str = "gpt-4") -> int:
        """Count tokens in text."""
        ...


@runtime_checkable
class ApprovalProvider(Protocol):
    """Human-in-the-loop approval provider."""

    async def request_approval(
        self,
        value: str,
        context: GuardContext | None = None,
        reason: str = "",
    ) -> bool:
        """Request human approval. Returns True if approved."""
        ...


@runtime_checkable
class AuditSink(Protocol):
    """Sink for audit events."""

    async def emit(self, event: AuditEvent) -> None:
        """Emit an audit event."""
        ...


@runtime_checkable
class StateBackend(Protocol):
    """Backend for storing guard state (sessions, rate limits)."""

    async def get(self, key: str) -> Any | None:
        """Get a value by key."""
        ...

    async def set(self, key: str, value: Any, ttl_seconds: float | None = None) -> None:
        """Set a value with optional TTL."""
        ...

    async def increment(self, key: str, delta: int = 1) -> int:
        """Atomically increment a counter and return new value."""
        ...

    async def delete(self, key: str) -> None:
        """Delete a key."""
        ...


@runtime_checkable
class ToolCallValidator(Protocol):
    """Validator for tool calls."""

    def validate(
        self,
        tool_call: ToolCall,
        context: GuardContext | None = None,
    ) -> GuardDecision:
        """Validate a tool call."""
        ...


@runtime_checkable
class StreamChunkValidator(Protocol):
    """Validator for streaming content chunks."""

    async def process_chunk(
        self,
        chunk: str,
        buffer: str,
        context: GuardContext | None = None,
    ) -> AsyncIterator[GuardFinding]:
        """Process a streaming chunk and yield any findings."""
        ...

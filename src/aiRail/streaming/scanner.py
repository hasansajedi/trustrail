"""Streaming content scanner with cross-chunk pattern detection."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from aiRail.models.core import GuardContext, GuardFinding, GuardResult, RiskScore
from aiRail.models.enums import GuardAction, RulePhase
from aiRail.rules.base import BaseRule


@dataclass(init=False)
class StreamResult:
    """Result from processing a streaming chunk."""

    chunk: str
    findings: list[GuardFinding] = field(default_factory=list)
    action: GuardAction = GuardAction.ALLOW
    safe_chunk: str = ""

    def __init__(
        self,
        chunk: str,
        findings: list[GuardFinding] | None = None,
        action: GuardAction = GuardAction.ALLOW,
        safe_chunk: str | None = None,
    ) -> None:
        self.chunk = chunk
        self.findings = findings if findings is not None else []
        self.action = action
        self.safe_chunk = chunk if safe_chunk is None else safe_chunk

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK

    @property
    def requires_approval(self) -> bool:
        return self.action == GuardAction.REQUIRE_APPROVAL


class StreamScanner:
    """Real-time streaming content scanner.

    Maintains a bounded look-behind buffer to detect patterns that span
    chunk boundaries.
    """

    def __init__(
        self,
        rules: list[BaseRule],
        context: GuardContext,
        buffer_size: int = 4096,
        chunk_overlap: int = 256,
    ) -> None:
        self._rules = rules
        self._context = context
        self._buffer_size = buffer_size
        self._chunk_overlap = chunk_overlap
        # Bounded deque for look-behind buffer
        self._buffer: deque[str] = deque(maxlen=buffer_size)
        self._total_chars = 0
        self._findings: list[GuardFinding] = []
        self._blocked = False
        self._requires_approval = False

    @property
    def findings(self) -> list[GuardFinding]:
        return list(self._findings)

    @property
    def is_blocked(self) -> bool:
        return self._blocked

    def _get_buffer_text(self) -> str:
        return "".join(self._buffer)

    def process_chunk(self, chunk: str) -> StreamResult:
        """Process a single chunk synchronously."""
        if self._blocked:
            return StreamResult(
                chunk=chunk,
                findings=self._findings,
                action=GuardAction.BLOCK,
                safe_chunk="",
            )

        safe_chunk = chunk
        new_findings: list[GuardFinding] = []

        # Apply normalization rules to each chunk before buffering or running
        # look-behind detection. This prevents invisible channels from crossing
        # chunk boundaries and ensures callers can emit only sanitized text.
        for rule in self._rules:
            if not rule.enabled or rule.phase != RulePhase.NORMALIZE:
                continue
            try:
                decision = rule.evaluate(safe_chunk, self._context)
                if decision.finding is not None:
                    new_findings.append(decision.finding)
                if (
                    decision.action in (GuardAction.REDACT, GuardAction.TRANSFORM)
                    and decision.transformed_value is not None
                ):
                    safe_chunk = decision.transformed_value
                if decision.action == GuardAction.BLOCK:
                    self._blocked = True
                    self._findings.extend(new_findings)
                    return StreamResult(
                        chunk=chunk,
                        findings=new_findings,
                        action=GuardAction.BLOCK,
                        safe_chunk="",
                    )
                if decision.action == GuardAction.REQUIRE_APPROVAL:
                    self._requires_approval = True
            except Exception:  # noqa: S110
                pass

        # Add sanitized content to the bounded buffer.
        for ch in safe_chunk:
            self._buffer.append(ch)
        self._total_chars += len(chunk)

        # Evaluate rules on the current buffer (with look-behind)
        buffer_text = self._get_buffer_text()
        # Use overlap window: last overlap + current chunk
        eval_text = buffer_text[-min(len(buffer_text), self._chunk_overlap + len(safe_chunk)) :]

        for rule in self._rules:
            if not rule.enabled or rule.phase == RulePhase.NORMALIZE:
                continue
            try:
                decision = rule.evaluate(eval_text, self._context)
                if decision.finding is not None:
                    new_findings.append(decision.finding)
                if decision.action == GuardAction.BLOCK:
                    self._blocked = True
                    self._findings.extend(new_findings)
                    return StreamResult(
                        chunk=chunk,
                        findings=new_findings,
                        action=GuardAction.BLOCK,
                        safe_chunk="",
                    )
                if decision.action == GuardAction.REQUIRE_APPROVAL:
                    self._requires_approval = True
            except Exception:  # noqa: S110
                pass

        self._findings.extend(new_findings)

        if new_findings:
            score = RiskScore.from_findings(self._findings)
            if score.should_block:
                self._blocked = True
                return StreamResult(
                    chunk=chunk,
                    findings=new_findings,
                    action=GuardAction.BLOCK,
                    safe_chunk="",
                )

        if self._requires_approval:
            return StreamResult(
                chunk=chunk,
                findings=new_findings,
                action=GuardAction.REQUIRE_APPROVAL,
                safe_chunk="",
            )

        return StreamResult(
            chunk=chunk,
            findings=new_findings,
            action=GuardAction.ALLOW,
            safe_chunk=safe_chunk,
        )

    async def aprocess_chunk(self, chunk: str) -> StreamResult:
        """Async version of process_chunk."""
        return await asyncio.to_thread(self.process_chunk, chunk)

    async def scan(self, source: AsyncIterator[str]) -> AsyncIterator[StreamResult]:
        """Scan an async stream of chunks."""
        async for chunk in source:
            result = await self.aprocess_chunk(chunk)
            yield result
            if result.is_blocked:
                break

    def finalize(self) -> GuardResult:
        """Return the final guard result after stream completion."""
        score = RiskScore.from_findings(self._findings)
        action = (
            GuardAction.BLOCK
            if (self._blocked or score.should_block)
            else (
                GuardAction.REQUIRE_APPROVAL
                if self._requires_approval
                else (GuardAction.WARN if score.should_warn else GuardAction.ALLOW)
            )
        )
        return GuardResult(
            action=action,
            findings=self._findings,
            score=score,
            value=self._get_buffer_text(),
            stage=self._context.stage,
            context=self._context,
            rules_evaluated=len(self._rules),
        )

    def reset(self) -> None:
        """Reset scanner state for reuse."""
        self._buffer.clear()
        self._total_chars = 0
        self._findings.clear()
        self._blocked = False
        self._requires_approval = False

"""Streaming content scanner with cross-chunk pattern detection."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from trustrail.models.core import GuardContext, GuardDecision, GuardFinding, GuardResult, RiskScore
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, SensitiveDataMode
from trustrail.rules.base import BaseRule


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
        sensitive_data_mode: SensitiveDataMode = SensitiveDataMode.DEFAULT,
    ) -> None:
        self._rules = rules
        self._context = context
        self._buffer_size = buffer_size
        self._chunk_overlap = chunk_overlap
        self._sensitive_data_mode = sensitive_data_mode
        # Bounded deque for look-behind buffer
        self._buffer: deque[str] = deque(maxlen=buffer_size)
        self._total_chars = 0
        self._findings: list[GuardFinding] = []
        self._blocked = False
        self._requires_approval = False
        self._redacted = False
        self._warned = False
        self._policy_handled_finding_ids: set[int] = set()

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
        redacted_chunk = False
        warned_chunk = False

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

        # Evaluate detection rules using sanitized look-behind plus this chunk.
        # Only emit replacements that preserve the already-emitted prefix. A
        # sensitive match spanning that boundary cannot be retracted, so it is
        # blocked fail-closed.
        lookbehind = self._get_buffer_text()[-self._chunk_overlap :]

        for rule in self._rules:
            if not rule.enabled or rule.phase == RulePhase.NORMALIZE:
                continue
            try:
                eval_text = lookbehind + safe_chunk
                decision = rule.evaluate(eval_text, self._context)
                policy_handled = self._apply_sensitive_data_mode(decision)
                if decision.finding is not None:
                    new_findings.append(decision.finding)
                    if policy_handled:
                        self._policy_handled_finding_ids.add(id(decision.finding))
                if decision.action == GuardAction.BLOCK:
                    self._blocked = True
                    self._findings.extend(new_findings)
                    return StreamResult(
                        chunk=chunk,
                        findings=new_findings,
                        action=GuardAction.BLOCK,
                        safe_chunk="",
                    )
                if (
                    decision.action in (GuardAction.REDACT, GuardAction.TRANSFORM)
                    and decision.transformed_value is not None
                ):
                    if not decision.transformed_value.startswith(lookbehind):
                        self._blocked = True
                        self._findings.extend(new_findings)
                        return StreamResult(
                            chunk=chunk,
                            findings=new_findings,
                            action=GuardAction.BLOCK,
                            safe_chunk="",
                        )
                    safe_chunk = decision.transformed_value[len(lookbehind) :]
                    self._redacted = True
                    redacted_chunk = True
                if decision.action == GuardAction.WARN:
                    self._warned = True
                    warned_chunk = True
                if decision.action == GuardAction.REQUIRE_APPROVAL:
                    self._requires_approval = True
            except Exception:  # noqa: S110
                pass

        # Buffer only content that is safe to emit downstream.
        for ch in safe_chunk:
            self._buffer.append(ch)
        self._total_chars += len(chunk)
        self._findings.extend(new_findings)

        actionable_findings = [
            finding
            for finding in self._findings
            if id(finding) not in self._policy_handled_finding_ids
        ]
        actionable_score = RiskScore.from_findings(actionable_findings)
        if actionable_score.should_block:
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
            action=(
                GuardAction.WARN
                if (warned_chunk or actionable_score.should_warn)
                else (GuardAction.REDACT if redacted_chunk else GuardAction.ALLOW)
            ),
            safe_chunk=safe_chunk,
        )

    def _apply_sensitive_data_mode(self, decision: GuardDecision) -> bool:
        finding = decision.finding
        if finding is None or finding.category not in (
            RuleCategory.SENSITIVE_DATA,
            RuleCategory.SECRET,
        ):
            return False
        if self._sensitive_data_mode == SensitiveDataMode.DEFAULT:
            return False
        if self._sensitive_data_mode == SensitiveDataMode.BLOCK:
            decision.action = GuardAction.BLOCK
            return False
        if self._sensitive_data_mode == SensitiveDataMode.REDACT:
            decision.action = (
                GuardAction.REDACT if decision.transformed_value is not None else GuardAction.BLOCK
            )
            return decision.action == GuardAction.REDACT

        decision.action = GuardAction.ALLOW
        decision.transformed_value = None
        return True

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
        actionable_findings = [
            finding
            for finding in self._findings
            if id(finding) not in self._policy_handled_finding_ids
        ]
        actionable_score = RiskScore.from_findings(actionable_findings)
        action = (
            GuardAction.BLOCK
            if (self._blocked or actionable_score.should_block)
            else (
                GuardAction.REQUIRE_APPROVAL
                if self._requires_approval
                else (
                    GuardAction.WARN
                    if (self._warned or actionable_score.should_warn)
                    else (GuardAction.REDACT if self._redacted else GuardAction.ALLOW)
                )
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
        self._redacted = False
        self._warned = False
        self._policy_handled_finding_ids.clear()

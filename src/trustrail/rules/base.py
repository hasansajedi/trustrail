"""Base rule infrastructure."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision, GuardFinding
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity


class BaseRule(ABC):
    """Abstract base for all synchronous guard rules."""

    rule_id: ClassVar[str] = ""
    rule_name: ClassVar[str] = ""
    category: ClassVar[RuleCategory] = RuleCategory.CONTENT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = ""
    owasp: ClassVar[Sequence[str]] = ()

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    @property
    def id(self) -> str:
        return self.rule_id

    @abstractmethod
    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Evaluate value and return decision."""
        ...

    def evaluate_stream(
        self,
        value: str,
        context: GuardContext,
        *,
        chunk: str,
        chunk_index: int,
        total_chars: int,
        total_bytes: int,
    ) -> GuardDecision:
        """Evaluate streaming content using bounded text and cumulative counters.

        Rules that need whole-stream resource counters can override this hook.
        Ordinary rules continue to evaluate the bounded look-behind window in
        ``value`` so streaming memory use remains bounded.
        """
        del chunk, chunk_index, total_chars, total_bytes
        return self.evaluate(value, context)

    def _allow(self) -> GuardDecision:
        return GuardDecision(action=GuardAction.ALLOW, rule_id=self.rule_id)

    def _finding(
        self,
        message: str,
        severity: Severity | None = None,
        offset_start: int | None = None,
        offset_end: int | None = None,
        confidence: float = 1.0,
        **metadata: object,
    ) -> GuardFinding:
        return GuardFinding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            category=self.category,
            severity=severity or self.default_severity,
            message=message,
            offset_start=offset_start,
            offset_end=offset_end,
            confidence=confidence,
            owasp=list(self.owasp),
            metadata=dict(metadata),
        )

    def _block(
        self,
        message: str,
        severity: Severity | None = None,
        offset_start: int | None = None,
        offset_end: int | None = None,
        confidence: float = 1.0,
        action: GuardAction | None = None,
        **metadata: object,
    ) -> GuardDecision:
        finding = self._finding(
            message,
            severity=severity,
            offset_start=offset_start,
            offset_end=offset_end,
            confidence=confidence,
            **metadata,
        )
        return GuardDecision(
            action=action or self.default_action,
            finding=finding,
            rule_id=self.rule_id,
        )

    def timed_evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Evaluate with latency tracking."""
        start = time.perf_counter()
        decision = self.evaluate(value, context)
        decision.latency_ms = (time.perf_counter() - start) * 1000
        return decision

    def timed_evaluate_stream(
        self,
        value: str,
        context: GuardContext,
        *,
        chunk: str,
        chunk_index: int,
        total_chars: int,
        total_bytes: int,
    ) -> GuardDecision:
        """Evaluate a stream chunk with latency tracking."""
        start = time.perf_counter()
        decision = self.evaluate_stream(
            value,
            context,
            chunk=chunk,
            chunk_index=chunk_index,
            total_chars=total_chars,
            total_bytes=total_bytes,
        )
        decision.latency_ms = (time.perf_counter() - start) * 1000
        return decision


class RuleRegistry:
    """Registry of all known rules."""

    def __init__(self) -> None:
        self._rules: dict[str, type[BaseRule]] = {}

    def register(self, rule_class: type[BaseRule]) -> type[BaseRule]:
        """Register a rule class."""
        self._rules[rule_class.rule_id] = rule_class
        return rule_class

    def get(self, rule_id: str) -> type[BaseRule] | None:
        return self._rules.get(rule_id)

    def all_ids(self) -> list[str]:
        return list(self._rules.keys())

    def all_rules(self) -> list[type[BaseRule]]:
        return list(self._rules.values())

    def by_category(self, category: RuleCategory) -> list[type[BaseRule]]:
        return [r for r in self._rules.values() if r.category == category]


registry = RuleRegistry()

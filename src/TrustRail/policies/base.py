"""Base policy infrastructure."""

from __future__ import annotations

from abc import ABC, abstractmethod

from aiRail.models.core import GuardContext, GuardDecision
from aiRail.rules.base import BaseRule


class BasePolicy(ABC):
    """Abstract base for guard policies."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._rules: list[BaseRule] = []

    @property
    def rules(self) -> list[BaseRule]:
        return self._rules

    def add_rule(self, rule: BaseRule) -> None:
        self._rules.append(rule)

    @abstractmethod
    def get_rules(self) -> list[BaseRule]:
        """Return the list of rules for this policy."""
        ...

    def evaluate_all(self, value: str, context: GuardContext) -> list[GuardDecision]:
        """Evaluate all rules and return all decisions."""
        if not self.enabled:
            return []
        results = []
        for rule in self.get_rules():
            if rule.enabled:
                decision = rule.timed_evaluate(value, context)
                results.append(decision)
        return results

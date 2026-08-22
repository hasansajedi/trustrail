"""Persistent memory security policy."""

from __future__ import annotations

from trustrail.policies.base import BasePolicy
from trustrail.rules.base import BaseRule
from trustrail.rules.memory import PersistentMemoryWriteRule


class MemoryPolicy(BasePolicy):
    """Policy for classifying and approving long-lived memory writes."""

    def __init__(self, enabled: bool = True, require_approval: bool = True) -> None:
        super().__init__(enabled=enabled)
        self.require_approval = require_approval

    def get_rules(self) -> list[BaseRule]:
        rules: list[BaseRule] = []
        if self.require_approval:
            rules.append(PersistentMemoryWriteRule())
        return rules + self._rules

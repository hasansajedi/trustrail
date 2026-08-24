"""AI supply-chain boundary policy."""

from __future__ import annotations

from trustrail.policies.base import BasePolicy
from trustrail.rules.base import BaseRule
from trustrail.rules.rag import ApiResponseIntegrityRule


class SupplyChainPolicy(BasePolicy):
    """Policy for detecting compromised third-party response content."""

    def __init__(self, enabled: bool = True, check_api_responses: bool = True) -> None:
        super().__init__(enabled=enabled)
        self.check_api_responses = check_api_responses

    def get_rules(self) -> list[BaseRule]:
        rules: list[BaseRule] = []
        if self.check_api_responses:
            rules.append(ApiResponseIntegrityRule())
        return rules + self._rules

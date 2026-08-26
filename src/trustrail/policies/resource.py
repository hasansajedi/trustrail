"""Resource limit policy."""

from __future__ import annotations

from trustrail.policies.base import BasePolicy
from trustrail.rules.base import BaseRule
from trustrail.rules.resource import (
    InputLengthRule,
    MessageCountRule,
    NestingDepthRule,
    RecursivePromptExpansionRule,
    RepetitivePatternRule,
    SessionRequestRateLimitRule,
    TokenEstimateRule,
    TokenFloodingRule,
)


class ResourcePolicy(BasePolicy):
    """Policy for enforcing resource limits."""

    def __init__(
        self,
        enabled: bool = True,
        max_chars: int = 100_000,
        max_tokens: int = 8_192,
        max_messages: int = 100,
        max_nesting_depth: int = 100,
        detect_repetitive_patterns: bool = True,
        detect_token_flooding: bool = True,
        detect_recursive_expansion: bool = True,
        max_requests_per_session: int | None = None,
        request_rate_window_seconds: float = 60.0,
    ) -> None:
        super().__init__(enabled=enabled)
        self.max_chars = max_chars
        self.max_tokens = max_tokens
        self.max_messages = max_messages
        self.max_nesting_depth = max_nesting_depth
        self.detect_repetitive_patterns = detect_repetitive_patterns
        self.detect_token_flooding = detect_token_flooding
        self.detect_recursive_expansion = detect_recursive_expansion
        self.max_requests_per_session = max_requests_per_session
        self.request_rate_window_seconds = request_rate_window_seconds

    def get_rules(self) -> list[BaseRule]:
        rules: list[BaseRule] = [
            InputLengthRule(max_chars=self.max_chars),
            TokenEstimateRule(max_tokens=self.max_tokens),
            MessageCountRule(max_messages=self.max_messages),
            NestingDepthRule(
                max_json_depth=self.max_nesting_depth,
                max_xml_depth=self.max_nesting_depth,
            ),
        ]
        if self.detect_repetitive_patterns:
            rules.append(RepetitivePatternRule())
        if self.detect_token_flooding:
            rules.append(TokenFloodingRule())
        if self.detect_recursive_expansion:
            rules.append(RecursivePromptExpansionRule())
        if self.max_requests_per_session is not None:
            rules.append(
                SessionRequestRateLimitRule(
                    max_requests=self.max_requests_per_session,
                    window_seconds=self.request_rate_window_seconds,
                )
            )
        return rules + self._rules
